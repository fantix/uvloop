import asyncio
import contextvars
import decimal
import itertools
import random
import socket
import unittest
import weakref

from uvloop import _testbase as tb


class _BaseProtocol(asyncio.BaseProtocol):
    def __init__(self, cvar, *, loop=None):
        self.cvar = cvar
        self.transport = None
        self.connection_made_fut = asyncio.Future(loop=loop)
        self.buffered_ctx = None
        self.data_received_fut = asyncio.Future(loop=loop)
        self.eof_received_fut = asyncio.Future(loop=loop)
        self.connection_lost_ctx = None
        self.done = asyncio.Future(loop=loop)

    def connection_made(self, transport):
        self.transport = transport
        self.connection_made_fut.set_result(self.cvar.get())

    def connection_lost(self, exc):
        self.connection_lost_ctx = self.cvar.get()
        if exc is None:
            self.done.set_result(None)
        else:
            self.done.set_exception(exc)

    def eof_received(self):
        self.eof_received_fut.set_result(self.cvar.get())


class _Protocol(_BaseProtocol, asyncio.Protocol):
    def data_received(self, data):
        self.data_received_fut.set_result(self.cvar.get())


class _BufferedProtocol(_BaseProtocol, asyncio.BufferedProtocol):
    def get_buffer(self, sizehint):
        if self.buffered_ctx is None:
            self.buffered_ctx = self.cvar.get()
        elif self.cvar.get() != self.buffered_ctx:
            self.data_received_fut.set_exception(ValueError("{} != {}".format(
                self.buffered_ctx, self.cvar.get(),
            )))
        return bytearray(65536)

    def buffer_updated(self, nbytes):
        if not self.data_received_fut.done():
            if self.cvar.get() == self.buffered_ctx:
                self.data_received_fut.set_result(self.cvar.get())
            else:
                self.data_received_fut.set_exception(
                    ValueError("{} != {}".format(
                        self.buffered_ctx, self.cvar.get(),
                    ))
                )


class _ContextBaseTests(tb.SSLTestCase):

    ONLYCERT = tb._cert_fullname(__file__, 'ssl_cert.pem')
    ONLYKEY = tb._cert_fullname(__file__, 'ssl_key.pem')

    def test_task_decimal_context(self):
        async def fractions(t, precision, x, y):
            with decimal.localcontext() as ctx:
                ctx.prec = precision
                a = decimal.Decimal(x) / decimal.Decimal(y)
                await asyncio.sleep(t)
                b = decimal.Decimal(x) / decimal.Decimal(y ** 2)
                return a, b

        async def main():
            r1, r2 = await asyncio.gather(
                fractions(0.1, 3, 1, 3), fractions(0.2, 6, 1, 3))

            return r1, r2

        r1, r2 = self.loop.run_until_complete(main())

        self.assertEqual(str(r1[0]), '0.333')
        self.assertEqual(str(r1[1]), '0.111')

        self.assertEqual(str(r2[0]), '0.333333')
        self.assertEqual(str(r2[1]), '0.111111')

    def test_task_context_1(self):
        cvar = contextvars.ContextVar('cvar', default='nope')

        async def sub():
            await asyncio.sleep(0.01)
            self.assertEqual(cvar.get(), 'nope')
            cvar.set('something else')

        async def main():
            self.assertEqual(cvar.get(), 'nope')
            subtask = self.loop.create_task(sub())
            cvar.set('yes')
            self.assertEqual(cvar.get(), 'yes')
            await subtask
            self.assertEqual(cvar.get(), 'yes')

        task = self.loop.create_task(main())
        self.loop.run_until_complete(task)

    def test_task_context_2(self):
        cvar = contextvars.ContextVar('cvar', default='nope')

        async def main():
            def fut_on_done(fut):
                # This change must not pollute the context
                # of the "main()" task.
                cvar.set('something else')

            self.assertEqual(cvar.get(), 'nope')

            for j in range(2):
                fut = self.loop.create_future()
                fut.add_done_callback(fut_on_done)
                cvar.set('yes{}'.format(j))
                self.loop.call_soon(fut.set_result, None)
                await fut
                self.assertEqual(cvar.get(), 'yes{}'.format(j))

                for i in range(3):
                    # Test that task passed its context to add_done_callback:
                    cvar.set('yes{}-{}'.format(i, j))
                    await asyncio.sleep(0.001)
                    self.assertEqual(cvar.get(), 'yes{}-{}'.format(i, j))

        task = self.loop.create_task(main())
        self.loop.run_until_complete(task)

        self.assertEqual(cvar.get(), 'nope')

    def test_task_context_3(self):
        cvar = contextvars.ContextVar('cvar', default=-1)

        # Run 100 Tasks in parallel, each modifying cvar.

        async def sub(num):
            for i in range(10):
                cvar.set(num + i)
                await asyncio.sleep(random.uniform(0.001, 0.05))
                self.assertEqual(cvar.get(), num + i)

        async def main():
            tasks = []
            for i in range(100):
                task = self.loop.create_task(sub(random.randint(0, 10)))
                tasks.append(task)

            await asyncio.gather(*tasks, return_exceptions=True)

        self.loop.run_until_complete(main())

        self.assertEqual(cvar.get(), -1)

    def test_task_context_4(self):
        cvar = contextvars.ContextVar('cvar', default='nope')

        class TrackMe:
            pass
        tracked = TrackMe()
        ref = weakref.ref(tracked)

        async def sub():
            cvar.set(tracked)  # NoQA
            self.loop.call_soon(lambda: None)

        async def main():
            await self.loop.create_task(sub())
            await asyncio.sleep(0.01)

        task = self.loop.create_task(main())
        self.loop.run_until_complete(task)

        del tracked
        self.assertIsNone(ref())

    def test_create_server_protocol_factory_context(self):
        cvar = contextvars.ContextVar('cvar', default='outer')
        factory_called_future = self.loop.create_future()
        proto = _Protocol(cvar, loop=self.loop)

        def factory():
            try:
                self.assertEqual(cvar.get(), 'inner')
            except Exception as e:
                factory_called_future.set_exception(e)
            else:
                factory_called_future.set_result(None)

            return proto

        async def test():
            cvar.set('inner')
            port = tb.find_free_port()
            srv = await self.loop.create_server(factory, '127.0.0.1', port)

            s = socket.socket(socket.AF_INET)
            with s:
                s.setblocking(False)
                await self.loop.sock_connect(s, ('127.0.0.1', port))

            try:
                await factory_called_future
            finally:
                srv.close()
                await proto.done
                await srv.wait_closed()

        self.loop.run_until_complete(test())

    def test_create_server_connection_protocol(self):
        cvar = contextvars.ContextVar('cvar', default='outer')

        async def test(proto_factory):
            proto = proto_factory(cvar, loop=self.loop)
            cvar.set('inner')
            port = tb.find_free_port()
            srv = await self.loop.create_server(
                lambda: proto, '127.0.0.1', port,
            )

            s = socket.socket(socket.AF_INET)
            s.setblocking(False)
            await self.loop.sock_connect(s, ('127.0.0.1', port))

            try:
                inner = await proto.connection_made_fut
                self.assertEqual(inner, "inner")

                await self.loop.sock_sendall(s, b'data')
                inner = await proto.data_received_fut
                self.assertEqual(inner, "inner")

                s.shutdown(socket.SHUT_WR)
                inner = await proto.eof_received_fut
                self.assertEqual(inner, "inner")

                s.close()
                await proto.done
                self.assertEqual(proto.connection_lost_ctx, "inner")
            finally:
                s.close()
                srv.close()
                await srv.wait_closed()

        for factory in (_Protocol, _BufferedProtocol):
            with self.subTest(factory=factory.__name__):
                self.loop.run_until_complete(test(factory))

    def test_create_ssl_server_connection_protocol(self):
        cvar = contextvars.ContextVar('cvar', default='outer')

        def resume_reading(transport):
            cvar.set("resume_reading")
            transport.resume_reading()

        async def test(proto_factory):
            proto = proto_factory(cvar, loop=self.loop)
            cvar.set('inner')
            sslctx = self._create_server_ssl_context(self.ONLYCERT,
                                                     self.ONLYKEY)
            client_sslctx = self._create_client_ssl_context()

            port = tb.find_free_port()
            srv = await self.loop.create_server(
                lambda: proto, '127.0.0.1', port, ssl=sslctx,
            )

            s = socket.socket(socket.AF_INET)
            await self.loop.run_in_executor(
                None, s.connect, ('127.0.0.1', port)
            )
            ssl_sock = await self.loop.run_in_executor(
                None, client_sslctx.wrap_socket, s
            )

            try:
                inner = await proto.connection_made_fut
                self.assertEqual(inner, "inner")

                await self.loop.run_in_executor(None, ssl_sock.send, b'data')
                inner = await proto.data_received_fut
                self.assertEqual(inner, "inner")

                if self.implementation != 'asyncio':
                    # this seems to be a bug in asyncio
                    proto.data_received_fut = self.loop.create_future()
                    proto.transport.pause_reading()
                    await self.loop.run_in_executor(None,
                                                    ssl_sock.send, b'data')
                    self.loop.call_soon(resume_reading, proto.transport)
                    inner = await proto.data_received_fut
                    self.assertEqual(inner, "inner")

                ssl_sock.shutdown(socket.SHUT_WR)
                inner = await proto.eof_received_fut
                self.assertEqual(inner, "inner")

                await self.loop.run_in_executor(None, ssl_sock.close)
                await proto.done
                self.assertEqual(proto.connection_lost_ctx, "inner")
            finally:
                if self.implementation == 'asyncio':
                    # mute resource warning in asyncio
                    proto.transport.close()
                s.close()
                srv.close()
                await srv.wait_closed()

        for factory in (_Protocol, _BufferedProtocol):
            with self.subTest(factory=factory.__name__):
                self.loop.run_until_complete(test(factory))

    def test_create_server_manual_connection_lost(self):
        if self.implementation == 'asyncio':
            raise unittest.SkipTest('this seems to be a bug in asyncio')

        cvar = contextvars.ContextVar('cvar', default='outer')
        proto = _Protocol(cvar, loop=self.loop)

        def close():
            cvar.set('closing')
            proto.transport.close()

        async def test():
            cvar.set('inner')
            port = tb.find_free_port()
            srv = await self.loop.create_server(
                lambda: proto, '127.0.0.1', port,
            )

            s = socket.socket(socket.AF_INET)
            s.setblocking(False)
            await self.loop.sock_connect(s, ('127.0.0.1', port))

            try:
                inner = await proto.connection_made_fut
                self.assertEqual(inner, "inner")

                self.loop.call_soon(close)

                await proto.done
                self.assertEqual(proto.connection_lost_ctx, "inner")
            finally:
                s.close()
                srv.close()
                await srv.wait_closed()

        self.loop.run_until_complete(test())

    def test_create_ssl_server_manual_connection_lost(self):
        cvar = contextvars.ContextVar('cvar', default='outer')
        proto = _Protocol(cvar, loop=self.loop)
        sslctx = self._create_server_ssl_context(self.ONLYCERT,
                                                 self.ONLYKEY)
        client_sslctx = self._create_client_ssl_context()

        def close():
            cvar.set('closing')
            proto.transport.close()

        async def test():
            cvar.set('inner')
            port = tb.find_free_port()
            srv = await self.loop.create_server(
                lambda: proto, '127.0.0.1', port, ssl=sslctx,
            )

            s = socket.socket(socket.AF_INET)
            await self.loop.run_in_executor(
                None, s.connect, ('127.0.0.1', port)
            )
            ssl_sock = await self.loop.run_in_executor(
                None, client_sslctx.wrap_socket, s
            )

            try:
                inner = await proto.connection_made_fut
                self.assertEqual(inner, "inner")

                if self.implementation == 'asyncio':
                    self.loop.call_soon(close)
                else:
                    # asyncio doesn't have the flushing phase

                    # put the incoming data on-hold
                    proto.transport.pause_reading()
                    # send data
                    await self.loop.run_in_executor(None,
                                                    ssl_sock.send, b'hello')
                    # schedule a proactive transport close which will trigger
                    # the flushing process to retrieve the remaining data
                    self.loop.call_soon(close)
                    # turn off the reading lock now (this also schedules a
                    # resume operation after transport.close, therefore it
                    # won't affect our test)
                    proto.transport.resume_reading()

                    inner = await proto.data_received_fut
                    self.assertEqual(inner, "inner")

                await self.loop.run_in_executor(None, ssl_sock.unwrap)
                await proto.done
                self.assertEqual(proto.connection_lost_ctx, "inner")
            finally:
                ssl_sock.close()
                s.close()
                srv.close()
                await srv.wait_closed()

        self.loop.run_until_complete(test())

    def test_create_connection_protocol(self):
        cvar = contextvars.ContextVar('cvar', default='outer')

        async def test(proto_factory, use_sock, use_ssl):
            proto = proto_factory(cvar, loop=self.loop)
            cvar.set('inner')
            port = tb.find_free_port()
            ss = socket.socket(socket.AF_INET)
            ss.bind(('127.0.0.1', port))
            ss.listen(1)

            def accept():
                sock, _ = ss.accept()
                if use_ssl:
                    sslctx = self._create_server_ssl_context(self.ONLYCERT,
                                                             self.ONLYKEY)
                    sock = sslctx.wrap_socket(sock, server_side=True)
                return sock

            s = self.loop.run_in_executor(None, accept)

            try:
                params = {}
                if use_sock:
                    cs = socket.socket(socket.AF_INET)
                    cs.connect(('127.0.0.1', port))
                    params['sock'] = cs
                    if use_ssl:
                        params['server_hostname'] = '127.0.0.1'
                else:
                    params['host'] = '127.0.0.1'
                    params['port'] = port
                if use_ssl:
                    params['ssl'] = self._create_client_ssl_context()
                await self.loop.create_connection(lambda: proto, **params)
                s = await s

                inner = await proto.connection_made_fut
                self.assertEqual(inner, "inner")

                await self.loop.run_in_executor(None, s.send, b'data')
                inner = await proto.data_received_fut
                self.assertEqual(inner, "inner")

                s.shutdown(socket.SHUT_WR)
                inner = await proto.eof_received_fut
                self.assertEqual(inner, "inner")

                s.close()
                await proto.done
                self.assertEqual(proto.connection_lost_ctx, "inner")
            finally:
                ss.close()
                proto.transport.close()

        for factory, use_sock, use_ssl in itertools.product(
            (_Protocol, _BufferedProtocol), (False, True), (False, True),
        ):
            with self.subTest(
                factory=factory.__name__, use_sock=use_sock, use_ssl=use_ssl,
            ):
                self.loop.run_until_complete(test(factory, use_sock, use_ssl))

    def test_start_tls(self):
        cvar = contextvars.ContextVar('cvar', default='outer')

        async def test(proto_factory):
            proto = proto_factory(cvar, loop=self.loop)
            cvar.set('inner')
            port = tb.find_free_port()
            ss = socket.socket(socket.AF_INET)
            ss.bind(('127.0.0.1', port))
            ss.listen(1)

            def accept():
                sock, _ = ss.accept()
                sslctx = self._create_server_ssl_context(self.ONLYCERT,
                                                         self.ONLYKEY)
                return sslctx.wrap_socket(sock, server_side=True)

            s = self.loop.run_in_executor(None, accept)

            try:
                await self.loop.create_connection(lambda: proto,
                                                  '127.0.0.1', port)
                inner = await proto.connection_made_fut
                self.assertEqual(inner, "inner")

                cvar.set('start_tls')
                transport = await self.loop.start_tls(
                    proto.transport, proto, self._create_client_ssl_context())
                s = await s

                await self.loop.run_in_executor(None, s.send, b'data')
                inner = await proto.data_received_fut
                if self.implementation == 'asyncio':
                    self.assertEqual(inner, "start_tls")
                else:
                    self.assertEqual(inner, "inner")

                s.shutdown(socket.SHUT_WR)
                inner = await proto.eof_received_fut
                if self.implementation == 'asyncio':
                    self.assertEqual(inner, "start_tls")
                else:
                    self.assertEqual(inner, "inner")

                s.close()
                await proto.done
                self.assertEqual(proto.connection_lost_ctx, "start_tls")
            finally:
                ss.close()
                transport.close()

        for factory in (_Protocol, _BufferedProtocol):
            with self.subTest(factory=factory.__name__):
                self.loop.run_until_complete(test(factory))


class Test_UV_Context(_ContextBaseTests, tb.UVTestCase):
    pass


class Test_AIO_Context(_ContextBaseTests, tb.AIOTestCase):
    pass
