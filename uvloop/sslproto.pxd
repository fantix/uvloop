cdef enum ProtocolState:
    _UNWRAPPED = 0
    _DO_HANDSHAKE = 1
    _WRAPPED = 2
    _FLUSHING = 3
    _SHUTDOWN = 4


cdef class SSLProtocol:
    cdef:
        bint _server_side
        str _server_hostname
        object _sslcontext

        object _extra

        object _write_backlog
        int _write_buffer_size

        object _waiter
        object _loop
        object _app_transport

        object _transport
        bint _call_connection_made
        object _ssl_handshake_timeout
        object _ssl_shutdown_timeout

        object _sslobj
        object _incoming
        object _outgoing
        object _ssl_buffer
        ProtocolState _state
        int _conn_lost
        bint _eof_received

        bint _ssl_writing_paused
        bint _app_reading_paused

        int _incoming_high_water
        int _incoming_low_water

        bint _app_writing_paused
        int _outgoing_high_water
        int _outgoing_low_water

        object _app_protocol
        bint _app_protocol_is_buffer

        object _handshake_start_time
        object _handshake_timeout_handle
        object _shutdown_timeout_handle

    cdef _set_app_protocol(self, app_protocol)
    cdef _wakeup_waiter(self, exc=*)
    cdef _get_extra_info(self, name, default=*)
    cdef _set_state(self, new_state)

    # Handshake flow

    cdef _start_handshake(self)
    cdef _check_handshake_timeout(self)
    cdef _do_handshake(self)
    cdef _on_handshake_complete(self, handshake_exc)

    # Shutdown flow

    cdef _start_shutdown(self)
    cdef _check_shutdown_timeout(self)
    cdef _do_flush(self)
    cdef _do_shutdown(self)
    cdef _on_shutdown_complete(self, shutdown_exc)
    cdef _abort(self, exc)

    # Outgoing flow

    cdef _write_appdata(self, list_of_data)
    cdef _do_write(self)
    cdef _process_outgoing(self)

    # Incoming flow

    cdef _do_read(self)
    cdef _do_read__buffered(self)
    cdef _do_read__copied(self)
    cdef _call_eof_received(self)

    # Flow control for writes from APP socket

    cdef _control_app_writing(self)
    cdef _get_write_buffer_size(self)
    cdef _set_write_buffer_limits(self, high=*, low=*)

    # Flow control for reads to APP socket

    cdef _pause_reading(self)
    cdef _resume_reading(self)

    # Flow control for reads from SSL socket

    cdef _control_ssl_reading(self)
    cdef _set_read_buffer_limits(self, high=*, low=*)
    cdef _get_read_buffer_size(self)
    cdef _fatal_error(self, exc, message=*)
