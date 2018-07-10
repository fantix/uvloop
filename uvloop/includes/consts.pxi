DEF UV_STREAM_RECV_BUF_SIZE = 256000  # 250kb

DEF FLOW_CONTROL_HIGH_WATER = 65536
DEF FLOW_CONTROL_LOW_WATER = 16384

DEF DEFAULT_FREELIST_SIZE = 250

DEF DEBUG_STACK_DEPTH = 10


DEF __PROCESS_DEBUG_SLEEP_AFTER_FORK = 1


DEF LOG_THRESHOLD_FOR_CONNLOST_WRITES = 5


# Number of seconds to wait for SSL handshake to complete
# The default timeout matches that of Nginx.
DEF SSL_HANDSHAKE_TIMEOUT = 60.0
# Number of seconds to wait for SSL shutdown to complete
# The default timeout mimics lingering_time
DEF SSL_SHUTDOWN_TIMEOUT = 30.0
