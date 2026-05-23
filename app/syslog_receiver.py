import asyncio
import logging
import ssl
import os
from redis.asyncio import Redis
from app.config.config import get_settings

logger = logging.getLogger("syslog-receiver")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [SYSLOG] %(message)s")

settings = get_settings()


class UDPTokenBucketProtocol(asyncio.DatagramProtocol):
    def __init__(self, redis: Redis, threshold: int = 1000, window: int = 10):
        self.redis = redis
        self.threshold = threshold
        self.window = window

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        # Fire-and-forget scheduling to avoid blocking the event loop
        asyncio.create_task(self.handle_datagram(data, addr))

    async def handle_datagram(self, data, addr):
        src_ip = addr[0]
        key = f"warsoc:syslog:count:{src_ip}"
        try:
            cur = await self.redis.incr(key)
            await self.redis.expire(key, self.window)
            if cur > self.threshold:
                # Drop silently and optionally add a short blacklist
                logger.warning(f"Dropping UDP syslog from {src_ip}; rate {cur} > {self.threshold}")
                return
        except Exception as e:
            logger.debug(f"Redis unavailable for syslog throttle: {e}")

        # Here, forward to Redis stream or local queue for processing
        # For minimal implementation, push raw payload into Redis stream
        try:
            queue_name = getattr(settings, 'raw_logs_queue', 'raw_logs_queue')
            maxlen = int(getattr(settings, 'raw_logs_maxlen', 100000))
            await self.redis.xadd(queue_name, {"payload": data.decode(errors="ignore")}, maxlen=maxlen)
        except Exception as e:
            logger.error(f"Failed to push syslog payload to Redis: {e}")


async def handle_tcp_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, redis: Redis):
    addr = writer.get_extra_info('peername')
    src_ip = addr[0] if addr else 'unknown'
    try:
        while True:
            line = await reader.readline()
            if not line:
                break
            payload = line.decode(errors='ignore').strip()
            queue_name = getattr(settings, 'raw_logs_queue', 'raw_logs_queue')
            maxlen = int(getattr(settings, 'raw_logs_maxlen', 100000))
            await redis.xadd(queue_name, {"payload": payload}, maxlen=maxlen)
    except Exception as e:
        logger.error(f"TCP client handler error from {src_ip}: {e}")
    finally:
        writer.close()
        await writer.wait_closed()


async def start_syslog_services():
    redis = await Redis.from_url(settings.redis_url, decode_responses=True)

    # UDP listener
    udp_port = getattr(settings, 'syslog_udp_port', 5140)
    loop = asyncio.get_running_loop()
    transport, protocol = await loop.create_datagram_endpoint(
        lambda: UDPTokenBucketProtocol(redis, threshold=getattr(settings, 'syslog_udp_threshold', 1000), window=getattr(settings, 'syslog_udp_window', 10)),
        local_addr=('0.0.0.0', udp_port)
    )
    logger.info(f"UDP syslog receiver listening on 0.0.0.0:{udp_port}")

    # Optional TCP/TLS listener
    tcp_port = getattr(settings, 'syslog_tcp_port', 6514)
    ssl_ctx = None
    cert_path = getattr(settings, 'syslog_tls_cert', None)
    key_path = getattr(settings, 'syslog_tls_key', None)
    if cert_path and key_path and os.path.exists(cert_path) and os.path.exists(key_path):
        ssl_ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        ssl_ctx.load_cert_chain(certfile=cert_path, keyfile=key_path)
        logger.info("Syslog relay: TLS enabled for TCP syslog")

    server = await asyncio.start_server(lambda r, w: handle_tcp_client(r, w, redis), host='0.0.0.0', port=tcp_port, ssl=ssl_ctx)
    logger.info(f"TCP syslog receiver listening on 0.0.0.0:{tcp_port} {'(TLS)' if ssl_ctx else ''}")

    async with server:
        await server.serve_forever()


if __name__ == '__main__':
    try:
        asyncio.run(start_syslog_services())
    except KeyboardInterrupt:
        logger.info("Syslog receiver shutting down.")
