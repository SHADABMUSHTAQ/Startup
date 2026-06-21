"""
╔══════════════════════════════════════════════════════════════════════╗
║  WARSOC TIER 2 — NETWORK SYSLOG RECEIVER                          ║
║  Async UDP Listener → In-Memory Buffer → Redis Stream Drain        ║
║  Author: Senior Backend Architect                                   ║
╚══════════════════════════════════════════════════════════════════════╝

Integration Point:
    UDP:5140 → asyncio.Queue(50000) → raw_logs_queue (Redis Stream)
    All four existing workers (SIEM, PECA, FBR, Detection) will
    automatically consume these logs with zero code changes.

Environment Variables:
    REDIS_HOST          (default: redis)
    REDIS_PORT          (default: 6379)
    REDIS_PASSWORD      (default: None)
    REDIS_TLS           (default: False)
    NETWORK_TENANT_ID   (default: WARSOC_NETWORK)
    SYSLOG_PORT         (default: 5140)
    DRAIN_BATCH_SIZE    (default: 50)
    DRAIN_INTERVAL_MS   (default: 100)
"""

import asyncio
import json
import logging
import os
import re
import signal
import sys
import uuid
from datetime import datetime, timezone

import redis.asyncio as aioredis
from motor.motor_asyncio import AsyncIOMotorClient

# ─── Configuration ───────────────────────────────────────────────
REDIS_HOST       = os.getenv("REDIS_HOST", "redis")
REDIS_PORT       = int(os.getenv("REDIS_PORT", "6379"))
REDIS_PASSWORD   = os.getenv("REDIS_PASSWORD", None)
REDIS_TLS        = os.getenv("REDIS_TLS", "false").lower() in ("true", "1", "yes")
TENANT_ID        = os.getenv("NETWORK_TENANT_ID", "WARSOC_NETWORK")
SYSLOG_PORT      = int(os.getenv("SYSLOG_PORT", "5140"))
DRAIN_BATCH_SIZE = int(os.getenv("DRAIN_BATCH_SIZE", "50"))
DRAIN_INTERVAL   = int(os.getenv("DRAIN_INTERVAL_MS", "100")) / 1000.0

RAW_LOGS_QUEUE       = "raw_logs_queue"
RAW_LOGS_QUEUE_MAXLEN = 100000
BUFFER_MAX           = 50_000
AGENT_ID             = "syslog_receiver"

# ─── Logging ─────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [SYSLOG-RX] %(levelname)s %(message)s",
)
logger = logging.getLogger("syslog_receiver")

# ─── Syslog Parsing ─────────────────────────────────────────────
# RFC 3164 priority header: <PRI>TIMESTAMP HOSTNAME MSG
_RFC3164_RE = re.compile(
    r"^<(\d{1,3})>"                     # <PRI>
    r"(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"  # Mmm dd HH:MM:SS
    r"(\S+)\s+"                          # hostname
    r"(.+)$",                            # message
    re.DOTALL,
)

# RFC 5424 structured header
_RFC5424_RE = re.compile(
    r"^<(\d{1,3})>"                      # <PRI>
    r"(\d+)\s+"                          # VERSION
    r"(\S+)\s+"                          # TIMESTAMP (ISO-8601)
    r"(\S+)\s+"                          # HOSTNAME
    r"(\S+)\s+"                          # APP-NAME
    r"(\S+)\s+"                          # PROCID
    r"(\S+)\s*"                          # MSGID
    r"(.*)",                             # STRUCTURED-DATA + MSG
    re.DOTALL,
)

# CEF header: CEF:Version|Device Vendor|Device Product|...
_CEF_RE = re.compile(
    r"^CEF:(\d+)\|"
    r"([^|]*)\|"   # Device Vendor
    r"([^|]*)\|"   # Device Product
    r"([^|]*)\|"   # Device Version
    r"([^|]*)\|"   # Signature ID → event_id
    r"([^|]*)\|"   # Name → message
    r"([^|]*)\|"   # Severity
    r"(.*)",       # Extension
    re.DOTALL,
)

# Syslog facility/severity from PRI
_FACILITY_NAMES = [
    "kern", "user", "mail", "daemon", "auth", "syslog", "lpr", "news",
    "uucp", "cron", "authpriv", "ftp", "ntp", "audit", "alert", "clock",
    "local0", "local1", "local2", "local3", "local4", "local5", "local6", "local7",
]
_SEVERITY_NAMES = [
    "EMERGENCY", "ALERT", "CRITICAL", "ERROR", "WARNING", "NOTICE", "INFO", "DEBUG",
]


def _decode_pri(pri: int) -> tuple[str, str]:
    """Decode PRI value into facility name and severity name."""
    facility = _FACILITY_NAMES[pri >> 3] if (pri >> 3) < len(_FACILITY_NAMES) else f"facility_{pri >> 3}"
    severity = _SEVERITY_NAMES[pri & 0x07]
    return facility, severity


def _parse_cef_extensions(ext_str: str) -> dict:
    """Parse CEF extension key=value pairs."""
    result = {}
    # CEF extensions are space-delimited key=value pairs
    # Values can contain spaces if they are the last value before the next key=
    parts = re.split(r'\s+(?=\w+=)', ext_str.strip())
    for part in parts:
        if "=" in part:
            k, v = part.split("=", 1)
            result[k.strip()] = v.strip()
    return result


def parse_syslog(raw: str) -> dict:
    """
    Parse a raw syslog/CEF datagram into the WarSOC unified log schema.
    Supports RFC 3164, RFC 5424, CEF, and plain-text fallback.
    """
    now = datetime.now(timezone.utc).isoformat()
    base = {
        "event_uid": str(uuid.uuid4()),
        "tenant_id": TENANT_ID,
        "agent_id": AGENT_ID,
        "agent_version": "syslog_rx_1.0",
        "timestamp": now,
        "source_ip": "0.0.0.0",
        "user": "SYSTEM",
        "event_id": 0,
        "message": "",
        "raw_data": {"raw": raw},
        "type": "network_log",
    }

    stripped = raw.strip()

    # ── CEF Detection (can be embedded after syslog header) ──
    cef_start = stripped.find("CEF:")
    if cef_start >= 0:
        cef_part = stripped[cef_start:]
        m = _CEF_RE.match(cef_part)
        if m:
            sig_id = m.group(5).strip()
            try:
                base["event_id"] = int(sig_id)
            except ValueError:
                base["event_id"] = hash(sig_id) % 100000
            base["message"] = m.group(6).strip() or "CEF Event"
            base["raw_data"] = {
                "format": "CEF",
                "version": m.group(1),
                "vendor": m.group(2),
                "product": m.group(3),
                "device_version": m.group(4),
                "signature_id": sig_id,
                "name": m.group(6).strip(),
                "severity": m.group(7).strip(),
                "extensions": _parse_cef_extensions(m.group(8)),
                "raw": raw,
            }
            # Extract source IP from CEF extensions if available
            exts = base["raw_data"]["extensions"]
            base["source_ip"] = exts.get("src") or exts.get("sourceAddress") or "0.0.0.0"
            base["user"] = exts.get("duser") or exts.get("suser") or "SYSTEM"
            return base

    # ── RFC 5424 ──
    m = _RFC5424_RE.match(stripped)
    if m:
        pri = int(m.group(1))
        facility, severity = _decode_pri(pri)
        ts_raw = m.group(3)
        hostname = m.group(4)
        app_name = m.group(5)
        proc_id = m.group(6)
        msg_id = m.group(7)
        msg_body = m.group(8).strip()

        # Parse ISO timestamp from RFC 5424
        try:
            parsed_ts = datetime.fromisoformat(ts_raw.replace("Z", "+00:00"))
            if parsed_ts.tzinfo is None:
                parsed_ts = parsed_ts.replace(tzinfo=timezone.utc)
            base["timestamp"] = parsed_ts.isoformat()
        except (ValueError, TypeError):
            pass

        base["source_ip"] = hostname if hostname != "-" else "0.0.0.0"
        base["message"] = msg_body or f"{app_name}: {msg_id}"
        base["event_id"] = hash(f"{facility}:{app_name}:{msg_id}") % 100000
        base["raw_data"] = {
            "format": "RFC5424",
            "facility": facility,
            "severity": severity,
            "hostname": hostname,
            "app_name": app_name,
            "proc_id": proc_id,
            "msg_id": msg_id,
            "raw": raw,
        }
        return base

    # ── RFC 3164 ──
    m = _RFC3164_RE.match(stripped)
    if m:
        pri = int(m.group(1))
        facility, severity = _decode_pri(pri)
        hostname = m.group(3)
        msg_body = m.group(4).strip()

        base["source_ip"] = hostname
        base["message"] = msg_body
        base["event_id"] = hash(f"{facility}:{hostname}") % 100000
        base["raw_data"] = {
            "format": "RFC3164",
            "facility": facility,
            "severity": severity,
            "hostname": hostname,
            "raw": raw,
        }
        return base

    # ── Plain-text Fallback ──
    base["message"] = stripped or "Empty syslog message"
    base["event_id"] = 0
    return base


# ═══════════════════════════════════════════════════════════════════
#  UDP PROTOCOL (PRODUCER)
# ═══════════════════════════════════════════════════════════════════
class SyslogUDPProtocol(asyncio.DatagramProtocol):
    """
    High-throughput UDP receiver. Decodes datagrams, parses them into
    the WarSOC schema, and pushes to the async buffer queue.
    Drops packets silently on queue overflow to prevent OOM.
    """

    def __init__(self, queue: asyncio.Queue):
        self._queue = queue
        self._received = 0
        self._dropped = 0

    def connection_made(self, transport):
        self._transport = transport
        logger.info(f"UDP socket bound. Listening for syslog datagrams...")

    def datagram_received(self, data: bytes, addr: tuple):
        self._received += 1

        try:
            raw = data.decode("utf-8", errors="replace").strip()
        except Exception:
            return

        if not raw:
            return

        log_dict = parse_syslog(raw)

        # Override source_ip with the actual sender address if the parser
        # couldn't extract one from the message body.
        sender_ip = addr[0] if addr else None
        log_dict["network_source_ip"] = sender_ip
        if sender_ip and log_dict.get("source_ip") in ("0.0.0.0", "-", ""):
            log_dict["source_ip"] = sender_ip

        try:
            self._queue.put_nowait(log_dict)
        except asyncio.QueueFull:
            self._dropped += 1
            if self._dropped % 1000 == 1:
                logger.critical(
                    f"BUFFER FULL — packet dropped (total dropped: {self._dropped}, "
                    f"received: {self._received}, queue: {self._queue.qsize()}/{BUFFER_MAX}). "
                    f"Increase DRAIN_BATCH_SIZE or add Redis capacity."
                )

    def error_received(self, exc):
        logger.warning(f"UDP socket error: {exc}")

    def connection_lost(self, exc):
        if exc:
            logger.error(f"UDP connection lost: {exc}")


# ═══════════════════════════════════════════════════════════════════
#  REDIS DRAINER (CONSUMER)
# ═══════════════════════════════════════════════════════════════════
async def drain_to_redis(queue: asyncio.Queue, pool: aioredis.ConnectionPool, db):
    """
    Continuously pulls from the in-memory buffer queue and pushes
    batches into the raw_logs_queue Redis Stream via pipeline.
    Uses batch + interval hybrid flush for throughput.
    """
    redis = aioredis.Redis(connection_pool=pool)
    drained_total = 0
    ip_tenant_cache = {}

    logger.info(
        f"Drainer online (batch={DRAIN_BATCH_SIZE}, interval={DRAIN_INTERVAL*1000:.0f}ms)"
    )

    while True:
        batch = []
        try:
            # Block until at least one item is available
            first = await queue.get()
            batch.append(first)

            # Drain up to DRAIN_BATCH_SIZE without blocking
            while len(batch) < DRAIN_BATCH_SIZE:
                try:
                    item = queue.get_nowait()
                    batch.append(item)
                except asyncio.QueueEmpty:
                    break

            # Pipeline push to Redis Stream
            async with redis.pipeline(transaction=False) as pipe:
                for log_dict in batch:
                    src_ip = log_dict.get("network_source_ip") or log_dict.get("source_ip")
                    tenant_id = ip_tenant_cache.get(src_ip)
                    if not tenant_id:
                        agent = await db['agents'].find_one({"last_ip": src_ip})
                        if agent and agent.get("tenant_id"):
                            tenant_id = agent.get("tenant_id")
                        else:
                            tenant_id = TENANT_ID
                        ip_tenant_cache[src_ip] = tenant_id
                    
                    log_dict["tenant_id"] = tenant_id
                    stream_payload = {"payload": json.dumps(log_dict, default=str)}
                    await pipe.xadd(
                        RAW_LOGS_QUEUE,
                        stream_payload,
                        maxlen=RAW_LOGS_QUEUE_MAXLEN,
                        approximate=True,
                    )
                await pipe.execute()

            drained_total += len(batch)
            if drained_total % 500 == 0:
                logger.info(
                    f"Drained {drained_total} total | queue={queue.qsize()}/{BUFFER_MAX}"
                )

        except aioredis.ConnectionError as e:
            logger.error(f"Redis connection lost: {e}. Re-queuing {len(batch)} items...")
            # Re-queue the batch so nothing is lost
            for item in batch:
                try:
                    queue.put_nowait(item)
                except asyncio.QueueFull:
                    pass
            await asyncio.sleep(1)

        except aioredis.RedisError as e:
            logger.error(f"Redis error: {e}. Retrying in 1s...")
            for item in batch:
                try:
                    queue.put_nowait(item)
                except asyncio.QueueFull:
                    pass
            await asyncio.sleep(1)

        except asyncio.CancelledError:
            # Graceful shutdown: flush remaining items
            if batch:
                try:
                    async with redis.pipeline(transaction=False) as pipe:
                        for log_dict in batch:
                            src_ip = log_dict.get("network_source_ip") or log_dict.get("source_ip")
                            tenant_id = ip_tenant_cache.get(src_ip, TENANT_ID)
                            log_dict["tenant_id"] = tenant_id
                            await pipe.xadd(
                                RAW_LOGS_QUEUE,
                                {"payload": json.dumps(log_dict, default=str)},
                                maxlen=RAW_LOGS_QUEUE_MAXLEN,
                                approximate=True,
                            )
                        await pipe.execute()
                    logger.info(f"Flushed {len(batch)} remaining items on shutdown.")
                except Exception:
                    pass
            raise

        except Exception as e:
            logger.exception(f"Unexpected drainer error: {e}")
            await asyncio.sleep(0.5)

        # Yield control between drain cycles
        await asyncio.sleep(DRAIN_INTERVAL)


# ═══════════════════════════════════════════════════════════════════
#  HEALTH STATS REPORTER
# ═══════════════════════════════════════════════════════════════════
async def stats_reporter(queue: asyncio.Queue, protocol_ref: list):
    """Periodic stats logger for observability."""
    while True:
        await asyncio.sleep(30)
        proto = protocol_ref[0] if protocol_ref else None
        received = proto._received if proto else 0
        dropped = proto._dropped if proto else 0
        logger.info(
            f"[STATS] received={received} | dropped={dropped} | "
            f"queue={queue.qsize()}/{BUFFER_MAX} | "
            f"drop_rate={dropped/max(received,1)*100:.2f}%"
        )


# ═══════════════════════════════════════════════════════════════════
#  MAIN
# ═══════════════════════════════════════════════════════════════════
async def main():
    logger.info("╔══════════════════════════════════════════════════╗")
    logger.info("║   WARSOC TIER 2 — SYSLOG RECEIVER ONLINE       ║")
    logger.info("╚══════════════════════════════════════════════════╝")
    logger.info(f"  Redis:     {REDIS_HOST}:{REDIS_PORT} (TLS={REDIS_TLS})")
    logger.info(f"  Tenant:    {TENANT_ID}")
    logger.info(f"  UDP Port:  {SYSLOG_PORT}")
    logger.info(f"  Buffer:    {BUFFER_MAX} slots")
    logger.info(f"  Stream:    {RAW_LOGS_QUEUE}")

    # ─── Redis Connection Pool ───
    redis_url = (
        f"{'rediss' if REDIS_TLS else 'redis'}://"
        f":{REDIS_PASSWORD}@{REDIS_HOST}:{REDIS_PORT}"
        if REDIS_PASSWORD
        else f"{'rediss' if REDIS_TLS else 'redis'}://{REDIS_HOST}:{REDIS_PORT}"
    )
    pool = aioredis.ConnectionPool.from_url(
        redis_url,
        decode_responses=True,
        max_connections=10,
    )

    # Verify Redis connectivity
    test_redis = aioredis.Redis(connection_pool=pool)
    try:
        await test_redis.ping()
        logger.info("✅ Redis connection verified.")
    except Exception as e:
        logger.critical(f"❌ Cannot connect to Redis at {REDIS_HOST}:{REDIS_PORT}: {e}")
        sys.exit(1)
    finally:
        await test_redis.close()

    # ─── MongoDB Connection ───
    mongo_uri = os.getenv("MONGODB_URI")
    if not mongo_uri:
        logger.critical("MONGODB_URI is required for syslog receiver persistence.")
        sys.exit(1)
    mongo_db_name = os.getenv("DB_NAME", "WarSOC_DB")
    mongo_client = AsyncIOMotorClient(mongo_uri)
    db = mongo_client[mongo_db_name]

    # ─── Buffer Queue ───
    queue = asyncio.Queue(maxsize=BUFFER_MAX)

    # ─── UDP Server ───
    loop = asyncio.get_running_loop()
    transport, protocol = await loop.create_datagram_endpoint(
        lambda: SyslogUDPProtocol(queue),
        local_addr=("0.0.0.0", SYSLOG_PORT),
    )
    protocol_ref = [protocol]
    logger.info(f"🛰️  UDP syslog listener active on 0.0.0.0:{SYSLOG_PORT}")

    # ─── Background Tasks ───
    drain_task = asyncio.create_task(drain_to_redis(queue, pool, db))
    stats_task = asyncio.create_task(stats_reporter(queue, protocol_ref))

    # ─── Graceful Shutdown ───
    stop_event = asyncio.Event()

    def _signal_handler():
        logger.info("Shutdown signal received. Draining buffer...")
        stop_event.set()

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, _signal_handler)
        except NotImplementedError:
            # Windows doesn't support add_signal_handler
            pass

    try:
        await stop_event.wait()
    except (KeyboardInterrupt, SystemExit):
        pass
    finally:
        logger.info("Shutting down...")
        transport.close()
        drain_task.cancel()
        stats_task.cancel()
        try:
            await asyncio.gather(drain_task, stats_task, return_exceptions=True)
        except Exception:
            pass
        await pool.disconnect()
        logger.info("🛑 Syslog receiver offline.")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
