"""
WarSOC Detection Worker (Phase 2: The Detection Engine)

Stateless, Redis-backed detection module for advanced threat correlation.

Architecture Rules:
  - ZERO PYTHON MEMORY STATE: No dicts, lists, or variables for counters.
  - REDIS IS TRUTH: All correlation windows live in Redis with TTLs.
  - TENANT ISOLATION: Every Redis key includes tenant_id.

This module exposes pure functions that can be called from the existing
siem_worker.py or run as a standalone consumer.
"""
import logging
import os
import socket
import time
import uuid
from datetime import datetime, timezone
from typing import Optional

import httpx
from redis.asyncio import Redis

logger = logging.getLogger("Detection-Worker")

# AbuseIPDB Configuration (compile-time constants, no Python state)
ABUSEIPDB_API_URL = "https://api.abuseipdb.com/api/v2/check"
ABUSEIPDB_CACHE_TTL = 86400  # 24 hours
ABUSEIPDB_TIMEOUT = 2.0      # seconds — strict to protect the worker
THREAT_SCORE_THRESHOLD = 80


# =================================================================
# REQUIREMENT 1: O(1) STATIC RULE MAP
# =================================================================
# Each entry maps a Windows Event ID to its MITRE ATT&CK classification.
# Lookup is O(1) dict access — no iteration, no regex, no branching.

CRITICAL_EVENT_MAP = {
    4648: {
        "mitre_tactic": "T1078 — Valid Accounts (Lateral Movement)",
        "severity": "HIGH",
        "summary": "Explicit credential use detected — possible Pass-the-Hash",
        "event_type": "EXPLICIT_CREDENTIAL_USE",
    },
    4769: {
        "mitre_tactic": "T1558.003 — Kerberoasting (Credential Access)",
        "severity": "HIGH",
        "summary": "Kerberos service ticket requested — possible Golden Ticket attack",
        "event_type": "KERBEROS_SERVICE_TICKET",
    },
    7045: {
        "mitre_tactic": "T1543.003 — Create or Modify System Process (Persistence)",
        "severity": "CRITICAL",
        "summary": "New system service installed — possible persistence mechanism",
        "event_type": "NEW_SERVICE_INSTALLED",
    },
    4719: {
        "mitre_tactic": "T1562.001 — Impair Defenses: Disable or Modify Tools (Defense Evasion)",
        "severity": "CRITICAL",
        "summary": "System audit policy changed — possible defense evasion attempt",
        "event_type": "AUDIT_POLICY_CHANGED",
    },
    4698: {
        "mitre_tactic": "T1053.005 — Scheduled Task/Job (Persistence)",
        "severity": "MEDIUM",
        "summary": "Scheduled task created — possible persistence mechanism",
        "event_type": "SCHEDULED_TASK_CREATED",
    },
}


def _build_alert_payload(
    tenant_id: str,
    event_id: int,
    severity: str,
    summary: str,
    mitre_tactic: str,
    source_ip: str,
    user: str,
    message: str,
) -> dict:
    """
    Constructs a standardized alert payload compatible with the
    AlertResponse schema and the security_alerts MongoDB collection.
    """
    return {
        "alert_id": uuid.uuid4().hex,
        "tenant_id": tenant_id,
        "event_id": event_id,
        "severity": severity,
        "status": "NEW",
        "assignee_id": None,
        "resolution_notes": None,
        "mitre_tactic": mitre_tactic,
        "summary": summary,
        "source_ip": source_ip,
        "user": user,
        "message": message,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "_retention_ts": datetime.now(timezone.utc),
    }


def evaluate_static_rules(log_data: dict) -> Optional[dict]:
    """
    O(1) static rule evaluation.

    Checks the log's event_id against the CRITICAL_EVENT_MAP.
    Returns a fully formed alert payload if matched, None otherwise.

    No loops, no regex, no state — one dict lookup.
    """
    raw_event_id = log_data.get("event_id")
    try:
        event_id = int(raw_event_id)
    except (TypeError, ValueError):
        return None

    # BUSINESS RULE: 4688 (Process Creation) and 4689 (Process Termination) are NOISY.
    # We write them to MongoDB/Elasticsearch for forensic search, but they MUST NEVER
    # generate a standalone static alert. They are strictly context-only.
    if event_id in [4688, 4689]:
        return None

    rule = CRITICAL_EVENT_MAP.get(event_id)
    if rule is None:
        return None

    tenant_id = log_data.get("tenant_id", "UNKNOWN")

    return _build_alert_payload(
        tenant_id=tenant_id,
        event_id=event_id,
        severity=rule["severity"],
        summary=rule["summary"],
        mitre_tactic=rule["mitre_tactic"],
        source_ip=log_data.get("source_ip", "N/A"),
        user=log_data.get("user", "N/A"),
        message=log_data.get("message", ""),
    )


# =================================================================
# REQUIREMENT 2: STATEFUL BRUTE FORCE DETECTION (Redis)
# =================================================================

# Thresholds — no Python memory, these are compile-time constants only.
BRUTE_FORCE_THRESHOLD = 5
BRUTE_FORCE_WINDOW_SECONDS = 300  # 5 minutes


async def detect_brute_force(
    redis_client: Redis,
    tenant_id: str,
    event_id: int,
    username: str,
    ip_address: str,
) -> Optional[dict]:
    """
    Redis-backed brute force correlation.

    Only fires on Event 4625 (Failed Login). Uses an atomic Redis pipeline
    to INCR a counter and SET its expiry in a single round-trip.

    The counter key includes tenant_id for strict multi-tenant isolation.
    The 300-second TTL acts as the sliding correlation window.

    Returns an alert payload when the threshold is breached, None otherwise.
    """
    if event_id != 4625:
        return None

    # Tenant-isolated Redis key
    redis_key = f"brute_force:{tenant_id}:{username}"

    now_ms = int(time.time() * 1000)
    window_start_ms = now_ms - (BRUTE_FORCE_WINDOW_SECONDS * 1000)
    member = f"{now_ms}:{uuid.uuid4().hex}:{ip_address}"

    # True rolling window: remove entries older than 5 minutes before counting.
    # This prevents slow attacks from stretching a fixed TTL into a fake window.
    async with redis_client.pipeline(transaction=True) as pipe:
        pipe.zadd(redis_key, {member: now_ms})
        pipe.zremrangebyscore(redis_key, 0, window_start_ms)
        pipe.zcard(redis_key)
        pipe.expire(redis_key, BRUTE_FORCE_WINDOW_SECONDS + 60)
        results = await pipe.execute()

    current_count = int(results[2])

    if current_count < BRUTE_FORCE_THRESHOLD:
        return None

    # Fire exactly once at the threshold boundary to prevent alert flooding.
    # Subsequent failures within the window are counted but don't re-alert.
    if current_count > BRUTE_FORCE_THRESHOLD:
        return None

    return _build_alert_payload(
        tenant_id=tenant_id,
        event_id=4625,
        severity="HIGH",
        summary=f"Brute force attack detected: {current_count} failed logins "
                f"from {ip_address} as '{username}' within 5 minutes",
        mitre_tactic="T1110 — Brute Force (Credential Access)",
        source_ip=ip_address,
        user=username,
        message=f"Failed login threshold breached: {current_count}/{BRUTE_FORCE_THRESHOLD}",
    )


# =================================================================
# REQUIREMENT 3: THREAT INTELLIGENCE ENRICHMENT (AbuseIPDB)
# =================================================================

# Private/internal IP prefixes — skip API calls for these.
_PRIVATE_PREFIXES = (
    "10.", "172.16.", "172.17.", "172.18.", "172.19.",
    "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
    "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
    "172.30.", "172.31.", "192.168.", "127.", "0.", "::1",
)


async def check_ip_reputation(redis_client: Redis, ip_address: str) -> Optional[int]:
    """
    Write-through cached IP reputation check against AbuseIPDB.

    Flow:
      1. Check Redis cache (key: ip_rep:{ip}).
      2. On HIT:  Return cached score instantly. Zero network cost.
      3. On MISS: Call AbuseIPDB API with a strict 2s timeout.
      4. Cache the result with SETEX (24-hour TTL) and return.

    Returns the abuseConfidenceScore (0-100) or None if the check
    failed or the IP is internal.
    """
    # Skip private/internal IPs — they are never in abuse databases
    if not ip_address or ip_address.startswith(_PRIVATE_PREFIXES):
        return None

    cache_key = f"ip_rep:{ip_address}"

    # ── STEP 1: Redis Cache Check ──
    try:
        cached = await redis_client.get(cache_key)
        if cached is not None:
            return int(cached)
    except Exception as e:
        logger.warning(f"[THREAT-INTEL] Redis cache read failed: {e}")

    # ── STEP 2: Cache Miss — Call AbuseIPDB ──
    api_key = os.environ.get("ABUSEIPDB_API_KEY", "")
    if not api_key:
        logger.debug("[THREAT-INTEL] ABUSEIPDB_API_KEY not configured. Skipping.")
        return None

    try:
        async with httpx.AsyncClient(timeout=ABUSEIPDB_TIMEOUT) as client:
            response = await client.get(
                ABUSEIPDB_API_URL,
                headers={
                    "Key": api_key,
                    "Accept": "application/json",
                },
                params={
                    "ipAddress": ip_address,
                    "maxAgeInDays": "90",
                },
            )
            response.raise_for_status()
            data = response.json()
            score = int(data.get("data", {}).get("abuseConfidenceScore", 0))

    except httpx.TimeoutException:
        logger.warning(f"[THREAT-INTEL] AbuseIPDB timeout for {ip_address}. Skipping.")
        return None
    except httpx.HTTPStatusError as e:
        logger.warning(f"[THREAT-INTEL] AbuseIPDB HTTP {e.response.status_code} for {ip_address}.")
        return None
    except Exception as e:
        logger.warning(f"[THREAT-INTEL] AbuseIPDB call failed for {ip_address}: {e}")
        return None

    # ── STEP 3: Write-Through Cache ──
    try:
        await redis_client.setex(cache_key, ABUSEIPDB_CACHE_TTL, score)
    except Exception as e:
        logger.warning(f"[THREAT-INTEL] Redis cache write failed: {e}")

    return score


# =================================================================
# REQUIREMENT 4: MAIN PROCESSING FLOW
# =================================================================

async def process_log(redis_client: Redis, log_payload: dict) -> list[dict]:
    """
    Master log router. Takes an incoming log and routes it through
    all detection stages sequentially.

    Returns a list of generated alert payloads (0, 1, or many).
    The caller is responsible for persisting them to MongoDB and
    publishing to Redis PubSub.

    Detection Pipeline:
      1. Static Rule Map (O(1) lookup)
      2. Brute Force Correlation (Redis-backed)
      3. Threat Intel Enrichment (AbuseIPDB + Redis cache)
      [Future: 4. Sigma Rule Engine]
    """
    alerts = []

    tenant_id = log_payload.get("tenant_id", "UNKNOWN")
    raw_event_id = log_payload.get("event_id", 0)
    try:
        event_id = int(raw_event_id)
    except (TypeError, ValueError):
        event_id = 0

    username = log_payload.get("user", "unknown")
    ip_address = log_payload.get("source_ip", "0.0.0.0")

    # ── STAGE 1: Static Rule Evaluation ──
    static_alert = evaluate_static_rules(log_payload)
    if static_alert:
        alerts.append(static_alert)

    # ── STAGE 2: Brute Force Correlation ──
    brute_alert = await detect_brute_force(
        redis_client,
        tenant_id,
        event_id,
        username,
        ip_address,
    )
    if brute_alert:
        alerts.append(brute_alert)

    # ── STAGE 3: Threat Intel Enrichment ──
    threat_score = await check_ip_reputation(redis_client, ip_address)
    if threat_score is not None and threat_score > THREAT_SCORE_THRESHOLD:
        threat_alert = _build_alert_payload(
            tenant_id=tenant_id,
            event_id=event_id,
            severity="CRITICAL",
            summary=f"Malicious IP detected: {ip_address} "
                    f"(AbuseIPDB confidence: {threat_score}%)",
            mitre_tactic="TA0001 — Initial Access (External Threat)",
            source_ip=ip_address,
            user=username,
            message=f"AbuseIPDB threat score {threat_score}/100 exceeds "
                    f"threshold of {THREAT_SCORE_THRESHOLD}. "
                    f"Source IP flagged as high-confidence malicious.",
        )
        alerts.append(threat_alert)

    # ── STAGE 4: [FUTURE] Sigma Rule Engine ──

    return alerts


# =================================================================
# REQUIREMENT 5: REDIS CONSUMER LOOP
# =================================================================

import asyncio
import json
from redis import exceptions as redis_exceptions
from motor.motor_asyncio import AsyncIOMotorClient
from app.config.config import get_settings
from app.utils.observability import record_worker_heartbeat_async

# Stream configuration
STREAM_NAME = os.environ.get("DETECTION_STREAM", "raw_logs_queue")
GROUP_NAME = "threat_hunters"
CONSUMER_NAME = os.environ.get("CONSUMER_NAME", f"threat_hunter_{socket.gethostname()}")
BLOCK_MS = 5000
BATCH_SIZE = 50


async def main():
    """
    Redis Stream consumer loop for the Detection Engine.

    Architecture:
      - Listens on the same stream as siem_worker (raw_logs_queue)
      - Uses its OWN consumer group (threat_hunters) for fan-out:
        both siem_group and threat_hunters independently receive
        every message.
      - Consumer name is pulled from env for horizontal scaling.
      - Single bad log cannot crash the process.
    """
    settings = get_settings()

    # ── Initialize Connections ──
    redis_client = await Redis.from_url(
        settings.redis_url, decode_responses=True
    )
    mongo_client = AsyncIOMotorClient(settings.mongodb_uri)
    db = mongo_client[settings.mongodb_db_name]

    logger.info(f"Detection Worker [{CONSUMER_NAME}] initializing...")
    logger.info(f"  Stream:   {STREAM_NAME}")
    logger.info(f"  Group:    {GROUP_NAME}")
    logger.info(f"  Consumer: {CONSUMER_NAME}")

    # ── Create Consumer Group (Idempotent) ──
    while True:
        try:
            await redis_client.xgroup_create(
                STREAM_NAME, GROUP_NAME, id="0", mkstream=True
            )
            logger.info(f"Created consumer group: {GROUP_NAME}")
            break
        except redis_exceptions.ResponseError as e:
            if "BUSYGROUP" in str(e):
                logger.info(f"Consumer group {GROUP_NAME} already exists. Joining.")
                break
            logger.error(f"Group creation error: {e}. Retrying in 2s...")
            await asyncio.sleep(2)
        except redis_exceptions.ConnectionError as e:
            logger.warning(f"Redis unavailable: {e}. Retrying in 2s...")
            await asyncio.sleep(2)

    logger.info(f"Detection Worker [{CONSUMER_NAME}] online. Awaiting logs...")

    # ── Main Consumer Loop ──
    while True:
        try:
            await record_worker_heartbeat_async("detection_worker")
            streams = await redis_client.xreadgroup(
                GROUP_NAME,
                CONSUMER_NAME,
                {STREAM_NAME: ">"},
                count=BATCH_SIZE,
                block=BLOCK_MS,
            )

            if not streams:
                continue

            for _, messages in streams:
                for message_id, payload in messages:
                    try:
                        # Parse the JSON log from the stream entry
                        raw = payload.get("payload", "")
                        if not raw:
                            logger.warning(
                                f"Empty payload in {message_id}. Acking."
                            )
                            await redis_client.xack(
                                STREAM_NAME, GROUP_NAME, message_id
                            )
                            continue

                        try:
                            log_data = json.loads(raw)
                        except json.JSONDecodeError:
                            logger.error(
                                f"[POISON] Unparseable JSON in {message_id}. "
                                f"Discarding."
                            )
                            await redis_client.xack(
                                STREAM_NAME, GROUP_NAME, message_id
                            )
                            continue

                        # Route through all detection stages
                        alerts = await process_log(redis_client, log_data)

                        # Persist and broadcast each generated alert
                        for alert in alerts:
                            try:
                                await db.security_alerts.insert_one(alert)
                            except Exception as db_err:
                                logger.error(
                                    f"[DB] Alert insert failed: {db_err}"
                                )
                                continue

                            # Publish to WebSocket bridge
                            try:
                                await redis_client.publish(
                                    "security_alerts",
                                    json.dumps(alert, default=str),
                                )
                            except Exception as pub_err:
                                logger.warning(
                                    f"[PUBSUB] Publish failed: {pub_err}"
                                )

                            logger.info(
                                f"[ALERT] {alert['severity']}: "
                                f"{alert['summary']}"
                            )

                        # CRITICAL: Acknowledge AFTER all processing succeeds
                        await redis_client.xack(
                            STREAM_NAME, GROUP_NAME, message_id
                        )

                    except Exception as e:
                        # Per-message isolation: one bad log never kills
                        # the worker. Log the error and move on.
                        logger.error(
                            f"[PROCESS] Error on {message_id}: {e}"
                        )
                        # Still ack to prevent infinite reprocessing loops
                        try:
                            await redis_client.xack(
                                STREAM_NAME, GROUP_NAME, message_id
                            )
                        except Exception:
                            pass

            await record_worker_heartbeat_async("detection_worker")

        except redis_exceptions.ConnectionError as e:
            logger.warning(f"Redis connection lost: {e}. Reconnecting in 2s...")
            await asyncio.sleep(2)
        except Exception as e:
            logger.error(f"[FATAL] Pipeline crash: {e}")
            await asyncio.sleep(1)


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [DETECTION] %(message)s",
    )
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Detection Worker shutting down gracefully.")
