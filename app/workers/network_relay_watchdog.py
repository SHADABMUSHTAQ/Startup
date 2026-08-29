"""
Network Relay Watchdog: Proactive SILENT/DEGRADED/OFFLINE notification.

Scans network_relay_device_status for devices that have stopped sending
evidence (DEVICE_SILENT) or are reporting failures without new events
(DEGRADED), and network_relays for relays whose last_seen is stale while
still marked active (RELAY_OFFLINE). Devices declared on a relay that have
never produced an event are also treated as silent once the silence window
has passed since registration.

Alerts are durable SIEM alerts: each one is persisted into security_alerts
(idempotent by alert_uid, seven-day hot window, archive-before-delete via the
storage archiver) and becomes visible through the standard alert and incident
APIs. The post-insert fan-out — operator incident projection, live dashboard
stream, tenant-admin email — is retried, so a transient Redis hiccup can
never erase the durable alert. Failed delivery channels remain pending in
Mongo and are retried by later watchdog cycles.

Health definitions mirror _relay_public_status / _device_public_status in
app/routes/network_relay.py so the watchdog and the status route can never
disagree about what SILENT, DEGRADED, or OFFLINE means.

Architecture: Called periodically by compliance_cron (every watchdog_interval_seconds).
"""

import asyncio
import json
import logging
from datetime import datetime, timedelta, timezone
from typing import Any

from pymongo.errors import DuplicateKeyError

from app.actions.alerting import dispatch_alert_if_entitled
from app.utils.security_incidents import project_and_publish_incident

logger = logging.getLogger(__name__)

# Relay-level offline threshold mirrors _relay_public_status: a relay whose
# last_seen is missing or older than 900s is OFFLINE while still marked active.
RELAY_OFFLINE_SECONDS = 900

# Watchdog alerts follow the security_alerts seven-day hot-feed convention:
# the storage archiver owns removal after the evidence is projected and
# archived — the same lifecycle as every other SIEM alert.
ALERT_HOT_RETENTION_DAYS = 7

# Attempts for post-insert fan-out (incident projection, dashboard stream,
# email dispatch). The durable security_alerts document is already committed
# when these run; retries only protect the live notification path.
ALERT_FANOUT_ATTEMPTS = 3
ALERT_FANOUT_RETRY_SECONDS = 60
ALERT_FANOUT_SCAN_LIMIT = 500
DELIVERY_CHANNELS = ("incident", "stream", "email")


def _parse_utc(value) -> datetime | None:
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc) if value.tzinfo else value.replace(tzinfo=timezone.utc)
    return None


async def _scan_silent_devices(db, *, silence_seconds: int, now: datetime) -> list[dict[str, Any]]:
    """Devices whose last evidence is older than silence_seconds — including
    devices that have never produced an event (no observation document at all,
    or a health-only observation without last_event_at). Never-reported
    devices are anchored to their observation/relay creation time so a fresh
    installation inside the grace window is not instantly flagged."""
    cutoff = now - timedelta(seconds=silence_seconds)
    # Observed devices: stale last_event_at, or an observation document that
    # never recorded an event (health reports only).
    cursor = db["network_relay_device_status"].find(
        {
            "$or": [
                {"last_event_at": {"$lt": cutoff}},
                {"last_event_at": None},
                {"last_event_at": {"$exists": False}},
            ]
        },
        {
            "tenant_id": 1,
            "relay_id": 1,
            "device_id": 1,
            "vendor": 1,
            "model": 1,
            "last_event_at": 1,
            "last_failure_at": 1,
            "created_at": 1,
        },
    )
    candidates: dict[tuple[str, str, str], dict[str, Any]] = {}
    for doc in await cursor.to_list(length=1000):
        key = (
            str(doc.get("tenant_id") or ""),
            str(doc.get("relay_id") or ""),
            str(doc.get("device_id") or ""),
        )
        if not all(key):
            continue
        if doc.get("last_event_at") is None:
            # Health-only observation (or legacy document) with no recorded
            # evidence: anchor the silence to first observation; fail closed
            # when even that is unknown.
            anchor = _parse_utc(doc.get("created_at"))
            if anchor is not None and anchor >= cutoff:
                continue
        candidates[key] = doc

    # Declared devices with NO observation document at all: silent once the
    # relay registration itself is older than the silence window.
    relay_cursor = db["network_relays"].find(
        {
            "status": {"$nin": ["revoked", "inactive"]},
            "devices": {"$exists": True, "$ne": []},
        },
        {"tenant_id": 1, "relay_id": 1, "created_at": 1, "devices": 1},
    )
    relays = await relay_cursor.to_list(length=1000)
    if relays:
        relay_ids = sorted(
            {str(relay.get("relay_id") or "") for relay in relays if relay.get("relay_id")}
        )
        observed_keys: set[tuple[str, str, str]] = set()
        observed_cursor = db["network_relay_device_status"].find(
            {"relay_id": {"$in": relay_ids}},
            {"tenant_id": 1, "relay_id": 1, "device_id": 1},
        )
        async for row in observed_cursor:
            observed_keys.add(
                (
                    str(row.get("tenant_id") or ""),
                    str(row.get("relay_id") or ""),
                    str(row.get("device_id") or ""),
                )
            )
        for relay in relays:
            tenant_id = str(relay.get("tenant_id") or "")
            relay_id = str(relay.get("relay_id") or "")
            if not tenant_id or not relay_id:
                continue
            registered_at = _parse_utc(relay.get("created_at"))
            if registered_at is not None and registered_at >= cutoff:
                continue
            for device in relay.get("devices") or []:
                device_id = str(device.get("device_id") or "")
                if not device_id or (tenant_id, relay_id, device_id) in observed_keys:
                    continue
                candidates[(tenant_id, relay_id, device_id)] = {
                    "tenant_id": tenant_id,
                    "relay_id": relay_id,
                    "device_id": device_id,
                    "vendor": device.get("vendor"),
                    "model": device.get("model"),
                    "last_event_at": None,
                }
    return list(candidates.values())


async def _scan_degraded_devices(
    db, *, silence_seconds: int, now: datetime
) -> list[dict[str, Any]]:
    """Devices reporting failures (last_failure_at >= last_event_at) that are
    not yet silent — mirrors the DEGRADED branch of _device_public_status."""
    cutoff = now - timedelta(seconds=silence_seconds)
    cursor = db["network_relay_device_status"].find(
        {
            # Device is still delivering within the silence window…
            "last_event_at": {"$gte": cutoff},
            # …but its most recent health report is a failure.
            "$expr": {"$gte": ["$last_failure_at", "$last_event_at"]},
        },
        {
            "tenant_id": 1,
            "relay_id": 1,
            "device_id": 1,
            "vendor": 1,
            "model": 1,
            "last_event_at": 1,
            "last_failure_at": 1,
            "last_failure_reason": 1,
            "last_reported_drops": 1,
        },
    )
    return await cursor.to_list(length=1000)


async def _scan_offline_relays(db, *, now: datetime) -> list[dict[str, Any]]:
    """Active relays whose last_seen is missing or older than 900s —
    mirrors the OFFLINE branch of _relay_public_status."""
    cutoff = now - timedelta(seconds=RELAY_OFFLINE_SECONDS)
    cursor = db["network_relays"].find(
        {
            "status": {"$nin": ["revoked", "inactive"]},
            "$or": [
                {"last_seen": None},
                {"last_seen": {"$exists": False}},
                {"last_seen": {"$lt": cutoff}},
            ],
        },
        {
            "tenant_id": 1,
            "relay_id": 1,
            "last_seen": 1,
            "version": 1,
        },
    )
    return await cursor.to_list(length=1000)


async def _retry_fanout(
    operation, *, description: str, alert_key: str
) -> tuple[bool, int, str | None]:
    """Run one post-insert fan-out step with bounded retries. The durable
    alert is already committed when this runs; a final failure is logged,
    never raised, so one degraded channel cannot abort the rest."""
    for attempt in range(1, ALERT_FANOUT_ATTEMPTS + 1):
        try:
            await operation()
            return True, attempt, None
        except Exception as exc:
            if attempt >= ALERT_FANOUT_ATTEMPTS:
                logger.warning(
                    "Failed to %s for network relay alert %s after %s attempts: %s",
                    description,
                    alert_key,
                    attempt,
                    exc,
                )
                return False, attempt, type(exc).__name__
            await asyncio.sleep(0.2 * attempt)
    return False, ALERT_FANOUT_ATTEMPTS, "UnknownDeliveryError"


def _new_delivery_state(now: datetime) -> dict[str, Any]:
    return {
        "incident_pending": True,
        "stream_pending": True,
        "email_pending": True,
        "attempts": {channel: 0 for channel in DELIVERY_CHANNELS},
        "errors": {},
        "next_attempt_at": now,
        "last_attempt_at": None,
        "completed_at": None,
    }


def _operator_alert_payload(alert: dict[str, Any]) -> dict[str, Any]:
    return {
        key: value
        for key, value in alert.items()
        if key not in {"_id", "watchdog_delivery"}
    }


async def _record_delivery_result(
    db,
    *,
    alert: dict[str, Any],
    channel: str,
    success: bool,
    attempts: int,
    error: str | None,
    now: datetime,
) -> None:
    update: dict[str, Any] = {
        "$set": {
            f"watchdog_delivery.{channel}_pending": not success,
            "watchdog_delivery.last_attempt_at": now,
        },
        "$inc": {f"watchdog_delivery.attempts.{channel}": attempts},
    }
    if error:
        update["$set"][f"watchdog_delivery.errors.{channel}"] = error
    else:
        update["$unset"] = {f"watchdog_delivery.errors.{channel}": ""}
    await db["security_alerts"].update_one({"_id": alert["_id"]}, update)


async def _deliver_alert(db, redis, alert: dict[str, Any], *, now: datetime) -> bool:
    """Attempt every pending channel and durably retain any failed channel."""
    delivery = alert.get("watchdog_delivery") or _new_delivery_state(now)
    operator_alert = _operator_alert_payload(alert)

    if delivery.get("incident_pending", True):

        async def _project_incident() -> None:
            nonlocal operator_alert
            operator_alert = await project_and_publish_incident(
                db,
                redis,
                operator_alert,
                publish_duplicates=True,
            )

        success, attempts, error = await _retry_fanout(
            _project_incident,
            description="project relay alert incident",
            alert_key=str(alert.get("alert_uid")),
        )
        await _record_delivery_result(
            db,
            alert=alert,
            channel="incident",
            success=success,
            attempts=attempts,
            error=error,
            now=now,
        )
        delivery["incident_pending"] = not success

    if delivery.get("stream_pending", True):
        if redis is None:
            success, attempts, error = False, 0, "RedisUnavailable"
        else:

            async def _publish_stream() -> None:
                await redis.publish(
                    "security_alerts", json.dumps(operator_alert, default=str)
                )

            success, attempts, error = await _retry_fanout(
                _publish_stream,
                description="publish relay alert to dashboard stream",
                alert_key=str(alert.get("alert_uid")),
            )
        await _record_delivery_result(
            db,
            alert=alert,
            channel="stream",
            success=success,
            attempts=attempts,
            error=error,
            now=now,
        )
        delivery["stream_pending"] = not success

    if delivery.get("email_pending", True):
        if redis is None:
            success, attempts, error = False, 0, "RedisUnavailable"
        else:

            async def _dispatch_email() -> None:
                await dispatch_alert_if_entitled(
                    db,
                    redis,
                    str(alert.get("tenant_id") or ""),
                    {
                        "matched_rule_id": alert.get("alert_uid"),
                        "event_id": alert.get("alert_uid"),
                        "matched_rule_severity": (
                            "High"
                            if str(alert.get("severity")).upper() == "HIGH"
                            else "Medium"
                        ),
                        "event": alert.get("summary"),
                        "timestamp": str(alert.get("timestamp") or ""),
                        "source_ip": "Unknown",
                        "user": "WarSOC Relay Watchdog",
                    },
                    "SIEM",
                    raise_on_error=True,
                )

            success, attempts, error = await _retry_fanout(
                _dispatch_email,
                description="dispatch relay alert email",
                alert_key=str(alert.get("alert_uid")),
            )
        await _record_delivery_result(
            db,
            alert=alert,
            channel="email",
            success=success,
            attempts=attempts,
            error=error,
            now=now,
        )
        delivery["email_pending"] = not success

    pending = any(delivery.get(f"{channel}_pending", True) for channel in DELIVERY_CHANNELS)
    await db["security_alerts"].update_one(
        {"_id": alert["_id"]},
        {
            "$set": {
                "watchdog_delivery.next_attempt_at": (
                    now + timedelta(seconds=ALERT_FANOUT_RETRY_SECONDS)
                    if pending
                    else None
                ),
                "watchdog_delivery.completed_at": None if pending else now,
            }
        },
    )
    return not pending


async def _retry_pending_deliveries(db, redis, *, now: datetime) -> dict[str, int]:
    cursor = (
        db["security_alerts"]
        .find(
            {
                "source": "network_relay_watchdog",
                "$and": [
                    {
                        "$or": [
                            {f"watchdog_delivery.{channel}_pending": True}
                            for channel in DELIVERY_CHANNELS
                        ]
                    },
                    {
                        "$or": [
                            {"watchdog_delivery.next_attempt_at": {"$lte": now}},
                            {"watchdog_delivery.next_attempt_at": None},
                            {"watchdog_delivery.next_attempt_at": {"$exists": False}},
                        ]
                    },
                ],
            }
        )
        .sort("watchdog_delivery.next_attempt_at", 1)
        .limit(ALERT_FANOUT_SCAN_LIMIT)
    )
    attempted = completed = 0
    async for alert in cursor:
        attempted += 1
        if await _deliver_alert(db, redis, alert, now=now):
            completed += 1
    return {"attempted": attempted, "completed": completed}


async def _emit_alert(
    db,
    redis,
    *,
    alert_key: str,
    alert_type: str,
    severity: str,
    tenant_id: str,
    summary: str,
    context: dict[str, Any],
    now: datetime,
    email_timestamp: str,
) -> bool:
    """Persist one durable SIEM alert into security_alerts (idempotent by
    alert_uid) and then fan out: project the operator incident, publish the
    live dashboard stream, and dispatch the tenant-admin email."""
    existing = await db["security_alerts"].find_one(
        {"tenant_id": tenant_id, "alert_uid": alert_key}
    )
    if existing:
        # Upgrade alerts created by an earlier watchdog build to the durable
        # delivery contract. The periodic pending scan handles the retry.
        if not existing.get("watchdog_delivery"):
            await db["security_alerts"].update_one(
                {"_id": existing["_id"]},
                {"$set": {"watchdog_delivery": _new_delivery_state(now)}},
            )
        return False

    alert_payload = {
        "tenant_id": tenant_id,
        "alert_uid": alert_key,
        "alert_type": alert_type,
        "type": alert_type,
        "severity": str(severity).upper(),
        "pack": "SIEM",
        "summary": summary,
        "timestamp": now,
        "created_at": now,
        "status": "NEW",
        "source": "network_relay_watchdog",
        "engine_source": "network_relay_watchdog",
        "event_uid": alert_key,
        "watchdog_delivery": _new_delivery_state(now),
        # Seven-day hot window: the storage archiver removes the evidence only
        # after projecting and archiving it, exactly like every other alert.
        "_expire_at": now + timedelta(days=ALERT_HOT_RETENTION_DAYS),
        **context,
    }

    try:
        await db["security_alerts"].insert_one(alert_payload)
    except DuplicateKeyError:
        return False
    except Exception as exc:
        logger.warning("Failed to persist network relay alert %s: %s", alert_key, exc)
        return False

    inserted = await db["security_alerts"].find_one(
        {"tenant_id": tenant_id, "alert_uid": alert_key}
    )
    if inserted:
        await _deliver_alert(db, redis, inserted, now=now)

    return True


async def run_network_relay_watchdog(
    db,
    redis,
    *,
    silence_seconds: int,
    now: datetime | None = None,
) -> dict[str, int]:
    """
    Main entry point: scan for offline relays, silent devices, and degraded
    devices, then emit window-keyed idempotent alerts.

    Returns a summary dict with counts.
    """
    now = now or datetime.now(timezone.utc)
    window_key = int(now.timestamp()) // silence_seconds
    delivery_retry = await _retry_pending_deliveries(db, redis, now=now)
    emitted = {"relay_offline": 0, "device_silent": 0, "device_degraded": 0}
    found = {"relay_offline": 0, "device_silent": 0, "device_degraded": 0}

    # 1. RELAY_OFFLINE — relay itself stopped delivering batches
    for relay in await _scan_offline_relays(db, now=now):
        found["relay_offline"] += 1
        tenant_id = relay.get("tenant_id")
        relay_id = relay.get("relay_id")
        if not tenant_id or not relay_id:
            continue
        last_seen = relay.get("last_seen")
        summary = (
            f"Network relay {relay_id} has not delivered a batch in over "
            f"{RELAY_OFFLINE_SECONDS}s while still marked active."
        )
        if await _emit_alert(
            db,
            redis,
            alert_key=f"{tenant_id}:{relay_id}:RELAY_OFFLINE:{window_key}",
            alert_type="RELAY_OFFLINE",
            severity="high",
            tenant_id=tenant_id,
            summary=summary,
            context={
                # Relay discriminator: the incident projector keys same-minute
                # alerts by (rule, event_id), so each relay gets its own incident.
                "event_id": relay_id,
                "relay_id": relay_id,
                "last_seen": last_seen,
                "version": relay.get("version"),
            },
            now=now,
            email_timestamp=last_seen.isoformat() if isinstance(last_seen, datetime) else str(last_seen),
        ):
            emitted["relay_offline"] += 1

    # 2. DEVICE_SILENT — device stopped sending evidence (or never started)
    for device in await _scan_silent_devices(db, silence_seconds=silence_seconds, now=now):
        found["device_silent"] += 1
        tenant_id = device.get("tenant_id")
        relay_id = device.get("relay_id")
        device_id = device.get("device_id")
        if not tenant_id or not relay_id or not device_id:
            continue
        last_event_at = _parse_utc(device.get("last_event_at"))
        if last_event_at is not None:
            summary = (
                f"Network relay device {device_id} (vendor={device.get('vendor')}) "
                f"has not sent evidence for {silence_seconds}s."
            )
            reference_iso = last_event_at.isoformat()
        else:
            summary = (
                f"Network relay device {device_id} (vendor={device.get('vendor')}) "
                f"has never sent evidence; it was expected to report at least "
                f"{silence_seconds}s after registration."
            )
            reference_iso = now.isoformat()
        if await _emit_alert(
            db,
            redis,
            alert_key=f"{tenant_id}:{relay_id}:{device_id}:DEVICE_SILENT:{window_key}",
            alert_type="DEVICE_SILENT",
            severity="high",
            tenant_id=tenant_id,
            summary=summary,
            context={
                # Device discriminator: keeps one operator incident per device
                # instead of merging every silent device detected in a minute.
                "event_id": device_id,
                "relay_id": relay_id,
                "device_id": device_id,
                "vendor": device.get("vendor"),
                "model": device.get("model"),
                "last_event_at": last_event_at,
                "silence_seconds": silence_seconds,
                "window_key": window_key,
            },
            now=now,
            email_timestamp=reference_iso,
        ):
            emitted["device_silent"] += 1

    # 3. DEVICE_DEGRADED — device is delivering but reporting failures
    for device in await _scan_degraded_devices(db, silence_seconds=silence_seconds, now=now):
        found["device_degraded"] += 1
        tenant_id = device.get("tenant_id")
        relay_id = device.get("relay_id")
        device_id = device.get("device_id")
        last_event_at = device.get("last_event_at")
        if not tenant_id or not relay_id or not device_id or not isinstance(last_event_at, datetime):
            continue
        drops = int(device.get("last_reported_drops") or 0)
        reason = device.get("last_failure_reason") or "unspecified"
        summary = (
            f"Network relay device {device_id} (vendor={device.get('vendor')}) is "
            f"degraded: reporting failures ({reason}) with {drops} dropped events."
        )
        if await _emit_alert(
            db,
            redis,
            alert_key=f"{tenant_id}:{relay_id}:{device_id}:DEVICE_DEGRADED:{window_key}",
            alert_type="DEVICE_DEGRADED",
            severity="medium",
            tenant_id=tenant_id,
            summary=summary,
            context={
                "event_id": device_id,
                "relay_id": relay_id,
                "device_id": device_id,
                "vendor": device.get("vendor"),
                "model": device.get("model"),
                "last_event_at": last_event_at,
                "last_failure_at": device.get("last_failure_at"),
                "last_failure_reason": reason,
                "last_reported_drops": drops,
                "window_key": window_key,
            },
            now=now,
            email_timestamp=last_event_at.isoformat(),
        ):
            emitted["device_degraded"] += 1

    return {
        "silent_devices_found": found["device_silent"],
        "degraded_devices_found": found["device_degraded"],
        "offline_relays_found": found["relay_offline"],
        "alerts_emitted": sum(emitted.values()),
        "pending_deliveries_attempted": delivery_retry["attempted"],
        "pending_deliveries_completed": delivery_retry["completed"],
        **{f"alerts_{k}_emitted": v for k, v in emitted.items()},
    }
