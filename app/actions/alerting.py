import hashlib
import json
import logging
from redis.asyncio import Redis

from app.config.config import get_settings

logger = logging.getLogger("Alerting-Bridge")
settings = get_settings()


EMAIL_TRIGGER_SEVERITIES = {"HIGH", "CRITICAL", "ALERT"}


def normalize_pack_id(pack_id: str | None) -> str:
    aliases = {
        "siem": "SIEM",
        "peca": "peca_forensic",
        "peca_forensic": "peca_forensic",
        "peca_vault": "peca_forensic",
        "eto": "peca_forensic",
        "eto_forensic": "peca_forensic",
        "fbr": "fbr_pos",
        "fbr_pos": "fbr_pos",
        "fbr_pos_shield": "fbr_pos",
    }
    key = str(pack_id or "").strip().lower()
    return aliases.get(key, key)


def is_email_trigger_severity(severity: str | None) -> bool:
    return str(severity or "").strip().upper() in EMAIL_TRIGGER_SEVERITIES


async def dispatch_alert_if_entitled(
    db, redis: Redis, tenant_id: str, alert_data: dict, required_pack: str
) -> bool:
    """
    Entitlement Gate: Dispatches an alert to the mail worker only if the tenant 
    is actively subscribed to the required compliance pack.
    """
    if not settings.enable_security_alert_emails:
        logger.debug("Security-alert email delivery is disabled; dashboard alert remains active.")
        return False
    if not tenant_id:
        return False
        
    try:
        # The Gate: Always route alerts to the tenant administrator, not a random analyst
        user = await db.users.find_one(
            {"tenant_id": tenant_id, "role": {"$in": ["admin", "Admin", "ADMIN"]}}
        )
        if not user:
            user = await db.users.find_one({"tenant_id": tenant_id})
        if not user:
            logger.warning(f"Alert dropped: No user found for tenant {tenant_id}")
            return False
        if user.get("has_active_plan") is False:
            logger.info(f"Alert dropped: Tenant {tenant_id} does not have an active plan.")
            return False
            
        normalized_required_pack = normalize_pack_id(required_pack)
        packs = {normalize_pack_id(pack) for pack in user.get("compliance_packs", [])}
        if normalized_required_pack != "SIEM" and normalized_required_pack not in packs:
            logger.info(f"Alert dropped: Tenant {tenant_id} not entitled to {required_pack} alerts.")
            return False

        # Sanitize (Strip encrypted payloads and db IDs)
        rule_id = str(
            alert_data.get("matched_rule_id")
            or alert_data.get("event_id")
            or alert_data.get("rule_id")
            or required_pack
            or "unknown"
        ).strip()
        if not rule_id:
            rule_id = hashlib.sha256(f"{tenant_id}:{required_pack}".encode("utf-8")).hexdigest()[:16]

        alert_context = alert_data.get("context") if isinstance(alert_data.get("context"), dict) else {}
        sanitized_alert = {
            "rule_id": rule_id,
            "incident_id": alert_data.get("incident_id"),
            "event_id": alert_data.get("event_id", "UNKNOWN"),
            "severity": alert_data.get("matched_rule_severity", "High"),
            "name": alert_data.get("event", alert_data.get("tags", "Security Event")),
            "timestamp": str(alert_data.get("timestamp", alert_data.get("ingested_at", ""))),
            "source_ip": alert_data.get("source_ip", "Unknown"),
            "user": alert_data.get("user", "System"),
            "agent_id": alert_data.get("agent_id") or alert_context.get("agent_id"),
            "target": alert_data.get("target") or alert_context.get("target"),
            "recipient": user.get("email") or user.get("username") or tenant_id,
        }

        incident_identity = str(alert_data.get("incident_id") or "").strip()
        if not incident_identity:
            incident_identity = hashlib.sha256(
                ":".join(
                    str(value or "unknown").strip().lower()
                    for value in (
                        rule_id,
                        sanitized_alert.get("agent_id"),
                        sanitized_alert.get("source_ip"),
                        sanitized_alert.get("user"),
                        sanitized_alert.get("target"),
                    )
                ).encode("utf-8")
            ).hexdigest()[:24]
        lock_key = f"alert_lock:{tenant_id}:{incident_identity}"
        acquired = await redis.set(lock_key, "1", nx=True, ex=300)
        if not acquired:
            logger.info(f"Duplicate alert dropped for tenant {tenant_id} rule {rule_id}.")
            return True

        job_payload = {
            "type": "security_alert_email",
            "payload": sanitized_alert,
            "tenant_id": tenant_id,
            "required_pack": required_pack,
            "lock_key": lock_key,
        }
        
        try:
            await redis.lpush("email_alert_queue", json.dumps(job_payload))
        except Exception:
            try:
                await redis.delete(lock_key)
            except Exception:
                pass
            raise

        logger.info(f"Dispatched {required_pack} alert to email queue for {tenant_id}")
        return True
        
    except Exception as e:
        logger.error(f"Failed to dispatch alert for {tenant_id}: {e}")
        return False
