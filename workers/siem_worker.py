"""
WarSOC SIEM Worker — Standard Security Alert Processing
========================================================
Consumer Group: siem_group
Stream: raw_logs_queue

Completely isolated from FBR and PECA compliance workers.
Handles brute-force detection, malware keyword matching,
and suspicious process creation alerts.

Tenant Filter: subscription_plan == "SIEM_ONLY"
"""

import asyncio
import json
import logging
import sys
import os
from datetime import datetime, timezone
import redis.asyncio as aioredis
from motor.motor_asyncio import AsyncIOMotorClient

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from app.config.config import get_settings

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("SIEM-Worker")

settings = get_settings()

REDIS_STREAM = "raw_logs_queue"
CONSUMER_GROUP = "siem_group"
CONSUMER_NAME = "siem_worker_1"

# Load SIEM policy
siem_policy_path = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "app", "config", "siem_policy.json"
)
try:
    with open(siem_policy_path, "r", encoding="utf-8") as f:
        siem_policy = json.load(f)
    WATCH_IDS = set(siem_policy.get("watch_ids", []))
    BRUTE_FORCE_IDS = set(siem_policy.get("brute_force_event_ids", []))
    SUSPICIOUS_PROCESS_IDS = set(siem_policy.get("suspicious_process_event_ids", []))
    MALWARE_KEYWORDS = [kw.lower() for kw in siem_policy.get("malware_keywords", [])]
except Exception as e:
    logger.error(f"Failed to load SIEM policy: {e}")
    WATCH_IDS = set()
    BRUTE_FORCE_IDS = set()
    SUSPICIOUS_PROCESS_IDS = set()
    MALWARE_KEYWORDS = []


async def setup_redis_group(redis_client):
    """Create consumer group if it doesn't exist."""
    try:
        await redis_client.xgroup_create(REDIS_STREAM, CONSUMER_GROUP, id="0", mkstream=True)
        logger.info(f"Created consumer group {CONSUMER_GROUP}")
    except aioredis.ResponseError as e:
        if "BUSYGROUP Consumer Group name already exists" not in str(e):
            raise e


async def get_mongo_collections():
    """Return isolated MongoDB collection handles."""
    client = AsyncIOMotorClient(settings.mongodb_uri)
    db = client["WarSOC_DB"]
    return db["logs"], db["security_alerts"], db["tenants"]


def classify_alert(event_id: str, message: str) -> dict | None:
    """
    Classify an event into a security alert category.
    Returns alert metadata dict or None if no alert triggered.
    """
    msg_lower = message.lower()

    # Brute-force detection (e.g., Event 4625 = failed logon)
    if event_id in BRUTE_FORCE_IDS:
        return {
            "alert_type": "BRUTE_FORCE_ATTEMPT",
            "severity": "HIGH",
            "description": f"Failed authentication detected (Event {event_id})",
            "mitre_attack": "T1110"
        }

    # Suspicious process creation (e.g., Event 4688)
    if event_id in SUSPICIOUS_PROCESS_IDS:
        for keyword in MALWARE_KEYWORDS:
            if keyword in msg_lower:
                return {
                    "alert_type": "SUSPICIOUS_PROCESS",
                    "severity": "CRITICAL",
                    "description": f"Suspicious process detected: matched keyword '{keyword}'",
                    "mitre_attack": "T1059"
                }

    # Generic malware keyword scan across all watched events
    if event_id in WATCH_IDS:
        for keyword in MALWARE_KEYWORDS:
            if keyword in msg_lower:
                return {
                    "alert_type": "MALWARE_INDICATOR",
                    "severity": "HIGH",
                    "description": f"Malware indicator detected: '{keyword}'",
                    "mitre_attack": "T1204"
                }

    return None


async def main():
    logger.info("🚀 SIEM Security Worker Starting...")
    redis_client = await aioredis.from_url(settings.redis_url, decode_responses=True)
    await setup_redis_group(redis_client)

    logs_col, alerts_col, tenants_col = await get_mongo_collections()

    while True:
        try:
            messages = await redis_client.xreadgroup(
                CONSUMER_GROUP, CONSUMER_NAME, {REDIS_STREAM: ">"}, count=50, block=1000
            )

            if not messages:
                continue

            for stream_name, msg_list in messages:
                for msg_id, msg_data in msg_list:
                    try:
                        payload_str = msg_data.get("payload")
                        log = json.loads(payload_str) if payload_str else dict(msg_data)

                        tenant_id = log.get("tenant_id")
                        event_id = str(log.get("event_id"))

                        if not tenant_id or event_id not in WATCH_IDS:
                            await redis_client.xack(REDIS_STREAM, CONSUMER_GROUP, msg_id)
                            continue

                        # Check Tenant Plan — only process SIEM_ONLY subscribers
                        tenant = await tenants_col.find_one({"tenant_id": tenant_id})
                        if not tenant or tenant.get("subscription_plan") != "SIEM_ONLY":
                            await redis_client.xack(REDIS_STREAM, CONSUMER_GROUP, msg_id)
                            continue

                        # Tag and timestamp the log
                        tags = log.get("tags", [])
                        if isinstance(tags, list):
                            if "SIEM" not in tags:
                                tags.append("SIEM")
                        else:
                            tags = ["SIEM"]
                        log["tags"] = tags
                        log["created_at"] = datetime.now(timezone.utc)

                        # Classify for security alerts
                        message = log.get("message", "")
                        alert_info = classify_alert(event_id, message)

                        # Insert the enriched log
                        await logs_col.insert_one(log)

                        # If an alert was triggered, create a security alert document
                        if alert_info:
                            alert_doc = {
                                "tenant_id": tenant_id,
                                "event_id": event_id,
                                "alert_type": alert_info["alert_type"],
                                "severity": alert_info["severity"],
                                "description": alert_info["description"],
                                "mitre_attack": alert_info["mitre_attack"],
                                "source_ip": log.get("source_ip", "0.0.0.0"),
                                "user": log.get("user", "unknown"),
                                "message": message,
                                "created_at": datetime.now(timezone.utc),
                                "tags": ["SIEM"]
                            }
                            await alerts_col.insert_one(alert_doc)

                            # Publish to Redis PubSub for real-time WebSocket delivery
                            await redis_client.publish(
                                "security_alerts",
                                json.dumps(alert_doc, default=str)
                            )
                            logger.warning(
                                f"🚨 [{tenant_id}] {alert_info['alert_type']}: {alert_info['description']}"
                            )
                        else:
                            logger.info(
                                f"📋 [{tenant_id}] SIEM log processed (no alert): Event {event_id}"
                            )

                        await redis_client.xack(REDIS_STREAM, CONSUMER_GROUP, msg_id)

                    except Exception as e:
                        logger.error(f"❌ Error processing message {msg_id}: {e}")
                        await redis_client.xack(REDIS_STREAM, CONSUMER_GROUP, msg_id)

        except asyncio.CancelledError:
            break
        except Exception as e:
            logger.error(f"❌ Redis Stream Connection Error: {e}")
            await asyncio.sleep(2)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("SIEM Worker shutting down gracefully.")
