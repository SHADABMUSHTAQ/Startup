"""Controlled production canary for relay admission through Wazuh shadow detection."""

from __future__ import annotations

import hashlib
import json
import time
import uuid
from datetime import datetime, timedelta, timezone

import httpx
import jwt
import orjson
import redis
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from pymongo import MongoClient

from app.config.config import get_settings
from app.routes.auth import ALGORITHM, SECRET_KEY
from app.routes.network_relay import RELAY_GENESIS_HASH, RelayBatch, RelayEvent


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _relay_event(run_id: str, sequence: int, *, blocked: bool) -> RelayEvent:
    received_at = utc_now()
    event_type = "network_connection_blocked" if blocked else "network_connection_permitted"
    action = "block" if blocked else "allow"
    raw_message = (
        f"{received_at:%b %d %H:%M:%S} warsoc-canary filterlog: "
        f"{action},tcp,93.184.216.34:{45000 + sequence}->1.1.1.1:443"
    )
    return RelayEvent(
        event_uid=f"{run_id}-event-{sequence:03d}",
        record_class="evidence",
        device_id="warsoc-pfsense-canary",
        vendor="pfsense",
        transport="udp",
        source_address="192.0.2.1",
        device_event_time=received_at,
        relay_receipt_time=received_at,
        raw_message=raw_message,
        raw_message_hash=hashlib.sha256(raw_message.encode("utf-8")).hexdigest(),
        normalized={
            "event_type": event_type,
            "action": action,
            "src_ip": "93.184.216.34",
            "dst_ip": "1.1.1.1",
            "src_port": 45000 + sequence,
            "dst_port": 443,
            "protocol": "tcp",
            "interface_in": "wan",
            "message": "Controlled WarSOC network-to-Wazuh acceptance event",
        },
    )


def main() -> None:
    settings = get_settings()
    if not settings.network_relay_enabled:
        raise SystemExit("NETWORK_RELAY_ENABLED is false")
    if settings.wazuh_detection_mode != "shadow" or settings.wazuh_primary_approved:
        raise SystemExit("Canary requires Wazuh shadow mode with primary approval disabled")

    mongo = MongoClient(settings.mongodb_uri)
    db = mongo[settings.mongodb_db_name]
    redis_client = redis.Redis.from_url(settings.redis_url, decode_responses=True)
    run_id = f"NETWORK-WAZUH-CANARY-{utc_now():%Y%m%dT%H%M%SZ}-{uuid.uuid4().hex[:8]}"
    tenant_id = f"WARSOC_CANARY_{uuid.uuid4().hex[:12].upper()}"
    relay_id = f"WARSOC_RELAY_{uuid.uuid4().hex}"
    chain_id = uuid.uuid4().hex
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")
    signing_key_id = hashlib.sha256(
        private_key.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    ).hexdigest()
    report: dict = {"run_id": run_id, "checks": {}, "cleanup": {}, "passed": False}

    try:
        now = utc_now()
        db.tenants.insert_one(
            {
                "tenant_id": tenant_id,
                "company_name": "WarSOC Network Wazuh Canary",
                "status": "active",
                "active": True,
                "has_active_plan": True,
                "retention_days": 90,
                "max_agents": 0,
                "max_network_relays": 1,
                "created_at": now,
                "test_run_id": run_id,
            }
        )
        db.network_relays.insert_one(
            {
                "tenant_id": tenant_id,
                "relay_id": relay_id,
                "public_key": public_key,
                "signing_key_id": signing_key_id,
                "status": "active",
                "key_epoch": 1,
                "last_sequence": 0,
                "last_batch_hash": RELAY_GENESIS_HASH,
                "chain_id": None,
                "version": settings.network_relay_minimum_version,
                "devices": [
                    {
                        "device_id": "warsoc-pfsense-canary",
                        "vendor": "pfsense",
                        "transport": "udp",
                        "source_addresses": ["192.0.2.1"],
                        "expected_eps": 100,
                    }
                ],
                "test_run_id": run_id,
            }
        )
        token = jwt.encode(
            {
                "sub": relay_id,
                "tenant_id": tenant_id,
                "type": "network_relay",
                "jti": uuid.uuid4().hex,
                "exp": now + timedelta(minutes=10),
            },
            SECRET_KEY,
            algorithm=ALGORITHM,
        )
        events = [
            *[_relay_event(run_id, index, blocked=True) for index in range(1, 32)],
            _relay_event(run_id, 32, blocked=False),
        ]
        batch = RelayBatch(
            schema_version="warsoc-relay-batch-v1",
            relay_id=relay_id,
            chain_id=chain_id,
            key_epoch=1,
            sequence=1,
            previous_batch_hash=RELAY_GENESIS_HASH,
            created_at=utc_now(),
            events=events,
        )
        raw_body = orjson.dumps(batch.model_dump(mode="json"))
        with httpx.Client(timeout=30.0) as client:
            response = client.post(
                "http://127.0.0.1:8000/api/v1/network-relay/ingest",
                content=raw_body,
                headers={
                    "Authorization": f"Bearer {token}",
                    "X-WarSOC-Signature": private_key.sign(raw_body).hex(),
                    "Content-Type": "application/json",
                },
            )
        report["ingest_http"] = response.status_code
        response_body = response.json() if response.content else {}
        report["checks"]["signed_relay_ingest"] = (
            response.status_code == 202 and response_body.get("queued") == len(events)
        )

        expected_dispatches = sum(1 for event in events if event.normalized.get("action") == "block")
        deadline = time.monotonic() + 180
        observations = []
        while time.monotonic() < deadline:
            observations = list(
                db.detection_engine_observations.find(
                    {"tenant_id": tenant_id},
                    {
                        "_id": 0,
                        "event_uid": 1,
                        "engine_rule_id": 1,
                        "status": 1,
                        "mode": 1,
                        "ruleset_version": 1,
                        "lineage_complete": 1,
                    },
                )
            )
            delivered = db.detection_dispatch_outbox.count_documents(
                {"tenant_id": tenant_id, "status": "delivered"}
            )
            if delivered == expected_dispatches and any(
                str(item.get("engine_rule_id")) == "100630" for item in observations
            ):
                break
            time.sleep(1)

        canonical_count = db.siem_cold_vault.count_documents(
            {
                "tenant_id": tenant_id,
                "source_assurance": "relay_attested",
                "signature_verified": True,
                "telemetry_family": "network",
            }
        )
        delivered_count = db.detection_dispatch_outbox.count_documents(
            {"tenant_id": tenant_id, "status": "delivered"}
        )
        network_observations = [
            item for item in observations if str(item.get("engine_rule_id")) == "100630"
        ]
        unexpected_observations = [
            item for item in observations if str(item.get("engine_rule_id")) != "100630"
        ]
        incident_count = sum(
            db[name].count_documents({"tenant_id": tenant_id, "detection_sources": "wazuh"})
            for name in ("incidents", "security_incidents")
            if name in db.list_collection_names()
        )
        report["checks"].update(
            {
                "canonical_relay_evidence": canonical_count == len(events),
                "eligible_dispatches_delivered": delivered_count == expected_dispatches,
                "network_rule_100630_shadow": bool(
                    network_observations
                    and all(
                        item.get("status") == "shadow_observation"
                        and item.get("mode") == "shadow"
                        and item.get("ruleset_version") == settings.wazuh_ruleset_version
                        and item.get("lineage_complete") is True
                        for item in network_observations
                    )
                ),
                "allowed_event_no_candidate": not unexpected_observations,
                "zero_wazuh_incidents": incident_count == 0,
            }
        )
        report["canonical_count"] = canonical_count
        report["dispatch_delivered_count"] = delivered_count
        report["observation_rule_ids"] = sorted(
            str(item.get("engine_rule_id")) for item in observations
        )
        report["passed"] = all(report["checks"].values())
    except Exception as exc:
        report["error"] = f"{type(exc).__name__}: {str(exc)[:300]}"
    finally:
        deleted: dict[str, int] = {}
        collection_names = db.list_collection_names()
        for collection_name in collection_names:
            try:
                result = db[collection_name].delete_many({"tenant_id": tenant_id})
                if result.deleted_count:
                    deleted[collection_name] = result.deleted_count
            except Exception:
                pass
        deleted_redis = 0
        for pattern in (f"*{tenant_id}*", f"*{relay_id}*", f"*{run_id}*"):
            keys = list(redis_client.scan_iter(match=pattern, count=100))
            if keys:
                deleted_redis += redis_client.delete(*keys)
        report["cleanup"] = {
            "mongo_deleted": deleted,
            "redis_keys_deleted": deleted_redis,
            "remaining_mongo_records": sum(
                db[name].count_documents({"tenant_id": tenant_id})
                for name in collection_names
            ),
        }
        redis_client.close()
        mongo.close()

    report["completed_at"] = utc_now().isoformat()
    print(json.dumps(report, indent=2, default=str))
    raise SystemExit(0 if report["passed"] else 1)


if __name__ == "__main__":
    main()
