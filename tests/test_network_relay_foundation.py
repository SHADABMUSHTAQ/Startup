import hashlib
import json
import os
import sqlite3
import types
import uuid
from datetime import datetime, timedelta, timezone

import orjson
import pytest
import httpx
import jwt
from pydantic import ValidationError
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from app.network_relay.batch import build_signed_batch, relay_event_from_parsed
from app.network_relay.collector import RelayCollector, RelayDevice
from app.network_relay.outbox import RelayOutbox, deliver_once
from app.network_relay.parsers import (
    NetworkParseError,
    parse_cisco_asa,
    parse_fortinet,
    parse_mikrotik,
    parse_network_message,
    parse_pfsense,
)
from app.network_relay.spool import (
    EncryptedBoundedSpool,
    SpoolFullError,
    SpoolIntegrityError,
)
from app.routes.network_relay import (
    RELAY_GENESIS_HASH,
    RELAY_SCHEMA_VERSION,
    RELAY_SIGNATURE_VERSION,
    RelayBatch,
    RelayEvent,
    _admit_batch,
    _queue_event,
    _resolve_tenant_relay_limit,
    _tenant_relay_limit,
    list_relay_status,
    settings as relay_settings,
)
from tests.helpers import provision_and_login_admin
from app.routes.auth import ALGORITHM, SECRET_KEY
from app.utils.siem_catalog import SIEM_RULES
from app.utils.siem_logic import CorrelationEngine
from app.workers.siem_worker import (
    _keyword_sources_for_event,
    _trusted_telemetry_family,
)


def _relay_event(**overrides) -> RelayEvent:
    raw_message = overrides.pop(
        "raw_message",
        "date=2026-07-27 time=10:00:00 type=traffic action=deny srcip=10.0.0.4 dstip=8.8.8.8",
    )
    values = {
        "event_uid": f"relay-event-{uuid.uuid4().hex}",
        "device_id": "branch-firewall-1",
        "vendor": "fortinet",
        "transport": "udp",
        "source_address": "10.0.0.1",
        "device_event_time": datetime.now(timezone.utc),
        "relay_receipt_time": datetime.now(timezone.utc),
        "raw_message": raw_message,
        "raw_message_hash": hashlib.sha256(raw_message.encode()).hexdigest(),
        "normalized": {
            "event_type": "network_connection_blocked",
            "action": "deny",
            "src_ip": "10.0.0.4",
            "dst_ip": "8.8.8.8",
            "dst_port": 53,
            "protocol": "udp",
        },
    }
    values.update(overrides)
    return RelayEvent.model_validate(values)


def _as_utc(value: datetime) -> datetime:
    """MongoDB returns stored UTC datetimes without tzinfo; reattach it so
    assertions can compare against the timezone-aware test clock."""
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value


def test_relay_entitlement_defaults_to_zero_and_respects_platform_cap():
    original_limit = relay_settings.network_relay_max_per_tenant
    relay_settings.network_relay_max_per_tenant = 2
    try:
        assert _tenant_relay_limit(None) == 0
        assert _tenant_relay_limit({"status": "active"}) == 0
        assert _tenant_relay_limit(
            {"status": "active", "max_network_relays": 1}
        ) == 1
        assert _tenant_relay_limit(
            {"status": "active", "max_network_relays": 99}
        ) == 2
    finally:
        relay_settings.network_relay_max_per_tenant = original_limit


@pytest.mark.asyncio
async def test_admin_provision_writes_max_network_relays_to_tenant_and_cache(
    async_client, db, redis_client
):
    """/admin/provision must persist max_network_relays on the tenant document
    and sync it to Redis so _tenant_relay_limit can read it back."""
    run_id = uuid.uuid4().hex[:10]
    email = f"relay-provision-{run_id}@example.com"
    response = await async_client.post(
        "/api/v1/admin/provision",
        headers={"X-Admin-Key": os.environ["SUPER_ADMIN_API_KEY"]},
        json={
            "company_name": f"Relay Provision Test {run_id}",
            "plan_type": "Customized",
            "compliance_packs": ["fbr_pos"],
            "max_agents": 10,
            "max_network_relays": 2,
            "admin_email": email,
            "admin_name": "Relay Provision Admin",
            "admin_password": "WarSOC-Pilot-2026!",
        },
    )
    assert response.status_code == 200, response.text
    body = response.json()
    tenant_id = body["tenant_id"]

    tenant = await db["tenants"].find_one({"tenant_id": tenant_id})
    assert tenant is not None
    assert tenant.get("max_network_relays") == 2

    cached = await redis_client.get(f"tenant_max_network_relays:{tenant_id}")
    assert cached is not None
    assert str(cached) == "2"


@pytest.mark.asyncio
async def test_admin_provision_defaults_max_network_relays_to_zero(async_client, db):
    """When max_network_relays is omitted, the tenant gets 0 (fail-closed)."""
    run_id = uuid.uuid4().hex[:10]
    email = f"relay-provision-zero-{run_id}@example.com"
    response = await async_client.post(
        "/api/v1/admin/provision",
        headers={"X-Admin-Key": os.environ["SUPER_ADMIN_API_KEY"]},
        json={
            "company_name": f"Relay Zero Test {run_id}",
            "plan_type": "Customized",
            "compliance_packs": ["fbr_pos"],
            "max_agents": 5,
            "admin_email": email,
            "admin_name": "Relay Zero Admin",
            "admin_password": "WarSOC-Pilot-2026!",
        },
    )
    assert response.status_code == 200, response.text
    tenant_id = response.json()["tenant_id"]
    tenant = await db["tenants"].find_one({"tenant_id": tenant_id})
    assert tenant.get("max_network_relays") == 0
    assert _tenant_relay_limit(tenant) == 0


@pytest.mark.asyncio
async def test_tenant_relay_limit_uses_mongo_grant_and_fail_closed_cache(
    db, redis_client
):
    """Mongo is the grant ceiling; Redis may restrict but never expand it."""
    tenant_id = f"WARSOC_RELAY_LIMIT_{uuid.uuid4().hex[:8]}"
    tenant = {
        "tenant_id": tenant_id,
        "status": "active",
        "active": True,
        "has_active_plan": True,
        "max_network_relays": 2,
    }
    # Cache miss -> the tenant document decides.
    assert await _resolve_tenant_relay_limit(redis_client, tenant, tenant_id) == 2
    # Redis unavailable -> the tenant document decides.
    assert await _resolve_tenant_relay_limit(None, tenant, tenant_id) == 2
    # A lower cache value restricts the document grant.
    await redis_client.set(f"tenant_max_network_relays:{tenant_id}", "1")
    assert await _resolve_tenant_relay_limit(redis_client, tenant, tenant_id) == 1
    # A stale-high cache cannot grant beyond the canonical Mongo document.
    tenant["max_network_relays"] = 1
    await redis_client.set(f"tenant_max_network_relays:{tenant_id}", "2")
    assert await _resolve_tenant_relay_limit(redis_client, tenant, tenant_id) == 1
    # A malformed cache safely falls back to the document grant.
    await redis_client.set(f"tenant_max_network_relays:{tenant_id}", "invalid")
    assert await _resolve_tenant_relay_limit(redis_client, tenant, tenant_id) == 1
    # The cache never entitles an inactive tenant.
    inactive = dict(tenant, status="suspended")
    assert await _resolve_tenant_relay_limit(redis_client, inactive, tenant_id) == 0


@pytest.mark.asyncio
async def test_provisioned_tenant_can_generate_relay_activation_end_to_end(
    async_client, db, redis_client, monkeypatch
):
    """Commit 1 exit criteria: a freshly provisioned tenant (max_network_relays=1)
    can immediately mint a relay activation code — no 403 entitlement rejection —
    and the Redis entitlement cache stays synchronized on the hot path."""
    original_enabled = relay_settings.network_relay_enabled
    relay_settings.network_relay_enabled = True
    try:
        session = await provision_and_login_admin(
            async_client, "relay_activation", max_network_relays=1
        )
        tenant_id = session["tenant_id"]
        assert str(
            await redis_client.get(f"tenant_max_network_relays:{tenant_id}")
        ) == "1"

        activation = await async_client.post(
            "/api/v1/network-relay/generate-activation",
            headers={"x-csrf-token": session["csrf_token"]},
            json={
                "relay_name": "Branch Firewall Relay",
                "devices": [
                    {
                        "device_id": "branch-firewall-1",
                        "vendor": "pfsense",
                        "source_addresses": ["10.0.0.1/32"],
                        "transport": "udp",
                    }
                ],
                "listeners": [
                    {"transport": "udp", "bind_host": "10.0.0.10", "port": 5514}
                ],
            },
        )
        assert activation.status_code == 200, activation.text
        body = activation.json()
        assert body["activation_code"].startswith("WARSOC-RELAY-")
        assert (
            body["expires_in_seconds"]
            == relay_settings.network_relay_activation_ttl_seconds
        )
        assert body["setup"]["configuration_filename"] == "relay-config.json"
        assert body["setup"]["configuration"]["schema_version"] == "warsoc-relay-runtime-v1"
        assert body["setup"]["configuration"]["backend_url"] == "https://api.warsoc.test"
        assert body["setup"]["configuration"]["listeners"] == [
            {"transport": "udp", "bind_host": "10.0.0.10", "port": 5514}
        ]
        assert body["setup"]["configuration"]["devices"][0]["device_id"] == "branch-firewall-1"
        assert body["setup"]["package_available"] is False
        assert body["setup"]["package_sha256"] is None
        assert body["setup"]["publisher_trust"] == "hash_allowlisted_pilot"

        unavailable_package = await async_client.get(
            "/api/v1/network-relay/setup-package"
        )
        assert unavailable_package.status_code == 503, unavailable_package.text
        monkeypatch.setattr(
            relay_settings,
            "network_relay_installer_url",
            "https://artifacts.warsoc.test/warsoc_relay_setup-1.0.0.zip",
        )
        monkeypatch.setattr(
            relay_settings,
            "network_relay_installer_sha256",
            "a" * 64,
        )
        package = await async_client.get("/api/v1/network-relay/setup-package")
        assert package.status_code == 307, package.text
        assert package.headers["location"] == (
            "https://artifacts.warsoc.test/warsoc_relay_setup-1.0.0.zip"
        )
        assert package.headers["x-warsoc-artifact-sha256"] == "a" * 64

        # The cache is fail-closed on the hot path: dropping it to 0 blocks
        # activation even though the Mongo tenant document still says 1.
        await redis_client.set(f"tenant_max_network_relays:{tenant_id}", "0")
        blocked = await async_client.post(
            "/api/v1/network-relay/generate-activation",
            headers={"x-csrf-token": session["csrf_token"]},
            json={
                "relay_name": "Second Branch Relay",
                "devices": [
                    {
                        "device_id": "branch-firewall-2",
                        "vendor": "pfsense",
                        "source_addresses": ["10.0.0.2/32"],
                        "transport": "udp",
                    }
                ],
                "listeners": [
                    {"transport": "udp", "bind_host": "10.0.0.10", "port": 5514}
                ],
            },
        )
        assert blocked.status_code == 403, blocked.text
        assert blocked.json()["detail"] == "Network relay contract limit reached"
    finally:
        relay_settings.network_relay_enabled = original_enabled


@pytest.mark.asyncio
async def test_admin_updates_tenant_relay_limit_end_to_end(
    async_client, db, redis_client
):
    """Commit 1 ops path: an operator can raise or disable a tenant's relay
    entitlement after provisioning — the tenant document, the admin user
    mirror, the restrictive Redis cache used by /generate-activation, and the
    management audit trail all move together."""
    original_enabled = relay_settings.network_relay_enabled
    relay_settings.network_relay_enabled = True
    try:
        session = await provision_and_login_admin(
            async_client, "relay_limit_update", max_network_relays=0
        )
        tenant_id = session["tenant_id"]
        admin_key = os.environ["SUPER_ADMIN_API_KEY"]

        # Provisioned at 0 -> activation is refused.
        blocked = await async_client.post(
            "/api/v1/network-relay/generate-activation",
            headers={"x-csrf-token": session["csrf_token"]},
            json={
                "relay_name": "Branch Firewall Relay",
                "devices": [
                    {
                        "device_id": "branch-firewall-1",
                        "vendor": "pfsense",
                        "source_addresses": ["10.0.0.1/32"],
                        "transport": "udp",
                    }
                ],
                "listeners": [
                    {"transport": "udp", "bind_host": "10.0.0.10", "port": 5514}
                ],
            },
        )
        assert blocked.status_code == 403, blocked.text

        # Unknown tenant -> 404; out-of-range value -> 422.
        missing = await async_client.post(
            "/api/v1/admin/tenants/WARSOC_MISSING/max-network-relays",
            headers={"X-Admin-Key": admin_key},
            json={"max_network_relays": 2},
        )
        assert missing.status_code == 404, missing.text
        invalid = await async_client.post(
            f"/api/v1/admin/tenants/{tenant_id}/max-network-relays",
            headers={"X-Admin-Key": admin_key},
            json={"max_network_relays": 11},
        )
        assert invalid.status_code == 422, invalid.text

        # Raise the cap through the ops update path.
        update = await async_client.post(
            f"/api/v1/admin/tenants/{tenant_id}/max-network-relays",
            headers={"X-Admin-Key": admin_key},
            json={"max_network_relays": 2},
        )
        assert update.status_code == 200, update.text
        body = update.json()
        assert body["max_network_relays"] == 2
        assert body["previous_max_network_relays"] == 0
        assert body["active_relays"] == 0
        assert body["warning"] is None

        # All entitlement stores moved together.
        assert str(
            await redis_client.get(f"tenant_max_network_relays:{tenant_id}")
        ) == "2"
        tenant_doc = await db["tenants"].find_one({"tenant_id": tenant_id})
        assert tenant_doc["max_network_relays"] == 2
        user_doc = await db["users"].find_one({"email": session["email"]})
        assert user_doc["max_network_relays"] == 2
        audit = await db["management_audit"].find_one(
            {"tenant_id": tenant_id, "action": "network_relay_limit_updated"}
        )
        assert audit is not None
        assert audit["new_max_network_relays"] == 2
        assert audit["previous_max_network_relays"] == 0
        assert audit["operator"] == "platform_admin"

        # The raised entitlement takes effect immediately.
        activation = await async_client.post(
            "/api/v1/network-relay/generate-activation",
            headers={"x-csrf-token": session["csrf_token"]},
            json={
                "relay_name": "Branch Firewall Relay",
                "devices": [
                    {
                        "device_id": "branch-firewall-1",
                        "vendor": "pfsense",
                        "source_addresses": ["10.0.0.1/32"],
                        "transport": "udp",
                    }
                ],
                "listeners": [
                    {"transport": "udp", "bind_host": "10.0.0.10", "port": 5514}
                ],
            },
        )
        assert activation.status_code == 200, activation.text
    finally:
        relay_settings.network_relay_enabled = original_enabled


@pytest.mark.asyncio
async def test_admin_rejects_relay_entitlement_above_platform_ceiling(
    async_client, db, redis_client
):
    """Fix 5: values above NETWORK_RELAY_MAX_PER_TENANT are rejected with 422
    instead of being accepted and silently clamped at enforcement time — the
    accepted entitlement is always the enforced entitlement."""
    original_ceiling = relay_settings.network_relay_max_per_tenant
    relay_settings.network_relay_max_per_tenant = 2
    try:
        session = await provision_and_login_admin(
            async_client, "relay_ceiling", max_network_relays=1
        )
        tenant_id = session["tenant_id"]
        admin_key = os.environ["SUPER_ADMIN_API_KEY"]

        # Provisioning above the ceiling is rejected up front.
        over_provision = await async_client.post(
            "/api/v1/admin/provision",
            headers={"X-Admin-Key": admin_key},
            json={
                "company_name": "Relay Ceiling Over Test",
                "plan_type": "Customized",
                "compliance_packs": ["fbr_pos"],
                "max_agents": 5,
                "max_network_relays": 3,
                "admin_email": f"relay-ceiling-{uuid.uuid4().hex[:8]}@example.com",
                "admin_name": "Relay Ceiling Admin",
                "admin_password": "WarSOC-Pilot-2026!",
            },
        )
        assert over_provision.status_code == 422, over_provision.text
        # The API sanitizes validation bodies; the model carries the reason.
        from app.routes.admin import RelayLimitUpdateRequest

        with pytest.raises(ValidationError, match="platform ceiling"):
            RelayLimitUpdateRequest(max_network_relays=3)
        assert RelayLimitUpdateRequest(max_network_relays=2).max_network_relays == 2

        # Updating above the ceiling is rejected too...
        over_update = await async_client.post(
            f"/api/v1/admin/tenants/{tenant_id}/max-network-relays",
            headers={"X-Admin-Key": admin_key},
            json={"max_network_relays": 3},
        )
        assert over_update.status_code == 422, over_update.text

        # ...while a value within the ceiling is accepted and enforced as-is.
        ok_update = await async_client.post(
            f"/api/v1/admin/tenants/{tenant_id}/max-network-relays",
            headers={"X-Admin-Key": admin_key},
            json={"max_network_relays": 2},
        )
        assert ok_update.status_code == 200, ok_update.text
        assert ok_update.json()["max_network_relays"] == 2
        tenant_doc = await db["tenants"].find_one({"tenant_id": tenant_id})
        assert _tenant_relay_limit(tenant_doc) == 2
    finally:
        relay_settings.network_relay_max_per_tenant = original_ceiling


@pytest.mark.asyncio
async def test_admin_relay_limit_update_fails_closed_when_cache_unavailable(
    async_client, db, redis_client
):
    """Fix 1: the entitlement update must never commit Mongo while the Redis
    cache still holds the previous limit — a
    cache outage rejects the whole operation and nothing moves."""
    from app.main import app as fastapi_app

    session = await provision_and_login_admin(
        async_client, "relay_limit_cache_down", max_network_relays=1
    )
    tenant_id = session["tenant_id"]
    admin_key = os.environ["SUPER_ADMIN_API_KEY"]

    class _UnavailableCache:
        async def ping(self):
            return True

        async def set(self, *args, **kwargs):
            raise ConnectionError("redis connection lost")

    original_redis = fastapi_app.state.redis
    fastapi_app.state.redis = _UnavailableCache()
    try:
        response = await async_client.post(
            f"/api/v1/admin/tenants/{tenant_id}/max-network-relays",
            headers={"X-Admin-Key": admin_key},
            json={"max_network_relays": 0},
        )
    finally:
        fastapi_app.state.redis = original_redis

    assert response.status_code == 503, response.text
    # The global error handler sanitizes 5xx detail bodies; the specific
    # reason is logged server-side, the 503 plus unchanged state is the contract.

    # Nothing moved: tenant document, admin mirror, cache, audit trail.
    tenant_doc = await db["tenants"].find_one({"tenant_id": tenant_id})
    assert tenant_doc["max_network_relays"] == 1
    user_doc = await db["users"].find_one({"email": session["email"]})
    assert user_doc["max_network_relays"] == 1
    assert str(await redis_client.get(f"tenant_max_network_relays:{tenant_id}")) == "1"
    assert await db["management_audit"].count_documents(
        {"tenant_id": tenant_id, "action": "network_relay_limit_updated"}
    ) == 0


@pytest.mark.asyncio
async def test_admin_relay_limit_update_rolls_back_cache_when_documents_fail(
    async_client, db, redis_client, monkeypatch
):
    """Fix 1: if the Mongo documents fail AFTER the cache was committed, the
    cache is rolled back to the previous entitlement so the hot path never
    enforces the rejected value."""
    from motor.motor_asyncio import AsyncIOMotorCollection

    session = await provision_and_login_admin(
        async_client, "relay_limit_rollback", max_network_relays=1
    )
    tenant_id = session["tenant_id"]
    admin_key = os.environ["SUPER_ADMIN_API_KEY"]

    original_update_one = AsyncIOMotorCollection.update_one
    tenants_updates = {"count": 0}

    async def _failing_update_one(self, *args, **kwargs):
        if self.name == "tenants":
            tenants_updates["count"] += 1
            if tenants_updates["count"] == 1:
                raise ConnectionError("mongo primary stepped down")
        return await original_update_one(self, *args, **kwargs)

    monkeypatch.setattr(AsyncIOMotorCollection, "update_one", _failing_update_one)

    response = await async_client.post(
        f"/api/v1/admin/tenants/{tenant_id}/max-network-relays",
        headers={"X-Admin-Key": admin_key},
        json={"max_network_relays": 0},
    )
    assert response.status_code == 503, response.text

    # The cache was committed with the rejected 0 and rolled back to 1.
    assert str(await redis_client.get(f"tenant_max_network_relays:{tenant_id}")) == "1"
    # Documents never durably changed; no audit entry was written.
    tenant_doc = await db["tenants"].find_one({"tenant_id": tenant_id})
    assert tenant_doc["max_network_relays"] == 1
    user_doc = await db["users"].find_one({"email": session["email"]})
    assert user_doc["max_network_relays"] == 1
    assert await db["management_audit"].count_documents(
        {"tenant_id": tenant_id, "action": "network_relay_limit_updated"}
    ) == 0


@pytest.mark.asyncio
async def test_admin_relay_limit_update_rejects_concurrent_tenant_writer(
    async_client, db, redis_client
):
    """A tenant-scoped lease serializes operators before any store changes."""
    session = await provision_and_login_admin(
        async_client, "relay_limit_lock", max_network_relays=1
    )
    tenant_id = session["tenant_id"]
    lock_key = f"warsoc:relay_entitlement_update_lock:{tenant_id}"
    await redis_client.set(lock_key, "other-operator", ex=30)

    response = await async_client.post(
        f"/api/v1/admin/tenants/{tenant_id}/max-network-relays",
        headers={"X-Admin-Key": os.environ["SUPER_ADMIN_API_KEY"]},
        json={"max_network_relays": 0},
    )
    assert response.status_code == 409, response.text
    tenant = await db["tenants"].find_one({"tenant_id": tenant_id})
    assert tenant["max_network_relays"] == 1
    assert str(await redis_client.get(f"tenant_max_network_relays:{tenant_id}")) == "1"


@pytest.mark.asyncio
async def test_relay_version_gate_rejects_evidence_but_allows_health_records(
    async_client, db, redis_client
):
    """Commit 2 exit criteria: an outdated relay's evidence batch is rejected
    with a structured update-required signal, while its control/health records
    (the relay heartbeat) still land so the operator can see the relay and
    push an upgrade."""
    original_enabled = relay_settings.network_relay_enabled
    original_minimum = relay_settings.network_relay_minimum_version
    relay_settings.network_relay_enabled = True
    relay_settings.network_relay_minimum_version = "2.0.0"
    tenant_id = f"WARSOC_RELAY_VGATE_{uuid.uuid4().hex[:8]}"
    relay_id = f"WARSOC_RELAY_{uuid.uuid4().hex}"
    chain_id = uuid.uuid4().hex
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")
    signing_key_id = hashlib.sha256(
        private_key.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    ).hexdigest()
    try:
        await db.tenants.insert_one(
            {
                "tenant_id": tenant_id,
                "status": "active",
                "active": True,
                "has_active_plan": True,
                "max_agents": 1,
                "max_network_relays": 1,
                "retention_days": 90,
            }
        )
        await db.network_relays.insert_one(
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
                "version": "1.0.0",
                "devices": [
                    {
                        "device_id": "branch-firewall-1",
                        "vendor": "fortinet",
                        "transport": "udp",
                        "source_addresses": ["10.0.0.1"],
                        "expected_eps": 100,
                    }
                ],
            }
        )
        token = jwt.encode(
            {
                "sub": relay_id,
                "tenant_id": tenant_id,
                "type": "network_relay",
                "jti": uuid.uuid4().hex,
                "exp": datetime.now(timezone.utc) + timedelta(minutes=10),
            },
            SECRET_KEY,
            algorithm=ALGORITHM,
        )

        async def _post_batch(batch: RelayBatch):
            raw_body = orjson.dumps(batch.model_dump(mode="json"))
            return await async_client.post(
                "/api/v1/network-relay/ingest",
                content=raw_body,
                headers={
                    "Authorization": f"Bearer {token}",
                    "X-WarSOC-Signature": private_key.sign(raw_body).hex(),
                    "Content-Type": "application/json",
                },
            )

        # Evidence from the outdated relay is rejected with the structured
        # update-required signal and lands nothing.
        evidence_response = await _post_batch(
            RelayBatch(
                schema_version="warsoc-relay-batch-v1",
                relay_id=relay_id,
                chain_id=chain_id,
                key_epoch=1,
                sequence=1,
                previous_batch_hash=RELAY_GENESIS_HASH,
                created_at=datetime.now(timezone.utc),
                events=[_relay_event()],
            )
        )
        assert evidence_response.status_code == 403, evidence_response.text
        gate_body = evidence_response.json()
        assert gate_body["error"] == "relay_version_below_minimum"
        assert gate_body["current_version"] == "1.0.0"
        assert gate_body["minimum_version"] == "2.0.0"
        assert "update required" in gate_body["message"].lower()
        assert await db.source_envelopes_siem.count_documents(
            {"source_principal_id": relay_id}
        ) == 0
        assert await redis_client.xlen("raw_logs_queue") == 0

        # Control/health records from the same outdated relay still land.
        health_data = {
            "event_type": "device_health",
            "state": "DEGRADED",
            "reason": "parser_rejected",
            "affected_device_id": "branch-firewall-1",
            "dropped_events": 4,
            "dropped_bytes": 400,
        }
        health_raw = json.dumps(health_data, sort_keys=True, separators=(",", ":"))
        health_event = RelayEvent(
            event_uid=f"relay-vgate-health-{uuid.uuid4().hex[:16]}",
            record_class="control",
            device_id=relay_id,
            vendor="generic",
            transport="api",
            source_address="127.0.0.1",
            device_event_time=None,
            relay_receipt_time=datetime.now(timezone.utc),
            raw_message=health_raw,
            raw_message_hash=hashlib.sha256(health_raw.encode("utf-8")).hexdigest(),
            normalized=health_data,
        )
        health_response = await _post_batch(
            RelayBatch(
                schema_version="warsoc-relay-batch-v1",
                relay_id=relay_id,
                chain_id=chain_id,
                key_epoch=1,
                sequence=1,
                previous_batch_hash=RELAY_GENESIS_HASH,
                created_at=datetime.now(timezone.utc),
                events=[health_event],
            )
        )
        assert health_response.status_code == 202, health_response.text
        relay_doc = await db.network_relays.find_one({"relay_id": relay_id})
        assert relay_doc["last_health_state"] == "DEGRADED"
        assert relay_doc["last_health_reason"] == "parser_rejected"
        assert await db.source_envelopes_siem.count_documents(
            {"source_principal_id": relay_id}
        ) == 1

        # A malformed stored version also fails closed for evidence.
        await db.network_relays.update_one(
            {"relay_id": relay_id}, {"$set": {"version": "not-a-version"}}
        )
        invalid_response = await _post_batch(
            RelayBatch(
                schema_version="warsoc-relay-batch-v1",
                relay_id=relay_id,
                chain_id=chain_id,
                key_epoch=1,
                sequence=1,
                previous_batch_hash=RELAY_GENESIS_HASH,
                created_at=datetime.now(timezone.utc),
                events=[_relay_event()],
            )
        )
        assert invalid_response.status_code == 403, invalid_response.text
        assert invalid_response.json()["error"] == "relay_version_invalid"
    finally:
        relay_settings.network_relay_enabled = original_enabled
        relay_settings.network_relay_minimum_version = original_minimum


def test_relay_version_gate_startup_check_requires_explicit_minimum():
    """Fix 2: the backend must refuse to start with NETWORK_RELAY_ENABLED=true
    and no explicit NETWORK_RELAY_MINIMUM_VERSION — the 0.0.0 default means
    "gate disabled", which would silently accept every relay build."""
    from app.config.config import _validate_network_relay_version_gate

    # Gate disabled: the unset default is acceptable.
    _validate_network_relay_version_gate(
        types.SimpleNamespace(
            network_relay_enabled=False, network_relay_minimum_version="0.0.0"
        )
    )

    # Gate enabled with an explicit, valid minimum: accepted.
    _validate_network_relay_version_gate(
        types.SimpleNamespace(
            network_relay_enabled=True, network_relay_minimum_version="1.0.0"
        )
    )

    # Gate enabled but the minimum is unset/empty/0.0.0: refuse to start.
    for unset in ("", "   ", "0.0.0", None):
        with pytest.raises(RuntimeError, match="NETWORK_RELAY_MINIMUM_VERSION"):
            _validate_network_relay_version_gate(
                types.SimpleNamespace(
                    network_relay_enabled=True, network_relay_minimum_version=unset
                )
            )

    # Gate enabled with a non-PEP-440 value: refuse to start.
    with pytest.raises(RuntimeError, match="PEP 440"):
        _validate_network_relay_version_gate(
            types.SimpleNamespace(
                network_relay_enabled=True,
                network_relay_minimum_version="not-a-version",
            )
        )


def test_relay_watchdog_interval_startup_check_is_bounded():
    from app.config.config import _validate_network_relay_watchdog_settings

    _validate_network_relay_watchdog_settings(
        types.SimpleNamespace(
            network_relay_enabled=False,
            network_relay_watchdog_interval_seconds=1,
        )
    )
    for interval in (30, 300, 86400):
        _validate_network_relay_watchdog_settings(
            types.SimpleNamespace(
                network_relay_enabled=True,
                network_relay_watchdog_interval_seconds=interval,
            )
        )
    for interval in (0, 29, 86401):
        with pytest.raises(RuntimeError, match="WATCHDOG_INTERVAL_SECONDS"):
            _validate_network_relay_watchdog_settings(
                types.SimpleNamespace(
                    network_relay_enabled=True,
                    network_relay_watchdog_interval_seconds=interval,
                )
            )


def test_relay_setup_package_requires_a_direct_url_and_exact_sha256():
    from app.config.config import _validate_network_relay_package_settings

    _validate_network_relay_package_settings(
        types.SimpleNamespace(
            network_relay_installer_url="",
            network_relay_installer_sha256="",
        )
    )
    _validate_network_relay_package_settings(
        types.SimpleNamespace(
            network_relay_installer_url=(
                "https://artifacts.warsoc.test/warsoc_relay_setup-1.0.0.zip"
            ),
            network_relay_installer_sha256="a" * 64,
        )
    )
    for url, sha256 in (
        ("https://artifacts.warsoc.test/relay.zip", ""),
        ("", "a" * 64),
        ("http://artifacts.warsoc.test/relay.zip", "a" * 64),
        ("https://artifacts.warsoc.test/relay.exe", "a" * 64),
        ("https://artifacts.warsoc.test/relay.zip", "not-a-sha256"),
    ):
        with pytest.raises(RuntimeError):
            _validate_network_relay_package_settings(
                types.SimpleNamespace(
                    network_relay_installer_url=url,
                    network_relay_installer_sha256=sha256,
                )
            )


@pytest.mark.asyncio
async def test_relay_status_exposes_tenant_capability_and_nested_device_contract(
    db, redis_client
):
    original_enabled = relay_settings.network_relay_enabled
    relay_settings.network_relay_enabled = True
    tenant_id = f"WARSOC_RELAY_UI_{uuid.uuid4().hex[:8]}"
    now = datetime.now(timezone.utc)
    try:
        await db.tenants.insert_one(
            {
                "tenant_id": tenant_id,
                "status": "active",
                "max_network_relays": 1,
            }
        )
        await db.network_relays.insert_one(
            {
                "tenant_id": tenant_id,
                "relay_id": "WARSOC_RELAY_" + uuid.uuid4().hex,
                "relay_name": "Branch Relay",
                "version": "1.0.0",
                "status": "active",
                "last_seen": now,
                "created_at": now,
                "devices": [
                    {
                        "device_id": "branch-pfsense",
                        "vendor": "pfsense",
                        "model": "CE 2.8.1",
                        "transport": "udp",
                        "expected_eps": 100,
                    }
                ],
            }
        )

        response = await list_relay_status(
            request=types.SimpleNamespace(
                app=types.SimpleNamespace(state=types.SimpleNamespace(redis=redis_client))
            ),
            current_user={"tenant_id": tenant_id, "role": "admin"},
            _="admin",
            db=db,
        )

        assert response["capability"] == {
            "enabled": True,
            "entitled": True,
            "max_relays": 1,
            "active_relays": 1,
            "remaining_relays": 0,
            "can_manage": True,
            "metadata_only": True,
            "validated_firewall_vendors": ["pfsense"],
            "minimum_relay_version": relay_settings.network_relay_minimum_version,
            "setup_package_available": bool(
                relay_settings.network_relay_installer_url
                and relay_settings.network_relay_installer_sha256
            ),
            "setup_package_endpoint": "/api/v1/network-relay/setup-package",
            "setup_package_sha256": (
                relay_settings.network_relay_installer_sha256 or None
            ),
            "publisher_trust": "hash_allowlisted_pilot",
        }
        assert response["relays"][0]["relay_name"] == "Branch Relay"
        assert response["relays"][0]["device_count"] == 1
        assert response["relays"][0]["devices"][0]["vendor"] == "pfsense"
    finally:
        relay_settings.network_relay_enabled = original_enabled
        await db.tenants.delete_many({"tenant_id": tenant_id})
        await db.network_relays.delete_many({"tenant_id": tenant_id})


@pytest.mark.asyncio
async def test_relay_contract_endpoint_exposes_version_contract(async_client):
    """The public relay contract endpoint lets installers and operators
    compare an installed relay version against the backend minimum before
    evidence ingest gets rejected."""
    original_enabled = relay_settings.network_relay_enabled
    relay_settings.network_relay_enabled = True
    try:
        response = await async_client.get("/api/v1/network-relay/contract")
        assert response.status_code == 200, response.text
        body = response.json()
        assert body["minimum_version"] == relay_settings.network_relay_minimum_version
        assert body["signature_version"] == RELAY_SIGNATURE_VERSION
        assert body["schema_version"] == RELAY_SCHEMA_VERSION
        assert body["setup_package_sha256"] == (
            relay_settings.network_relay_installer_sha256 or None
        )
        assert body["publisher_trust"] == "hash_allowlisted_pilot"
    finally:
        relay_settings.network_relay_enabled = original_enabled


@pytest.mark.asyncio
async def test_relay_contract_endpoint_is_rate_limited(async_client):
    """Fix 4: PUBLIC_BOUNDED must be accurate — the public contract route
    enforces its per-client rate limit like every other unauthenticated
    boundary."""
    original_enabled = relay_settings.network_relay_enabled
    relay_settings.network_relay_enabled = True
    try:
        statuses = [
            (await async_client.get("/api/v1/network-relay/contract")).status_code
            for _ in range(11)
        ]
        assert statuses[:10] == [200] * 10
        assert statuses[10] == 429
    finally:
        relay_settings.network_relay_enabled = original_enabled


def _relay_batch(sequence: int = 1, previous_hash: str = RELAY_GENESIS_HASH) -> RelayBatch:
    return RelayBatch(
        schema_version="warsoc-relay-batch-v1",
        relay_id=f"WARSOC_RELAY_{uuid.uuid4().hex}",
        chain_id=uuid.uuid4().hex,
        key_epoch=1,
        sequence=sequence,
        previous_batch_hash=previous_hash,
        created_at=datetime.now(timezone.utc),
        events=[_relay_event()],
    )


@pytest.mark.asyncio
async def test_relay_route_commits_encrypted_source_before_redis_dispatch(
    async_client,
    db,
    redis_client,
):
    original_enabled = relay_settings.network_relay_enabled
    relay_settings.network_relay_enabled = True
    tenant_id = f"WARSOC_RELAY_INGEST_{uuid.uuid4().hex[:8]}"
    relay_id = f"WARSOC_RELAY_{uuid.uuid4().hex}"
    chain_id = uuid.uuid4().hex
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")
    signing_key_id = hashlib.sha256(
        private_key.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    ).hexdigest()
    try:
        await db.tenants.insert_one(
            {
                "tenant_id": tenant_id,
                "status": "active",
                "active": True,
                "has_active_plan": True,
                "max_agents": 1,
                "max_network_relays": 1,
                "retention_days": 90,
            }
        )
        await db.network_relays.insert_one(
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
                "version": "1.0.0",
                "devices": [
                    {
                        "device_id": "branch-firewall-1",
                        "vendor": "fortinet",
                        "transport": "udp",
                        "source_addresses": ["10.0.0.1"],
                        "expected_eps": 100,
                    }
                ],
            }
        )
        event = _relay_event()
        batch = RelayBatch(
            schema_version="warsoc-relay-batch-v1",
            relay_id=relay_id,
            chain_id=chain_id,
            key_epoch=1,
            sequence=1,
            previous_batch_hash=RELAY_GENESIS_HASH,
            created_at=datetime.now(timezone.utc),
            events=[event],
        )
        raw_body = orjson.dumps(batch.model_dump(mode="json"))
        signature = private_key.sign(raw_body).hex()
        token = jwt.encode(
            {
                "sub": relay_id,
                "tenant_id": tenant_id,
                "type": "network_relay",
                "jti": uuid.uuid4().hex,
                "exp": datetime.now(timezone.utc) + timedelta(minutes=10),
            },
            SECRET_KEY,
            algorithm=ALGORITHM,
        )

        response = await async_client.post(
            "/api/v1/network-relay/ingest",
            content=raw_body,
            headers={
                "Authorization": f"Bearer {token}",
                "X-WarSOC-Signature": signature,
                "Content-Type": "application/json",
            },
        )
        assert response.status_code == 202, response.text
        assert response.json()["dispatch_published"] == 1

        duplicate = await async_client.post(
            "/api/v1/network-relay/ingest",
            content=raw_body,
            headers={
                "Authorization": f"Bearer {token}",
                "X-WarSOC-Signature": signature,
                "Content-Type": "application/json",
            },
        )
        assert duplicate.status_code == 202, duplicate.text
        assert duplicate.json()["status"] == "duplicate_acknowledged"
        assert duplicate.json()["queued"] == 0
        assert await db.source_envelopes_siem.count_documents(
            {"source_principal_id": relay_id, "state": "COMMITTED"}
        ) == 1
        envelope = await db.source_envelopes_siem.find_one(
            {"source_principal_id": relay_id}
        )
        assert envelope["dispatch_complete"] is True
        assert event.raw_message not in envelope["encrypted_package"]
        assert await redis_client.xlen("raw_logs_queue") == 1
    finally:
        relay_settings.network_relay_enabled = original_enabled


def test_fortinet_traffic_and_vpn_are_normalized_without_packet_payload():
    denied = parse_fortinet(
        '<189>1 2026-07-27T10:00:00Z fw1 fortigate - TRAFFIC - '
        'type=traffic subtype=forward action=deny srcip=10.0.0.4 srcport=52000 '
        'dstip=8.8.8.8 dstport=53 proto=17 sentbyte=120 rcvdbyte=0 policyid=7 '
        'msg="confidential-payload-marker"'
    )
    assert denied.device_event_time == datetime(2026, 7, 27, 10, 0, tzinfo=timezone.utc)
    assert denied.normalized["event_type"] == "network_connection_blocked"
    assert denied.normalized["src_ip"] == "10.0.0.4"
    assert denied.normalized["dst_port"] == 53
    assert "payload" not in denied.normalized
    assert "confidential-payload-marker" not in json.dumps(denied.normalized)

    vpn = parse_fortinet(
        'date=2026-07-27 time=10:01:00 type=event subtype=vpn '
        'action=login user="branch-admin" remip=203.0.113.7 status=success'
    )
    assert vpn.normalized["event_type"] == "vpn_authentication"
    assert vpn.normalized["action"] == "successful"
    assert vpn.normalized["user"] == "branch-admin"
    assert vpn.normalized["src_ip"] == "203.0.113.7"


@pytest.mark.asyncio
async def test_relay_destination_aliases_drive_native_port_scan_rules(redis_client):
    engine = CorrelationEngine(redis_client, SIEM_RULES)
    tenant_id = f"WARSOC_RELAY_SCAN_{uuid.uuid4().hex[:8]}"
    alerts = []

    for offset in range(10):
        log_entry = {
            "event_uid": f"relay-scan-{uuid.uuid4().hex}",
            "event_id": "NET-CONNECTION-BLOCK",
            "event_type": "network_connection_blocked",
            "source_ip": "198.51.100.25",
            "processed_data": {
                "event_type": "network_connection_blocked",
                "src_ip": "198.51.100.25",
                "dst_ip": f"192.0.2.{offset + 20}",
                "dst_port": 4000 + offset,
                "action": "block",
            },
        }
        alerts.extend(
            await engine.run_dynamic_rules(
                tenant_id,
                "198.51.100.25",
                "NETWORK_DEVICE",
                "NET-CONNECTION-BLOCK",
                event_type="network_connection_blocked",
                timestamp_iso=datetime.now(timezone.utc).isoformat(),
                log_entry=log_entry,
            )
        )

    dynamic_rules = {alert.get("dynamic_rule") for alert in alerts}
    assert "vertical_port_scan" in dynamic_rules
    assert "horizontal_port_scan" in dynamic_rules


def test_cisco_asa_and_mikrotik_preserve_conservative_outcomes():
    cisco = parse_cisco_asa(
        '<166>Jul 27 10:02:00 asa1 %ASA-4-106023: Deny tcp src inside:'
        '10.0.0.10/50100 dst outside:198.51.100.8/443 by access-group "inside"'
    )
    assert cisco.normalized["event_type"] == "network_connection_blocked"
    assert cisco.normalized["message_id"] == "106023"
    assert cisco.normalized["dst_port"] == 443
    assert "access-group" not in cisco.normalized["message"]

    mikrotik = parse_mikrotik(
        '<134>Jul 27 10:03:00 router1 firewall,info forward: in:ether2 out:ether1, '
        'connection-state:new proto TCP (SYN), 10.0.0.20:51000->198.51.100.20:443, len 60'
    )
    # RouterOS prefixes are customer-defined. Absence of an explicit drop must
    # not be relabelled as an allow event.
    assert mikrotik.normalized["event_type"] == "network_observation"
    assert mikrotik.normalized["dst_ip"] == "198.51.100.20"
    assert "connection-state" not in mikrotik.normalized["message"]

    vpn = parse_cisco_asa(
        '<166>Jul 27 10:03:01 asa1 %ASA-6-113012: AAA user authentication '
        'Successful : local database : user = branch-admin'
    )
    assert vpn.normalized["event_type"] == "vpn_authentication"
    assert vpn.normalized["action"] == "successful"
    assert vpn.normalized["user"] == "branch-admin"

    rejected = parse_cisco_asa(
        '<166>Jul 27 10:03:02 asa1 %ASA-6-113005: AAA user authentication '
        'Rejected : reason = Unspecified : server = 10.0.0.2 : user = analyst '
        ': user IP = 203.0.113.44'
    )
    assert rejected.normalized["action"] == "rejected"
    assert rejected.normalized["user"] == "analyst"
    assert rejected.normalized["src_ip"] == "203.0.113.44"

    with pytest.raises(NetworkParseError):
        parse_mikrotik(
            "firewall,debug,packet PACKET: 45 00 00 34 payload-content-out-of-scope"
        )


def test_generic_and_malformed_messages_fail_or_degrade_safely():
    generic = parse_network_message(
        "generic", '<13>1 2026-07-27T10:04:00Z appliance app - MSG-1 - status changed'
    )
    assert generic.normalized["event_type"] == "network_observation"
    assert generic.normalized["message_id"] == "MSG-1"
    with pytest.raises(NetworkParseError):
        parse_fortinet('type=traffic msg="unterminated')


def test_pfsense_filterlog_ipv4_ipv6_and_fail_closed_contract():
    blocked = parse_pfsense(
        '<134>1 2026-07-27T10:05:00Z pf1 filterlog - - - '
        '5,,,1000000103,em0,match,block,in,4,0x0,,64,1234,0,DF,6,tcp,60,'
        '192.0.2.10,198.51.100.20,50100,443,0,S,123,0,65535,,mss'
    )
    assert blocked.device_event_time == datetime(2026, 7, 27, 10, 5, tzinfo=timezone.utc)
    assert blocked.normalized == {
        "event_type": "network_connection_blocked",
        "action": "block",
        "direction": "in",
        "ip_version": 4,
        "rule_id": "5",
        "tracker_id": "1000000103",
        "interface_in": "em0",
        "reason": "match",
        "protocol": "tcp",
        "src_ip": "192.0.2.10",
        "dst_ip": "198.51.100.20",
        "src_port": 50100,
        "dst_port": 443,
        "packet_length": 60,
        "data_length": 0,
        "tcp_flags": "S",
        "message": "pfSense firewall block in",
        "hostname": "pf1",
        "severity": 6,
    }

    permitted = parse_pfsense(
        '<134>Jul 27 10:05:01 pf1 filterlog: '
        '6,,,1000000104,em1,match,pass,out,6,0x00,0,64,tcp,6,60,'
        '2001:db8::1,2001:4860:4860::8888,50101,443,0,S,124,0,65535,,mss'
    )
    assert permitted.normalized["event_type"] == "network_connection_permitted"
    assert permitted.normalized["ip_version"] == 6
    assert permitted.normalized["interface_out"] == "em1"
    assert permitted.normalized["dst_ip"] == "2001:4860:4860::8888"
    assert "payload" not in permitted.normalized

    # pfSense's default remote BSD format omits the hostname. This exact
    # envelope shape is emitted by pfSense CE 2.8.1 over UDP syslog.
    bsd_no_host = parse_pfsense(
        '<134>Aug  2 15:12:05 filterlog[55624]: '
        '4,,,1000000103,hn0,match,block,in,4,0x0,,128,49872,0,none,17,udp,78,'
        '172.19.224.1,172.19.239.255,137,137,58'
    )
    assert bsd_no_host.device_event_time is None
    assert bsd_no_host.normalized["event_type"] == "network_connection_blocked"
    assert bsd_no_host.normalized["src_ip"] == "172.19.224.1"
    assert bsd_no_host.normalized["dst_ip"] == "172.19.239.255"
    assert bsd_no_host.normalized["src_port"] == 137
    assert bsd_no_host.normalized["dst_port"] == 137
    assert bsd_no_host.normalized["severity"] == 6
    assert "hostname" not in bsd_no_host.normalized

    with pytest.raises(NetworkParseError):
        parse_pfsense("openvpn[123]: peer connected")
    with pytest.raises(NetworkParseError):
        parse_pfsense("filterlog: 5,,,100,em0,match,block,in,4")


def test_relay_schema_rejects_unknown_fields_and_raw_message_changes():
    event = _relay_event().model_dump(mode="json")
    event["normalized"]["packet_payload"] = "secret"
    with pytest.raises(ValidationError):
        RelayEvent.model_validate(event)

    event = _relay_event().model_dump(mode="json")
    event["raw_message"] += " altered"
    with pytest.raises(ValidationError):
        RelayEvent.model_validate(event)

    batch = _relay_batch().model_dump(mode="json")
    batch["schema_version"] = "future-unapproved-schema"
    with pytest.raises(ValidationError):
        RelayBatch.model_validate(batch)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("src_ip", "999.1.1.1"),
        ("dst_port", 70000),
        ("dropped_events", -1),
        ("spool_usage_bytes", True),
    ],
)
def test_relay_schema_rejects_malformed_normalized_values(field, value):
    event = _relay_event().model_dump(mode="json")
    event["normalized"][field] = value
    with pytest.raises(ValidationError):
        RelayEvent.model_validate(event)


def test_device_health_cannot_be_disguised_as_network_evidence():
    event = _relay_event().model_dump(mode="json")
    event["normalized"]["event_type"] = "device_health"
    with pytest.raises(ValidationError):
        RelayEvent.model_validate(event)


def test_relay_batch_builder_matches_cloud_schema_and_signature_contract():
    private_key = ed25519.Ed25519PrivateKey.generate()
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    parsed = parse_fortinet(
        "type=traffic action=deny srcip=10.0.0.2 dstip=198.51.100.2 dstport=443 proto=6"
    )
    event = relay_event_from_parsed(
        parsed,
        device_id="branch-firewall-1",
        transport="udp",
        source_address="10.0.0.1",
        raw_message="type=traffic action=deny srcip=10.0.0.2 dstip=198.51.100.2 dstport=443 proto=6",
        relay_receipt_time=datetime.now(timezone.utc),
        event_uid="relay-event-stable-0001",
    )
    signed = build_signed_batch(
        relay_id=f"WARSOC_RELAY_{uuid.uuid4().hex}",
        chain_id=uuid.uuid4().hex,
        key_epoch=1,
        sequence=1,
        previous_batch_hash=RELAY_GENESIS_HASH,
        events=[event],
        private_key_pem=private_pem,
    )
    validated = RelayBatch.model_validate_json(signed.body)
    assert validated.events[0].event_uid == "relay-event-stable-0001"
    assert signed.batch_hash == hashlib.sha256(signed.body).hexdigest()
    private_key.public_key().verify(bytes.fromhex(signed.signature), signed.body)


def test_relay_batch_preserves_signed_raw_message_whitespace():
    private_key = ed25519.Ed25519PrivateKey.generate()
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    raw_message = (
        " <134>Aug  2 15:12:05 filterlog[55624]: "
        "4,,,1000000103,hn0,match,block,in,4,0x0,,128,49872,0,none,17,udp,78,"
        "172.19.224.1,172.19.239.255,137,137,58   "
    )
    parsed = parse_pfsense(raw_message.strip())
    event = relay_event_from_parsed(
        parsed,
        device_id="pfsense-lab",
        transport="udp",
        source_address="192.0.2.1",
        raw_message=raw_message,
        relay_receipt_time=datetime.now(timezone.utc),
        event_uid="relay-event-whitespace-0001",
    )
    signed = build_signed_batch(
        relay_id=f"WARSOC_RELAY_{uuid.uuid4().hex}",
        chain_id=uuid.uuid4().hex,
        key_epoch=1,
        sequence=1,
        previous_batch_hash=RELAY_GENESIS_HASH,
        events=[event],
        private_key_pem=private_pem,
    )

    validated = RelayBatch.model_validate_json(signed.body)

    assert validated.events[0].raw_message == raw_message
    assert validated.events[0].raw_message_hash == hashlib.sha256(
        raw_message.encode("utf-8")
    ).hexdigest()


def test_encrypted_spools_are_fifo_bounded_and_independent(tmp_path):
    key = os.urandom(32)
    evidence = EncryptedBoundedSpool(
        tmp_path / "evidence.db",
        stream_name="evidence",
        encryption_key=key,
        max_payload_bytes=220,
        max_record_bytes=180,
        min_free_disk_bytes=0,
    )
    control = EncryptedBoundedSpool(
        tmp_path / "control.db",
        stream_name="control",
        encryption_key=key,
        max_payload_bytes=220,
        max_record_bytes=180,
        min_free_disk_bytes=0,
    )
    first = evidence.append({"event_uid": "event-0001", "message": "private-firewall-log-a"})
    second = evidence.append({"event_uid": "event-0002", "message": "private-firewall-log-b"})
    control.append({"state": "SATURATED", "dropped": 12})

    assert [row.sequence for row in evidence.records()] == [first.sequence, second.sequence]
    assert b"private-firewall-log-a" not in (tmp_path / "evidence.db").read_bytes()
    with pytest.raises(SpoolFullError):
        evidence.append({"event_uid": "event-0003", "message": "x" * 120})
    assert control.stats()["records"] == 1
    assert evidence.acknowledge_through(first.sequence) == 1
    assert [row.sequence for row in evidence.records()] == [second.sequence]
    evidence.verify_chain()
    evidence.close()
    control.close()


def test_spool_detects_ciphertext_tampering(tmp_path):
    path = tmp_path / "tamper.db"
    spool = EncryptedBoundedSpool(
        path,
        stream_name="evidence",
        encryption_key=os.urandom(32),
        max_payload_bytes=1024,
        max_record_bytes=512,
        min_free_disk_bytes=0,
    )
    spool.append({"event_uid": "event-tamper", "message": "sensitive"})
    spool._db.execute(
        "UPDATE spool_records SET ciphertext=? WHERE sequence=1", (b"corrupted",)
    )
    with pytest.raises(SpoolIntegrityError):
        list(spool.records())
    with pytest.raises(SpoolIntegrityError):
        spool.verify_chain()
    spool.close()


def test_collector_limits_before_parse_and_reports_loss_in_control_spool(tmp_path):
    key = os.urandom(32)
    evidence = EncryptedBoundedSpool(
        tmp_path / "collector-evidence.db",
        stream_name="evidence",
        encryption_key=key,
        max_payload_bytes=4096,
        max_record_bytes=2048,
        min_free_disk_bytes=0,
    )
    control = EncryptedBoundedSpool(
        tmp_path / "collector-control.db",
        stream_name="control",
        encryption_key=key,
        max_payload_bytes=4096,
        max_record_bytes=2048,
        min_free_disk_bytes=0,
    )
    collector = RelayCollector(
        relay_id=f"WARSOC_RELAY_{uuid.uuid4().hex}",
        devices=[
            RelayDevice(
                device_id="fw-1",
                vendor="fortinet",
                source_addresses=("10.0.0.1/32",),
                expected_eps=1,
            )
        ],
        evidence_spool=evidence,
        control_spool=control,
        max_datagram_bytes=512,
        global_eps=2,
        global_bytes_per_second=1024,
    )
    message = b"type=traffic action=deny srcip=10.0.0.2 dstip=198.51.100.2 dstport=443 proto=6"
    assert collector.accept_datagram(message, source_address="10.0.0.1").status == "accepted"
    assert collector.accept_datagram(message, source_address="10.0.0.1").status == "accepted"
    limited = collector.accept_datagram(message, source_address="10.0.0.1")
    assert limited.status == "dropped"
    assert limited.reason == "edge_rate_limit"
    unknown = collector.accept_datagram(message, source_address="10.0.0.99")
    assert unknown.reason == "unregistered_or_ambiguous_source"
    assert collector.flush_loss_summaries() == 2
    controls = list(control.records())
    assert {row.payload["normalized"]["reason"] for row in controls} == {
        "edge_rate_limit",
        "unregistered_or_ambiguous_source",
    }
    affected = {
        row.payload["normalized"]["reason"]: row.payload["normalized"][
            "affected_device_id"
        ]
        for row in controls
    }
    assert affected == {
        "edge_rate_limit": "fw-1",
        "unregistered_or_ambiguous_source": "unknown",
    }
    assert all(row.payload["record_class"] == "control" for row in controls)
    evidence.close()
    control.close()


def test_device_rate_limit_does_not_exhaust_shared_relay_capacity(tmp_path):
    key = os.urandom(32)
    evidence = EncryptedBoundedSpool(
        tmp_path / "fairness-evidence.db",
        stream_name="evidence",
        encryption_key=key,
        max_payload_bytes=16384,
        max_record_bytes=2048,
        min_free_disk_bytes=0,
    )
    control = EncryptedBoundedSpool(
        tmp_path / "fairness-control.db",
        stream_name="control",
        encryption_key=key,
        max_payload_bytes=4096,
        max_record_bytes=2048,
        min_free_disk_bytes=0,
    )
    collector = RelayCollector(
        relay_id=f"WARSOC_RELAY_{uuid.uuid4().hex}",
        devices=[
            RelayDevice(
                device_id="fw-noisy",
                vendor="fortinet",
                source_addresses=("10.0.0.1/32",),
                expected_eps=1,
            ),
            RelayDevice(
                device_id="fw-healthy",
                vendor="fortinet",
                source_addresses=("10.0.0.2/32",),
                expected_eps=1,
            ),
        ],
        evidence_spool=evidence,
        control_spool=control,
        global_eps=2,
        global_bytes_per_second=1024,
    )
    message = b"type=traffic action=deny srcip=10.0.0.3 dstip=198.51.100.2 dstport=443 proto=6"

    assert collector.accept_datagram(message, source_address="10.0.0.1").status == "accepted"
    assert collector.accept_datagram(message, source_address="10.0.0.1").status == "accepted"
    for _ in range(20):
        assert collector.accept_datagram(message, source_address="10.0.0.1").status == "dropped"

    assert collector.accept_datagram(message, source_address="10.0.0.2").status == "accepted"
    assert collector.accept_datagram(message, source_address="10.0.0.2").status == "accepted"
    evidence.close()
    control.close()


@pytest.mark.asyncio
async def test_outbox_retries_exact_batch_prioritizes_control_and_acks_fifo(tmp_path):
    key = os.urandom(32)
    private_key = ed25519.Ed25519PrivateKey.generate()
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    relay_id = f"WARSOC_RELAY_{uuid.uuid4().hex}"
    evidence = EncryptedBoundedSpool(
        tmp_path / "outbox-evidence.db",
        stream_name="evidence",
        encryption_key=key,
        max_payload_bytes=8192,
        max_record_bytes=4096,
        min_free_disk_bytes=0,
    )
    control = EncryptedBoundedSpool(
        tmp_path / "outbox-control.db",
        stream_name="control",
        encryption_key=key,
        max_payload_bytes=8192,
        max_record_bytes=4096,
        min_free_disk_bytes=0,
    )
    evidence.append(_relay_event().model_dump(mode="json"))
    control_event = _relay_event(
        record_class="control",
        device_id=relay_id,
        vendor="generic",
        transport="api",
        source_address="127.0.0.1",
        normalized={"event_type": "device_health", "state": "DEGRADED"},
    )
    control.append(control_event.model_dump(mode="json"))
    outbox = RelayOutbox(
        tmp_path / "cloud-state.db",
        relay_id=relay_id,
        private_key_pem=private_pem,
        encryption_key=key,
    )
    observed_bodies = []
    attempts = 0

    async def handler(request: httpx.Request) -> httpx.Response:
        nonlocal attempts
        attempts += 1
        observed_bodies.append(request.content)
        private_key.public_key().verify(
            bytes.fromhex(request.headers["X-WarSOC-Signature"]), request.content
        )
        if attempts == 1:
            return httpx.Response(503, json={"detail": "retry"})
        batch = RelayBatch.model_validate_json(request.content)
        return httpx.Response(
            202, json={"status": "accepted", "queued": 1, "sequence": batch.sequence}
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        first = await deliver_once(
            outbox,
            control_spool=control,
            evidence_spool=evidence,
            ingest_url="https://api.example.test/api/v1/network-relay/ingest",
            relay_token="relay-token",
            client=client,
        )
        second = await deliver_once(
            outbox,
            control_spool=control,
            evidence_spool=evidence,
            ingest_url="https://api.example.test/api/v1/network-relay/ingest",
            relay_token="relay-token",
            client=client,
        )
    assert first == "retry"
    assert second == "accepted"
    assert observed_bodies[0] == observed_bodies[1]
    assert control.stats()["records"] == 0
    assert evidence.stats()["records"] == 1
    assert outbox.pending() is None
    outbox.close()
    evidence.close()
    control.close()


@pytest.mark.asyncio
async def test_redis_batch_admission_is_atomic_duplicate_safe_and_does_not_dispatch(redis_client):
    batch = _relay_batch()
    relay_context = {
        "relay_id": batch.relay_id,
        "tenant_id": "WARSOC_TEST_RELAY",
        "relay": {
            "last_sequence": 0,
            "last_batch_hash": RELAY_GENESIS_HASH,
            "chain_id": None,
            "key_epoch": 1,
        },
    }
    payloads = [json.dumps({"event_uid": batch.events[0].event_uid})]
    batch_hash = hashlib.sha256(orjson.dumps(batch.model_dump(mode="json"))).hexdigest()
    assert await _admit_batch(
        redis_client,
        relay_context,
        batch,
        batch_hash,
        payloads,
        quota_bytes=1000,
        payload_bytes=100,
    ) == 1
    assert await _admit_batch(
        redis_client,
        relay_context,
        batch,
        batch_hash,
        payloads,
        quota_bytes=1000,
        payload_bytes=100,
    ) == 2
    # Chain/quota admission is deliberately separate from dispatch. The route
    # must commit the encrypted Mongo source envelope before its outbox writes
    # the first Redis stream entry.
    assert await redis_client.xlen("raw_logs_queue") == 0
    quota_keys = [key async for key in redis_client.scan_iter("warsoc:ingest:bytes:*")]
    assert len(quota_keys) == 2
    quota_values = [int(await redis_client.get(key)) for key in quota_keys]
    assert quota_values == [100, 100]

    second = _relay_batch(sequence=2, previous_hash=batch_hash)
    second = second.model_copy(update={"relay_id": batch.relay_id, "chain_id": batch.chain_id})
    second_hash = hashlib.sha256(orjson.dumps(second.model_dump(mode="json"))).hexdigest()
    assert await _admit_batch(
        redis_client,
        relay_context,
        second,
        second_hash,
        [json.dumps({"event_uid": second.events[0].event_uid})],
        quota_bytes=1000,
        payload_bytes=100,
    ) == 1
    assert await redis_client.xlen("raw_logs_queue") == 0

    platform_rejected = second.model_copy(
        update={"sequence": 3, "previous_batch_hash": second_hash}
    )
    assert await _admit_batch(
        redis_client,
        relay_context,
        platform_rejected,
        "f" * 64,
        [json.dumps({"event_uid": "over-platform-quota"})],
        quota_bytes=1000,
        platform_quota_bytes=200,
        payload_bytes=100,
    ) == -5
    assert await redis_client.xlen("raw_logs_queue") == 0

    wrong_epoch = _relay_batch()
    wrong_epoch = wrong_epoch.model_copy(
        update={
            "relay_id": f"WARSOC_RELAY_{uuid.uuid4().hex}",
            "key_epoch": 1,
        }
    )
    wrong_context = {
        "relay_id": wrong_epoch.relay_id,
        "tenant_id": "WARSOC_TEST_RELAY",
        "relay": {
            "last_sequence": 0,
            "last_batch_hash": RELAY_GENESIS_HASH,
            "chain_id": None,
            "key_epoch": 2,
        },
    }
    assert await _admit_batch(
        redis_client,
        wrong_context,
        wrong_epoch,
        "e" * 64,
        [json.dumps({"event_uid": wrong_epoch.events[0].event_uid})],
    ) == -2

    out_of_sequence = second.model_copy(update={"sequence": 4, "previous_batch_hash": second_hash})
    assert await _admit_batch(
        redis_client,
        relay_context,
        out_of_sequence,
        "a" * 64,
        [json.dumps({"event_uid": "must-not-queue"})],
        quota_bytes=1000,
        payload_bytes=100,
    ) == -1
    assert await redis_client.xlen("raw_logs_queue") == 0

    quota_rejected = second.model_copy(
        update={"sequence": 3, "previous_batch_hash": second_hash}
    )
    assert await _admit_batch(
        redis_client,
        relay_context,
        quota_rejected,
        "d" * 64,
        [json.dumps({"event_uid": "over-quota"})],
        quota_bytes=200,
        payload_bytes=100,
    ) == -4
    assert await redis_client.xlen("raw_logs_queue") == 0


def test_relay_events_encrypt_raw_vendor_evidence_before_queueing(monkeypatch):
    key = Fernet.generate_key()
    monkeypatch.setattr(relay_settings, "encryption_key", key.decode("ascii"))
    batch = _relay_batch()
    event = _queue_event(
        batch.events[0],
        {
            "tenant_id": "WARSOC_TEST_RELAY",
            "relay_id": batch.relay_id,
            "relay": {"signing_key_id": "key-1", "version": "relay-test"},
        },
        batch,
        "b" * 64,
        "c" * 128,
        datetime.now(timezone.utc),
    )
    plaintext = json.loads(Fernet(key).decrypt(event["raw_data"].encode("ascii")))

    assert event["raw_data_encryption_version"] == "fernet-v1"
    assert plaintext["raw_message"] == batch.events[0].raw_message
    assert plaintext["raw_message_hash"] == batch.events[0].raw_message_hash
    assert batch.events[0].raw_message not in orjson.dumps(event).decode("utf-8")


def test_relay_event_queueing_fails_closed_without_evidence_key(monkeypatch):
    monkeypatch.setattr(relay_settings, "encryption_key", "")
    batch = _relay_batch()

    with pytest.raises(RuntimeError, match="encryption is not configured"):
        _queue_event(
            batch.events[0],
            {
                "tenant_id": "WARSOC_TEST_RELAY",
                "relay_id": batch.relay_id,
                "relay": {"signing_key_id": "key-1", "version": "relay-test"},
            },
            batch,
            "b" * 64,
            "c" * 128,
            datetime.now(timezone.utc),
        )


def test_relay_events_are_source_isolated_from_legacy_keyword_rules(monkeypatch):
    monkeypatch.setattr(
        relay_settings, "encryption_key", Fernet.generate_key().decode("ascii")
    )
    batch = _relay_batch()
    event = _queue_event(
        batch.events[0],
        {
            "tenant_id": "WARSOC_TEST_RELAY",
            "relay_id": batch.relay_id,
            "relay": {"signing_key_id": "key-1", "version": "relay-test"},
        },
        batch,
        "b" * 64,
        "c" * 128,
        datetime.now(timezone.utc),
    )
    family = _trusted_telemetry_family(
        event, event["event_id"], event["event_type"]
    )
    assert family == "network"
    assert _keyword_sources_for_event(family, event["event_id"], {}) == ()


def _network_log(event_type: str, *, action: str, src_ip: str | None, user: str):
    normalized = {
        "event_type": event_type,
        "action": action,
        "user": user,
        "dst_ip": "8.8.8.8",
        "dst_port": 443,
    }
    if src_ip:
        normalized["src_ip"] = src_ip
    return {
        "tenant_id": f"WARSOC_HYBRID_{uuid.uuid4().hex[:8]}",
        "agent_id": "WARSOC_RELAY_TEST",
        "network_device_id": "branch-firewall-1",
        "source_type": "network_device",
        "source_assurance": "relay_attested",
        "signature_verified": True,
        "time_confidence": "high",
        "telemetry_family": "network",
        "event_id": "NET-VPN-AUTH" if event_type == "vpn_authentication" else "NET-CONNECTION-ALLOW",
        "event_type": event_type,
        "event_uid": f"network-{uuid.uuid4().hex}",
        "source_ip": src_ip or "10.0.0.1",
        "user": user,
        "processed_data": normalized,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@pytest.mark.asyncio
async def test_hybrid_correlation_is_inert_when_relay_feature_is_disabled(
    redis_client, monkeypatch
):
    monkeypatch.setenv("NETWORK_RELAY_ENABLED", "false")
    engine = CorrelationEngine(redis_client, SIEM_RULES)
    tenant_id = f"WARSOC_HYBRID_{uuid.uuid4().hex[:8]}"
    event = {
        "tenant_id": tenant_id,
        "agent_id": "WARSOC_AGENT_TEST",
        "telemetry_family": "windows",
        "event_id": "1102",
        "event_type": "clear_logs",
        "event_uid": f"windows-{uuid.uuid4().hex}",
        "source_ip": "10.0.0.20",
        "user": "Administrator",
        "processed_data": {"computer": "POS-01"},
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    assert await engine.check_hybrid_network_correlations(
        tenant_id,
        event["source_ip"],
        event["user"],
        event["event_id"],
        event["event_type"],
        event["timestamp"],
        event,
    ) == []
    assert [key async for key in redis_client.scan_iter("warsoc:hybrid:*")] == []


@pytest.mark.asyncio
async def test_hybrid_vpn_spray_requires_remote_ip_and_five_distinct_users(
    redis_client, monkeypatch
):
    monkeypatch.setenv("NETWORK_RELAY_ENABLED", "true")
    engine = CorrelationEngine(redis_client, SIEM_RULES)
    tenant_id = f"WARSOC_HYBRID_{uuid.uuid4().hex[:8]}"

    unattributed = _network_log(
        "vpn_authentication", action="rejected", src_ip=None, user="user-0"
    )
    unattributed["tenant_id"] = tenant_id
    assert await engine.run_all(
        tenant_id, unattributed["source_ip"], "user-0", "NET-VPN-AUTH",
        event_type="vpn_authentication", log_entry=unattributed,
    ) == []

    alerts = []
    for index in range(5):
        event = _network_log(
            "vpn_authentication",
            action="rejected",
            src_ip="203.0.113.44",
            user=f"user-{index}",
        )
        event["tenant_id"] = tenant_id
        alerts = await engine.run_all(
            tenant_id,
            event["source_ip"],
            event["user"],
            event["event_id"],
            event_type=event["event_type"],
            timestamp_iso=event["timestamp"],
            log_entry=event,
        )
        if index < 4:
            assert alerts == []

    spray = [alert for alert in alerts if alert["type"] == "HYBRID_VPN_PASSWORD_SPRAY"]
    assert len(spray) == 1
    assert spray[0]["unique_targets"] == 5
    assert spray[0]["source_assurance"] == "relay_attested"


@pytest.mark.asyncio
async def test_hybrid_vpn_to_windows_logon_is_context_not_threat(
    redis_client, monkeypatch
):
    monkeypatch.setenv("NETWORK_RELAY_ENABLED", "true")
    engine = CorrelationEngine(redis_client, SIEM_RULES)
    tenant_id = f"WARSOC_HYBRID_{uuid.uuid4().hex[:8]}"
    vpn = _network_log(
        "vpn_authentication",
        action="successful",
        src_ip="203.0.113.45",
        user="branch-admin",
    )
    vpn["tenant_id"] = tenant_id
    assert await engine.run_all(
        tenant_id, vpn["source_ip"], vpn["user"], vpn["event_id"],
        event_type=vpn["event_type"], timestamp_iso=vpn["timestamp"], log_entry=vpn,
    ) == []

    windows = {
        "tenant_id": tenant_id,
        "agent_id": "WARSOC_AGENT_TEST",
        "telemetry_family": "windows",
        "event_id": "4624",
        "event_type": "successful_login",
        "event_uid": f"windows-{uuid.uuid4().hex}",
        "source_ip": "203.0.113.45",
        "user": "branch-admin",
        "processed_data": {
            "user": "branch-admin",
            "source_network_address": "203.0.113.45",
            "logon_type": "10",
        },
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    assert await engine.run_all(
        tenant_id, windows["source_ip"], windows["user"], "4624",
        event_type="successful_login", timestamp_iso=windows["timestamp"], log_entry=windows,
    ) == []
    assert windows["hybrid_correlations"] == [
        {
            "type": "vpn_to_windows_logon",
            "outcome": "observed",
            "source_assurance": "relay_attested",
            "vpn_event_uid": vpn["event_uid"],
            "network_device_id": "branch-firewall-1",
            "remote_ip": "203.0.113.45",
        }
    ]


@pytest.mark.asyncio
async def test_hybrid_high_risk_host_event_requires_same_source_and_public_destination(
    redis_client, monkeypatch
):
    monkeypatch.setenv("NETWORK_RELAY_ENABLED", "true")
    engine = CorrelationEngine(redis_client, SIEM_RULES)
    tenant_id = f"WARSOC_HYBRID_{uuid.uuid4().hex[:8]}"
    host_event = {
        "tenant_id": tenant_id,
        "agent_id": "WARSOC_AGENT_TEST",
        "telemetry_family": "windows",
        "event_id": "1102",
        "event_type": "clear_logs",
        "event_uid": f"windows-{uuid.uuid4().hex}",
        "source_ip": "10.0.0.20",
        "user": "Administrator",
        "processed_data": {"computer": "POS-01"},
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    assert await engine.run_all(
        tenant_id, "10.0.0.20", "Administrator", "1102",
        event_type="clear_logs", timestamp_iso=host_event["timestamp"], log_entry=host_event,
    ) == []

    unrelated = _network_log(
        "network_connection_permitted", action="built", src_ip="10.0.0.21", user="-"
    )
    unrelated["tenant_id"] = tenant_id
    assert await engine.run_all(
        tenant_id, "10.0.0.21", "-", unrelated["event_id"],
        event_type=unrelated["event_type"], log_entry=unrelated,
    ) == []

    stale = _network_log(
        "network_connection_permitted", action="built", src_ip="10.0.0.20", user="-"
    )
    stale["tenant_id"] = tenant_id
    stale["timestamp"] = (
        datetime.fromisoformat(host_event["timestamp"]) - timedelta(hours=1)
    ).isoformat()
    stale_alerts = await engine.run_all(
        tenant_id, "10.0.0.20", "-", stale["event_id"],
        event_type=stale["event_type"], timestamp_iso=stale["timestamp"], log_entry=stale,
    )
    assert not any(
        alert["type"] == "HYBRID_AUDIT_LOG_CLEARED_TO_PUBLIC_NETWORK"
        for alert in stale_alerts
    )

    outbound = _network_log(
        "network_connection_permitted", action="built", src_ip="10.0.0.20", user="-"
    )
    outbound["tenant_id"] = tenant_id
    outbound["time_confidence"] = "low"
    alerts = await engine.run_all(
        tenant_id, "10.0.0.20", "-", outbound["event_id"],
        event_type=outbound["event_type"], timestamp_iso=outbound["timestamp"], log_entry=outbound,
    )
    hybrid = [
        alert for alert in alerts
        if alert["type"] == "HYBRID_AUDIT_LOG_CLEARED_TO_PUBLIC_NETWORK"
    ]
    assert len(hybrid) == 1
    assert hybrid[0]["host_event_uid"] == host_event["event_uid"]
    assert hybrid[0]["destination_ip"] == "8.8.8.8"
    assert hybrid[0]["confidence"] == "medium"
    assert hybrid[0]["clock_confidence"] == "low"


@pytest.mark.asyncio
async def test_watchdog_emits_silent_device_alert_exactly_once_per_window(
    db, redis_client
):
    """The watchdog must emit exactly one DEVICE_SILENT alert per device per
    silence window, and not re-fire on subsequent scans within the same window."""
    from app.workers.network_relay_watchdog import run_network_relay_watchdog

    now = datetime.now(timezone.utc)
    tenant_id = f"WARSOC_WATCHDOG_{uuid.uuid4().hex[:8]}"
    relay_id = "WARSOC_RELAY_WATCHDOG_TEST"
    device_id = "silent-firewall-01"
    silence_seconds = 900

    # Seed a device that went silent 20 minutes ago
    silent_time = now - timedelta(minutes=20)
    await db["network_relay_device_status"].insert_one(
        {
            "tenant_id": tenant_id,
            "relay_id": relay_id,
            "device_id": device_id,
            "vendor": "pfsense",
            "model": "netgate-2100",
            "last_event_at": silent_time,
        }
    )

    # First scan: should emit exactly one alert
    result = await run_network_relay_watchdog(
        db, redis_client, silence_seconds=silence_seconds, now=now
    )
    assert result["silent_devices_found"] == 1
    assert result["alerts_emitted"] == 1

    # Verify the alert was persisted as a durable SIEM alert
    alerts = await db["security_alerts"].find(
        {"tenant_id": tenant_id, "device_id": device_id}
    ).to_list(length=10)
    assert len(alerts) == 1
    assert alerts[0]["alert_type"] == "DEVICE_SILENT"
    assert ":DEVICE_SILENT:" in alerts[0]["alert_uid"]
    assert alerts[0]["severity"] == "HIGH"
    assert alerts[0]["vendor"] == "pfsense"
    assert alerts[0]["status"] == "NEW"
    assert alerts[0]["pack"] == "SIEM"
    assert isinstance(alerts[0]["timestamp"], datetime)
    assert _as_utc(alerts[0]["_expire_at"]) > now

    # Second scan (same window): should NOT re-fire
    result2 = await run_network_relay_watchdog(
        db, redis_client, silence_seconds=silence_seconds, now=now
    )
    assert result2["silent_devices_found"] == 1
    assert result2["alerts_emitted"] == 0

    # Total alerts still 1
    alerts2 = await db["security_alerts"].find(
        {"tenant_id": tenant_id, "device_id": device_id}
    ).to_list(length=10)
    assert len(alerts2) == 1


@pytest.mark.asyncio
async def test_watchdog_does_not_alert_for_recently_active_devices(db, redis_client):
    """Devices that sent events within the silence window must not trigger alerts."""
    from app.workers.network_relay_watchdog import run_network_relay_watchdog

    now = datetime.now(timezone.utc)
    tenant_id = f"WARSOC_WATCHDOG_OK_{uuid.uuid4().hex[:8]}"

    # Seed a device that sent evidence 2 minutes ago (well within 900s window)
    await db["network_relay_device_status"].insert_one(
        {
            "tenant_id": tenant_id,
            "relay_id": "WARSOC_RELAY_OK",
            "device_id": "active-firewall-01",
            "vendor": "fortinet",
            "last_event_at": now - timedelta(minutes=2),
        }
    )

    result = await run_network_relay_watchdog(
        db, redis_client, silence_seconds=900, now=now
    )
    assert result["silent_devices_found"] == 0
    assert result["alerts_emitted"] == 0


@pytest.mark.asyncio
async def test_watchdog_alerts_new_window_after_device_stays_silent(
    db, redis_client
):
    """After a full silence window passes, the watchdog must emit a new alert
    for the next window (proving the window-key mechanism works)."""
    from app.workers.network_relay_watchdog import run_network_relay_watchdog

    now = datetime.now(timezone.utc)
    tenant_id = f"WARSOC_WATCHDOG_MW_{uuid.uuid4().hex[:8]}"
    relay_id = "WARSOC_RELAY_MW"
    device_id = "stale-firewall-01"
    silence_seconds = 900

    # Device last seen 40 minutes ago — spans two 900s windows
    last_seen = now - timedelta(minutes=40)
    await db["network_relay_device_status"].insert_one(
        {
            "tenant_id": tenant_id,
            "relay_id": relay_id,
            "device_id": device_id,
            "vendor": "cisco",
            "last_event_at": last_seen,
        }
    )

    # First scan: emit alert for window 0
    result = await run_network_relay_watchdog(
        db, redis_client, silence_seconds=silence_seconds, now=now
    )
    assert result["alerts_emitted"] == 1

    # Simulate time advancing by one full silence window (900s)
    future_now = now + timedelta(seconds=silence_seconds)
    result2 = await run_network_relay_watchdog(
        db, redis_client, silence_seconds=silence_seconds, now=future_now
    )
    # The device is still silent, and the window key has changed,
    # so a new alert should be emitted
    assert result2["silent_devices_found"] == 1
    assert result2["alerts_emitted"] == 1

    # Total: 2 alerts (one per window)
    total = await db["security_alerts"].count_documents(
        {"tenant_id": tenant_id, "device_id": device_id}
    )
    assert total == 2


@pytest.mark.asyncio
async def test_watchdog_emits_degraded_device_alert(db, redis_client):
    """A device whose last_failure_at is more recent than its last_event_at
    (and is not yet silent) must produce exactly one DEVICE_DEGRADED alert."""
    from app.workers.network_relay_watchdog import run_network_relay_watchdog

    now = datetime.now(timezone.utc)
    tenant_id = f"WARSOC_WATCHDOG_DG_{uuid.uuid4().hex[:8]}"
    relay_id = "WARSOC_RELAY_DG"
    device_id = "degraded-firewall-01"

    # Device sent evidence 2 minutes ago but reported a failure 1 minute ago
    await db["network_relay_device_status"].insert_one(
        {
            "tenant_id": tenant_id,
            "relay_id": relay_id,
            "device_id": device_id,
            "vendor": "mikrotik",
            "last_event_at": now - timedelta(minutes=2),
            "last_failure_at": now - timedelta(minutes=1),
            "last_failure_reason": "rate_limited",
            "last_reported_drops": 42,
        }
    )

    result = await run_network_relay_watchdog(
        db, redis_client, silence_seconds=900, now=now
    )
    assert result["degraded_devices_found"] == 1
    assert result["alerts_device_degraded_emitted"] == 1
    assert result["silent_devices_found"] == 0

    alert = await db["security_alerts"].find_one(
        {"tenant_id": tenant_id, "device_id": device_id}
    )
    assert alert is not None
    assert alert["alert_type"] == "DEVICE_DEGRADED"
    assert alert["severity"] == "MEDIUM"
    assert alert["last_failure_reason"] == "rate_limited"
    assert alert["last_reported_drops"] == 42
    assert alert["event_id"] == device_id
    assert _as_utc(alert["_expire_at"]) > now

    # Re-scan in the same window: no re-fire
    result2 = await run_network_relay_watchdog(
        db, redis_client, silence_seconds=900, now=now
    )
    assert result2["alerts_device_degraded_emitted"] == 0


@pytest.mark.asyncio
async def test_watchdog_emits_relay_offline_alert(db, redis_client):
    """An active relay whose last_seen is stale must produce exactly one
    RELAY_OFFLINE alert, even though no device status exists."""
    from app.workers.network_relay_watchdog import run_network_relay_watchdog

    now = datetime.now(timezone.utc)
    tenant_id = f"WARSOC_WATCHDOG_RO_{uuid.uuid4().hex[:8]}"
    relay_id = f"WARSOC_RELAY_RO_{uuid.uuid4().hex[:6]}"

    await db["network_relays"].insert_one(
        {
            "tenant_id": tenant_id,
            "relay_id": relay_id,
            "status": "active",
            "last_seen": now - timedelta(minutes=30),
            "version": "1.0.0",
        }
    )

    result = await run_network_relay_watchdog(
        db, redis_client, silence_seconds=900, now=now
    )
    assert result["offline_relays_found"] == 1
    assert result["alerts_relay_offline_emitted"] == 1

    alert = await db["security_alerts"].find_one(
        {"tenant_id": tenant_id, "alert_type": "RELAY_OFFLINE"}
    )
    assert alert is not None
    assert alert["severity"] == "HIGH"
    assert alert["relay_id"] == relay_id
    assert alert["event_id"] == relay_id
    assert _as_utc(alert["_expire_at"]) > now

    # Re-scan in the same window: no re-fire
    result2 = await run_network_relay_watchdog(
        db, redis_client, silence_seconds=900, now=now
    )
    assert result2["alerts_relay_offline_emitted"] == 0


@pytest.mark.asyncio
async def test_watchdog_ignores_revoked_relay_and_fresh_relay(db, redis_client):
    """Revoked relays and recently-seen relays must not produce OFFLINE alerts."""
    from app.workers.network_relay_watchdog import run_network_relay_watchdog

    now = datetime.now(timezone.utc)
    tenant_id = f"WARSOC_WATCHDOG_RX_{uuid.uuid4().hex[:8]}"

    # Revoked relay — already rejected at ingest; no watchdog alert needed
    await db["network_relays"].insert_one(
        {
            "tenant_id": tenant_id,
            "relay_id": f"WARSOC_RELAY_REVOKED_{uuid.uuid4().hex[:6]}",
            "status": "revoked",
            "last_seen": now - timedelta(hours=2),
        }
    )
    # Fresh relay — seen 60 seconds ago
    await db["network_relays"].insert_one(
        {
            "tenant_id": tenant_id,
            "relay_id": f"WARSOC_RELAY_FRESH_{uuid.uuid4().hex[:6]}",
            "status": "active",
            "last_seen": now - timedelta(seconds=60),
        }
    )

    result = await run_network_relay_watchdog(
        db, redis_client, silence_seconds=900, now=now
    )
    assert result["offline_relays_found"] == 0
    assert result["alerts_relay_offline_emitted"] == 0


@pytest.mark.asyncio
async def test_watchdog_alerts_on_devices_that_never_reported(db, redis_client):
    """Fix 3: devices declared on a relay that never produced an observation
    document — and health-only observations that never recorded an event —
    are flagged as silent once the grace window since registration passed.
    Freshly registered devices inside the grace window are left alone."""
    from app.workers.network_relay_watchdog import run_network_relay_watchdog

    now = datetime.now(timezone.utc)
    tenant_id = f"WARSOC_WATCHDOG_NR_{uuid.uuid4().hex[:8]}"

    # Stale relay (registered 40 minutes ago) whose two declared devices have
    # no observation documents at all.
    stale_relay_id = f"WARSOC_RELAY_NR_{uuid.uuid4().hex[:6]}"
    await db["network_relays"].insert_one(
        {
            "tenant_id": tenant_id,
            "relay_id": stale_relay_id,
            "status": "active",
            "last_seen": now - timedelta(minutes=1),
            "created_at": now - timedelta(minutes=40),
            "devices": [
                {"device_id": "never-reported-fw", "vendor": "pfsense"},
                {"device_id": "never-reported-sw", "vendor": "cisco"},
            ],
        }
    )
    # Fresh relay (registered 1 minute ago): its never-reported device is
    # still inside the grace window and must not be flagged.
    await db["network_relays"].insert_one(
        {
            "tenant_id": tenant_id,
            "relay_id": f"WARSOC_RELAY_NRF_{uuid.uuid4().hex[:6]}",
            "status": "active",
            "last_seen": now,
            "created_at": now - timedelta(minutes=1),
            "devices": [{"device_id": "fresh-never-reported-fw", "vendor": "pfsense"}],
        }
    )
    # Health-only observation (no last_event_at) anchored 30 minutes ago —
    # past the grace window, so it is silent.
    await db["network_relay_device_status"].insert_one(
        {
            "tenant_id": tenant_id,
            "relay_id": stale_relay_id,
            "device_id": "health-only-fw",
            "vendor": "fortinet",
            "last_event_at": None,
            "created_at": now - timedelta(minutes=30),
        }
    )

    result = await run_network_relay_watchdog(
        db, redis_client, silence_seconds=900, now=now
    )
    # Two declared devices on the stale relay plus the health-only device.
    assert result["silent_devices_found"] == 3
    assert result["alerts_device_silent_emitted"] == 3

    alerts = await db["security_alerts"].find(
        {"tenant_id": tenant_id, "alert_type": "DEVICE_SILENT"}
    ).to_list(length=10)
    by_device = {alert["device_id"]: alert for alert in alerts}
    assert set(by_device) == {
        "never-reported-fw",
        "never-reported-sw",
        "health-only-fw",
    }
    for alert in alerts:
        assert alert["last_event_at"] is None
        assert alert["event_id"] == alert["device_id"]
        assert "never sent evidence" in alert["summary"]
    # Both relays were seen recently, so no relay-level offline alert fires.
    assert result["alerts_relay_offline_emitted"] == 0


@pytest.mark.asyncio
async def test_watchdog_alert_is_durable_and_visible_through_alerts_api(
    async_client, db, redis_client
):
    """Fix 3: watchdog alerts land in the durable security_alerts store with
    the seven-day hot window, project into the operator incident read model,
    and surface through the standard /alerts API — first-class SIEM alerts
    instead of transient notifications."""
    from app.workers.network_relay_watchdog import run_network_relay_watchdog

    session = await provision_and_login_admin(
        async_client, "relay_watchdog_durable", max_network_relays=1
    )
    tenant_id = session["tenant_id"]
    now = datetime.now(timezone.utc)

    await db["network_relay_device_status"].insert_one(
        {
            "tenant_id": tenant_id,
            "relay_id": "WARSOC_RELAY_DURABLE",
            "device_id": "durable-silent-fw",
            "vendor": "pfsense",
            "last_event_at": now - timedelta(minutes=20),
        }
    )

    result = await run_network_relay_watchdog(
        db, redis_client, silence_seconds=900, now=now
    )
    assert result["alerts_emitted"] == 1

    alert = await db["security_alerts"].find_one(
        {"tenant_id": tenant_id, "alert_type": "DEVICE_SILENT"}
    )
    assert alert is not None
    assert alert["alert_uid"].startswith(
        f"{tenant_id}:WARSOC_RELAY_DURABLE:durable-silent-fw:DEVICE_SILENT:"
    )
    assert alert["severity"] == "HIGH"
    assert alert["pack"] == "SIEM"
    assert alert["status"] == "NEW"
    assert alert["engine_source"] == "network_relay_watchdog"
    assert alert["event_id"] == "durable-silent-fw"
    assert isinstance(alert["timestamp"], datetime)
    assert _as_utc(alert["_expire_at"]) > now
    assert _as_utc(alert["_expire_at"]) <= now + timedelta(days=7)

    # The alert projected into the operator incident read model.
    occurrence = await db["security_incident_occurrences"].find_one(
        {"tenant_id": tenant_id, "alert_uid": alert["alert_uid"]}
    )
    assert occurrence is not None

    # And it is visible through the standard alerts API.
    response = await async_client.get(
        "/api/v1/alerts", params={"aggregate": "false"}
    )
    assert response.status_code == 200, response.text
    items = response.json()["data"]
    assert any(item.get("alert_uid") == alert["alert_uid"] for item in items)


@pytest.mark.asyncio
async def test_watchdog_retries_fanout_failures_and_keeps_alerts_durable(
    db, redis_client
):
    """Fix 3: a failing live-notification channel (Redis pub/sub down) is
    retried and then tolerated — the durable security_alerts document and the
    incident projection survive, and the watchdog run does not crash."""
    from app.workers.network_relay_watchdog import (
        _retry_pending_deliveries,
        run_network_relay_watchdog,
    )

    now = datetime.now(timezone.utc)
    tenant_id = f"WARSOC_WATCHDOG_FO_{uuid.uuid4().hex[:8]}"
    await db["network_relay_device_status"].insert_one(
        {
            "tenant_id": tenant_id,
            "relay_id": "WARSOC_RELAY_FO",
            "device_id": "fanout-silent-fw",
            "vendor": "pfsense",
            "last_event_at": now - timedelta(minutes=20),
        }
    )

    class _HalfBrokenRedis:
        """Delegates everything to the real client except publish, which
        simulates a dead pub/sub channel."""

        def __init__(self, inner):
            self._inner = inner

        def __getattr__(self, name):
            return getattr(self._inner, name)

        async def publish(self, *args, **kwargs):
            raise ConnectionError("pub/sub connection lost")

    result = await run_network_relay_watchdog(
        db, _HalfBrokenRedis(redis_client), silence_seconds=900, now=now
    )
    assert result["alerts_emitted"] == 1

    # The durable alert survived the broken live channel.
    alert = await db["security_alerts"].find_one({"tenant_id": tenant_id})
    assert alert is not None
    assert alert["alert_type"] == "DEVICE_SILENT"
    assert alert["watchdog_delivery"]["stream_pending"] is True
    # Mongo projection exists, but the incident notification is still pending
    # until its Redis publish succeeds on a later watchdog cycle.
    assert alert["watchdog_delivery"]["incident_pending"] is True
    # The retried incident projection recovered on its second attempt
    # (idempotent upsert), so the operator read model still moved.
    occurrences = await db["security_incident_occurrences"].count_documents(
        {"tenant_id": tenant_id}
    )
    assert occurrences == 1

    # The failed channel remains durable and a later cron cycle recovers it
    # without creating another security_alerts document.
    retry = await _retry_pending_deliveries(
        db,
        redis_client,
        now=now + timedelta(seconds=61),
    )
    assert retry == {"attempted": 1, "completed": 1}
    recovered = await db["security_alerts"].find_one({"_id": alert["_id"]})
    assert recovered["watchdog_delivery"]["stream_pending"] is False
    assert recovered["watchdog_delivery"]["email_pending"] is False
    assert recovered["watchdog_delivery"]["completed_at"] is not None
