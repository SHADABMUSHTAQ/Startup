import asyncio
import json
from datetime import datetime, timezone

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519


pytestmark = pytest.mark.asyncio


def _ed25519_public_key_pem() -> str:
    signing_key = ed25519.Ed25519PrivateKey.generate()
    return signing_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")


async def test_50_agent_tenant_allows_final_seat_and_blocks_51st(
    async_client,
    db,
    redis_client,
):
    tenant_id = "WARSOC_QUOTA_50"
    activation_code = "WARSOC-QUOTA50"
    now = datetime.now(timezone.utc)

    await db["tenants"].insert_one(
        {
            "tenant_id": tenant_id,
            "company_name": "Quota Contract 50",
            "plan": "Enterprise",
            "plan_type": "Enterprise",
            "status": "active",
            "max_agents": 50,
            "agent_limit": 50,
            "compliance_packs": ["fbr_pos", "peca_forensic"],
            "created_at": now,
        }
    )
    await redis_client.set(
        f"warsoc:activation:{activation_code}",
        json.dumps(
            {
                "tenant_id": tenant_id,
                "features": "SIEM,fbr_pos,peca_forensic",
                "created_by": "quota-contract-test",
            }
        ),
    )
    await redis_client.set(f"tenant:{tenant_id}:active_count", "49")

    final_seat = await async_client.post(
        "/api/v1/agent/register",
        json={
            "activation_code": activation_code,
            "public_key": _ed25519_public_key_pem(),
        },
    )

    assert final_seat.status_code == 200, final_seat.text
    assert final_seat.json()["tenant_id"] == tenant_id
    assert await redis_client.get(f"tenant:{tenant_id}:active_count") == "50"
    assert await db["agents"].count_documents({"tenant_id": tenant_id, "status": "active"}) == 1

    second_activation_code = "WARSOC-QUOTA51"
    await redis_client.set(
        f"warsoc:activation:{second_activation_code}",
        json.dumps(
            {
                "tenant_id": tenant_id,
                "features": "SIEM,fbr_pos,peca_forensic",
                "created_by": "quota-contract-test",
            }
        ),
    )
    over_limit = await async_client.post(
        "/api/v1/agent/register",
        json={
            "activation_code": second_activation_code,
            "public_key": _ed25519_public_key_pem(),
        },
    )

    assert over_limit.status_code == 403, over_limit.text
    assert "contract limit (50)" in over_limit.json()["detail"]
    assert await redis_client.get(f"tenant:{tenant_id}:active_count") == "50"
    assert await db["agents"].count_documents({"tenant_id": tenant_id, "status": "active"}) == 1


async def test_activation_code_is_atomically_single_use_under_concurrency(
    async_client,
    db,
    redis_client,
):
    tenant_id = "WARSOC_ATOMIC_ACTIVATION"
    activation_code = "WARSOC-ATOMIC"
    now = datetime.now(timezone.utc)
    await db["tenants"].insert_one(
        {
            "tenant_id": tenant_id,
            "company_name": "Atomic Activation Contract",
            "plan_type": "Enterprise",
            "status": "active",
            "max_agents": 50,
            "agent_limit": 50,
            "created_at": now,
        }
    )
    await redis_client.set(
        f"warsoc:activation:{activation_code}",
        json.dumps(
            {
                "tenant_id": tenant_id,
                "features": "SIEM",
                "created_by": "atomic-activation-test",
            }
        ),
    )

    async def register_once():
        return await async_client.post(
            "/api/v1/agent/register",
            json={
                "activation_code": activation_code,
                "public_key": _ed25519_public_key_pem(),
            },
        )

    first, second = await asyncio.gather(register_once(), register_once())
    assert sorted([first.status_code, second.status_code]) == [200, 401]
    assert await db["agents"].count_documents({"tenant_id": tenant_id}) == 1
    assert await redis_client.get(f"tenant:{tenant_id}:active_count") == "1"
    assert await redis_client.get(f"warsoc:activation:{activation_code}") is None


async def test_invalid_public_key_does_not_consume_activation_code(
    async_client,
    db,
    redis_client,
):
    tenant_id = "WARSOC_KEY_VALIDATION"
    activation_code = "WARSOC-KEYCHECK"
    await db["tenants"].insert_one(
        {
            "tenant_id": tenant_id,
            "company_name": "Key Validation Contract",
            "plan_type": "Enterprise",
            "status": "active",
            "active": True,
            "max_agents": 10,
        }
    )
    activation_key = f"warsoc:activation:{activation_code}"
    await redis_client.set(
        activation_key,
        json.dumps({"tenant_id": tenant_id, "features": "SIEM"}),
    )

    invalid = await async_client.post(
        "/api/v1/agent/register",
        json={
            "activation_code": activation_code,
            "public_key": "-----BEGIN PUBLIC KEY-----\n" + ("A" * 120) + "\n-----END PUBLIC KEY-----",
        },
    )

    assert invalid.status_code == 400
    assert invalid.json()["detail"] == "Invalid Ed25519 public key"
    assert await redis_client.get(activation_key) is not None

    valid = await async_client.post(
        "/api/v1/agent/register",
        json={
            "activation_code": activation_code,
            "public_key": _ed25519_public_key_pem(),
        },
    )
    assert valid.status_code == 200, valid.text
    assert await redis_client.get(activation_key) is None


async def test_database_count_prevents_redis_restart_from_bypassing_50_agent_cap(
    async_client,
    db,
    redis_client,
):
    tenant_id = "WARSOC_DB_FLOOR_50"
    activation_code = "WARSOC-DBFLOOR"
    now = datetime.now(timezone.utc)
    await db["tenants"].insert_one(
        {
            "tenant_id": tenant_id,
            "company_name": "Database Floor Contract",
            "plan_type": "Enterprise",
            "status": "active",
            "active": True,
            "max_agents": 100,
            "agent_limit": 100,
            "created_at": now,
        }
    )
    await db["agents"].insert_many(
        [
            {
                "tenant_id": tenant_id,
                "agent_id": f"WARSOC_EXISTING_{index}",
                "status": "active",
                "public_key": "existing",
            }
            for index in range(50)
        ]
    )
    await redis_client.delete(f"tenant:{tenant_id}:active_count")
    await redis_client.set(
        f"warsoc:activation:{activation_code}",
        json.dumps({"tenant_id": tenant_id, "features": "SIEM"}),
    )

    response = await async_client.post(
        "/api/v1/agent/register",
        json={
            "activation_code": activation_code,
            "public_key": _ed25519_public_key_pem(),
        },
    )

    assert response.status_code == 403
    assert "contract limit (50)" in response.json()["detail"]
    assert await redis_client.get(f"tenant:{tenant_id}:active_count") == "50"
    assert await db["agents"].count_documents({"tenant_id": tenant_id}) == 50


async def test_platform_cap_blocks_51st_agent_across_different_tenants(
    async_client,
    db,
    redis_client,
):
    now = datetime.now(timezone.utc)
    existing_tenant = "WARSOC_PLATFORM_EXISTING"
    new_tenant = "WARSOC_PLATFORM_NEW"
    activation_code = "WARSOC-PLATFORM51"
    await db["tenants"].insert_many(
        [
            {
                "tenant_id": existing_tenant,
                "company_name": "Existing Platform Tenant",
                "plan_type": "Custom",
                "status": "active",
                "max_agents": 50,
                "created_at": now,
            },
            {
                "tenant_id": new_tenant,
                "company_name": "New Platform Tenant",
                "plan_type": "Custom",
                "status": "active",
                "max_agents": 50,
                "created_at": now,
            },
        ]
    )
    await db["agents"].insert_many(
        [
            {
                "tenant_id": existing_tenant,
                "agent_id": f"WARSOC_PLATFORM_{index}",
                "status": "active",
                "public_key": "existing",
            }
            for index in range(50)
        ]
    )
    await redis_client.set(
        f"warsoc:activation:{activation_code}",
        json.dumps({"tenant_id": new_tenant, "features": "SIEM"}),
    )

    response = await async_client.post(
        "/api/v1/agent/register",
        json={
            "activation_code": activation_code,
            "public_key": _ed25519_public_key_pem(),
        },
    )

    assert response.status_code == 503
    assert response.json()["detail"] == "The service is temporarily unavailable."
    assert await redis_client.get("warsoc:platform:active_agent_count") == "50"
    assert await db["agents"].count_documents({"tenant_id": new_tenant}) == 0
