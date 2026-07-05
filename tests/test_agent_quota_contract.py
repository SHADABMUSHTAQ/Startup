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
    assert "license limit (50)" in over_limit.json()["detail"]
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
