from __future__ import annotations

import os
import uuid

import pytest

from app.main import app as fastapi_app


@pytest.mark.asyncio
async def test_health_checks_mongodb_and_redis(async_client):
    response = await async_client.get("/health")

    assert response.status_code == 200
    assert response.json() == {
        "status": "healthy",
        "dependencies": {"mongodb": "healthy", "redis": "healthy"},
    }


@pytest.mark.asyncio
async def test_health_reports_degraded_when_redis_is_unavailable(async_client):
    redis_client = fastapi_app.state.redis
    fastapi_app.state.redis = None
    try:
        response = await async_client.get("/health")
    finally:
        fastapi_app.state.redis = redis_client

    assert response.status_code == 503
    assert response.json()["status"] == "degraded"
    assert response.json()["dependencies"]["redis"] == "unavailable"


@pytest.mark.asyncio
async def test_provisioning_rolls_back_tenant_and_genesis_when_user_insert_fails(
    async_client,
    db,
    monkeypatch,
):
    run_id = uuid.uuid4().hex[:10]
    email = f"rollback-{run_id}@example.com"
    collection_type = type(db["users"])
    original_insert_one = collection_type.insert_one
    captured: dict[str, str] = {}

    async def fail_target_user_insert(collection, document, *args, **kwargs):
        if collection.name == "tenants" and document.get("company_name") == f"Rollback Contract {run_id}":
            captured["tenant_id"] = document["tenant_id"]
        if collection.name == "users" and document.get("email") == email:
            raise RuntimeError("simulated user insert failure")
        return await original_insert_one(collection, document, *args, **kwargs)

    monkeypatch.setattr(collection_type, "insert_one", fail_target_user_insert)

    response = await async_client.post(
        "/api/v1/admin/provision",
        headers={"X-Admin-Key": os.environ["SUPER_ADMIN_API_KEY"]},
        json={
            "company_name": f"Rollback Contract {run_id}",
            "plan_type": "Customized",
            "compliance_packs": ["fbr_pos", "peca_forensic"],
            "max_agents": 50,
            "admin_email": email,
            "admin_name": "Rollback Admin",
            "admin_password": f"Rollback-{run_id}-2026!",
        },
    )

    assert response.status_code == 500
    assert response.json()["detail"] == "Tenant provisioning failed; no account was created."
    assert await db["users"].count_documents({"email": email}) == 0
    tenant = await db["tenants"].find_one({"company_name": f"Rollback Contract {run_id}"})
    assert tenant is None
    assert captured.get("tenant_id")
    assert await db["daily_forensic_ledgers"].count_documents(
        {"worker_id": "admin_provisioning", "tenant_id": captured["tenant_id"]}
    ) == 0
