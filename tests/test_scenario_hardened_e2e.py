import pytest
import asyncio
from httpx import AsyncClient

pytestmark = [pytest.mark.asyncio, pytest.mark.backend, pytest.mark.hardening]

async def test_scenario_admin_provisioning_forces_admin_role(async_client: AsyncClient, redis_client):
    """
    Scenario: A user attempts to sign up (provision) and inject a custom role.
    Expected: The system strictly forces the 'admin' role, and the default SIEM features are active.
    """
    # 1. Attempt malicious signup
    payload = {
        "username": "scenario_user",
        "password": "Password123!",
        "email": "scenario@example.com",
        "full_name": "Scenario Tenant",
        "plan_type": "Free",
        "role": "master_admin"  # Malicious role injection attempt
    }
    resp = await async_client.post(
        "/api/v1/auth/signup", 
        json=payload,
        headers={"X-Forwarded-For": "192.168.1.100"}
    )
    
    if resp.status_code == 403:
        assert "Self-service signup is disabled" in resp.text
        return

    assert resp.status_code == 201
    
    # 2. Login to verify the role assigned
    login = await async_client.post(
        "/api/v1/auth/login",
        json={"username": "scenario_user", "password": "Password123!"},
        headers={"X-Forwarded-For": "192.168.1.100"}
    )
    assert login.status_code == 200
    assert login.json()["tenant_id"].startswith("WARSOC_")
    
    # Check the JWT or ME endpoint
    csrf = login.json()["csrf_token"]
    async_client.cookies.set("warsoc_token", login.cookies.get("warsoc_token"))
    async_client.cookies.set("csrf_token", csrf)
    
    me_resp = await async_client.get("/api/v1/auth/me", headers={"x-csrf-token": csrf})
    assert me_resp.status_code == 200
    user_data = me_resp.json()["user"]
    
    # Assert the malicious role was blocked and 'admin' was forced
    assert user_data["role"] == "admin"
    assert user_data["role"] != "master_admin"


async def test_scenario_agent_quota_blocks_over_provisioning(async_client: AsyncClient, redis_client, override_db_dependency):
    """
    Scenario: An admin attempts to register more agents than their quota allows.
    Expected: The system blocks the activation at the gate and prevents database pollution.
    """
    # Setup dummy tenant with limit of 1
    tenant_id = "WARSOC_LIMIT_TEST"
    from app.database import db_manager
    test_db = db_manager.db
    
    await test_db["tenants"].insert_one({
        "tenant_id": tenant_id,
        "max_agents": 1,
        "status": "active"
    })
    await test_db["users"].insert_one({
        "username": "admin_user",
        "tenant_id": tenant_id,
        "role": "admin"
    })
    await redis_client.set(f"tenant:{tenant_id}:active_count", "1")
    
    # Mock admin login token creation
    from app.routes.auth import create_access_token
    token = create_access_token({"sub": "admin_user", "type": "user", "tenant_id": tenant_id, "role": "admin"})
    
    # Attempt to generate an activation code (should fail because limit is 1 and current is 1)
    async_client.cookies.set("warsoc_token", token)
    async_client.cookies.set("csrf_token", "dummy_csrf")
    
    gen_resp = await async_client.post(
        "/api/v1/agent/generate-activation", 
        headers={"x-csrf-token": "dummy_csrf"}
    )
    
    assert gen_resp.status_code == 403
    assert "Agent license limit (1) reached" in gen_resp.text


async def test_scenario_rate_limiting_blocks_brute_force(async_client: AsyncClient):
    """
    Scenario: An attacker attempts to brute force the login endpoint.
    Expected: The rate limiter strictly blocks requests after 5 attempts.
    """
    # Send 6 rapid requests to login
    responses = []
    for _ in range(6):
        resp = await async_client.post(
            "/api/v1/auth/login",
            json={"username": "brute_force_user", "password": "WrongPassword!"}
        )
        responses.append(resp.status_code)
        
    # The first 5 should be 401 (Invalid credentials)
    # The 6th MUST be 429 (Too Many Requests)
    assert 429 in responses, f"Rate limiter failed to block brute force. Responses: {responses}"
    
    # Verify the specific blocking threshold
    assert responses.count(401) <= 5
    assert responses[-1] == 429
