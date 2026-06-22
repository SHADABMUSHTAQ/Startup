import pytest
from motor.motor_asyncio import AsyncIOMotorClient
import secrets
import uuid

from app.config.config import get_settings
from scripts.admin_provision import provision_tenant

settings = get_settings()

@pytest.mark.asyncio
async def test_e2e_admin_and_user_pov(async_client):
    username = f"e2e_user_{uuid.uuid4().hex[:6]}"
    password = "SuperSecretPassword123!"
    
    # 1. USER POV: Signup
    res = await async_client.post("/api/v1/auth/signup", json={
        "full_name": "E2E Test User",
        "username": username,
        "email": f"{username}@example.com",
        "password": password
    })
    assert res.status_code == 201, f"Signup failed: {res.text}"
    
    # 2. Get Tenant ID from DB
    mongo_client = AsyncIOMotorClient(settings.mongodb_uri)
    db = mongo_client[settings.mongodb_db_name]
    user_doc = await db.users.find_one({"username": username})
    tenant_id = user_doc["tenant_id"]
    
    # 3. ADMIN POV: Air-gapped Provisioning (4 agents + FBR + PECA)
    await provision_tenant(
        tenant_id=tenant_id,
        endpoints=4,
        fbr=True,
        peca=True
    )
    
    # 4. USER POV: Login & Verify Quotas
    res = await async_client.post("/api/v1/auth/login", json={
        "username": username,
        "password": password
    })
    assert res.status_code == 200, f"Login failed: {res.text}"
    csrf_token = res.json().get("csrf_token")
    if csrf_token:
        async_client.headers.update({"x-csrf-token": csrf_token})
    
    res = await async_client.get("/api/v1/auth/me")
    assert res.status_code == 200
    
    tenant_doc = await db.tenants.find_one({"tenant_id": tenant_id})
    assert tenant_doc["max_agents"] == 4
    assert "fbr_pos" in tenant_doc["compliance_packs"]
    assert "peca_forensic" in tenant_doc["compliance_packs"]
    
    # 5. USER POV: Generate 4 Activations (to stay under 5/min rate limit)
    activation_codes = []
    for _ in range(4):
        res = await async_client.post("/api/v1/agent/generate-activation")
        assert res.status_code == 200, f"Activation gen failed: {res.text}"
        activation_codes.append(res.json()["activation_code"])
    
    # 6. USER POV: Register 4 Agents
    for code in activation_codes:
        pub_key = f"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI{secrets.token_hex(16)}"
        res = await async_client.post("/api/v1/agent/register", json={
            "activation_code": code,
            "public_key": pub_key
        })
        assert res.status_code == 200, f"Registration failed: {res.text}"
        
    # Try 5th generation after limit reached -> Should fail!
    res = await async_client.post("/api/v1/agent/generate-activation")
    assert res.status_code == 403, "System allowed 5th activation code to be generated when limit is 4!"
        
    # Try reusing code
    res = await async_client.post("/api/v1/agent/register", json={
        "activation_code": activation_codes[0],
        "public_key": "some_other_key"
    })
    assert res.status_code == 401, "System allowed activation code reuse!"
    
    # Success
    with open("C:\\Users\\Lenovo\\Desktop\\Startup-backend\\scratch\\e2e_pytest_passed.txt", "w", encoding="utf-8") as f:
        f.write("All E2E scenarios passed successfully!\n")
