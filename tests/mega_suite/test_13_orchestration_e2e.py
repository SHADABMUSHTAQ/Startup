import pytest
from motor.motor_asyncio import AsyncIOMotorClient
import uuid

from app.config.config import get_settings
from tests.helpers import ed25519_keypair_pem, provision_and_login_admin

settings = get_settings()

@pytest.mark.asyncio
async def test_e2e_admin_and_user_pov(async_client):
    session = await provision_and_login_admin(async_client, "e2e_user", max_agents=4)
    tenant_id = session["tenant_id"]

    # 1. Verify the protected provisioning result in the database
    mongo_client = AsyncIOMotorClient(settings.mongodb_uri)
    db = mongo_client[settings.mongodb_db_name]
    csrf_token = session["csrf_token"]
    if csrf_token:
        async_client.headers.update({"x-csrf-token": csrf_token})
    
    res = await async_client.get("/api/v1/auth/me")
    assert res.status_code == 200
    
    tenant_doc = await db.tenants.find_one({"tenant_id": tenant_id})
    assert tenant_doc["max_agents"] == 4
    assert "fbr_pos" in tenant_doc["compliance_packs"]
    assert "peca_forensic" in tenant_doc["compliance_packs"]
    
    # 2. USER POV: Generate 4 Activations
    activation_codes = []
    for _ in range(4):
        res = await async_client.post("/api/v1/agent/generate-activation")
        assert res.status_code == 200, f"Activation gen failed: {res.text}"
        activation_codes.append(res.json()["activation_code"])
    
    # 3. USER POV: Register 4 Agents with valid Ed25519 identities
    for code in activation_codes:
        _, pub_key = ed25519_keypair_pem()
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
        "public_key": ed25519_keypair_pem()[1]
    })
    assert res.status_code in {401, 403}, f"Reused activation code was not rejected: {res.status_code} {res.text}"
    
    mongo_client.close()
