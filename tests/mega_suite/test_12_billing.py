import hmac
import hashlib
import json
import pytest
from app.config.config import get_settings

@pytest.fixture(autouse=True)
def setup_safepay_secret(monkeypatch):
    """Automatically configure a test Safepay webhook secret across all billing tests."""
    settings = get_settings()
    test_secret = "test_safepay_webhook_secret_key"
    monkeypatch.setattr(settings, "safepay_webhook_secret", test_secret)
    return test_secret


@pytest.mark.asyncio
async def test_safepay_webhook_missing_signature(async_client):
    """Sending a Safepay webhook request without the X-SFPY-SIGNATURE header must return a 400 Bad Request."""
    payload = {"type": "payment.succeeded", "data": {}}
    resp = await async_client.post("/api/v1/billing/safepay-webhook", json=payload)
    assert resp.status_code == 400
    assert resp.json()["detail"] == "Missing signature"


@pytest.mark.asyncio
async def test_safepay_webhook_invalid_signature(async_client):
    """Sending a Safepay webhook request with an invalid/forged signature must return a 401 Unauthorized."""
    payload = {"type": "payment.succeeded", "data": {}}
    headers = {"X-SFPY-SIGNATURE": "invalid_signature_hash"}
    resp = await async_client.post("/api/v1/billing/safepay-webhook", json=payload, headers=headers)
    assert resp.status_code == 401
    assert resp.json()["detail"] == "Invalid signature"


@pytest.mark.asyncio
async def test_safepay_webhook_success(async_client, setup_safepay_secret, redis_client, mongo_client):
    """Sending a validly signed payment.succeeded webhook must successfully provision the tenant to the Enterprise tier."""
    settings = get_settings()
    test_secret = setup_safepay_secret
    
    # Setup mock target tenant in database
    db = mongo_client[settings.mongodb_db_name]
    target_tenant_id = "TENANT_SAFEPAY_TEST_99"
    target_email = "billing_recipient@example.com"
    
    # Seed initial free-tier tenant & user
    await db["tenants"].delete_many({"tenant_id": target_tenant_id})
    await db["users"].delete_many({"tenant_id": target_tenant_id})
    await db["tenants"].insert_one({
        "tenant_id": target_tenant_id,
        "status": "pending",
        "plan_type": "Free",
        "payment_status": "unpaid"
    })
    await db["users"].insert_one({
        "username": "billing_user",
        "tenant_id": target_tenant_id,
        "email": target_email,
        "has_active_plan": False,
        "plan_type": "Free"
    })
    
    # Clean Redis state
    await redis_client.delete(f"tenant_plan:{target_tenant_id}")
    
    # 3. Construct the Safepay payload
    payload = {
        "type": "payment.succeeded",
        "data": {
            "metadata": {
                "tenant_id": target_tenant_id,
                "user_email": target_email,
                "plan_type": "Enterprise"
            }
        }
    }
    payload_bytes = json.dumps(payload, default=str).encode("utf-8")
    
    # Generate authentic HMAC-SHA256 signature
    signature = hmac.new(test_secret.encode("utf-8"), payload_bytes, hashlib.sha256).hexdigest()
    
    # 4. Trigger the webhook endpoint
    headers = {
        "X-SFPY-SIGNATURE": signature,
        "Content-Type": "application/json"
    }
    resp = await async_client.post(
        "/api/v1/billing/safepay-webhook",
        content=payload_bytes,
        headers=headers
    )
    
    # Verify HTTP response is success
    assert resp.status_code == 200
    assert resp.json()["status"] == "success"
    
    # 5. Assert MongoDB modifications are correctly committed
    tenant = await db["tenants"].find_one({"tenant_id": target_tenant_id})
    assert tenant is not None
    assert tenant["status"] == "active"
    assert tenant["plan_type"] == "Enterprise"
    assert tenant["payment_status"] == "paid"
    
    user = await db["users"].find_one({"tenant_id": target_tenant_id, "username": "billing_user"})
    assert user is not None
    assert user["has_active_plan"] is True
    assert user["plan_type"] == "Enterprise"
    
    # 6. Assert Redis cache is provisioned
    redis_plan = await redis_client.get(f"tenant_plan:{target_tenant_id}")
    assert redis_plan == "Enterprise"
    
    # Clean up test artifacts
    await db["tenants"].delete_many({"tenant_id": target_tenant_id})
    await db["users"].delete_many({"tenant_id": target_tenant_id})
    await redis_client.delete(f"tenant_plan:{target_tenant_id}")
