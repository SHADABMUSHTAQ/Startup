import hmac
import hashlib
import json
import logging
from fastapi import APIRouter, Request, HTTPException, Depends, Header

from app.database import get_db
from app.config.config import get_settings

router = APIRouter(prefix="/billing", tags=["Billing"])
logger = logging.getLogger("safepay-webhook")

@router.post("/safepay-webhook")
async def safepay_webhook(
    request: Request,
    x_sfpy_signature: str = Header(None, alias="X-SFPY-SIGNATURE"),
    db=Depends(get_db),
):
    settings = get_settings()
    payload_bytes = await request.body()
    
    # 1. Verify Safepay Webhook Signature (Security Gate)
    secret = getattr(settings, "safepay_webhook_secret", "").encode("utf-8")
    if not secret:
        logger.error("SAFEPAY_WEBHOOK_SECRET is not configured in .env.")
        raise HTTPException(status_code=500, detail="Billing configuration error")
        
    if not x_sfpy_signature:
        logger.warning("Missing Safepay signature header.")
        raise HTTPException(status_code=400, detail="Missing signature")

    expected_sig = hmac.new(secret, payload_bytes, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected_sig, x_sfpy_signature):
        logger.warning("Invalid Safepay webhook signature mismatch.")
        raise HTTPException(status_code=401, detail="Invalid signature")

    # 2. Parse payload safely
    try:
        data = json.loads(payload_bytes)
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Invalid JSON")

    event_type = data.get("type", data.get("event"))
    
    # 3. Handle Successful Payment & Auto-Provision
    if event_type == "payment.succeeded":
        metadata = data.get("data", {}).get("metadata", {})
        tenant_id = metadata.get("tenant_id")
        user_email = metadata.get("user_email")
        plan_type = metadata.get("plan_type", "Enterprise")

        if not tenant_id or not user_email:
            logger.error("Missing tenant_id or user_email in Safepay metadata.")
            return {"status": "ignored", "reason": "missing_metadata"}

        # Update MongoDB Tenant and User Status
        await db["tenants"].update_one({"tenant_id": tenant_id}, {"$set": {"status": "active", "plan_type": plan_type, "payment_status": "paid"}})
        await db["users"].update_many({"tenant_id": tenant_id}, {"$set": {"has_active_plan": True, "plan_type": plan_type}})

        # Flush Redis Tenant Cache + push Zoho welcome email job
        redis_client = getattr(request.app.state, "redis", None)
        if redis_client:
            await redis_client.set(f"tenant_plan:{tenant_id}", plan_type)
            email_job = {"type": "welcome_email", "tenant_id": tenant_id, "recipient": user_email, "plan": plan_type}
            await redis_client.xadd("email_send_queue", {"payload": json.dumps(email_job)}, maxlen=10000)
        else:
            logger.warning(f"Redis unavailable: welcome email not queued for {tenant_id}")
        logger.info(f"✅ Successfully provisioned tenant {tenant_id} via Safepay.")

    return {"status": "success"}