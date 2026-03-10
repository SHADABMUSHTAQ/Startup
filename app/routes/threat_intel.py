from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
from datetime import datetime, timezone
import redis.asyncio as aioredis

from app.database import get_db
from app.api.ws_manager import manager 
from app.config.config import get_settings
from app.routes.auth import get_current_user, verify_agent_token

router = APIRouter()
settings = get_settings()

class BanRequest(BaseModel):
    ip: str
    reason: str = "Manual Admin Intervention"

WHITELIST_IPS = ["127.0.0.1", "localhost", "::1", "0.0.0.0"]

# ---------------------------------------------------------
# 1. ACTIVE MITIGATION (BAN)
# ---------------------------------------------------------
@router.post("/mitigate")
async def execute_mitigation(payload: BanRequest, db=Depends(get_db), current_user=Depends(get_current_user)):
    target_ip = payload.ip.strip()
    secure_tenant_id = current_user.get("tenant_id")
    
    if not secure_tenant_id:
        raise HTTPException(status_code=403, detail="Critical: User lacks tenant assignment.")

    if target_ip in WHITELIST_IPS:
        raise HTTPException(status_code=400, detail="Safety Lock: Cannot ban system IP.")

    # 🚨 SURGICAL FIX: Consistent .db access
    existing = await db.db["firewall_rules"].find_one({"ip": target_ip, "tenant_id": secure_tenant_id})
    
    if not existing:
        ban_entry = {
            "tenant_id": secure_tenant_id,
            "ip": target_ip,
            "reason": payload.reason,
            "status": "blocked",
            "banned_at": datetime.now(timezone.utc).isoformat(),
            "banned_by": current_user["username"]
        }
        await db.db["firewall_rules"].insert_one(ban_entry)

    try:
        r = await aioredis.from_url(settings.redis_url, decode_responses=True)
        redis_key = f"warsoc:banned_ips:{secure_tenant_id}"
        await r.sadd(redis_key, target_ip)
        await r.close()
    except Exception as e:
        print(f"❌ Redis Sync Error: {e}")

    await manager.broadcast_to_tenant(secure_tenant_id, {
        "type": "MITIGATION_SUCCESS",
        "severity": "SUCCESS", 
        "ip": target_ip,
        "message": f"IP {target_ip} blocked successfully.",
        "timestamp": datetime.now(timezone.utc).isoformat()
    })
    
    return {"status": "success", "ip": target_ip}

# ---------------------------------------------------------
# 2. REVOKE MITIGATION (UNBAN)
# ---------------------------------------------------------
@router.post("/revoke")
async def revoke_mitigation(payload: BanRequest, db=Depends(get_db), current_user=Depends(get_current_user)):
    target_ip = payload.ip.strip()
    secure_tenant_id = current_user.get("tenant_id")

    # 🚨 SURGICAL FIX: Added missing delete_one command and fixed db access
    await db.db["firewall_rules"].delete_one({"ip": target_ip, "tenant_id": secure_tenant_id})

    try:
        r = await aioredis.from_url(settings.redis_url, decode_responses=True)
        redis_key = f"warsoc:banned_ips:{secure_tenant_id}"
        await r.srem(redis_key, target_ip)
        await r.close()
    except Exception as e:
        print(f"❌ Redis Revoke Error: {e}")

    return {"status": "success", "message": "Access restored"}

# ---------------------------------------------------------
# 3. AGENT HEARTBEAT (C2 TUNNEL)
# ---------------------------------------------------------
@router.get("/agent/heartbeat/{tenant_id}")
async def agent_heartbeat(tenant_id: str, current_agent: str = Depends(verify_agent_token)):
    if tenant_id != current_agent:
        raise HTTPException(status_code=403, detail="Tenant ID mismatch blocked.")

    try:
        r = await aioredis.from_url(settings.redis_url, decode_responses=True)
        redis_key = f"warsoc:banned_ips:{tenant_id}"
        banned_ips = await r.smembers(redis_key)
        await r.close()

        return {
            "status": "active",
            "enforce_bans": list(banned_ips)
        }
    except Exception as e:
        return {"status": "error", "enforce_bans": []}

# ---------------------------------------------------------
# 4. DASHBOARD LIST
# ---------------------------------------------------------
@router.get("/list")
async def get_blocked_list(db=Depends(get_db), current_user=Depends(get_current_user)):
    secure_tenant_id = current_user.get("tenant_id")
    
    # 🚨 SURGICAL FIX: Dictionary access and isolation filtering
    cursor = db.db["firewall_rules"].find({"tenant_id": secure_tenant_id}).sort("banned_at", -1)
    results = []
    async for doc in cursor:
        doc["_id"] = str(doc["_id"])
        results.append(doc)
    return results