from fastapi import APIRouter, HTTPException, Depends, Request
from pydantic import BaseModel
from datetime import datetime, timezone
import asyncio
import logging

from app.database import get_db
from app.api.ws_manager import manager
from app.routes.auth import get_current_user, verify_agent_token
from app.utils.rbac import RoleChecker as RequireRole
import ipaddress

router = APIRouter()
logger = logging.getLogger("threat_intel")

class BanRequest(BaseModel):
    ip: str
    reason: str = "Manual Admin Intervention"
    force: bool = False

WHITELIST_IPS = ["127.0.0.1", "localhost", "::1", "0.0.0.0"]


def _is_valid_ip_or_cidr(value: str) -> bool:
    try:
        if "/" in value:
            ipaddress.ip_network(value, strict=False)
        else:
            ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _target_contains_ip(target: str, candidate_ip: str | None) -> bool:
    if not candidate_ip:
        return False
    try:
        candidate = ipaddress.ip_address(str(candidate_ip).strip())
        if "/" in target:
            return candidate in ipaddress.ip_network(target, strict=False)
        return candidate == ipaddress.ip_address(target)
    except ValueError:
        return False


def _targets_overlap(left: str, right: str) -> bool:
    try:
        left_network = ipaddress.ip_network(str(left).strip(), strict=False)
        right_network = ipaddress.ip_network(str(right).strip(), strict=False)
        return (
            left_network.version == right_network.version
            and left_network.overlaps(right_network)
        )
    except ValueError:
        return False


async def _find_protected_asset_conflict(
    db,
    redis_client,
    tenant_id: str,
    target_ip: str,
) -> str | None:
    cursor = db["soar_whitelist"].find(
        {"tenant_id": tenant_id, "ip": {"$exists": True, "$ne": ""}},
        {"_id": 0, "ip": 1},
    ).limit(5000)
    async for entry in cursor:
        protected_ip = str(entry.get("ip") or "").strip()
        if protected_ip and _targets_overlap(target_ip, protected_ip):
            return protected_ip

    redis_entries = await redis_client.smembers(f"warsoc:soar_whitelist:{tenant_id}")
    for entry in redis_entries:
        protected_ip = str(entry or "").strip()
        if protected_ip and _targets_overlap(target_ip, protected_ip):
            return protected_ip
    return None


async def _find_active_agent_ip_conflict(db, tenant_id: str, target_ip: str):
    active_status_filter = {
        "$or": [
            {"status": {"$exists": False}},
            {"status": "active"},
        ]
    }

    if "/" not in target_ip:
        return await db["agents"].find_one({
            "tenant_id": tenant_id,
            "last_ip": target_ip,
            **active_status_filter,
        })

    cursor = db["agents"].find(
        {
            "tenant_id": tenant_id,
            "last_ip": {"$exists": True, "$ne": None},
            **active_status_filter,
        },
        {"agent_id": 1, "last_ip": 1},
    )
    async for agent in cursor:
        if _target_contains_ip(target_ip, agent.get("last_ip")):
            return agent
    return None


async def _redis_sadd_with_retry(redis_client, redis_key, target_ip, retries: int = 2, backoff: float = 0.2):
    for attempt in range(retries + 1):
        try:
            await redis_client.sadd(redis_key, target_ip)
            print(f"âœ… Redis SADD success: {redis_key} <- {target_ip}")
            return True
        except Exception as e:
            print(f"âš ï¸ Redis SADD attempt {attempt+1} failed for {redis_key}: {e}")
            if attempt < retries:
                await asyncio.sleep(backoff)
    return False


async def _redis_srem_with_retry(redis_client, redis_key, target_ip, retries: int = 2, backoff: float = 0.2):
    for attempt in range(retries + 1):
        try:
            await redis_client.srem(redis_key, target_ip)
            print(f"âœ… Redis SREM success: {redis_key} - {target_ip}")
            return True
        except Exception as e:
            print(f"âš ï¸ Redis SREM attempt {attempt+1} failed for {redis_key}: {e}")
            if attempt < retries:
                await asyncio.sleep(backoff)
    return False

# ---------------------------------------------------------
# 1. ACTIVE MITIGATION (BAN)
# ---------------------------------------------------------
@router.post("/mitigate")
async def execute_mitigation(
    payload: BanRequest,
    request: Request,
    db=Depends(get_db),
    current_user=Depends(get_current_user),
    role: str = Depends(RequireRole(["admin", "manager"])),
):
    target_ip = payload.ip.strip()

    if target_ip == "N/A" or not target_ip or not _is_valid_ip_or_cidr(target_ip):
        raise HTTPException(status_code=400, detail="Invalid IP address format: cannot ban.")

    secure_tenant_id = current_user.get("tenant_id")
    if not secure_tenant_id:
        raise HTTPException(status_code=403, detail="Critical: User lacks tenant assignment.")

    if target_ip in WHITELIST_IPS or any(_target_contains_ip(target_ip, ip) for ip in WHITELIST_IPS if ip != "localhost"):
        raise HTTPException(status_code=400, detail="Safety Lock: Cannot ban system IP.")

    requester_ip = request.client.host if request.client else None
    if not payload.force and _target_contains_ip(target_ip, requester_ip):
        raise HTTPException(
            status_code=409,
            detail="Safety Lock: target includes your current API client IP. Re-run with force=true only after confirming alternate access.",
        )

    conflicting_agent = await _find_active_agent_ip_conflict(db, secure_tenant_id, target_ip)
    if conflicting_agent and not payload.force:
        raise HTTPException(
            status_code=409,
            detail=(
                "Safety Lock: target includes an active WarSOC agent reporting IP "
                f"({conflicting_agent.get('agent_id')}). Re-run with force=true only if you intend to cut off that endpoint."
            ),
        )

    redis_client = getattr(request.app.state, 'redis', None)
    if not redis_client:
        raise HTTPException(status_code=503, detail="Mitigation enforcement unavailable: Redis is not connected.")

    # Fail closed until protected-asset and Redis enforcement checks pass.
    try:
        protected = await _find_protected_asset_conflict(
            db,
            redis_client,
            secure_tenant_id,
            target_ip,
        )
        if protected:
            raise HTTPException(status_code=403, detail="Protected asset: IP is whitelisted and cannot be banned.")
        existing = await db["firewall_rules"].find_one(
            {"tenant_id": secure_tenant_id, "ip": target_ip}
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error("SOAR whitelist check failed: %s", e)
        raise HTTPException(status_code=503, detail="SOAR service unavailable: cannot verify protected assets")

    redis_key = f"warsoc:banned_ips:{secure_tenant_id}"
    try:
        ok = await _redis_sadd_with_retry(redis_client, redis_key, target_ip)
        if not ok:
            raise HTTPException(status_code=503, detail="Mitigation enforcement unavailable: Redis sync failed.")
    except HTTPException:
        raise
    except Exception as e:
        logger.warning("Redis ban sync error for %s: %s", target_ip, e)
        raise HTTPException(status_code=503, detail="Mitigation enforcement unavailable: Redis sync failed.")

    ban_entry = {
        "tenant_id": secure_tenant_id,
        "ip": target_ip,
        "reason": payload.reason,
        "status": "blocked",
        "banned_at": datetime.now(timezone.utc).isoformat(),
        "banned_by": current_user["username"]
    }
    try:
        await db["firewall_rules"].update_one(
            {"ip": target_ip, "tenant_id": secure_tenant_id},
            {"$set": ban_entry},
            upsert=True,
        )
    except Exception as e:
        if not existing:
            rollback_ok = await _redis_srem_with_retry(redis_client, redis_key, target_ip)
            if not rollback_ok:
                logger.critical(
                    "Mitigation rollback failed after database error: tenant=%s target=%s",
                    secure_tenant_id,
                    target_ip,
                )
        logger.error("Mitigation audit persistence failed: %s", e)
        raise HTTPException(status_code=503, detail="Mitigation could not be persisted.")

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
async def revoke_mitigation(
    payload: BanRequest,
    request: Request,
    db=Depends(get_db),
    current_user=Depends(get_current_user),
    role: str = Depends(RequireRole(["admin", "manager"])),
):
    target_ip = payload.ip.strip()
    if target_ip == "N/A" or not target_ip or not _is_valid_ip_or_cidr(target_ip):
        raise HTTPException(status_code=400, detail="Invalid IP address format: cannot revoke.")

    secure_tenant_id = current_user.get("tenant_id")
    if not secure_tenant_id:
        raise HTTPException(status_code=403, detail="Critical: User lacks tenant assignment.")

    try:
        existing = await db["firewall_rules"].find_one(
            {"tenant_id": secure_tenant_id, "ip": target_ip}
        )
    except Exception as e:
        logger.error("Mitigation lookup failed before revoke: %s", e)
        raise HTTPException(status_code=503, detail="Mitigation state is unavailable.")

    redis_client = getattr(request.app.state, 'redis', None)
    if not redis_client:
        raise HTTPException(status_code=503, detail="Mitigation enforcement unavailable: Redis is not connected.")

    redis_key = f"warsoc:banned_ips:{secure_tenant_id}"
    try:
        ok = await _redis_srem_with_retry(redis_client, redis_key, target_ip)
        if not ok:
            raise HTTPException(status_code=503, detail="Mitigation enforcement unavailable: Redis sync failed.")
    except HTTPException:
        raise
    except Exception as e:
        logger.warning("Redis revoke sync error for %s: %s", target_ip, e)
        raise HTTPException(status_code=503, detail="Mitigation enforcement unavailable: Redis sync failed.")

    try:
        await db["firewall_rules"].delete_one(
            {"ip": target_ip, "tenant_id": secure_tenant_id}
        )
    except Exception as e:
        if existing:
            rollback_ok = await _redis_sadd_with_retry(redis_client, redis_key, target_ip)
            if not rollback_ok:
                logger.critical(
                    "Revoke rollback failed after database error: tenant=%s target=%s",
                    secure_tenant_id,
                    target_ip,
                )
        logger.error("Mitigation revoke persistence failed: %s", e)
        raise HTTPException(status_code=503, detail="Mitigation revoke could not be persisted.")

    return {"status": "success", "message": "Access restored"}

# ---------------------------------------------------------
# 3. AGENT HEARTBEAT (C2 TUNNEL)
# ---------------------------------------------------------
@router.get("/agent/heartbeat/{tenant_id}")
async def agent_heartbeat(tenant_id: str, request: Request, current_agent: dict = Depends(verify_agent_token)):
    if tenant_id != current_agent.get("tenant_id"):
        raise HTTPException(status_code=403, detail="Tenant ID mismatch blocked.")

    redis_client = getattr(request.app.state, 'redis', None)
    if not redis_client:
        return {"status": "degraded", "enforce_bans": []}

    try:
        redis_key = f"warsoc:banned_ips:{tenant_id}"
        raw_banned_ips = await redis_client.smembers(redis_key)
        banned_ips = []
        invalid_entries = []

        for candidate in raw_banned_ips:
            c = str(candidate).strip()
            if _is_valid_ip_or_cidr(c):
                banned_ips.append(c)
            else:
                invalid_entries.append(c)

        # Self-heal Redis set so agents never receive hostnames/non-IP garbage.
        if invalid_entries:
            try:
                await redis_client.srem(redis_key, *invalid_entries)
            except Exception:
                pass

        return {
            "status": "active",
            "enforce_bans": banned_ips
        }
    except Exception:
        return {"status": "error", "enforce_bans": []}

# ---------------------------------------------------------
# 4. DASHBOARD LIST
# ---------------------------------------------------------
@router.get("/list")
async def get_blocked_list(db=Depends(get_db), current_user=Depends(get_current_user)):
    secure_tenant_id = current_user.get("tenant_id")

    # ðŸš¨ SURGICAL FIX: Dictionary access and isolation filtering
    cursor = db["firewall_rules"].find({"tenant_id": secure_tenant_id}).sort("banned_at", -1)
    results = []
    async for doc in cursor:
        doc["_id"] = str(doc["_id"])
        results.append(doc)
    return results

# ---------------------------------------------------------
# 4.5 DASHBOARD FRESH START (HIDE OLD TENANT DATA)
# ---------------------------------------------------------
@router.post("/session/fresh-start")
async def tenant_fresh_start(db=Depends(get_db), current_user=Depends(get_current_user)):
    secure_tenant_id = current_user.get("tenant_id")
    username = current_user.get("username")
    if not secure_tenant_id:
        raise HTTPException(status_code=403, detail="Critical: User lacks tenant assignment.")
    if not username:
        raise HTTPException(status_code=403, detail="Critical: User identity unavailable.")

    fresh_start_at = datetime.now(timezone.utc).isoformat()
    await db["users"].update_one(
        {"tenant_id": secure_tenant_id, "username": username},
        {"$set": {"agent_issued_at": fresh_start_at}},
    )

    return {
        "status": "success",
        "message": "Fresh start activated. Only new logs/alerts will be visible.",
        "fresh_start_at": fresh_start_at,
    }

@router.get("/virustotal/ip/{ip}")
async def check_virustotal_ip(ip: str, current_user=Depends(get_current_user)):
    """VirusTotal IP lookup endpoint."""
    raise HTTPException(status_code=501, detail="Threat intel enrichment pending VT integration")


