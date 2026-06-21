from fastapi import APIRouter, HTTPException, Depends, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from datetime import datetime, timezone
import asyncio
import io
import json
import logging
import zipfile
from pathlib import Path

from app.database import get_db
from app.api.ws_manager import manager
from app.config.config import get_settings
from app.routes.auth import get_current_user, verify_agent_token
from app.utils.rbac import RoleChecker as RequireRole
import uuid
import ipaddress

router = APIRouter()
settings = get_settings()
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

    # ðŸš¨ SURGICAL FIX: Consistent .db access
    existing = await db["firewall_rules"].find_one({"ip": target_ip, "tenant_id": secure_tenant_id})

    if not existing:
        ban_entry = {
            "tenant_id": secure_tenant_id,
            "ip": target_ip,
            "reason": payload.reason,
            "status": "blocked",
            "banned_at": datetime.now(timezone.utc).isoformat(),
            "banned_by": current_user["username"]
        }
        # Tenant-aware SOAR whitelist: prevent banning protected assets
        try:
            protected = await db["soar_whitelist"].find_one({"tenant_id": secure_tenant_id, "ip": target_ip})
            if protected:
                raise HTTPException(status_code=403, detail="Protected asset: IP is whitelisted and cannot be banned.")
        except HTTPException:
            raise
        except Exception as e:
            # On DB lookup failure, fail-closed: refuse to ban until whitelist check succeeds
            logger.error(f"SOAR whitelist check failed: {e}")
            raise HTTPException(status_code=503, detail="SOAR service unavailable: cannot verify protected assets")

        await db["firewall_rules"].insert_one(ban_entry)

    redis_client = getattr(request.app.state, 'redis', None)
    redis_key = f"warsoc:banned_ips:{secure_tenant_id}"
    try:
        if redis_client:
            ok = await _redis_sadd_with_retry(redis_client, redis_key, target_ip)
            if not ok:
                logger.warning("Redis ban sync failed after retries for key %s", redis_key)
        else:
            logger.warning("Redis unavailable; firewall rule saved but live agent ban sync skipped for %s", target_ip)
    except Exception as e:
        logger.warning("Redis ban sync error for %s: %s", target_ip, e)

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

    # ðŸš¨ SURGICAL FIX: Added missing delete_one command and fixed db access
    await db["firewall_rules"].delete_one({"ip": target_ip, "tenant_id": secure_tenant_id})

    redis_client = getattr(request.app.state, 'redis', None)
    redis_key = f"warsoc:banned_ips:{secure_tenant_id}"
    try:
        if redis_client:
            ok = await _redis_srem_with_retry(redis_client, redis_key, target_ip)
            if not ok:
                logger.warning("Redis revoke failed after retries for key %s", redis_key)
        else:
            logger.warning("Redis unavailable; firewall rule removed but live agent revoke sync skipped for %s", target_ip)
    except Exception as e:
        logger.warning("Redis revoke sync error for %s: %s", target_ip, e)

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

# ---------------------------------------------------------
AGENT_SCRIPT = None

AGENT_REQUIREMENTS = """pywin32>=306
requests>=2.31.0
python-dotenv>=1.0.0
ecdsa>=0.19.1
"""

AGENT_README = """# WarSOC Agent Setup

## Requirements
- Windows 10/11 or Windows Server
- Python 3.10+
- Administrator privileges (for Windows Event Log access)

## Installation
1. Open PowerShell as Administrator
2. Navigate to this folder
3. Install dependencies:
   ```
   pip install -r requirements.txt
   ```
4. Run the agent:
   ```
   python warsoc_agent.py
   ```

## What it monitors
- **Windows Security Events**: Login attempts, account changes, audit log clearing
- **Web Server Logs**: Apache/Nginx access logs (configure WEB_LOG_PATH in .env)
- **Firewall Enforcement**: Automatically blocks IPs flagged by WarSOC

## Configuration
Edit the `.env` file to change:
- `BACKEND_URL` - Your WarSOC server address
- `WEB_LOG_PATH` - Path to your web server access log
- `AGENT_ID` - The unique identity for this endpoint

The agent prompts for a one-time Enrollment Token on first run. Generate that token
from the WarSOC dashboard and deliver it separately from the ZIP package.

Your Tenant ID is pre-configured. Do not change it.
"""


@router.get("/agent/download")
async def download_agent(current_user=Depends(get_current_user), db=Depends(get_db)):
    tenant_id = current_user.get("tenant_id")
    username = current_user.get("username", "user")
    if not tenant_id:
        raise HTTPException(status_code=403, detail="No tenant assigned")
    if not username:
        raise HTTPException(status_code=403, detail="No user identity available")

    fresh_start_at = datetime.now(timezone.utc).isoformat()
    await db["users"].update_one(
        {"tenant_id": tenant_id, "username": username},
        {"$set": {"agent_issued_at": fresh_start_at}},
    )

    backend_url = settings.backend_public_url.rstrip("/")
    agent_id = f"{tenant_id}-{username}-{uuid.uuid4().hex[:8]}"

    await db["agents"].update_one(
        {"agent_id": agent_id},
        {
            "$setOnInsert": {
                "agent_id": agent_id,
                "tenant_id": tenant_id,
                "approved": True,
                "status": "pending_enrollment",
                "issued_to": username,
                "created_at": datetime.now(timezone.utc),
            }
        },
        upsert=True,
    )

    target_event_ids = []
    capture_all_security_events = False
    capture_all_windows_channels = False
    windows_channels = ["Security"]
    web_log_paths = ["access.log"]
    try:
        config_path = Path(__file__).resolve().parent.parent / "config" / "config.json"
        if config_path.exists():
            with open(config_path, "r", encoding="utf-8") as f:
                app_cfg = json.load(f)
            monitoring_cfg = app_cfg.get("monitoring", {})
            raw_ids = monitoring_cfg.get("target_event_ids", [])
            target_event_ids = [int(eid) for eid in raw_ids]
            capture_all_security_events = bool(monitoring_cfg.get("capture_all_security_events", False))
            capture_all_windows_channels = bool(monitoring_cfg.get("capture_all_windows_channels", False))
            raw_channels = monitoring_cfg.get("windows_channels", ["Security"])
            windows_channels = [str(ch).strip() for ch in raw_channels if str(ch).strip()] or ["Security"]
            raw_web_paths = monitoring_cfg.get("web_log_paths", ["access.log"])
            web_log_paths = [str(p).strip() for p in raw_web_paths if str(p).strip()] or ["access.log"]
    except Exception:
        target_event_ids = []
        capture_all_security_events = False
        capture_all_windows_channels = False
        windows_channels = ["Security"]
        web_log_paths = ["access.log"]

    agent_source_path = Path(__file__).resolve().parent.parent.parent / "agent" / "windows_agent.py"
    if not agent_source_path.exists():
        raise HTTPException(status_code=500, detail="Live agent source file is missing")
    agent_script_content = agent_source_path.read_text(encoding="utf-8")

    tenant_policy = {
        "agent_settings": {
            "tenant_id": tenant_id,
            "agent_id": agent_id,
            "backend_url": backend_url,
        },
        "monitoring": {
            "target_event_ids": target_event_ids,
            "capture_all_security_events": capture_all_security_events,
            "capture_all_windows_channels": capture_all_windows_channels,
            "windows_channels": windows_channels,
            "web_log_paths": web_log_paths,
        },
    }

    default_web_log_path = web_log_paths[0] if web_log_paths else "access.log"

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("warsoc-agent/warsoc_agent.py", agent_script_content)
        zf.writestr("warsoc-agent/requirements.txt", AGENT_REQUIREMENTS)
        zf.writestr("warsoc-agent/README.md", AGENT_README)
        zf.writestr("warsoc-agent/tenant_policy.json", json.dumps(tenant_policy, indent=2))
        zf.writestr("warsoc-agent/.env", (
            f"TENANT_ID={tenant_id}\n"
            f"AGENT_ID={agent_id}\n"
            f"BACKEND_URL={backend_url}\n"
            f"WEB_LOG_PATH={default_web_log_path}\n"
        ))
    buf.seek(0)

    filename = f"WarSOC_Agent_{username}.zip"
    return StreamingResponse(
        buf,
        media_type="application/zip",
        headers={
            "Content-Disposition": f'attachment; filename=\"{filename}\"',
            "X-WarSOC-Agent-ID": agent_id,
        }
    )


@router.get("/virustotal/ip/{ip}")
async def check_virustotal_ip(ip: str, current_user=Depends(get_current_user)):
    """VirusTotal IP lookup endpoint."""
    raise HTTPException(status_code=501, detail="Threat intel enrichment pending VT integration")


