from fastapi import APIRouter, HTTPException, Depends, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from datetime import datetime, timezone
import asyncio
import io
import json
import os
import secrets as _secrets
import zipfile
from pathlib import Path
import redis.asyncio as aioredis

from app.database import get_db
from app.api.ws_manager import manager 
from app.config.config import get_settings
from app.routes.auth import get_current_user, verify_agent_token, get_password_hash
import ipaddress

router = APIRouter()
settings = get_settings()

class BanRequest(BaseModel):
    ip: str
    reason: str = "Manual Admin Intervention"

WHITELIST_IPS = ["127.0.0.1", "localhost", "::1", "0.0.0.0"]


async def _redis_sadd_with_retry(redis_client, redis_key, target_ip, retries: int = 2, backoff: float = 0.2):
    for attempt in range(retries + 1):
        try:
            await redis_client.sadd(redis_key, target_ip)
            print(f"✅ Redis SADD success: {redis_key} <- {target_ip}")
            return True
        except Exception as e:
            print(f"⚠️ Redis SADD attempt {attempt+1} failed for {redis_key}: {e}")
            if attempt < retries:
                await asyncio.sleep(backoff)
    return False


async def _redis_srem_with_retry(redis_client, redis_key, target_ip, retries: int = 2, backoff: float = 0.2):
    for attempt in range(retries + 1):
        try:
            await redis_client.srem(redis_key, target_ip)
            print(f"✅ Redis SREM success: {redis_key} - {target_ip}")
            return True
        except Exception as e:
            print(f"⚠️ Redis SREM attempt {attempt+1} failed for {redis_key}: {e}")
            if attempt < retries:
                await asyncio.sleep(backoff)
    return False

# ---------------------------------------------------------
# 1. ACTIVE MITIGATION (BAN)
# ---------------------------------------------------------
@router.post("/mitigate")
async def execute_mitigation(payload: BanRequest, request: Request, db=Depends(get_db), current_user=Depends(get_current_user)):
    target_ip = payload.ip.strip()
    try:
        ipaddress.ip_address(target_ip)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid IP address format.")
    secure_tenant_id = current_user.get("tenant_id")
    
    if not secure_tenant_id:
        raise HTTPException(status_code=403, detail="Critical: User lacks tenant assignment.")

    if target_ip in WHITELIST_IPS:
        raise HTTPException(status_code=400, detail="Safety Lock: Cannot ban system IP.")

    # 🚨 SURGICAL FIX: Consistent .db access
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
        await db["firewall_rules"].insert_one(ban_entry)

    # Try to use the global Redis pool; if missing, create a temporary client
    redis_client = getattr(request.app.state, 'redis', None)
    temp_redis = None
    redis_key = f"warsoc:banned_ips:{secure_tenant_id}"
    try:
        if not redis_client:
            temp_redis = await aioredis.from_url(settings.redis_url, decode_responses=True)
            redis_client = temp_redis
        ok = await _redis_sadd_with_retry(redis_client, redis_key, target_ip)
        if not ok:
            print(f"❌ Redis Sync Failed after retries for key {redis_key}")
    except Exception as e:
        print(f"❌ Redis Sync Error: {e}")
    finally:
        if temp_redis:
            try:
                await temp_redis.close()
            except Exception:
                pass

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
async def revoke_mitigation(payload: BanRequest, request: Request, db=Depends(get_db), current_user=Depends(get_current_user)):
    target_ip = payload.ip.strip()
    secure_tenant_id = current_user.get("tenant_id")

    # 🚨 SURGICAL FIX: Added missing delete_one command and fixed db access
    await db["firewall_rules"].delete_one({"ip": target_ip, "tenant_id": secure_tenant_id})

    redis_client = getattr(request.app.state, 'redis', None)
    temp_redis = None
    redis_key = f"warsoc:banned_ips:{secure_tenant_id}"
    try:
        if not redis_client:
            temp_redis = await aioredis.from_url(settings.redis_url, decode_responses=True)
            redis_client = temp_redis
        ok = await _redis_srem_with_retry(redis_client, redis_key, target_ip)
        if not ok:
            print(f"❌ Redis Revoke Failed after retries for key {redis_key}")
    except Exception as e:
        print(f"❌ Redis Revoke Error: {e}")
    finally:
        if temp_redis:
            try:
                await temp_redis.close()
            except Exception:
                pass

    return {"status": "success", "message": "Access restored"}

# ---------------------------------------------------------
# 3. AGENT HEARTBEAT (C2 TUNNEL)
# ---------------------------------------------------------
@router.get("/agent/heartbeat/{tenant_id}")
async def agent_heartbeat(tenant_id: str, request: Request, current_agent: str = Depends(verify_agent_token)):
    if tenant_id != current_agent:
        raise HTTPException(status_code=403, detail="Tenant ID mismatch blocked.")

    redis_client = getattr(request.app.state, 'redis', None)
    temp_redis = None
    try:
        if not redis_client:
            temp_redis = await aioredis.from_url(settings.redis_url, decode_responses=True)
            redis_client = temp_redis
        redis_key = f"warsoc:banned_ips:{tenant_id}"
        banned_ips = await redis_client.smembers(redis_key)
        return {
            "status": "active",
            "enforce_bans": list(banned_ips)
        }
    except Exception as e:
        return {"status": "error", "enforce_bans": []}
    finally:
        if temp_redis:
            try:
                await temp_redis.close()
            except Exception:
                pass

# ---------------------------------------------------------
# 4. DASHBOARD LIST
# ---------------------------------------------------------
@router.get("/list")
async def get_blocked_list(db=Depends(get_db), current_user=Depends(get_current_user)):
    secure_tenant_id = current_user.get("tenant_id")
    
    # 🚨 SURGICAL FIX: Dictionary access and isolation filtering
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
    if not secure_tenant_id:
        raise HTTPException(status_code=403, detail="Critical: User lacks tenant assignment.")

    fresh_start_at = datetime.now(timezone.utc).isoformat()
    await db["users"].update_one(
        {"tenant_id": secure_tenant_id},
        {"$set": {"agent_issued_at": fresh_start_at}},
    )

    return {
        "status": "success",
        "message": "Fresh start activated. Only new logs/alerts will be visible.",
        "fresh_start_at": fresh_start_at,
    }

# ---------------------------------------------------------
# 5. DOWNLOAD PRE-CONFIGURED AGENT
# ---------------------------------------------------------
AGENT_SCRIPT = r'''import win32evtlog
import win32evtlogutil
import win32security
import requests
import time
import socket
import subprocess
import os
import sys
import re
import json
import ipaddress
import threading
from pathlib import Path
from datetime import datetime, timezone
from dotenv import load_dotenv, find_dotenv

# ==========================================
# 1. CONFIG & STATE
# ==========================================
env_path = find_dotenv()
load_dotenv(env_path, override=True)

TENANT_ID = os.getenv("TENANT_ID")
if not TENANT_ID:
    print("[ERROR] TENANT_ID not found. Check your .env file.")
    sys.exit(1)

BACKEND_URL = os.getenv("BACKEND_URL", "http://127.0.0.1:8000").rstrip('/')
AGENT_SECRET = os.getenv("AGENT_MASTER_SECRET", "warsoc_enterprise_agent_key_2026")
WEB_LOG_PATH = os.getenv("WEB_LOG_PATH", "access.log")

WHITELIST_IPS = {"127.0.0.1", "localhost", "::1", "0.0.0.0"}
POLL_INTERVAL = 0.25
HEARTBEAT_INTERVAL = 3

JWT_TOKEN = None
BANNED_IPS = set()
BAN_LOCK = threading.Lock()
_IP_IN_TEXT_PATTERN = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')

def load_target_event_ids():
    """Strictly load Event IDs from tenant policy/config, no hardcoded fallback."""
    agent_dir = Path(__file__).resolve().parent
    policy_path = agent_dir / "tenant_policy.json"
    config_json_path = agent_dir / "config.json"

    def _parse(raw):
        try:
            return {int(eid) for eid in raw}
        except Exception:
            return set()

    for p in [policy_path, config_json_path]:
        try:
            if p.exists():
                with open(p, "r", encoding="utf-8") as f:
                    doc = json.load(f)
                ids = _parse(doc.get("monitoring", {}).get("target_event_ids", []))
                if ids:
                    return ids
        except Exception:
            continue

    return set()

TARGET_EVENT_IDS = load_target_event_ids()

def extract_source_ip_from_line(line: str):
    for candidate in _IP_IN_TEXT_PATTERN.findall(line):
        try:
            ip_obj = ipaddress.ip_address(candidate)
            if ip_obj.is_multicast or ip_obj.is_unspecified:
                continue
            return candidate
        except ValueError:
            continue
    return None

# ==========================================
# 2. HELPERS
# ==========================================
def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"

def resolve_user(sid):
    try:
        if sid:
            name, domain, _ = win32security.LookupAccountSid(None, sid)
            return f"{domain}\\{name}"
    except Exception:
        pass
    return "SYSTEM"

_IP_PATTERN = re.compile(r'^[\d.:a-fA-F]+(/\d{1,3})?$')

def enforce_block(ip):
    if ip in WHITELIST_IPS:
        return
    if not _IP_PATTERN.match(ip):
        return
    with BAN_LOCK:
        if ip in BANNED_IPS:
            return
        try:
            subprocess.run(
                ["netsh", "advfirewall", "firewall", "add", "rule",
                 f"name=WarSOC_Block_{ip}", "dir=in", "action=block", f"remoteip={ip}"],
                check=True, capture_output=True, text=True
            )
            BANNED_IPS.add(ip)
            print(f"[BLOCKED] {ip}")
        except Exception as e:
            print(f"[BLOCK FAILED] {e}")

# ==========================================
# 3. AUTHENTICATION
# ==========================================
def authenticate_agent():
    global JWT_TOKEN
    print(f"[AUTH] Connecting Tenant {TENANT_ID}...")
    try:
        resp = requests.post(f"{BACKEND_URL}/api/v1/auth/agent-login",
                             json={"agent_id": TENANT_ID, "agent_secret": AGENT_SECRET},
                             timeout=5)
        if resp.status_code == 200:
            JWT_TOKEN = resp.json().get("access_token")
            print("[AUTH] Connected successfully.")
            return True
        else:
            print(f"[AUTH FAILED] {resp.status_code} - {resp.text}")
            return False
    except Exception as e:
        print(f"[AUTH ERROR] Backend unreachable: {e}")
        return False

def secure_request(method, url, **kwargs):
    global JWT_TOKEN
    if not JWT_TOKEN:
        if not authenticate_agent():
            return None
    headers = kwargs.get("headers", {})
    headers["Authorization"] = f"Bearer {JWT_TOKEN}"
    kwargs["headers"] = headers
    try:
        resp = requests.request(method, url, **kwargs)
        if resp.status_code == 401:
            if authenticate_agent():
                headers["Authorization"] = f"Bearer {JWT_TOKEN}"
                kwargs["headers"] = headers
                resp = requests.request(method, url, **kwargs)
        return resp
    except Exception as e:
        print(f"[NET ERROR] {e}")
        return None

# ==========================================
# 4. SENSOR THREADS
# ==========================================
def heartbeat_thread():
    heartbeat_url = f"{BACKEND_URL}/api/v1/agent/heartbeat/{TENANT_ID}"
    while True:
        resp = secure_request("GET", heartbeat_url, timeout=10)
        if resp and resp.status_code == 200:
            data = resp.json()
            for bad_ip in data.get("enforce_bans", []):
                enforce_block(bad_ip)
        time.sleep(HEARTBEAT_INTERVAL)

def web_hunter_thread():
    print(f"[SENSOR] Web Hunter active: {WEB_LOG_PATH}")
    ingest_url = f"{BACKEND_URL}/api/v1/ingest/windows"
    if not os.path.exists(WEB_LOG_PATH):
        with open(WEB_LOG_PATH, 'w') as f:
            f.write("")
    with open(WEB_LOG_PATH, "r", encoding="utf-8") as file:
        file.seek(0, 2)
        while True:
            line = file.readline()
            if not line:
                time.sleep(0.2)
                file.seek(file.tell())  # Windows fix: clear internal buffer to see new data
                continue
            line = line.strip()
            if line:
                extracted_source_ip = extract_source_ip_from_line(line)
                payload = {
                    "agent_id": TENANT_ID,
                    "source_ip": extracted_source_ip or get_local_ip(),
                    "user": "Web-Visitor",
                    "event_id": 80,
                    "message": line,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "raw_data": line,
                    "agent_version": "4.0"
                }
                secure_request("POST", ingest_url, json=payload, timeout=10)

def log_hunter_thread():
    print("[SENSOR] Windows Event Log Hunter active")
    print(f"[SENSOR] Monitoring Event IDs: {sorted(TARGET_EVENT_IDS)}")
    ingest_url = f"{BACKEND_URL}/api/v1/ingest/windows"
    log_type = "Security"
    try:
        temp_hand = win32evtlog.OpenEventLog(None, log_type)
        total = win32evtlog.GetNumberOfEventLogRecords(temp_hand)
        oldest = win32evtlog.GetOldestEventLogRecord(temp_hand)
        highest_record_seen = oldest + total - 1
        win32evtlog.CloseEventLog(temp_hand)
    except Exception as e:
        print(f"[ERROR] Admin privileges required: {e}")
        os._exit(1)
    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
    while True:
        hand = None
        try:
            hand = win32evtlog.OpenEventLog(None, log_type)
            events = win32evtlog.ReadEventLog(hand, flags, 0)
            if events:
                current_batch_highest = highest_record_seen
                for event in events:
                    if event.RecordNumber <= highest_record_seen:
                        break
                    current_batch_highest = max(current_batch_highest, event.RecordNumber)
                    event_id = event.EventID & 0xFFFF
                    if event_id in TARGET_EVENT_IDS:
                        try:
                            msg = win32evtlogutil.SafeFormatMessage(event, log_type)
                            clean_msg = msg.split("\\n")[0] if msg else "Raw Data"
                        except Exception:
                            clean_msg = "Format Error"
                        payload = {
                            "agent_id": TENANT_ID,
                            "source_ip": get_local_ip(),
                            "user": resolve_user(event.Sid),
                            "event_id": event_id,
                            "message": f"Event {event_id}: {clean_msg}",
                            "timestamp": event.TimeGenerated.isoformat(),
                            "raw_data": clean_msg,
                            "agent_version": "4.0"
                        }
                        print(f"[EVENT] {event_id} captured")
                        secure_request("POST", ingest_url, json=payload, timeout=10)
                highest_record_seen = current_batch_highest
        except Exception:
            pass
        finally:
            if hand:
                win32evtlog.CloseEventLog(hand)
        time.sleep(POLL_INTERVAL)

# ==========================================
# 5. MAIN
# ==========================================
if __name__ == "__main__":
    print("=" * 50)
    print("  WarSOC Agent v4.0")
    print(f"  Tenant: {TENANT_ID}")
    print(f"  Backend: {BACKEND_URL}")
    print("=" * 50)
    if not TARGET_EVENT_IDS:
        print("[ERROR] No event IDs configured in tenant_policy.json/config.json")
        sys.exit(1)
    authenticate_agent()
    threading.Thread(target=heartbeat_thread, daemon=True).start()
    threading.Thread(target=log_hunter_thread, daemon=True).start()
    threading.Thread(target=web_hunter_thread, daemon=True).start()
    print("[READY] All sensors active. Monitoring...")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\\nShutting down.")
        sys.exit(0)
'''

AGENT_REQUIREMENTS = """pywin32>=306
requests>=2.31.0
python-dotenv>=1.0.0
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
- `BACKEND_URL` — Your WarSOC server address
- `WEB_LOG_PATH` — Path to your web server access log
- `AGENT_MASTER_SECRET` — Your agent authentication key

Your Tenant ID is pre-configured. Do not change it.
"""


@router.get("/agent/download")
async def download_agent(current_user=Depends(get_current_user), db=Depends(get_db)):
    tenant_id = current_user.get("tenant_id")
    username = current_user.get("username", "user")
    if not tenant_id:
        raise HTTPException(status_code=403, detail="No tenant assigned")

    # ✅ OPTION A: Keep agent secret across downloads (only generate once per tenant)
    # 1. Check if user already has an agent secret
    existing_user = await db["users"].find_one({"tenant_id": tenant_id})
    stored_secret = existing_user.get("agent_secret") if existing_user else None

    # We will ensure the value stored in DB is a hashed secret, while the
    # plaintext `agent_secret_for_zip` is used for the downloadable .env.
    agent_secret_for_zip = None

    if stored_secret:
        # If stored value appears to be a hash (passlib hashes usually start with "$"),
        # we cannot recover the plaintext. Rotate to a new secret and store its hash.
        if isinstance(stored_secret, str) and stored_secret.startswith("$"):
            agent_secret_for_zip = _secrets.token_urlsafe(32)
            hashed_secret = get_password_hash(agent_secret_for_zip)
            await db["users"].update_one(
                {"tenant_id": tenant_id},
                {"$set": {"agent_secret": hashed_secret}},
            )
        else:
            # Stored secret appears to be plaintext; migrate by hashing it and
            # keep the plaintext for the downloaded package this time.
            agent_secret_for_zip = stored_secret
            hashed_secret = get_password_hash(agent_secret_for_zip)
            await db["users"].update_one(
                {"tenant_id": tenant_id},
                {"$set": {"agent_secret": hashed_secret}},
            )
    else:
        # No secret exists; create one, store the hash, and keep plaintext for zip
        agent_secret_for_zip = _secrets.token_urlsafe(32)
        hashed_secret = get_password_hash(agent_secret_for_zip)
        await db["users"].update_one(
            {"tenant_id": tenant_id},
            {"$set": {"agent_secret": hashed_secret}},
        )

    # 3. Mark this download as a fresh start point for dashboard views.
    #    Data is not deleted; older records are simply hidden by default.
    fresh_start_at = datetime.now(timezone.utc).isoformat()
    await db["users"].update_one(
        {"tenant_id": tenant_id},
        {"$set": {"agent_issued_at": fresh_start_at}},
    )

    backend_url = settings.backend_public_url.rstrip("/")

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
            windows_channels = [str(ch).strip() for ch in raw_channels if str(ch).strip()]
            if not windows_channels:
                windows_channels = ["Security"]
            raw_web_paths = monitoring_cfg.get("web_log_paths", ["access.log"])
            web_log_paths = [str(p).strip() for p in raw_web_paths if str(p).strip()]
            if not web_log_paths:
                web_log_paths = ["access.log"]
    except Exception:
        target_event_ids = []
        capture_all_security_events = False
        capture_all_windows_channels = False
        windows_channels = ["Security"]
        web_log_paths = ["access.log"]

    agent_script_content = AGENT_SCRIPT
    try:
        agent_source_path = Path(__file__).resolve().parent.parent.parent / "agent" / "windows_agent.py"
        if agent_source_path.exists():
            agent_script_content = agent_source_path.read_text(encoding="utf-8")
    except Exception:
        agent_script_content = AGENT_SCRIPT

    tenant_policy = {
        "agent_settings": {
            "tenant_id": tenant_id,
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

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("warsoc-agent/warsoc_agent.py", agent_script_content)
        zf.writestr("warsoc-agent/requirements.txt", AGENT_REQUIREMENTS)
        zf.writestr("warsoc-agent/README.md", AGENT_README)
        zf.writestr("warsoc-agent/tenant_policy.json", json.dumps(tenant_policy, indent=2))
        # Use the plaintext secret for the zip. If we rotated or migrated above,
        # `agent_secret_for_zip` will contain the plaintext value. As a fallback,
        # avoid writing an incorrect hashed value into the .env.
        zf.writestr("warsoc-agent/.env", (
            f"TENANT_ID={tenant_id}\n"
            f"BACKEND_URL={backend_url}\n"
            f"AGENT_MASTER_SECRET={agent_secret_for_zip or ''}\n"
            f"WEB_LOG_PATH=access.log\n"
        ))
    buf.seek(0)

    filename = f"WarSOC_Agent_{username}.zip"
    return StreamingResponse(
        buf,
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'}
    )