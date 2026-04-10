import win32evtlog
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
                            "timestamp": event.TimeGenerated.replace(tzinfo=datetime.now().astimezone().tzinfo).astimezone(timezone.utc).isoformat() if event.TimeGenerated else datetime.now(timezone.utc).isoformat(),
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
