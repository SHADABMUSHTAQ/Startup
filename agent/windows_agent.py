import win32evtlog
import win32evtlogutil
import win32security
import requests
import time
import socket
import subprocess
import os
import sys
import json
import ipaddress
import threading
import queue
import glob
from pathlib import Path
from datetime import datetime, timezone # 🚀 ADDED TIMEZONE

# 🔐 ENV COMPLIANCE
from dotenv import load_dotenv, find_dotenv

# ==========================================
# 1. ENTERPRISE CONFIG & STATE
# ==========================================
env_path = find_dotenv()
print(f"[🛡️] ARCHITECT OVERRIDE: Loading .env from -> {env_path}")
load_dotenv(env_path, override=True)

TENANT_ID = os.getenv("TENANT_ID")
if not TENANT_ID:
    print("[❌] FATAL: TENANT_ID is still empty. Check your .env file!")
    sys.exit(1)

BACKEND_URL = os.getenv("BACKEND_URL", "http://127.0.0.1:8000").rstrip('/')
AGENT_SECRET = os.getenv("AGENT_MASTER_SECRET", "warsoc_enterprise_agent_key_2026")

# 🚀 NEW: Web Server Log File Path (You can change this to your Apache/Nginx path later)
WEB_LOG_PATH = os.getenv("WEB_LOG_PATH", "access.log")

WHITELIST_IPS = set(["127.0.0.1", "localhost", "::1", "0.0.0.0"])
POLL_INTERVAL = 0.25
HEARTBEAT_INTERVAL = 3
OUTBOUND_QUEUE_MAX = int(os.getenv("OUTBOUND_QUEUE_MAX", "5000"))
OUTBOUND_BATCH_SIZE = int(os.getenv("OUTBOUND_BATCH_SIZE", "25"))
OUTBOUND_BATCH_WAIT_SECONDS = float(os.getenv("OUTBOUND_BATCH_WAIT_SECONDS", "0.25"))
INGEST_URL = f"{BACKEND_URL}/api/v1/ingest/windows"
LOCAL_IP = "127.0.0.1"
WEB_LOG_PATHS = [WEB_LOG_PATH]
WINDOWS_CHANNELS = ["Security"]

JWT_TOKEN = None
BANNED_IPS = set()
BAN_LOCK = threading.Lock()
REQUEST_SESSION = requests.Session()
OUTBOUND_QUEUE = queue.Queue(maxsize=OUTBOUND_QUEUE_MAX)

# ==========================================
# 2. HELPER FUNCTIONS & MITIGATION 
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

LOCAL_IP = get_local_ip()

import re as _re
_IP_PATTERN = _re.compile(r'^[\d.:a-fA-F]+(/\d{1,3})?$')
_IP_IN_TEXT_PATTERN = _re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')

def _load_monitoring_document():
    """Load monitoring document from tenant policy first, then app config."""
    agent_dir = Path(__file__).resolve().parent
    policy_path = agent_dir / "tenant_policy.json"
    config_json_path = agent_dir.parent / "app" / "config" / "config.json"

    for cfg_path in [policy_path, config_json_path]:
        try:
            if not cfg_path.exists():
                continue
            with open(cfg_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            continue
    return {}

def load_target_event_ids():
    """Load monitorable Event IDs only from config sources (no hardcoded defaults)."""
    def _parse_target_ids(raw):
        try:
            parsed = {int(eid) for eid in raw}
            return parsed
        except Exception:
            return set()

    monitoring = _load_monitoring_document().get("monitoring", {})
    parsed = _parse_target_ids(monitoring.get("target_event_ids", []))
    if parsed:
        return parsed

    print("[!] No monitorable Event IDs found in tenant_policy.json or config.json")
    return set()

def load_capture_all_security_events():
    """Load whether to capture all security events from config sources."""
    monitoring = _load_monitoring_document().get("monitoring", {})
    return bool(monitoring.get("capture_all_security_events", False))

def load_capture_all_windows_channels():
    monitoring = _load_monitoring_document().get("monitoring", {})
    return bool(monitoring.get("capture_all_windows_channels", False))

def load_windows_channels():
    monitoring = _load_monitoring_document().get("monitoring", {})
    channels = monitoring.get("windows_channels", ["Security"])
    parsed = [str(c).strip() for c in channels if str(c).strip()]
    if not parsed:
        parsed = ["Security"]
    return list(dict.fromkeys(parsed))

def load_web_log_paths():
    monitoring = _load_monitoring_document().get("monitoring", {})
    configured = monitoring.get("web_log_paths", [])
    parsed = [str(p).strip() for p in configured if str(p).strip()]
    if not parsed:
        parsed = [WEB_LOG_PATH]
    return list(dict.fromkeys(parsed))

TARGET_EVENT_IDS = load_target_event_ids()
CAPTURE_ALL_SECURITY_EVENTS = load_capture_all_security_events()
CAPTURE_ALL_WINDOWS_CHANNELS = load_capture_all_windows_channels()
WINDOWS_CHANNELS = load_windows_channels()
WEB_LOG_PATHS = load_web_log_paths()

def extract_source_ip_from_line(line: str):
    """Try to recover client IP from a web log line; return None when unavailable."""
    for candidate in _IP_IN_TEXT_PATTERN.findall(line):
        try:
            ip_obj = ipaddress.ip_address(candidate)
            if ip_obj.is_multicast or ip_obj.is_unspecified:
                continue
            return candidate
        except ValueError:
            continue
    return None

def enforce_block(ip):
    if ip in WHITELIST_IPS:
        print(f"[⚠️] SAFETY OVERRIDE: {ip} is whitelisted. Ignored.")
        return

    if not _IP_PATTERN.match(ip):
        print(f"[!] INVALID IP rejected: {ip}")
        return

    with BAN_LOCK:
        if ip in BANNED_IPS: return
        try:
            subprocess.run(
                ["netsh", "advfirewall", "firewall", "add", "rule",
                 f"name=WarSOC_Block_{ip}", "dir=in", "action=block", f"remoteip={ip}"],
                check=True, capture_output=True, text=True
            )
            BANNED_IPS.add(ip)
            print(f"[🛡️] MITIGATION SUCCESS: Block applied to {ip}")
        except Exception as e:
            print(f"[!] MITIGATION FAILED: {e}")

# ==========================================
# 3. ENTERPRISE AUTHENTICATION PIPELINE
# ==========================================
def authenticate_agent():
    global JWT_TOKEN
    print(f"[🔐] Authenticating Tenant {TENANT_ID} with WarSOC Backbone...")
    try:
        resp = REQUEST_SESSION.post(f"{BACKEND_URL}/api/v1/auth/agent-login", 
                             json={"agent_id": TENANT_ID, "agent_secret": AGENT_SECRET}, 
                             timeout=5)
        if resp.status_code == 200:
            JWT_TOKEN = resp.json().get("access_token")
            print("[✅] Connection Secured. Vault access granted.")
            return True
        else:
            print(f"[❌] Access Denied: {resp.status_code} - {resp.text}")
            return False
    except Exception as e:
        print(f"[!] Backbone Unreachable: {e}")
        return False

def secure_request(method, url, **kwargs):
    global JWT_TOKEN
    if not JWT_TOKEN:
        if not authenticate_agent(): return None
    
    headers = kwargs.get("headers", {})
    headers["Authorization"] = f"Bearer {JWT_TOKEN}"
    kwargs["headers"] = headers

    try:
        resp = REQUEST_SESSION.request(method, url, **kwargs)
        
        if method == "POST" and "ingest" in url and resp.status_code == 200:
             pass # Silently succeed to avoid console spam

        if resp.status_code == 401:
            print("[⚠️] Token expired. Re-authenticating...")
            if authenticate_agent():
                headers["Authorization"] = f"Bearer {JWT_TOKEN}"
                kwargs["headers"] = headers
                resp = REQUEST_SESSION.request(method, url, **kwargs)
        
        elif resp.status_code != 200:
            print(f"[❌] Backend rejected payload: {resp.status_code}")

        return resp
    except Exception as e:
        print(f"[📡] Connection Error to {url}: {e}")
        return None

def enqueue_payload(payload):
    """Non-blocking enqueue to keep log readers fast under burst traffic."""
    try:
        OUTBOUND_QUEUE.put_nowait(payload)
    except queue.Full:
        try:
            OUTBOUND_QUEUE.get_nowait()
            OUTBOUND_QUEUE.put_nowait(payload)
            print("[⚠️] Outbound queue full. Oldest payload dropped to keep agent real-time.")
        except Exception:
            pass

def ingest_sender_thread():
    print(f"[*] Sender Online. Queue capacity={OUTBOUND_QUEUE_MAX}, batch={OUTBOUND_BATCH_SIZE}")
    while True:
        try:
            first = OUTBOUND_QUEUE.get(timeout=1)
        except queue.Empty:
            continue

        batch = [first]
        batch_deadline = time.time() + OUTBOUND_BATCH_WAIT_SECONDS

        while len(batch) < OUTBOUND_BATCH_SIZE and time.time() < batch_deadline:
            try:
                batch.append(OUTBOUND_QUEUE.get_nowait())
            except queue.Empty:
                break

        for payload in batch:
            resp = secure_request("POST", INGEST_URL, json=payload, timeout=10)
            if not resp or resp.status_code != 200:
                enqueue_payload(payload)
                break

def resolve_web_log_files():
    """Resolve configured web log files and glob patterns to concrete file paths."""
    resolved = []
    for path_pattern in WEB_LOG_PATHS:
        matches = glob.glob(path_pattern)
        if matches:
            resolved.extend(matches)
        elif os.path.exists(path_pattern):
            resolved.append(path_pattern)
    return sorted(set(resolved))

# ==========================================
# 4. THREADS 
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

# 🚀 NEW: WEB LOG HUNTER (Monitors text files live)
def web_hunter_thread():
    print(f"[*] Web Hunter Online. Monitoring paths: {WEB_LOG_PATHS}")
    file_positions = {}

    while True:
        log_files = resolve_web_log_files()

        for file_path in log_files:
            if not os.path.exists(file_path):
                continue

            if file_path not in file_positions:
                try:
                    file_positions[file_path] = os.path.getsize(file_path)
                except Exception:
                    file_positions[file_path] = 0

            try:
                current_size = os.path.getsize(file_path)
                if current_size < file_positions[file_path]:
                    # Log rotated/truncated, restart from beginning of new file.
                    file_positions[file_path] = 0

                with open(file_path, "r", encoding="utf-8", errors="replace") as file:
                    file.seek(file_positions[file_path], 0)
                    while True:
                        line = file.readline()
                        if not line:
                            break

                        line = line.strip()
                        if not line:
                            continue

                        print(f"[🌐] Web Event Detected: {line[:50]}...")
                        extracted_source_ip = extract_source_ip_from_line(line)
                        payload = {
                            "agent_id": TENANT_ID,
                            "source_ip": extracted_source_ip or LOCAL_IP,
                            "user": "Web-Visitor",
                            "event_id": 80, # Custom ID for Web Logs
                            "message": line,
                            "timestamp": datetime.now(timezone.utc).isoformat(),
                            "raw_data": {"raw": line, "web_log_file": file_path},
                            "agent_version": "4.0-Omni"
                        }
                        enqueue_payload(payload)

                    file_positions[file_path] = file.tell()
            except Exception as e:
                print(f"[!] Web log read error ({file_path}): {e}")

        time.sleep(0.2)


def log_hunter_thread():
    print(f"[*] Windows Hunter Online. Streaming via Secure Tunnel...")
    if CAPTURE_ALL_SECURITY_EVENTS:
        print("[*] Monitoring Mode: capture_all_security_events=true (all Security log events)")
    if CAPTURE_ALL_WINDOWS_CHANNELS:
        print("[*] Monitoring Mode: capture_all_windows_channels=true")
    print(f"[*] Monitoring Channels: {WINDOWS_CHANNELS}")
    print(f"[*] Monitoring Event IDs: {sorted(TARGET_EVENT_IDS)}")
    highest_record_seen = {}

    for log_type in WINDOWS_CHANNELS:
        try:
            temp_hand = win32evtlog.OpenEventLog(None, log_type)
            total = win32evtlog.GetNumberOfEventLogRecords(temp_hand)
            oldest = win32evtlog.GetOldestEventLogRecord(temp_hand)
            highest_record_seen[log_type] = oldest + total - 1
            win32evtlog.CloseEventLog(temp_hand)
            print(f"[*] Synced channel '{log_type}'. Watermark: {highest_record_seen[log_type]}")
        except Exception as e:
            print(f"[!] Channel open failed ({log_type}): {e}")
            highest_record_seen[log_type] = 0

    if not any(v >= 0 for v in highest_record_seen.values()):
        print("[!] No Windows Event channels available. Run agent as Administrator.")
        os._exit(1)

    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ

    while True:
        for log_type in WINDOWS_CHANNELS:
            hand = None
            try:
                hand = win32evtlog.OpenEventLog(None, log_type)
                events = win32evtlog.ReadEventLog(hand, flags, 0)
                
                if events:
                    channel_watermark = highest_record_seen.get(log_type, 0)
                    current_batch_highest = channel_watermark
                    for event in events:
                        if event.RecordNumber <= channel_watermark:
                            break 
                        
                        current_batch_highest = max(current_batch_highest, event.RecordNumber)
                        event_id = event.EventID & 0xFFFF

                        include_event = CAPTURE_ALL_WINDOWS_CHANNELS
                        if not include_event:
                            if log_type.lower() == "security" and CAPTURE_ALL_SECURITY_EVENTS:
                                include_event = True
                            elif event_id in TARGET_EVENT_IDS:
                                include_event = True
                        
                        if include_event:
                            try:
                                msg = win32evtlogutil.SafeFormatMessage(event, log_type)
                                clean_msg = msg.split("\n")[0] if msg else "Raw Data"
                            except Exception:
                                clean_msg = "Format Error"

                            payload = {
                                "agent_id": TENANT_ID,
                                "source_ip": LOCAL_IP,
                                "user": resolve_user(event.Sid),
                                "event_id": event_id,
                                "message": f"[{log_type}] Event {event_id}: {clean_msg}",
                                "timestamp": event.TimeGenerated.isoformat(),
                                "raw_data": {"raw": clean_msg, "windows_channel": log_type},
                                "agent_version": "4.0-Omni"
                            }
                            print(f"[🛡️] Windows Event Streamed: {log_type}:{event_id}")
                            enqueue_payload(payload)

                    highest_record_seen[log_type] = current_batch_highest

            except Exception:
                pass
            finally:
                if hand:
                    win32evtlog.CloseEventLog(hand)
            
        time.sleep(POLL_INTERVAL)

if __name__ == "__main__":
    print("==========================================")
    print(f"   WarSOC OMNI AGENT v4.0 ")
    print(f"   Tenant ID: {TENANT_ID}")
    print("==========================================")

    if not TARGET_EVENT_IDS and not CAPTURE_ALL_SECURITY_EVENTS:
        print("[❌] FATAL: No Event IDs configured. Set monitoring.target_event_ids in tenant_policy.json or app/config/config.json")
        sys.exit(1)
    
    authenticate_agent()

    # 🚀 START ALL SENSORS
    threading.Thread(target=heartbeat_thread, daemon=True).start()
    threading.Thread(target=ingest_sender_thread, daemon=True).start()
    threading.Thread(target=log_hunter_thread, daemon=True).start()
    threading.Thread(target=web_hunter_thread, daemon=True).start() # The new Web Scanner!

    try:
        while True: time.sleep(1)
    except KeyboardInterrupt:
        print("\n🛑 Safe exit.")
        sys.exit(0)