import win32evtlog
import win32evtlogutil
import win32security
import requests
import time
import socket
import subprocess
import os
import sys
import threading
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
POLL_INTERVAL = 1  
HEARTBEAT_INTERVAL = 5

JWT_TOKEN = None
BANNED_IPS = set()
BAN_LOCK = threading.Lock()

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

def enforce_block(ip):
    if ip in WHITELIST_IPS:
        print(f"[⚠️] SAFETY OVERRIDE: {ip} is whitelisted. Ignored.")
        return

    with BAN_LOCK:
        if ip in BANNED_IPS: return
        try:
            cmd = f'netsh advfirewall firewall add rule name="WarSOC_Block_{ip}" dir=in action=block remoteip={ip}'
            subprocess.run(cmd, shell=True, check=True, capture_output=True, text=True)
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
        resp = requests.post(f"{BACKEND_URL}/api/v1/auth/agent-login", 
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
        resp = requests.request(method, url, **kwargs)
        
        if method == "POST" and "ingest" in url and resp.status_code == 200:
             pass # Silently succeed to avoid console spam

        if resp.status_code == 401:
            print("[⚠️] Token expired. Re-authenticating...")
            if authenticate_agent():
                headers["Authorization"] = f"Bearer {JWT_TOKEN}"
                kwargs["headers"] = headers
                resp = requests.request(method, url, **kwargs)
        
        elif resp.status_code != 200:
            print(f"[❌] Backend rejected payload: {resp.status_code}")

        return resp
    except Exception as e:
        print(f"[📡] Connection Error to {url}: {e}")
        return None

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
    print(f"[*] Web Hunter Online. Monitoring file: {WEB_LOG_PATH}")
    ingest_url = f"{BACKEND_URL}/api/v1/ingest/windows" # Sending to same pipeline for now
    
    # Create the file if it doesn't exist so we don't crash
    if not os.path.exists(WEB_LOG_PATH):
        with open(WEB_LOG_PATH, 'w') as f:
            f.write("WarSOC Web Monitoring Initialized...\n")

    with open(WEB_LOG_PATH, "r", encoding="utf-8") as file:
        file.seek(0, 2) # 🚀 Go exactly to the END of the file (Don't read old logs)
        
        while True:
            line = file.readline()
            if not line:
                time.sleep(1) # Wait for new data
                continue
            
            line = line.strip()
            if line:
                print(f"[🌐] Web Event Detected: {line[:50]}...")
                payload = {
                    "agent_id": TENANT_ID,
                    "source_ip": get_local_ip(),
                    "user": "Web-Visitor",
                    "event_id": 80, # Custom ID for Web Logs
                    "message": line,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "raw_data": line,
                    "agent_version": "4.0-Omni"
                }
                secure_request("POST", ingest_url, json=payload, timeout=10)


def log_hunter_thread():
    print(f"[*] Windows Hunter Online. Streaming via Secure Tunnel...")
    ingest_url = f"{BACKEND_URL}/api/v1/ingest/windows"
    log_type = "Security"

    try:
        temp_hand = win32evtlog.OpenEventLog(None, log_type)
        total = win32evtlog.GetNumberOfEventLogRecords(temp_hand)
        oldest = win32evtlog.GetOldestEventLogRecord(temp_hand)
        highest_record_seen = oldest + total - 1
        win32evtlog.CloseEventLog(temp_hand)
        print(f"[*] Synced to Windows Live. Watermark: {highest_record_seen}")
    except Exception as e:
        print(f"[!] Admin privileges required: {e}")
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
                    
                    if event_id in [4720, 4726, 1102, 4624, 4625]:
                        try:
                            msg = win32evtlogutil.SafeFormatMessage(event, log_type)
                            clean_msg = msg.split("\n")[0] if msg else "Raw Data"
                        except: clean_msg = "Format Error"

                        payload = {
                            "agent_id": TENANT_ID,
                            "source_ip": get_local_ip(),
                            "user": resolve_user(event.Sid),
                            "event_id": event_id,
                            "message": f"Event {event_id}: {clean_msg}",
                            "timestamp": event.TimeGenerated.isoformat(),
                            "raw_data": clean_msg,
                            "agent_version": "4.0-Omni"
                        }
                        print(f"[🛡️] Windows Event Streamed: {event_id}")
                        secure_request("POST", ingest_url, json=payload, timeout=10)

                highest_record_seen = current_batch_highest

        except Exception: pass 
        finally:
            if hand: win32evtlog.CloseEventLog(hand)
            
        time.sleep(POLL_INTERVAL)

if __name__ == "__main__":
    print("==========================================")
    print(f"   WarSOC OMNI AGENT v4.0 (Windows + Web)")
    print(f"   Tenant ID: {TENANT_ID}")
    print("==========================================")
    
    authenticate_agent()

    # 🚀 START ALL SENSORS
    threading.Thread(target=heartbeat_thread, daemon=True).start()
    threading.Thread(target=log_hunter_thread, daemon=True).start()
    threading.Thread(target=web_hunter_thread, daemon=True).start() # The new Web Scanner!

    try:
        while True: time.sleep(1)
    except KeyboardInterrupt:
        print("\n🛑 Safe exit.")
        sys.exit(0)