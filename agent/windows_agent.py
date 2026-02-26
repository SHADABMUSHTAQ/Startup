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
import threading
from datetime import datetime
# 🔐 ENV COMPLIANCE: Import decouple or python-dotenv if you use them, 
# otherwise use standard os.environ
from dotenv import load_dotenv, find_dotenv
import os

# ==========================================
# 1. ENTERPRISE CONFIG & STATE
# ==========================================
# 🔐 SURGICAL FIX: Automatically hunt down the .env file and override system cache
env_path = find_dotenv()
print(f"[🛡️] ARCHITECT OVERRIDE: Loading .env from -> {env_path}")
load_dotenv(env_path, override=True)

TENANT_ID = os.getenv("TENANT_ID")
if not TENANT_ID:
    print("[❌] FATAL: TENANT_ID is still empty. Check your .env file!")
    sys.exit(1)

BACKEND_URL = os.getenv("BACKEND_URL", "http://127.0.0.1:8000").rstrip('/')
AGENT_SECRET = os.getenv("AGENT_SECRET", "warsoc_enterprise_agent_key_2026")

WHITELIST_IPS = set(["127.0.0.1", "localhost", "::1", "0.0.0.0"])
POLL_INTERVAL = 1  
HEARTBEAT_INTERVAL = 5

JWT_TOKEN = None
BANNED_IPS = set()
BAN_LOCK = threading.Lock()

# ==========================================
# 2. HELPER FUNCTIONS & MITIGATION (UNTOUCHED)
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
        # 🚨 SURGICAL FIX: Aligned with your auth route requirements
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
        
        if method == "POST" and "windows" in url and resp.status_code == 200:
             print(f"[🚀] Streamed Event to Backbone!")

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
# 4. THREADS (REMAIN AS PROVIDED)
# ==========================================
def heartbeat_thread():
    heartbeat_url = f"{BACKEND_URL}/api/v1/agent/heartbeat/{TENANT_ID}"
    while True:
        resp = secure_request("GET", heartbeat_url, timeout=3)
        if resp and resp.status_code == 200:
            data = resp.json()
            for bad_ip in data.get("enforce_bans", []):
                enforce_block(bad_ip)
        time.sleep(HEARTBEAT_INTERVAL)

def log_hunter_thread():
    print(f"[*] Log Hunter Online. Streaming via Secure Tunnel...")
    ingest_url = f"{BACKEND_URL}/api/v1/ingest/windows"
    log_type = "Security"

    try:
        temp_hand = win32evtlog.OpenEventLog(None, log_type)
        total = win32evtlog.GetNumberOfEventLogRecords(temp_hand)
        oldest = win32evtlog.GetOldestEventLogRecord(temp_hand)
        highest_record_seen = oldest + total - 1
        win32evtlog.CloseEventLog(temp_hand)
        print(f"[*] Synced to Live. Watermark: {highest_record_seen}")
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
                            "agent_version": "3.3-Enterprise"
                        }
                        secure_request("POST", ingest_url, json=payload, timeout=10)

                highest_record_seen = current_batch_highest

        except Exception: pass 
        finally:
            if hand: win32evtlog.CloseEventLog(hand)
            
        time.sleep(POLL_INTERVAL)

if __name__ == "__main__":
    print("==========================================")
    print(f"   WarSOC EDR AGENT v4.0 (SECURE VAULT)")
    print(f"   Tenant ID: {TENANT_ID}")
    print("==========================================")
    
    authenticate_agent()

    threading.Thread(target=heartbeat_thread, daemon=True).start()
    threading.Thread(target=log_hunter_thread, daemon=True).start()

    try:
        while True: time.sleep(1)
    except KeyboardInterrupt:
        print("\n🛑 Safe exit.")
        sys.exit(0)