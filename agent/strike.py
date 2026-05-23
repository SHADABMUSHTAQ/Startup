import os
import time
import requests
import uuid
import sys
from datetime import datetime, timezone

BASE_URL = "http://127.0.0.1:8000/api/v1"
session = requests.Session()

def setup_and_fire():
    # 1. Login / Signup
    username = os.getenv("WARSOC_STRIKE_ADMIN_USERNAME")
    password = os.getenv("WARSOC_STRIKE_ADMIN_PASSWORD")
    if not username or not password:
        print("Set WARSOC_STRIKE_ADMIN_USERNAME and WARSOC_STRIKE_ADMIN_PASSWORD before running this local simulation.")
        sys.exit(1)

    login_payload = {"username": username, "password": password}
    resp = session.post(f"{BASE_URL}/auth/login", json=login_payload)
    if resp.status_code != 200:
        print("Failed to login")
        sys.exit(1)
    
    cookie = session.cookies.get("warsoc_token")
    headers = {"Authorization": f"Bearer {cookie}"} if cookie else {}

    # 2. Get Provisioning Token
    prov_resp = session.post(f"{BASE_URL}/auth/agents/generate-token", headers=headers, json={"agent_id": "VM-STRIKE-01"})
    if prov_resp.status_code != 200:
        print("Failed to get token:", prov_resp.text)
        sys.exit(1)
    
    token = prov_resp.json()["provisioning_token"]

    # 3. Configure Env
    with open(".env.strike", "w") as f:
        f.write("TENANT_ID=WARSOC_DEFAULT\nAGENT_ID=VM-STRIKE-01\nBACKEND_URL=http://127.0.0.1:8000\n")

    print("[*] Local simulation environment configured in .env.strike without embedding the enrollment token.")

    # 4. Inject into Agent
    import threading
    import windows_agent

    windows_agent.AGENT_ID = "VM-STRIKE-01"
    windows_agent.ENROLLMENT_TOKEN = token

    if not windows_agent.authenticate_agent():
        print("[-] Agent failed to authenticate")
        sys.exit(1)

    print("[*] Agent authenticated. Simulating 30 concurrent failed RDP attempts (Event ID 4625)...")

    for i in range(1, 31):
        timestamp = datetime.now(timezone.utc).isoformat()
        raw_msg = f"Event ID: 4625. Account Name: SYSTEM. Account Name: Administrator. Source Network Address: 10.0.0.{i}. Logon Type: 3."
        
        payload = {
            "agent_id": windows_agent.AGENT_ID,
            "source_ip": f"10.0.0.{i}",
            "user": "Administrator",
            "event_id": 4625,
            "event_uid": uuid.uuid4().hex,
            "message": raw_msg,
            "timestamp": timestamp,
            "raw_data": {"raw": raw_msg},
            "raw_event_data": raw_msg,
            "processed_data": {
                "target_user": "Administrator",
                "source_network_address": f"10.0.0.{i}",
                "logon_type": 3
            },
            "agent_version": "4.0-Omni"
        }
        
        windows_agent._sign_event_payload(payload, windows_agent._load_or_create_signing_key())
        windows_agent.enqueue_payload(payload)

    print("[*] 30 events queued in spooler. Launching transmission thread...")
    t = threading.Thread(target=windows_agent.ingest_sender_thread, daemon=True)
    t.start()

    time.sleep(5)
    print("[+] Strike Complete. 30 payloads delivered.")

if __name__ == "__main__":
    setup_and_fire()
