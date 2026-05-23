import asyncio
import json
import uuid
import time
import httpx
import websockets
import ssl
import sys
import os
import requests
import urllib3

# Suppress InsecureRequestWarning for local self-signed certs
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# ---------------------------------------------------------
# MONKEYPATCH: Disable SSL verification for sync agent requests
# ---------------------------------------------------------
original_request = requests.Session.request
def insecure_request(self, method, url, **kwargs):
    kwargs['verify'] = False
    return original_request(self, method, url, **kwargs)
requests.Session.request = insecure_request

# ---------------------------------------------------------
# PREPARATION: Load Agent Context
# ---------------------------------------------------------
agent_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "agent"))
sys.path.insert(0, agent_dir)
os.chdir(agent_dir)

try:
    import windows_agent
except ImportError as e:
    print(f"FAIL: Could not import windows_agent. {e}")
    if os.getenv("FORCE_CHUNK_RUN") == "1":
        print("FORCE_CHUNK_RUN=1 set — continuing despite import error for local stress run.")
    else:
        sys.exit(1)

if not os.getenv("FORCE_CHUNK_RUN") == "1":
    if not windows_agent.authenticate_agent():
        print("FAIL: Agent could not authenticate with the backend.")
        sys.exit(1)
else:
    print("FORCE_CHUNK_RUN=1 set — skipping agent authentication check for local stress run.")

AGENT_TOKEN = windows_agent.JWT_TOKEN
TENANT_ID = windows_agent.TENANT_ID
AGENT_ID = windows_agent.AGENT_ID

os.chdir("..")

# ---------------------------------------------------------
# CHUNK 2: The Glass Latency Test
# ---------------------------------------------------------
async def run_latency_test():
    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE

    async with httpx.AsyncClient(verify=False, timeout=10.0) as client:
        print("[*] Stage 1: Authenticating as Analyst...")
        login_resp = await client.post("https://localhost/api/v1/auth/login", json={
            "username": "admin@warsoc.com",
            "password": "password"
        })
        if login_resp.status_code != 200:
            print(f"FAIL: Analyst login failed. Status {login_resp.status_code}")
            return
        
        user_token = login_resp.cookies.get("warsoc_token")
        if not user_token:
            print("FAIL: No HttpOnly token cookie found.")
            return

        print("[*] Stage 2: Requesting WebSocket Access Ticket...")
        ticket_resp = await client.post("https://localhost/api/v1/ws/ticket", headers={
            "Authorization": f"Bearer {user_token}"
        })
        if ticket_resp.status_code != 200:
            print(f"FAIL: Failed to provision WS ticket. {ticket_resp.text}")
            return
            
        ticket = ticket_resp.json()["ticket"]
        
        print("[*] Stage 3: Forging Cryptographically Valid Payload...")
        event_uid = str(uuid.uuid4())
        raw_payload = {
            "agent_id": AGENT_ID,
            "source_ip": "10.0.0.99",
            "user": "SystemAdmin",
            "event_id": 4625,
            "event_uid": event_uid,
            "message": "Latency Benchmark Event",
            "timestamp": __import__('datetime').datetime.now(__import__('datetime').timezone.utc).isoformat(),
            "raw_data": {"raw": "Nuclear Latency Test"},
            "processed_data": {},
            "agent_version": "4.0-Omni"
        }
        
        from agent.windows_agent import _sign_event_payload, _estimate_payload_bytes, SigningKey, PRIVATE_KEY_PATH, NIST256p, os
        
        # Load the signing key directly to pass it to the signer
        with open(PRIVATE_KEY_PATH, "r") as f:
            signing_key = SigningKey.from_pem(f.read(), hashfunc=__import__('hashlib').sha256)

        # Strip processed_data if empty to match agent behavior
        if not raw_payload.get("processed_data"):
            raw_payload.pop("processed_data", None)
            
        _sign_event_payload(raw_payload, signing_key)
        
        ws_url = f"wss://localhost/ws/alerts?ticket={ticket}"
        print(f"[*] Stage 4: Opening WebSocket to {ws_url}")
        
        try:
            async with websockets.connect(ws_url, ssl=ssl_context) as websocket:
                print("[*] WebSocket Connected. Arming Listener...")
                
                loop = asyncio.get_running_loop()
                message_received = loop.create_future()
                
                async def listen():
                    try:
                        while True:
                            msg = await websocket.recv()
                            data = json.loads(msg)
                            
                            # Inspect the parsed message
                            print(f"[WS] Received message type: {type(data)}")
                            if isinstance(data, dict):
                                # If it's a single alert
                                alerts = [data]
                            elif isinstance(data, list):
                                alerts = data
                                
                            for alert in alerts:
                                print(f"[WS] Alert event_uid: {alert.get('event_uid')}")
                                if alert.get("event_uid") == event_uid:
                                    message_received.set_result(time.perf_counter())
                                    return
                    except websockets.exceptions.ConnectionClosed as e:
                        print(f"WebSocket closed by server: {e}")
                        if not message_received.done():
                            message_received.set_exception(e)
                    except Exception as e:
                        print(f"WebSocket listener exception: {e}")
                        if not message_received.done():
                            message_received.set_exception(e)

                listen_task = asyncio.create_task(listen())
                
                print("[*] Stage 5: Firing HTTP POST to Nginx/Uvicorn Gateway...")
                
                # Critical Millisecond Timer Starts EXACTLY at Network Egress
                start_time = time.perf_counter()
                
                import copy
                safe_payload = copy.deepcopy(raw_payload)
                # Ensure the signature is a string
                if not isinstance(safe_payload.get("agent_signature"), str):
                    safe_payload["agent_signature"] = safe_payload["agent_signature"].hex()
                    
                print(f"[*] Payload keys: {safe_payload.keys()}")
                
                ingest_resp = await client.post("https://localhost/api/v1/ingest/pulse", headers={
                    "Authorization": f"Bearer {AGENT_TOKEN}",
                    "Content-Type": "application/json"
                }, json=[safe_payload])
                
                if ingest_resp.status_code != 200:
                    print(f"FAIL: Ingestion rejected. {ingest_resp.text}")
                    listen_task.cancel()
                    return
                
                print("[*] Payload Accepted. Awaiting Glass Delivery...")
                
                try:
                    end_time = await asyncio.wait_for(message_received, timeout=10.0)
                except asyncio.TimeoutError:
                    print("FAIL: WebSocket message not received within 10 seconds.")
                    return
                
                latency_ms = (end_time - start_time) * 1000
                print(f"\n==================================================")
                print(f"               LATENCY DAMAGE REPORT                ")
                print(f"==================================================")
                print(f"Event UID: {event_uid}")
                print(f"End-to-End Latency: {latency_ms:.2f} ms")
                print(f"==================================================")
                
                if latency_ms < 500:
                    print(f"✅ PASS: Latency is strictly < 500ms. Pipeline is real-time.")
                else:
                    print(f"❌ FAIL: Latency is >= 500ms. Pipeline is too slow.")
                
        except Exception as e:
            print(f"FAIL: WebSocket connection error: {e}")

if __name__ == "__main__":
    asyncio.run(run_latency_test())
