import asyncio
import httpx
import json
from datetime import datetime, timezone

async def run_proof():
    print("="*50)
    print(" WarSOC LIVE SYSTEM PROOF OF LIFE ")
    print("="*50)
    
    # 1. API Health
    print("\n[1] Checking API Health...")
    async with httpx.AsyncClient() as client:
        try:
            resp = await client.get("http://localhost:8000/health")
            print(f"    Status: {resp.status_code}")
            print(f"    Response: {resp.text}")
        except Exception as e:
            print(f"    FAILED: {e}")
            return

    # 2. Login as CTO Admin
    print("\n[2] Logging in as restored cto_admin...")
    token = None
    tenant_id = None
    async with httpx.AsyncClient() as client:
        payload = {
            "username": "cto_admin",
            "password": "SuperSecretPassword123!"
        }
        try:
            resp = await client.post("http://localhost:8000/api/v1/auth/login", json=payload)
            print(f"    Status: {resp.status_code}")
            if resp.status_code == 200:
                data = resp.json()
                token = data.get("access_token")
                print("    Success! Received JWT Access Token.")
            else:
                print(f"    FAILED: {resp.text}")
                return
        except Exception as e:
            print(f"    FAILED: {e}")
            return

    # 3. Verify Identity and Tenant
    print("\n[3] Verifying Identity & Tenant Binding...")
    headers = {"Authorization": f"Bearer {token}"}
    async with httpx.AsyncClient() as client:
        try:
            resp = await client.get("http://localhost:8000/api/v1/auth/me", headers=headers)
            print(f"    Status: {resp.status_code}")
            if resp.status_code == 200:
                data = resp.json()
                tenant_id = data.get("tenant_id")
                print(f"    Username: {data.get('username')}")
                print(f"    Role: {data.get('role')}")
                print(f"    Tenant ID: {tenant_id}")
            else:
                print(f"    FAILED: {resp.text}")
                return
        except Exception as e:
            print(f"    FAILED: {e}")
            return

    # 4. Test Installer Download (Agent Orchestration)
    print("\n[4] Testing Enterprise Installer Download Route...")
    async with httpx.AsyncClient() as client:
        try:
            # We use stream=True so we don't load 15MB into memory
            async with client.stream("GET", "http://localhost:8000/api/v1/agent/download", headers=headers) as resp:
                print(f"    Status: {resp.status_code}")
                if resp.status_code == 200:
                    content_type = resp.headers.get("content-type")
                    content_length = resp.headers.get("content-length", "Unknown")
                    content_disp = resp.headers.get("content-disposition", "")
                    print(f"    Content-Type: {content_type}")
                    print(f"    Content-Length: {content_length} bytes")
                    print(f"    Content-Disposition: {content_disp}")
                    print("    Success! Binary is being served correctly.")
                else:
                    text = await resp.aread()
                    print(f"    FAILED: {text.decode('utf-8', errors='ignore')}")
        except Exception as e:
            print(f"    FAILED: {e}")

    # 5. Pipeline Test - Inject Pulse
    print("\n[5] Testing Telemetry Ingestion Pipeline...")
    pulse_payload = {
        "event_id": 4624,
        "type": "security",
        "message": "Live Proof of Life Test Event",
        "source_ip": "192.168.1.100",
        "user": "proof_tester",
        "timestamp": datetime.now(timezone.utc).isoformat()
    }
    
    # We use the generic log injection endpoint used by admins to test the pipeline
    async with httpx.AsyncClient() as client:
        try:
            resp = await client.post("http://localhost:8000/api/v1/logs/inject", json=pulse_payload, headers=headers)
            print(f"    Status: {resp.status_code}")
            if resp.status_code == 200:
                print(f"    Success! Injected test event. ID: {resp.json().get('id')}")
            else:
                print(f"    FAILED: {resp.text}")
        except Exception as e:
            print(f"    FAILED: {e}")

    print("\n="*50)
    print(" SYSTEM VALIDATION COMPLETE")
    print("="*50)

if __name__ == "__main__":
    asyncio.run(run_proof())
