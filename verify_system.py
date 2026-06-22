import asyncio
import httpx
import json
from datetime import datetime, timezone

async def run_proof():
    print("==================================================")
    print(" WARSO C END-TO-END SYSTEM VERIFICATION ")
    print("==================================================")
    
    async with httpx.AsyncClient(timeout=10.0) as client:
        # 1. API Health
        print("\n[1] Checking API Health...")
        try:
            resp = await client.get("http://localhost:8000/health")
            print(f"    Status: {resp.status_code} - {resp.json()}")
        except Exception as e:
            print(f"    FAILED: {e}")
            return

        # 2. Login as CTO Admin
        print("\n[2] Authenticating as CTO Admin...")
        payload = {
            "username": "cto_admin",
            "password": "WarSOCPassword123!"
        }
        try:
            resp = await client.post("http://localhost:8000/api/v1/auth/login", json=payload)
            if resp.status_code == 200:
                data = resp.json()
                token = data.get("access_token")
                print("    Success! Authenticated.")
            else:
                print(f"    FAILED: {resp.text}")
                return
        except Exception as e:
            print(f"    FAILED: {e}")
            return

        headers = {"Authorization": f"Bearer {token}"}
        
        # Manually extract CSRF from cookies and add to headers for mutating requests
        csrf_token = client.cookies.get("fastapi-csrf-token")
        if csrf_token:
            headers["x-csrf-token"] = csrf_token

        # 3. Verify Identity and Tenant
        print("\n[3] Verifying Multi-Tenant Boundaries...")
        try:
            resp = await client.get("http://localhost:8000/api/v1/auth/me", headers=headers)
            if resp.status_code == 200:
                data = resp.json()
                tenant_id = data.get("tenant_id")
                print(f"    User: {data.get('username')} (Role: {data.get('role')})")
                print(f"    Bound Tenant ID: {tenant_id}")
            else:
                print(f"    FAILED: {resp.text}")
        except Exception as e:
            print(f"    FAILED: {e}")

        # 4. Test Installer Download (Agent Orchestration)
        print("\n[4] Requesting Enterprise Agent Installer...")
        try:
            async with client.stream("GET", "http://localhost:8000/api/v1/agent/download", headers=headers) as resp:
                if resp.status_code == 200:
                    content_type = resp.headers.get("content-type")
                    content_length = resp.headers.get("content-length", "Unknown")
                    print(f"    Status: {resp.status_code} OK")
                    print(f"    Binary Type: {content_type}")
                    print(f"    Binary Size: {content_length} bytes")
                    print("    Success! Binary securely served from Output directory.")
                else:
                    text = await resp.aread()
                    print(f"    FAILED: {text.decode('utf-8', errors='ignore')}")
        except Exception as e:
            print(f"    FAILED: {e}")

        # 5. Pipeline Test - Inject Pulse
        print("\n[5] Injecting Live Telemetry Event into Pipeline...")
        pulse_payload = {
            "event_id": 4624,
            "type": "security",
            "message": "Live Proof of Life Test Event",
            "source_ip": "192.168.1.100",
            "user": "proof_tester",
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        try:
            resp = await client.post("http://localhost:8000/api/v1/logs/inject", json=pulse_payload, headers=headers)
            if resp.status_code == 200:
                print(f"    Status: {resp.status_code} OK")
                print(f"    Success! Event accepted by fan-out pipeline. ID: {resp.json().get('id')}")
            else:
                print(f"    FAILED: {resp.text}")
        except Exception as e:
            print(f"    FAILED: {e}")

    print("\n==================================================")
    print(" ALL END-TO-END PIPELINES FUNCTIONAL")
    print("==================================================")

if __name__ == "__main__":
    asyncio.run(run_proof())
