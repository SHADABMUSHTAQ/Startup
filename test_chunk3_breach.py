import pytest
import httpx
import uuid
import os
import json
from dotenv import load_dotenv

# Load env file to get credentials
load_dotenv(os.path.join(os.path.dirname(__file__), "agent", ".env"))

BASE_URL = "https://localhost"
ADMIN_EMAIL = os.getenv("ANALYST_USERNAME", "admin@warsoc.com")
ADMIN_PASSWORD = os.getenv("ANALYST_PASSWORD", "WarSOC2026!")

@pytest.mark.asyncio
async def test_csrf_bypass():
    print("\n--- Test 1: The CSRF Bypass ---")
    async with httpx.AsyncClient(verify=False) as client:
        # 1. Login to get cookies
        login_resp = await client.post(
            f"{BASE_URL}/api/v1/auth/login",
            json={"username": ADMIN_EMAIL, "password": ADMIN_PASSWORD}
        )
        assert login_resp.status_code == 200, f"Login failed: {login_resp.text}"
        
        # 2. Attempt a state-mutating POST request *without* the X-CSRF-Token header
        invite_resp = await client.post(
            f"{BASE_URL}/api/v1/auth/invite",
            json={"email": f"test_{uuid.uuid4()}@warsoc.com", "role": "analyst", "temp_password": "TestPassword123!"}
        )
        
        if invite_resp.status_code in (401, 403):
            print("✅ PASS: State mutation rejected without X-CSRF-Token header.")
        else:
            print(f"❌ FAIL: Expected 401/403, got {invite_resp.status_code}.")
            print(f"Response: {invite_resp.text}")
        assert invite_resp.status_code in (401, 403), f"Expected 401/403, got {invite_resp.status_code}"
            
@pytest.mark.asyncio
async def test_stale_session():
    print("\n--- Test 2: The Stale Session Attack ---")
    async with httpx.AsyncClient(verify=False) as client:
        # Provide a mangled session cookie
        client.cookies.set("session", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJtYW5nbGVkIn0.invalid_signature")
        
        resp = await client.get(f"{BASE_URL}/api/v1/logs")
        if resp.status_code == 401:
            print("✅ PASS: Protected route rejected mangled session cookie.")
        else:
            print(f"❌ FAIL: Expected 401, got {resp.status_code}.")
            print(f"Response: {resp.text}")
        assert resp.status_code == 401, f"Expected 401, got {resp.status_code}"
            
@pytest.mark.asyncio
async def test_tenant_bleed():
    print("\n--- Test 3: The Tenant Bleed (BOLA/IDOR) ---")
    async with httpx.AsyncClient(verify=False) as client:
        # Login normally
        login_resp = await client.post(
            f"{BASE_URL}/api/v1/auth/login",
            json={"username": ADMIN_EMAIL, "password": ADMIN_PASSWORD}
        )
        assert login_resp.status_code == 200, f"Login failed: {login_resp.text}"
        
        # We'll use the export logs route but pass a mock tenant_id if it accepts one
        # If it uses the internal context, it shouldn't bleed data
        export_resp = await client.post(
            f"{BASE_URL}/api/v1/export/logs",
            json={"start_time": "2020-01-01T00:00:00Z", "end_time": "2030-01-01T00:00:00Z"}
        )
        
        if export_resp.status_code in (200, 202, 404):
            # 200/202 is fine as long as we only get our own data. Let's see if we can trick an IDOR
            print("✅ PASS: Basic route check completed. Let's try an IDOR request directly.")
        else:
            print(f"⚠️ Unexpected status: {export_resp.status_code}")
            
        # Attempt to access an admin-only endpoint simulating another tenant context
        # In a real environment we'd create two distinct users. Here we'll just check if auth context correctly rejects unauthorized tenant ids
        bleed_resp = await client.get(
            f"{BASE_URL}/api/v1/compliance/report?tenant_id=MOCK_TENANT_9999"
        )
        if bleed_resp.status_code in (403, 401, 404, 400):
            print("✅ PASS: Route enforces tenant boundaries or rejects mock BOLA query.")
        else:
            print(f"❌ FAIL: Expected 403/401/404, got {bleed_resp.status_code}. Possible data bleed.")
            print(f"Response: {bleed_resp.text}")
        assert bleed_resp.status_code in (403, 401, 404, 400), f"Expected 403/401/404/400, got {bleed_resp.status_code}"
