"""
DEFINITIVE AUTH DIAGNOSTIC - Run this to see exactly why the agent is rejected.
Usage: python scripts/test_auth.py
"""
import os
import hmac
import requests
from pathlib import Path
from dotenv import load_dotenv

# Force load the correct .env
_ENV_PATH = Path(__file__).resolve().parent.parent / ".env"
load_dotenv(str(_ENV_PATH), override=True)

TENANT_ID = "WARSOC_88604B18"  # hardcoded — what agent is sending
SECRET_FROM_ENV = os.getenv("AGENT_MASTER_SECRET", "NOT_FOUND")
BACKEND_URL = os.getenv("BACKEND_URL", "http://127.0.0.1:8000").rstrip("/")

print("=" * 55)
print("  WarSOC Agent Auth Diagnostic")
print("=" * 55)
print(f"  .env path:       {_ENV_PATH}")
print(f"  .env exists:     {_ENV_PATH.exists()}")
print(f"  TENANT_ID:       {TENANT_ID}")
print(f"  AGENT_SECRET:    {SECRET_FROM_ENV}")
print(f"  BACKEND_URL:     {BACKEND_URL}")
print("=" * 55)
print()

print("[1] Testing with AGENT_MASTER_SECRET from .env...")
try:
    r = requests.post(
        f"{BACKEND_URL}/api/v1/auth/agent-login",
        json={"agent_id": TENANT_ID, "agent_secret": SECRET_FROM_ENV},
        timeout=5
    )
    print(f"    Status: {r.status_code}")
    print(f"    Response: {r.text[:200]}")
except Exception as e:
    print(f"    ERROR: {e}")

print()
print("[2] Testing with hardcoded master secret...")
HARDCODED = "W4rS0c_Ag3nt_M4st3r_2026!_k7Lp5nBwS1"
try:
    r2 = requests.post(
        f"{BACKEND_URL}/api/v1/auth/agent-login",
        json={"agent_id": TENANT_ID, "agent_secret": HARDCODED},
        timeout=5
    )
    print(f"    Status: {r2.status_code}")
    print(f"    Response: {r2.text[:200]}")
except Exception as e:
    print(f"    ERROR: {e}")

print()
print("[3] Testing with tenant WARSOC_898F3395 (backend .env tenant)...")
try:
    r3 = requests.post(
        f"{BACKEND_URL}/api/v1/auth/agent-login",
        json={"agent_id": "WARSOC_898F3395", "agent_secret": HARDCODED},
        timeout=5
    )
    print(f"    Status: {r3.status_code}")
    print(f"    Response: {r3.text[:200]}")
except Exception as e:
    print(f"    ERROR: {e}")

print()
print("=" * 55)
print("  Which test returned 200? That is your working config.")
print("=" * 55)
