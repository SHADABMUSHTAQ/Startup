#!/usr/bin/env python3
"""
Generate valid JWT agent token and test the REAL security layers
"""

import jwt
import requests
from datetime import datetime, timezone, timedelta

# Secret from .env
AGENT_MASTER_SECRET = "W4rS0c_Ag3nt_M4st3r_2026!_k7Lp5nBwS1"
API_URL = "http://localhost:8000/api/v1/ingest/windows"

# Generate valid JWT agent token
def create_agent_token():
    payload = {
        "sub": "agent_windows_01",
        "type": "agent",
        "iat": datetime.now(timezone.utc),
        "exp": datetime.now(timezone.utc) + timedelta(hours=24)
    }
    token = jwt.encode(payload, AGENT_MASTER_SECRET, algorithm="HS256")
    return token

agent_token = create_agent_token()
print(f"Generated valid agent token:\n{agent_token}\n")

headers_with_token = {
    "Authorization": f"Bearer {agent_token}",
    "Content-Type": "application/json"
}

def test_attack(name, payload, headers=None):
    """Test an attack"""
    if headers is None:
        headers = headers_with_token

    try:
        resp = requests.post(API_URL, json=payload, headers=headers, timeout=5)
        status = resp.status_code
        blocked = status in [400, 403, 413]
        symbol = "BLOCKED" if blocked else "ALLOWED"

        print(f"[{symbol}] {name}: HTTP {status}")
        if resp.text:
            try:
                msg = resp.json().get('detail', resp.text)
            except:
                msg = resp.text[:100]
            print(f"      -> {msg}\n")

        return status
    except Exception as e:
        print(f"[ERROR] {name}: {str(e)}\n")
        return None

print("="*70)
print("LAYER TESTS - WITH VALID JWT TOKEN")
print("="*70)

# TEST 1: Valid log (should pass all layers)
print("\nTEST 1: VALID LOG - Should be ALLOWED")
test_attack(
    "Valid log with valid token",
    [{
        "agent_id": "agent_test",
        "source_ip": "127.0.0.1",
        "user": "system",
        "event_id": 4624,
        "message": "Legitimate log entry",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "raw_data": {},
        "agent_version": "1.0"
    }],
    headers=headers_with_token
)

# TEST 2: Stale timestamp (should get 400)
print("\nTEST 2: STALE TIMESTAMP - Should be BLOCKED with 400")
old_time = (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat()
test_attack(
    "Log from 2 hours ago",
    [{
        "agent_id": "agent_test",
        "source_ip": "127.0.0.1",
        "user": "admin",
        "event_id": 4661,
        "message": "INJECTED: Fake delete from 2 hours ago",
        "timestamp": old_time,
        "raw_data": {},
        "agent_version": "1.0"
    }],
    headers=headers_with_token
)

# TEST 3: Huge payload (should get 413)
print("\nTEST 3: HUGE PAYLOAD - Should be BLOCKED with 413")
huge_msg = "ATTACK" * (600000)  # ~3.6MB
test_attack(
    "3.6MB payload DoS",
    [{
        "agent_id": "agent_test",
        "source_ip": "127.0.0.1",
        "user": "system",
        "event_id": 4624,
        "message": huge_msg,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "raw_data": {},
        "agent_version": "1.0"
    }],
    headers=headers_with_token
)

# TEST 4: Mixed batch with old log
print("\nTEST 4: MIXED BATCH - Should be BLOCKED with 400")
test_attack(
    "Batch with 1 old log hidden in 3 recent",
    [
        {
            "agent_id": "agent_test",
            "source_ip": "127.0.0.1",
            "user": "system",
            "event_id": 4624,
            "message": "Fresh log 1",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "raw_data": {},
            "agent_version": "1.0"
        },
        {
            "agent_id": "agent_test",
            "source_ip": "127.0.0.1",
            "user": "admin",
            "event_id": 4661,
            "message": "SNEAKY: Old malicious log",
            "timestamp": (datetime.now(timezone.utc) - timedelta(minutes=30)).isoformat(),
            "raw_data": {},
            "agent_version": "1.0"
        },
        {
            "agent_id": "agent_test",
            "source_ip": "127.0.0.1",
            "user": "system",
            "event_id": 4624,
            "message": "Fresh log 2",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "raw_data": {},
            "agent_version": "1.0"
        }
    ],
    headers=headers_with_token
)

# TEST 5: Boundary test - exactly 300 seconds old (should pass)
print("\nTEST 5: BOUNDARY TEST - Exactly 300s old - Should be ALLOWED")
boundary_time = (datetime.now(timezone.utc) - timedelta(seconds=299)).isoformat()
test_attack(
    "Log from 299 seconds ago (within limit)",
    [{
        "agent_id": "agent_test",
        "source_ip": "127.0.0.1",
        "user": "system",
        "event_id": 4624,
        "message": "At the boundary",
        "timestamp": boundary_time,
        "raw_data": {},
        "agent_version": "1.0"
    }],
    headers=headers_with_token
)

print("="*70)
print("SUMMARY")
print("="*70)
print("""
Layer 1 (JWT Token):        All tests have valid token - PASSES
Layer 2 (IP Whitelist):     Requests from 127.0.0.1 - PASSES
Layer 3 (Payload Size):     Test 3 with 3.6MB should get 413
Layer 4 (Timestamp):        Tests 2,4 with old logs should get 400
""")
