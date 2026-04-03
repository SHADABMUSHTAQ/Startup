#!/usr/bin/env python3
"""
Ironclad Ingestion - Real Attack Tests
Tests if the 4-layer defense actually blocks attacks
"""

import requests
import json
from datetime import datetime, timezone, timedelta
import sys

API_URL = "http://localhost:8000/api/v1/ingest/windows"

def test_attack(name, payload, headers=None, expected_code=None):
    """Test an attack"""
    if headers is None:
        headers = {"Content-Type": "application/json"}

    try:
        resp = requests.post(API_URL, json=payload, headers=headers, timeout=5)
        status = resp.status_code

        # Determine if blocked
        blocked = status in [400, 403, 413]

        symbol = "[BLOCKED]" if blocked else "[ALLOWED]"

        print(f"\n{symbol} {name}")
        print(f"    Status: {status}")
        if resp.text:
            try:
                msg = resp.json().get('detail', resp.text)
            except:
                msg = resp.text[:100]
            print(f"    Response: {msg}")

        return status
    except requests.exceptions.ConnectionError:
        print(f"\n[ERROR] {name}")
        print(f"    Backend not running on localhost:8000")
        return None
    except Exception as e:
        print(f"\n[ERROR] {name}: {str(e)}")
        return None

print("="*70)
print("IRONCLAD INGESTION: ATTACK TESTS")
print("="*70)

# Test without any token
print("\n" + "="*70)
print("ATTACK 1: NO TOKEN (Should get 401/403)")
print("="*70)

test_attack(
    "Send log with NO Authorization header",
    [{
        "agent_id": "attacker",
        "source_ip": "127.0.0.1",
        "user": "hacker",
        "event_id": 4624,
        "message": "Injected fake log",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "raw_data": {},
        "agent_version": "1.0"
    }],
    headers={"Content-Type": "application/json"}
)

# Test with invalid token
print("\n" + "="*70)
print("ATTACK 2: INVALID TOKEN (Should get 401/403)")
print("="*70)

test_attack(
    "Send log with FAKE invalid token",
    [{
        "agent_id": "attacker",
        "source_ip": "127.0.0.1",
        "user": "admin",
        "event_id": 4624,
        "message": "Trying to hijack admin account",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "raw_data": {},
        "agent_version": "1.0"
    }],
    headers={
        "Authorization": "Bearer INVALID_FAKE_TOKEN_XYZ123",
        "Content-Type": "application/json"
    }
)

# Test with stale timestamp (5 hours old)
print("\n" + "="*70)
print("ATTACK 3: STALE TIMESTAMP - Log Injection (Should get 400)")
print("="*70)

old_time = (datetime.now(timezone.utc) - timedelta(hours=5)).isoformat()

test_attack(
    "Send log from 5 hours ago (try to hide attack)",
    [{
        "agent_id": "attacker",
        "source_ip": "127.0.0.1",
        "user": "admin",
        "event_id": 4625,
        "message": "INJECTED: Fake failed login from 5 hours ago",
        "timestamp": old_time,
        "raw_data": {},
        "agent_version": "1.0"
    }],
    headers={
        "Authorization": "Bearer invalid_token",
        "Content-Type": "application/json"
    }
)

# Test with massive payload (DoS)
print("\n" + "="*70)
print("ATTACK 4: HUGE PAYLOAD - DoS Attack (Should get 413)")
print("="*70)

huge_msg = "ATTACK" * (500000)  # ~3MB

test_attack(
    "Send 3MB payload to crash backend (DoS)",
    [{
        "agent_id": "attacker",
        "source_ip": "127.0.0.1",
        "user": "system",
        "event_id": 4624,
        "message": huge_msg,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "raw_data": {},
        "agent_version": "1.0"
    }],
    headers={
        "Authorization": "Bearer invalid",
        "Content-Type": "application/json"
    }
)

# Test mixed batch - one stale (sneaky)
print("\n" + "="*70)
print("ATTACK 5: MIXED BATCH - Sneak in old log with new ones (Should get 400)")
print("="*70)

test_attack(
    "Send batch with ONE old log hidden among recent ones",
    [
        {
            "agent_id": "attacker",
            "source_ip": "127.0.0.1",
            "user": "system",
            "event_id": 4624,
            "message": "Legit recent log",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "raw_data": {},
            "agent_version": "1.0"
        },
        {
            "agent_id": "attacker",
            "source_ip": "127.0.0.1",
            "user": "admin",
            "event_id": 4661,
            "message": "SNEAKY: Delete sensitive data (from 30min ago)",
            "timestamp": (datetime.now(timezone.utc) - timedelta(minutes=30)).isoformat(),
            "raw_data": {},
            "agent_version": "1.0"
        },
        {
            "agent_id": "attacker",
            "source_ip": "127.0.0.1",
            "user": "system",
            "event_id": 4624,
            "message": "Another legit recent log",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "raw_data": {},
            "agent_version": "1.0"
        }
    ],
    headers={
        "Authorization": "Bearer invalid",
        "Content-Type": "application/json"
    }
)

print("\n" + "="*70)
print("TEST COMPLETE")
print("="*70)
print("""
Expected Results:
  ATTACK 1: NO TOKEN -> 401/403 (Blocked by JWT layer) [OK]
  ATTACK 2: BAD TOKEN -> 401/403 (Blocked by JWT layer) [OK]
  ATTACK 3: STALE LOG -> 400 (Blocked by Timestamp layer) [OK]
  ATTACK 4: HUGE PAYLOAD -> 413 (Blocked by Size layer) [OK]
  ATTACK 5: MIXED BATCH -> 400 (Blocked by Timestamp layer) [OK]

All attacks should show [BLOCKED] status with 400/401/403/413 codes.
""")
