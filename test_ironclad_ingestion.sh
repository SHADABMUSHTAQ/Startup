#!/bin/bash
# Ironclad Ingestion Test Suite
# Tests all 4 security layers at /api/v1/ingest/windows endpoint

set -e

API_URL="http://localhost:8000/api/v1/ingest"
AGENT_TOKEN="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZ2VudF8xIiwidHlwZSI6ImFnZW50In0.test_token"

echo "========================================================================"
echo "IRONCLAD INGESTION: 4-LAYER SECURITY TEST SUITE"
echo "========================================================================"

# ===== LAYER 1: IP WHITELIST TEST =====
echo ""
echo "[TEST 1] LAYER 1: IP WHITELIST - Valid IP (127.0.0.1)"
echo "Expected: HTTP 200 (or 4xx if token invalid, but NOT 403)"
curl -X POST "$API_URL/windows" \
  -H "Authorization: Bearer $AGENT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '[{
    "agent_id": "agent_test",
    "source_ip": "127.0.0.1",
    "user": "system",
    "event_id": 4624,
    "message": "Test log from valid IP",
    "timestamp": "'$(date -u +'%Y-%m-%dT%H:%M:%SZ')'",
    "raw_data": {},
    "agent_version": "1.0"
  }]' \
  -w "\nHTTP Status: %{http_code}\n" 2>/dev/null || echo "Connection failed (backend not running?)"

echo ""
echo "[TEST 2] LAYER 1: IP WHITELIST - Invalid IP (192.168.1.100)"
echo "Expected: HTTP 403 Forbidden"
curl -X POST "$API_URL/windows" \
  -H "Authorization: Bearer $AGENT_TOKEN" \
  -H "Content-Type: application/json" \
  --header "X-Forwarded-For: 192.168.1.100" \
  -d '[{
    "agent_id": "agent_test",
    "source_ip": "127.0.0.1",
    "user": "system",
    "event_id": 4624,
    "message": "Test log from blocked IP",
    "timestamp": "'$(date -u +'%Y-%m-%dT%H:%M:%SZ')'",
    "raw_data": {},
    "agent_version": "1.0"
  }]' \
  -w "\nHTTP Status: %{http_code}\n" 2>/dev/null || true

# ===== LAYER 2: PAYLOAD SIZE TEST =====
echo ""
echo "[TEST 3] LAYER 2: PAYLOAD SIZE - Valid size (~10KB)"
echo "Expected: HTTP 200 (or 4xx if token invalid, but NOT 413)"
curl -X POST "$API_URL/windows" \
  -H "Authorization: Bearer $AGENT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '[{
    "agent_id": "agent_test",
    "source_ip": "127.0.0.1",
    "user": "system",
    "event_id": 4624,
    "message": "Small valid payload test",
    "timestamp": "'$(date -u +'%Y-%m-%dT%H:%M:%SZ')'",
    "raw_data": {},
    "agent_version": "1.0"
  }]' \
  -w "\nHTTP Status: %{http_code}\n" 2>/dev/null || true

echo ""
echo "[TEST 4] LAYER 2: PAYLOAD SIZE - Oversized payload (>1MB)"
echo "Expected: HTTP 413 Payload Too Large"
# Create oversized payload
python3 << 'PYTHON_SCRIPT'
import json
import requests
from datetime import datetime, timezone

# Generate 2MB payload
large_message = "X" * (2 * 1024 * 1024)
payload = [{
    "agent_id": "agent_test",
    "source_ip": "127.0.0.1",
    "user": "system",
    "event_id": 4624,
    "message": large_message,
    "timestamp": datetime.now(timezone.utc).isoformat(),
    "raw_data": {},
    "agent_version": "1.0"
}]

try:
    response = requests.post(
        "http://localhost:8000/api/v1/ingest/windows",
        json=payload,
        headers={
            "Authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZ2VudF8xIiwidHlwZSI6ImFnZW50In0.test_token",
            "Content-Type": "application/json"
        },
        timeout=5
    )
    print(f"HTTP Status: {response.status_code}")
    print(f"Response: {response.text}")
except Exception as e:
    print(f"Error: {e}")
PYTHON_SCRIPT

# ===== LAYER 3: TIMESTAMP VALIDATION TEST =====
echo ""
echo "[TEST 5] LAYER 3: TIMESTAMP - Recent timestamp (valid)"
echo "Expected: HTTP 200 (or 4xx if token invalid, but NOT 400)"
curl -X POST "$API_URL/windows" \
  -H "Authorization: Bearer $AGENT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '[{
    "agent_id": "agent_test",
    "source_ip": "127.0.0.1",
    "user": "system",
    "event_id": 4624,
    "message": "Fresh log with recent timestamp",
    "timestamp": "'$(date -u +'%Y-%m-%dT%H:%M:%SZ')'",
    "raw_data": {},
    "agent_version": "1.0"
  }]' \
  -w "\nHTTP Status: %{http_code}\n" 2>/dev/null || true

echo ""
echo "[TEST 6] LAYER 3: TIMESTAMP - Old timestamp (>300 seconds)"
echo "Expected: HTTP 400 Bad Request"
OLD_TIMESTAMP=$(date -u -d '10 minutes ago' +'%Y-%m-%dT%H:%M:%SZ')
curl -X POST "$API_URL/windows" \
  -H "Authorization: Bearer $AGENT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '[{
    "agent_id": "agent_test",
    "source_ip": "127.0.0.1",
    "user": "system",
    "event_id": 4624,
    "message": "Stale log from 10 minutes ago",
    "timestamp": "'$OLD_TIMESTAMP'",
    "raw_data": {},
    "agent_version": "1.0"
  }]' \
  -w "\nHTTP Status: %{http_code}\n" 2>/dev/null || true

# ===== LAYER 4: JWT TOKEN TEST =====
echo ""
echo "[TEST 7] LAYER 4: JWT TOKEN - Missing token"
echo "Expected: HTTP 403 Forbidden (missing auth)"
curl -X POST "$API_URL/windows" \
  -H "Content-Type: application/json" \
  -d '[{
    "agent_id": "agent_test",
    "source_ip": "127.0.0.1",
    "user": "system",
    "event_id": 4624,
    "message": "Log without token",
    "timestamp": "'$(date -u +'%Y-%m-%dT%H:%M:%SZ')'",
    "raw_data": {},
    "agent_version": "1.0"
  }]' \
  -w "\nHTTP Status: %{http_code}\n" 2>/dev/null || true

echo ""
echo "[TEST 8] LAYER 4: JWT TOKEN - Invalid token"
echo "Expected: HTTP 403 Forbidden (invalid signature)"
curl -X POST "$API_URL/windows" \
  -H "Authorization: Bearer invalid_token_here" \
  -H "Content-Type: application/json" \
  -d '[{
    "agent_id": "agent_test",
    "source_ip": "127.0.0.1",
    "user": "system",
    "event_id": 4624,
    "message": "Log with bad token",
    "timestamp": "'$(date -u +'%Y-%m-%dT%H:%M:%SZ')'",
    "raw_data": {},
    "agent_version": "1.0"
  }]' \
  -w "\nHTTP Status: %{http_code}\n" 2>/dev/null || true

echo ""
echo "========================================================================"
echo "TEST SUITE COMPLETE"
echo "========================================================================"
echo ""
echo "Summary:"
echo "   TEST 1: Valid IP → Should allow (200 or auth error)"
echo "   TEST 2: Invalid IP → Should block with 403"
echo "   TEST 3: Valid size → Should allow (200 or auth error)"
echo "   TEST 4: Oversized → Should block with 413"
echo "   TEST 5: Recent time → Should allow (200 or auth error)"
echo "   TEST 6: Old time → Should block with 400"
echo "   TEST 7: No token → Should block with 403"
echo "   TEST 8: Bad token → Should block with 403"
echo ""
