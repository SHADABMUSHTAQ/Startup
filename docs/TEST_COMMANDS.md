# IRONCLAD INGESTION: Direct Test Commands

## Prerequisites
Make sure the backend is running:
```bash
docker-compose up -d
```

---

## TEST 1: Valid Request (Should Get 200 or Auth Error, NOT 403)

```bash
curl -X POST http://localhost:8000/api/v1/ingest/windows \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZ2VudF8xIiwidHlwZSI6ImFnZW50In0.test_token" \
  -H "Content-Type: application/json" \
  -d '[{
    "agent_id": "agent_test",
    "source_ip": "127.0.0.1",
    "user": "system",
    "event_id": 4624,
    "message": "Valid log from whitelisted IP",
    "timestamp": "'$(date -u +'%Y-%m-%dT%H:%M:%SZ')'",
    "raw_data": {},
    "agent_version": "1.0"
  }]' \
  -w "\n\nHTTP Status: %{http_code}\n"
```

**Expected**:
- HTTP 200 (if token valid and DB/Redis up)
- HTTP 500 (if backend services down, not a security issue)
- NOT HTTP 403 (security layer didn't reject)

---

## TEST 2: IP Whitelist - Invalid IP (Should Get HTTP 403)

**Python Script** (easier to control client IP):

```python
import requests
from datetime import datetime, timezone

payload = [{
    "agent_id": "agent_test",
    "source_ip": "127.0.0.1",
    "user": "system",
    "event_id": 4624,
    "message": "Test from blocked IP",
    "timestamp": datetime.now(timezone.utc).isoformat(),
    "raw_data": {},
    "agent_version": "1.0"
}]

# Simulate request from unauthorized IP 192.168.1.100
# Note: In real scenario, this would be the actual source IP in request.client.host
try:
    response = requests.post(
        "http://localhost:8000/api/v1/ingest/windows",
        json=payload,
        headers={
            "Authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZ2VudF8xIiwidHlwZSI6ImFnZW50In0.test_token"
        }
    )
    print(f"Status: {response.status_code}")
    print(f"Response: {response.text}")
except Exception as e:
    print(f"Error: {e}")
```

**Expected**: HTTP 403 (if request comes from unauthorized IP)

---

## TEST 3: Payload Size - Oversized Payload (Should Get HTTP 413)

```python
import requests
from datetime import datetime, timezone

# Create 2MB payload
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

response = requests.post(
    "http://localhost:8000/api/v1/ingest/windows",
    json=payload,
    headers={
        "Authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZ2VudF8xIiwidHlwZSI6ImFnZW50In0.test_token"
    }
)
print(f"Status: {response.status_code}")  # Should be 413
print(f"Response: {response.text}")
```

**Expected**: HTTP 413 Payload Too Large

---

## TEST 4: Timestamp - Stale Log (Should Get HTTP 400)

```bash
# Create timestamp from 10 minutes ago
OLD_TIMESTAMP=$(date -u -d '10 minutes ago' +'%Y-%m-%dT%H:%M:%SZ')

curl -X POST http://localhost:8000/api/v1/ingest/windows \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZ2VudF8xIiwidHlwZSI6ImFnZW50In0.test_token" \
  -H "Content-Type: application/json" \
  -d '[{
    "agent_id": "agent_test",
    "source_ip": "127.0.0.1",
    "user": "system",
    "event_id": 4624,
    "message": "Old log from 10 minutes ago",
    "timestamp": "'$OLD_TIMESTAMP'",
    "raw_data": {},
    "agent_version": "1.0"
  }]' \
  -w "\n\nHTTP Status: %{http_code}\n"
```

**Expected**: HTTP 400 Bad Request (timestamp is too old)

---

## TEST 5: JWT Token - Missing Authorization (Should Get HTTP 403)

```bash
curl -X POST http://localhost:8000/api/v1/ingest/windows \
  -H "Content-Type: application/json" \
  -d '[{
    "agent_id": "agent_test",
    "source_ip": "127.0.0.1",
    "user": "system",
    "event_id": 4624,
    "message": "No token provided",
    "timestamp": "'$(date -u +'%Y-%m-%dT%H:%M:%SZ')'",
    "raw_data": {},
    "agent_version": "1.0"
  }]' \
  -w "\n\nHTTP Status: %{http_code}\n"
```

**Expected**: HTTP 403 Forbidden (missing auth header)

---

## TEST 6: JWT Token - Invalid Token (Should Get HTTP 403)

```bash
curl -X POST http://localhost:8000/api/v1/ingest/windows \
  -H "Authorization: Bearer invalid_token_xyz_123" \
  -H "Content-Type: application/json" \
  -d '[{
    "agent_id": "agent_test",
    "source_ip": "127.0.0.1",
    "user": "system",
    "event_id": 4624,
    "message": "Bad token",
    "timestamp": "'$(date -u +'%Y-%m-%dT%H:%M:%SZ')'",
    "raw_data": {},
    "agent_version": "1.0"
  }]' \
  -w "\n\nHTTP Status: %{http_code}\n"
```

**Expected**: HTTP 403 Forbidden (invalid token signature)

---

## TEST 7: Batch Ingestion - Multiple Valid Logs (Should Get 200)

```bash
curl -X POST http://localhost:8000/api/v1/ingest/windows \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZ2VudF8xIiwidHlwZSI6ImFnZW50In0.test_token" \
  -H "Content-Type: application/json" \
  -d '[
    {
      "agent_id": "agent_test",
      "source_ip": "127.0.0.1",
      "user": "system",
      "event_id": 4624,
      "message": "Log 1 - Login attempt",
      "timestamp": "'$(date -u +'%Y-%m-%dT%H:%M:%SZ')'",
      "raw_data": {},
      "agent_version": "1.0"
    },
    {
      "agent_id": "agent_test",
      "source_ip": "127.0.0.1",
      "user": "admin",
      "event_id": 4688,
      "message": "Log 2 - Process creation",
      "timestamp": "'$(date -u +'%Y-%m-%dT%H:%M:%SZ')'",
      "raw_data": {},
      "agent_version": "1.0"
    }
  ]' \
  -w "\n\nHTTP Status: %{http_code}\n"
```

**Expected**: HTTP 200 OK

---

## TEST 8: Batch with Mixed Timestamps (Should Get HTTP 400)

```python
import requests
from datetime import datetime, timezone, timedelta

# Batch: Log 1 fresh, Log 2 stale
payload = [
    {
        "agent_id": "agent_test",
        "source_ip": "127.0.0.1",
        "user": "system",
        "event_id": 4624,
        "message": "Fresh log",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "raw_data": {},
        "agent_version": "1.0"
    },
    {
        "agent_id": "agent_test",
        "source_ip": "127.0.0.1",
        "user": "system",
        "event_id": 4624,
        "message": "Stale log from 20 minutes ago",
        "timestamp": (datetime.now(timezone.utc) - timedelta(minutes=20)).isoformat(),
        "raw_data": {},
        "agent_version": "1.0"
    }
]

response = requests.post(
    "http://localhost:8000/api/v1/ingest/windows",
    json=payload,
    headers={
        "Authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZ2VudF8xIiwidHlwZSI6ImFnZW50In0.test_token"
    }
)
print(f"Status: {response.status_code}")  # Should be 400
print(f"Response: {response.text}")
```

**Expected**: HTTP 400 Bad Request (one of the logs in batch is too old)

---

## Quick Test Script (Python)

```bash
python3 test_ironclad_ingestion_py.py
```

This runs all 8 tests automatically and shows results.

---

## Expected Behavior Summary

| Test | Security Layer | Expected Status | Why |
|------|---|---|---|
| 1 | All layers | 200 | Passes all checks |
| 2 | IP Whitelist | 403 | IP not in allowed_ips |
| 3 | Payload Size | 413 | Content-Length > 1MB |
| 4 | Timestamp | 400 | Timestamp older than 300s |
| 5 | JWT Token | 403 | Missing auth header |
| 6 | JWT Token | 403 | Invalid token signature |
| 7 | All layers | 200 | Valid batch of logs |
| 8 | Timestamp | 400 | One log in batch too old |

---

## Configuration File

To adjust limits, edit `app/config/config.json` (lines 115-122):

```json
"agent_security": {
  "enforce_ip_whitelist": true,
  "enforce_payload_size": true,
  "enforce_timestamp_validation": true,
  "allowed_ips": ["127.0.0.1", "localhost", "172.18.0.1", "172.18.0.0/12"],
  "max_payload_bytes": 1048576,
  "max_log_age_seconds": 300
}
```

- Set `enforce_*: false` to disable a layer
- Adjust `max_payload_bytes` for larger batches (default 1MB)
- Adjust `max_log_age_seconds` if agents have clock skew (default 300s = 5 min)
