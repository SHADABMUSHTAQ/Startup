import requests
import json

try:
    r = requests.post('http://127.0.0.1:8000/api/v1/auth/agent-login', json={'agent_id': 'WARSOC_98F626B8', 'timestamp': '2026-06-02T10:00:00Z', 'nonce': '1234567890123456', 'signature': 'dummy'}, timeout=5)
    print(f"STATUS: {r.status_code}")
    print(f"TEXT: {r.text}")
except Exception as e:
    print(f"ERROR: {e}")
