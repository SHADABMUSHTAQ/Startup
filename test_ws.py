import requests
import websocket

BASE = "http://127.0.0.1:8000/api/v1"
session = requests.Session()
r = session.post(f"{BASE}/auth/login", json={"username": "cto_admin", "password": "WarSOCPassword123!"})
token = session.cookies.get("warsoc_token")
print(f"Login: {r.status_code}, token_len={len(token) if token else 0}")

# Try WebSocket with the auth token
ws = websocket.create_connection(
    f"ws://127.0.0.1:8000/ws/WARSOC_DEMO_TENANT",
    timeout=5,
    cookie=f"warsoc_token={token}"
)
print(f"WebSocket connected: {ws.connected}")
ws.close()
