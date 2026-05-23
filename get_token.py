import requests
import sys

BASE_URL = "http://127.0.0.1:8000/api/v1"
session = requests.Session()

# 1. Login
login_payload = {"username": "admin@warsoc.com", "password": "password"}
resp = session.post(f"{BASE_URL}/auth/login", json=login_payload)
if resp.status_code != 200:
    print("Login failed")
    sys.exit(1)

cookie = session.cookies.get("warsoc_token")
headers = {"Authorization": f"Bearer {cookie}"} if cookie else {}

# 2. Get Provisioning Token
prov_resp = session.post(f"{BASE_URL}/auth/agents/generate-token", headers=headers, json={"agent_id": "VM-STRIKE-01"})
token = prov_resp.json()["provisioning_token"]
print(token)
