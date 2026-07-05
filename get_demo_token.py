import requests
import sys

BASE_URL = "http://127.0.0.1:8000/api/v1"
session = requests.Session()

login_payload = {"username": "cto_admin", "password": "WarSOCPassword123!"}
resp = session.post(f"{BASE_URL}/auth/login", json=login_payload)
if resp.status_code != 200:
    print(f"Login failed: {resp.text}")
    sys.exit(1)

csrf_token = session.cookies.get("csrf_token")
headers = {"X-CSRF-Token": csrf_token}

prov_resp = session.post(f"{BASE_URL}/agent/generate-activation", headers=headers)
print(f"Activation Output: {prov_resp.text}")
