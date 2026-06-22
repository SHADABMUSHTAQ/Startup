import requests
BASE = "http://127.0.0.1:8000/api/v1"
r = requests.post(f"{BASE}/auth/login", json={"username": "cto_admin", "password": "WarSOCPassword123!"}, timeout=10)
print(f"Login Status: {r.status_code}")
print(f"Cookies: {dict(r.cookies)}")
if r.status_code == 200:
    print("LOGIN WORKS")
else:
    print(f"FAILED: {r.text}")
