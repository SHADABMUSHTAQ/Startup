import requests
import json

BASE = "http://127.0.0.1:8000"

def pretty(resp):
    try:
        body = resp.json()
    except Exception:
        body = resp.text
    print(f"STATUS: {resp.status_code}")
    print(json.dumps(body, indent=2, ensure_ascii=False))


def signup():
    payload = {
        "username": "autotestuser",
        "email": "autotest@example.com",
        "password": "S3cureP@ssw0rd",
        "full_name": "Auto Test"
    }
    print("--- SIGNUP ---")
    r = requests.post(f"{BASE}/api/v1/auth/signup", json=payload, timeout=10)
    pretty(r)
    return r


def login():
    payload = {"username": "autotestuser", "password": "S3cureP@ssw0rd"}
    print("--- LOGIN ---")
    r = requests.post(f"{BASE}/api/v1/auth/login", json=payload, timeout=10)
    pretty(r)
    if r.ok:
        return r.json().get("access_token")
    return None


def get_me(token):
    print("--- GET /me ---")
    headers = {"Authorization": f"Bearer {token}"}
    r = requests.get(f"{BASE}/api/v1/auth/me", headers=headers, timeout=10)
    pretty(r)
    return r


def logout(token):
    print("--- LOGOUT ---")
    headers = {"Authorization": f"Bearer {token}"}
    r = requests.post(f"{BASE}/api/v1/auth/logout", headers=headers, timeout=10)
    pretty(r)
    return r


def agent_login():
    print("--- AGENT LOGIN (negative) ---")
    payload = {"agent_id": "AGENT_XYZ", "agent_secret": "wrongsecret"}
    r = requests.post(f"{BASE}/api/v1/auth/agent-login", json=payload, timeout=10)
    pretty(r)
    return r


if __name__ == '__main__':
    signup()
    token = login()
    if token:
        get_me(token)
        logout(token)
    agent_login()
