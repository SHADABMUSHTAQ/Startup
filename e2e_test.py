import requests, time, json, os, sys

BASE="http://127.0.0.1:8000"
s = requests.Session()

def wait_for_service(url, timeout=60):
    start = time.time()
    while time.time() - start < timeout:
        try:
            r = requests.get(url, timeout=3)
            if r.status_code < 500:
                return True
        except Exception:
            pass
        time.sleep(1)
    return False

if not wait_for_service(BASE + "/docs", timeout=120):
    print("Service not responding at", BASE)
    sys.exit(2)

print("Service responding, starting E2E tests")

# 1) Signup a test user
username = f"e2e_test_user_{int(time.time())}"
email = f"{username}@example.com"

signup = s.post(f"{BASE}/api/v1/auth/signup", json={
  "username": username,
  "email": email,
  "password": "TestPass123!",
  "full_name": "E2E Tester"
}, timeout=30)
print('signup', signup.status_code, signup.text)
if signup.status_code not in (200,201):
    print('Signup failed, aborting')
    sys.exit(3)

# 2) Login
login = s.post(f"{BASE}/api/v1/auth/login", json={"username": username, "password": "TestPass123!"}, timeout=30)
print('login', login.status_code, login.text)
if login.status_code != 200:
    print('Login failed, aborting')
    sys.exit(4)

token = login.json().get("access_token")
headers = {"Authorization": f"Bearer {token}"}

# 3) POST mitigate (should create DB record + Redis set)
mit = s.post(f"{BASE}/api/v1/mitigate", headers=headers, json={"ip":"1.2.3.4","reason":"e2e test"}, timeout=30)
print('mitigate', mit.status_code, mit.text)

# 4) Upload a small CSV to test async upload
csv_content = "timestamp,message,source_ip\n2026-03-17T00:00:00Z,Test event,1.2.3.4\n"
with open("test_e2e.csv","w",encoding="utf-8") as f:
    f.write(csv_content)

files = {"file": open("test_e2e.csv","rb")}
try:
    upl = s.post(f"{BASE}/api/v1/upload/analyze", headers=headers, files=files, timeout=120)
    print('upload', upl.status_code, upl.text)
except Exception as e:
    print('upload error', e)

# 5) Check dashboard logs (requires login)
logs = s.get(f"{BASE}/api/v1/logs", headers=headers, timeout=30)
print('logs', logs.status_code, logs.text)

print('E2E script finished')
