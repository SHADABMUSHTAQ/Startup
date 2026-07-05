import requests

try:
    r = requests.get('http://127.0.0.1:8000/health', timeout=5)
    print(f"STATUS: {r.status_code}")
    print(f"TEXT: {r.text}")
except Exception as e:
    print(f"ERROR: {e}")
