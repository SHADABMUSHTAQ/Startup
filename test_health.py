import requests
resp = requests.get('http://127.0.0.1:8000/health')
print(f"Status: {resp.status_code}")
print(f"Response: {resp.text}")
