import os
import requests

# Monkeypatch to disable SSL verification for local testing
original_request = requests.Session.request
def insecure_request(self, method, url, **kwargs):
    kwargs['verify'] = False
    return original_request(self, method, url, **kwargs)
requests.Session.request = insecure_request

# Disable insecure request warnings
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Update BACKEND_URL in .env to use https gateway
with open("agent/.env", "r") as f:
    content = f.read()
content = content.replace("http://127.0.0.1:8000", "https://localhost")
with open("agent/.env", "w") as f:
    f.write(content)

from agent import windows_agent

if windows_agent.authenticate_agent():
    print("TOKEN_START:" + windows_agent.JWT_TOKEN + ":TOKEN_END")
else:
    print("Authentication failed")
