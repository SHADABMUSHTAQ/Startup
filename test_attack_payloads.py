
import requests
import datetime

def get_agent_token():
    url = "http://127.0.0.1:8000/api/v1/auth/agent-login"
    data = {
        "agent_id": "WARSOC_98F626B8",
        "agent_secret": "warsoc_enterprise_agent_key_2026"
    }
    resp = requests.post(url, json=data)
    if resp.status_code == 200:
        return resp.json()["access_token"]
    else:
        print(f"Failed to get agent token: {resp.status_code} {resp.text}")
        exit(1)

def send_attack(payload, token):
    url = "http://127.0.0.1:8000/api/v1/ingest/windows"
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {token}"
    }
    response = requests.post(url, json=payload, headers=headers)
    print(f"Status: {response.status_code}, Response: {response.text}")

now = datetime.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"

payloads = [
    # Universal failed login (should always trigger detection)
    {
        "agent_id": "WARSOC_98F626B8",
        "source_ip": "10.10.10.99",
        "user": "testuser",
        "event_id": 4625,
        "event_type": "failed_login",
        "mitre": "T1110",
        "message": "failed password authentication failure login failed access denied for user testuser from 10.10.10.99",
        "timestamp": now,
        "raw_data": {},
        "agent_version": "1.0.0"
    },
    # Universal SQL Injection
    {
        "agent_id": "WARSOC_98F626B8",
        "source_ip": "10.10.10.101",
        "user": "webuser",
        "event_id": 4688,
        "event_type": "http_request",
        "mitre": "T1190",
        "message": "select union or 1=1 -- drop information_schema xp_cmdshell GET /index.php?id=1' OR 1=1 UNION SELECT * FROM users -- HTTP/1.1",
        "timestamp": now,
        "raw_data": {},
        "agent_version": "1.0.0"
    },
    # Universal XSS
    {
        "agent_id": "WARSOC_98F626B8",
        "source_ip": "10.10.10.102",
        "user": "webuser",
        "event_id": 4688,
        "event_type": "http_request",
        "mitre": "T1190",
        "message": "<script>javascript:onerror=alert(1) onload=run() in comment field",
        "timestamp": now,
        "raw_data": {},
        "agent_version": "1.0.0"
    },
    # Universal Command Injection
    {
        "agent_id": "WARSOC_98F626B8",
        "source_ip": "10.10.10.103",
        "user": "webuser",
        "event_id": 4688,
        "event_type": "http_request",
        "mitre": "T1059",
        "message": "; whoami | nc -e /bin/sh $(`id`) | bash",
        "timestamp": now,
        "raw_data": {},
        "agent_version": "1.0.0"
    },
    # Universal Phishing
    {
        "agent_id": "WARSOC_98F626B8",
        "source_ip": "10.10.10.104",
        "user": "victim",
        "event_id": 4688,
        "event_type": "http_request",
        "mitre": "T1566",
        "message": "verify your account password expired urgent action required invoice attached payment failed mfa required security alert at http://bit.ly/evil. Please reset password immediately.",
        "timestamp": now,
        "raw_data": {},
        "agent_version": "1.0.0"
    },
    # Universal failed login (should always trigger detection)
    {
        "agent_id": "WARSOC_98F626B8",
        "source_ip": "10.10.10.99",
        "user": "testuser",
        "event_id": 4625,
        "event_type": "failed_login",
        "mitre": "T1110",
        "message": "failed password authentication failure login failed access denied for user testuser from 10.10.10.99",
        "timestamp": now,
        "raw_data": {},
        "agent_version": "1.0.0"
    },
    # Brute Force
    {
        "agent_id": "WARSOC_98F626B8",
        "source_ip": "10.10.10.10",
        "user": "attacker",
        "event_id": 4625,
        "event_type": "failed_login",
        "mitre": "T1110",
        "message": "failed password for root from 10.10.10.10 port 22 ssh2",
        "timestamp": now,
        "raw_data": {},
        "agent_version": "1.0.0"
    },
    # SQL Injection (must_include_any: select, union, or 1=1, --, drop, information_schema)
    {
        "agent_id": "WARSOC_98F626B8",
        "source_ip": "10.10.10.11",
        "user": "webuser",
        "event_id": 4688,
        "event_type": "http_request",
        "mitre": "T1190",
        "message": "GET /index.php?id=1' OR 1=1 UNION SELECT * FROM users -- drop table information_schema HTTP/1.1",
        "timestamp": now,
        "raw_data": {},
        "agent_version": "1.0.0"
    },
    # XSS (must_include_any: <script, javascript:, onerror, onload)
    {
        "agent_id": "WARSOC_98F626B8",
        "source_ip": "10.10.10.12",
        "user": "webuser",
        "event_id": 4688,
        "event_type": "http_request",
        "mitre": "T1190",
        "message": "<script>alert('xss')</script> onerror=alert(1) onload=run() javascript:evil() in comment field",
        "timestamp": now,
        "raw_data": {},
        "agent_version": "1.0.0"
    },
    # Command Injection (pattern: ; whoami)
    {
        "agent_id": "WARSOC_98F626B8",
        "source_ip": "10.10.10.13",
        "user": "webuser",
        "event_id": 4688,
        "event_type": "http_request",
        "mitre": "T1059",
        "message": "; whoami | nc -e /bin/sh",
        "timestamp": now,
        "raw_data": {},
        "agent_version": "1.0.0"
    },
    # Phishing (must_include_any: verify your account, http://, bit.ly)
    {
        "agent_id": "WARSOC_98F626B8",
        "source_ip": "10.10.10.14",
        "user": "victim",
        "event_id": 4688,
        "event_type": "http_request",
        "mitre": "T1566",
        "message": "Urgent action required: verify your account at http://bit.ly/evil. Please reset password immediately.",
        "timestamp": now,
        "raw_data": {},
        "agent_version": "1.0.0"
    }
]

if __name__ == "__main__":
    token = get_agent_token()
    for p in payloads:
        send_attack(p, token)
