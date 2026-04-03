import requests
import json
import time
from datetime import datetime, timedelta

API_URL = "http://localhost:8000"
VALID_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZXN0X2FnZW50X2xldmVsNCIsImp0aSI6IjQxOTc3Zjc5LWQ2ZDktNDM3My1iOTljLTViYzcwYjM3ZTJmMyIsImlhdCI6MTc3NTE5ODA3OCwiZXhwIjoxNzc1Mjg0NDc4LCJ0eXBlIjoiYWdlbnQifQ.5daXTBw_96xzNfLd3l74EZYAJkGuzdJmYIUQoOPi9I0"

def test_ransomware_attack():
    """Ransomware: batch file modifications (4663)"""
    print("\n[ATTACK 1] Ransomware - File Modifications (Event 4663)")
    payload = [
        {
            "agent_id": "test_agent_level4",
            "source_ip": "127.0.0.1",
            "user": "SYSTEM",
            "event_id": 4663,
            "message": "File created/modified (ransomware pattern)",
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "agent_version": "1.0.0",
            "raw_data": {"file": "C:\\Users\\Public\\*.docx", "process": "crypto_ransom.exe"}
        } for _ in range(50)
    ]
    try:
        r = requests.post(f"{API_URL}/api/v1/ingest/windows", json=payload,
                         headers={"Authorization": f"Bearer {VALID_TOKEN}"}, timeout=5)
        print(f"  Status: {r.status_code} | OK" if r.status_code < 300 else f"  Status: {r.status_code} | FAIL")
    except Exception as e:
        print(f"  ERROR: {e}")

def test_c2_beaconing():
    """C2 beaconing: repeated network connections (Sysmon Event 3)"""
    print("\n[ATTACK 2] C2 Beaconing - Network Connections (Sysmon Event 3)")
    payload = [
        {
            "agent_id": "test_agent_level4",
            "source_ip": "127.0.0.1",
            "user": "Administrator",
            "event_id": 3,
            "message": "Network connection (C2 pattern)",
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "agent_version": "1.0.0",
            "raw_data": {"dest_ip": "192.0.2.1", "dest_port": 4444, "process": "weasel.exe"}
        } for _ in range(15)
    ]
    try:
        r = requests.post(f"{API_URL}/api/v1/ingest/windows", json=payload,
                         headers={"Authorization": f"Bearer {VALID_TOKEN}"}, timeout=5)
        print(f"  Status: {r.status_code} | OK" if r.status_code < 300 else f"  Status: {r.status_code} | FAIL")
    except Exception as e:
        print(f"  ERROR: {e}")

def test_registry_persistence():
    """Registry backdoor: persistence modification (4657)"""
    print("\n[ATTACK 3] Registry Persistence - Registry Modified (Event 4657)")
    payload = [
        {
            "agent_id": "test_agent_level4",
            "source_ip": "127.0.0.1",
            "user": "SYSTEM",
            "event_id": 4657,
            "message": "Registry value modified (persistence)",
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "agent_version": "1.0.0",
            "raw_data": {"reg_path": "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "value": "C:\\malware\\backdoor.exe"}
        }
    ]
    try:
        r = requests.post(f"{API_URL}/api/v1/ingest/windows", json=payload,
                         headers={"Authorization": f"Bearer {VALID_TOKEN}"}, timeout=5)
        print(f"  Status: {r.status_code} | OK" if r.status_code < 300 else f"  Status: {r.status_code} | FAIL")
    except Exception as e:
        print(f"  ERROR: {e}")

def test_scheduled_task_backdoor():
    """Scheduled task persistence (Event 4698)"""
    print("\n[ATTACK 4] Scheduled Task Backdoor (Event 4698)")
    payload = [
        {
            "agent_id": "test_agent_level4",
            "source_ip": "127.0.0.1",
            "user": "SYSTEM",
            "event_id": 4698,
            "message": "Scheduled task created (backdoor)",
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "agent_version": "1.0.0",
            "raw_data": {"task": "WindowsUpdateCheck", "path": "C:\\malware\\payload.exe"}
        }
    ]
    try:
        r = requests.post(f"{API_URL}/api/v1/ingest/windows", json=payload,
                         headers={"Authorization": f"Bearer {VALID_TOKEN}"}, timeout=5)
        print(f"  Status: {r.status_code} | OK" if r.status_code < 300 else f"  Status: {r.status_code} | FAIL")
    except Exception as e:
        print(f"  ERROR: {e}")

def test_privilege_escalation():
    """Privilege escalation: local group member added (Event 4732)"""
    print("\n[ATTACK 5] Privilege Escalation - Local Group Member Added (Event 4732)")
    payload = [
        {
            "agent_id": "test_agent_level4",
            "source_ip": "127.0.0.1",
            "user": "Administrator",
            "event_id": 4732,
            "message": "Local group member added (PrivEsc)",
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "agent_version": "1.0.0",
            "raw_data": {"group": "Administrators", "member": "attacker_account"}
        }
    ]
    try:
        r = requests.post(f"{API_URL}/api/v1/ingest/windows", json=payload,
                         headers={"Authorization": f"Bearer {VALID_TOKEN}"}, timeout=5)
        print(f"  Status: {r.status_code} | OK" if r.status_code < 300 else f"  Status: {r.status_code} | FAIL")
    except Exception as e:
        print(f"  ERROR: {e}")

def test_log_poisoning_attack():
    """Log poisoning: stale timestamp (should be BLOCKED - Layer 3)"""
    print("\n[ATTACK 6] Log Poisoning - Stale Timestamp (SHOULD BE BLOCKED 400)")
    stale_time = (datetime.utcnow() - timedelta(minutes=10)).isoformat() + "Z"
    payload = [
        {
            "agent_id": "test_agent_level4",
            "source_ip": "127.0.0.1",
            "user": "Admin",
            "event_id": 4688,
            "message": "Process creation (old)",
            "timestamp": stale_time,
            "agent_version": "1.0.0",
            "raw_data": {"process": "malware.exe"}
        }
    ]
    try:
        r = requests.post(f"{API_URL}/api/v1/ingest/windows", json=payload,
                         headers={"Authorization": f"Bearer {VALID_TOKEN}"}, timeout=5)
        print(f"  Status: {r.status_code} | {'PASS' if r.status_code == 400 else 'FAIL'} (Expected: 400)")
    except Exception as e:
        print(f"  ERROR: {e}")

def test_dos_attack():
    """DoS: oversized payload (should be BLOCKED - Layer 2)"""
    print("\n[ATTACK 7] DoS - Oversized Payload (SHOULD BE BLOCKED 413)")
    payload = [
        {
            "agent_id": "test_agent_level4",
            "source_ip": "127.0.0.1",
            "user": "Admin",
            "event_id": 4688,
            "message": "Process",
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "agent_version": "1.0.0",
            "raw_data": {"data": "X" * 1_500_000}
        }
    ]
    try:
        r = requests.post(f"{API_URL}/api/v1/ingest/windows", json=payload,
                         headers={"Authorization": f"Bearer {VALID_TOKEN}"}, timeout=5)
        print(f"  Status: {r.status_code} | {'PASS' if r.status_code == 413 else 'FAIL'} (Expected: 413)")
    except Exception as e:
        print(f"  ERROR: {e}")

def test_missing_token():
    """Token bypass: no JWT (should be BLOCKED - Layer 4)"""
    print("\n[ATTACK 8] Token Bypass - No JWT (SHOULD BE BLOCKED 401)")
    payload = [
        {
            "agent_id": "test_agent_level4",
            "source_ip": "127.0.0.1",
            "user": "Admin",
            "event_id": 4688,
            "message": "Process",
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "agent_version": "1.0.0"
        }
    ]
    try:
        r = requests.post(f"{API_URL}/api/v1/ingest/windows", json=payload, timeout=5)
        print(f"  Status: {r.status_code} | {'PASS' if r.status_code == 401 else 'FAIL'} (Expected: 401)")
    except Exception as e:
        print(f"  ERROR: {e}")

if __name__ == "__main__":
    print("\n" + "=" * 70)
    print("WARSOC ATTACK SIMULATION SUITE - LEVEL 4 (Event IDs 4663, 4660, 4657, 3, 4698, 4732)")
    print("=" * 70)

    test_ransomware_attack()
    time.sleep(1)
    test_c2_beaconing()
    time.sleep(1)
    test_registry_persistence()
    time.sleep(1)
    test_scheduled_task_backdoor()
    time.sleep(1)
    test_privilege_escalation()
    time.sleep(1)
    test_log_poisoning_attack()
    time.sleep(1)
    test_dos_attack()
    time.sleep(1)
    test_missing_token()

    print("\n" + "=" * 70)
    print("ATTACKS COMPLETE - Check Dashboard for alerts + security validation")
    print("=" * 70)
