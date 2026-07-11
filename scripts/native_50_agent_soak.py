"""Provision 50 agents and validate the native SIEM/FBR/PECA burst path."""

from __future__ import annotations

import argparse
import concurrent.futures
import os
import sys
import time
import uuid
import urllib.parse
from datetime import datetime, timezone

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from launch_readiness_validator import ApiClient


def public_key_pem() -> str:
    key = ed25519.Ed25519PrivateKey.generate()
    return key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")


def ingest_agent(base_url: str, agent_jwt: str, events: list[dict]) -> tuple[int, object]:
    client = ApiClient(base_url)
    response = client.request(
        "POST",
        "/api/v1/ingest/pulse",
        {
            "nonce": uuid.uuid4().hex,
            "timestamp": int(time.time()),
            "payload": events,
        },
        headers={"Authorization": f"Bearer {agent_jwt}"},
        timeout=30,
    )
    return response.status, response.body


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", default=os.getenv("WARSOC_BASE_URL", "http://127.0.0.1:8000"))
    parser.add_argument("--admin-key", default=os.getenv("SUPER_ADMIN_API_KEY", ""))
    parser.add_argument("--email-domain", default="warsoc.tech")
    parser.add_argument("--timeout", type=int, default=60)
    args = parser.parse_args()
    if not args.admin_key:
        parser.error("--admin-key or SUPER_ADMIN_API_KEY is required")

    run_id = uuid.uuid4().hex[:10]
    admin = ApiClient(args.base_url)
    admin_email = f"soak-admin-{run_id}@{args.email_domain}"
    password = f"SoakPass-{run_id}-123!"
    failures: list[str] = []

    provision = admin.request(
        "POST",
        "/api/v1/admin/provision",
        {
            "company_name": f"Native 50 Agent Soak {run_id}",
            "plan_type": "Customized",
            "compliance_packs": ["fbr_pos", "peca_forensic"],
            "max_agents": 50,
            "admin_email": admin_email,
            "admin_name": "Soak Admin",
            "admin_password": password,
        },
        headers={"X-Admin-Key": args.admin_key},
        timeout=180,
    )
    if provision.status != 200:
        print(f"[FAIL] Provision tenant: HTTP {provision.status} {provision.body}")
        return 1
    tenant_id = provision.body["tenant_id"]
    if admin.login(admin_email, password).status != 200:
        print("[FAIL] Admin login")
        return 1
    print(f"[PASS] Provisioned tenant {tenant_id} with 50 seats")

    agents: list[tuple[str, str]] = []
    for index in range(50):
        activation = admin.request("POST", "/api/v1/agent/generate-activation", {})
        code = activation.body.get("activation_code") if isinstance(activation.body, dict) else None
        if activation.status != 200 or not code:
            failures.append(f"activation {index}: HTTP {activation.status}")
            break
        registration = admin.request(
            "POST",
            "/api/v1/agent/register",
            {"activation_code": code, "public_key": public_key_pem()},
        )
        if registration.status != 200:
            failures.append(f"registration {index}: HTTP {registration.status}")
            break
        agents.append((registration.body["agent_id"], registration.body["agent_jwt"]))

    print(f"[{'PASS' if len(agents) == 50 else 'FAIL'}] Registered agents: {len(agents)}/50")
    if len(agents) != 50:
        return 1

    extra_activation = admin.request("POST", "/api/v1/agent/generate-activation", {})
    if extra_activation.status in {403, 409}:
        quota_status = extra_activation.status
    else:
        extra_registration = admin.request(
            "POST",
            "/api/v1/agent/register",
            {
                "activation_code": extra_activation.body.get("activation_code", ""),
                "public_key": public_key_pem(),
            },
        )
        quota_status = extra_registration.status
    quota_ok = quota_status in {403, 409}
    print(f"[{'PASS' if quota_ok else 'FAIL'}] 51st agent blocked: HTTP {quota_status}")
    if not quota_ok:
        failures.append(f"51st agent was not blocked: HTTP {quota_status}")

    expected_4688_uids = set()
    jobs = []
    emitted_at = datetime.now(timezone.utc).isoformat()
    for index, (_, agent_jwt) in enumerate(agents):
        process_uid = f"{run_id}-agent-{index:02d}-4688"
        expected_4688_uids.add(process_uid)
        events = [
            {
                "event_id": "4688",
                "event_uid": process_uid,
                "timestamp": emitted_at,
                "source_ip": f"10.50.0.{index + 1}",
                "user": "SYSTEM",
                "message": "C:\\Windows\\System32\\notepad.exe",
                "processed_data": {
                    "new_process_name": r"C:\Windows\System32\notepad.exe",
                    "command_line": "notepad.exe",
                },
            }
        ]
        if index == 0:
            events.extend(
                [
                    {
                        "event_id": "1102",
                        "event_uid": f"{run_id}-siem",
                        "timestamp": emitted_at,
                        "source_ip": "10.50.0.1",
                        "user": "Administrator",
                        "message": "Security audit log cleared during native soak validation",
                    },
                    {
                        "event_id": "4663",
                        "event_uid": f"{run_id}-fim-intent",
                        "timestamp": emitted_at,
                        "source_ip": "10.50.0.1",
                        "user": "pos-user",
                        "message": "POS database delete intent",
                        "processed_data": {
                            "object_name": r"C:\POS\data\soak.mdf",
                            "handle_id": "0x99",
                            "access_mask": "0x10000",
                        },
                    },
                    {
                        "event_id": "4660",
                        "event_uid": f"{run_id}-fim-delete",
                        "timestamp": emitted_at,
                        "source_ip": "10.50.0.1",
                        "user": "pos-user",
                        "message": "POS database deleted",
                        "processed_data": {"handle_id": "0x99"},
                    },
                ]
            )
        jobs.append((agent_jwt, events))

    burst_started = time.monotonic()
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as pool:
        results = list(
            pool.map(
                lambda item: ingest_agent(args.base_url, item[0], item[1]),
                jobs,
            )
        )
    accepted = sum(1 for status, _ in results if status in {200, 202})
    print(f"[{'PASS' if accepted == 50 else 'FAIL'}] Burst accepted: {accepted}/50 requests")
    if accepted != 50:
        failures.append(f"only {accepted}/50 burst requests accepted")

    alert_seen_at = None
    peca_seen = fbr_seen = False
    deadline = time.monotonic() + args.timeout
    while time.monotonic() < deadline:
        alert = admin.request(
            "GET",
            f"/api/v1/alerts?event_uid={urllib.parse.quote(run_id + '-siem')}&limit=20",
        )
        if alert.status == 200 and isinstance(alert.body, dict) and alert.body.get("data"):
            alert_seen_at = alert_seen_at or time.monotonic()

        peca = admin.request(
            "GET",
            "/api/v1/compliance/evidence/peca_forensic?event_id=4688&limit=500",
        )
        if peca.status == 200 and isinstance(peca.body, dict):
            observed = {
                row.get("event_uid")
                for row in peca.body.get("data", [])
                if row.get("event_uid") in expected_4688_uids
            }
            peca_seen = len(observed) == 50

        fbr = admin.request(
            "GET",
            "/api/v1/compliance/evidence/fbr_pos?event_id=FIM-DB-MOD&limit=500",
        )
        expected_fim_uid = f"{run_id}-fim-delete:fim-delete"
        if fbr.status == 200 and isinstance(fbr.body, dict):
            fbr_seen = any(row.get("event_uid") == expected_fim_uid for row in fbr.body.get("data", []))

        if alert_seen_at and peca_seen and fbr_seen:
            break
        time.sleep(1)

    completed_in = time.monotonic() - burst_started
    detection_in = (alert_seen_at - burst_started) if alert_seen_at else None
    fim_intent_alerts = admin.request(
        "GET",
        f"/api/v1/alerts?event_uid={urllib.parse.quote(run_id + '-fim-intent')}&limit=20",
    )
    false_ransomware_alert = False
    if fim_intent_alerts.status == 200 and isinstance(fim_intent_alerts.body, dict):
        false_ransomware_alert = any(
            "ransomware file extension" in " ".join(
                [
                    str(row.get("type") or ""),
                    str(row.get("summary") or ""),
                    str(row.get("message") or ""),
                ]
            ).lower()
            for row in fim_intent_alerts.body.get("data", [])
        )

    print(f"[{'PASS' if alert_seen_at else 'FAIL'}] SIEM canary latency: {detection_in if detection_in is not None else 'timeout'}s")
    print(f"[{'PASS' if peca_seen else 'FAIL'}] PECA vaulted all 50 native process events")
    print(f"[{'PASS' if fbr_seen else 'FAIL'}] FBR Redis-correlated deletion visible")
    print(f"[{'PASS' if not false_ransomware_alert else 'FAIL'}] Normal .mdf path caused no ransomware-extension alert")
    print(f"[{'PASS' if completed_in <= args.timeout else 'FAIL'}] Pipeline completion: {completed_in:.2f}s")

    if not alert_seen_at:
        failures.append("SIEM canary not visible")
    if not peca_seen:
        failures.append("PECA did not vault all 50 process events")
    if not fbr_seen:
        failures.append("FBR correlated deletion not visible")
    if false_ransomware_alert:
        failures.append("normal .mdf FBR path generated a ransomware-extension alert")
    if completed_in > args.timeout:
        failures.append(f"pipeline exceeded {args.timeout}s")

    print(f"Soak summary: failures={len(failures)}")
    for failure in failures:
        print(f" - {failure}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
