from __future__ import annotations

import argparse
import hashlib
import os
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

import requests
from dotenv import load_dotenv
from ecdsa import NIST256p, SigningKey
from passlib.context import CryptContext
from pymongo import MongoClient

from app.utils.agent_crypto import (
    build_event_signature_string,
    build_login_signature_string,
    build_payload_hash,
    build_signable_event_payload,
)


ROOT = Path(__file__).resolve().parent
load_dotenv(ROOT / ".env")
TRACE_PATH = ROOT / "local_e2e_trace.log"

PWD = CryptContext(schemes=["pbkdf2_sha256", "bcrypt"], deprecated="auto")

BASE_URL = os.getenv("BACKEND_PUBLIC_URL", "http://127.0.0.1:8000")
API_BASE_URL = f"{BASE_URL.rstrip('/')}/api/v1"
MONGODB_URI = os.getenv("MONGODB_URI", "mongodb://127.0.0.1:27017")
MONGODB_DB_NAME = os.getenv("MONGODB_DB_NAME", "WarSOC_DB")


def _hash_password(password: str) -> str:
    return PWD.hash(password)


def _log(message: str) -> None:
    print(message)
    try:
        with TRACE_PATH.open("a", encoding="utf-8") as handle:
            handle.write(message + "\n")
    except Exception:
        pass


def _upsert(collection, query: dict, document: dict) -> None:
    collection.update_one(query, {"$set": document}, upsert=True)


def _provision_tenant_and_admin(db, *, tenant_label: str, admin_email: str, admin_password: str, plan_type: str = "Enterprise") -> dict:
    tenant_id = f"WARSOC_{tenant_label.upper()}_{uuid.uuid4().hex[:6].upper()}"
    username = admin_email.split("@")[0].strip().lower()
    tenant_doc = {
        "tenant_id": tenant_id,
        "company_name": f"{tenant_label} Corp",
        "plan_type": plan_type,
        "plan": plan_type,
        "retention_days": 365,
        "status": "active",
        "created_at": datetime.now(timezone.utc),
    }
    user_doc = {
        "username": username,
        "email": admin_email.strip().lower(),
        "full_name": f"{tenant_label} Admin",
        "hashed_password": _hash_password(admin_password),
        "tenant_id": tenant_id,
        "plan_type": plan_type,
        "role": "admin",
        "compliance_packs": ["eto_forensic", "fbr_pos"],
        "has_active_plan": True,
        "created_at": datetime.now(timezone.utc),
    }
    _upsert(db["tenants"], {"tenant_id": tenant_id}, tenant_doc)
    _upsert(db["users"], {"email": user_doc["email"]}, user_doc)
    return {"tenant_id": tenant_id, "username": username, "email": user_doc["email"], "password": admin_password}


def _admin_login(session: requests.Session, username_or_email: str, password: str) -> dict:
    response = session.post(
        f"{API_BASE_URL}/auth/login",
        json={"username": username_or_email, "password": password},
        timeout=30,
    )
    response.raise_for_status()
    data = response.json()
    csrf = data.get("csrf_token") or session.cookies.get("csrf_token")
    if not csrf:
        raise RuntimeError("CSRF token missing after login")
    return {"payload": data, "csrf": csrf}


def _generate_enrollment_token(session: requests.Session, *, csrf: str, agent_id: str) -> str:
    response = session.post(
        f"{API_BASE_URL}/auth/agents/generate-token",
        headers={"x-csrf-token": csrf},
        json={"agent_id": agent_id},
        timeout=30,
    )
    response.raise_for_status()
    data = response.json()
    return data.get("enrollment_token") or data.get("provisioning_token")


def _enroll_agent(provisioning_token: str, agent_id: str, public_key_pem: str) -> requests.Response:
    return requests.post(
        f"{API_BASE_URL}/auth/agents/enroll",
        headers={"Authorization": f"Bearer {provisioning_token}"},
        json={
            "agent_id": agent_id,
            "public_key": public_key_pem,
            "hostname": "verify-host",
            "mac_address": "00:11:22:33:44:55",
        },
        timeout=30,
    )


def _agent_login(agent_id: str, signing_key: SigningKey) -> str:
    timestamp = datetime.now(timezone.utc).isoformat()
    nonce = uuid.uuid4().hex
    canonical = build_login_signature_string(agent_id, timestamp, nonce)
    signature = signing_key.sign(canonical.encode("utf-8"), hashfunc=hashlib.sha256).hex()

    response = requests.post(
        f"{API_BASE_URL}/auth/agent-login",
        json={
            "agent_id": agent_id,
            "timestamp": timestamp,
            "nonce": nonce,
            "signature": signature,
        },
        timeout=30,
    )
    response.raise_for_status()
    return response.json()["access_token"]


def _signed_ingest(agent_bearer: str, signing_key: SigningKey, agent_id: str, run_id: str) -> requests.Response:
    payload = {
        "tenant_id": "system-test",
        "agent_id": agent_id,
        "source_ip": "127.0.0.1",
        "user": "SYSTEM",
        "event_id": 4688,
        "event_uid": "local-test-1",
        "message": "cmd.exe /c powershell.exe -w hidden -enc base64",
        "source": "Windows_Agent",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "raw_data": {
            "tenant_id": "system-test",
            "event_uid": "local-test-1",
            "event_id": 4688,
            "message": "cmd.exe /c powershell.exe -w hidden -enc base64",
            "source": "Windows_Agent",
            "test_run_id": run_id,
        },
        "raw_event_data": {"channel": "Security"},
        "processed_data": {},
        "agent_version": "prod_test/1.0",
        "agent_signature": "",
    }
    signable = build_signable_event_payload(payload)
    payload_hash = build_payload_hash(signable)
    canonical = build_event_signature_string(
        payload["agent_id"],
        payload["timestamp"],
        payload["event_uid"],
        payload_hash,
    )
    payload["agent_signature"] = signing_key.sign(canonical.encode("utf-8"), hashfunc=hashlib.sha256).hex()

    return requests.post(
        f"{API_BASE_URL}/ingest/pulse",
        headers={"Authorization": f"Bearer {agent_bearer}"},
        json=payload,
        timeout=30,
    )


def run_integration_test() -> bool:
    try:
        TRACE_PATH.write_text("", encoding="utf-8")
    except Exception:
        pass

    _log(f"[START] Local E2E against: {BASE_URL}")
    client = MongoClient(MONGODB_URI)
    db = client[MONGODB_DB_NAME]

    run_id = f"local_{uuid.uuid4().hex[:8]}"
    admin = _provision_tenant_and_admin(
        db,
        tenant_label="LOCAL",
        admin_email=f"local_admin_{run_id}@test.local",
        admin_password="Password123!",
        plan_type="Enterprise",
    )
    _log(f"[OK] Provisioned tenant {admin['tenant_id']}")

    session = requests.Session()
    login = _admin_login(session, admin["email"], admin["password"])
    _log(f"[OK] Admin login complete for {login['payload'].get('username')}")

    agent_id = f"LOCAL_AGENT_{uuid.uuid4().hex[:8].upper()}"
    enrollment_token = _generate_enrollment_token(session, csrf=login["csrf"], agent_id=agent_id)
    if not enrollment_token:
        _log("[-] Failed to mint enrollment token")
        return False
    _log("[OK] Enrollment token minted")

    signing_key = SigningKey.generate(curve=NIST256p, hashfunc=hashlib.sha256)
    public_key_pem = signing_key.verifying_key.to_pem().decode("utf-8")

    enroll_response = _enroll_agent(enrollment_token, agent_id, public_key_pem)
    _log(f"[ENROLL] {enroll_response.status_code} {enroll_response.text}")
    if enroll_response.status_code != 201:
        _log(f"[-] Agent enroll failed: {enroll_response.status_code} {enroll_response.text}")
        return False
    _log("[OK] Agent enrolled (first use)")

    replay_response = _enroll_agent(enrollment_token, agent_id, public_key_pem)
    _log(f"[REPLAY] {replay_response.status_code} {replay_response.text}")

    agent_access_token = _agent_login(agent_id, signing_key)
    _log("[OK] Agent login token issued")

    ingest_response = _signed_ingest(agent_access_token, signing_key, agent_id, run_id)
    _log(f"[INGEST] {ingest_response.status_code} {ingest_response.text}")

    return ingest_response.status_code == 200


if __name__ == "__main__":
    raise SystemExit(0 if run_integration_test() else 1)
