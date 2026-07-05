from __future__ import annotations

import argparse
import os
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

import requests
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from dotenv import load_dotenv
from passlib.context import CryptContext
from pymongo import MongoClient


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


def _generate_activation_code(session: requests.Session, *, csrf: str) -> str:
    response = session.post(
        f"{API_BASE_URL}/agent/generate-activation",
        headers={"x-csrf-token": csrf},
        timeout=30,
    )
    response.raise_for_status()
    return response.json()["activation_code"]


def _register_agent(activation_code: str, public_key_pem: str) -> requests.Response:
    return requests.post(
        f"{API_BASE_URL}/agent/register",
        json={
            "activation_code": activation_code,
            "public_key": public_key_pem,
        },
        timeout=30,
    )


def _signed_ingest(agent_bearer: str, agent_id: str, run_id: str) -> requests.Response:
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

    activation_code = _generate_activation_code(session, csrf=login["csrf"])
    if not activation_code:
        _log("[-] Failed to mint activation code")
        return False
    _log("[OK] Activation code minted")

    agent_private_key = ed25519.Ed25519PrivateKey.generate()
    public_key_pem = agent_private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")

    register_response = _register_agent(activation_code, public_key_pem)
    _log(f"[REGISTER] {register_response.status_code} {register_response.text}")
    if register_response.status_code != 200:
        _log(f"[-] Agent register failed: {register_response.status_code} {register_response.text}")
        return False
    registered_agent = register_response.json()
    agent_id = registered_agent["agent_id"]
    agent_access_token = registered_agent["agent_jwt"]
    _log("[OK] Agent registered")

    replay_response = _register_agent(activation_code, public_key_pem)
    _log(f"[REPLAY] {replay_response.status_code} {replay_response.text}")

    ingest_response = _signed_ingest(agent_access_token, agent_id, run_id)
    _log(f"[INGEST] {ingest_response.status_code} {ingest_response.text}")

    return ingest_response.status_code == 200


if __name__ == "__main__":
    raise SystemExit(0 if run_integration_test() else 1)
