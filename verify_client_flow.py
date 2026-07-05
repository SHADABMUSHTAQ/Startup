"""Closed-enterprise client flow verifier.

Verifies the chain:
1) Admin provisioning (tenant + admin user in MongoDB)
2) Admin login (cookie + CSRF)
3) Agent enrollment token generation and one-time enroll replay rejection
4) Agent ECDSA login and signed ingest
5) Vault routing and tenant isolation checks in MongoDB
"""

from __future__ import annotations

import argparse
import hashlib
import os
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

import requests
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from redis import Redis
from dotenv import load_dotenv
from ecdsa import NIST256p, SigningKey
from passlib.context import CryptContext
from pymongo import MongoClient

from app.utils.agent_crypto import (
    build_event_signature_string,
    build_payload_hash,
    build_signable_event_payload,
)


ROOT = Path(__file__).resolve().parent
load_dotenv(ROOT / ".env")

PWD = CryptContext(schemes=["pbkdf2_sha256", "bcrypt"], deprecated="auto")


def _env(name: str, default: str) -> str:
    value = os.getenv(name, default)
    return value.strip() if isinstance(value, str) else default


def _hash_password(password: str) -> str:
    return PWD.hash(password)


def _upsert(collection, query: dict, document: dict) -> None:
    collection.update_one(query, {"$set": document}, upsert=True)


def _sync_tenant_plan(redis_url: str, tenant_id: str, plan_type: str) -> None:
    redis_client = Redis.from_url(redis_url, decode_responses=True)
    try:
        redis_client.set(f"tenant_plan:{tenant_id}", plan_type)
    finally:
        redis_client.close()


def _provision_tenant_and_admin(db, *, tenant_label: str, admin_email: str, admin_password: str, plan_type: str = "Enterprise") -> dict:
    tenant_id = f"WARSOC_{tenant_label.upper()}_{uuid.uuid4().hex[:6].upper()}"
    tenant_doc = {
        "tenant_id": tenant_id,
        "company_name": f"{tenant_label} Corp",
        "plan_type": plan_type,
        "plan": plan_type,
        "retention_days": 365 if plan_type != "Free" else 90,
        "status": "active",
        "created_at": datetime.now(timezone.utc),
    }
    username = admin_email.split("@")[0].strip().lower()
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
    return {
        "tenant_id": tenant_id,
        "username": username,
        "email": user_doc["email"],
        "password": admin_password,
    }


def _admin_login(session: requests.Session, base_url: str, username_or_email: str, password: str) -> dict:
    response = session.post(
        f"{base_url}/auth/login",
        json={"username": username_or_email, "password": password},
        timeout=30,
    )
    response.raise_for_status()
    data = response.json()
    csrf = data.get("csrf_token") or session.cookies.get("csrf_token")
    if not csrf:
        raise RuntimeError("CSRF token missing after login")
    return {"payload": data, "csrf": csrf}


def _generate_activation_code(session: requests.Session, base_url: str, *, csrf: str) -> str:
    response = session.post(
        f"{base_url}/agent/generate-activation",
        headers={"x-csrf-token": csrf},
        timeout=30,
    )
    response.raise_for_status()
    return response.json()["activation_code"]


def _register_agent(base_url: str, *, activation_code: str, public_key_pem: str) -> requests.Response:
    return requests.post(
        f"{base_url}/agent/register",
        json={
            "activation_code": activation_code,
            "public_key": public_key_pem,
        },
        timeout=30,
    )


def _signed_ingest(base_url: str, *, agent_bearer: str, signing_key: SigningKey, agent_id: str, event_id: int, run_id: str, mode: str) -> requests.Response:
    payload = {
        "agent_id": agent_id,
        "source_ip": "127.0.0.1",
        "user": "SYSTEM",
        "event_id": event_id,
        "event_uid": uuid.uuid4().hex,
        "message": f"{mode} test event",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "raw_data": {
            "test_run_id": run_id,
            "mode": mode,
            "origin": "verify_client_flow",
            "type": "network_log" if mode == "linux" else "windows_log",
        },
        "raw_event_data": {"channel": "Security"},
        "processed_data": {},
        "agent_version": "verify-client-flow/1.0",
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
        f"{base_url}/ingest/pulse",
        headers={"Authorization": f"Bearer {agent_bearer}"},
        json=payload,
        timeout=30,
    )


def _wait_for_count(db, *, collection: str, query: dict, expected_min: int, timeout_seconds: int = 30) -> int:
    deadline = time.time() + timeout_seconds
    while time.time() < deadline:
        count = db[collection].count_documents(query)
        if count >= expected_min:
            return count
        time.sleep(1)
    return db[collection].count_documents(query)


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify closed-enterprise client onboarding and ingest flow.")
    parser.add_argument("--api-base-url", default=_env("BACKEND_PUBLIC_URL", "http://127.0.0.1:8000") + "/api/v1")
    parser.add_argument("--mongodb-uri", default=_env("MONGODB_URI", "mongodb://localhost:27017"))
    parser.add_argument("--mongodb-db", default=_env("MONGODB_DB_NAME", "WarSOC_DB"))
    parser.add_argument("--redis-url", default=_env("REDIS_URL", "redis://localhost:6379"))
    parser.add_argument("--events-per-mode", type=int, default=10)
    args = parser.parse_args()

    run_id = f"verify_{uuid.uuid4().hex[:10]}"
    client = MongoClient(args.mongodb_uri)
    db = client[args.mongodb_db]

    alpha = _provision_tenant_and_admin(
        db,
        tenant_label="ALPHA",
        admin_email=f"alpha_admin_{run_id}@test.local",
        admin_password="Password123!",
    )
    beta = _provision_tenant_and_admin(
        db,
        tenant_label="BETA",
        admin_email=f"beta_admin_{run_id}@test.local",
        admin_password="Password123!",
    )
    _sync_tenant_plan(args.redis_url, alpha["tenant_id"], "Enterprise")
    _sync_tenant_plan(args.redis_url, beta["tenant_id"], "Enterprise")
    print(f"[OK] Provisioned tenants: {alpha['tenant_id']} and {beta['tenant_id']}")

    alpha_session = requests.Session()
    alpha_login = _admin_login(alpha_session, args.api_base_url, alpha["email"], alpha["password"])
    print(f"[OK] Alpha admin login: {alpha_login['payload'].get('username')} tenant={alpha_login['payload'].get('tenant_id')}")

    beta_session = requests.Session()
    beta_login = _admin_login(beta_session, args.api_base_url, beta["email"], beta["password"])
    print(f"[OK] Beta admin login: {beta_login['payload'].get('username')} tenant={beta_login['payload'].get('tenant_id')}")

    alpha_activation_code = _generate_activation_code(
        alpha_session,
        args.api_base_url,
        csrf=alpha_login["csrf"],
    )

    alpha_signing_key = SigningKey.generate(curve=NIST256p, hashfunc=hashlib.sha256)
    alpha_agent_private_key = ed25519.Ed25519PrivateKey.generate()
    alpha_pub = alpha_agent_private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")

    register_response = _register_agent(
        args.api_base_url,
        activation_code=alpha_activation_code,
        public_key_pem=alpha_pub,
    )
    if register_response.status_code != 200:
        raise RuntimeError(f"Register failed: {register_response.status_code} {register_response.text}")
    registered_agent = register_response.json()
    alpha_agent_id = registered_agent["agent_id"]
    agent_access_token = registered_agent["agent_jwt"]
    print("[OK] Agent registered (first use)")

    replay_response = _register_agent(
        args.api_base_url,
        activation_code=alpha_activation_code,
        public_key_pem=alpha_pub,
    )
    replay_pass = replay_response.status_code in (401, 403)
    print(f"[{'OK' if replay_pass else 'FAIL'}] Activation replay rejection status={replay_response.status_code}")

    windows_event_id = 4657
    linux_event_id = 1102
    failures = []

    for _ in range(args.events_per_mode):
        r = _signed_ingest(
            args.api_base_url,
            agent_bearer=agent_access_token,
            signing_key=alpha_signing_key,
            agent_id=alpha_agent_id,
            event_id=windows_event_id,
            run_id=run_id,
            mode="windows",
        )
        if r.status_code != 200:
            failures.append(f"windows ingest failed: {r.status_code} {r.text}")

    for _ in range(args.events_per_mode):
        r = _signed_ingest(
            args.api_base_url,
            agent_bearer=agent_access_token,
            signing_key=alpha_signing_key,
            agent_id=alpha_agent_id,
            event_id=linux_event_id,
            run_id=run_id,
            mode="linux",
        )
        if r.status_code != 200:
            failures.append(f"linux ingest failed: {r.status_code} {r.text}")

    if failures:
        raise RuntimeError("; ".join(failures))
    print(f"[OK] Queued {args.events_per_mode * 2} signed logs")

    alpha_fbr_query = {"tenant_id": alpha["tenant_id"], "raw_data.test_run_id": run_id}
    alpha_peca_query = {"tenant_id": alpha["tenant_id"], "raw_data.test_run_id": run_id}
    beta_fbr_query = {"tenant_id": beta["tenant_id"], "raw_data.test_run_id": run_id}
    beta_peca_query = {"tenant_id": beta["tenant_id"], "raw_data.test_run_id": run_id}

    alpha_fbr = _wait_for_count(db, collection="fbr_pos_logs", query=alpha_fbr_query, expected_min=args.events_per_mode)
    alpha_peca = _wait_for_count(db, collection="peca_forensic_logs", query=alpha_peca_query, expected_min=args.events_per_mode)
    beta_fbr = db["fbr_pos_logs"].count_documents(beta_fbr_query)
    beta_peca = db["peca_forensic_logs"].count_documents(beta_peca_query)

    print(f"[INFO] Alpha FBR count={alpha_fbr}")
    print(f"[INFO] Alpha PECA count={alpha_peca}")
    print(f"[INFO] Beta FBR count={beta_fbr}")
    print(f"[INFO] Beta PECA count={beta_peca}")

    checks = {
        "replay_rejected": replay_pass,
        "alpha_fbr_received": alpha_fbr >= args.events_per_mode,
        "alpha_peca_received": alpha_peca >= args.events_per_mode,
        "cross_pollination_blocked": beta_fbr == 0 and beta_peca == 0,
    }

    print("\nVerification summary:")
    for name, ok in checks.items():
        print(f"- {name}: {'PASS' if ok else 'FAIL'}")

    failed = [name for name, ok in checks.items() if not ok]
    if failed:
        print(f"\nRESULT: FAIL -> {', '.join(failed)}")
        return 2

    print("\nRESULT: PASS -> Closed-enterprise flow verified end-to-end.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
