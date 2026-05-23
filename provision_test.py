"""Closed-enterprise provisioning helper for local testing.

This script does not restore public signup.
It provisions a tenant directly in MongoDB, creates a local admin user, logs in
through the real backend auth endpoint, and then provisions a second team member
through the admin invite flow.
"""

from __future__ import annotations

import argparse
import os
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

import requests
from redis import Redis
from dotenv import load_dotenv
from passlib.context import CryptContext
from pymongo import MongoClient


ROOT = Path(__file__).resolve().parent
load_dotenv(ROOT / ".env")

pwd_context = CryptContext(schemes=["pbkdf2_sha256", "bcrypt"], deprecated="auto")


def getenv(name: str, default: str) -> str:
    value = os.getenv(name, default)
    return value.strip() if isinstance(value, str) else default


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def make_user_document(*, username: str, email: str, full_name: str, password: str, tenant_id: str, plan_type: str, role: str, compliance_packs: list[str]) -> dict:
    return {
        "username": username,
        "email": email,
        "full_name": full_name,
        "hashed_password": hash_password(password),
        "tenant_id": tenant_id,
        "plan_type": plan_type,
        "role": role,
        "compliance_packs": compliance_packs,
        "has_active_plan": plan_type != "Free",
        "created_at": datetime.now(timezone.utc),
    }


def upsert_document(collection, query: dict, document: dict) -> None:
    collection.update_one(query, {"$set": document}, upsert=True)


def provision_tenant(db, *, company_name: str, plan_type: str) -> str:
    tenant_id = f"WARSOC_{uuid.uuid4().hex[:8].upper()}"
    tenant_doc = {
        "tenant_id": tenant_id,
        "company_name": company_name,
        "plan_type": plan_type,
        "plan": plan_type,
        "retention_days": 365 if plan_type != "Free" else 90,
        "status": "active",
        "created_at": datetime.now(timezone.utc),
    }
    upsert_document(db["tenants"], {"tenant_id": tenant_id}, tenant_doc)
    return tenant_id


def sync_tenant_plan(redis_url: str, tenant_id: str, plan_type: str) -> None:
    redis_client = Redis.from_url(redis_url, decode_responses=True)
    try:
        redis_client.set(f"tenant_plan:{tenant_id}", plan_type)
    finally:
        redis_client.close()


def provision_admin(db, *, tenant_id: str, email: str, password: str, full_name: str, plan_type: str) -> dict:
    username = email.split("@")[0].strip().lower()
    admin_doc = make_user_document(
        username=username,
        email=email.strip().lower(),
        full_name=full_name,
        password=password,
        tenant_id=tenant_id,
        plan_type=plan_type,
        role="admin",
        compliance_packs=["eto_forensic", "fbr_pos"] if plan_type != "Free" else [],
    )
    upsert_document(db["users"], {"email": admin_doc["email"]}, admin_doc)
    return admin_doc


def login(session: requests.Session, base_url: str, *, username: str, password: str) -> dict:
    response = session.post(
        f"{base_url}/auth/login",
        json={"username": username, "password": password},
        timeout=30,
    )
    response.raise_for_status()
    return response.json()


def main() -> int:
    parser = argparse.ArgumentParser(description="Provision a closed-enterprise test tenant and login identity.")
    parser.add_argument("--company", default="Closed Enterprise Test Tenant")
    parser.add_argument("--plan", default="Enterprise", choices=["Free", "Basic", "Professional", "Enterprise", "FULL_SUITE", "FBR_PLAN"])
    parser.add_argument("--admin-email", default="admin@test.local")
    parser.add_argument("--admin-password", default="Password123!")
    parser.add_argument("--admin-name", default="Test Admin")
    parser.add_argument("--team-email", default="analyst@test.local")
    parser.add_argument("--team-password", default="Password123!")
    parser.add_argument("--team-role", default="analyst", choices=["analyst", "auditor", "admin"])
    parser.add_argument("--api-base-url", default=getenv("BACKEND_PUBLIC_URL", "http://127.0.0.1:8000") + "/api/v1")
    parser.add_argument("--mongodb-uri", default=getenv("MONGODB_URI", "mongodb://localhost:27017"))
    parser.add_argument("--mongodb-db", default=getenv("MONGODB_DB_NAME", "WarSOC_DB"))
    args = parser.parse_args()

    client = MongoClient(args.mongodb_uri)
    db = client[args.mongodb_db]

    tenant_id = provision_tenant(db, company_name=args.company, plan_type=args.plan)
    sync_tenant_plan(getenv("REDIS_URL", "redis://localhost:6379"), tenant_id, args.plan)
    admin_doc = provision_admin(
        db,
        tenant_id=tenant_id,
        email=args.admin_email,
        password=args.admin_password,
        full_name=args.admin_name,
        plan_type=args.plan,
    )

    print(f"[1/4] Tenant provisioned: {tenant_id}")
    print(f"[2/4] Admin user provisioned: {admin_doc['email']} / {args.admin_password}")

    session = requests.Session()
    auth_payload = login(session, args.api_base_url, username=args.admin_email, password=args.admin_password)
    print(f"[3/4] Login successful for {auth_payload['username']}")
    print(f"      Tenant: {auth_payload.get('tenant_id')}")
    print(f"      Plan: {auth_payload.get('plan_type')}")
    print(f"      Cookies: {session.cookies.get_dict()}")

    bearer_token = session.cookies.get("warsoc_token")
    invite_headers = {"Authorization": f"Bearer {bearer_token}"} if bearer_token else {}

    invite_resp = session.post(
        f"{args.api_base_url}/auth/invite",
        headers=invite_headers,
        json={
            "email": args.team_email,
            "password": args.team_password,
            "role": args.team_role,
            "allowed_packs": ["eto_forensic"],
        },
        timeout=30,
    )

    if invite_resp.ok:
        invite_data = invite_resp.json()
        print(f"[4/4] Team member provisioned: {args.team_email} ({invite_data.get('role')})")
    else:
        print(f"[4/4] Team invite skipped: {invite_resp.status_code} {invite_resp.text}")
    print()
    print("Next steps:")
    print(f"- Sign in at /login with {args.admin_email} / {args.admin_password}")
    print("- Open /dashboard for Enterprise or Professional tenants")
    print(f"- Optional test user: {args.team_email} / {args.team_password}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())