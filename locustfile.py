
from __future__ import annotations

import os
import random
import uuid
from datetime import datetime, timezone

from passlib.context import CryptContext
from pymongo import MongoClient
from redis import Redis
import requests
from locust import between, task
from locust.contrib.fasthttp import FastHttpUser
from app.routes.auth import get_password_hash
from app.config.config import get_settings


EVENT_IDS = [4624, 3, 4657, 4688, 4697, 5157]
PWD = CryptContext(schemes=["pbkdf2_sha256", "bcrypt"], deprecated="auto")
SETTINGS = get_settings()


def _env(name: str, default: str) -> str:
    value = os.getenv(name, default)
    return value.strip() if isinstance(value, str) else default


def _ensure_stress_tenant() -> dict:
    mongo_uri = _env("LOCUST_MONGO_URI", SETTINGS.mongodb_uri)
    mongo_db_name = _env("LOCUST_MONGO_DB", SETTINGS.mongodb_db_name)
    redis_url = _env("LOCUST_REDIS_URL", SETTINGS.redis_url)

    tenant_label = _env("LOCUST_STRESS_TENANT_ID", "WARSOC_STRESS_TEST")
    tenant_id = tenant_label if tenant_label.startswith("WARSOC_") else f"WARSOC_{tenant_label}"
    username = _env("LOCUST_USERNAME", f"locust_admin_{tenant_id.lower()}@warsoc.local")
    password = _env("LOCUST_PASSWORD", "WarSOC2026!")

    client = MongoClient(mongo_uri)
    db = client[mongo_db_name]
    redis_client = Redis.from_url(redis_url, decode_responses=True)

    tenant_doc = {
        "tenant_id": tenant_id,
        "company_name": f"{tenant_id} Load Test",
        "plan_type": "Enterprise",
        "plan": "Enterprise",
        "retention_days": 365,
        "status": "active",
        "created_at": datetime.now(timezone.utc),
    }
    user_doc = {
        "username": username.split("@")[0],
        "email": username,
        "full_name": "Locust Stress Admin",
        "hashed_password": get_password_hash(password),
        "tenant_id": tenant_id,
        "plan_type": "Enterprise",
        "role": "admin",
        "compliance_packs": ["eto_forensic", "fbr_pos"],
        "has_active_plan": True,
        "created_at": datetime.now(timezone.utc),
    }

    db["tenants"].update_one({"tenant_id": tenant_id}, {"$set": tenant_doc}, upsert=True)
    db["users"].update_one({"email": username}, {"$set": user_doc}, upsert=True)
    redis_client.set(f"tenant_plan:{tenant_id}", "Enterprise")
    redis_client.close()
    client.close()

    return {"tenant_id": tenant_id, "username": username, "password": password}


def _bootstrap_shared_auth() -> dict:
    account = _ensure_stress_tenant()
    base_url = _env("LOCUST_BASE_URL", SETTINGS.api_base_url if hasattr(SETTINGS, "api_base_url") else "http://127.0.0.1:8000")
    login_url = f"{base_url.rstrip('/')}/api/v1/auth/login"

    session = requests.Session()
    response = session.post(login_url, json={"username": account["username"], "password": account["password"]}, timeout=30)
    response.raise_for_status()

    csrf_token = response.json().get("csrf_token") or session.cookies.get("csrf_token")
    warsoc_token = session.cookies.get("warsoc_token")
    if not csrf_token or not warsoc_token:
        raise RuntimeError("Failed to bootstrap shared auth cookies for Locust")

    return {
        "tenant_id": account["tenant_id"],
        "username": account["username"],
        "password": account["password"],
        "csrf_token": csrf_token,
        "warsoc_token": warsoc_token,
    }


SHARED_AUTH = _bootstrap_shared_auth()


class AgentUser(FastHttpUser):
    wait_time = between(0.5, 2.0)

    def on_start(self) -> None:
        self.username = SHARED_AUTH["username"]
        self.password = SHARED_AUTH["password"]
        self.stress_tenant_id = SHARED_AUTH["tenant_id"]
        self.source_ip_prefix = os.getenv("LOCUST_SOURCE_IP_PREFIX", "10.99.0.")
        self.csrf_token = SHARED_AUTH["csrf_token"]
        self.auth_cookie_header = f"warsoc_token={SHARED_AUTH['warsoc_token']}; csrf_token={SHARED_AUTH['csrf_token']}"

    def _build_payload(self) -> dict:
        event_id = random.choice(EVENT_IDS)
        source_host = random.randint(10, 250)
        source_ip = f"{self.source_ip_prefix}{source_host}"
        timestamp = datetime.now(timezone.utc).isoformat(timespec="milliseconds")
        event_uid = str(uuid.uuid4())

        if event_id == 4624:
            message = "Successful interactive logon"
        elif event_id == 3:
            message = "Outbound network connection detected"
        elif event_id == 4657:
            message = "Registry value modified"
        elif event_id == 4688:
            message = "Process creation event"
        elif event_id == 4697:
            message = "Service installation detected"
        else:
            message = "Windows Filtering Platform network event"

        return {
            "tenant_id": self.stress_tenant_id,
            "event_uid": event_uid,
            "timestamp": timestamp,
            "event_id": event_id,
            "source_ip": source_ip,
            "user": "SYSTEM",
            "message": message,
            "agent_id": f"LOCUST_{self.environment.runner.user_count if self.environment and self.environment.runner else 'NA'}",
            "agent_version": "locust-1.0",
            "raw_data": {
                "event_id": event_id,
                "source_ip": source_ip,
                "source": "locust",
                "tenant_id": self.stress_tenant_id,
            },
            "raw_event_data": {
                "event_id": event_id,
                "message": message,
                "timestamp": timestamp,
            },
            "processed_data": {
                "source": "locust",
                "severity": "LOW" if event_id in {4624, 3} else "MEDIUM",
            },
            "signature": "locust-dummy-signature",
        }

    @task
    def inject_log(self) -> None:
        if not self.csrf_token:
            raise RuntimeError("CSRF token missing for shared Locust session")

        payload = self._build_payload()
        headers = {"x-csrf-token": self.csrf_token, "Cookie": self.auth_cookie_header}

        with self.client.post(
            "/api/v1/logs/inject",
            json=payload,
            headers=headers,
            name="/api/v1/logs/inject",
            catch_response=True,
        ) as response:
            if response.status_code >= 400:
                response.failure(f"unexpected status {response.status_code}: {response.text}")
            else:
                response.success()
