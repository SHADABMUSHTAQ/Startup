"""
Pytest configuration and fixtures for WarSOC test suite.
All tests use async_client fixture and pytest-asyncio for async execution.
Database is Motor (async MongoDB) in test DB; Redis is flushed per test.
"""
import os
import sys
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit, urlunsplit

from dotenv import load_dotenv
load_dotenv()

# Establish isolated service targets before importing any application module.
_runtime_db_name = os.getenv("MONGODB_DB_NAME", "WarSOC_DB")
_test_db_name = os.getenv("TEST_MONGODB_DB_NAME", f"{_runtime_db_name}_pytest")
if _test_db_name == _runtime_db_name:
    raise RuntimeError("Pytest MongoDB database must differ from the runtime database")
os.environ["MONGODB_DB_NAME"] = _test_db_name

_runtime_redis_url = os.getenv("REDIS_URL", "redis://localhost:6379")
_parsed_redis_url = urlsplit(_runtime_redis_url)
_test_redis_url = os.getenv(
    "TEST_REDIS_URL",
    urlunsplit(
        (
            _parsed_redis_url.scheme,
            _parsed_redis_url.netloc,
            "/15",
            _parsed_redis_url.query,
            _parsed_redis_url.fragment,
        )
    ),
)
if _test_redis_url == _runtime_redis_url:
    raise RuntimeError("Pytest Redis URL must differ from the runtime Redis URL")
os.environ["REDIS_URL"] = _test_redis_url
os.environ["ENABLE_SELF_SIGNUP"] = "true"
os.environ.setdefault("SUPER_ADMIN_API_KEY", "warsoc-test-super-admin-key-2026")

import pytest
import pytest_asyncio

sys.path.append(os.path.dirname(os.path.dirname(__file__)))

from app.config.config import get_settings
from app.routes.auth import AGENT_TOKEN_EXPIRE_MINUTES, create_access_token, get_password_hash, resolve_tenant_retention_days
from motor.motor_asyncio import AsyncIOMotorClient
from httpx import AsyncClient, ASGITransport

from app.main import app as fastapi_app
from app.database import get_db, db_manager
from app.utils.redis_client import create_redis_client
from tests.helpers import ed25519_keypair_pem, provision_and_login_admin


# Disable MemoryLimitMiddleware for tests (host memory percent is non-deterministic)
async def _noop_dispatch(self, request, call_next):
    return await call_next(request)

try:
    from app.main import MemoryLimitMiddleware
    MemoryLimitMiddleware.dispatch = _noop_dispatch
except Exception:
    pass


@pytest.fixture(scope="session")
def settings():
    """Return settings already bound to isolated test services."""
    runtime_settings = get_settings()
    if runtime_settings.mongodb_db_name == _runtime_db_name:
        raise RuntimeError("Refusing to run tests against the runtime MongoDB database")
    if runtime_settings.redis_url == _runtime_redis_url:
        raise RuntimeError("Refusing to run tests against the runtime Redis database")
    return runtime_settings


@pytest_asyncio.fixture(scope="function")
async def mongo_client(settings):
    """Function-scoped Motor client created on the active test event loop."""
    client = AsyncIOMotorClient(settings.mongodb_uri)
    yield client
    client.close()


@pytest_asyncio.fixture(scope="function", autouse=True)
async def override_db_dependency(mongo_client, settings, redis_client):
    """Override get_db() to return the test Motor db instance and set app.state.redis to None."""
    test_db = mongo_client[settings.mongodb_db_name]
    previous_db = db_manager.db
    previous_client = db_manager.client

    async def _get_test_db():
        return test_db

    fastapi_app.dependency_overrides[get_db] = _get_test_db
    db_manager.client = mongo_client
    db_manager.db = test_db

    # Bind the active test Redis client so routes that check `if redis:` use it
    fastapi_app.state.redis = redis_client

    yield

    fastapi_app.dependency_overrides.pop(get_db, None)
    db_manager.client = previous_client
    db_manager.db = previous_db
    fastapi_app.state.redis = None


@pytest_asyncio.fixture(scope="function", autouse=True)
async def db(mongo_client, settings):
    """Function-scoped fixture to provide clean db per test."""
    db = mongo_client[settings.mongodb_db_name]
    collections = [
        "agents",
        "analysis_results",
        "archive_retrieval_allowances",
        "archive_retrieval_requests",
        "archive_retrieval_usage",
        "archive_storage_daily",
        "source_envelopes_siem",
        "source_envelopes_peca",
        "source_envelopes_fbr",
        "agent_coverage_observations",
        "legal_holds",
        "evidence_hold_audit",
        "evidence_retention_fences",
        "evidence_cases",
        "evidence_case_items",
        "evidence_custody_events",
        "evidence_exports",
        "source_evidence_outbox",
        "billing",
        "csv_uploads",
        "dead_letter_logs",
        "fbr_pos_logs",
        "fbr_pos_summaries",
        "fbr_vault",
        "firewall_rules",
        "logs",
        "management_audit",
        "notifications",
        "network_relay_batches",
        "network_relay_chain_resets",
        "network_relay_device_status",
        "network_relays",
        "peca_forensic_logs",
        "incident_audit_log",
        "security_incident_occurrences",
        "security_incidents",
        "security_alerts",
        "siem_cold_vault",
        "storage_archives",
        "system_audit",
        "detection_engine_connectors",
        "detection_rule_registry",
        "detection_engine_agent_bindings",
        "detection_shadow_observations",
        "detection_engine_observations",
        "detection_candidates_quarantine",
        "detection_dispatch_outbox",
        "detection_dispatch_dlq",
        "detection_coverage_gaps",
        "detection_projector_state",
        "tenants",
        "used_provisioning_tokens",
        "users",
    ]
    for c in collections:
        try:
            await db[c].delete_many({})
        except Exception:
            pass

    yield db

    for c in collections:
        try:
            await db[c].delete_many({})
        except Exception:
            pass


@pytest_asyncio.fixture(scope="function")
async def redis_client(settings):
    """Function-scoped fixture for Redis (auto cleanup)."""
    r = create_redis_client(settings.redis_url)
    try:
        await r.flushdb()
    except Exception:
        pass
    yield r
    try:
        await r.flushdb()
    except Exception:
        pass
    await r.aclose()


async def _provision_mock_tenant(db, redis, *, tenant_suffix: str, plan_type: str = "Enterprise") -> dict:
    tenant_id = f"WARSOC_{tenant_suffix.upper()}"
    agent_id = f"{tenant_id}_AGENT"
    hostname = f"{tenant_suffix.lower()}-host"

    private_key_pem, public_key = ed25519_keypair_pem()

    tenant_doc = {
        "tenant_id": tenant_id,
        "company_name": f"{tenant_suffix} Holdings",
        "plan": plan_type,
        "plan_type": plan_type,
        "retention_days": resolve_tenant_retention_days(plan_type),
        "status": "active",
        "created_at": datetime.now(timezone.utc),
    }
    user_doc = {
        "username": f"{tenant_suffix.lower()}_admin",
        "email": f"{tenant_suffix.lower()}_admin@example.com",
        "full_name": f"{tenant_suffix} Admin",
        "hashed_password": get_password_hash("Password123!Secure"),
        "tenant_id": tenant_id,
        "plan_type": plan_type,
        "role": "admin",
        "compliance_packs": ["eto_forensic", "fbr_pos"] if plan_type.lower() != "free" else [],
        "has_active_plan": True,
        "created_at": datetime.now(timezone.utc),
    }
    agent_doc = {
        "agent_id": agent_id,
        "tenant_id": tenant_id,
        "hostname": hostname,
        "public_key": public_key,
        "approved": True,
        "status": "active",
        "created_at": datetime.now(timezone.utc),
    }

    await db["tenants"].update_one({"tenant_id": tenant_id}, {"$set": tenant_doc}, upsert=True)
    await db["users"].update_one({"username": user_doc["username"]}, {"$set": user_doc}, upsert=True)
    await db["agents"].update_one({"agent_id": agent_id}, {"$set": agent_doc}, upsert=True)
    agent_jwt = create_access_token(
        data={"sub": agent_id, "type": "agent", "tenant_id": tenant_id},
        expires_delta=timedelta(minutes=AGENT_TOKEN_EXPIRE_MINUTES),
    )

    if redis is not None:
        await redis.set(f"tenant_plan:{tenant_id}", plan_type)
        await redis.set(f"tenant_features:{tenant_id}", "SIEM,fbr_pos,peca_forensic")
        await redis.hset(
            f"warsoc:agent_cache:{agent_id}",
            mapping={"tenant_id": tenant_id, "public_key": public_key, "approved": "True"},
        )
        await redis.expire(f"warsoc:agent_cache:{agent_id}", 3600)

    return {
        "tenant_id": tenant_id,
        "agent_id": agent_id,
        "hostname": hostname,
        "public_key": public_key,
        "private_key_pem": private_key_pem,
        "agent_jwt": agent_jwt,
        "username": user_doc["username"],
        "password": "Password123!Secure",
        "plan_type": plan_type,
    }


@pytest_asyncio.fixture(scope="function")
async def mock_tenant_a(db, redis_client):
    return await _provision_mock_tenant(db, redis_client, tenant_suffix="TENANT_A", plan_type="Enterprise")


@pytest_asyncio.fixture(scope="function")
async def mock_tenant_b(db, redis_client):
    return await _provision_mock_tenant(db, redis_client, tenant_suffix="TENANT_B", plan_type="Enterprise")


@pytest_asyncio.fixture(scope="function")
async def clean_slate(db, redis_client):
    collections = [
        "agents",
        "analysis_results",
        "billing",
        "csv_uploads",
        "dead_letter_logs",
        "fbr_pos_logs",
        "fbr_pos_summaries",
        "fbr_vault",
        "firewall_rules",
        "logs",
        "management_audit",
        "notifications",
        "network_relay_batches",
        "network_relay_chain_resets",
        "network_relays",
        "peca_forensic_logs",
        "incident_audit_log",
        "security_incident_occurrences",
        "security_incidents",
        "security_alerts",
        "siem_cold_vault",
        "system_audit",
        "evidence_cases",
        "evidence_case_items",
        "evidence_custody_events",
        "evidence_exports",
        "tenants",
        "used_provisioning_tokens",
        "users",
    ]
    for collection_name in collections:
        try:
            await db[collection_name].delete_many({})
        except Exception:
            pass

    try:
        await redis_client.flushdb()
    except Exception:
        pass

    yield

    for collection_name in collections:
        try:
            await db[collection_name].delete_many({})
        except Exception:
            pass

    try:
        await redis_client.flushdb()
    except Exception:
        pass


@pytest_asyncio.fixture(scope="function")
async def async_client(redis_client, db):
    """Async HTTP client using ASGITransport for route testing."""
    transport = ASGITransport(app=fastapi_app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as ac:
        yield ac


@pytest_asyncio.fixture(scope="function")
async def auth_headers(async_client):
    """Provision an active B2B tenant admin and return browser auth headers."""
    session = await provision_and_login_admin(async_client, "test_integ")
    return {"x-csrf-token": session["csrf_token"]}


@pytest.fixture(scope="function")
def agent_public_key_pem():
    """Return a valid Ed25519 public key for enrollment tests."""
    return ed25519_keypair_pem()[1]


@pytest_asyncio.fixture(scope="function")
async def free_auth_headers(async_client):
    """Create an inactive self-signup account for premium-access denial tests."""
    payload = {
        "username": "free_integ_user",
        "password": "Password123!Secure",
        "email": "free_integ@example.com",
        "full_name": "Free Integration Tester",
        "plan_type": "Free",
    }
    signup = await async_client.post("/api/v1/auth/signup", json=payload)
    assert signup.status_code == 201, signup.text
    login = await async_client.post(
        "/api/v1/auth/login",
        json={"username": payload["username"], "password": payload["password"]},
    )
    assert login.status_code == 200, login.text
    token = login.cookies.get("warsoc_token")
    csrf_token = login.json().get("csrf_token", "")
    async_client.cookies.set("warsoc_token", token)
    async_client.cookies.set("csrf_token", csrf_token)
    return {"x-csrf-token": csrf_token}


@pytest_asyncio.fixture(scope="function")
async def client(async_client):
    """Alias for async_client for backward compatibility with existing tests."""
    return async_client


@pytest_asyncio.fixture(scope="function")
async def authenticated_user(auth_headers):
    """Alias for auth_headers for backward compatibility with existing tests."""
    return auth_headers
