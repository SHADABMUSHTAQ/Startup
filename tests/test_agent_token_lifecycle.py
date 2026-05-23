import asyncio
import copy
import uuid
from datetime import datetime, timezone, timedelta
import ecdsa
from fastapi.testclient import TestClient

from app.main import app
from app.routes.auth import _validate_public_key_pem
from app.routes import auth as auth_module


# --- Fake Redis and Fake DB ---
class FakeRedis:
    def __init__(self):
        self.store = {}

    async def set(self, key, value, ex=None):
        self.store[key] = value
        return True

    async def setex(self, key, ttl, value):
        self.store[key] = value
        return True

    async def get(self, key):
        return self.store.get(key)

    async def delete(self, key):
        self.store.pop(key, None)
        return True

    async def exists(self, key):
        return 1 if key in self.store else 0


class FakeCollection:
    def __init__(self):
        self.docs = []

    async def find_one(self, q):
        for d in self.docs:
            match = True
            for k, v in q.items():
                if k == "used_at" and v == {"$exists": False}:
                    if "used_at" in d:
                        match = False
                        break
                elif d.get(k) != v:
                    match = False
                    break
            if match:
                return d
        return None

    async def find_one_and_update(self, filter, update, return_document=None, **kwargs):
        found_doc = None
        for d in self.docs:
            match = True
            for k, v in filter.items():
                if k == "used_at" and v == {"$exists": False}:
                    if "used_at" in d:
                        match = False
                        break
                elif d.get(k) != v:
                    match = False
                    break
            if match:
                found_doc = d
                break

        if found_doc is None:
            return None

        old_doc = copy.deepcopy(found_doc)

        if "$set" in update:
            for k, v in update["$set"].items():
                found_doc[k] = v

        return old_doc

    async def insert_one(self, doc):
        self.docs.append(doc)
        class R: pass
        r = R()
        r.inserted_id = uuid.uuid4()
        return r

    async def count_documents(self, q):
        c = 0
        for d in self.docs:
            ok = True
            for k, v in q.items():
                if d.get(k) != v:
                    ok = False
                    break
            if ok:
                c += 1
        return c

    async def update_one(self, filter, update, upsert=False):
        found_doc = None
        for d in self.docs:
            match = True
            for k, v in filter.items():
                if d.get(k) != v:
                    match = False
                    break
            if match:
                found_doc = d
                break

        if found_doc is None:
            if upsert:
                new_doc = {}
                if "$set" in update:
                    new_doc.update(update["$set"])
                for k, v in filter.items():
                    new_doc[k] = v
                self.docs.append(new_doc)
            return None

        if "$set" in update:
            for k, v in update["$set"].items():
                found_doc[k] = v
        return None

    async def delete_one(self, filter):
        to_remove = None
        for d in self.docs:
            match = True
            for k, v in filter.items():
                if d.get(k) != v:
                    match = False
                    break
            if match:
                to_remove = d
                break
        if to_remove:
            self.docs.remove(to_remove)
        return None


class FakeDB:
    def __init__(self):
        self._cols = {
            "tenants": FakeCollection(),
            "agents": FakeCollection(),
            "used_provisioning_tokens": FakeCollection(),
        }

    def __getitem__(self, name):
        if name not in self._cols:
            self._cols[name] = FakeCollection()
        return self._cols[name]


# --- Test ---

def override_get_current_user():
    return {"username": "admin", "tenant_id": "T1", "role": "admin", "plan_type": "Enterprise"}


def test_token_lifecycle(monkeypatch):
    # Setup fake redis and db
    fake_redis = FakeRedis()
    fake_db = FakeDB()

    # Insert tenant with max_endpoints=2
    tenant = {"tenant_id": "T1", "max_endpoints": 2}
    asyncio.get_event_loop().run_until_complete(fake_db["tenants"].insert_one(tenant))

    # Attach fakes to app state
    app.dependency_overrides.clear()
    
    def _get_db_override():
        return fake_db

    async def _current_user_override():
        return override_get_current_user()

    app.dependency_overrides[auth_module.get_db] = _get_db_override
    app.dependency_overrides[auth_module.get_current_user] = _current_user_override
    app.dependency_overrides[auth_module.require_premium_plan] = _current_user_override

    # FastAPI app state requires attribute set on startup; set here
    app.state.redis = fake_redis

    client = TestClient(app)

    # Generate token via endpoint
    access_token = auth_module.create_access_token(
        data={"sub": "admin", "type": "user", "tenant_id": "T1", "role": "admin"},
        expires_delta=timedelta(minutes=15)
    )
    csrf = "csrf-test-token-123"
    client.cookies.set("warsoc_token", access_token)
    client.cookies.set("csrf_token", csrf)
    headers = {"x-csrf-token": csrf}

    resp = client.post("/api/v1/auth/agents/generate-token", headers=headers, json={"agent_id": "T1-agent"})
    assert resp.status_code == 200, resp.text
    data = resp.json()
    token = data.get("provisioning_token")
    assert token

    # Create ECDSA public key
    sk = ecdsa.SigningKey.generate(curve=ecdsa.NIST256p)
    vk_pem = sk.get_verifying_key().to_pem().decode()
    assert _validate_public_key_pem(vk_pem) == vk_pem

    # Enroll agent
    enroll_payload = {
        "agent_id": "T1-agent",
        "public_key": vk_pem,
        "hostname": "test-host",
        "mac_address": "00:00:00:00:00:02"
    }
    resp2 = client.post(
        "/api/v1/auth/agents/enroll",
        headers={"Authorization": f"Bearer {token}"},
        json=enroll_payload
    )
    assert resp2.status_code == 201, resp2.text
    a = resp2.json()
    assert "agent_id" in a

    # Token must be blacklisted in fake redis
    blacklisted_key = None
    # Let's inspect fake redis store to see if any warsoc:blacklist key is set
    for k in fake_redis.store.keys():
        if "warsoc:blacklist:" in k:
            blacklisted_key = k
            break
    assert blacklisted_key is not None

    # Agent present in fake DB
    found = None
    for d in fake_db["agents"].docs:
        if d.get("agent_id") == "T1-agent":
            found = d
            break
    assert found is not None
    assert found["tenant_id"] == "T1"