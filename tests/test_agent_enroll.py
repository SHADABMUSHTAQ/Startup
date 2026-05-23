import asyncio
import copy
import uuid
from datetime import timedelta, timezone, datetime
from fastapi.testclient import TestClient
from app.main import app

from app.routes import auth as auth_module

import ecdsa


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

    async def hset(self, key, mapping=None):
        self.store[key] = mapping
        return True

    async def expire(self, key, seconds):
        return True


class FakeCollection:
    def __init__(self):
        self.docs = []

    async def find_one(self, query):
        for d in self.docs:
            match = True
            for k, v in query.items():
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

    async def count_documents(self, query):
        cnt = 0
        for d in self.docs:
            match = True
            for k, v in query.items():
                if d.get(k) != v:
                    match = False
                    break
            if match:
                cnt += 1
        return cnt

    async def insert_one(self, doc):
        self.docs.append(doc)
        class R: pass
        r = R()
        r.inserted_id = len(self.docs)
        return r

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


class FakeDB(dict):
    def __getitem__(self, item):
        if item not in self:
            self[item] = FakeCollection()
        return dict.__getitem__(self, item)


def test_enroll_token_lifecycle():
    fake_db = FakeDB()
    # create tenant record
    tenant_id = "TENANT_TEST"
    fake_db.setdefault("tenants", FakeCollection()).docs.append({"tenant_id": tenant_id, "max_endpoints": 3, "plan": "Enterprise"})

    # install fake redis and override app state
    fake_redis = FakeRedis()
    app.state.redis = fake_redis

    # override get_db and get_current_user
    def _get_db_override():
        return fake_db

    async def _current_user_override():
        return {"username": "admin@test.local", "tenant_id": tenant_id, "role": "admin", "endpoints": 3, "plan_type": "Enterprise"}

    app.dependency_overrides.clear()
    app.dependency_overrides[auth_module.get_db] = _get_db_override
    app.dependency_overrides[auth_module.get_current_user] = _current_user_override
    app.dependency_overrides[auth_module.require_premium_plan] = _current_user_override

    client = TestClient(app)
    # Create a valid access token and CSRF token so get_current_user/CSRF passes
    access_token = auth_module.create_access_token(
        data={"sub": "admin@test.local", "type": "user", "tenant_id": tenant_id, "role": "admin"},
        expires_delta=timedelta(minutes=15)
    )
    csrf = "csrf-test-token-123"
    client.cookies.set("warsoc_token", access_token)
    client.cookies.set("csrf_token", csrf)

    headers = {"x-csrf-token": csrf}

    # Generate a provisioning token as admin
    r = client.post("/api/v1/auth/agents/generate-token", headers=headers, json={"agent_id": "agent_test_id"})
    assert r.status_code == 200, r.text
    token = r.json().get("provisioning_token")
    assert token

    # Generate an ECDSA keypair for the agent
    sk = ecdsa.SigningKey.generate(curve=ecdsa.NIST256p)
    vk = sk.get_verifying_key()
    pub_pem = vk.to_pem().decode("utf-8")

    # Enroll agent using token as bearer
    enroll_payload = {
        "agent_id": "agent_test_id",
        "public_key": pub_pem,
        "hostname": "test-host",
        "mac_address": "00:11:22:33:44:55"
    }
    enroll_resp = client.post(
        "/api/v1/auth/agents/enroll",
        headers={"Authorization": f"Bearer {token}"},
        json=enroll_payload
    )
    assert enroll_resp.status_code == 201, enroll_resp.text
    agent_id = enroll_resp.json().get("agent_id")
    assert agent_id == "agent_test_id"

    # Token should be single-use: second enroll should fail
    enroll_resp2 = client.post(
        "/api/v1/auth/agents/enroll",
        headers={"Authorization": f"Bearer {token}"},
        json=enroll_payload
    )
    assert enroll_resp2.status_code == 401

    # Verify agent doc exists
    agents_coll = fake_db["agents"]
    assert any(d.get("agent_id") == agent_id for d in agents_coll.docs)
