"""
Layer 8: PECA and FBR chaos tests.

These tests verify that the forensic and financial workers do not XACK on
MongoDB blackout, and that duplicate Redis deliveries are handled idempotently
through msg_id -> _id deduplication.
"""

import asyncio
import json
from dataclasses import dataclass, field
from typing import Any

import pytest
from pymongo.errors import BulkWriteError, DuplicateKeyError

from app.workers import fbr_worker
from app.workers import peca_worker


@dataclass
class FakeRedis:
    batches: list[list[tuple[str, dict[str, str]]]]
    xack_calls: list[tuple[str, str, str]] = field(default_factory=list)
    xgroup_calls: int = 0
    _time_offset: float = 0.0
    _empty_rounds: dict = field(default_factory=dict)

    async def xgroup_create(self, *args, **kwargs):
        self.xgroup_calls += 1
        return True

    async def xadd(self, stream, fields, maxlen=None):
        print(f"XADD called: {stream} {fields}")
        return "12345-0"

    async def xreadgroup(self, *args, **kwargs):
        if not self.batches:
            self._time_offset += 4.0
            await asyncio.sleep(0.01)
            # Cancel after a few empty rounds to stop the worker
            task = asyncio.current_task()
            rounds = self._empty_rounds.get(task, 0) + 1
            self._empty_rounds[task] = rounds
            if rounds > 4:
                raise asyncio.CancelledError()
            return []
        return self.batches.pop(0)

    async def xpending_range(self, *args, **kwargs):
        return []

    async def xack(self, stream, group, message_id):
        self.xack_calls.append((stream, group, message_id))
        return 1

    async def get(self, key):
        if key.startswith("tenant_features:"):
            if "TENANT-PECA" in key: return "peca_forensic"
            if "TENANT-FBR" in key: return "fbr_pos"
            return "SIEM"
        return None

    async def expire(self, name, time):
        print(f"EXPIRE called: {name} {time}")
        return True

    def pipeline(self, **kwargs):
        outer_self = self
        class FakePipeline:
            def hgetall(self, *args): pass
            def sadd(self, *args): pass
            def xack(self, stream, group, message_id):
                print(f"XACK called: {stream} {group} {message_id}")
                outer_self.xack_calls.append((stream, group, message_id))
            async def execute(self): pass
            async def __aenter__(self): return self
            async def __aexit__(self, exc_type, exc_val, exc_tb): pass
        return FakePipeline()

@dataclass
class FakeTenantCollection:
    plan: str

    async def find_one(self, query, projection=None):
        tenant_id = query.get("tenant_id")
        if tenant_id:
            return {"tenant_id": tenant_id, "subscription_plan": self.plan}
        return None


@dataclass
class FakePecaCollection:
    docs: list[dict[str, Any]] = field(default_factory=list)
    seen_ids: set[str] = field(default_factory=set)
    fail_on_insert: bool = False
    insert_calls: int = 0

    async def insert_one(self, document):
        self.insert_calls += 1
        if self.fail_on_insert:
            raise ConnectionError("mongo blackout")
        doc_id = document.get("_id")
        if doc_id in self.seen_ids:
            raise DuplicateKeyError("E11000 duplicate key error")
        self.seen_ids.add(doc_id)
        self.docs.append(document)
        return {"inserted_id": doc_id}

    async def insert_many(self, documents, ordered=False):
        self.insert_calls += len(documents)
        if self.fail_on_insert:
            raise ConnectionError("mongo blackout")
        for doc in documents:
            self.docs.append(doc)

    async def bulk_write(self, ops, ordered=False):
        self.insert_calls += len(ops)
        if self.fail_on_insert:
            raise ConnectionError("mongo blackout")
        for op in ops:
            if hasattr(op, "_filter") and hasattr(op, "_doc"):
                filter_doc = op._filter
                update_doc = op._doc.get("$set", {})
                match_found = False
                for existing_doc in self.docs:
                    match = True
                    for k, v in filter_doc.items():
                        if existing_doc.get(k) != v:
                            match = False
                            break
                    if match:
                        existing_doc.update(update_doc)
                        match_found = True
                        break
                if not match_found and getattr(op, "_upsert", False):
                    new_doc = update_doc.copy()
                    new_doc.update(filter_doc)
                    self.docs.append(new_doc)
            else:
                self.docs.append(op._doc if hasattr(op, "_doc") else {})

@dataclass
class FakeFbrCollection:
    docs: list[dict[str, Any]] = field(default_factory=list)
    seen_ids: set[str] = field(default_factory=set)
    fail_on_insert: bool = False
    insert_calls: int = 0

    async def bulk_write(self, ops, ordered=False):
        self.insert_calls += len(ops)
        if self.fail_on_insert:
            raise ConnectionError("mongo blackout")
        for op in ops:
            if hasattr(op, "_filter") and hasattr(op, "_doc"):
                filter_doc = op._filter
                update_doc = op._doc.get("$set", {})
                match_found = False
                for existing_doc in self.docs:
                    match = True
                    for k, v in filter_doc.items():
                        if existing_doc.get(k) != v:
                            match = False
                            break
                    if match:
                        existing_doc.update(update_doc)
                        match_found = True
                        break
                if not match_found and getattr(op, "_upsert", False):
                    new_doc = update_doc.copy()
                    new_doc.update(filter_doc)
                    self.docs.append(new_doc)
            else:
                self.docs.append(op._doc if hasattr(op, "_doc") else {})

    async def find(self, filter, projection=None):
        for doc in self.docs:
            yield doc

    async def insert_one(self, document):
        self.insert_calls += 1
        if self.fail_on_insert:
            raise ConnectionError("mongo blackout")
        doc_id = document.get("_id")
        if doc_id in self.seen_ids:
            raise DuplicateKeyError("E11000 duplicate key error")
        self.seen_ids.add(doc_id)
        self.docs.append(document)
        return {"inserted_id": doc_id}

    async def insert_many(self, documents, ordered=False):
        self.insert_calls += len(documents)
        if self.fail_on_insert:
            raise ConnectionError("mongo blackout")
        for doc in documents:
            self.docs.append(doc)

        return {"inserted_ids": [doc.get("_id") for doc in documents]}


def _patch_peca_worker(monkeypatch, fake_redis, logs_col, tenants_col):
    async def fake_from_url(*args, **kwargs):
        return fake_redis

    monkeypatch.setattr(peca_worker.Redis, "from_url", fake_from_url)

    class FakeDatabase:
        def __getattr__(self, name):
            if name == "peca_forensic_logs": return logs_col
            if name == "peca_vault": return logs_col
            if name == "dead_letter_logs": return logs_col
            if name == "users": return tenants_col
            if name == "tenants": return tenants_col
            return logs_col
        def __getitem__(self, name):
            return self.__getattr__(name)

    class FakeMongoClient:
        def __init__(self, *args, **kwargs):
            pass
        def __getitem__(self, name):
            return FakeDatabase()

    monkeypatch.setattr(peca_worker, "AsyncIOMotorClient", FakeMongoClient)

    import time
    original_time = time.time
    def fake_time():
        return original_time() + fake_redis._time_offset
    monkeypatch.setattr(peca_worker.time, "time", fake_time)




def _patch_fbr_worker(monkeypatch, fake_redis, logs_col, tenants_col):
    async def fake_from_url(*args, **kwargs):
        return fake_redis

    monkeypatch.setattr(fbr_worker.Redis, "from_url", fake_from_url)
    async def _fake_validate_fbr(*args, **kwargs):
        return True, None
    monkeypatch.setattr(fbr_worker, "_validate_stream_signature", _fake_validate_fbr)
    async def _fake_project_incident(*args, **kwargs):
        return {}
    # Incident projection has its own contract tests. These chaos cases isolate
    # FBR evidence durability and must not count incident-ledger writes as FBR
    # evidence inserts.
    monkeypatch.setattr(fbr_worker, "project_and_publish_incident", _fake_project_incident)
    class FakeDatabase:
        def __getattr__(self, name):
            if name == "fbr_pos_logs": return logs_col
            if name == "fbr_vault": return logs_col
            if name == "fbr_pos_summaries": return logs_col
            if name == "dead_letter_logs": return logs_col
            if name == "users": return tenants_col
            if name == "tenants": return tenants_col
            return logs_col
        def __getitem__(self, name):
            return self.__getattr__(name)

    class FakeMongoClient:
        def __init__(self, *args, **kwargs):
            pass
        def __getitem__(self, name):
            return FakeDatabase()

    monkeypatch.setattr(fbr_worker, "AsyncIOMotorClient", FakeMongoClient)

    import time
    original_time = time.time
    def fake_time():
        return original_time() + fake_redis._time_offset
    monkeypatch.setattr(fbr_worker.time, "time", fake_time)



@pytest.mark.asyncio
@pytest.mark.chaos
async def test_peca_worker_mongo_blackout_does_not_ack(monkeypatch):
    payload = {"tenant_id": "TENANT-PECA", "event_id": "4625", "message": "failed logon", "event_uid": "static-uid-peca", "agent_id": "AGENT-X", "source_assurance": "agent_signed", "signature_verified": True}
    fake_redis = FakeRedis([[("raw_logs_queue", [("1-0", {"payload": json.dumps(payload)})])]])
    logs_col = FakePecaCollection(fail_on_insert=True)
    tenants_col = FakeTenantCollection(plan="PECA_PLAN")

    _patch_peca_worker(monkeypatch, fake_redis, logs_col, tenants_col)

    try:
        await peca_worker.eto_worker()
    except asyncio.CancelledError:
        pass

    assert logs_col.insert_calls == 1
    assert logs_col.docs == []
    assert len(fake_redis.xack_calls) == 0


@pytest.mark.asyncio
@pytest.mark.chaos
async def test_peca_worker_duplicate_delivery_is_idempotent(monkeypatch):
    payload = {"tenant_id": "TENANT-PECA", "event_id": "4625", "message": "failed logon", "event_uid": "static-uid-peca", "agent_id": "AGENT-X", "source_assurance": "agent_signed", "signature_verified": True}
    fake_redis = FakeRedis([
        [("raw_logs_queue", [("1-0", {"payload": json.dumps(payload)})])],
        [("raw_logs_queue", [("1-0", {"payload": json.dumps(payload)})])],
    ])
    logs_col = FakePecaCollection()
    tenants_col = FakeTenantCollection(plan="PECA_PLAN")

    _patch_peca_worker(monkeypatch, fake_redis, logs_col, tenants_col)

    worker_a = asyncio.create_task(peca_worker.eto_worker())
    worker_b = asyncio.create_task(peca_worker.eto_worker())
    try:
        await asyncio.wait_for(asyncio.gather(worker_a, worker_b), timeout=5)
    except asyncio.CancelledError:
        pass

    assert logs_col.insert_calls == 2
    assert len(logs_col.docs) == 1
    assert len(fake_redis.xack_calls) == 2


@pytest.mark.asyncio
@pytest.mark.chaos
async def test_fbr_worker_mongo_blackout_does_not_ack(monkeypatch):
    from datetime import datetime, timezone
    timestamp = datetime.now(timezone.utc).isoformat()
    payload = {"tenant_id": "TENANT-FBR", "event_id": "FBR-INV-DEL", "message": "sale event", "event_uid": "static-uid-fbr", "agent_id": "AGENT-X", "timestamp": timestamp, "source_assurance": "agent_signed", "signature_verified": True}
    fake_redis = FakeRedis([[("raw_logs_queue", [("2-0", {"payload": json.dumps(payload)})])]])
    logs_col = FakeFbrCollection(fail_on_insert=True)
    tenants_col = FakeTenantCollection(plan="FBR_PLAN")

    _patch_fbr_worker(monkeypatch, fake_redis, logs_col, tenants_col)

    try:
        await fbr_worker.fbr_worker()
    except asyncio.CancelledError:
        pass

    assert logs_col.insert_calls == 1
    assert logs_col.docs == []
    assert len(fake_redis.xack_calls) == 0


@pytest.mark.asyncio
@pytest.mark.chaos
async def test_fbr_worker_duplicate_delivery_is_idempotent(monkeypatch):
    from datetime import datetime, timezone
    timestamp = datetime.now(timezone.utc).isoformat()
    payload = {"tenant_id": "TENANT-FBR", "event_id": "FBR-INV-DEL", "message": "sale event", "event_uid": "static-uid-fbr", "agent_id": "AGENT-X", "timestamp": timestamp, "source_assurance": "agent_signed", "signature_verified": True}
    fake_redis = FakeRedis([
        [("raw_logs_queue", [("2-0", {"payload": json.dumps(payload)})])],
        [("raw_logs_queue", [("2-0", {"payload": json.dumps(payload)})])],
    ])
    logs_col = FakeFbrCollection()
    tenants_col = FakeTenantCollection(plan="FBR_PLAN")

    _patch_fbr_worker(monkeypatch, fake_redis, logs_col, tenants_col)

    worker_a = asyncio.create_task(fbr_worker.fbr_worker())
    worker_b = asyncio.create_task(fbr_worker.fbr_worker())
    try:
        await asyncio.wait_for(asyncio.gather(worker_a, worker_b), timeout=5)
    except asyncio.CancelledError:
        pass

    assert logs_col.insert_calls == 4
    assert len(logs_col.docs) == 2
    assert len(fake_redis.xack_calls) == 2
