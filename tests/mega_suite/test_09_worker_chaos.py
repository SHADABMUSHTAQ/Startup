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

import workers.fbr_worker as fbr_worker
import workers.peca_worker as peca_worker


@dataclass
class FakeRedis:
    batches: list[list[tuple[str, dict[str, str]]]]
    xack_calls: list[tuple[str, str, str]] = field(default_factory=list)
    xgroup_calls: int = 0

    async def xgroup_create(self, *args, **kwargs):
        self.xgroup_calls += 1
        return True

    async def xreadgroup(self, *args, **kwargs):
        if not self.batches:
            raise asyncio.CancelledError()
        return self.batches.pop(0)

    async def xack(self, stream, group, message_id):
        self.xack_calls.append((stream, group, message_id))
        return 1


@dataclass
class FakeTenantCollection:
    plan: str

    async def find_one(self, query):
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


@dataclass
class FakeFbrCollection:
    docs: list[dict[str, Any]] = field(default_factory=list)
    seen_ids: set[str] = field(default_factory=set)
    fail_on_insert: bool = False
    insert_calls: int = 0

    async def insert_many(self, documents, ordered=False):
        self.insert_calls += 1
        if self.fail_on_insert:
            raise ConnectionError("mongo blackout")

        write_errors = []
        inserted_any = False
        for document in documents:
            doc_id = document.get("_id")
            if doc_id in self.seen_ids:
                write_errors.append({"code": 11000, "errmsg": "duplicate key"})
                continue
            self.seen_ids.add(doc_id)
            self.docs.append(document)
            inserted_any = True

        if write_errors:
            raise BulkWriteError({"writeErrors": write_errors, "nInserted": 1 if inserted_any else 0})

        return {"inserted_ids": [doc.get("_id") for doc in documents]}


def _patch_peca_worker(monkeypatch, fake_redis, logs_col, tenants_col):
    async def fake_from_url(*args, **kwargs):
        return fake_redis

    async def fake_get_mongo_collections():
        return logs_col, tenants_col

    monkeypatch.setattr(peca_worker.aioredis, "from_url", fake_from_url)
    monkeypatch.setattr(peca_worker, "get_mongo_collections", fake_get_mongo_collections)
    monkeypatch.setattr(peca_worker, "WATCH_IDS", {"4625"})


def _patch_fbr_worker(monkeypatch, fake_redis, logs_col, tenants_col):
    async def fake_from_url(*args, **kwargs):
        return fake_redis

    async def fake_get_mongo_collections():
        return logs_col, tenants_col

    monkeypatch.setattr(fbr_worker.aioredis, "from_url", fake_from_url)
    monkeypatch.setattr(fbr_worker, "get_mongo_collections", fake_get_mongo_collections)
    monkeypatch.setattr(fbr_worker, "WATCH_IDS", {"4663"})
    monkeypatch.setattr(fbr_worker, "BATCH_SIZE", 1)
    monkeypatch.setattr(fbr_worker, "BATCH_TIMEOUT", 999)


@pytest.mark.asyncio
@pytest.mark.chaos
async def test_peca_worker_mongo_blackout_does_not_ack(monkeypatch):
    payload = {"tenant_id": "TENANT-PECA", "event_id": "4625", "message": "failed logon"}
    fake_redis = FakeRedis([[("raw_logs_queue", [("1-0", {"payload": json.dumps(payload)})])]])
    logs_col = FakePecaCollection(fail_on_insert=True)
    tenants_col = FakeTenantCollection(plan="PECA_PLAN")

    _patch_peca_worker(monkeypatch, fake_redis, logs_col, tenants_col)

    await peca_worker.main()

    assert logs_col.insert_calls == 1
    assert logs_col.docs == []
    assert fake_redis.xack_calls == []


@pytest.mark.asyncio
@pytest.mark.chaos
async def test_peca_worker_duplicate_delivery_is_idempotent(monkeypatch):
    payload = {"tenant_id": "TENANT-PECA", "event_id": "4625", "message": "failed logon"}
    fake_redis = FakeRedis([
        [("raw_logs_queue", [("1-0", {"payload": json.dumps(payload)})])],
        [("raw_logs_queue", [("1-0", {"payload": json.dumps(payload)})])],
    ])
    logs_col = FakePecaCollection()
    tenants_col = FakeTenantCollection(plan="PECA_PLAN")

    _patch_peca_worker(monkeypatch, fake_redis, logs_col, tenants_col)

    worker_a = asyncio.create_task(peca_worker.main())
    worker_b = asyncio.create_task(peca_worker.main())
    await asyncio.wait_for(asyncio.gather(worker_a, worker_b), timeout=5)

    assert logs_col.insert_calls == 2
    assert len(logs_col.docs) == 1
    assert len(fake_redis.xack_calls) == 2


@pytest.mark.asyncio
@pytest.mark.chaos
async def test_fbr_worker_mongo_blackout_does_not_ack(monkeypatch):
    payload = {"tenant_id": "TENANT-FBR", "event_id": "4663", "message": "sale event"}
    fake_redis = FakeRedis([[("raw_logs_queue", [("2-0", {"payload": json.dumps(payload)})])]])
    logs_col = FakeFbrCollection(fail_on_insert=True)
    tenants_col = FakeTenantCollection(plan="FBR_PLAN")

    _patch_fbr_worker(monkeypatch, fake_redis, logs_col, tenants_col)

    await fbr_worker.main()

    assert logs_col.insert_calls == 1
    assert logs_col.docs == []
    assert fake_redis.xack_calls == []


@pytest.mark.asyncio
@pytest.mark.chaos
async def test_fbr_worker_duplicate_delivery_is_idempotent(monkeypatch):
    payload = {"tenant_id": "TENANT-FBR", "event_id": "4663", "message": "sale event"}
    fake_redis = FakeRedis([
        [("raw_logs_queue", [("2-0", {"payload": json.dumps(payload)})])],
        [("raw_logs_queue", [("2-0", {"payload": json.dumps(payload)})])],
    ])
    logs_col = FakeFbrCollection()
    tenants_col = FakeTenantCollection(plan="FBR_PLAN")

    _patch_fbr_worker(monkeypatch, fake_redis, logs_col, tenants_col)

    worker_a = asyncio.create_task(fbr_worker.main())
    worker_b = asyncio.create_task(fbr_worker.main())
    await asyncio.wait_for(asyncio.gather(worker_a, worker_b), timeout=5)

    assert logs_col.insert_calls == 2
    assert len(logs_col.docs) == 1
    assert len(fake_redis.xack_calls) == 2