"""
Layer 8: Chaos and failure-mode tests.

These tests exercise the worker code under MongoDB blackout and duplicate
Redis stream delivery conditions so the suite reflects actual resilience
coverage instead of only happy-path API checks.
"""

import asyncio
import json
from dataclasses import dataclass, field
from typing import Any

import pytest

import workers.siem_worker as siem_worker


@dataclass
class FakeCollection:
    docs: list[dict[str, Any]] = field(default_factory=list)
    fail_on_insert: bool = False
    fail_mode: str = "connection"  # "connection" or "duplicate"
    insert_calls: int = 0
    seen_ids: set = field(default_factory=set)

    async def insert_one(self, document):
        from pymongo.errors import DuplicateKeyError
        
        self.insert_calls += 1
        if self.fail_on_insert:
            if self.fail_mode == "duplicate":
                raise DuplicateKeyError("E11000 duplicate key error")
            else:
                raise ConnectionError("mongo blackout")
        
        # Simulate MongoDB _id uniqueness constraint
        doc_id = document.get("_id")
        if doc_id and doc_id in self.seen_ids:
            raise DuplicateKeyError(f"E11000 duplicate key error for _id: {doc_id}")
        
        if doc_id:
            self.seen_ids.add(doc_id)
        
        self.docs.append(document)
        return {"inserted_id": doc_id or f"id-{self.insert_calls}"}

    async def insert_many(self, documents):
        for document in documents:
            await self.insert_one(document)

    async def find_one(self, query):
        if query.get("tenant_id") == "TENANT-CHAOS":
            return {"tenant_id": "TENANT-CHAOS", "subscription_plan": "SIEM_ONLY"}
        return None


class FakeRedis:
    def __init__(self, batches):
        self.batches = list(batches)
        self.xack_calls = []
        self.publish_calls = []
        self.xgroup_calls = 0

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

    async def publish(self, channel, message):
        self.publish_calls.append((channel, message))
        return 1


def _patch_siem_worker(monkeypatch, fake_redis, logs_col, alerts_col, tenants_col):
    async def fake_from_url(*args, **kwargs):
        return fake_redis

    async def fake_get_mongo_collections():
        return logs_col, alerts_col, tenants_col

    monkeypatch.setattr(siem_worker.aioredis, "from_url", fake_from_url)
    monkeypatch.setattr(siem_worker, "get_mongo_collections", fake_get_mongo_collections)
    monkeypatch.setattr(siem_worker, "WATCH_IDS", {"4625"})
    monkeypatch.setattr(siem_worker, "BRUTE_FORCE_IDS", set())
    monkeypatch.setattr(siem_worker, "SUSPICIOUS_PROCESS_IDS", set())
    monkeypatch.setattr(siem_worker, "MALWARE_KEYWORDS", [])


@pytest.mark.asyncio
@pytest.mark.chaos
async def test_siem_worker_mongo_blackout_acks_message(monkeypatch):
    """Test that worker does NOT acknowledge when MongoDB is down (blackout scenario).
    
    If XACK is called on database failure, Redis deletes the message and evidence is lost.
    The message must stay in the Pending Entries List (PEL) for recovery after Mongo reboots.
    """
    payload = {
        "tenant_id": "TENANT-CHAOS",
        "event_id": "4625",
        "message": "failed logon",
    }
    fake_redis = FakeRedis([
        [
            (
                "raw_logs_queue",
                [
                    ("1-0", {"payload": json.dumps(payload)}),
                ],
            )
        ]
    ])
    logs_col = FakeCollection(fail_on_insert=True, fail_mode="connection")
    alerts_col = FakeCollection()
    tenants_col = FakeCollection()

    _patch_siem_worker(monkeypatch, fake_redis, logs_col, alerts_col, tenants_col)

    await siem_worker.main()

    # Worker tried to insert but failed due to connection error
    assert logs_col.insert_calls == 1
    # Alert was not inserted because log insert failed
    assert alerts_col.insert_calls == 0
    # CRITICAL: XACK was NOT called - message stays in PEL for retry after recovery
    assert fake_redis.xack_calls == [], f"Expected no XACK calls on blackout, got {fake_redis.xack_calls}"


@pytest.mark.asyncio
@pytest.mark.chaos
async def test_siem_worker_split_brain_should_not_duplicate_inserts(monkeypatch):
    """Test that duplicate Redis delivery is safely deduplicated via MongoDB _id idempotency.
    
    Two workers reading the same message from Redis should insert only once due to
    the _id field being set to the Redis message ID. The second insert attempt will
    fail with DuplicateKeyError, which is correctly treated as idempotent.
    """
    payload = {
        "tenant_id": "TENANT-CHAOS",
        "event_id": "4625",
        "message": "failed logon",
    }
    fake_redis = FakeRedis([
        [
            (
                "raw_logs_queue",
                [
                    ("1-0", {"payload": json.dumps(payload)}),
                ],
            )
        ],
        [
            (
                "raw_logs_queue",
                [
                    ("1-0", {"payload": json.dumps(payload)}),
                ],
            )
        ],
    ])
    logs_col = FakeCollection()
    alerts_col = FakeCollection()
    tenants_col = FakeCollection()

    _patch_siem_worker(monkeypatch, fake_redis, logs_col, alerts_col, tenants_col)

    worker_a = asyncio.create_task(siem_worker.main())
    worker_b = asyncio.create_task(siem_worker.main())
    await asyncio.wait_for(asyncio.gather(worker_a, worker_b), timeout=5)

    # Only one actual insert to MongoDB (second worker gets DuplicateKeyError which is safe)
    assert logs_col.insert_calls == 2, f"Expected 2 insert attempts, got {logs_col.insert_calls}"
    # But only 1 document actually stored
    assert len(logs_col.docs) == 1, f"Expected 1 document in DB, got {len(logs_col.docs)}"
    # Both workers should acknowledge because duplicate is idempotent
    assert len(fake_redis.xack_calls) == 2, f"Expected 2 XACK calls, got {len(fake_redis.xack_calls)}"