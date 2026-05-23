import pytest
import asyncio
from datetime import datetime, timezone

import pytest

import app.utils.observability as obs


class FakeRedis:
    def __init__(self):
        self.store = {}

    async def set(self, key, value):
        self.store[key] = str(value)

    async def get(self, key):
        return self.store.get(key)

    async def expire(self, key, ttl):
        return True

    async def scan(self, cursor=0, match=None, count=100):
        keys = [k for k in self.store.keys() if (not match or k.startswith(match.rstrip("*")))]
        return 0, keys

    async def ping(self):
        return True


@pytest.mark.asyncio
async def test_redis_heartbeat_roundtrip(monkeypatch):
    fake = FakeRedis()

    async def _get_redis():
        return fake

    monkeypatch.setattr("app.utils.redis_client.get_redis", _get_redis)

    # write heartbeat via Redis-backed helper
    ts = await obs.record_worker_heartbeat_redis("test_worker")
    assert ts is not None

    # list and age should reflect the fake redis state
    data = await obs.list_worker_heartbeats_redis()
    assert "test_worker" in data
    age = await obs.get_worker_heartbeat_age_redis("test_worker")
    assert age is not None
    assert age >= 0
