import pytest
from fastapi import HTTPException

from app.routes.ingest_pulse import (
    DEFAULT_DAILY_INGEST_BYTES_PER_AGENT,
    MAX_DAILY_INGEST_BYTES,
    _enforce_daily_ingest_quota,
    _resolve_daily_ingest_quota_bytes,
)


class FakeQuotaRedis:
    def __init__(self, values=None):
        self.values = values or {}
        self.counters = {}
        self.expiry = {}

    async def get(self, key):
        return self.values.get(key)

    async def eval(self, _script, _numkeys, key, increment, limit, ttl):
        current = int(self.counters.get(key, 0))
        increment = int(increment)
        limit = int(limit)
        if current + increment > limit:
            return [0, current, limit]
        updated = current + increment
        self.counters[key] = updated
        self.expiry[key] = int(ttl)
        return [1, updated, limit]


@pytest.mark.asyncio
async def test_daily_ingest_quota_uses_contract_override_when_present():
    redis = FakeQuotaRedis({"tenant_ingest_quota_bytes:WARSOC_QUOTA": b"12345"})

    quota = await _resolve_daily_ingest_quota_bytes(redis, "WARSOC_QUOTA")

    assert quota == 12345


@pytest.mark.asyncio
async def test_daily_ingest_quota_caps_oversized_contract_override():
    oversized = str(MAX_DAILY_INGEST_BYTES * 100).encode()
    redis = FakeQuotaRedis({"tenant_ingest_quota_bytes:WARSOC_QUOTA": oversized})

    quota = await _resolve_daily_ingest_quota_bytes(redis, "WARSOC_QUOTA")

    assert quota == MAX_DAILY_INGEST_BYTES


@pytest.mark.asyncio
async def test_daily_ingest_quota_scales_from_agent_limit_when_no_override():
    redis = FakeQuotaRedis({"tenant_agent_limit:WARSOC_QUOTA": b"50"})

    quota = await _resolve_daily_ingest_quota_bytes(redis, "WARSOC_QUOTA")

    assert quota == 50 * DEFAULT_DAILY_INGEST_BYTES_PER_AGENT


@pytest.mark.asyncio
async def test_daily_ingest_quota_blocks_before_queue_costs_explode():
    redis = FakeQuotaRedis({"tenant_ingest_quota_bytes:WARSOC_QUOTA": b"100"})

    await _enforce_daily_ingest_quota(redis, "WARSOC_QUOTA", 60)
    with pytest.raises(HTTPException) as exc:
        await _enforce_daily_ingest_quota(redis, "WARSOC_QUOTA", 50)

    assert exc.value.status_code == 429
