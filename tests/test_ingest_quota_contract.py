import pytest
from fastapi import HTTPException

from app.routes.ingest_pulse import (
    DEFAULT_DAILY_INGEST_BYTES_PER_AGENT,
    MAX_DAILY_INGEST_BYTES,
    PLATFORM_DAILY_INGEST_BYTES_MAX,
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

    async def eval(
        self,
        _script,
        _numkeys,
        tenant_key,
        platform_key,
        increment,
        tenant_limit,
        platform_limit,
        ttl,
    ):
        tenant_current = int(self.counters.get(tenant_key, 0))
        platform_current = int(self.counters.get(platform_key, 0))
        increment = int(increment)
        tenant_limit = int(tenant_limit)
        platform_limit = int(platform_limit)
        if tenant_current + increment > tenant_limit:
            return [0, tenant_current, tenant_limit, platform_current, platform_limit, 1]
        if platform_limit > 0 and platform_current + increment > platform_limit:
            return [0, tenant_current, tenant_limit, platform_current, platform_limit, 2]
        tenant_updated = tenant_current + increment
        platform_updated = platform_current + increment
        self.counters[tenant_key] = tenant_updated
        self.counters[platform_key] = platform_updated
        self.expiry[tenant_key] = int(ttl)
        self.expiry[platform_key] = int(ttl)
        return [1, tenant_updated, tenant_limit, platform_updated, platform_limit, 0]


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


@pytest.mark.asyncio
async def test_platform_daily_ingest_ceiling_is_atomic_across_tenants(monkeypatch):
    monkeypatch.setattr(
        "app.routes.ingest_pulse.PLATFORM_DAILY_INGEST_BYTES_MAX",
        100,
    )
    redis = FakeQuotaRedis(
        {
            "tenant_ingest_quota_bytes:TENANT_A": b"100",
            "tenant_ingest_quota_bytes:TENANT_B": b"100",
        }
    )

    await _enforce_daily_ingest_quota(redis, "TENANT_A", 60)
    with pytest.raises(HTTPException) as exc:
        await _enforce_daily_ingest_quota(redis, "TENANT_B", 50)

    assert exc.value.status_code == 503
    assert sum(
        value
        for key, value in redis.counters.items()
        if ":platform:" not in key
    ) == 60
    assert any(
        value == 60
        for key, value in redis.counters.items()
        if ":platform:" in key
    )


def test_platform_daily_ingest_default_matches_current_host_budget():
    assert PLATFORM_DAILY_INGEST_BYTES_MAX == 3 * 1024 * 1024 * 1024
