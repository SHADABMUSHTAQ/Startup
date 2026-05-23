import pytest
import asyncio
from unittest.mock import AsyncMock

from app.utils.rate_limiter import incr_count, set_flag, get_flag


@pytest.mark.asyncio
async def test_incr_count_calls_incr_and_expire():
    mock_redis = AsyncMock()
    mock_redis.incr.return_value = 5
    mock_redis.expire.return_value = True

    val = await incr_count(mock_redis, "warsoc:test:key", window_seconds=7)

    mock_redis.incr.assert_awaited_with("warsoc:test:key")
    mock_redis.expire.assert_awaited_with("warsoc:test:key", 7)
    assert val == 5


@pytest.mark.asyncio
async def test_set_and_get_flag():
    mock_redis = AsyncMock()
    mock_redis.set.return_value = True
    mock_redis.get.return_value = "1"

    ok = await set_flag(mock_redis, "warsoc:flag:key", ex=12)
    assert ok is True
    mock_redis.set.assert_awaited_with("warsoc:flag:key", "1", ex=12)

    present = await get_flag(mock_redis, "warsoc:flag:key")
    assert present is True
    mock_redis.get.assert_awaited_with("warsoc:flag:key")
