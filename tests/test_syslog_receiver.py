import pytest
from unittest.mock import AsyncMock

from app.syslog_receiver import UDPTokenBucketProtocol


@pytest.mark.asyncio
async def test_udp_token_bucket_allows_and_records():
    mock_redis = AsyncMock()
    # First increment returns 1 (below threshold)
    mock_redis.incr.return_value = 1
    mock_redis.expire.return_value = True
    mock_redis.xadd.return_value = "15879321-0"

    proto = UDPTokenBucketProtocol(mock_redis, threshold=5, window=2)
    await proto.handle_datagram(b"test-payload", ("1.2.3.4", 5140))

    mock_redis.incr.assert_awaited()
    mock_redis.xadd.assert_awaited()


@pytest.mark.asyncio
async def test_udp_token_bucket_drops_when_over_threshold():
    mock_redis = AsyncMock()
    # Simulate a high counter value
    mock_redis.incr.return_value = 100
    mock_redis.expire.return_value = True

    proto = UDPTokenBucketProtocol(mock_redis, threshold=10, window=2)
    await proto.handle_datagram(b"spam", ("9.9.9.9", 5140))

    mock_redis.incr.assert_awaited()
    # Should not call xadd when dropped
    assert not mock_redis.xadd.await_count
import asyncio
import pytest
from unittest.mock import AsyncMock

from app.syslog_receiver import UDPTokenBucketProtocol


@pytest.mark.asyncio
async def test_udp_token_bucket_throttle(monkeypatch):
    redis = AsyncMock()
    # First call: incr returns 1
    redis.incr.side_effect = [1, 1200]
    redis.expire.return_value = True
    redis.xadd = AsyncMock()

    proto = UDPTokenBucketProtocol(redis, threshold=1000, window=1)

    # First datagram should be forwarded
    await proto.handle_datagram(b"test payload 1", ("1.2.3.4", 514))
    redis.xadd.assert_called_once()

    # Reset mock call history
    redis.xadd.reset_mock()

    # Second datagram exceeds threshold and should be dropped
    await proto.handle_datagram(b"flood payload", ("1.2.3.4", 514))
    redis.xadd.assert_not_called()