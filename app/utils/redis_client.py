from __future__ import annotations

import asyncio
import os
from typing import Optional

from redis.asyncio import BlockingConnectionPool, Redis
from app.config.config import get_settings

_REDIS: Optional[Redis] = None
_LOCK = asyncio.Lock()


def create_redis_client(url: str, *, decode_responses: bool = True) -> Redis:
    """Create a bounded pool that waits briefly instead of failing on bursts."""
    max_connections = max(20, int(os.getenv("REDIS_MAX_CONNECTIONS", "200")))
    pool_timeout = max(0.1, float(os.getenv("REDIS_POOL_TIMEOUT_SECONDS", "5")))
    pool = BlockingConnectionPool.from_url(
        url,
        decode_responses=decode_responses,
        max_connections=max_connections,
        timeout=pool_timeout,
    )
    return Redis(connection_pool=pool)


async def get_redis() -> Optional[Redis]:
    """Return a shared Redis client or None on failure."""
    global _REDIS
    if _REDIS is not None:
        return _REDIS
    settings = get_settings()
    url = getattr(settings, "redis_url", None)
    if not url:
        return None
    async with _LOCK:
        if _REDIS is not None:
            return _REDIS
        try:
            _REDIS = create_redis_client(url)
            # Warm ping to detect early failures (non-fatal)
            try:
                await _REDIS.ping()
            except Exception:
                pass
            return _REDIS
        except Exception:
            return None


async def close_redis() -> None:
    global _REDIS
    if _REDIS is None:
        return
    try:
        await _REDIS.aclose()
    except Exception:
        pass
    _REDIS = None
