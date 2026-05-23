from __future__ import annotations

import asyncio
from typing import Optional

from redis.asyncio import Redis
from app.config.config import get_settings

_REDIS: Optional[Redis] = None
_LOCK = asyncio.Lock()


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
            _REDIS = await Redis.from_url(url, decode_responses=True)
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
        await _REDIS.close()
    except Exception:
        pass
    _REDIS = None
