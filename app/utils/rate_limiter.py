from __future__ import annotations

from typing import Optional
from redis.asyncio import Redis


async def incr_count(redis_client: Optional[Redis], key: str, window_seconds: int = 10) -> int:
    """Increment a simple counter with a TTL to act as a sliding-window approximation.

    This uses INCR + EXPIRE and is suitable for short windows where precise sliding-window
    semantics are not required. Returns the counter value after increment.
    """
    if not redis_client:
        return 0
    try:
        cur = await redis_client.incr(key)
        # Ensure the key expires to bound the window
        try:
            await redis_client.expire(key, int(window_seconds))
        except Exception:
            pass
        return int(cur)
    except Exception:
        return 0


async def set_flag(redis_client: Optional[Redis], key: str, ex: int = 60) -> bool:
    if not redis_client:
        return False
    try:
        await redis_client.set(key, "1", ex=int(ex))
        return True
    except Exception:
        return False


async def get_flag(redis_client: Optional[Redis], key: str) -> bool:
    if not redis_client:
        return False
    try:
        v = await redis_client.get(key)
        return bool(v)
    except Exception:
        return False
