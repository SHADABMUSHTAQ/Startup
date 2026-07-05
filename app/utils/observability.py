from __future__ import annotations

from datetime import datetime, timezone
from threading import Lock
from typing import Optional

from redis.asyncio import Redis
from app.utils.redis_client import get_redis
import asyncio

_LOCK = Lock()
_AUTH_FAIL_CLOSED_TOTAL = 0
_WORKER_HEARTBEATS: dict[str, float] = {}


def record_auth_fail_closed(amount: int = 1) -> None:
    global _AUTH_FAIL_CLOSED_TOTAL
    with _LOCK:
        _AUTH_FAIL_CLOSED_TOTAL += int(amount)


def get_auth_fail_closed_total() -> int:
    with _LOCK:
        return int(_AUTH_FAIL_CLOSED_TOTAL)


def record_worker_heartbeat(worker_name: str, timestamp: datetime | None = None) -> float:
    heartbeat_at = (timestamp or datetime.now(timezone.utc)).timestamp()
    with _LOCK:
        _WORKER_HEARTBEATS[str(worker_name)] = heartbeat_at
    return heartbeat_at


def get_worker_heartbeat_age(worker_name: str, now: datetime | None = None) -> float | None:
    with _LOCK:
        heartbeat_at = _WORKER_HEARTBEATS.get(str(worker_name))
    if heartbeat_at is None:
        return None
    current = (now or datetime.now(timezone.utc)).timestamp()
    return max(0.0, current - heartbeat_at)


def get_worker_staleness_seconds(now: datetime | None = None) -> float:
    current = (now or datetime.now(timezone.utc)).timestamp()
    with _LOCK:
        if not _WORKER_HEARTBEATS:
            return 0.0
        oldest_heartbeat = min(_WORKER_HEARTBEATS.values())
    return max(0.0, current - oldest_heartbeat)


async def increment_redis_counter(redis_client: Optional[Redis], key: str, amount: int = 1) -> bool:
    if not redis_client:
        return False
    try:
        await redis_client.incrby(key, int(amount))
        return True
    except Exception:
        return False


async def get_redis_health(redis_client: Optional[Redis]) -> int:
    if not redis_client:
        return 0
    try:
        return 1 if await redis_client.ping() else 0
    except Exception:
        return 0


async def get_dlq_depth(redis_client: Optional[Redis], prefix: str = "warsoc:dlq:") -> int:
    if not redis_client:
        return 0

    total = 0
    cursor = 0
    try:
        while True:
            cursor, keys = await redis_client.scan(cursor=cursor, match=f"{prefix}*", count=100)
            for key in keys:
                try:
                    total += int(await redis_client.xlen(key))
                except Exception:
                    try:
                        total += int(await redis_client.llen(key))
                    except Exception:
                        continue
            if cursor == 0:
                break
    except Exception:
        return 0
    return total


async def record_worker_heartbeat_redis(worker_name: str, timestamp: datetime | None = None) -> float | None:
    """Write a per-worker heartbeat to Redis. Returns epoch seconds or None on failure."""
    try:
        redis_client = await get_redis()
        if not redis_client:
            return None
        heartbeat_at = (timestamp or datetime.now(timezone.utc)).timestamp()
        key = f"warsoc:worker_heartbeat:{worker_name}"
        # store as integer epoch seconds for compactness
        await redis_client.set(key, int(heartbeat_at))
        # Keep history for 7 days as default cleanup
        try:
            await redis_client.expire(key, 60 * 60 * 24 * 7)
        except Exception:
            pass
        return float(heartbeat_at)
    except Exception:
        return None


async def get_worker_heartbeat_age_redis(worker_name: str, now: datetime | None = None) -> float | None:
    try:
        redis_client = await get_redis()
        if not redis_client:
            return None
        key = f"warsoc:worker_heartbeat:{worker_name}"
        raw = await redis_client.get(key)
        if raw is None:
            return None
        try:
            heartbeat_at = float(raw)
        except Exception:
            try:
                heartbeat_at = float(int(raw))
            except Exception:
                return None
        current = (now or datetime.now(timezone.utc)).timestamp()
        return max(0.0, current - heartbeat_at)
    except Exception:
        return None


async def list_worker_heartbeats_redis() -> dict[str, float]:
    out: dict[str, float] = {}
    try:
        redis_client = await get_redis()
        if not redis_client:
            return out
        cursor = 0
        while True:
            cursor, keys = await redis_client.scan(cursor=cursor, match="warsoc:worker_heartbeat:*", count=100)
            for key in keys:
                try:
                    raw = await redis_client.get(key)
                    if raw is None:
                        continue
                    name = key.split(":", 2)[-1]
                    out[name] = float(raw)
                except Exception:
                    continue
            if cursor == 0:
                break
    except Exception:
        return {}
    return out


async def record_worker_heartbeat_async(worker_name: str, timestamp: datetime | None = None) -> float:
    """Async-friendly wrapper: try Redis then fall back to process-local store."""
    # Try Redis first
    try:
        val = await record_worker_heartbeat_redis(worker_name, timestamp=timestamp)
        if val is not None:
            # Also update local store for immediate in-process visibility
            try:
                # reuse sync function
                record_worker_heartbeat(worker_name, timestamp=timestamp)
            except Exception:
                pass
            return val
    except Exception:
        pass
    # Redis not available or failed -> fallback to in-memory sync heartbeat
    return record_worker_heartbeat(worker_name, timestamp=timestamp)


async def record_worker_heartbeat_with_client(
    redis_client: Optional[Redis],
    worker_name: str,
    timestamp: datetime | None = None,
    ttl_seconds: int = 120,
) -> float:
    heartbeat_at = (timestamp or datetime.now(timezone.utc)).timestamp()
    record_worker_heartbeat(worker_name, timestamp=timestamp)
    if redis_client:
        try:
            await redis_client.set(
                f"warsoc:worker_heartbeat:{worker_name}",
                int(heartbeat_at),
                ex=max(30, int(ttl_seconds)),
            )
        except Exception:
            pass
    return heartbeat_at
