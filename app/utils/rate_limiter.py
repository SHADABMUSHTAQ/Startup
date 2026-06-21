from __future__ import annotations

import hashlib
import time
from typing import Optional

from fastapi import HTTPException, Request, status
from redis.asyncio import Redis

from app.utils.redis_client import get_redis

INGEST_RATE_LIMIT_PER_SECOND = 100
INGEST_RATE_WINDOW_SECONDS = 1


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


def _extract_tenant_identity(request: Request) -> str:
    tenant_id = (
        request.headers.get("x-tenant-id")
        or request.headers.get("x-tenant_id")
        or request.headers.get("X-Tenant-ID")
        or request.headers.get("X-Tenant-Id")
    )
    if tenant_id:
        normalized = str(tenant_id).strip()
        if normalized:
            return f"tenant:{normalized}"

    api_key = request.headers.get("x-api-key") or request.headers.get("X-API-Key")
    if api_key:
        normalized = str(api_key).strip()
        if normalized:
            return f"api_key:{hashlib.sha256(normalized.encode('utf-8')).hexdigest()}"

    authorization = request.headers.get("authorization") or request.headers.get("Authorization")
    if not authorization and "warsoc_token" in request.cookies:
        authorization = request.cookies.get("warsoc_token")

    if authorization:
        token = str(authorization).strip()
        if token.lower().startswith("bearer "):
            token = token[7:].strip()
        if token:
            return f"bearer:{hashlib.sha256(token.encode('utf-8')).hexdigest()}"

    return ""


async def redis_ingest_rate_limit(
    request: Request,
    limit_per_second: int = INGEST_RATE_LIMIT_PER_SECOND,
    window_seconds: int = INGEST_RATE_WINDOW_SECONDS,
) -> str:
    """Redis-backed fixed-window ingest limiter keyed by tenant identity.

    This dependency must run before any worker queue writes. It never queries MongoDB.
    """
    identity = _extract_tenant_identity(request)
    if not identity:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Missing tenant identity header or API key.",
        )

    redis_client = getattr(request.app.state, "redis", None)
    if redis_client is None:
        redis_client = await get_redis()

    if redis_client is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Redis unavailable for request throttling.",
        )

    window_bucket = int(time.time() // max(1, int(window_seconds)))
    rate_key = f"warsoc:ingest:rl:{identity}:{window_bucket}"
    current_count = await redis_client.incr(rate_key)
    if current_count == 1:
        await redis_client.expire(rate_key, max(1, int(window_seconds) + 1))

    if current_count > int(limit_per_second):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many requests. Please slow down and retry.",
        )

    return identity
