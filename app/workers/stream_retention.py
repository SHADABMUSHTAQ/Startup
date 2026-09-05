from __future__ import annotations

import asyncio
import logging
import os
from typing import Any, Iterable

from redis.exceptions import ResponseError

from app.config.config import get_settings
from app.utils.observability import increment_redis_counter, record_worker_heartbeat_with_client
from app.utils.redis_client import create_redis_client

logger = logging.getLogger("stream-retention")

RAW_LOGS_QUEUE = "raw_logs_queue"
SIEM_HOT_QUEUE = "siem_hot_queue"
RAW_REQUIRED_GROUPS = frozenset({"siem_group", "fbr_group", "eto_group"})
HOT_REQUIRED_GROUPS = frozenset({"siem_hot_group"})


def _text(value: Any) -> str:
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="ignore")
    return str(value or "")


def _field(mapping: dict, name: str, default=None):
    return mapping.get(name, mapping.get(name.encode("utf-8"), default))


def _stream_id_key(stream_id: Any) -> tuple[int, int]:
    raw = _text(stream_id)
    try:
        milliseconds, sequence = raw.split("-", 1)
        return int(milliseconds), int(sequence)
    except (TypeError, ValueError):
        return 0, 0


async def trim_acknowledged_stream(
    redis_client,
    stream_name: str,
    required_groups: Iterable[str],
) -> int:
    """Trim only entries safe for every explicitly required consumer group."""
    try:
        group_rows = await redis_client.xinfo_groups(stream_name)
    except ResponseError as exc:
        if "no such key" in str(exc).lower():
            return 0
        raise

    groups = {_text(_field(row, "name")): row for row in group_rows}
    required_group_names = {_text(group_name) for group_name in required_groups}
    if not required_group_names.issubset(groups):
        return 0

    boundaries: list[str] = []
    # Historical or profile-gated groups must not pin the active pipeline
    # forever. Only the explicitly required consumers participate in the
    # acknowledgement boundary.
    for group_name in sorted(required_group_names):
        group = groups[group_name]
        pending = await redis_client.xpending(stream_name, group_name)
        pending_count = int(_field(pending, "pending", 0) or 0)
        boundary = _field(pending, "min") if pending_count else _field(group, "last-delivered-id")
        boundary_text = _text(boundary)
        if _stream_id_key(boundary_text) == (0, 0):
            return 0
        boundaries.append(boundary_text)

    if not boundaries:
        return 0

    safe_boundary = min(boundaries, key=_stream_id_key)
    return int(await redis_client.xtrim(stream_name, minid=safe_boundary, approximate=False))


async def stream_retention_worker() -> None:
    settings = get_settings()
    redis_client = create_redis_client(settings.redis_url)
    interval_seconds = max(30, int(os.getenv("STREAM_TRIM_INTERVAL_SECONDS", "60")))
    raw_required_groups = set(RAW_REQUIRED_GROUPS)
    if settings.security_stories_enabled:
        raw_required_groups.add("security_story_group")

    try:
        while True:
            try:
                raw_trimmed = await trim_acknowledged_stream(
                    redis_client, RAW_LOGS_QUEUE, raw_required_groups
                )
                hot_trimmed = await trim_acknowledged_stream(
                    redis_client, SIEM_HOT_QUEUE, HOT_REQUIRED_GROUPS
                )
                if raw_trimmed or hot_trimmed:
                    if raw_trimmed:
                        await increment_redis_counter(
                            redis_client,
                            "warsoc_raw_stream_trimmed_total",
                            raw_trimmed,
                        )
                    if hot_trimmed:
                        await increment_redis_counter(
                            redis_client,
                            "warsoc_siem_hot_stream_trimmed_total",
                            hot_trimmed,
                        )
                    logger.info(
                        "Safely trimmed acknowledged stream entries: raw=%s hot=%s",
                        raw_trimmed,
                        hot_trimmed,
                    )
                await record_worker_heartbeat_with_client(redis_client, "stream_retention_worker")
            except Exception as exc:
                logger.error("Consumer-safe stream trimming failed: %s", exc)
            await asyncio.sleep(interval_seconds)
    finally:
        await redis_client.aclose()
