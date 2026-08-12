from __future__ import annotations

import os
from dataclasses import dataclass


RAW_STREAM_MAX_ENTRIES = max(0, int(os.getenv("RAW_STREAM_MAX_ENTRIES", "500000")))
RAW_STREAM_MAX_BYTES = max(
    0,
    int(os.getenv("RAW_STREAM_MAX_BYTES", str(192 * 1024 * 1024))),
)
REDIS_INGEST_MEMORY_HIGH_WATERMARK_PERCENT = min(
    95,
    max(1, int(os.getenv("REDIS_INGEST_MEMORY_HIGH_WATERMARK_PERCENT", "70"))),
)
REDIS_INGEST_MEMORY_RESERVE_BYTES = max(
    0,
    int(os.getenv("REDIS_INGEST_MEMORY_RESERVE_BYTES", str(128 * 1024 * 1024))),
)
REDIS_STREAM_ENTRY_OVERHEAD_BYTES = max(
    0,
    int(os.getenv("REDIS_STREAM_ENTRY_OVERHEAD_BYTES", "256")),
)


@dataclass(frozen=True)
class IngestCapacitySnapshot:
    stream_entries: int
    stream_bytes: int
    redis_used_bytes: int
    redis_max_bytes: int
    redis_admission_limit_bytes: int


class IngestCapacityError(RuntimeError):
    def __init__(self, reason: str, snapshot: IngestCapacitySnapshot | None = None):
        super().__init__(reason)
        self.reason = reason
        self.snapshot = snapshot


def _integer(value, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _memory_value(info: dict, name: str) -> int:
    return _integer(info.get(name, info.get(name.encode("utf-8"), 0)))


async def enforce_redis_ingest_capacity(
    redis_client,
    stream_name: str,
    *,
    incoming_entries: int,
    incoming_stream_bytes: int,
    incoming_redis_bytes: int | None = None,
) -> IngestCapacitySnapshot:
    """Fail closed before Redis reaches its no-eviction memory ceiling."""
    if redis_client is None:
        raise IngestCapacityError("redis_unavailable")

    incoming_entries = max(0, int(incoming_entries))
    incoming_stream_bytes = max(0, int(incoming_stream_bytes))
    projected_redis_bytes = max(
        incoming_stream_bytes,
        int(incoming_redis_bytes or 0),
    ) + (incoming_entries * REDIS_STREAM_ENTRY_OVERHEAD_BYTES)

    try:
        stream_entries = _integer(await redis_client.xlen(stream_name))
        stream_bytes = _integer(await redis_client.memory_usage(stream_name, samples=5))
        memory_info = await redis_client.info("memory")
    except Exception as exc:
        raise IngestCapacityError("capacity_check_unavailable") from exc

    redis_used_bytes = _memory_value(memory_info, "used_memory")
    redis_max_bytes = _memory_value(memory_info, "maxmemory")
    redis_admission_limit_bytes = 0
    if redis_max_bytes > 0:
        percentage_limit = (
            redis_max_bytes * REDIS_INGEST_MEMORY_HIGH_WATERMARK_PERCENT // 100
        )
        reserve_limit = max(0, redis_max_bytes - REDIS_INGEST_MEMORY_RESERVE_BYTES)
        redis_admission_limit_bytes = (
            min(percentage_limit, reserve_limit)
            if reserve_limit > 0
            else percentage_limit
        )

    snapshot = IngestCapacitySnapshot(
        stream_entries=stream_entries,
        stream_bytes=stream_bytes,
        redis_used_bytes=redis_used_bytes,
        redis_max_bytes=redis_max_bytes,
        redis_admission_limit_bytes=redis_admission_limit_bytes,
    )

    if (
        RAW_STREAM_MAX_ENTRIES > 0
        and stream_entries + incoming_entries > RAW_STREAM_MAX_ENTRIES
    ):
        raise IngestCapacityError("stream_entry_limit", snapshot)
    if (
        RAW_STREAM_MAX_BYTES > 0
        and stream_bytes + incoming_stream_bytes > RAW_STREAM_MAX_BYTES
    ):
        raise IngestCapacityError("stream_byte_limit", snapshot)
    if (
        redis_admission_limit_bytes > 0
        and redis_used_bytes + projected_redis_bytes > redis_admission_limit_bytes
    ):
        raise IngestCapacityError("redis_memory_high_watermark", snapshot)

    return snapshot
