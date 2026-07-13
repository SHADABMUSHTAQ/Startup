import pytest

from app.workers.stream_retention import RAW_REQUIRED_GROUPS, trim_acknowledged_stream


@pytest.mark.asyncio
async def test_stream_trim_waits_for_every_group_and_preserves_pending(redis_client):
    stream = "stream-retention-contract"
    message_ids = [await redis_client.xadd(stream, {"payload": str(index)}) for index in range(6)]

    for group in RAW_REQUIRED_GROUPS:
        await redis_client.xgroup_create(stream, group, id="0-0")

    for group in RAW_REQUIRED_GROUPS:
        rows = await redis_client.xreadgroup(group, f"{group}-consumer", {stream: ">"}, count=10)
        delivered_ids = [message_id for _, messages in rows for message_id, _ in messages]
        if group == "fbr_group":
            await redis_client.xack(stream, group, *delivered_ids[:3])
        else:
            await redis_client.xack(stream, group, *delivered_ids)

    trimmed = await trim_acknowledged_stream(redis_client, stream, RAW_REQUIRED_GROUPS)
    remaining_ids = [message_id for message_id, _ in await redis_client.xrange(stream)]

    assert trimmed == 3
    assert remaining_ids == message_ids[3:]


@pytest.mark.asyncio
async def test_stream_trim_does_nothing_until_all_required_groups_exist(redis_client):
    stream = "stream-retention-missing-group"
    await redis_client.xadd(stream, {"payload": "one"})
    await redis_client.xgroup_create(stream, "siem_group", id="0-0")

    assert await trim_acknowledged_stream(redis_client, stream, RAW_REQUIRED_GROUPS) == 0
    assert await redis_client.xlen(stream) == 1


def test_ingest_producers_do_not_use_unsafe_maxlen_trimming():
    from pathlib import Path

    root = Path(__file__).resolve().parents[1]
    for source_path in (
        root / "app/routes/ingest_pulse.py",
        root / "app/routes/pos.py",
        root / "app/syslog_receiver.py",
        root / "syslog_receiver.py",
    ):
        assert "maxlen=" not in source_path.read_text(encoding="utf-8")
