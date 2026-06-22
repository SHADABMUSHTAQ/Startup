from __future__ import annotations

import asyncio
import json
import os
import random
import string
import time

import requests
from pymongo import MongoClient
from redis import Redis


TENANT_ID = "TENANT_CHAOS_01"
DEFAULT_INGEST_URL = os.getenv("CHAOS_INGEST_URL", "http://localhost:8000/ingest/v2/pulse")
FALLBACK_INGEST_URL = os.getenv("CHAOS_FALLBACK_INGEST_URL", "http://localhost:8000/api/v1/ingest/pulse")
MONGO_URI = os.getenv("CHAOS_MONGO_URI", "mongodb://localhost:27017")
MONGO_DB_NAME = os.getenv("MONGODB_DB_NAME", "WarSOC_DB")
REDIS_URL = os.getenv("CHAOS_REDIS_URL", "redis://localhost:6379/0")
CHAOS_BEARER_TOKEN = os.getenv("CHAOS_BEARER_TOKEN", "").strip()

PECA_EVENT_IDS = {
    "4624",
    "4625",
    "4672",
    "4688",
    "4697",
    "4720",
    "4726",
    "4732",
    "1102",
}

FBR_EVENT_IDS = {
    "4660",
    "4663",
    "4670",
    "4657",
    "4698",
    "FBR-INV-DEL",
    "FBR-INV-MOD",
    "FBR-INV-ADD",
}

LAST_PERFECT_PAYLOADS: list[dict] | None = None
LAST_MALFORMED_PAYLOADS: list[dict] | None = None
LAST_FAT_MAN_PAYLOAD: list[dict] | None = None

VALID_WINDOWS_EVENT_IDS = [
    7,
    8,
    9,
    10,
    13,
    17,
    18,
    80,
    1102,
    4616,
    4624,
    4625,
    4648,
    4657,
    4660,
    4663,
    4670,
    4672,
    4688,
    4697,
    4698,
    4719,
    4720,
    4726,
    4732,
    4768,
    4769,
    4776,
    4798,
    5140,
    5156,
    7045,
]


def _token(length: int = 16) -> str:
    alphabet = string.ascii_lowercase + string.digits
    return "".join(random.choice(alphabet) for _ in range(length))


def _message_blob(size: int) -> str:
    alphabet = string.ascii_letters + string.digits + " _-./:"
    return "".join(random.choices(alphabet, k=size))


def _base_payload(event_id, index: int, *, message: str, extra: dict | None = None) -> dict:
    event_uid = f"chaos-event-{index}-{_token(18)}"
    alert_uid = f"chaos-alert-{index}-{_token(18)}"
    payload = {
        "tenant_id": TENANT_ID,
        "agent_id": f"{TENANT_ID}_AGENT",
        "source_ip": f"10.77.{index % 10}.{(index * 7) % 254 + 1}",
        "user": f"DOMAIN\\chaos_user_{index:02d}",
        "event_id": event_id,
        "event_uid": event_uid,
        "alert_uid": alert_uid,
        "message": message,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime()),
        "raw_data": {"event_id": event_id, "alert_uid": alert_uid},
        "raw_event_data": {"event_id": event_id, "alert_uid": alert_uid},
        "processed_data": {"chaos": True},
        "agent_version": "agent-chaos-driver",
    }
    if extra:
        payload.update(extra)
    return payload


def generate_perfect_35() -> list[dict]:
    payloads: list[dict] = []
    for index, event_id in enumerate(VALID_WINDOWS_EVENT_IDS, start=1):
        payloads.append(
            _base_payload(
                event_id,
                index,
                message=f"Windows event {event_id} simulated for chaos verification",
            )
        )

    custom_strings = ["FBR-INV-DEL", "FBR-INV-MOD", "FBR-INV-ADD"]
    for offset, custom_event_id in enumerate(custom_strings, start=len(payloads) + 1):
        payloads.append(
            _base_payload(
                custom_event_id,
                offset,
                message=f"Compliance event {custom_event_id} simulated for chaos verification",
            )
        )

    return payloads


def generate_duplicates(logs: list[dict]) -> list[dict]:
    return logs


def generate_malformed() -> list[dict]:
    malformed: list[dict] = []
    for index in range(5):
        malformed.append(
            {
                "tenant_id": TENANT_ID if index % 2 == 0 else None,
                "agent_id": None,
                "event_id": "NOT_AN_INT",
                "timestamp": [
                    "2026-99-99T99:99:99Z",
                    "not-a-timestamp",
                    "2026-06-02T25:61:61Z",
                    "2026/06/02 12:00:00",
                    123456789,
                ][index],
                "message": f"malformed chaos log {index}",
                "chaos_marker": f"malformed-{index}-{_token(10)}",
                "raw_data": {"event_id": "NOT_AN_INT"},
            }
        )
    return malformed


def generate_fat_man() -> list[dict]:
    size = int(6.5 * 1024 * 1024)
    fat_message = _message_blob(size)
    return [
        {
            "tenant_id": TENANT_ID,
            "agent_id": f"{TENANT_ID}_AGENT",
            "event_id": 4688,
            "event_uid": f"fat-man-{_token(20)}",
            "alert_uid": f"fat-alert-{_token(20)}",
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime()),
            "message": fat_message,
            "chaos_marker": f"fat-man-{_token(10)}",
            "raw_data": {"event_id": 4688},
            "raw_event_data": {"event_id": 4688},
            "processed_data": {"fat": True},
            "agent_version": "agent-chaos-driver",
        }
    ]


def sabotage_redis_cache(tenant_id: str):
    redis_client = Redis.from_url(REDIS_URL, decode_responses=True)
    key = f"tenant_plan:{tenant_id}"
    current_value = redis_client.get(key)
    if current_value is None:
        redis_client.close()
        return None

    if isinstance(current_value, str):
        stripped = current_value.strip()
        if stripped.startswith("["):
            try:
                items = json.loads(stripped)
            except Exception:
                items = [part.strip() for part in stripped.strip("[]").split(",") if part.strip()]
        else:
            items = [part.strip() for part in stripped.split(",") if part.strip()]
    else:
        items = list(current_value)

    items = [item for item in items if str(item).strip().lower() != "peca_forensic"]

    if current_value.strip().startswith("["):
        redis_client.set(key, json.dumps(items))
    else:
        redis_client.set(key, ",".join(items))

    redis_client.close()
    return items


def _auth_headers() -> dict[str, str]:
    if not CHAOS_BEARER_TOKEN:
        raise RuntimeError("CHAOS_BEARER_TOKEN is required to authenticate the ingest attack.")
    return {"Authorization": f"Bearer {CHAOS_BEARER_TOKEN}"}


def _post_payload(url: str, payloads: list[dict], *, expected_status: int):
    response = requests.post(url, json=payloads, headers=_auth_headers(), timeout=120)
    if response.status_code != expected_status:
        raise AssertionError(
            f"POST {url} expected {expected_status}, got {response.status_code}: {response.text[:500]}"
        )
    return response


async def execute_assault():
    global LAST_PERFECT_PAYLOADS, LAST_MALFORMED_PAYLOADS, LAST_FAT_MAN_PAYLOAD

    perfect = generate_perfect_35()
    malformed = generate_malformed()
    fat_man = generate_fat_man()

    LAST_PERFECT_PAYLOADS = perfect
    LAST_MALFORMED_PAYLOADS = malformed
    LAST_FAT_MAN_PAYLOAD = fat_man

    primary_url = DEFAULT_INGEST_URL
    fallback_url = FALLBACK_INGEST_URL

    try:
        _post_payload(primary_url, perfect, expected_status=200)
    except AssertionError as primary_error:
        if "404" not in str(primary_error) and "405" not in str(primary_error):
            raise
        _post_payload(fallback_url, perfect, expected_status=200)

    sabotage_redis_cache(TENANT_ID)

    try:
        _post_payload(primary_url, generate_duplicates(perfect), expected_status=200)
    except AssertionError as primary_error:
        if "404" not in str(primary_error) and "405" not in str(primary_error):
            raise
        _post_payload(fallback_url, generate_duplicates(perfect), expected_status=200)

    try:
        _post_payload(primary_url, malformed, expected_status=422)
    except AssertionError as primary_error:
        if "404" not in str(primary_error) and "405" not in str(primary_error):
            raise
        _post_payload(fallback_url, malformed, expected_status=422)

    try:
        _post_payload(primary_url, fat_man, expected_status=413)
    except AssertionError as primary_error:
        if "404" not in str(primary_error) and "405" not in str(primary_error):
            raise
        _post_payload(fallback_url, fat_man, expected_status=413)


def _count(collection, query: dict) -> int:
    return int(collection.count_documents(query))


def verify_database():
    time.sleep(5)

    mongo = MongoClient(MONGO_URI)
    db = mongo[MONGO_DB_NAME]

    perfect = LAST_PERFECT_PAYLOADS or generate_perfect_35()
    malformed_payloads = LAST_MALFORMED_PAYLOADS or generate_malformed()
    fat_man_payloads = LAST_FAT_MAN_PAYLOAD or generate_fat_man()

    peca_expected = sum(1 for doc in perfect if str(doc["event_id"]) in PECA_EVENT_IDS)
    fbr_expected = sum(1 for doc in perfect if str(doc["event_id"]) in FBR_EVENT_IDS)

    malformed_markers = [doc["chaos_marker"] for doc in malformed_payloads]
    fat_man_doc = fat_man_payloads[0]
    fat_marker = fat_man_doc["chaos_marker"]
    fat_message = fat_man_doc["message"]

    assert _count(db.siem_cold_vault, {"tenant_id": TENANT_ID}) == 35
    assert _count(db.security_alerts, {"tenant_id": TENANT_ID}) == 35
    assert _count(db.peca_forensic_logs, {"tenant_id": TENANT_ID}) == peca_expected
    assert _count(db.fbr_pos_logs, {"tenant_id": TENANT_ID}) == fbr_expected

    zero_markers = 0
    for collection_name in db.list_collection_names():
        collection = db[collection_name]
        zero_markers += _count(collection, {"chaos_marker": {"$in": malformed_markers}})
        zero_markers += _count(collection, {"chaos_marker": fat_marker})
        zero_markers += _count(collection, {"message": fat_message})
        zero_markers += _count(collection, {"event_id": "NOT_AN_INT"})

    assert zero_markers == 0


async def main():
    await execute_assault()
    verify_database()


if __name__ == "__main__":
    asyncio.run(main())
