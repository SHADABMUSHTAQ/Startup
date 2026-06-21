import hashlib
import json
from datetime import datetime, timezone
from typing import Any, Optional


def _json_default(value: Any) -> str:
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc).isoformat()
    return str(value)


def canonical_json(value: Any) -> str:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=_json_default,
    )


def build_payload_hash(signable_payload: dict[str, Any]) -> str:
    canonical = canonical_json(signable_payload)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def build_signable_event_payload(payload: dict[str, Any]) -> dict[str, Any]:
    raw_event_data = payload.get("raw_event_data")
    if raw_event_data is None:
        raw_event_data = payload.get("raw_data", {})

    return {
        "source_ip": payload.get("source_ip", ""),
        "user": payload.get("user", ""),
        "event_id": "" if payload.get("event_id") is None else str(payload.get("event_id")).strip(),
        "message": payload.get("message", ""),
        "processed_data": payload.get("processed_data") or {},
        "raw_event_data": raw_event_data or {},
    }


def build_event_signature_string(
    agent_id: str,
    timestamp: str,
    event_uid: str,
    payload_hash: str,
) -> str:
    return f"{agent_id}|{timestamp}|{event_uid}|{payload_hash}"


def parse_utc_timestamp(timestamp_str: str) -> Optional[datetime]:
    try:
        if not isinstance(timestamp_str, str):
            return None

        ts = timestamp_str.strip()
        if not ts:
            return None

        tz_suffix = ""
        ts_core = ts

        if ts_core.endswith("Z"):
            tz_suffix = "Z"
            ts_core = ts_core[:-1]
        elif (
            len(ts_core) >= 6
            and ts_core[-6] in "+-"
            and ts_core[-3] == ":"
            and ts_core[-5:-3].isdigit()
            and ts_core[-2:].isdigit()
        ):
            tz_suffix = ts_core[-6:]
            ts_core = ts_core[:-6]

        if "." in ts_core:
            head, frac = ts_core.rsplit(".", 1)
            if frac.isdigit() and len(frac) == 7:
                ts_core = f"{head}.{frac[:6]}"

        normalized_ts = f"{ts_core}{tz_suffix}"
        parsed = datetime.fromisoformat(normalized_ts.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)
    except (TypeError, ValueError):
        return None


def timestamp_age_seconds(timestamp_str: str) -> Optional[int]:
    parsed = parse_utc_timestamp(timestamp_str)
    if parsed is None:
        return None
    return int((datetime.now(timezone.utc) - parsed).total_seconds())
