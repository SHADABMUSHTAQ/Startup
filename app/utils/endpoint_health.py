import json
import os


EVENT_SIGNATURE_STATUS_KEY_PREFIX = "warsoc:agent_event_signature"
EVENT_SIGNATURE_STATUS_TTL_SECONDS = 7 * 24 * 60 * 60


def event_signature_mode() -> str:
    mode = os.getenv("AGENT_EVENT_SIGNATURE_MODE", "observe").strip().lower()
    return mode if mode in {"observe", "required"} else "required"


def decode_event_signature_status(raw_status) -> dict:
    if isinstance(raw_status, bytes):
        raw_status = raw_status.decode("utf-8", errors="ignore")
    try:
        parsed = json.loads(raw_status) if raw_status else {}
    except (TypeError, ValueError):
        parsed = {}
    if not isinstance(parsed, dict):
        parsed = {}

    status = str(parsed.get("status") or "unknown").strip().lower()
    if status not in {"verified", "unsigned_legacy", "mixed", "unknown"}:
        status = "unknown"
    return {
        "status": status,
        "ready": status == "verified",
        "last_event_at": parsed.get("last_event_at"),
        "last_signed_event_at": parsed.get("last_signed_event_at"),
        "endpoint_name": str(parsed.get("endpoint_name") or "").strip()[:255] or None,
        "agent_version": str(parsed.get("agent_version") or "").strip()[:64] or None,
    }
