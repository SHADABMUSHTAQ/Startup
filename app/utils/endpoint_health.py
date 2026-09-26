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


def endpoint_health_issues(
    *, online: bool, sensor_status: dict, signing_required: bool,
    signing_ready: bool, server_required: bool, server_health: str | None,
    audit_configured: bool,
) -> list[dict]:
    """Explain existing health gates without exposing raw sensor errors/secrets."""
    if not online:
        return [{
            "code": "AGENT_OFFLINE",
            "summary": "No current agent heartbeat. Endpoint visibility is unavailable.",
            "remediation": [
                "Confirm the endpoint is powered on and connected to the network.",
                "Check the WarSOC_Agent Windows service and HTTPS access to the backend.",
                "Restore reporting; acknowledging an alert does not restart the agent.",
            ],
        }]
    issues = []
    channels = sensor_status.get("channels")
    channels = channels if isinstance(channels, dict) else {}
    affected = [
        name for name in ("Security", "System")
        if not isinstance(channels.get(name), dict)
        or str(channels[name].get("status") or "").lower() != "ok"
    ]
    spool = sensor_status.get("spool")
    spool = spool if isinstance(spool, dict) else {}
    if bool(spool.get("blocked")):
        issues.append({
            "code": "SPOOL_BLOCKED",
            "summary": "Local evidence buffering is blocked. Collection may be paused until the queue drains or disk reserve recovers.",
            "affected_channels": affected,
            "remediation": [
                "Check backend HTTPS connectivity, ingestion rejection logs, spool usage and free disk.",
                "Use the approved current agent, preserving enrollment keys, spool files and collection cursors.",
                "Allow the sender to drain below its resume boundary; do not delete queued evidence or make the limit unlimited.",
            ],
        })
    elif affected:
        issues.append({
            "code": "EVENT_CHANNEL_UNHEALTHY",
            "summary": "Required Windows event channels are unavailable or not confirmed healthy.",
            "affected_channels": affected,
            "remediation": [
                "Confirm Windows Event Log and WarSOC_Agent services are running.",
                "Check agent permissions and its collection diagnostics; repair the reported channel error.",
            ],
        })
    if not audit_configured:
        issues.append({
            "code": "AUDIT_POLICY_NOT_READY",
            "summary": "Required Windows auditing is not confirmed configured.",
            "remediation": [
                "Review effective audit policy with the endpoint administrator or domain policy owner.",
                "Use the approved telemetry configuration process; do not silently override domain policy.",
            ],
        })
    if signing_required and not signing_ready:
        issues.append({
            "code": "EVENT_SIGNING_NOT_READY",
            "summary": "The backend has not confirmed current signed event delivery.",
            "remediation": [
                "Check event delivery and enrolled signing-key diagnostics.",
                "Preserve the existing identity and use the approved signed agent; do not disable signature enforcement.",
            ],
        })
    if server_required and server_health != "READY":
        issues.append({
            "code": "SERVER_PROFILE_NOT_READY",
            "summary": "The required server monitoring profile is not ready.",
            "remediation": [
                "Review desired and reported server profile revisions and effective audit coverage.",
                "Have a tenant administrator correct the profile assignment on a supported server.",
            ],
        })
    return issues
