"""Shared, dependency-free server collection contract used by API and agent."""

import copy
import hashlib
import json
from datetime import datetime, timezone


PROFILE_SCHEMA = "warsoc-server-profile-v1"
PROFILE_ID = "general_server"
PROFILE_VERSION = 1
MAX_PROFILE_BYTES = 16384
AUDIT_MAX_AGE_SECONDS = 900

# Existing native detections only. File/POS, share and DC inputs are not enabled.
GENERAL_EVENT_IDS = (
    "1100", "1102", "4616", "4624", "4625", "4648", "4672", "4688",
    "4697", "4698", "4719", "4720", "4726", "4732", "4798", "5157", "7045",
)
GENERAL_AUDIT_REQUIREMENTS = {
    "0cce9215-69ae-11d9-bed3-505054503030": 3,  # Logon
    "0cce922b-69ae-11d9-bed3-505054503030": 1,  # Process creation
    "0cce9227-69ae-11d9-bed3-505054503030": 3,  # Other object access (tasks)
    "0cce9226-69ae-11d9-bed3-505054503030": 2,  # Blocked connections only
    "0cce9235-69ae-11d9-bed3-505054503030": 3,  # Account management
    "0cce9237-69ae-11d9-bed3-505054503030": 3,  # Security groups
    "0cce921b-69ae-11d9-bed3-505054503030": 1,  # Special logon
    "0cce9211-69ae-11d9-bed3-505054503030": 3,  # Security extensions
    "0cce922f-69ae-11d9-bed3-505054503030": 3,  # Audit policy changes
}
PROFILE_ERROR_CODES = {
    "PROFILE_INVALID", "PROFILE_REPLAY", "PROFILE_CONFLICT", "PROFILE_BINDING",
    "PROFILE_STORAGE", "HOST_UNSUPPORTED", "HOST_IDENTITY_CHANGED",
    "PROFILE_RESPONSE_BINDING", "PROFILE_STATE_INVALID",
}


def canonical_profile_json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def profile_digest(profile):
    return hashlib.sha256(canonical_profile_json(profile).encode("ascii")).hexdigest()


def general_server_profile(*, enabled=True):
    if type(enabled) is not bool:
        raise ValueError("PROFILE_INVALID")
    return {
        "schema_version": PROFILE_SCHEMA,
        "profile_id": PROFILE_ID,
        "profile_version": PROFILE_VERSION,
        "enabled": enabled,
        "response_mode": "MONITOR_ONLY",
        "windows_channels": ["Security", "System"],
        "target_event_ids": list(GENERAL_EVENT_IDS),
        "capture_all_windows_channels": False,
        "capture_all_security_events": False,
        "web_log_paths": [],
        "audit_requirements": dict(GENERAL_AUDIT_REQUIREMENTS),
        "command_line_required": True,
        "audit_management": "VERIFY_ONLY",
    }


def validate_assignment(value, *, agent_id=None, tenant_id=None):
    if not isinstance(value, dict) or set(value) != {
        "agent_id", "tenant_id", "revision", "profile", "profile_hash"
    }:
        raise ValueError("PROFILE_INVALID")
    if len(canonical_profile_json(value).encode("ascii")) > MAX_PROFILE_BYTES:
        raise ValueError("PROFILE_INVALID")
    for field in ("agent_id", "tenant_id"):
        if not isinstance(value[field], str) or not 1 <= len(value[field]) <= 128:
            raise ValueError("PROFILE_BINDING")
    if agent_id is not None and value["agent_id"] != agent_id:
        raise ValueError("PROFILE_BINDING")
    if tenant_id is not None and value["tenant_id"] != tenant_id:
        raise ValueError("PROFILE_BINDING")
    if type(value["revision"]) is not int or not 1 <= value["revision"] <= 2147483647:
        raise ValueError("PROFILE_INVALID")
    profile = value["profile"]
    if not isinstance(profile, dict) or type(profile.get("enabled")) is not bool:
        raise ValueError("PROFILE_INVALID")
    expected = general_server_profile(enabled=profile["enabled"])
    # Comparing canonical bytes also rejects bool/int substitutions and extra fields.
    if canonical_profile_json(profile) != canonical_profile_json(expected):
        raise ValueError("PROFILE_INVALID")
    if value["profile_hash"] != profile_digest(profile):
        raise ValueError("PROFILE_INVALID")
    return copy.deepcopy(value)


def make_assignment(agent_id, tenant_id, revision, *, enabled=True):
    profile = general_server_profile(enabled=enabled)
    return validate_assignment({
        "agent_id": agent_id, "tenant_id": tenant_id, "revision": revision,
        "profile": profile, "profile_hash": profile_digest(profile),
    })


def assignment_context(assignment):
    """Return the signed event provenance for one validated profile snapshot."""
    current = validate_assignment(assignment)
    if not current["profile"]["enabled"]:
        return None
    return {
        "profile_id": current["profile"]["profile_id"],
        "profile_version": current["profile"]["profile_version"],
        "profile_hash": current["profile_hash"],
        "assignment_revision": current["revision"],
    }


def assignment_allows_event(assignment, channel, event_id):
    """Apply only the fixed server allowlist; workstation flags never participate."""
    try:
        current = validate_assignment(assignment)
    except (TypeError, ValueError):
        return False
    profile = current["profile"]
    return bool(
        profile["enabled"]
        and channel in profile["windows_channels"]
        and str(event_id) in profile["target_event_ids"]
    )


def sanitize_host_facts(raw):
    raw = raw if isinstance(raw, dict) else {}
    product_type = raw.get("product_type")
    if type(product_type) is not int or product_type not in (1, 2, 3):
        product_type = 0
    build = raw.get("build")
    if type(build) is not int or not 0 <= build <= 999999:
        build = 0
    fingerprint = str(raw.get("machine_fingerprint") or "").lower()
    if len(fingerprint) != 64 or any(c not in "0123456789abcdef" for c in fingerprint):
        fingerprint = ""
    return {
        "product_type": product_type,
        "build": build,
        "edition_id": str(raw.get("edition_id") or "")[:64],
        "installation_type": str(raw.get("installation_type") or "")[:32],
        "architecture": str(raw.get("architecture") or "")[:16].upper(),
        "domain_joined": raw.get("domain_joined") if type(raw.get("domain_joined")) is bool else None,
        "machine_fingerprint": fingerprint,
    }


def general_server_compatible(facts):
    facts = sanitize_host_facts(facts)
    return (
        facts["product_type"] == 3
        and facts["build"] == 20348
        and facts["installation_type"] == "Server"
        and facts["edition_id"] in {"ServerStandard", "ServerStandardEval"}
        and facts["architecture"] in {"AMD64", "X86_64"}
        and bool(facts["machine_fingerprint"])
    )


def server_response_blocked(agent, facts=None):
    """Legacy workstations are unchanged; a server observation is sticky."""
    agent = agent if isinstance(agent, dict) else {}
    if agent.get("server_monitoring_required") or agent.get("asset_class") == "server":
        return True
    if agent.get("monitoring_assignment"):
        return True
    return facts is not None and sanitize_host_facts(facts)["product_type"] != 1


def sanitize_profile_report(raw):
    raw = raw if isinstance(raw, dict) else {}
    state = raw.get("state")
    if state not in {"PENDING", "APPLIED", "PAUSED", "PROFILE_APPLY_FAILED", "UNSUPPORTED"}:
        state = "PENDING"
    revision = raw.get("applied_revision")
    if type(revision) is not int or not 0 <= revision <= 2147483647:
        revision = 0
    digest = str(raw.get("applied_profile_hash") or "")
    if len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
        digest = ""
    error = raw.get("error_code")
    audit = raw.get("audit") if isinstance(raw.get("audit"), dict) else {}
    audit_state = audit.get("state")
    if audit_state not in {"AUDIT_OK", "AUDIT_DRIFTED", "AUDIT_STALE", "AUDIT_UNKNOWN"}:
        audit_state = "AUDIT_UNKNOWN"
    missing = audit.get("missing")
    allowed_missing = set(GENERAL_AUDIT_REQUIREMENTS) | {"process_command_line"}
    return {
        "state": state,
        "applied_revision": revision,
        "applied_profile_id": PROFILE_ID if raw.get("applied_profile_id") == PROFILE_ID else None,
        "applied_profile_version": 1 if raw.get("applied_profile_version") == 1 else None,
        "applied_profile_hash": digest,
        "error_code": error if error in PROFILE_ERROR_CODES else None,
        "audit": {
            "state": audit_state,
            "observed_at": str(audit.get("observed_at") or "")[:64],
            "policy_owner": audit.get("policy_owner") if audit.get("policy_owner") in {"LOCAL", "DOMAIN_GPO"} else "UNKNOWN",
            "missing": sorted({str(x) for x in missing if str(x) in allowed_missing}) if isinstance(missing, list) else [],
        },
    }


def server_profile_health(agent, report, *, now=None):
    report = sanitize_profile_report(report)
    assignment = agent.get("monitoring_assignment")
    if not assignment:
        return "PROFILE_PENDING"
    try:
        assignment = validate_assignment(assignment, agent_id=agent.get("agent_id"), tenant_id=agent.get("tenant_id"))
    except ValueError:
        return "PROFILE_INVALID"
    if agent.get("host_identity_status") == "conflict":
        return "HOST_IDENTITY_CHANGED"
    if not general_server_compatible(agent.get("host_facts")):
        return "HOST_UNSUPPORTED"
    if (
        report["applied_revision"] != assignment["revision"]
        or report["applied_profile_hash"] != assignment["profile_hash"]
        or report["applied_profile_id"] != PROFILE_ID
        or report["applied_profile_version"] != PROFILE_VERSION
    ):
        return "PROFILE_PENDING"
    if report["state"] == "PROFILE_APPLY_FAILED":
        return "PROFILE_APPLY_FAILED"
    if not assignment["profile"]["enabled"]:
        return "PROFILE_PAUSED"
    if report["state"] != "APPLIED":
        return "PROFILE_PENDING"
    audit = report["audit"]
    try:
        observed = datetime.fromisoformat(audit["observed_at"].replace("Z", "+00:00"))
        if observed.tzinfo is None:
            return "AUDIT_UNKNOWN"
        age = ((now or datetime.now(timezone.utc)) - observed).total_seconds()
    except (ValueError, TypeError):
        return "AUDIT_UNKNOWN"
    if not -30 <= age <= AUDIT_MAX_AGE_SECONDS:
        return "AUDIT_STALE"
    if audit["state"] != "AUDIT_OK" or audit["missing"]:
        return "AUDIT_DRIFTED" if audit["missing"] else audit["state"]
    return "READY"
