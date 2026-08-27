"""Evidence-state and claim-readiness evaluation for compliance records."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any


def _present(value: Any) -> bool:
    return value not in (None, "", {}, [])


def _parse_timestamp(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
    else:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def evaluate_evidence_claim(doc: dict, pack_id: str, rule: dict | None) -> dict:
    """Derive technical observation and claim state without making legal conclusions."""

    event_timestamp = _parse_timestamp(doc.get("timestamp") or doc.get("ingested_at"))
    collection_timestamp = _parse_timestamp(doc.get("agent_collection_time"))
    signature_version = str(doc.get("signature_version") or "").strip().lower()

    if not event_timestamp:
        time_state = "UNTRUSTED"
    elif signature_version == "ed25519-v2" and collection_timestamp:
        time_state = "TRUSTED"
    else:
        time_state = "DEGRADED"

    checks = {
        "catalog_control_matched": rule is not None,
        "identity_complete": all(
            _present(doc.get(field))
            for field in ("tenant_id", "agent_id", "event_uid")
        ),
        "event_time_present": event_timestamp is not None,
        "source_signature_verified": (
            doc.get("signature_verified") is True
            and str(doc.get("signature_verification_status") or "").lower() == "verified"
        ),
        "source_envelope_committed": (
            _present(doc.get("source_envelope_uid"))
            and str(doc.get("source_envelope_state") or "").upper() == "COMMITTED"
        ),
    }

    source_class = str((rule or {}).get("evidence_source_class") or "")
    if pack_id == "peca_forensic":
        checks["server_integrity_protected"] = all(
            _present(doc.get(field))
            for field in (
                "forensic_seal",
                "digital_signature",
                "canonicalization_version",
                "encryption_version",
            )
        )
    else:
        checks["server_integrity_protected"] = (
            str(doc.get("encryption_version") or "").lower() == "fernet-v1"
        )

    if source_class == "POS_SEMANTIC":
        checks["required_source_fields_present"] = all(
            _present(doc.get(field)) for field in ("invoice_id", "user")
        )
    elif source_class == "WINDOWS_FIM":
        checks["required_source_fields_present"] = _present(
            doc.get("target_fingerprint")
        )
    else:
        checks["required_source_fields_present"] = True

    observation_ready = all(checks.values())
    evidence_state = "OBSERVED" if observation_ready else "UNVERIFIED"

    retention_ready = True
    if pack_id == "fbr_pos":
        retention_ready = str(doc.get("retention_state") or "").upper() in {
            "TENANT_POLICY",
            "RESOLVED",
            "HELD",
        }

    claim_ready = observation_ready and retention_ready and time_state != "UNTRUSTED"
    claim_state = (
        str((rule or {}).get("claim_state") or "UNSUPPORTED")
        if claim_ready
        else "UNSUPPORTED"
    )
    gaps = [name for name, passed in checks.items() if not passed]
    if not retention_ready:
        gaps.append("retention_basis_unresolved")

    return {
        "evidence_state": evidence_state,
        "claim_state": claim_state,
        "time_trust_state": time_state,
        "retention_ready": retention_ready,
        "evidence_checks": checks,
        "evidence_gaps": gaps,
    }
