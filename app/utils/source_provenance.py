"""Server-owned source provenance and compliance eligibility contracts."""

from __future__ import annotations

from typing import Final


SIGNED_WINDOWS_AGENT: Final = "signed_windows_agent"
AUTHENTICATED_POS: Final = "authenticated_pos"
RELAY_ATTESTED_NETWORK: Final = "relay_attested_network"
LEGACY_SYSLOG: Final = "legacy_syslog"
LEGACY_ENDPOINT_UNVERIFIED: Final = "legacy_endpoint_unverified"
INTERNAL_TEST: Final = "internal_test"

WINDOWS_ENDPOINT_PROFILE: Final = "windows_endpoint"
FBR_POS_SEMANTIC_PROFILE: Final = "fbr_pos_semantic"
NETWORK_TELEMETRY_PROFILE: Final = "network_telemetry"
INTERNAL_TEST_PROFILE: Final = "internal_test"


def classify_source(event: dict) -> tuple[str, str]:
    """Return a conservative server-side source classification.

    Explicit values are accepted only when they agree with cryptographic
    admission metadata. This keeps client-supplied labels from promoting an
    event into compliance evidence.
    """

    event_type = str(event.get("type") or event.get("event_type") or "").strip().lower()
    assurance = str(event.get("source_assurance") or "").strip().lower()
    signature_verified = event.get("signature_verified") is True
    signature_version = str(event.get("signature_version") or "").strip().lower()

    if event_type == "network_log":
        return LEGACY_SYSLOG, NETWORK_TELEMETRY_PROFILE
    if assurance == "relay_attested" and signature_verified:
        return RELAY_ATTESTED_NETWORK, NETWORK_TELEMETRY_PROFILE
    if (
        event_type == "fbr_pos"
        and assurance == "agent_signed"
        and signature_verified
        and signature_version == "ed25519-http-body-v1"
    ):
        return AUTHENTICATED_POS, FBR_POS_SEMANTIC_PROFILE
    if assurance == "agent_signed" and signature_verified:
        return SIGNED_WINDOWS_AGENT, WINDOWS_ENDPOINT_PROFILE
    if str(event.get("source_class") or "").strip().lower() == INTERNAL_TEST:
        return INTERNAL_TEST, INTERNAL_TEST_PROFILE
    return LEGACY_ENDPOINT_UNVERIFIED, WINDOWS_ENDPOINT_PROFILE


def apply_source_provenance(event: dict) -> dict:
    source_class, evidence_profile = classify_source(event)
    event["source_class"] = source_class
    event["evidence_profile"] = evidence_profile
    event["compliance_source_eligible"] = source_class in {
        SIGNED_WINDOWS_AGENT,
        AUTHENTICATED_POS,
    }
    return event


def compliance_source_allowed(event: dict, domain: str) -> bool:
    source_class, evidence_profile = classify_source(event)
    if domain == "peca":
        return (
            source_class == SIGNED_WINDOWS_AGENT
            and evidence_profile == WINDOWS_ENDPOINT_PROFILE
        )
    if domain == "fbr":
        return (
            source_class == SIGNED_WINDOWS_AGENT
            and evidence_profile == WINDOWS_ENDPOINT_PROFILE
        ) or (
            source_class == AUTHENTICATED_POS
            and evidence_profile == FBR_POS_SEMANTIC_PROFILE
        )
    raise ValueError(f"Unsupported compliance domain: {domain}")
