from datetime import datetime, timezone

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from app.routes.ingest_pulse import _verify_endpoint_event
from app.utils.agent_crypto import (
    AgentEventSignatureError,
    build_event_signature_string,
    build_payload_hash,
    build_signable_event_payload,
    verify_event_signature,
)


def _keypair():
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_pem = private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")
    return private_key, public_pem


def _signed_event(private_key, agent_id="WARSOC_AGENT_SIGNING"):
    event = {
        "agent_id": agent_id,
        "event_id": "4688",
        "event_uid": "evt-signing-001",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source_ip": "192.0.2.10",
        "user": "Operator",
        "message": "Windows process creation",
        "event_type": "process_create",
        "processed_data": {"process_name": "cmd.exe"},
        "raw_event_data": {"CommandLine": "cmd.exe /c whoami"},
        "agent_version": "4.2.5-Native-Signed",
        "signature_version": "ed25519-v1",
        "signature_algorithm": "Ed25519",
    }
    payload_hash = build_payload_hash(build_signable_event_payload(event))
    event["payload_hash"] = payload_hash
    signature_input = build_event_signature_string(
        agent_id,
        event["timestamp"],
        event["event_uid"],
        payload_hash,
    )
    event["agent_signature"] = private_key.sign(signature_input.encode("utf-8")).hex()
    return event


def test_ed25519_event_signature_verifies_and_returns_provenance():
    private_key, public_pem = _keypair()
    event = _signed_event(private_key)

    result = verify_event_signature(
        event,
        agent_id=event["agent_id"],
        public_key_pem=public_pem,
    )

    assert result["signature_verified"] is True
    assert result["source_assurance"] == "agent_signed"
    assert result["signature_algorithm"] == "Ed25519"
    assert len(result["signing_key_id"]) == 64


def test_mutated_signed_event_is_rejected():
    private_key, public_pem = _keypair()
    event = _signed_event(private_key)
    event["message"] = "tampered after signing"

    with pytest.raises(AgentEventSignatureError, match="hash mismatch"):
        verify_event_signature(
            event,
            agent_id=event["agent_id"],
            public_key_pem=public_pem,
        )


def test_mutated_detection_routing_field_is_rejected():
    private_key, public_pem = _keypair()
    event = _signed_event(private_key)
    event["event_type"] = "http_request"

    with pytest.raises(AgentEventSignatureError, match="hash mismatch"):
        verify_event_signature(
            event,
            agent_id=event["agent_id"],
            public_key_pem=public_pem,
        )


def test_wrong_agent_identity_is_rejected():
    private_key, public_pem = _keypair()
    event = _signed_event(private_key)

    with pytest.raises(AgentEventSignatureError, match="verification failed"):
        verify_event_signature(
            event,
            agent_id="WARSOC_AGENT_OTHER",
            public_key_pem=public_pem,
        )


def test_observe_mode_marks_unsigned_legacy_event(monkeypatch):
    monkeypatch.setenv("AGENT_EVENT_SIGNATURE_MODE", "observe")
    candidate = _verify_endpoint_event(
        {"event_uid": "legacy-1", "timestamp": "2026-01-01T00:00:00+00:00"},
        {"agent_id": "WARSOC_AGENT_LEGACY", "public_key": ""},
    )

    assert candidate["signature_verified"] is False
    assert candidate["source_assurance"] == "agent_jwt_only"
    assert candidate["signature_verification_status"] == "unsigned_legacy"


def test_required_mode_rejects_unsigned_event(monkeypatch):
    monkeypatch.setenv("AGENT_EVENT_SIGNATURE_MODE", "required")
    with pytest.raises(AgentEventSignatureError, match="required"):
        _verify_endpoint_event(
            {"event_uid": "legacy-1", "timestamp": "2026-01-01T00:00:00+00:00"},
            {"agent_id": "WARSOC_AGENT_LEGACY", "public_key": ""},
        )
