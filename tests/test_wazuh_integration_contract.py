from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from cryptography.fernet import Fernet
from pydantic import ValidationError

from app.wazuh_integration.contracts import (
    DETECTION_CANDIDATE_SCHEMA,
    DETECTION_INPUT_SCHEMA,
    DetectionCandidate,
    DetectionCandidateBatch,
    DetectionInput,
)
from app.wazuh_integration.security import (
    ConnectorBodyTooLarge,
    ConnectorSecurityError,
    build_signed_headers,
    decrypt_payload,
    encrypt_payload,
    purpose_hmac,
    read_bounded_request_body,
    verify_signed_request,
)


NOW = datetime(2026, 8, 11, 12, 0, tzinfo=timezone.utc)
DISPATCH_UID = "WZD_0123456789ABCDEF0123456789ABCDEF"


def _input_payload(**overrides):
    payload = {
        "schema": DETECTION_INPUT_SCHEMA,
        "dispatch_uid": DISPATCH_UID,
        "event_uid": "event-00000001",
        "tenant_scope": "a" * 64,
        "source_family": "windows_endpoint",
        "source_assurance": "endpoint_signed",
        "original_event_time": NOW - timedelta(seconds=2),
        "receipt_time": NOW - timedelta(seconds=1),
        "dispatch_time": NOW,
        "dispatch_mode": "live",
        "event_age_ms": 2000,
        "event_id": "4688",
        "endpoint_id": "endpoint-01",
        "correlation_key_version": "corr-v1",
        "correlation_keys": {"corr_tenant": "b" * 64},
        "security_fields": {
            "process_name": "powershell.exe",
            "command_line": "powershell.exe -NoProfile",
        },
    }
    payload.update(overrides)
    return payload


def test_detection_input_accepts_minimized_signed_endpoint_event():
    parsed = DetectionInput.model_validate(_input_payload())
    serialized = parsed.model_dump(mode="json", by_alias=True)
    assert serialized["schema"] == DETECTION_INPUT_SCHEMA
    assert serialized["source_assurance"] == "endpoint_signed"
    assert "tenant_id" not in serialized


@pytest.mark.parametrize(
    ("source_family", "source_assurance"),
    [
        ("windows_endpoint", "relay_attested"),
        ("network_device", "endpoint_signed"),
        ("web_application", "relay_attested"),
    ],
)
def test_detection_input_rejects_source_assurance_mismatch(source_family, source_assurance):
    with pytest.raises(ValidationError, match="source assurance"):
        DetectionInput.model_validate(
            _input_payload(
                source_family=source_family,
                source_assurance=source_assurance,
            )
        )


@pytest.mark.parametrize(
    "bad_fields",
    [
        {"nested": {"secret": "value"}},
        {"array": ["one", "two"]},
        {"binary": b"not-json"},
    ],
)
def test_detection_input_rejects_nested_or_binary_security_fields(bad_fields):
    with pytest.raises(ValidationError, match="not allowed"):
        DetectionInput.model_validate(_input_payload(security_fields=bad_fields))


def test_candidate_contract_has_no_tenant_authority():
    candidate = DetectionCandidate.model_validate(
        {
            "schema": DETECTION_CANDIDATE_SCHEMA,
            "connector_id": "wazuh-shadow-01",
            "engine_instance_id": "wazuh-node-01",
            "engine_version": "4.14.7",
            "ruleset_version": "ruleset-20260811",
            "engine_alert_id": "alert-01",
            "engine_rule_id": "100001",
            "engine_rule_level": 10,
            "engine_detected_at": NOW,
            "trigger_dispatch_uid": DISPATCH_UID,
            "engine_reported_category": "credential_attack",
            "engine_reported_mitre_ids": ["T1110", "T1110"],
            "engine_context": {"decoder": "json"},
        }
    )
    assert candidate.engine_reported_mitre_ids == ["T1110"]
    with pytest.raises(ValidationError):
        DetectionCandidate.model_validate(
            {
                **candidate.model_dump(mode="json", by_alias=True),
                "tenant_id": "WARSOC_FORGED",
            }
        )


def test_candidate_batch_rejects_duplicate_engine_delivery_identity():
    base = {
        "schema": DETECTION_CANDIDATE_SCHEMA,
        "connector_id": "wazuh-shadow-01",
        "engine_instance_id": "wazuh-node-01",
        "engine_version": "4.14.7",
        "ruleset_version": "ruleset-20260811",
        "engine_alert_id": "alert-01",
        "engine_rule_id": "100001",
        "engine_rule_level": 10,
        "engine_detected_at": NOW,
        "trigger_dispatch_uid": DISPATCH_UID,
        "engine_reported_category": "credential_attack",
    }
    with pytest.raises(ValidationError, match="duplicate engine delivery"):
        DetectionCandidateBatch.model_validate(
            {
                "schema": "warsoc.detection-candidate-batch/v1",
                "batch_id": "WZB_0123456789ABCDEF0123456789ABCDEF",
                "connector_id": "wazuh-shadow-01",
                "created_at": NOW,
                "candidates": [base, base],
            }
        )


def test_signed_request_detects_tamper_stale_time_and_wrong_connector():
    secret = "dispatch-secret-" + "x" * 48
    body = b'{"schema":"warsoc.detection-input-batch/v1"}'
    headers = build_signed_headers(
        secret=secret,
        connector_id="wazuh-shadow-01",
        body=body,
        timestamp=NOW,
        nonce="a" * 32,
    )
    nonce, received_at = verify_signed_request(
        secret=secret,
        expected_connector_id="wazuh-shadow-01",
        headers=headers,
        body=body,
        now=NOW,
    )
    assert nonce == "a" * 32
    assert received_at == NOW

    with pytest.raises(ConnectorSecurityError, match="body hash"):
        verify_signed_request(
            secret=secret,
            expected_connector_id="wazuh-shadow-01",
            headers=headers,
            body=body + b"tampered",
            now=NOW,
        )
    with pytest.raises(ConnectorSecurityError, match="identity"):
        verify_signed_request(
            secret=secret,
            expected_connector_id="different-connector",
            headers=headers,
            body=body,
            now=NOW,
        )
    with pytest.raises(ConnectorSecurityError, match="outside the allowed window"):
        verify_signed_request(
            secret=secret,
            expected_connector_id="wazuh-shadow-01",
            headers=headers,
            body=body,
            now=NOW + timedelta(minutes=6),
        )


def test_connector_encryption_and_purpose_separated_hmac():
    key = Fernet.generate_key().decode("ascii")
    token = encrypt_payload(key, b"minimized security fields")
    assert decrypt_payload(key, token) == b"minimized security fields"

    secret = "correlation-secret-" + "y" * 48
    tenant = purpose_hmac(secret, purpose="tenant", values=["WARSOC_A"])
    actor = purpose_hmac(secret, purpose="tenant-actor", values=["WARSOC_A", "user"])
    other_tenant = purpose_hmac(secret, purpose="tenant", values=["WARSOC_B"])
    assert len(tenant) == 64
    assert tenant != actor
    assert tenant != other_tenant


class _StreamingRequest:
    def __init__(self, chunks, content_length=None):
        self.headers = {}
        if content_length is not None:
            self.headers["content-length"] = str(content_length)
        self._chunks = chunks

    async def stream(self):
        for chunk in self._chunks:
            yield chunk


@pytest.mark.asyncio
async def test_bounded_connector_body_rejects_chunked_overflow_before_full_buffering():
    request = _StreamingRequest([b"1234", b"5678", b"9"])
    with pytest.raises(ConnectorBodyTooLarge, match="byte limit"):
        await read_bounded_request_body(request, max_bytes=8)


@pytest.mark.asyncio
async def test_bounded_connector_body_rejects_invalid_claimed_length():
    request = _StreamingRequest([b"{}"], content_length="invalid")
    with pytest.raises(ConnectorSecurityError, match="content length"):
        await read_bounded_request_body(request, max_bytes=8)
