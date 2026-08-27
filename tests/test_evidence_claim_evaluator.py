from app.utils.evidence_claims import evaluate_evidence_claim
from app.utils.compliance_catalog import get_rule_for_pack


def _trusted_peca_record() -> dict:
    return {
        "tenant_id": "TENANT-A",
        "agent_id": "AGENT-A",
        "event_uid": "EVENT-A",
        "event_id": "4625",
        "timestamp": "2026-08-20T10:00:00Z",
        "agent_collection_time": "2026-08-20T10:00:01Z",
        "signature_version": "ed25519-v2",
        "signature_verified": True,
        "signature_verification_status": "verified",
        "source_envelope_uid": "nonce:peca",
        "source_envelope_state": "COMMITTED",
        "forensic_seal": "rsa-pss-signature",
        "digital_signature": "RSA-2048-PSS-SHA256 (WarSOC Master)",
        "canonicalization_version": "canonicaljson-v1",
        "encryption_version": "fernet-v1",
    }


def test_matching_event_is_not_observed_without_evidence_proof():
    rule = get_rule_for_pack("peca_forensic", "4625")
    result = evaluate_evidence_claim(
        {"event_id": "4625", "timestamp": "2026-08-20T10:00:00Z"},
        "peca_forensic",
        rule,
    )

    assert result["evidence_state"] == "UNVERIFIED"
    assert result["claim_state"] == "UNSUPPORTED"
    assert "source_signature_verified" in result["evidence_gaps"]
    assert "source_envelope_committed" in result["evidence_gaps"]


def test_signed_sealed_linked_peca_record_is_observed_with_trusted_time():
    rule = get_rule_for_pack("peca_forensic", "4625")
    result = evaluate_evidence_claim(_trusted_peca_record(), "peca_forensic", rule)

    assert result["evidence_state"] == "OBSERVED"
    assert result["claim_state"] == "CONDITIONALLY_SUPPORTED"
    assert result["time_trust_state"] == "TRUSTED"
    assert result["evidence_gaps"] == []


def test_fbr_observation_with_unresolved_retention_does_not_support_claim():
    rule = get_rule_for_pack("fbr_pos", "FBR-INV-MOD")
    record = {
        "tenant_id": "TENANT-A",
        "agent_id": "AGENT-A",
        "event_uid": "EVENT-FBR-A",
        "event_id": "FBR-INV-MOD",
        "invoice_id": "INV-001",
        "user": "cashier-1",
        "timestamp": "2026-08-20T10:00:00Z",
        "signature_version": "ed25519-http-body-v1",
        "signature_verified": True,
        "signature_verification_status": "verified",
        "source_envelope_uid": "pos-nonce",
        "source_envelope_state": "COMMITTED",
        "encryption_version": "fernet-v1",
        "retention_state": "UNRESOLVED",
    }
    result = evaluate_evidence_claim(record, "fbr_pos", rule)

    assert result["evidence_state"] == "OBSERVED"
    assert result["claim_state"] == "UNSUPPORTED"
    assert result["retention_ready"] is False
    assert "retention_basis_unresolved" in result["evidence_gaps"]


def test_fbr_observation_with_tenant_retention_supports_claim():
    rule = get_rule_for_pack("fbr_pos", "FBR-INV-MOD")
    record = {
        "tenant_id": "TENANT-A",
        "agent_id": "AGENT-A",
        "event_uid": "EVENT-FBR-TENANT",
        "event_id": "FBR-INV-MOD",
        "invoice_id": "INV-002",
        "user": "cashier-1",
        "timestamp": "2026-08-20T10:00:00Z",
        "signature_version": "ed25519-http-body-v1",
        "signature_verified": True,
        "signature_verification_status": "verified",
        "source_envelope_uid": "pos-nonce-tenant",
        "source_envelope_state": "COMMITTED",
        "encryption_version": "fernet-v1",
        "retention_model": "TENANT_ENTITLEMENT_V1",
        "retention_state": "TENANT_POLICY",
        "retention_basis": "TENANT_RETENTION_ENTITLEMENT",
    }
    result = evaluate_evidence_claim(record, "fbr_pos", rule)

    assert result["evidence_state"] == "OBSERVED"
    assert result["claim_state"] == "CONDITIONALLY_SUPPORTED"
    assert result["retention_ready"] is True
    assert result["evidence_gaps"] == []


def test_fbr_fim_requires_non_reversible_target_identity():
    rule = get_rule_for_pack("fbr_pos", "4663")
    record = {
        "tenant_id": "TENANT-A",
        "agent_id": "AGENT-A",
        "event_uid": "EVENT-FIM-A",
        "event_id": "4663",
        "timestamp": "2026-08-20T10:00:00Z",
        "signature_verified": True,
        "signature_verification_status": "verified",
        "source_envelope_uid": "endpoint-nonce:fbr:pk-st-2026-08",
        "source_envelope_state": "COMMITTED",
        "encryption_version": "fernet-v1",
        "retention_state": "RESOLVED",
    }
    result = evaluate_evidence_claim(record, "fbr_pos", rule)

    assert result["evidence_state"] == "UNVERIFIED"
    assert "required_source_fields_present" in result["evidence_gaps"]
