import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from app.routes.evidence_cases import CASE_EVIDENCE_COLLECTIONS, CustodyActionRequest
from app.utils.compliance_chain import case_evidence_record_digest
from app.wazuh_integration.registry import validate_registry_document


REGISTRY_DIR = Path(__file__).parent.parent / "deploy" / "wazuh" / "registry"


def _registry(name: str) -> dict:
    return json.loads((REGISTRY_DIR / name).read_text(encoding="utf-8"))


def test_legacy_registry_remains_the_reviewed_six_rule_baseline():
    document = _registry("warsoc-v1-production-registry.json")
    rules = validate_registry_document(document)

    assert set(rules) == {"63103", "60117", "60122", "60105", "61138", "67027"}
    assert not {
        "60106",
        "60200",
        "60201",
        "60202",
        "60600",
        "60601",
        "60602",
    }.intersection(rules)


def test_active_projected_registry_is_shadow_only():
    document = _registry("warsoc-projected-shadow-v2.json")
    rules = validate_registry_document(document)

    assert document["ruleset_version"] == "warsoc-projected-shadow-v2"
    assert document["authority_mode"] == "shadow_only"
    assert len(rules) == 22
    assert {rule["family_status"] for rule in rules.values()} == {"shadow"}


def test_detection_observations_are_not_case_evidence_sources():
    assert "detection_engine_observations" not in CASE_EVIDENCE_COLLECTIONS
    assert "detection_shadow_observations" not in CASE_EVIDENCE_COLLECTIONS


def test_custody_action_rejects_unimplemented_counter_signature():
    request = CustodyActionRequest(
        action="VERIFY",
        reason="Routine integrity verification for this evidence case",
    )
    assert request.action == "VERIFY"

    with pytest.raises(ValidationError):
        CustodyActionRequest(
            action="VERIFY",
            reason="Attempt to claim an independent second approval",
            counter_signer_email="auditor@example.test",
        )


def test_detection_admission_has_no_implicit_retention_hold():
    source = (
        Path(__file__).parent.parent
        / "app"
        / "wazuh_integration"
        / "candidate_service.py"
    ).read_text(encoding="utf-8")

    assert "auto_hold_for_detection" not in source
    assert "DETECTION_AUTO_HOLD" not in source
    assert not (
        Path(__file__).parent.parent
        / "app"
        / "services"
        / "evidence_hold_service.py"
    ).exists()


def test_case_hash_ignores_only_alert_workflow_metadata():
    alert = {
        "tenant_id": "tenant-1",
        "alert_uid": "alert-1",
        "event_uid": "event-1",
        "severity": "HIGH",
        "status": "NEW",
        "updated_by": "worker",
    }
    original = case_evidence_record_digest("security_alerts", alert)

    workflow_update = {
        **alert,
        "status": "CLOSED",
        "resolution_notes": "Reviewed by the operator",
        "updated_by": "admin@example.test",
    }
    assert case_evidence_record_digest("security_alerts", workflow_update) == original

    changed_evidence = {**workflow_update, "severity": "LOW"}
    assert case_evidence_record_digest("security_alerts", changed_evidence) != original
