import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from app.routes.compliance import _curate_evidence_record
from app.utils.compliance_catalog import (
    CLAIM_STATES,
    COMPLIANCE_CATALOG,
    COMPLIANCE_CATALOG_VERSION,
    EVIDENCE_STATES,
)
from app.utils.compliance_legal_registry import LEGAL_REFERENCE_REGISTRY
from scripts.generate_api_security_inventory import build_inventory


REPO_ROOT = Path(__file__).resolve().parents[1]


def test_phase0_preserves_runtime_control_and_retention_contracts():
    peca = COMPLIANCE_CATALOG["peca_forensic"]
    fbr = COMPLIANCE_CATALOG["fbr_pos"]

    assert COMPLIANCE_CATALOG_VERSION == "2026-08-24.tenant-retention-v4"
    assert {str(rule["event_id"]) for rule in peca["rules"]} == {
        "4625",
        "1102",
        "4624",
        "4688",
        "4672",
        "4720",
        "4726",
        "4732",
        "4697",
        "7045",
        "1100",
    }
    assert {str(rule["event_id"]) for rule in fbr["rules"]} == {
        "FBR-INV-DEL",
        "FBR-INV-MOD",
        "4660",
        "4663",
        "4670",
        "FIM-DB-MOD",
    }
    assert peca["retention"]["local_hot_days"] == 7
    assert peca["retention"]["vault_days"] is None
    assert peca["retention"]["inherits_tenant_retention_days"] is True
    assert peca["retention"]["basis"] == "TENANT_RETENTION_ENTITLEMENT"
    assert fbr["retention"]["local_hot_days"] == 7
    assert fbr["retention"]["vault_days"] is None
    assert fbr["retention"]["inherits_tenant_retention_days"] is True
    assert fbr["retention"]["basis"] == "TENANT_RETENTION_ENTITLEMENT"


def test_phase0_corrects_claims_and_keeps_legal_status_explicit():
    peca = COMPLIANCE_CATALOG["peca_forensic"]
    fbr = COMPLIANCE_CATALOG["fbr_pos"]
    sro_288 = LEGAL_REFERENCE_REGISTRY["PK_FBR_SRO_288_I_2026_DRAFT"]

    assert "section 46" not in peca["name"].lower()
    assert "statutory compliance declaration" in peca["description"].lower()
    assert "not an fbr-licensed integrator" in fbr["description"].lower()
    assert sro_288["instrument_status"] == "DRAFT"
    assert sro_288["tax_regime"] == "INCOME_TAX"
    assert "PK_FBR_SRO_288_I_2026_DRAFT" not in {
        reference_id
        for rule in fbr["rules"]
        for reference_id in rule["legal_reference_ids"]
    }


def test_every_control_has_evidence_claim_and_reference_metadata():
    required = {
        "control_id",
        "evidence_source_class",
        "required_telemetry",
        "evidence_purpose",
        "legal_relevance",
        "legal_reference_ids",
        "mapping_type",
        "applicability",
        "claim_state",
        "claim_boundary",
        "retention_basis",
    }
    for pack in COMPLIANCE_CATALOG.values():
        for rule in pack["rules"]:
            assert required <= set(rule)
            assert rule["claim_state"] in CLAIM_STATES
            assert rule["legal_reference_ids"]
            assert all(
                reference_id in LEGAL_REFERENCE_REGISTRY
                for reference_id in rule["legal_reference_ids"]
            )


def test_fbr_semantic_and_fim_evidence_remain_separate():
    rules = {
        rule["event_id"]: rule for rule in COMPLIANCE_CATALOG["fbr_pos"]["rules"]
    }

    assert rules["FBR-INV-DEL"]["evidence_source_class"] == "POS_SEMANTIC"
    assert rules["FBR-INV-MOD"]["evidence_source_class"] == "POS_SEMANTIC"
    assert rules["4660"]["evidence_source_class"] == "WINDOWS_FIM"
    assert rules["4663"]["evidence_source_class"] == "WINDOWS_FIM"
    assert rules["4670"]["evidence_source_class"] == "WINDOWS_FIM"
    assert rules["FIM-DB-MOD"]["evidence_source_class"] == "WINDOWS_FIM"
    assert all(rule["what_it_does_not_prove"] for rule in rules.values())


def test_curated_evidence_separates_observation_from_claim_state():
    observed = _curate_evidence_record(
        {
            "_id": "phase0-evidence",
            "tenant_id": "TENANT-PHASE0",
            "agent_id": "AGENT-PHASE0",
            "event_uid": "EVENT-PHASE0",
            "event_id": "4625",
            "timestamp": "2026-08-20T10:00:00Z",
            "message": "Failed logon",
            "signature_verified": True,
            "signature_verification_status": "verified",
            "source_envelope_uid": "envelope-phase0",
            "source_envelope_state": "COMMITTED",
            "forensic_seal": "rsa-pss-signature",
            "digital_signature": "RSA-2048-PSS-SHA256 (WarSOC Master)",
            "canonicalization_version": "canonicaljson-v1",
            "encryption_version": "fernet-v1",
        },
        "peca_forensic",
        "peca_forensic_logs",
    )
    unknown = _curate_evidence_record(
        {"_id": "unknown", "event_id": "999999", "message": "Unknown"},
        "peca_forensic",
        "peca_forensic_logs",
    )

    assert observed["control_id"] == "PECA-101"
    assert observed["evidence_state"] == "OBSERVED"
    assert observed["claim_state"] == "CONDITIONALLY_SUPPORTED"
    assert observed["time_trust_state"] == "DEGRADED"
    assert all(observed["evidence_checks"].values())
    assert observed["evidence_state"] in EVIDENCE_STATES
    assert unknown["control_id"] is None
    assert unknown["evidence_state"] == "UNVERIFIED"
    assert unknown["claim_state"] == "UNSUPPORTED"


def test_generated_api_security_inventory_matches_source_and_sensitive_boundaries():
    inventory = build_inventory(REPO_ROOT)
    committed = json.loads(
        (
            REPO_ROOT
            / "docs"
            / "generated"
            / "WARSOC_API_SECURITY_INVENTORY.json"
        ).read_text(encoding="utf-8")
    )

    assert inventory == committed
    assert inventory["summary"]["route_count"] >= 100
    assert inventory["summary"]["manual_review_required"] == 0
    assert all(not route["source_file"].startswith(("C:/", "/")) for route in inventory["routes"])

    routes = {
        (route["method"], route["route"]): route for route in inventory["routes"]
    }
    assert routes[("POST", "/api/v1/ingest/pulse")]["auth_type"] == "AGENT_IDENTITY"
    assert routes[("POST", "/api/v1/fbr/pos/ingest")]["tenant_scope"] == "SERVICE_IDENTITY_TENANT"
    assert routes[("GET", "/api/v1/compliance/evidence")]["allowed_roles"] == [
        "admin",
        "auditor",
    ]
    assert routes[("POST", "/api/v1/admin/provision")]["auth_type"] == "PLATFORM_ADMIN_KEY"
    assert routes[("GET", "/api/v1/network-relay/status")]["feature_condition"] == "settings.network_relay_enabled"


def test_reports_do_not_claim_to_be_compliance_certificates():
    report_source = (REPO_ROOT / "app" / "utils" / "report_engine.py").read_text(
        encoding="utf-8"
    )

    assert "Compliance Certificate" not in report_source
    assert "FBR Evidence Readiness Report" in report_source
    assert "PECA-Oriented Evidence Ledger" in report_source


@pytest.mark.asyncio
async def test_compliance_api_publishes_phase0_claim_metadata(
    client, authenticated_user
):
    response = await client.get(
        "/api/v1/compliance/packs", headers=authenticated_user
    )

    assert response.status_code == 200
    packs = {pack["pack_id"]: pack for pack in response.json()}
    assert packs["peca_forensic"]["catalog_version"] == COMPLIANCE_CATALOG_VERSION
    assert "Section 46" not in packs["peca_forensic"]["name"]
    assert packs["fbr_pos"]["claim_boundary"]

    detail = await client.get(
        "/api/v1/compliance/packs/fbr_pos", headers=authenticated_user
    )
    assert detail.status_code == 200
    body = detail.json()
    assert body["catalog_version"] == COMPLIANCE_CATALOG_VERSION
    assert len(body["monitored_events"]) == 6
    assert all(rule["claim_boundary"] for rule in body["monitored_events"])


@pytest.mark.asyncio
async def test_retention_status_is_tenant_scoped_and_uses_active_product_model(
    client, authenticated_user, db
):
    tenant = await db["tenants"].find_one({}, {"tenant_id": 1})
    assert tenant is not None
    tenant_id = tenant["tenant_id"]
    now = datetime.now(timezone.utc)
    await db["tenants"].update_one(
        {"tenant_id": tenant_id},
        {"$set": {"retention_days": 270}},
    )
    await db["legal_holds"].insert_many(
        [
            {"tenant_id": tenant_id, "hold_id": "HOLD-A", "status": "ACTIVE"},
            {"tenant_id": "OTHER-TENANT", "hold_id": "HOLD-B", "status": "ACTIVE"},
        ]
    )
    await db["storage_archives"].insert_many(
        [
            {
                "tenant_id": tenant_id,
                "archive_key": "archive-a",
                "status": "archived_hot_deleted",
                "created_at": now,
                "container_name": "must-not-be-returned",
                "blob_name": "must-not-be-returned",
            },
            {
                "tenant_id": "OTHER-TENANT",
                "archive_key": "archive-b",
                "status": "archived_hot_deleted",
                "created_at": now,
            },
        ]
    )

    response = await client.get(
        "/api/v1/compliance/retention/status",
        headers=authenticated_user,
    )

    assert response.status_code == 200
    retention = response.json()["retention"]
    assert retention["model"] == "TENANT_ENTITLEMENT_V1"
    assert retention["tenant_retention_days"] == 270
    assert retention["hot_storage_days"] == 7
    assert retention["fbr_archive_retention_days"] == 270
    assert retention["peca_archive_retention_days"] == 270
    assert retention["peca_retention_model"] == "TENANT_ENTITLEMENT_V1"
    assert retention["active_hold_count"] == 1
    assert retention["archive_availability"] == "ARCHIVED_EVIDENCE_AVAILABLE"
    assert retention["archived_batch_count"] == 1
    assert "container_name" not in retention
    assert "blob_name" not in retention
    assert "tax_period" not in retention
