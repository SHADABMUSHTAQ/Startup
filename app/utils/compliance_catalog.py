"""WarSOC compliance evidence catalog.

The catalog defines technical evidence controls, not legal conclusions. Pack
IDs, event IDs, and retention policy identifiers are runtime contracts shared
by the API, workers, and archiver.
"""

from __future__ import annotations

from app.utils.compliance_legal_registry import LEGAL_REFERENCE_REGISTRY


COMPLIANCE_CATALOG_VERSION = "2026-08-24.tenant-retention-v4"
EVIDENCE_STATES = frozenset(
    {"OBSERVED", "NOT_OBSERVED", "UNVERIFIED", "NOT_APPLICABLE"}
)
CLAIM_STATES = frozenset(
    {"SUPPORTED", "CONDITIONALLY_SUPPORTED", "UNSUPPORTED"}
)


def _peca_control(
    control_number: int,
    event_id: str,
    name: str,
    severity: str,
    evidence_purpose: str,
    required_channel: str,
) -> dict:
    control_id = f"PECA-{control_number}"
    return {
        "id": f"{control_id} ({event_id})",
        "control_id": control_id,
        "event_id": event_id,
        "name": name,
        "severity": severity,
        "evidence_source_class": "WINDOWS_ENDPOINT",
        "required_telemetry": [f"Windows {required_channel} event {event_id}"],
        "evidence_purpose": evidence_purpose,
        "legal_relevance": (
            "Potentially relevant to an authorized cybercrime investigation; "
            "applicability and legal effect require case-specific assessment."
        ),
        "legal_reference_ids": [
            "PK_PECA_2016_CURRENT",
            "PK_ETO_2002_SECTIONS_5_6",
        ],
        "mapping_type": "INVESTIGATION_SUPPORT",
        "applicability": "Windows endpoints with the required channel and audit policy",
        "claim_state": "CONDITIONALLY_SUPPORTED",
        "claim_boundary": (
            "Proves only that WarSOC preserved the reported endpoint observation. "
            "It does not by itself establish intent, attribution, offence, legal "
            "admissibility, blanket PECA compliance, or PECA section 32 traffic-data retention."
        ),
        "retention_basis": "TENANT_RETENTION_ENTITLEMENT",
    }


def _fbr_control(
    control_number: int,
    event_id: str,
    name: str,
    severity: str,
    source_class: str,
    evidence_purpose: str,
    proves: str,
    does_not_prove: str,
) -> dict:
    control_id = f"FBR-{control_number}"
    required_telemetry = (
        [f"Approved POS semantic event {event_id}"]
        if source_class == "POS_SEMANTIC"
        else [f"Windows FIM/audit event {event_id} on an approved protected path"]
    )
    return {
        "id": f"{control_id} ({event_id})",
        "control_id": control_id,
        "event_id": event_id,
        "name": name,
        "severity": severity,
        "tax_regime": "SALES_TAX",
        "evidence_source_class": source_class,
        "required_telemetry": required_telemetry,
        "evidence_purpose": evidence_purpose,
        "legal_relevance": (
            "Supports POS/digital-invoice record integrity and reconciliation; "
            "applicability requires the tenant's actual tax and invoicing context."
        ),
        "legal_reference_ids": [
            "PK_SALES_TAX_RULES_2006_CHAPTER_XIV",
            "PK_FBR_STGO_01_2026",
        ],
        "mapping_type": "EVIDENCE_READINESS",
        "applicability": "Approved tenant POS source or protected Windows POS path",
        "claim_state": "CONDITIONALLY_SUPPORTED",
        "what_it_proves": proves,
        "what_it_does_not_prove": does_not_prove,
        "claim_boundary": (
            "WarSOC preserves and compares source observations. It does not submit "
            "invoices to FBR, issue FBR invoice numbers, act as a licensed integrator, "
            "or automatically certify statutory compliance."
        ),
        "retention_basis": "TENANT_RETENTION_ENTITLEMENT",
    }


COMPLIANCE_CATALOG = {
    "peca_forensic": {
        "name": "WarSOC PECA Evidence Pack",
        "description": (
            "Signed endpoint evidence controls designed to support authorized "
            "security investigations. This profile is not a statutory compliance declaration."
        ),
        "evidence_domain": "PECA_ORIENTED_ENDPOINT_FORENSICS",
        "legal_reference_ids": [
            "PK_PECA_2016_CURRENT",
            "PK_ETO_2002_SECTIONS_5_6",
        ],
        "claim_boundary": (
            "The profile preserves endpoint observations with potential PECA relevance. "
            "It does not establish an offence, legal admissibility, blanket PECA compliance, "
            "or PECA section 32 traffic-data retention."
        ),
        "retention": {
            "local_hot_days": 7,
            "vault_days": None,
            "basis": "TENANT_RETENTION_ENTITLEMENT",
            "inherits_tenant_retention_days": True,
            "final_model_state": "ACTIVE_PRODUCT_MODEL",
        },
        "rules": [
            _peca_control(101, "4625", "Unauthorized Access Attempt (Failed Logon)", "High", "Preserve failed-authentication observations.", "Security"),
            _peca_control(102, "1102", "Forensic Log Deletion (Audit Cleared)", "Critical", "Preserve an audit-log clearing observation.", "Security"),
            _peca_control(103, "4624", "Successful Logon", "Informational", "Preserve successful-authentication context.", "Security"),
            _peca_control(104, "4688", "Process Creation", "Medium", "Preserve process-creation context for investigation.", "Security"),
            _peca_control(105, "4672", "Special Privileges Assigned", "Medium", "Preserve elevated-token assignment context.", "Security"),
            _peca_control(106, "4720", "Account Created", "High", "Preserve local account-creation evidence.", "Security"),
            _peca_control(107, "4726", "Account Deleted", "High", "Preserve local account-deletion evidence.", "Security"),
            _peca_control(108, "4732", "Local Group Membership Added", "High", "Preserve local group-membership change evidence.", "Security"),
            _peca_control(109, "4697", "Service Installation", "Critical", "Preserve Security-channel service-installation evidence.", "Security"),
            _peca_control(110, "7045", "New Windows Service", "Critical", "Preserve System-channel service-installation evidence.", "System"),
            _peca_control(111, "1100", "Event Logging Service Shut Down", "Critical", "Preserve an event-logging shutdown observation.", "Security"),
        ],
    },
    "fbr_pos": {
        "name": "WarSOC FBR POS Evidence Readiness",
        "description": (
            "POS semantic and file-integrity evidence supporting invoice-tamper "
            "investigation and future reconciliation. WarSOC is not an FBR-licensed integrator."
        ),
        "evidence_domain": "FBR_POS_AND_DIGITAL_INVOICE_EVIDENCE",
        "tax_regimes": ["SALES_TAX"],
        "legal_reference_ids": [
            "PK_SALES_TAX_RULES_2006_CHAPTER_XIV",
            "PK_FBR_STGO_01_2026",
            "PK_FBR_SRO_288_I_2026_DRAFT",
        ],
        "claim_boundary": (
            "WarSOC monitors evidence supplied by approved sources. It does not "
            "integrate a taxpayer with FBR, submit invoices, issue FBR invoice numbers, "
            "or certify statutory compliance."
        ),
        "retention": {
            "local_hot_days": 7,
            "vault_days": None,
            "basis": "TENANT_RETENTION_ENTITLEMENT",
            "inherits_tenant_retention_days": True,
            "final_model_state": "ACTIVE_PRODUCT_MODEL",
        },
        "rules": [
            _fbr_control(101, "FBR-INV-DEL", "Financial Record Deletion", "Warning", "POS_SEMANTIC", "Preserve an approved POS source's invoice-deletion statement.", "The approved POS source reported deletion of the identified record.", "That FBR accepted the original invoice or that the deletion was unauthorized."),
            _fbr_control(102, "FBR-INV-MOD", "Financial Record Modification", "Critical", "POS_SEMANTIC", "Preserve an approved POS source's invoice-modification statement.", "The approved POS source reported modification and supplied the recorded business fields.", "That the fields match an authoritative database or FBR submission without reconciliation."),
            _fbr_control(103, "4660", "Object Deleted", "Warning", "WINDOWS_FIM", "Preserve deletion evidence for an approved protected path.", "Windows reported deletion of an object on an approved protected path.", "Which invoice business fields changed or whether FBR accepted an invoice."),
            _fbr_control(104, "4663", "Database Delete Intent (Correlation Context)", "Informational", "WINDOWS_FIM", "Preserve bounded object-access context for a protected path.", "Windows reported an access operation relevant to deletion correlation.", "Completed deletion, invoice semantics, actor intent, or FBR status by itself."),
            _fbr_control(105, "4670", "Permissions Changed", "High", "WINDOWS_FIM", "Preserve permissions-change evidence for an approved protected path.", "Windows reported a permissions change on an approved protected object.", "That invoice contents changed or that the permissions change was malicious."),
            _fbr_control(106, "FIM-DB-MOD", "Database File Tamper Confirmed", "Critical", "WINDOWS_FIM", "Preserve a confirmed protected database-file modification observation.", "WarSOC's approved FIM path observed a database-file modification.", "The affected invoice fields, authoritative transaction state, or FBR acceptance status."),
        ],
    },
}


def get_rule_for_pack(pack_id: str, event_id: str):
    for rule in COMPLIANCE_CATALOG.get(pack_id, {}).get("rules", []):
        if str(rule["event_id"]) == str(event_id):
            return rule
    return None


def get_rule_by_event_id(event_id: str):
    """Find the first compliance pack and rule matching an event ID."""
    for pack_id in COMPLIANCE_CATALOG:
        rule = get_rule_for_pack(pack_id, event_id)
        if rule:
            return pack_id, rule
    return None, None


def validate_compliance_catalog() -> None:
    required_rule_fields = {
        "id",
        "control_id",
        "event_id",
        "name",
        "severity",
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
    seen_control_ids = set()
    for pack_id, pack in COMPLIANCE_CATALOG.items():
        for reference_id in pack.get("legal_reference_ids", []):
            if reference_id not in LEGAL_REFERENCE_REGISTRY:
                raise RuntimeError(f"Unknown legal reference {reference_id} in {pack_id}")
        for rule in pack.get("rules", []):
            missing = required_rule_fields - set(rule)
            if missing:
                raise RuntimeError(
                    f"Compliance control {rule.get('id')} is missing fields: {sorted(missing)}"
                )
            if rule["control_id"] in seen_control_ids:
                raise RuntimeError(f"Duplicate compliance control ID {rule['control_id']}")
            seen_control_ids.add(rule["control_id"])
            if rule["claim_state"] not in CLAIM_STATES:
                raise RuntimeError(f"Invalid claim state for {rule['control_id']}")
            for reference_id in rule["legal_reference_ids"]:
                if reference_id not in LEGAL_REFERENCE_REGISTRY:
                    raise RuntimeError(
                        f"Unknown legal reference {reference_id} in {rule['control_id']}"
                    )

    if "section 46" in COMPLIANCE_CATALOG["peca_forensic"]["name"].lower():
        raise RuntimeError("PECA evidence profile must not claim a Section 46 mapping")


validate_compliance_catalog()
