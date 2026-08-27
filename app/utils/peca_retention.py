"""Active retention metadata for PECA evidence-pack records."""

from __future__ import annotations

from app.utils.fbr_retention import normalize_tenant_retention_days


PECA_ACTIVE_RETENTION_MODEL = "TENANT_ENTITLEMENT_V1"
PECA_RETENTION_STATE_TENANT_POLICY = "TENANT_POLICY"
PECA_RETENTION_BASIS_TENANT = "TENANT_RETENTION_ENTITLEMENT"
PECA_RETENTION_POLICY_TENANT = "TENANT_ENTITLEMENT"


def tenant_peca_retention_metadata(retention_days) -> dict:
    """Return the active PECA retention marker for a tenant entitlement."""

    normalized_days = normalize_tenant_retention_days(retention_days)
    return {
        "retention_model": PECA_ACTIVE_RETENTION_MODEL,
        "retention_state": PECA_RETENTION_STATE_TENANT_POLICY,
        "retention_basis": PECA_RETENTION_BASIS_TENANT,
        "retention_policy": PECA_RETENTION_POLICY_TENANT,
        "tenant_retention_days_at_ingest": normalized_days,
    }


def apply_peca_tenant_retention(document: dict, retention_days) -> dict:
    """Apply active product retention without changing historical documents."""

    document.pop("_expire_at", None)
    document.update(tenant_peca_retention_metadata(retention_days))
    return document
