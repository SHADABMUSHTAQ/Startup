from app.utils.pricing import (
    calculate_package_price,
    normalize_billing_cycle,
    normalize_compliance_packs,
)
from app.routes.sales import QuoteRequest
import pytest


def test_quote_scope_normalization_has_no_price_side_effects():
    assert normalize_compliance_packs(["fbr", "peca", "fbr_pos"]) == [
        "fbr_pos",
        "peca_forensic",
    ]
    assert normalize_billing_cycle("yearly") == "yearly"


def test_quote_request_preserves_scope_without_requiring_a_client_price():
    quote = QuoteRequest(
        contact_name="Pilot Buyer",
        contact_email="buyer@warsoc.tech",
        company_name="Pilot Co",
        plan_type="Custom Platform",
        endpoints=50,
        compliance_packs=["fbr_pos", "peca_forensic"],
        billing_cycle="monthly",
        customization={"endpoints": 50, "retentionMonths": 12},
    )

    assert quote.customization.normalized(fallback_endpoints=quote.endpoints) == {
        "endpoints": 50,
        "retention_months": 12,
        "retention_days": 360,
        "cold_archive_requested": True,
    }
    assert quote.frontend_calculated_total is None


def test_automated_pricing_fails_closed():
    with pytest.raises(RuntimeError, match="Automated pricing is disabled"):
        calculate_package_price(
            endpoints=15,
            compliance_packs=["fbr_pos", "peca_forensic"],
            billing_cycle="monthly",
        )
