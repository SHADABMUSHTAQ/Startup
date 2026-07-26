from app.utils.pricing import (
    PRICING_VERSION,
    calculate_package_price,
    normalize_billing_cycle,
    normalize_compliance_packs,
)
from app.routes.sales import QuoteRequest


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
        plan_type="WarSOC Deployment",
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


def test_server_pricing_calculates_the_approved_monthly_public_price():
    estimate = calculate_package_price(
        endpoints=15,
        compliance_packs=["fbr_pos", "peca_forensic"],
        billing_cycle="monthly",
    )

    assert estimate == {
        "pricing_version": PRICING_VERSION,
        "currency": "PKR",
        "billing_cycle": "monthly",
        "period_months": 1,
        "endpoints": 15,
        "compliance_packs": ["fbr_pos", "peca_forensic"],
        "retention_months": 3,
        "endpoint_monthly_subtotal": 30_000,
        "compliance_monthly_subtotal": 45_000,
        "monthly_recurring": 75_000,
        "recurring_total": 75_000,
        "one_time_setup_fee": 5_000,
        "estimated_first_invoice": 80_000,
        "taxes_included": False,
    }


def test_annual_price_is_twelve_months_without_an_unapproved_discount():
    estimate = calculate_package_price(
        endpoints=15,
        compliance_packs=["fbr_pos", "peca_forensic"],
        billing_cycle="yearly",
        retention_months=12,
    )

    assert estimate["monthly_recurring"] == 75_000
    assert estimate["recurring_total"] == 900_000
    assert estimate["estimated_first_invoice"] == 905_000
