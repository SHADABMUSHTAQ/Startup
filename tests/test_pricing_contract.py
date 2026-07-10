from app.utils.pricing import calculate_package_price
from app.routes.sales import QuoteRequest
import pytest


def test_15_agent_fbr_peca_monthly_price_contract():
    price = calculate_package_price(
        endpoints=15,
        compliance_packs=["fbr_pos", "peca_forensic"],
        billing_cycle="monthly",
    )

    assert price.monthly_total == 75000
    assert price.activation_fee == 5000
    assert price.initial_payment == 80000
    assert price.yearly_value == 900000
    assert price.breakdown == {
        "endpoints": 30000,
        "fbr_pos": 20000,
        "peca_forensic": 25000,
    }


def test_15_agent_fbr_peca_yearly_price_contract():
    price = calculate_package_price(
        endpoints=15,
        compliance_packs=["fbr", "peca"],
        billing_cycle="yearly",
    )

    assert price.compliance_packs == ["fbr_pos", "peca_forensic"]
    assert price.monthly_total == 75000
    assert price.initial_payment == 755000


def test_quote_request_preserves_frontend_archive_customization():
    quote = QuoteRequest(
        contact_name="Pilot Buyer",
        contact_email="buyer@warsoc.tech",
        company_name="Pilot Co",
        plan_type="Custom Platform",
        endpoints=50,
        compliance_packs=["fbr_pos", "peca_forensic"],
        billing_cycle="monthly",
        frontend_calculated_total=145000,
        customization={"endpoints": 50, "retentionMonths": 12},
    )

    assert quote.customization.normalized(fallback_endpoints=quote.endpoints) == {
        "endpoints": 50,
        "retention_months": 12,
        "retention_days": 360,
        "cold_archive_requested": True,
    }


def test_pricing_rejects_more_than_50_endpoints():
    with pytest.raises(ValueError, match="between 1 and 50"):
        calculate_package_price(
            endpoints=51,
            compliance_packs=["fbr_pos", "peca_forensic"],
            billing_cycle="monthly",
        )
