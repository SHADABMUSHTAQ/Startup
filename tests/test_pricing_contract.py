from app.utils.pricing import calculate_package_price


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
