from typing import Any

from app.utils.security_policy import PLATFORM_MAX_AGENTS
from app.utils.tenant_cache import normalize_pack_id


PRICING_VERSION = "2026-07-26-pkr-v1"
PRICING_CURRENCY = "PKR"
PUBLIC_MIN_ENDPOINTS = 10
ENDPOINT_MONTHLY_PRICE = 2_000
ONE_TIME_SETUP_FEE = 5_000
ANNUAL_MONTHS = 12
SUPPORTED_RETENTION_MONTHS = (3, 6, 9, 12)
COMPLIANCE_PACK_MONTHLY_PRICES = {
    "fbr_pos": 20_000,
    "peca_forensic": 25_000,
}


def normalize_billing_cycle(billing_cycle: str | None) -> str:
    cycle = str(billing_cycle or "monthly").strip().lower()
    return "yearly" if cycle == "yearly" else "monthly"


def normalize_compliance_packs(packs: list[str] | None) -> list[str]:
    return sorted({normalize_pack_id(pack) for pack in packs or [] if normalize_pack_id(pack)})


def public_pricing_catalog() -> dict[str, Any]:
    return {
        "version": PRICING_VERSION,
        "currency": PRICING_CURRENCY,
        "taxes_included": False,
        "minimum_endpoints": PUBLIC_MIN_ENDPOINTS,
        "maximum_endpoints": PLATFORM_MAX_AGENTS,
        "endpoint_monthly_price": ENDPOINT_MONTHLY_PRICE,
        "one_time_setup_fee": ONE_TIME_SETUP_FEE,
        "annual_months": ANNUAL_MONTHS,
        "retention_months": list(SUPPORTED_RETENTION_MONTHS),
        "retention_included": True,
        "compliance_pack_monthly_prices": dict(COMPLIANCE_PACK_MONTHLY_PRICES),
    }


def calculate_package_price(
    *,
    endpoints: int,
    compliance_packs: list[str] | None,
    billing_cycle: str | None = "monthly",
    retention_months: int = 3,
) -> dict[str, Any]:
    endpoint_count = int(endpoints)
    if not PUBLIC_MIN_ENDPOINTS <= endpoint_count <= PLATFORM_MAX_AGENTS:
        raise ValueError(
            f"endpoints must be between {PUBLIC_MIN_ENDPOINTS} and {PLATFORM_MAX_AGENTS}"
        )

    selected_packs = normalize_compliance_packs(compliance_packs)
    unsupported_packs = sorted(set(selected_packs) - set(COMPLIANCE_PACK_MONTHLY_PRICES))
    if unsupported_packs:
        raise ValueError("unsupported compliance pack")

    selected_retention = int(retention_months or 3)
    if selected_retention not in SUPPORTED_RETENTION_MONTHS:
        raise ValueError("retention_months must be one of 3, 6, 9, or 12")

    cycle = normalize_billing_cycle(billing_cycle)
    endpoint_monthly = endpoint_count * ENDPOINT_MONTHLY_PRICE
    pack_monthly = sum(COMPLIANCE_PACK_MONTHLY_PRICES[pack] for pack in selected_packs)
    monthly_recurring = endpoint_monthly + pack_monthly
    period_months = ANNUAL_MONTHS if cycle == "yearly" else 1
    recurring_total = monthly_recurring * period_months

    return {
        "pricing_version": PRICING_VERSION,
        "currency": PRICING_CURRENCY,
        "billing_cycle": cycle,
        "period_months": period_months,
        "endpoints": endpoint_count,
        "compliance_packs": selected_packs,
        "retention_months": selected_retention,
        "endpoint_monthly_subtotal": endpoint_monthly,
        "compliance_monthly_subtotal": pack_monthly,
        "monthly_recurring": monthly_recurring,
        "recurring_total": recurring_total,
        "one_time_setup_fee": ONE_TIME_SETUP_FEE,
        "estimated_first_invoice": recurring_total + ONE_TIME_SETUP_FEE,
        "taxes_included": False,
    }
