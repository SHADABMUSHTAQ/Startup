from dataclasses import asdict, dataclass

from app.utils.tenant_cache import normalize_pack_id


PRICING_VERSION = "commercial_package_v1"
PRICE_PER_ENDPOINT = 2000
FBR_PRICE = 20000
PECA_PRICE = 25000
ACTIVATION_FEE = 5000
YEARLY_BILLED_MONTHS = 10


@dataclass(frozen=True)
class PackagePrice:
    pricing_version: str
    billing_cycle: str
    endpoints: int
    compliance_packs: list[str]
    endpoints_cost: int
    addons_cost: int
    monthly_total: int
    activation_fee: int
    initial_payment: int
    yearly_value: int
    breakdown: dict[str, int]

    def to_dict(self) -> dict:
        return asdict(self)


def normalize_billing_cycle(billing_cycle: str | None) -> str:
    cycle = str(billing_cycle or "monthly").strip().lower()
    return "yearly" if cycle == "yearly" else "monthly"


def normalize_compliance_packs(packs: list[str] | None) -> list[str]:
    return sorted({normalize_pack_id(pack) for pack in packs or [] if normalize_pack_id(pack)})


def calculate_package_price(
    *,
    endpoints: int,
    compliance_packs: list[str] | None,
    billing_cycle: str | None = "monthly",
) -> PackagePrice:
    """Single source of truth for commercial package pricing."""
    normalized_packs = normalize_compliance_packs(compliance_packs)
    cycle = normalize_billing_cycle(billing_cycle)
    endpoint_count = max(0, int(endpoints or 0))

    endpoints_cost = endpoint_count * PRICE_PER_ENDPOINT
    breakdown = {
        "endpoints": endpoints_cost,
        "fbr_pos": FBR_PRICE if "fbr_pos" in normalized_packs else 0,
        "peca_forensic": PECA_PRICE if "peca_forensic" in normalized_packs else 0,
    }
    addons_cost = breakdown["fbr_pos"] + breakdown["peca_forensic"]
    monthly_total = endpoints_cost + addons_cost

    billed_months = YEARLY_BILLED_MONTHS if cycle == "yearly" else 1
    initial_payment = monthly_total * billed_months + ACTIVATION_FEE
    yearly_value = monthly_total * (YEARLY_BILLED_MONTHS if cycle == "yearly" else 12)

    return PackagePrice(
        pricing_version=PRICING_VERSION,
        billing_cycle=cycle,
        endpoints=endpoint_count,
        compliance_packs=normalized_packs,
        endpoints_cost=endpoints_cost,
        addons_cost=addons_cost,
        monthly_total=monthly_total,
        activation_fee=ACTIVATION_FEE,
        initial_payment=initial_payment,
        yearly_value=yearly_value,
        breakdown=breakdown,
    )
