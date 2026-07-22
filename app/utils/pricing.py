from app.utils.tenant_cache import normalize_pack_id


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
):
    """Fail closed if retired automated pricing is called.

    WarSOC commercial terms are agreed through a reviewed custom contract and
    manual invoice. This compatibility symbol remains only so stale internal
    code cannot accidentally restore an obsolete public pricing algorithm.
    """
    del endpoints, compliance_packs, billing_cycle
    raise RuntimeError("Automated pricing is disabled; use manual commercial review")
