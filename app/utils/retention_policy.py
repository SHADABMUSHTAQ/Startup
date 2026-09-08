"""Commercial evidence-retention terms supported by the active product."""

from __future__ import annotations


DEFAULT_TENANT_RETENTION_DAYS = 90
RETENTION_DAYS_BY_MONTHS = {
    3: 90,
    6: 180,
    9: 270,
    12: 365,
}
SUPPORTED_RETENTION_MONTHS = tuple(RETENTION_DAYS_BY_MONTHS)
SUPPORTED_TENANT_RETENTION_DAYS = tuple(RETENTION_DAYS_BY_MONTHS.values())


def retention_days_for_months(months: int) -> int:
    """Map a sold calendar-month term to its approved immutable-vault route."""

    try:
        return RETENTION_DAYS_BY_MONTHS[int(months)]
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError("retention_months must be one of 3, 6, 9, or 12") from exc


def validate_tenant_retention_days(days: int) -> int:
    """Reject tenant terms that cannot be routed to an approved Azure vault."""

    try:
        normalized = int(days)
    except (TypeError, ValueError) as exc:
        raise ValueError("retention_days must be one of 90, 180, 270, or 365") from exc
    if normalized not in SUPPORTED_TENANT_RETENTION_DAYS:
        raise ValueError("retention_days must be one of 90, 180, 270, or 365")
    return normalized
