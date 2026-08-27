"""FBR evidence retention metadata.

The active product keeps FBR monitoring evidence under the tenant's normal
WarSOC retention entitlement. The tax-period helpers remain below as isolated
legacy utilities so historical records can still be interpreted without
rewriting or shortening them.
"""

from __future__ import annotations

from calendar import monthrange
from datetime import datetime, timedelta, timezone
from math import ceil
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from app.utils.agent_crypto import parse_utc_timestamp


FBR_ACTIVE_RETENTION_MODEL = "TENANT_ENTITLEMENT_V1"
FBR_RETENTION_STATE_TENANT_POLICY = "TENANT_POLICY"
FBR_RETENTION_BASIS_TENANT = "TENANT_RETENTION_ENTITLEMENT"
FBR_RETENTION_POLICY_TENANT = "TENANT_ENTITLEMENT"
DEFAULT_TENANT_RETENTION_DAYS = 90


def normalize_tenant_retention_days(
    value,
    *,
    default: int = DEFAULT_TENANT_RETENTION_DAYS,
) -> int:
    """Normalize the tenant value without defining a separate FBR ceiling."""

    try:
        days = int(value)
    except (TypeError, ValueError):
        days = int(default)
    return max(1, days)


def tenant_fbr_retention_metadata(retention_days) -> dict:
    """Return the active FBR retention marker for a tenant entitlement."""

    normalized_days = normalize_tenant_retention_days(retention_days)
    return {
        "retention_model": FBR_ACTIVE_RETENTION_MODEL,
        "retention_state": FBR_RETENTION_STATE_TENANT_POLICY,
        "retention_basis": FBR_RETENTION_BASIS_TENANT,
        "retention_policy": FBR_RETENTION_POLICY_TENANT,
        "tenant_retention_days_at_ingest": normalized_days,
    }


def apply_fbr_tenant_retention(document: dict, retention_days) -> dict:
    """Apply active product retention and remove caller-supplied legacy fields."""

    for field_name in (
        "_expire_at",
        "tax_regime",
        "tax_period_id",
        "tax_period_start",
        "tax_period_end",
        "base_retention_until",
        "effective_retention_until",
        "automatic_archive_expiry_allowed",
        "retention_calculation_version",
        "retention_profile_version",
        "retention_timezone",
    ):
        document.pop(field_name, None)
    document.update(tenant_fbr_retention_metadata(retention_days))
    return document


# Legacy tax-period model. These helpers are intentionally not called by active
# ingestion, worker, database-initialization, or archival paths.
FBR_RETENTION_STATE_UNRESOLVED = "UNRESOLVED"
FBR_RETENTION_STATE_RESOLVED = "RESOLVED"
FBR_RETENTION_STATE_HELD = "HELD"
FBR_RETENTION_BASIS_UNRESOLVED = "TAX_PERIOD_PENDING"
FBR_RETENTION_BASIS_SALES_TAX = "PK_SALES_TAX_PERIOD_END_PLUS_6_CALENDAR_YEARS"
FBR_RETENTION_CALCULATION_VERSION = "fbr-tax-period-v1"
SUPPORTED_TAX_REGIME = "PK_SALES_TAX"
SUPPORTED_PERIOD_TYPE = "CALENDAR_MONTH"

# Seven years is a conservative temporary vault floor while the applicable
# tax period is unresolved. It is not represented as the legal requirement.
FBR_UNRESOLVED_VAULT_FLOOR_DAYS = (365 * 7) + 2


def apply_unresolved_fbr_retention(document: dict) -> dict:
    document.pop("_expire_at", None)
    document.update(
        {
            "retention_state": FBR_RETENTION_STATE_UNRESOLVED,
            "retention_basis": FBR_RETENTION_BASIS_UNRESOLVED,
            "tax_period_id": None,
            "tax_period_start": None,
            "tax_period_end": None,
            "base_retention_until": None,
            "effective_retention_until": None,
            "automatic_archive_expiry_allowed": False,
            "retention_calculation_version": FBR_RETENTION_CALCULATION_VERSION,
        }
    )
    return document


def _coerce_utc_datetime(value) -> datetime | None:
    if isinstance(value, datetime):
        parsed = value
        if parsed.tzinfo is None:
            return None
        return parsed.astimezone(timezone.utc)
    return parse_utc_timestamp(str(value or ""))


def _add_calendar_years(value: datetime, years: int) -> datetime:
    target_year = value.year + years
    target_day = min(value.day, monthrange(target_year, value.month)[1])
    return value.replace(year=target_year, day=target_day)


def resolve_fbr_retention_metadata(
    event_timestamp,
    profile: dict | None,
) -> dict:
    """Resolve a supported, explicitly configured sales-tax period fail-closed."""

    if not isinstance(profile, dict):
        return apply_unresolved_fbr_retention({})
    tax_regime = str(profile.get("tax_regime") or "").strip().upper()
    period_type = str(profile.get("period_type") or "").strip().upper()
    if tax_regime != SUPPORTED_TAX_REGIME or period_type != SUPPORTED_PERIOD_TYPE:
        return apply_unresolved_fbr_retention({})

    event_time = _coerce_utc_datetime(event_timestamp)
    timezone_name = str(profile.get("timezone") or "Asia/Karachi").strip()
    if event_time is None:
        return apply_unresolved_fbr_retention({})
    try:
        local_zone = ZoneInfo(timezone_name)
    except ZoneInfoNotFoundError:
        if timezone_name != "Asia/Karachi":
            return apply_unresolved_fbr_retention({})
        # Windows Python installations may not ship the IANA tzdata package.
        # Pakistan's supported sales-tax profile uses UTC+05:00; keep every
        # other unknown zone fail-closed instead of guessing.
        local_zone = timezone(timedelta(hours=5), name="Asia/Karachi")

    local_time = event_time.astimezone(local_zone)
    period_start_local = datetime(
        local_time.year,
        local_time.month,
        1,
        tzinfo=local_zone,
    )
    period_end_local = datetime(
        local_time.year,
        local_time.month,
        monthrange(local_time.year, local_time.month)[1],
        23,
        59,
        59,
        999999,
        tzinfo=local_zone,
    )
    base_retention_local = _add_calendar_years(period_end_local, 6)
    period_prefix = str(profile.get("period_id_prefix") or "PK-ST").strip().upper()

    return {
        "retention_state": FBR_RETENTION_STATE_RESOLVED,
        "retention_basis": FBR_RETENTION_BASIS_SALES_TAX,
        "tax_regime": SUPPORTED_TAX_REGIME,
        "tax_period_id": f"{period_prefix}-{local_time:%Y-%m}",
        "tax_period_start": period_start_local.astimezone(timezone.utc),
        "tax_period_end": period_end_local.astimezone(timezone.utc),
        "base_retention_until": base_retention_local.astimezone(timezone.utc),
        "effective_retention_until": base_retention_local.astimezone(timezone.utc),
        "automatic_archive_expiry_allowed": True,
        "retention_calculation_version": FBR_RETENTION_CALCULATION_VERSION,
        "retention_profile_version": str(profile.get("version") or "unversioned")[:64],
        "retention_timezone": timezone_name,
    }


def apply_fbr_retention_profile(
    document: dict,
    profile: dict | None,
    *,
    timestamp_field: str = "timestamp",
) -> dict:
    document.pop("_expire_at", None)
    metadata = resolve_fbr_retention_metadata(document.get(timestamp_field), profile)
    document.update(metadata)
    return document


def fbr_retention_cohort(metadata: dict) -> str:
    if metadata.get("retention_state") != FBR_RETENTION_STATE_RESOLVED:
        return "unresolved"
    period_id = str(metadata.get("tax_period_id") or "").strip()
    return period_id.lower().replace("_", "-") or "unresolved"


def required_fbr_vault_days(documents: list[dict], now: datetime | None = None) -> tuple[int, str]:
    """Return the fail-closed vault duration and batch retention state."""

    now = now or datetime.now(timezone.utc)
    resolved_until: list[datetime] = []
    for document in documents:
        if document.get("retention_state") != FBR_RETENTION_STATE_RESOLVED:
            return FBR_UNRESOLVED_VAULT_FLOOR_DAYS, FBR_RETENTION_STATE_UNRESOLVED
        value = document.get("effective_retention_until")
        if not isinstance(value, datetime):
            return FBR_UNRESOLVED_VAULT_FLOOR_DAYS, FBR_RETENTION_STATE_UNRESOLVED
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        resolved_until.append(value.astimezone(timezone.utc))

    if not resolved_until:
        return FBR_UNRESOLVED_VAULT_FLOOR_DAYS, FBR_RETENTION_STATE_UNRESOLVED

    remaining_seconds = max((value - now).total_seconds() for value in resolved_until)
    return max(1, ceil(remaining_seconds / 86_400)), FBR_RETENTION_STATE_RESOLVED
