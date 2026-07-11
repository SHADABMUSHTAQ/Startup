import hashlib
import hmac
import json
from datetime import date, datetime, timezone
from typing import Any, Iterable


CHAIN_VERSION = "sha256-evidence-chain-v1"
HASH_ALGORITHM = "SHA-256"

# These fields are Mongo/archive lifecycle mechanics, not evidence content.
_NON_EVIDENCE_FIELDS = {
    "_expire_at",
    "_retention_ts",
    "_archived",
    "_archive_blob_name",
    "_archive_collection",
    "_source_collection",
}


def _json_value(value: Any) -> Any:
    if isinstance(value, datetime):
        normalized = value if value.tzinfo else value.replace(tzinfo=timezone.utc)
        return normalized.astimezone(timezone.utc).isoformat()
    if isinstance(value, date):
        return value.isoformat()
    if isinstance(value, bytes):
        return value.hex()
    if isinstance(value, dict):
        return {
            str(key): _json_value(item)
            for key, item in value.items()
            if str(key) not in _NON_EVIDENCE_FIELDS
        }
    if isinstance(value, (list, tuple)):
        return [_json_value(item) for item in value]
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    return str(value)


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        _json_value(value),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")


def evidence_record_digest(collection_name: str, document: dict) -> str:
    envelope = {
        "collection": str(collection_name),
        "document": document,
    }
    return hashlib.sha256(_canonical_bytes(envelope)).hexdigest()


def aggregate_evidence_digest(records: Iterable[tuple[str, dict]]) -> tuple[str, int, dict[str, int]]:
    aggregate = hashlib.sha256()
    count = 0
    source_counts: dict[str, int] = {}
    for collection_name, document in records:
        digest = evidence_record_digest(collection_name, document)
        aggregate.update(f"{collection_name}:{digest}\n".encode("ascii"))
        count += 1
        source_counts[collection_name] = source_counts.get(collection_name, 0) + 1
    return aggregate.hexdigest(), count, source_counts


def genesis_root(tenant_id: str) -> str:
    return hashlib.sha256(f"GENESIS:{tenant_id}".encode("utf-8")).hexdigest()


def compute_daily_root(
    *,
    tenant_id: str,
    date_str: str,
    previous_root_hash: str,
    evidence_digest: str,
    log_count: int,
    source_counts: dict[str, int],
) -> str:
    payload = {
        "chain_version": CHAIN_VERSION,
        "date": str(date_str),
        "evidence_digest": str(evidence_digest),
        "log_count": int(log_count),
        "previous_root_hash": str(previous_root_hash),
        "source_counts": {str(key): int(value) for key, value in sorted(source_counts.items())},
        "tenant_id": str(tenant_id),
    }
    return hashlib.sha256(_canonical_bytes(payload)).hexdigest()


def verify_ledger_entry(entry: dict) -> bool:
    if entry.get("chain_version") != CHAIN_VERSION:
        return False
    required = (
        "tenant_id",
        "date",
        "previous_root_hash",
        "evidence_digest",
        "daily_root_hash",
        "log_count",
        "source_counts",
    )
    if any(field not in entry for field in required):
        return False
    expected = compute_daily_root(
        tenant_id=entry["tenant_id"],
        date_str=entry["date"],
        previous_root_hash=entry["previous_root_hash"],
        evidence_digest=entry["evidence_digest"],
        log_count=entry["log_count"],
        source_counts=entry["source_counts"],
    )
    return hmac.compare_digest(str(entry.get("daily_root_hash") or ""), expected)


def verify_ledger_sequence(entries: list[dict]) -> dict[str, Any]:
    invalid_dates: list[str] = []
    broken_links: list[str] = []
    reset_dates: list[str] = []
    previous_entry = None

    for entry in entries:
        date_str = str(entry.get("date") or "unknown")
        if entry.get("chain_reset_reason"):
            reset_dates.append(date_str)
        if not verify_ledger_entry(entry):
            invalid_dates.append(date_str)
        if previous_entry is not None:
            expected_previous = str(previous_entry.get("daily_root_hash") or "")
            if str(entry.get("previous_root_hash") or "") != expected_previous:
                # A declared reset is explicit and does not masquerade as continuity.
                if not entry.get("chain_reset_reason"):
                    broken_links.append(date_str)
        previous_entry = entry

    verified = bool(entries) and not invalid_dates and not broken_links
    if verified and reset_dates:
        status = "VERIFIED_WITH_RESET"
    elif verified:
        status = "VERIFIED"
    else:
        status = "UNVERIFIED"
    return {
        "verified": verified,
        "continuous": verified and not reset_dates,
        "entry_count": len(entries),
        "invalid_dates": invalid_dates,
        "broken_links": broken_links,
        "reset_dates": reset_dates,
        "status": status,
    }
