import asyncio
import hashlib
import json
import logging
import os
import uuid
from datetime import datetime, timedelta, timezone

from azure.core.exceptions import ResourceExistsError
from azure.storage.blob import (
    BlobImmutabilityPolicyMode,
    ImmutabilityPolicy,
    StandardBlobTier,
)
from azure.storage.blob.aio import BlobServiceClient
from app.utils.security_incidents import project_security_incident
from bson import ObjectId
from dotenv import load_dotenv
from motor.motor_asyncio import AsyncIOMotorClient

from app.utils.compliance_catalog import COMPLIANCE_CATALOG
from app.utils.fbr_retention import FBR_ACTIVE_RETENTION_MODEL
from app.utils.peca_retention import PECA_ACTIVE_RETENTION_MODEL
from app.utils.evidence_locks import acquire_retention_fence, release_retention_fence
from app.utils.archive_legal_holds import protect_archive_for_hold

load_dotenv()

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
logger = logging.getLogger("storage_archiver")
logging.getLogger("azure.core.pipeline.policies.http_logging_policy").setLevel(
    logging.WARNING
)

DEFAULT_ARCHIVE_COLLECTIONS = (
    "logs",
    "siem_cold_vault",
    "security_alerts",
    "fbr_pos_logs",
    "peca_forensic_logs",
    "source_envelopes_siem",
    "source_envelopes_peca",
    "source_envelopes_fbr",
    "csv_uploads",
    "analysis_results",
)

# Every automatic archive decision uses exactly one server-controlled clock.
# Source/event timestamps remain evidence, but can never make a fresh record
# eligible for archival or hot deletion.
COLLECTION_ARCHIVE_CLOCKS = {
    "logs": ("_retention_ts", "anchor", "SERVER_ACCEPTED_AT"),
    "siem_cold_vault": ("_expire_at", "expiry", "SERVER_HOT_EXPIRY"),
    "security_alerts": ("_expire_at", "expiry", "SERVER_HOT_EXPIRY"),
    "fbr_pos_logs": ("ingested_at", "anchor", "SERVER_INGESTED_AT"),
    "peca_forensic_logs": ("ingested_at", "anchor", "SERVER_INGESTED_AT"),
    "source_envelopes_siem": ("received_at", "anchor", "SERVER_RECEIVED_AT"),
    "source_envelopes_peca": ("received_at", "anchor", "SERVER_RECEIVED_AT"),
    "source_envelopes_fbr": ("received_at", "anchor", "SERVER_RECEIVED_AT"),
    "csv_uploads": ("_retention_ts", "anchor", "SERVER_ACCEPTED_AT"),
    "analysis_results": ("uploaded_at", "anchor", "SERVER_UPLOADED_AT"),
}
COMPLIANCE_PACK_BY_COLLECTION = {
    "peca_forensic_logs": "peca_forensic",
    "source_envelopes_peca": "peca_forensic",
}
COMPLIANCE_HOT_RETENTION_DAYS = {
    collection_name: int(COMPLIANCE_CATALOG[pack_name]["retention"]["local_hot_days"])
    for collection_name, pack_name in COMPLIANCE_PACK_BY_COLLECTION.items()
}
COMPLIANCE_VAULT_RETENTION_DAYS = {
    collection_name: int(COMPLIANCE_CATALOG[pack_name]["retention"]["vault_days"])
    for collection_name, pack_name in COMPLIANCE_PACK_BY_COLLECTION.items()
    if COMPLIANCE_CATALOG[pack_name]["retention"]["vault_days"] is not None
}
DEFAULT_SIEM_HOT_RETENTION_DAYS = max(1, min(7, int(os.getenv("SIEM_HOT_RETENTION_DAYS", "7"))))
DEFAULT_RAW_LOG_HOT_RETENTION_DAYS = max(1, min(7, int(os.getenv("RAW_LOG_HOT_RETENTION_DAYS", "7"))))
HOT_RETENTION_DAYS_BY_COLLECTION = {
    **COMPLIANCE_HOT_RETENTION_DAYS,
    "fbr_pos_logs": int(COMPLIANCE_CATALOG["fbr_pos"]["retention"]["local_hot_days"]),
    "source_envelopes_fbr": int(
        COMPLIANCE_CATALOG["fbr_pos"]["retention"]["local_hot_days"]
    ),
    "siem_cold_vault": DEFAULT_SIEM_HOT_RETENTION_DAYS,
    "security_alerts": DEFAULT_SIEM_HOT_RETENTION_DAYS,
    "logs": DEFAULT_RAW_LOG_HOT_RETENTION_DAYS,
    "csv_uploads": DEFAULT_RAW_LOG_HOT_RETENTION_DAYS,
    "analysis_results": DEFAULT_RAW_LOG_HOT_RETENTION_DAYS,
    "source_envelopes_siem": DEFAULT_SIEM_HOT_RETENTION_DAYS,
}

ARCHIVE_RETENTION_CLASS_BY_COLLECTION = {
    "fbr_pos_logs": "GENERAL",
    "peca_forensic_logs": "GENERAL",
    "siem_cold_vault": "SIEM",
    "security_alerts": "SIEM",
    "logs": "SIEM",
    "source_envelopes_siem": "SIEM",
    "source_envelopes_peca": "GENERAL",
    "source_envelopes_fbr": "GENERAL",
}


def _archive_retention_class(collection_name: str) -> str:
    return ARCHIVE_RETENTION_CLASS_BY_COLLECTION.get(collection_name, "GENERAL")


def _archive_routing_key(collection_name: str, vault_retention_days: int | None = None) -> str:
    retention_class = _archive_retention_class(collection_name)
    if retention_class in {"SIEM", "GENERAL"} and vault_retention_days:
        return f"{retention_class}_{max(1, int(vault_retention_days))}"
    return retention_class


def _archive_container_name(
    collection_name: str,
    vault_retention_days: int | None = None,
) -> str:
    retention_class = _archive_retention_class(collection_name)
    routing_key = _archive_routing_key(collection_name, vault_retention_days)
    exact = os.getenv(f"AZURE_STORAGE_CONTAINER_{routing_key}", "").strip()
    if (
        not exact
        and retention_class in {"SIEM", "GENERAL"}
        and vault_retention_days
        and _environment_flag("AZURE_EXACT_RETENTION_ROUTE_REQUIRED", default=False)
    ):
        raise RuntimeError(
            f"Required Azure archive route {routing_key} is not configured; "
            "hot records were preserved"
        )
    class_fallback = os.getenv(f"AZURE_STORAGE_CONTAINER_{retention_class}", "").strip()
    return exact or class_fallback or os.getenv(
        "AZURE_STORAGE_CONTAINER", "warsoc-cold-storage"
    ).strip()


def _archive_access_tier(
    collection_name: str,
    vault_retention_days: int | None = None,
):
    """Resolve a tier only from the route that actually selected the container."""

    retention_class = _archive_retention_class(collection_name)
    routing_key = _archive_routing_key(collection_name, vault_retention_days)
    exact_container = os.getenv(f"AZURE_STORAGE_CONTAINER_{routing_key}", "").strip()
    class_container = os.getenv(
        f"AZURE_STORAGE_CONTAINER_{retention_class}", ""
    ).strip()
    if exact_container:
        raw_tier = os.getenv(f"AZURE_STORAGE_TIER_{routing_key}", "").strip()
        if (
            not raw_tier
            and _environment_flag("AZURE_EXACT_RETENTION_ROUTE_REQUIRED", default=False)
        ):
            raise RuntimeError(
                f"Required Azure archive tier {routing_key} is not configured; "
                "hot records were preserved"
            )
    elif class_container:
        raw_tier = os.getenv(f"AZURE_STORAGE_TIER_{retention_class}", "").strip()
    else:
        raw_tier = os.getenv("AZURE_STORAGE_TIER", "").strip()

    if not raw_tier:
        return None
    tiers = {
        "hot": StandardBlobTier.HOT,
        "cool": StandardBlobTier.COOL,
        "cold": StandardBlobTier.COLD,
        "archive": StandardBlobTier.ARCHIVE,
    }
    try:
        return tiers[raw_tier.lower()]
    except KeyError as exc:
        raise RuntimeError(
            "Azure archive tier must be one of Hot, Cool, Cold, or Archive"
        ) from exc


def _archive_immutability_scope(
    collection_name: str,
    vault_retention_days: int | None = None,
) -> str:
    """Resolve container/blob verification scope for the selected route."""

    retention_class = _archive_retention_class(collection_name)
    routing_key = _archive_routing_key(collection_name, vault_retention_days)
    exact_container = os.getenv(f"AZURE_STORAGE_CONTAINER_{routing_key}", "").strip()
    class_container = os.getenv(
        f"AZURE_STORAGE_CONTAINER_{retention_class}", ""
    ).strip()
    if exact_container:
        raw_scope = os.getenv(f"AZURE_IMMUTABILITY_SCOPE_{routing_key}", "").strip()
        if (
            not raw_scope
            and _environment_flag("AZURE_EXACT_RETENTION_ROUTE_REQUIRED", default=False)
        ):
            raise RuntimeError(
                f"Required Azure immutability scope {routing_key} is not configured; "
                "hot records were preserved"
            )
    elif class_container:
        raw_scope = os.getenv(
            f"AZURE_IMMUTABILITY_SCOPE_{retention_class}", ""
        ).strip()
    else:
        raw_scope = os.getenv("AZURE_IMMUTABILITY_SCOPE", "blob").strip()
    scope = (raw_scope or os.getenv("AZURE_IMMUTABILITY_SCOPE", "blob")).lower()
    if scope not in {"blob", "container"}:
        raise RuntimeError("AZURE_IMMUTABILITY_SCOPE must be 'blob' or 'container'")
    return scope


def _container_policy_setting(
    collection_name: str,
    setting: str,
    default: str,
    vault_retention_days: int | None = None,
) -> str:
    retention_class = _archive_retention_class(collection_name)
    routing_key = _archive_routing_key(collection_name, vault_retention_days)
    exact = os.getenv(f"AZURE_CONTAINER_IMMUTABILITY_{setting}_{routing_key}", "").strip()
    class_fallback = os.getenv(
        f"AZURE_CONTAINER_IMMUTABILITY_{setting}_{retention_class}", ""
    ).strip()
    return exact or class_fallback or os.getenv(
        f"AZURE_CONTAINER_IMMUTABILITY_{setting}", default
    )


def _environment_flag(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _as_utc(value):
    if not isinstance(value, datetime):
        return None
    return value.astimezone(timezone.utc) if value.tzinfo else value.replace(tzinfo=timezone.utc)


def _property_value(properties, name: str):
    value = getattr(properties, name, None)
    if value is None and hasattr(properties, "get"):
        value = properties.get(name)
    return value


def _enum_value(value):
    if value is None:
        return None
    return str(getattr(value, "value", value))


def _blob_storage_facts(properties) -> dict:
    policy = _property_value(properties, "immutability_policy")
    return {
        "version_id": _property_value(properties, "version_id"),
        "etag": _enum_value(_property_value(properties, "etag")),
        "creation_time": _as_utc(_property_value(properties, "creation_time")),
        "last_modified": _as_utc(_property_value(properties, "last_modified")),
        "tier": _enum_value(_property_value(properties, "blob_tier")),
        "legal_hold": bool(_property_value(properties, "has_legal_hold")),
        "immutability_policy_mode": _enum_value(
            getattr(policy, "policy_mode", None)
        ),
        "immutability_until": _as_utc(getattr(policy, "expiry_time", None)),
    }


def _required_blob_worm_until(blob_facts: dict, retention_days: int) -> datetime:
    creation_time = _as_utc(blob_facts.get("creation_time"))
    if creation_time is None:
        raise RuntimeError(
            "Azure blob creation time is required for immutable-retention verification; "
            "hot records were preserved"
        )
    return creation_time + timedelta(days=max(1, int(retention_days)))


def _verify_required_blob_version_ids(json_facts: dict, hash_facts: dict) -> None:
    if not (
        _environment_flag("AZURE_BLOB_VERSION_ID_REQUIRED", default=False)
        or _environment_flag("AZURE_EXACT_RETENTION_ROUTE_REQUIRED", default=False)
    ):
        return
    if not json_facts.get("version_id") or not hash_facts.get("version_id"):
        raise RuntimeError(
            "Azure blob version identity is required but was not returned; hot "
            "records were preserved"
        )


async def _stream_blob_sha256(blob_client) -> str:
    """Hash an Azure blob without buffering the archive in worker memory."""
    downloader = await blob_client.download_blob(max_concurrency=1)
    digest = hashlib.sha256()
    async for chunk in downloader.chunks():
        digest.update(chunk)
    return digest.hexdigest()


def _blob_immutability_status(properties, required_until: datetime) -> dict:
    legal_hold = bool(_property_value(properties, "has_legal_hold"))
    policy = _property_value(properties, "immutability_policy")
    raw_policy_mode = getattr(policy, "policy_mode", "") or ""
    policy_mode = str(getattr(raw_policy_mode, "value", raw_policy_mode))
    policy_expiry = _as_utc(getattr(policy, "expiry_time", None))
    required_until = _as_utc(required_until)
    locked = policy_mode.strip().lower() == "locked"
    adequate_expiry = bool(policy_expiry and required_until and policy_expiry >= required_until)
    return {
        "verified": legal_hold or (locked and adequate_expiry),
        "legal_hold": legal_hold,
        "policy_mode": policy_mode or None,
        "policy_expiry": policy_expiry,
    }


async def _verify_blob_immutability(blob_client, required_until: datetime) -> dict:
    properties = await blob_client.get_blob_properties()
    status = _blob_immutability_status(properties, required_until)
    if not status["verified"]:
        raise RuntimeError(
            "Azure blob is not protected by a legal hold or a locked immutability "
            f"policy through {required_until.isoformat()}"
        )
    return status


async def _ensure_blob_immutability(blob_client, required_until: datetime) -> dict:
    properties = await blob_client.get_blob_properties()
    status = _blob_immutability_status(properties, required_until)
    if status["verified"]:
        return status
    if not _environment_flag("AZURE_BLOB_IMMUTABILITY_AUTO_LOCK", default=False):
        raise RuntimeError(
            "Azure blob is not protected by a legal hold or a locked immutability "
            f"policy through {required_until.isoformat()}"
        )
    await blob_client.set_immutability_policy(
        ImmutabilityPolicy(
            expiry_time=required_until,
            policy_mode=BlobImmutabilityPolicyMode.LOCKED,
        )
    )
    return await _verify_blob_immutability(blob_client, required_until)


async def _verify_container_immutability_capability(
    container_client,
    collection_name: str = "",
    vault_retention_days: int | None = None,
) -> dict:
    properties = await container_client.get_container_properties()
    has_policy = bool(getattr(properties, "has_immutability_policy", False))
    has_legal_hold = bool(getattr(properties, "has_legal_hold", False))
    version_immutability = bool(
        getattr(properties, "immutable_storage_with_versioning_enabled", False)
    )
    capable = has_policy or has_legal_hold or version_immutability
    if not capable:
        raise RuntimeError(
            "Azure evidence container has no immutable-storage capability or policy. "
            "Hot records will not be deleted."
        )
    try:
        configured_days = int(
            _container_policy_setting(
                collection_name,
                "DAYS",
                "0",
                vault_retention_days,
            )
        )
    except ValueError as exc:
        raise RuntimeError("AZURE_CONTAINER_IMMUTABILITY_DAYS must be an integer") from exc
    return {
        "has_immutability_policy": has_policy,
        "has_legal_hold": has_legal_hold,
        "immutable_storage_with_versioning_enabled": version_immutability,
        "declared_locked": _container_policy_setting(
            collection_name,
            "LOCKED",
            "false",
            vault_retention_days,
        ).strip().lower() in {"1", "true", "yes", "on"},
        "configured_days": configured_days,
    }


def _verify_container_immutability_for_retention(
    container_status: dict | None,
    required_days: int,
) -> dict:
    status = dict(container_status or {})
    legal_hold = bool(status.get("has_legal_hold"))
    policy_verified = bool(
        status.get("has_immutability_policy")
        and status.get("declared_locked")
        and int(status.get("configured_days") or 0) >= required_days
    )
    if not legal_hold and not policy_verified:
        raise RuntimeError(
            "Azure container-scoped immutability is not verified for the required "
            f"{required_days}-day retention period. Confirm the policy is locked and "
            "set AZURE_CONTAINER_IMMUTABILITY_LOCKED=true plus "
            "AZURE_CONTAINER_IMMUTABILITY_DAYS to the actual Azure policy duration."
        )
    return {
        "verified": True,
        "scope": "container",
        "legal_hold": legal_hold,
        "declared_locked": bool(status.get("declared_locked")),
        "configured_days": int(status.get("configured_days") or 0),
        "verification_source": "azure-container-properties-and-operator-declaration",
    }


def _parse_archive_collections() -> tuple[str, ...]:
    raw = os.getenv("ARCHIVE_COLLECTIONS", "")
    if not raw.strip():
        return DEFAULT_ARCHIVE_COLLECTIONS
    return tuple(part.strip() for part in raw.split(",") if part.strip())


def _json_default(value):
    if isinstance(value, ObjectId):
        return str(value)
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc).isoformat()
    return str(value)


def _coerce_archive_datetime(value):
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
        except ValueError:
            return None
    return None


def _effective_retention_days(collection_name: str, tenant_retention_days: int) -> int:
    """Return Mongo hot-retention, not the total Azure compliance-retention period."""
    fixed_hot_days = HOT_RETENTION_DAYS_BY_COLLECTION.get(collection_name)
    if fixed_hot_days is not None:
        return max(1, fixed_hot_days)
    return max(1, tenant_retention_days)


def _archive_cutoffs(
    collection_name: str,
    tenant_retention_days: int,
    archive_lead_days: int,
    now: datetime | None = None,
) -> tuple[datetime, datetime]:
    now = now or datetime.now(timezone.utc)
    effective_retention_days = _effective_retention_days(collection_name, tenant_retention_days)
    return (
        now - timedelta(days=effective_retention_days),
        now + timedelta(days=archive_lead_days),
    )


def _archive_query(tenant_id: str, collection_name: str, retention_cutoff: datetime, expiry_cutoff: datetime) -> dict:
    clock = COLLECTION_ARCHIVE_CLOCKS.get(collection_name)
    if clock is None:
        raise RuntimeError(
            f"No trusted archive clock is defined for collection {collection_name!r}"
        )
    field_name, clock_kind, _ = clock
    cutoff = expiry_cutoff if clock_kind == "expiry" else retention_cutoff
    query = {
        "tenant_id": tenant_id,
        "$or": [
            {field_name: {"$lte": cutoff}},
            {field_name: {"$lte": cutoff.isoformat()}},
        ],
    }
    if collection_name in {"fbr_pos_logs", "source_envelopes_fbr"}:
        # Existing records from the retired tax-period model are deliberately
        # left untouched. Only evidence created under the active tenant model
        # can be moved and deleted by this archiver.
        query["retention_model"] = FBR_ACTIVE_RETENTION_MODEL
    if collection_name in {"peca_forensic_logs", "source_envelopes_peca"}:
        # Unmarked PECA evidence predates the tenant-entitlement model. It may
        # already carry a longer retention obligation or reference a locked
        # Azure object, so only explicitly versioned new evidence is eligible.
        query["retention_model"] = PECA_ACTIVE_RETENTION_MODEL
    if collection_name.startswith("source_envelopes_"):
        query["dispatch_complete"] = True
    return query


def _document_retention_anchor(
    document: dict,
    collection_name: str,
    tenant_retention_days: int,
) -> datetime | None:
    clock = COLLECTION_ARCHIVE_CLOCKS.get(collection_name)
    if clock is None:
        return None
    field_name, clock_kind, _ = clock
    value = _coerce_archive_datetime(document.get(field_name))
    if value is None:
        return None
    value = value.astimezone(timezone.utc)
    if clock_kind == "expiry":
        return value - timedelta(
            days=_effective_retention_days(collection_name, tenant_retention_days)
        )
    return value


def _batch_retention_window(
    documents: list[dict],
    collection_name: str,
    tenant_retention_days: int,
) -> tuple[datetime, datetime, str]:
    clock = COLLECTION_ARCHIVE_CLOCKS.get(collection_name)
    if clock is None:
        raise RuntimeError(
            f"No trusted archive clock is defined for collection {collection_name!r}"
        )
    anchors = [
        _document_retention_anchor(document, collection_name, tenant_retention_days)
        for document in documents
    ]
    if not anchors or any(anchor is None for anchor in anchors):
        raise RuntimeError(
            f"Archive batch contains {collection_name} evidence without its trusted "
            f"{clock[0]} clock. Records were preserved for manual review."
        )
    return min(anchors), max(anchors), clock[2]


def _archive_partition_time(
    docs: list[dict],
    collection_name: str,
    tenant_retention_days: int,
) -> datetime:
    oldest_anchor, _, _ = _batch_retention_window(
        docs,
        collection_name,
        tenant_retention_days,
    )
    return oldest_anchor


def _blob_base_name(
    tenant_id: str,
    collection_name: str,
    archive_key: str,
    partition_time: datetime,
) -> str:
    return (
        f"{tenant_id}/{collection_name}/"
        f"year={partition_time:%Y}/month={partition_time:%m}/day={partition_time:%d}/"
        f"archive_{collection_name}_{archive_key}"
    )


def _effective_vault_retention_days(collection_name: str, tenant_retention_days: int) -> int:
    compliance_vault_days = COMPLIANCE_VAULT_RETENTION_DAYS.get(collection_name)
    if compliance_vault_days is not None:
        return max(1, compliance_vault_days)
    return max(1, tenant_retention_days)


def _batch_vault_retention(
    collection_name: str,
    documents: list[dict],
    tenant_retention_days: int,
) -> tuple[int, str | None]:
    return _effective_vault_retention_days(collection_name, tenant_retention_days), None


def _archive_cohorts(
    collection_name: str,
    documents: list[dict],
    tenant_retention_days: int,
) -> list[list[dict]]:
    """Keep each immutable blob within one trusted UTC retention day."""
    cohorts: dict[str, list[dict]] = {}
    for index, document in enumerate(documents):
        anchor = _document_retention_anchor(
            document,
            collection_name,
            tenant_retention_days,
        )
        # A missing trusted clock is isolated so _archive_batch fails closed
        # without preventing otherwise valid documents from being archived.
        cohort_key = (
            anchor.astimezone(timezone.utc).date().isoformat()
            if anchor is not None
            else f"missing:{index}"
        )
        cohorts.setdefault(cohort_key, []).append(document)
    return list(cohorts.values())


def _bounded_archive_documents(documents: list[dict], max_encoded_bytes: int) -> list[dict]:
    selected = []
    encoded_bytes = 2
    for document in documents:
        document_bytes = len(
            json.dumps(document, default=_json_default, separators=(",", ":")).encode("utf-8")
        )
        if selected and encoded_bytes + document_bytes + 1 > max_encoded_bytes:
            break
        if document_bytes + 2 > max_encoded_bytes:
            raise RuntimeError("A single archive document exceeds ARCHIVE_BATCH_MAX_BYTES")
        selected.append(document)
        encoded_bytes += document_bytes + 1
    return selected


async def _active_holds_for_batch(db, tenant_id: str, collection_name: str, docs: list[dict]) -> list[dict]:
    event_uids = [str(doc.get("event_uid")) for doc in docs if doc.get("event_uid")]
    scope_queries: list[dict] = [
        {"scope_type": "TENANT"},
        {"scope_type": "COLLECTION", "collection": collection_name},
    ]
    if event_uids:
        scope_queries.append(
            {
                "scope_type": "EVENT",
                "collection": collection_name,
                "event_uid": {"$in": event_uids},
            }
        )
    holds = await db["legal_holds"].find(
        {
            "tenant_id": tenant_id,
            "status": {"$in": ["ACTIVE", "PENDING_RELEASE"]},
            "$or": scope_queries,
        },
        {"_id": 1, "hold_id": 1, "tenant_id": 1, "scope_type": 1, "collection": 1, "event_uid": 1},
    ).limit(500).to_list(500)
    return holds


async def _archive_batch(
    container_client,
    db,
    tenant_id: str,
    collection_name: str,
    docs: list[dict],
    run_id: str,
    batch_number: int,
    tenant_retention_days: int,
    container_immutability: dict | None = None,
    container_name: str | None = None,
):
    document_ids = [doc["_id"] for doc in docs if "_id" in doc]
    if not document_ids:
        return 0

    json_dump = json.dumps(docs, default=_json_default, separators=(",", ":")).encode("utf-8")
    sha256_hash = hashlib.sha256(json_dump).hexdigest()
    identity = "|".join(
        (
            tenant_id,
            collection_name,
            sha256_hash,
            *(str(document_id) for document_id in document_ids),
        )
    )
    archive_key = hashlib.sha256(identity.encode("utf-8")).hexdigest()[:24]

    vault_retention_days, retention_state = _batch_vault_retention(
        collection_name,
        docs,
        tenant_retention_days,
    )
    oldest_anchor, newest_anchor, retention_clock_basis = _batch_retention_window(
        docs,
        collection_name,
        tenant_retention_days,
    )
    # Azure Blob immutability timestamps are exposed at whole-second precision.
    # Use that same clock for the minimum WORM boundary so sub-second precision
    # cannot make an exact 90-day policy appear a fraction of a second short.
    archived_at = datetime.now(timezone.utc).replace(microsecond=0)
    customer_access_until = newest_anchor + timedelta(days=vault_retention_days)
    oldest_customer_access_until = oldest_anchor + timedelta(days=vault_retention_days)
    base_name = _blob_base_name(
        tenant_id,
        collection_name,
        archive_key,
        oldest_anchor,
    )
    json_blob_name = f"{base_name}.json"
    hash_blob_name = f"{base_name}.sha256"
    access_tier = _archive_access_tier(collection_name, vault_retention_days)
    upload_options = {}
    if access_tier is not None:
        upload_options["standard_blob_tier"] = access_tier

    json_blob = container_client.get_blob_client(json_blob_name)
    try:
        await json_blob.upload_blob(
            json_dump,
            overwrite=False,
            validate_content=True,
            metadata={
                "sha256": sha256_hash,
                "collection": collection_name,
                "retention_days": str(vault_retention_days or 0),
                "retention_state": str(retention_state or "configured"),
                "retention_clock": retention_clock_basis.lower(),
                "customer_access_until": customer_access_until.isoformat(),
            },
            **upload_options,
        )
    except ResourceExistsError:
        pass

    hash_blob = container_client.get_blob_client(hash_blob_name)
    hash_payload = sha256_hash.encode("utf-8")
    try:
        await hash_blob.upload_blob(
            hash_payload,
            overwrite=False,
            validate_content=True,
            **upload_options,
        )
    except ResourceExistsError:
        pass

    immutability_required = _environment_flag("AZURE_IMMUTABILITY_REQUIRED", default=False)
    immutability_status = None
    physical_worm_required_until = archived_at + timedelta(days=vault_retention_days)
    if immutability_required:
        scope = _archive_immutability_scope(collection_name, vault_retention_days)
        if scope == "container":
            immutability_status = _verify_container_immutability_for_retention(
                container_immutability,
                vault_retention_days,
            )
        elif scope == "blob":
            preliminary_json_facts = _blob_storage_facts(
                await json_blob.get_blob_properties()
            )
            preliminary_hash_facts = _blob_storage_facts(
                await hash_blob.get_blob_properties()
            )
            json_required_until = _required_blob_worm_until(
                preliminary_json_facts,
                vault_retention_days,
            )
            hash_required_until = _required_blob_worm_until(
                preliminary_hash_facts,
                vault_retention_days,
            )
            json_status = await _ensure_blob_immutability(
                json_blob, json_required_until
            )
            hash_status = await _ensure_blob_immutability(
                hash_blob, hash_required_until
            )
            physical_worm_required_until = min(
                json_required_until,
                hash_required_until,
            )
            immutability_status = {
                "verified": True,
                "scope": "blob",
                "json": json_status,
                "sha256": hash_status,
            }

    # Compatibility alias retained for existing archive readers and reports.
    retain_until = physical_worm_required_until

    json_properties = await json_blob.get_blob_properties()
    hash_properties = await hash_blob.get_blob_properties()
    json_facts = _blob_storage_facts(json_properties)
    hash_facts = _blob_storage_facts(hash_properties)
    expected_tier = _enum_value(access_tier)
    if expected_tier:
        observed_tiers = {
            str(json_facts.get("tier") or "").lower(),
            str(hash_facts.get("tier") or "").lower(),
        }
        if observed_tiers != {expected_tier.lower()}:
            raise RuntimeError(
                "Azure archive tier verification failed; hot records were preserved"
            )
    _verify_required_blob_version_ids(json_facts, hash_facts)

    downloaded_json_sha256 = await _stream_blob_sha256(json_blob)
    if downloaded_json_sha256 != sha256_hash:
        raise RuntimeError(
            "Azure archive readback failed SHA-256 verification; hot records were preserved"
        )
    expected_hash_blob_sha256 = hashlib.sha256(hash_payload).hexdigest()
    downloaded_hash_blob_sha256 = await _stream_blob_sha256(hash_blob)
    if downloaded_hash_blob_sha256 != expected_hash_blob_sha256:
        raise RuntimeError(
            "Azure archive hash-sidecar readback failed verification; hot records were preserved"
        )

    worm_expiries = [
        value
        for value in (
            json_facts.get("immutability_until"),
            hash_facts.get("immutability_until"),
        )
        if value is not None
    ]
    physical_worm_until = min(worm_expiries) if len(worm_expiries) == 2 else None

    timestamps = [doc.get("timestamp") or doc.get("ingested_at") or doc.get("uploaded_at") for doc in docs]
    parsed_timestamps = [timestamp for timestamp in map(_coerce_archive_datetime, timestamps) if timestamp]
    event_ids = sorted({str(doc.get("event_id")) for doc in docs if doc.get("event_id") is not None})
    event_uids = sorted({str(doc.get("event_uid")) for doc in docs if doc.get("event_uid")})
    alert_uids = sorted({str(doc.get("alert_uid")) for doc in docs if doc.get("alert_uid")})
    resolved_container_name = container_name or _archive_container_name(
        collection_name,
        vault_retention_days,
    )
    archive_doc = {
        "tenant_id": tenant_id,
        "collection": collection_name,
        "container_name": resolved_container_name,
        "blob_name": json_blob_name,
        "hash_blob_name": hash_blob_name,
        "archive_key": archive_key,
        "run_id": run_id,
        "batch_number": batch_number,
        "sha256": sha256_hash,
        "blob_size_bytes": len(json_dump),
        "hash_blob_size_bytes": len(hash_payload),
        "document_count": len(document_ids),
        "first_document_id": str(document_ids[0]),
        "last_document_id": str(document_ids[-1]),
        "oldest_timestamp": min((str(ts) for ts in timestamps if ts is not None), default=None),
        "newest_timestamp": max((str(ts) for ts in timestamps if ts is not None), default=None),
        "oldest_at": min(parsed_timestamps) if parsed_timestamps else None,
        "newest_at": max(parsed_timestamps) if parsed_timestamps else None,
        "event_ids": event_ids,
        "event_uids": event_uids,
        "alert_uids": alert_uids,
        "retention_model": "TENANT_ENTITLEMENT_V1",
        "retention_clock_basis": retention_clock_basis,
        "logical_retention_start_at": oldest_anchor,
        "logical_retention_latest_start_at": newest_anchor,
        "logical_retention_days": vault_retention_days,
        "oldest_customer_access_until": oldest_customer_access_until,
        "customer_access_until": customer_access_until,
        "archive_created_at": archived_at,
        "physical_worm_required_until": physical_worm_required_until,
        "physical_worm_until": physical_worm_until,
        "physical_worm_verified": bool(
            immutability_status and immutability_status.get("verified")
        ),
        "blob_version_id": json_facts.get("version_id"),
        "hash_blob_version_id": hash_facts.get("version_id"),
        "blob_etag": json_facts.get("etag"),
        "hash_blob_etag": hash_facts.get("etag"),
        "blob_created_at": json_facts.get("creation_time"),
        "hash_blob_created_at": hash_facts.get("creation_time"),
        "archive_tier": json_facts.get("tier"),
        "hash_archive_tier": hash_facts.get("tier"),
        "readback_verified": True,
        "readback_verified_at": datetime.now(timezone.utc),
        "vault_retention_days": vault_retention_days,
        "retain_until": retain_until,
        "retention_state": retention_state,
        "automatic_final_expiry_allowed": retention_state != "UNRESOLVED",
        "immutability": immutability_status,
        "created_at": archived_at,
        "status": "archived",
    }
    refresh_fields = {
        "container_name",
        "retention_model",
        "retention_clock_basis",
        "logical_retention_start_at",
        "logical_retention_latest_start_at",
        "logical_retention_days",
        "oldest_customer_access_until",
        "customer_access_until",
        "archive_created_at",
        "physical_worm_required_until",
        "physical_worm_until",
        "physical_worm_verified",
        "blob_version_id",
        "hash_blob_version_id",
        "blob_etag",
        "hash_blob_etag",
        "blob_created_at",
        "hash_blob_created_at",
        "archive_tier",
        "hash_archive_tier",
        "readback_verified",
        "readback_verified_at",
        "vault_retention_days",
        "retain_until",
        "retention_state",
        "automatic_final_expiry_allowed",
        "immutability",
    }
    archive_insert = {
        key: value for key, value in archive_doc.items() if key not in refresh_fields
    }
    archive_refresh = {
        key: archive_doc[key] for key in refresh_fields
    }
    ledger_result = await db["storage_archives"].update_one(
        {
            "tenant_id": tenant_id,
            "collection": collection_name,
            "archive_key": archive_key,
        },
        {"$setOnInsert": archive_insert, "$set": archive_refresh},
        upsert=True,
    )
    if ledger_result.upserted_id is not None:
        retention_class = _archive_retention_class(collection_name)
        try:
            await db["archive_storage_daily"].update_one(
                {
                    "tenant_id": tenant_id,
                    "day": f"{archived_at:%Y-%m-%d}",
                    "retention_class": retention_class,
                },
                {
                    "$setOnInsert": {
                        "tenant_id": tenant_id,
                        "day": f"{archived_at:%Y-%m-%d}",
                        "retention_class": retention_class,
                        "created_at": archived_at,
                    },
                    "$inc": {
                        "archived_bytes": len(json_dump),
                        "hash_bytes": len(hash_payload),
                        "archive_blobs": 1,
                        "documents": len(document_ids),
                    },
                    "$set": {"updated_at": archived_at},
                },
                upsert=True,
            )
        except Exception:
            # The immutable archive ledger remains the billing source of truth.
            # A derived daily rollup must never block hot-data cleanup after the
            # Azure blob and its ledger record have been committed.
            logger.exception(
                "Unable to update archive storage rollup for %s/%s/%s",
                tenant_id,
                collection_name,
                archive_key,
            )

    fence_owner = f"archive-delete:{run_id}:{collection_name}:{archive_key}"
    if not await acquire_retention_fence(db, tenant_id, fence_owner):
        logger.warning("Archive delete fence is busy for tenant %s; preserving hot records.", tenant_id)
        return 0
    try:
        active_holds = await _active_holds_for_batch(
            db,
            tenant_id,
            collection_name,
            docs,
        )
        if active_holds:
            archive_record = await db["storage_archives"].find_one(
                {
                    "tenant_id": tenant_id,
                    "collection": collection_name,
                    "archive_key": archive_key,
                }
            )
            if not archive_record:
                raise RuntimeError("Archive ledger disappeared before legal-hold protection")
            try:
                for hold in active_holds:
                    await protect_archive_for_hold(
                        db,
                        None,
                        hold,
                        archive_record,
                        container_client=container_client,
                    )
            except Exception as exc:
                await db["storage_archives"].update_one(
                    {"_id": archive_record["_id"]},
                    {
                        "$set": {
                            "status": "archive_hold_protection_failed",
                            "legal_hold_error": type(exc).__name__,
                            "hot_delete_blocked_at": datetime.now(timezone.utc),
                        }
                    },
                )
                raise
            active_hold_ids = sorted(
                str(hold.get("hold_id") or hold.get("_id")) for hold in active_holds
            )
            await db["storage_archives"].update_one(
                {
                    "tenant_id": tenant_id,
                    "collection": collection_name,
                    "archive_key": archive_key,
                },
                {
                    "$set": {
                        "status": "archived_hot_preserved_hold",
                        "active_hold_ids": active_hold_ids,
                        "hot_delete_blocked_at": datetime.now(timezone.utc),
                    }
                },
            )
            logger.warning(
                "Archived %s.%s batch %s but preserved hot records due to active hold %s.",
                tenant_id,
                collection_name,
                batch_number,
                active_hold_ids,
            )
            return 0

        delete_result = await db[collection_name].delete_many({
            "tenant_id": tenant_id,
            "_id": {"$in": document_ids},
        })
    finally:
        await release_retention_fence(db, tenant_id, fence_owner)
    await db["storage_archives"].update_one(
        {
            "tenant_id": tenant_id,
            "collection": collection_name,
            "archive_key": archive_key,
        },
        {
            "$set": {
                "status": "archived_hot_deleted",
                "hot_deleted_at": datetime.now(timezone.utc),
                "hot_deleted_count": delete_result.deleted_count,
            },
            "$unset": {
                "active_hold_ids": "",
                "hot_delete_blocked_at": "",
            },
        },
    )
    logger.info(
        "Archived %s.%s batch %s to %s/%s and deleted %s hot records.",
        tenant_id,
        collection_name,
        batch_number,
        resolved_container_name,
        json_blob_name,
        delete_result.deleted_count,
    )
    return delete_result.deleted_count


async def run_archiver():
    logger.info("========================================")
    logger.info(" WARSOC COLD STORAGE ARCHIVER STARTED ")
    logger.info("========================================")

    azure_conn_str = os.getenv("AZURE_STORAGE_CONNECTION_STRING")
    if not azure_conn_str:
        raise RuntimeError("AZURE_STORAGE_CONNECTION_STRING is required for archival")

    mongo_uri = os.getenv("MONGODB_URI", "mongodb://localhost:27017")
    db_name = os.getenv("MONGODB_DB_NAME", "warsoc_db")
    archive_batch_size = max(1, min(int(os.getenv("ARCHIVE_BATCH_SIZE", "100")), 500))
    archive_fetch_size = min(archive_batch_size, 25)
    archive_batch_max_bytes = max(
        1024 * 1024,
        min(int(os.getenv("ARCHIVE_BATCH_MAX_BYTES", str(32 * 1024 * 1024))), 64 * 1024 * 1024),
    )
    archive_lead_days = int(os.getenv("ARCHIVE_LEAD_DAYS", "1"))
    collections_to_archive = _parse_archive_collections()
    run_id = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S") + "_" + uuid.uuid4().hex[:8]

    mongo_client = AsyncIOMotorClient(mongo_uri)
    blob_service_client = None

    try:
        db = mongo_client[db_name]
        blob_service_client = BlobServiceClient.from_connection_string(azure_conn_str)
        container_contexts = {}

        async def get_container_context(
            collection_name: str,
            tenant_retention_days: int,
            required_vault_days: int | None = None,
        ):
            retention_class = _archive_retention_class(collection_name)
            vault_retention_days = required_vault_days or _effective_vault_retention_days(
                collection_name, tenant_retention_days
            )
            routing_key = _archive_routing_key(collection_name, vault_retention_days)
            container_name = _archive_container_name(collection_name, vault_retention_days)
            context_key = (container_name, routing_key)
            if context_key in container_contexts:
                return container_contexts[context_key]

            container_client = blob_service_client.get_container_client(container_name)
            if not await container_client.exists():
                await container_client.create_container()
                logger.info("Created Azure container: %s", container_name)
            container_immutability = None
            if _environment_flag("AZURE_IMMUTABILITY_REQUIRED", default=False):
                container_immutability = await _verify_container_immutability_capability(
                    container_client,
                    collection_name,
                    vault_retention_days,
                )
            context = (container_name, container_client, container_immutability)
            container_contexts[context_key] = context
            return context

        cursor = db.tenants.find({})
        async for tenant in cursor:
            tenant_id = tenant.get("tenant_id")
            retention_days = int(tenant.get("retention_days", 30) or 30)
            if not tenant_id:
                continue

            logger.info(
                "Processing tenant %s with retention_days=%s archive_lead_days=%s",
                tenant_id,
                retention_days,
                archive_lead_days,
            )

            for collection_name in collections_to_archive:
                retention_cutoff, expiry_cutoff = _archive_cutoffs(
                    collection_name,
                    retention_days,
                    archive_lead_days,
                )
                query = _archive_query(tenant_id, collection_name, retention_cutoff, expiry_cutoff)
                batch_number = 1

                while True:
                    candidates = await db[collection_name].find(query).sort("_id", 1).limit(archive_fetch_size).to_list(length=archive_fetch_size)
                    docs = _bounded_archive_documents(candidates, archive_batch_max_bytes)
                    if not docs:
                        break

                    deleted_in_iteration = 0
                    try:
                        if collection_name == "security_alerts":
                            # Archive is allowed to remove alert evidence only
                            # after its mutable workflow state has been projected.
                            # Any projection failure aborts the batch, preserving
                            # the original MongoDB documents for a later retry.
                            for alert in docs:
                                await project_security_incident(db, alert)
                        for cohort_docs in _archive_cohorts(
                            collection_name,
                            docs,
                            retention_days,
                        ):
                            required_vault_days, _ = _batch_vault_retention(
                                collection_name,
                                cohort_docs,
                                retention_days,
                            )
                            container_name, container_client, container_immutability = await get_container_context(
                                collection_name,
                                retention_days,
                                required_vault_days,
                            )
                            deleted_in_iteration += await _archive_batch(
                                container_client,
                                db,
                                tenant_id,
                                collection_name,
                                cohort_docs,
                                run_id,
                                batch_number,
                                retention_days,
                                container_immutability,
                                container_name,
                            )
                            batch_number += 1
                    except Exception as exc:
                        logger.error(
                            "Failed to archive %s for tenant %s. Records were not deleted. Error: %s",
                            collection_name,
                            tenant_id,
                            exc,
                        )
                        break

                    if deleted_in_iteration == 0:
                        break

    finally:
        if blob_service_client is not None:
            await blob_service_client.close()
        mongo_client.close()

    logger.info("Storage Archiver run completed.")


async def run_archiver_scheduler():
    interval_seconds = int(os.getenv("ARCHIVE_INTERVAL_SECONDS", "0"))
    if interval_seconds <= 0:
        await run_archiver()
        return
    if interval_seconds < 300:
        raise RuntimeError("ARCHIVE_INTERVAL_SECONDS must be at least 300")

    while True:
        await run_archiver()
        logger.info("Next storage archival run in %s seconds.", interval_seconds)
        await asyncio.sleep(interval_seconds)


if __name__ == "__main__":
    asyncio.run(run_archiver_scheduler())
