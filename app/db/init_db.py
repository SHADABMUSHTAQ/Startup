import logging
import os
from motor.motor_asyncio import AsyncIOMotorClient
from pymongo.errors import OperationFailure
from app.config.config import get_settings

logger = logging.getLogger(__name__)
settings = get_settings()

RAW_RETENTION_SECONDS = 7776000  # 90 days
DEFAULT_TENANT_RETENTION_DAYS = 90
SIEM_HOT_RETENTION_DAYS = max(1, min(7, int(os.getenv("SIEM_HOT_RETENTION_DAYS", "7"))))
RAW_RETENTION_ANCHOR_FIELD = "_retention_ts"

async def init_db():
    """Initialize Database connection and core indexes"""
    try:
        client = AsyncIOMotorClient(settings.mongodb_uri)
        db = client[settings.mongodb_db_name]
        
        # Create core indexes for general logs
        await db.logs.create_index([("timestamp", -1)])
        await db.logs.create_index([("severity", 1)])
        await db.logs.create_index([("log_type", 1)])
        
        logger.info("Core MongoDB indexes initialized successfully")
        return db
    except Exception as e:
        logger.error(f"Failed to initialize database: {e}")
        raise


def _is_single_field_key(index_def: dict, field_name: str) -> bool:
    key = index_def.get("key")
    return isinstance(key, list) and len(key) == 1 and key[0][0] == field_name


async def _drop_ttl_indexes(collection, collection_name: str):
    indexes = await collection.index_information()
    for idx_name, idx_def in indexes.items():
        if idx_name == "_id_":
            continue
        if idx_def.get("expireAfterSeconds") is not None:
            try:
                await collection.drop_index(idx_name)
                logger.warning(f"Dropped legacy TTL index {collection_name}.{idx_name}")
            except OperationFailure as e:
                if e.code == 27 or "IndexNotFound" in str(e):
                    pass
                else:
                    raise e


async def _drop_ttl_indexes_except(collection, collection_name: str, allowed_field_name: str):
    indexes = await collection.index_information()
    for idx_name, idx_def in indexes.items():
        if idx_name == "_id_":
            continue
        if idx_def.get("expireAfterSeconds") is None:
            continue
        if _is_single_field_key(idx_def, allowed_field_name):
            continue
        try:
            await collection.drop_index(idx_name)
            logger.warning(
                f"Dropped legacy TTL index {collection_name}.{idx_name}; {allowed_field_name} is the retention source of truth"
            )
        except OperationFailure as e:
            if e.code == 27 or "IndexNotFound" in str(e):
                pass
            else:
                raise e


async def _backfill_expire_at(collection, retention_days: int):
    await collection.update_many(
        {"_expire_at": {"$exists": False}},
        [
            {
                "$set": {
                    "_expire_at": {
                        "$dateAdd": {
                            "startDate": {
                                "$switch": {
                                    "branches": [
                                        {
                                            "case": {"$eq": [{"$type": "$_retention_ts"}, "date"]},
                                            "then": "$_retention_ts",
                                        },
                                        {
                                            "case": {"$eq": [{"$type": "$timestamp"}, "date"]},
                                            "then": "$timestamp",
                                        },
                                        {
                                            "case": {"$eq": [{"$type": "$ingested_at"}, "date"]},
                                            "then": "$ingested_at",
                                        },
                                    ],
                                    "default": "$$NOW",
                                }
                            },
                            "unit": "day",
                            "amount": retention_days,
                        }
                    }
                }
            }
        ],
    )



async def _ensure_ttl_index(
    collection,
    collection_name: str,
    field_name: str,
    ttl_seconds: int,
    index_name: str,
):
    indexes = await collection.index_information()
    for idx_name, idx_def in indexes.items():
        if idx_name == "_id_":
            continue
        if not _is_single_field_key(idx_def, field_name):
            continue

        existing_ttl = idx_def.get("expireAfterSeconds")
        if existing_ttl == ttl_seconds:
            # Matching TTL already present.
            return

        # Same key with wrong/missing TTL blocks compliant recreation.
        try:
            await collection.drop_index(idx_name)
            logger.warning(
                f"Dropped index {collection_name}.{idx_name} to enforce TTL={ttl_seconds}s on {field_name}"
            )
        except OperationFailure as e:
            if e.code == 27 or "IndexNotFound" in str(e):
                pass
            else:
                raise e

    await collection.create_index(
        [(field_name, 1)],
        name=index_name,
        expireAfterSeconds=ttl_seconds,
    )

async def init_compliance_db(db):
    """
    Enforce PTA CTDISR-2025 and ETO 2002 Sections 5 & 6 compliance via TTL indexes.
    This ensures automated data retention and forensic sealing audit trails.
    """
    
async def _aggressive_create_index(collection, keys, **kwargs):
    try:
        await collection.create_index(keys, **kwargs)
    except OperationFailure as e:
        if e.code == 85 or "IndexOptionsConflict" in str(e):
            logger.warning(f"Conflicting index found for {keys} with options {kwargs}. Purging and recreating...")
            indexes = await collection.index_information()
            expected_key = keys if isinstance(keys, list) else [(keys, 1)]
            for idx_name, idx_info in indexes.items():
                if idx_info.get("key") == expected_key:
                    try:
                        await collection.drop_index(idx_name)
                        logger.warning(f"Dropped conflicting index: {idx_name}")
                    except OperationFailure as err:
                        if err.code == 27 or "IndexNotFound" in str(err):
                            pass
                        else:
                            raise err
            if "name" in kwargs and kwargs["name"] in indexes:
                try:
                    await collection.drop_index(kwargs["name"])
                    logger.warning(f"Dropped conflicting index by name: {kwargs['name']}")
                except Exception:
                    pass
            await collection.create_index(keys, **kwargs)
            logger.info(f"Successfully recreated index for {keys}")
        else:
            raise e

async def init_compliance_db(db):
    try:
        logger.info("Initializing PTA/ETO 2002 Sections 5 & 6 Compliance Layer...")
        
        # 1. PECA Forensic Logs: 1 Year Retention (via _expire_at)
        await _drop_ttl_indexes_except(db.peca_forensic_logs, "peca_forensic_logs", "_expire_at")
        await _backfill_expire_at(db.peca_forensic_logs, retention_days=365)
        await _ensure_ttl_index(
            db.peca_forensic_logs,
            collection_name="peca_forensic_logs",
            field_name="_expire_at",
            ttl_seconds=0,
            index_name="peca_forensic_logs_expire_at",
        )
        # Drop legacy unique index if present; PECA must allow repeated event IDs across tenants/time.
        peca_indexes = await db.peca_forensic_logs.index_information()
        legacy_event_idx = peca_indexes.get("event_id_1")
        if legacy_event_idx and legacy_event_idx.get("unique"):
            await db.peca_forensic_logs.drop_index("event_id_1")
            logger.warning("Dropped legacy unique index peca_forensic_logs.event_id_1")

        await _aggressive_create_index(db.peca_forensic_logs, [("event_id", 1)], name="event_id_1", unique=False)
        await _aggressive_create_index(db.peca_forensic_logs, [("tenant_id", 1), ("timestamp", -1)])
        #  LEGAL PHYSICS: Hard engine-level block on cross-tenant overwrites
        await _aggressive_create_index(db.peca_forensic_logs, [("tenant_id", 1), ("event_uid", 1)], unique=True, name="idx_peca_tenant_event_uid")

        # 2. FBR POS Compliance: 6 Year Retention (via _expire_at)
        await _drop_ttl_indexes_except(db.fbr_pos_logs, "fbr_pos_logs", "_expire_at")
        await _backfill_expire_at(db.fbr_pos_logs, retention_days=365 * 6)
        await _ensure_ttl_index(
            db.fbr_pos_logs,
            collection_name="fbr_pos_logs",
            field_name="_expire_at",
            ttl_seconds=0,
            index_name="fbr_pos_logs_expire_at",
        )
        await _aggressive_create_index(db.fbr_pos_logs, [("tenant_id", 1), ("timestamp", -1)])
        await _aggressive_create_index(db.fbr_pos_logs, [("fbr_invoice_id", 1)])
        #  LEGAL PHYSICS: Hard engine-level block on cross-tenant overwrites
        await _aggressive_create_index(db.fbr_pos_logs, [("tenant_id", 1), ("event_uid", 1)], unique=True, name="idx_fbr_tenant_event_uid")

        # 3. SIEM Security Audit Trail: Hot Feed (via _expire_at)
        await _drop_ttl_indexes_except(db.security_alerts, "security_alerts", "_expire_at")
        await _ensure_ttl_index(
            db.security_alerts,
            collection_name="security_alerts",
            field_name="_expire_at",
            ttl_seconds=0,
            index_name="security_alerts_expire_at",
        )
        #  LEGAL PHYSICS: Hard engine-level block on cross-tenant overwrites for hot feed
        await _aggressive_create_index(db.security_alerts, [("tenant_id", 1), ("alert_uid", 1)], unique=True, name="idx_alerts_tenant_alert_uid")
        # Legacy FBR/correlation alerts used a non-indexed retention field. Give
        # them a full hot-retention window before the absolute TTL applies.
        await db.security_alerts.update_many(
            {"_expire_at": {"$exists": False}},
            [
                {
                    "$set": {
                        "_expire_at": {
                            "$dateAdd": {
                                "startDate": "$$NOW",
                                "unit": "day",
                                "amount": 7,
                            }
                        }
                    }
                }
            ],
        )

        # 3.5 SIEM Cold Vault: the archiver owns hot-data removal. A Mongo TTL
        # could delete evidence during an Azure outage before archival succeeds.
        await _drop_ttl_indexes(db.siem_cold_vault, "siem_cold_vault")
        await _backfill_expire_at(db.siem_cold_vault, retention_days=SIEM_HOT_RETENTION_DAYS)

        # 4. PHASE 5 RAW DATA SELF-CLEANING (90-Day)
        # Drop legacy TTL index on string timestamp to save DB overhead
        await _drop_ttl_indexes(db.logs, "logs_ttl_90d")
        await _ensure_ttl_index(
            db.logs,
            collection_name="logs",
            field_name=RAW_RETENTION_ANCHOR_FIELD,
            ttl_seconds=RAW_RETENTION_SECONDS,
            index_name="logs_anchor_ttl_90d",
        )
        # Drop legacy TTL index on string timestamp
        await _drop_ttl_indexes(db.csv_uploads, "csv_uploads_ttl_90d")
        await _ensure_ttl_index(
            db.csv_uploads,
            collection_name="csv_uploads",
            field_name=RAW_RETENTION_ANCHOR_FIELD,
            ttl_seconds=RAW_RETENTION_SECONDS,
            index_name="csv_uploads_anchor_ttl_90d",
        )
        await _ensure_ttl_index(
            db.analysis_results,
            collection_name="analysis_results",
            field_name="uploaded_at",
            ttl_seconds=RAW_RETENTION_SECONDS,
            index_name="analysis_results_ttl_90d",
        )

        # Backfill Date anchors so TTL applies to existing string-timestamp records too.
        await db.logs.update_many(
            {RAW_RETENTION_ANCHOR_FIELD: {"$exists": False}},
            [
                {
                    "$set": {
                        RAW_RETENTION_ANCHOR_FIELD: {
                            "$cond": [
                                {"$eq": [{"$type": "$timestamp"}, "date"]},
                                "$timestamp",
                                {
                                    "$dateFromString": {
                                        "dateString": "$timestamp",
                                        "onError": "$$NOW",
                                        "onNull": "$$NOW",
                                    }
                                },
                            ]
                        }
                    }
                }
            ],
        )
        await db.csv_uploads.update_many(
            {RAW_RETENTION_ANCHOR_FIELD: {"$exists": False}},
            [
                {
                    "$set": {
                        RAW_RETENTION_ANCHOR_FIELD: {
                            "$cond": [
                                {"$eq": [{"$type": "$timestamp"}, "date"]},
                                "$timestamp",
                                {
                                    "$dateFromString": {
                                        "dateString": "$timestamp",
                                        "onError": "$$NOW",
                                        "onNull": "$$NOW",
                                    }
                                },
                            ]
                        }
                    }
                }
            ],
        )

        # 5. CTO VETO ENFORCEMENT: Audit trails are excluded from raw TTL policy.
        await _drop_ttl_indexes(db.management_audit, "management_audit")
        await _drop_ttl_indexes(db.system_audit, "system_audit")
        await db.management_audit.create_index([("timestamp", -1)], name="management_audit_timestamp_desc")
        await db.management_audit.create_index([("operator", 1), ("timestamp", -1)])
        await db.system_audit.create_index([("tenant_id", 1), ("timestamp", -1)])

        # 6. TIERED RETENTION PREP: seed tenant retention defaults (ready for premium overrides).
        await db.tenants.update_many(
            {"retention_days": {"$exists": False}},
            {"$set": {"retention_days": DEFAULT_TENANT_RETENTION_DAYS}},
        )
        
        #  PERFORMANCE HARDENING: Unified Tenant Exploration
        # Composite index for O(log n) dashboard log lookups at scale.
        await _aggressive_create_index(db.logs, [("tenant_id", 1), ("timestamp", -1)])
        await _aggressive_create_index(db.logs, [("source_ip", 1)])
        
        # High-cardinality search optimization
        await _aggressive_create_index(db.fbr_pos_logs, [("data.store_id", 1), ("timestamp", -1)])
        await _aggressive_create_index(db.peca_forensic_logs, [("forensic_seal", 1)])
        await _aggressive_create_index(db.storage_archives, [("tenant_id", 1), ("collection", 1), ("created_at", -1)])
        await _aggressive_create_index(db.storage_archives, [("tenant_id", 1), ("collection", 1), ("newest_at", -1)])
        await _aggressive_create_index(db.storage_archives, [("tenant_id", 1), ("collection", 1), ("event_ids", 1)])
        await _aggressive_create_index(db.storage_archives, [("tenant_id", 1), ("collection", 1), ("event_uids", 1)])

        logger.info(" 7-Tier Database Layer Hardened: Capacity TTL active and audit-veto enforced.")
        
    except Exception as e:
        logger.error(f"Critical failure in compliance DB initialization: {e}")
