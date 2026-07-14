import logging
import os
from motor.motor_asyncio import AsyncIOMotorClient
from pymongo.errors import OperationFailure
from app.config.config import get_settings

logger = logging.getLogger(__name__)
settings = get_settings()

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
        
        # Archive-managed collections keep retention metadata, but only the
        # verified Azure archiver may delete their hot records.
        await _drop_ttl_indexes(db.peca_forensic_logs, "peca_forensic_logs")
        await _backfill_expire_at(db.peca_forensic_logs, retention_days=365)
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

        # 2. FBR POS Compliance: 6 Year vault-retention metadata.
        await _drop_ttl_indexes(db.fbr_pos_logs, "fbr_pos_logs")
        await _backfill_expire_at(db.fbr_pos_logs, retention_days=365 * 6)
        await _aggressive_create_index(db.fbr_pos_logs, [("tenant_id", 1), ("timestamp", -1)])
        await _aggressive_create_index(db.fbr_pos_logs, [("fbr_invoice_id", 1)])
        #  LEGAL PHYSICS: Hard engine-level block on cross-tenant overwrites
        await _aggressive_create_index(db.fbr_pos_logs, [("tenant_id", 1), ("event_uid", 1)], unique=True, name="idx_fbr_tenant_event_uid")

        # 3. SIEM Security Audit Trail: seven-day hot feed, archive-before-delete.
        await _drop_ttl_indexes(db.security_alerts, "security_alerts")
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

        # 4. Raw uploads/results are also archive-managed. Remove every legacy
        # TTL so an Azure outage causes visible hot-storage growth, not data loss.
        await _drop_ttl_indexes(db.logs, "logs")
        await _drop_ttl_indexes(db.csv_uploads, "csv_uploads")
        await _drop_ttl_indexes(db.analysis_results, "analysis_results")

        # Backfill date anchors so the archiver can select legacy records that
        # stored display timestamps as strings.
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
        await _aggressive_create_index(
            db.storage_archives,
            [("tenant_id", 1), ("collection", 1), ("archive_key", 1)],
            unique=True,
            sparse=True,
            name="uq_storage_archive_key",
        )
        await _aggressive_create_index(
            db.user_activation_tokens,
            [("token_hash", 1)],
            unique=True,
            name="uq_user_activation_token_hash",
        )
        await _aggressive_create_index(
            db.user_activation_tokens,
            [("expires_at", 1)],
            expireAfterSeconds=0,
            name="ttl_user_activation_tokens",
        )
        await _aggressive_create_index(
            db.user_activation_tokens,
            [("user_id", 1), ("purpose", 1), ("used_at", 1)],
            name="idx_user_activation_lifecycle",
        )

        logger.info(" 7-Tier Database Layer Hardened: Capacity TTL active and audit-veto enforced.")
        
    except Exception as e:
        logger.error(f"Critical failure in compliance DB initialization: {e}")
