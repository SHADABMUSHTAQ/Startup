import logging
from motor.motor_asyncio import AsyncIOMotorClient
from app.config.config import get_settings

logger = logging.getLogger(__name__)
settings = get_settings()

RAW_RETENTION_SECONDS = 7776000  # 90 days
DEFAULT_TENANT_RETENTION_DAYS = 90
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
            await collection.drop_index(idx_name)
            logger.warning(f"Dropped legacy TTL index {collection_name}.{idx_name}")


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
        await collection.drop_index(idx_name)
        logger.warning(
            f"Dropped index {collection_name}.{idx_name} to enforce TTL={ttl_seconds}s on {field_name}"
        )

    await collection.create_index(
        [(field_name, 1)],
        name=index_name,
        expireAfterSeconds=ttl_seconds,
    )

async def init_compliance_db(db):
    """
    Enforce PTA CTDISR-2025 and PECA Section 46 compliance via TTL indexes.
    This ensures automated data retention and forensic sealing audit trails.
    """
    try:
        logger.info("Initializing PTA/PECA Compliance Layer...")
        
        # 1. PECA Section 46: Forensic Log Integrity (365 Day Retention)
        await db.peca_forensic_logs.create_index(
            "timestamp", 
            expireAfterSeconds=31536000  # 365 days
        )
        # Drop legacy unique index if present; PECA must allow repeated event IDs across tenants/time.
        peca_indexes = await db.peca_forensic_logs.index_information()
        legacy_event_idx = peca_indexes.get("event_id_1")
        if legacy_event_idx and legacy_event_idx.get("unique"):
            await db.peca_forensic_logs.drop_index("event_id_1")
            logger.warning("Dropped legacy unique index peca_forensic_logs.event_id_1")

        # ✅ MASTER BUILD REMEDIATION: Remove unique=True to allow scaling of repeated events (e.g. Logon 4624)
        await db.peca_forensic_logs.create_index([("event_id", 1)], name="event_id_1", unique=False)
        await db.peca_forensic_logs.create_index([("tenant_id", 1), ("timestamp", -1)])
        
        # 2. FBR POS Compliance (S.R.O. 288/I/2026): 30-Day Batch Storage
        await db.fbr_pos_logs.create_index(
            "timestamp", 
            expireAfterSeconds=2592000  # 30 days
        )
        await db.fbr_pos_logs.create_index([("tenant_id", 1), ("timestamp", -1)])
        await db.fbr_pos_logs.create_index([("fbr_invoice_id", 1)])

        # 3. SIEM Security Audit Trail (90 Day Retention)
        await db.security_alerts.create_index(
            "timestamp",
            expireAfterSeconds=7776000  # 90 days
        )

        # 4. PHASE 5 RAW DATA SELF-CLEANING (90-Day)
        await _ensure_ttl_index(
            db.logs,
            collection_name="logs",
            field_name="timestamp",
            ttl_seconds=RAW_RETENTION_SECONDS,
            index_name="logs_ttl_90d",
        )
        await _ensure_ttl_index(
            db.logs,
            collection_name="logs",
            field_name=RAW_RETENTION_ANCHOR_FIELD,
            ttl_seconds=RAW_RETENTION_SECONDS,
            index_name="logs_anchor_ttl_90d",
        )
        await _ensure_ttl_index(
            db.csv_uploads,
            collection_name="csv_uploads",
            field_name="timestamp",
            ttl_seconds=RAW_RETENTION_SECONDS,
            index_name="csv_uploads_ttl_90d",
        )
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
        
        # 🚀 PERFORMANCE HARDENING: Unified Tenant Exploration
        # Composite index for O(log n) dashboard log lookups at scale.
        await db.logs.create_index([("tenant_id", 1), ("timestamp", -1)])
        await db.logs.create_index([("source_ip", 1)])
        
        # High-cardinality search optimization
        await db.fbr_pos_logs.create_index([("data.store_id", 1), ("timestamp", -1)])
        await db.peca_forensic_logs.create_index([("forensic_seal", 1)])

        logger.info(" 7-Tier Database Layer Hardened: Capacity TTL active and audit-veto enforced.")
        
    except Exception as e:
        logger.error(f"Critical failure in compliance DB initialization: {e}")
