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
        if e.code in {85, 86} or any(
            conflict_name in str(e)
            for conflict_name in ("IndexOptionsConflict", "IndexKeySpecsConflict")
        ):
            indexes = await collection.index_information()
            expected_key = keys if isinstance(keys, list) else [(keys, 1)]
            expected_unique = bool(kwargs.get("unique", False))
            expected_sparse = bool(kwargs.get("sparse", False))
            expected_partial = kwargs.get("partialFilterExpression")
            for idx_name, idx_info in indexes.items():
                if idx_info.get("key") != expected_key:
                    continue
                equivalent = (
                    bool(idx_info.get("unique", False)) == expected_unique
                    and bool(idx_info.get("sparse", False)) == expected_sparse
                    and idx_info.get("partialFilterExpression") == expected_partial
                    and idx_info.get("expireAfterSeconds") is None
                )
                if equivalent:
                    logger.info(
                        "Using equivalent existing index %s for %s",
                        idx_name,
                        expected_key,
                    )
                    return
                try:
                    await collection.drop_index(idx_name)
                    logger.warning(f"Dropped incompatible index: {idx_name}")
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
        await _aggressive_create_index(
            db.peca_forensic_logs,
            [("tenant_id", 1), ("timestamp", -1)],
            name="idx_peca_forensic_logs_tenant_id_1_timestamp_-1",
        )
        await _aggressive_create_index(
            db.peca_forensic_logs,
            [("tenant_id", 1), ("timestamp", -1), ("ingested_at", -1), ("_id", -1)],
            name="idx_peca_operator_page",
        )
        #  LEGAL PHYSICS: Hard engine-level block on cross-tenant overwrites
        await _aggressive_create_index(db.peca_forensic_logs, [("tenant_id", 1), ("event_uid", 1)], unique=True, name="idx_peca_tenant_event_uid")

        # 2. FBR POS Compliance: 6 Year vault-retention metadata.
        await _drop_ttl_indexes(db.fbr_pos_logs, "fbr_pos_logs")
        await _backfill_expire_at(db.fbr_pos_logs, retention_days=365 * 6)
        await _aggressive_create_index(
            db.fbr_pos_logs,
            [("tenant_id", 1), ("timestamp", -1)],
            name="idx_fbr_pos_logs_tenant_id_1_timestamp_-1",
        )
        await _aggressive_create_index(
            db.fbr_pos_logs,
            [("tenant_id", 1), ("timestamp", -1), ("ingested_at", -1), ("_id", -1)],
            name="idx_fbr_operator_page",
        )
        await _aggressive_create_index(db.fbr_pos_logs, [("fbr_invoice_id", 1)])
        #  LEGAL PHYSICS: Hard engine-level block on cross-tenant overwrites
        await _aggressive_create_index(db.fbr_pos_logs, [("tenant_id", 1), ("event_uid", 1)], unique=True, name="idx_fbr_tenant_event_uid")

        # 3. SIEM Security Audit Trail: seven-day hot feed, archive-before-delete.
        await _drop_ttl_indexes(db.security_alerts, "security_alerts")
        #  LEGAL PHYSICS: Hard engine-level block on cross-tenant overwrites for hot feed
        await _aggressive_create_index(
            db.security_alerts,
            [("tenant_id", 1), ("alert_uid", 1)],
            unique=True,
            partialFilterExpression={"alert_uid": {"$type": "string"}},
            name="idx_alerts_tenant_alert_uid",
        )
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

        # 3.1 Operational incidents: mutable workflow state is deliberately
        # separated from seven-day alert evidence. Occurrence rows provide
        # cross-worker idempotency and expire only after the hot evidence has
        # safely passed through the Azure archiver.
        await _aggressive_create_index(
            db.security_incidents,
            [("tenant_id", 1), ("incident_id", 1)],
            unique=True,
            name="uq_security_incident_tenant_id",
        )
        await _aggressive_create_index(
            db.security_incidents,
            [("tenant_id", 1), ("status", 1), ("last_seen", -1), ("_id", -1)],
            name="idx_security_incident_work_queue",
        )
        await _aggressive_create_index(
            db.security_incidents,
            [("tenant_id", 1), ("suppressed", 1), ("last_seen", -1)],
            name="idx_security_incident_operator_feed",
        )
        await _aggressive_create_index(
            db.security_incident_occurrences,
            [("tenant_id", 1), ("occurrence_uid", 1)],
            unique=True,
            name="uq_security_incident_occurrence",
        )
        await _aggressive_create_index(
            db.security_incident_occurrences,
            [("tenant_id", 1), ("incident_id", 1)],
            name="idx_security_incident_occurrence_parent",
        )
        await _aggressive_create_index(
            db.security_incident_occurrences,
            [("tenant_id", 1), ("event_uid", 1)],
            name="idx_security_incident_occurrence_event",
        )
        await _aggressive_create_index(
            db.security_incident_occurrences,
            [("expires_at", 1)],
            expireAfterSeconds=0,
            name="ttl_security_incident_occurrences",
        )
        await _aggressive_create_index(
            db.incident_audit_log,
            [("tenant_id", 1), ("incident_id", 1), ("timestamp", -1)],
            name="idx_incident_audit_tenant_incident",
        )
        await _aggressive_create_index(
            db.system_migrations,
            [("migration_id", 1)],
            unique=True,
            name="uq_system_migration_id",
        )

        # 3.5 SIEM Cold Vault: the archiver owns hot-data removal. A Mongo TTL
        # could delete evidence during an Azure outage before archival succeeds.
        await _drop_ttl_indexes(db.siem_cold_vault, "siem_cold_vault")
        await _backfill_expire_at(db.siem_cold_vault, retention_days=SIEM_HOT_RETENTION_DAYS)
        # SIEM writes are idempotent by tenant/event UID, and dashboard reads
        # are tenant-scoped and newest-first. Without these indexes every
        # upsert/search degrades to a collection scan as the vault grows.
        await _aggressive_create_index(
            db.siem_cold_vault,
            [("tenant_id", 1), ("event_uid", 1)],
            name="idx_siem_vault_tenant_event_uid",
            unique=False,
        )
        await _aggressive_create_index(
            db.siem_cold_vault,
            [("tenant_id", 1), ("timestamp", -1)],
            name="idx_siem_vault_tenant_timestamp",
        )

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
        await _aggressive_create_index(
            db.logs,
            [("tenant_id", 1), ("timestamp", -1)],
            name="idx_logs_tenant_id_1_timestamp_-1",
        )
        await _aggressive_create_index(db.logs, [("source_ip", 1)])
        
        # High-cardinality search optimization
        await _aggressive_create_index(db.fbr_pos_logs, [("data.store_id", 1), ("timestamp", -1)])
        await _aggressive_create_index(db.peca_forensic_logs, [("forensic_seal", 1)])
        await _aggressive_create_index(db.storage_archives, [("tenant_id", 1), ("collection", 1), ("created_at", -1)])
        await _aggressive_create_index(
            db.storage_archives,
            [("tenant_id", 1), ("collection", 1), ("status", 1), ("created_at", -1)],
            name="idx_archive_tenant_collection_status_created",
        )
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

        # Customer-side relays are independent principals. Batch receipts make
        # replay/sequence state recoverable after Redis loss without mixing
        # relay identities with endpoint-agent seat records.
        await _aggressive_create_index(
            db.network_relays,
            [("relay_id", 1)],
            unique=True,
            name="uq_network_relay_id",
        )
        await _aggressive_create_index(
            db.network_relays,
            [("tenant_id", 1), ("status", 1), ("last_seen", -1)],
            name="idx_network_relay_tenant_status_seen",
        )
        await _aggressive_create_index(
            db.network_relays,
            [("registration_nonce", 1)],
            unique=True,
            name="uq_network_relay_registration_nonce",
            partialFilterExpression={"registration_nonce": {"$type": "string"}},
        )
        await _aggressive_create_index(
            db.network_relays,
            [("activation_digest", 1)],
            name="idx_network_relay_activation_digest",
            partialFilterExpression={"activation_digest": {"$type": "string"}},
        )
        await _aggressive_create_index(
            db.network_relay_batches,
            [("relay_id", 1), ("chain_id", 1), ("key_epoch", 1), ("sequence", 1)],
            unique=True,
            name="uq_network_relay_batch_sequence",
        )
        await _aggressive_create_index(
            db.network_relay_batches,
            [("tenant_id", 1), ("cloud_receipt_time", -1)],
            name="idx_network_relay_batch_tenant_time",
        )
        await _aggressive_create_index(
            db.network_relay_chain_resets,
            [("tenant_id", 1), ("relay_id", 1), ("recovered_at", -1)],
            name="idx_network_relay_chain_resets",
        )
        await _aggressive_create_index(
            db.network_relay_chain_resets,
            [("relay_id", 1), ("new_key_epoch", 1)],
            unique=True,
            name="uq_network_relay_chain_reset_epoch",
        )

        from app.utils.security_incidents import backfill_hot_security_incidents

        backfill_limit = max(0, min(50000, int(os.getenv("INCIDENT_BACKFILL_LIMIT", "5000"))))
        backfill_result = await backfill_hot_security_incidents(db, limit=backfill_limit)
        logger.info(
            "Operational incident backfill complete: scanned=%s projected=%s",
            backfill_result["scanned"],
            backfill_result["projected"],
        )

        logger.info(" 7-Tier Database Layer Hardened: Capacity TTL active and audit-veto enforced.")
        
    except Exception as e:
        logger.error(f"Critical failure in compliance DB initialization: {e}")
