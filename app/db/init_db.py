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


async def _legacy_backfill_fbr_tax_retention_state(collection):
    """Retained for offline legacy analysis; never run during initialization."""

    await collection.update_many(
        {"retention_state": {"$exists": False}},
        {
            "$set": {
                "retention_state": "UNRESOLVED",
                "retention_basis": "TAX_PERIOD_PENDING",
                "tax_period_id": None,
                "tax_period_start": None,
                "tax_period_end": None,
                "base_retention_until": None,
                "effective_retention_until": None,
                "automatic_archive_expiry_allowed": False,
                "retention_calculation_version": "fbr-tax-period-v1",
            },
            "$unset": {"_expire_at": ""},
        },
    )
    await collection.update_many(
        {"retention_state": "UNRESOLVED", "_expire_at": {"$exists": True}},
        {"$unset": {"_expire_at": ""}},
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
                except OperationFailure as err:
                    if err.code != 27 and "IndexNotFound" not in str(err):
                        raise
            await collection.create_index(keys, **kwargs)
            logger.info(f"Successfully recreated index for {keys}")
        else:
            raise e

async def init_compliance_db(db):
    try:
        logger.info("Initializing PTA/ETO 2002 Sections 5 & 6 Compliance Layer...")

        # Browser login has no tenant selector, so email and username must be
        # globally unambiguous. The case-insensitive collation also closes
        # races between app-level duplicate checks.
        identity_collation = {"locale": "en", "strength": 2}
        await _aggressive_create_index(
            db.users,
            [("email", 1)],
            name="uq_users_email_ci",
            unique=True,
            partialFilterExpression={"email": {"$type": "string"}},
            collation=identity_collation,
        )
        await _aggressive_create_index(
            db.users,
            [("username", 1)],
            name="uq_users_username_ci",
            unique=True,
            partialFilterExpression={"username": {"$type": "string"}},
            collation=identity_collation,
        )
        
        # Archive-managed collections keep retention metadata, but only the
        # verified Azure archiver may delete their hot records.
        await _drop_ttl_indexes(db.peca_forensic_logs, "peca_forensic_logs")
        # Do not backfill or rewrite historical PECA retention. New records
        # receive an explicit tenant-entitlement marker during ingestion.
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
        await _aggressive_create_index(
            db.peca_forensic_logs,
            [("tenant_id", 1), ("retention_model", 1), ("timestamp", 1)],
            name="idx_peca_tenant_retention_archive",
        )
        #  LEGAL PHYSICS: Hard engine-level block on cross-tenant overwrites
        await _aggressive_create_index(db.peca_forensic_logs, [("tenant_id", 1), ("event_uid", 1)], unique=True, name="idx_peca_tenant_event_uid")

        # 2. FBR POS evidence: seven-day hot window, then tenant retention.
        # Historical tax-period records are not rewritten by initialization.
        await _drop_ttl_indexes(db.fbr_pos_logs, "fbr_pos_logs")
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
        await _aggressive_create_index(
            db.fbr_pos_logs,
            [("tenant_id", 1), ("retention_model", 1), ("timestamp", 1)],
            name="idx_fbr_tenant_retention_archive",
        )
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
        await _aggressive_create_index(
            db.security_alerts,
            [("tenant_id", 1), ("timestamp", -1)],
            name="idx_security_alerts_tenant_timestamp",
        )
        await _aggressive_create_index(
            db.security_alerts,
            [("source", 1), ("watchdog_delivery.next_attempt_at", 1)],
            name="idx_security_alerts_watchdog_delivery",
            partialFilterExpression={"source": "network_relay_watchdog"},
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
        await _aggressive_create_index(
            db.siem_cold_vault,
            [("ingested_at", 1), ("_id", 1)],
            name="idx_siem_vault_detection_projector_scan",
        )

        # External detection is an optional post-persistence consumer. These
        # queues and ledgers are isolated from canonical SIEM/FBR/PECA writes.
        await _aggressive_create_index(
            db.detection_projector_state,
            [("projector_id", 1)],
            unique=True,
            name="uq_detection_projector_id",
        )
        await _aggressive_create_index(
            db.detection_rule_registry,
            [("engine", 1), ("ruleset_version", 1), ("rule_id", 1)],
            unique=True,
            name="uq_detection_rule_registry_version",
        )
        await _aggressive_create_index(
            db.detection_rule_registry,
            [
                ("engine", 1),
                ("status", 1),
                ("dispatch_enabled", 1),
                ("ruleset_version", 1),
                ("source_family", 1),
                ("event_ids", 1),
            ],
            name="idx_detection_rule_dispatch_lookup",
        )
        await _aggressive_create_index(
            db.detection_engine_connectors,
            [("connector_id", 1), ("engine_instance_id", 1)],
            unique=True,
            name="uq_detection_engine_connector",
        )
        await _aggressive_create_index(
            db.detection_engine_connectors,
            [("status", 1), ("ruleset_version", 1)],
            name="idx_detection_engine_connector_status",
        )
        await _aggressive_create_index(
            db.detection_engine_health_events,
            [("connector_id", 1), ("engine_instance_id", 1), ("event_uid", 1)],
            unique=True,
            name="uq_detection_engine_health_event",
        )
        await _aggressive_create_index(
            db.detection_engine_health_events,
            [("status", 1), ("last_received_at", -1)],
            name="idx_detection_engine_health_status",
        )
        await _aggressive_create_index(
            db.detection_engine_health_events,
            [("record_expires_at", 1)],
            expireAfterSeconds=0,
            name="ttl_detection_engine_health_events",
        )
        await _aggressive_create_index(
            db.detection_dispatch_outbox,
            [("dispatch_uid", 1)],
            unique=True,
            name="uq_detection_dispatch_uid",
        )
        await _aggressive_create_index(
            db.detection_dispatch_outbox,
            [("status", 1), ("next_attempt_at", 1), ("created_at", 1)],
            name="idx_detection_dispatch_queue",
        )
        await _aggressive_create_index(
            db.detection_dispatch_outbox,
            [("record_expires_at", 1)],
            expireAfterSeconds=0,
            name="ttl_detection_dispatch_outbox",
        )
        await _aggressive_create_index(
            db.detection_dispatch_dlq,
            [("dispatch_uid", 1)],
            unique=True,
            name="uq_detection_dispatch_dlq_uid",
        )
        await _aggressive_create_index(
            db.detection_dispatch_dlq,
            [("tenant_id", 1), ("failed_at", -1)],
            name="idx_detection_dispatch_dlq_tenant",
        )
        await _aggressive_create_index(
            db.detection_dispatch_dlq,
            [("record_expires_at", 1)],
            expireAfterSeconds=0,
            name="ttl_detection_dispatch_dlq",
        )
        await _aggressive_create_index(
            db.detection_coverage_gaps,
            [("gap_type", 1), ("tenant_id", 1), ("event_uid", 1), ("ruleset_version", 1)],
            unique=True,
            name="uq_detection_coverage_gap_event",
        )
        await _aggressive_create_index(
            db.detection_coverage_gaps,
            [("status", 1), ("last_seen_at", -1)],
            name="idx_detection_coverage_gap_status",
        )
        await _aggressive_create_index(
            db.detection_engine_observations,
            [
                ("engine_instance_id", 1),
                ("engine_alert_id", 1),
                ("ruleset_version", 1),
            ],
            unique=True,
            name="uq_detection_engine_delivery",
        )
        await _aggressive_create_index(
            db.detection_engine_observations,
            [("tenant_id", 1), ("candidate_fingerprint", 1)],
            unique=True,
            name="uq_detection_candidate_fingerprint",
        )
        await _aggressive_create_index(
            db.detection_engine_observations,
            [("tenant_id", 1), ("created_at", -1)],
            name="idx_detection_observation_tenant_created",
        )
        await _aggressive_create_index(
            db.detection_engine_observations,
            [("record_expires_at", 1)],
            expireAfterSeconds=0,
            name="ttl_detection_engine_observations",
        )
        await _aggressive_create_index(
            db.detection_candidates_quarantine,
            [
                ("connector_id", 1),
                ("engine_instance_id", 1),
                ("engine_alert_id", 1),
                ("ruleset_version", 1),
            ],
            unique=True,
            name="uq_detection_candidate_quarantine_delivery",
        )
        await _aggressive_create_index(
            db.detection_candidates_quarantine,
            [("connector_id", 1), ("received_at", -1)],
            name="idx_detection_candidate_quarantine_connector",
        )
        await _aggressive_create_index(
            db.detection_candidates_quarantine,
            [("record_expires_at", 1)],
            expireAfterSeconds=0,
            name="ttl_detection_candidate_quarantine",
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
        await _aggressive_create_index(
            db.csv_uploads,
            [("tenant_id", 1), (RAW_RETENTION_ANCHOR_FIELD, -1)],
            name="idx_csv_uploads_tenant_retention",
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

        # 6.1 NETWORK RELAY ENTITLEMENT: seed relay contract cap so pre-existing
        # tenants remain unable to activate relays until an operator explicitly
        # sets max_network_relays on their tenant document. Zero is fail-closed.
        await db.tenants.update_many(
            {"max_network_relays": {"$exists": False}},
            {"$set": {"max_network_relays": 0}},
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
            db.archive_retrieval_requests,
            [("request_id", 1)],
            unique=True,
            name="uq_archive_retrieval_request_id",
        )
        await _aggressive_create_index(
            db.archive_retrieval_requests,
            [("tenant_id", 1), ("created_at", -1)],
            name="idx_archive_retrieval_tenant_created",
        )
        await _aggressive_create_index(
            db.archive_retrieval_requests,
            [("status", 1), ("created_at", 1)],
            name="idx_archive_retrieval_worker_queue",
        )
        await _aggressive_create_index(
            db.archive_retrieval_requests,
            [("tenant_id", 1), ("billing_month", 1), ("status", 1)],
            name="idx_archive_retrieval_monthly_allowance",
        )
        await _aggressive_create_index(
            db.archive_retrieval_usage,
            [("tenant_id", 1), ("billing_month", 1)],
            unique=True,
            name="uq_archive_retrieval_usage_month",
        )
        await _aggressive_create_index(
            db.archive_retrieval_allowances,
            [("tenant_id", 1), ("billing_month", 1)],
            unique=True,
            name="uq_archive_retrieval_allowance_month",
        )
        await _aggressive_create_index(
            db.archive_storage_daily,
            [("tenant_id", 1), ("day", 1), ("retention_class", 1)],
            unique=True,
            name="uq_archive_storage_daily",
        )

        # Authenticated source bytes are committed before Redis fan-out. Domain
        # collections remain separate even where the commercial retention model
        # is shared.
        for source_collection_name in (
            "source_envelopes_siem",
            "source_envelopes_peca",
            "source_envelopes_fbr",
        ):
            source_collection = db[source_collection_name]
            await _drop_ttl_indexes(source_collection, source_collection_name)
            await _aggressive_create_index(
                source_collection,
                [
                    ("tenant_id", 1),
                    ("source_principal_type", 1),
                    ("source_principal_id", 1),
                    ("source_channel", 1),
                    ("source_envelope_uid", 1),
                ],
                unique=True,
                name="uq_source_envelope_identity",
            )
            await _aggressive_create_index(
                source_collection,
                [("tenant_id", 1), ("dispatch_complete", 1), ("timestamp", 1)],
                name="idx_source_envelope_archive",
            )
            if source_collection_name == "source_envelopes_fbr":
                await _aggressive_create_index(
                    source_collection,
                    [
                        ("tenant_id", 1),
                        ("retention_model", 1),
                        ("dispatch_complete", 1),
                        ("timestamp", 1),
                    ],
                    name="idx_fbr_source_tenant_retention_archive",
                )
            elif source_collection_name == "source_envelopes_peca":
                await _aggressive_create_index(
                    source_collection,
                    [
                        ("tenant_id", 1),
                        ("retention_model", 1),
                        ("dispatch_complete", 1),
                        ("timestamp", 1),
                    ],
                    name="idx_peca_source_tenant_retention_archive",
                )

        await _aggressive_create_index(
            db.source_evidence_outbox,
            [("outbox_uid", 1)],
            unique=True,
            name="uq_source_outbox_uid",
        )
        await _aggressive_create_index(
            db.source_evidence_outbox,
            [("ready", 1), ("status", 1), ("next_attempt_at", 1), ("created_at", 1)],
            name="idx_source_outbox_dispatch",
        )
        await _aggressive_create_index(
            db.source_evidence_outbox,
            [("delete_after", 1)],
            expireAfterSeconds=0,
            name="ttl_source_outbox_published",
        )
        await _drop_ttl_indexes(
            db.agent_coverage_observations,
            "agent_coverage_observations",
        )
        await _aggressive_create_index(
            db.agent_coverage_observations,
            [("tenant_id", 1), ("agent_id", 1), ("server_received_time", -1)],
            name="idx_agent_coverage_tenant_agent_time",
        )
        await _aggressive_create_index(
            db.agent_coverage_observations,
            [("tenant_id", 1), ("agent_id", 1), ("protocol_version", 1), ("nonce", 1)],
            unique=True,
            partialFilterExpression={"nonce": {"$type": "string"}},
            name="uq_agent_coverage_v2_nonce",
        )
        await _aggressive_create_index(
            db.legal_holds,
            [("hold_id", 1)],
            unique=True,
            name="uq_legal_hold_id",
        )
        await _aggressive_create_index(
            db.legal_holds,
            [("tenant_id", 1), ("status", 1), ("scope_type", 1), ("created_at", -1)],
            name="idx_legal_holds_tenant_status_scope",
        )
        await _aggressive_create_index(
            db.legal_holds,
            [("tenant_id", 1), ("collection", 1), ("event_uid", 1), ("status", 1)],
            name="idx_legal_holds_event_scope",
        )
        await _aggressive_create_index(
            db.evidence_hold_audit,
            [("operation_id", 1)],
            unique=True,
            name="uq_evidence_hold_operation",
        )
        await _aggressive_create_index(
            db.evidence_hold_audit,
            [("tenant_id", 1), ("hold_id", 1), ("created_at", 1)],
            name="idx_evidence_hold_audit_lifecycle",
        )
        await _aggressive_create_index(
            db.evidence_retention_fences,
            [("lock_id", 1)],
            unique=True,
            name="uq_evidence_retention_fence",
        )
        await _aggressive_create_index(
            db.evidence_retention_fences,
            [("expires_at", 1)],
            expireAfterSeconds=0,
            name="ttl_evidence_retention_fence",
        )
        await _aggressive_create_index(
            db.evidence_cases,
            [("case_id", 1)],
            unique=True,
            name="uq_evidence_case_id",
        )
        await _aggressive_create_index(
            db.evidence_cases,
            [("tenant_id", 1), ("status", 1), ("created_at", -1)],
            name="idx_evidence_cases_tenant_status",
        )
        await _aggressive_create_index(
            db.evidence_case_items,
            [("case_item_id", 1)],
            unique=True,
            name="uq_evidence_case_item_id",
        )
        await _aggressive_create_index(
            db.evidence_case_items,
            [("tenant_id", 1), ("case_id", 1), ("collection", 1), ("document_id", 1)],
            unique=True,
            partialFilterExpression={"state": {"$in": ["PENDING", "COMMITTED"]}},
            name="uq_evidence_case_source_reference",
        )
        await _aggressive_create_index(
            db.evidence_custody_events,
            [("custody_event_id", 1)],
            unique=True,
            name="uq_evidence_custody_event_id",
        )
        await _aggressive_create_index(
            db.evidence_custody_events,
            [("tenant_id", 1), ("case_id", 1), ("sequence", 1)],
            unique=True,
            partialFilterExpression={"state": "COMMITTED"},
            name="uq_evidence_custody_sequence",
        )
        await _aggressive_create_index(
            db.daily_forensic_ledgers,
            [("tenant_id", 1), ("date", 1)],
            unique=True,
            name="uq_daily_forensic_ledger_tenant_date",
        )
        await _aggressive_create_index(
            db.daily_forensic_ledgers,
            [("anchor_status", 1), ("date", 1)],
            name="idx_daily_forensic_anchor_retry",
        )
        await _aggressive_create_index(
            db.evidence_exports,
            [("export_id", 1)],
            unique=True,
            name="uq_evidence_export_id",
        )
        await _aggressive_create_index(
            db.evidence_exports,
            [("tenant_id", 1), ("case_id", 1), ("created_at", -1)],
            name="idx_evidence_exports_tenant_case",
        )
        await _aggressive_create_index(
            db.evidence_exports,
            [("status", 1), ("created_at", 1)],
            name="idx_evidence_exports_worker_queue",
        )
        await _aggressive_create_index(
            db.fbr_reconciliation_results,
            [("tenant_id", 1), ("invoice_id", 1), ("evaluated_at", -1)],
            name="idx_fbr_reconciliation_tenant_invoice",
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
            db.network_relay_device_status,
            [("tenant_id", 1), ("relay_id", 1), ("device_id", 1)],
            unique=True,
            name="uq_network_relay_device_status",
        )
        await _aggressive_create_index(
            db.network_relay_device_status,
            [("tenant_id", 1), ("last_event_at", -1)],
            name="idx_network_relay_device_last_event",
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
        
    except Exception:
        logger.exception("Critical failure in compliance DB initialization")
        raise
