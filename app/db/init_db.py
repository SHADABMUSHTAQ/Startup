import logging
from motor.motor_asyncio import AsyncIOMotorClient
from app.config.config import get_settings

logger = logging.getLogger(__name__)
settings = get_settings()

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
        # ✅ MASTER BUILD REMEDIATION: Remove unique=True to allow scaling of repeated events (e.g. Logon 4624)
        await db.peca_forensic_logs.create_index([("event_id", 1)], unique=False)
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
        
        # 🛡️ 4. NEW: Internal Management Audit (365 Day Retention)
        # Tracks who accessed the dashboard and modified plans.
        await db.management_audit.create_index(
            "timestamp",
            expireAfterSeconds=31536000  # 365 days
        )
        await db.management_audit.create_index([("operator", 1), ("timestamp", -1)])
        
        # 🚀 PERFORMANCE HARDENING: Unified Tenant Exploration
        # Composite index for O(log n) dashboard log lookups at scale.
        await db.logs.create_index([("tenant_id", 1), ("timestamp", -1)])
        await db.logs.create_index([("source_ip", 1)])
        
        # High-cardinality search optimization
        await db.fbr_pos_logs.create_index([("data.store_id", 1), ("timestamp", -1)])
        await db.peca_forensic_logs.create_index([("forensic_seal", 1)])

        logger.info("✅ 7-Tier Database Layer Hardened: Tenant Indexes and Management Audit Active.")
        
    except Exception as e:
        logger.error(f"Critical failure in compliance DB initialization: {e}")
