import asyncio
import hashlib
import json
import logging
import os
import socket
from datetime import datetime, timezone, timedelta
from pathlib import Path
from motor.motor_asyncio import AsyncIOMotorClient
from app.config.config import get_settings
from app.utils.report_engine import ComplianceReportGenerator
from app.utils.compliance_chain import (
    CHAIN_VERSION,
    HASH_ALGORITHM,
    compute_daily_root,
    evidence_record_digest,
    genesis_root,
    verify_ledger_entry,
)

# 🏗 COMPLIANCE CRON: Daily compliance maintenance worker
# Architecture: Standalone asyncio worker.  Does NOT share the FastAPI event loop.
# Runs once per day at 00:05 UTC (5-minute grace period for late-arriving logs).

logging.basicConfig(level=logging.INFO, format="%(asctime)s [COMPLIANCE-CRON] %(message)s")
logger = logging.getLogger("Compliance-Cron")

settings = get_settings()


def load_dead_air_threshold() -> int:
    """Load dead-air detection threshold from env or tenant policy, with a short simulation fallback."""
    env_value = os.getenv("DEAD_AIR_THRESHOLD")
    if env_value:
        try:
            value = int(env_value)
            return value if value > 0 else 10
        except Exception:
            pass

    root_dir = Path(__file__).resolve().parents[2]
    for policy_path in [root_dir / "agent" / "tenant_policy.json", root_dir / "deploy" / "tenant_policy.json"]:
        if not policy_path.exists():
            continue
        try:
            with open(policy_path, "r", encoding="utf-8") as f:
                doc = json.load(f)
            heartbeat = int(doc.get("agent_settings", {}).get("heartbeat_interval_seconds", 5))
            return max(1, heartbeat * 2)
        except Exception:
            continue

    return 10

# The collection where we store the daily ledger entries
LEDGER_COLLECTION = "daily_forensic_ledgers"

# Source collections to chain
SOURCE_COLLECTIONS = ["peca_forensic_logs", "fbr_pos_logs"]
DEAD_AIR_THRESHOLD = load_dead_air_threshold()


async def _compute_daily_root(db, tenant_id: str, date_str: str, start_dt: datetime, end_dt: datetime, previous_root: str) -> dict:
    """Build a deterministic hash commitment over the day's evidence."""
    log_count = 0
    seen_event_ids = []
    source_counts = {}
    evidence_hasher = hashlib.sha256()

    for collection_name in SOURCE_COLLECTIONS:
        collection = db[collection_name]

        # Query: tenant + timestamp window, sorted by _id (insertion order)
        query = {
            "tenant_id": tenant_id,
            "$or": [
                # Handle BSON Date timestamps (primary, used by workers after normalization)
                {"_retention_ts": {"$gte": start_dt, "$lt": end_dt}},
                # Fallback: timestamp field (also normalized to BSON Date by workers)
                {"timestamp": {"$gte": start_dt, "$lt": end_dt}},
            ]
        }
        cursor = collection.find(query).sort("_id", 1)

        async for doc in cursor:
            log_count += 1
            source_counts[collection_name] = source_counts.get(collection_name, 0) + 1
            record_digest = evidence_record_digest(collection_name, doc)
            evidence_hasher.update(f"{collection_name}:{record_digest}\n".encode("ascii"))
            event_id = doc.get("event_id")
            if event_id is not None:
                seen_event_ids.append(str(event_id))

    evidence_digest = evidence_hasher.hexdigest()
    daily_root = compute_daily_root(
        tenant_id=tenant_id,
        date_str=date_str,
        previous_root_hash=previous_root,
        evidence_digest=evidence_digest,
        log_count=log_count,
        source_counts=source_counts,
    )

    ledger_entry = {
        "tenant_id": tenant_id,
        "date": date_str,
        "chain_version": CHAIN_VERSION,
        "hash_algorithm": HASH_ALGORITHM,
        "daily_root_hash": daily_root,
        "previous_root_hash": previous_root,
        "evidence_digest": evidence_digest,
        "log_count": log_count,
        "source_counts": source_counts,
        "event_id_sample": seen_event_ids[:25],
        "source_collections": SOURCE_COLLECTIONS,
        "computed_at": datetime.now(timezone.utc).isoformat(),
        "worker_id": f"cron_{socket.gethostname()}",
    }

    return ledger_entry


async def run_daily_chain(db):
    """Executes the daily maintenance run for all active tenants."""
    # Target: yesterday (full 24-hour window)
    now_utc = datetime.now(timezone.utc)
    yesterday = (now_utc - timedelta(days=1)).replace(hour=0, minute=0, second=0, microsecond=0)
    end_of_yesterday = yesterday + timedelta(days=1)
    date_str = yesterday.strftime("%Y-%m-%d")

    logger.info(f"=== Daily Integrity Chain: Processing {date_str} ===")

    # 1. Discover all active tenants from source collections
    all_tenants = set()
    for coll_name in SOURCE_COLLECTIONS:
        tenants = await db[coll_name].distinct("tenant_id")
        all_tenants.update(t for t in tenants if t)

    if not all_tenants:
        logger.warning("No active tenants found in source collections. Skipping.")
        return

    logger.info(f"Active tenants discovered: {len(all_tenants)}")

    ledger_coll = db[LEDGER_COLLECTION]

    for tenant_id in sorted(all_tenants):
        # Check if we already computed this day (idempotency guard)
        existing = await ledger_coll.find_one({"tenant_id": tenant_id, "date": date_str})
        if existing and verify_ledger_entry(existing):
            logger.info(f"[{tenant_id}] {date_str} already chained. Skipping.")
            continue

        # Fetch the previous day's root marker
        prev_date_str = (yesterday - timedelta(days=1)).strftime("%Y-%m-%d")
        prev_entry = await ledger_coll.find_one({"tenant_id": tenant_id, "date": prev_date_str})

        chain_reset_reason = None
        if prev_entry and verify_ledger_entry(prev_entry):
            previous_root = prev_entry["daily_root_hash"]
        else:
            previous_root = genesis_root(tenant_id)
            chain_reset_reason = "previous_ledger_missing_or_unverified"
            logger.info(f"[{tenant_id}] Starting a verified chain from the tenant genesis root.")

        # Compute the daily maintenance entry
        ledger_entry = await _compute_daily_root(
            db, tenant_id, date_str, yesterday, end_of_yesterday, previous_root
        )
        if chain_reset_reason:
            ledger_entry["chain_reset_reason"] = chain_reset_reason

        # Replace legacy/unverified entries for the same day without creating duplicates.
        await ledger_coll.replace_one(
            {"tenant_id": tenant_id, "date": date_str},
            ledger_entry,
            upsert=True,
        )
        logger.info(f"[{tenant_id}]  Recorded {date_str}: {ledger_entry['log_count']} logs.")

    logger.info(f"=== Daily Maintenance Complete for {date_str} ===")

async def run_monthly_reports(db):
    """
    Executes the monthly PDF generation for ALL active tenants.
    Targets the previous month.
    """
    now_utc = datetime.now(timezone.utc)
    if now_utc.day != 1:
        return
        
    logger.info("=== Monthly Rollup: Generating PDFs ===")
    
    # Calculate previous month
    if now_utc.month == 1:
        target_year = now_utc.year - 1
        target_month = 12
    else:
        target_year = now_utc.year
        target_month = now_utc.month - 1
        
    tenants = await db["tenants"].distinct("tenant_id")
    for tenant_id in tenants:
        if not tenant_id:
            continue
            
        generator = ComplianceReportGenerator(tenant_id, db)
        try:
            # Generate FBR Report
            fbr_path = await generator.generate_monthly_report(target_year, target_month, "fbr_pos")
            logger.info(f"[{tenant_id}] Generated FBR report: {fbr_path}")
            
            # Generate PECA Report
            peca_path = await generator.generate_monthly_report(target_year, target_month, "peca_forensic")
            logger.info(f"[{tenant_id}] Generated PECA report: {peca_path}")
        except Exception as e:
            logger.error(f"[{tenant_id}] Monthly report generation failed: {e}")
            
    logger.info("=== Monthly Rollup Complete ===")


async def check_heartbeats(app_redis, db):
    """
    Checks the Redis LAST_HEARTBEAT keys. If an agent has missed its heartbeat (key expired),
    it flags the tenant's agent status as offline in MongoDB.
    """
    try:
        tenants = await db["tenants"].find({"status": "active"}).to_list(length=1000)
        for tenant in tenants:
            tenant_id = tenant["tenant_id"]
            # Look for any heartbeat key for this tenant
            keys = await app_redis.keys(f"status:{tenant_id}:*")
            if not keys:
                # Agent is offline
                await db["agents"].update_many(
                    {"tenant_id": tenant_id},
                    {"$set": {"status": "offline", "last_dead_air": datetime.now(timezone.utc).isoformat()}}
                )
            else:
                # Agent is online
                await db["agents"].update_many(
                    {"tenant_id": tenant_id},
                    {"$set": {"status": "online"}}
                )
    except Exception as e:
        logger.error(f"[!] Heartbeat check failed: {e}")

async def compliance_cron():
    """
    Main loop: Executes tasks based on their required schedules.
    Uses pure asyncio — no external scheduling library required.
    """
    client = AsyncIOMotorClient(settings.mongodb_uri)
    db = client[settings.mongodb_db_name]
    
    # We need a dedicated Redis client for the worker
    import redis.asyncio as aioredis
    app_redis = await aioredis.from_url(settings.redis_url, decode_responses=True)

    logger.info("⚡ WarSOC Compliance Cron: Multi-Schedule Engine Active.")

    last_daily_run = None
    last_monthly_run = None
    last_heartbeat_run = None

    while True:
        now = datetime.now(timezone.utc)
        
        # 1. Heartbeat Check
        if last_heartbeat_run is None or (now - last_heartbeat_run).total_seconds() >= DEAD_AIR_THRESHOLD:
            logger.info(f"Running dead air heartbeat check (threshold: {DEAD_AIR_THRESHOLD}s)...")
            await check_heartbeats(app_redis, db)
            last_heartbeat_run = now

        # 2. Daily Hash Chain (At 00:05 UTC)
        if now.hour == 0 and now.minute >= 5 and (last_daily_run is None or last_daily_run.day != now.day):
            logger.info("Running daily integrity hash chain...")
            try:
                await run_daily_chain(db)
                last_daily_run = now
            except Exception as e:
                logger.error(f"[!] Daily chain computation failed: {e}")

        # 3. Monthly Rollup (On the 1st of the month at 01:00 UTC)
        if now.day == 1 and now.hour >= 1 and (last_monthly_run is None or last_monthly_run.month != now.month):
            logger.info("Running monthly compliance PDF rollup...")
            try:
                await run_monthly_reports(db)
                last_monthly_run = now
            except Exception as e:
                logger.error(f"[!] Monthly report generation failed: {e}")

        # Sleep a short duration to prevent CPU spin, evaluating schedules dynamically based on DEAD_AIR_THRESHOLD
        sleep_duration = min(60, max(5, DEAD_AIR_THRESHOLD // 2))
        await asyncio.sleep(sleep_duration)


if __name__ == "__main__":
    try:
        asyncio.run(compliance_cron())
    except KeyboardInterrupt:
        logger.info("[*] Compliance Cron shutting down gracefully.")
