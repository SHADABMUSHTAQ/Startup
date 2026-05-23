import json
import logging
from redis.asyncio import Redis

logger = logging.getLogger(__name__)

# 💳 WarSOC Tenant Plan Cache (Enterprise S.R.O. 288/I/2026 Optimization)
# Moving plan verification to Redis ensures workers can process thousands of events/sec
# without creating a MongoDB bottleneck for hospitality/healthcare sectors.

TENANT_CACHE_PREFIX = "tenant_plan:"


def normalize_tenant_plan(plan: str) -> str:
    """
    Normalizes plan aliases to canonical values used by workers.
    """
    if not plan:
        return "FREE"

    raw = str(plan).strip()
    key = raw.lower()

    aliases = {
        "free": "FREE",
        "trial": "FREE",
        "basic": "BASIC",
        "starter": "BASIC",
        "pro": "Professional",
        "professional": "Professional",
        "ent": "Enterprise",
        "enterprise": "Enterprise",
        "fbr_plan": "FBR_PLAN",
        "full_suite": "FULL_SUITE",
        "fullsuite": "FULL_SUITE",
    }
    return aliases.get(key, raw)

async def get_tenant_plan(redis: Redis, tenant_id: str) -> str:
    """
    Retrieves the subscription plan for a tenant from Redis cache.
    Defaults to 'FREE' if not found.
    """
    try:
        plan = await redis.get(f"{TENANT_CACHE_PREFIX}{tenant_id}")
        return normalize_tenant_plan(plan) if plan else "FREE"
    except Exception as e:
        logger.error(f"Error fetching tenant plan from cache: {e}")
        return "FREE"

async def sync_tenant_cache(db, redis: Redis):
    """
    Synchronizes all tenant plan mappings from MongoDB to Redis.
    Should be called during API startup lifespan and periodically for updates.
    
    ROOT FIX: Reads from the 'users' collection (source of truth for plan_type)
    instead of the stale 'tenants' collection which lacked the plan field entirely.
    Deduplicates by tenant_id so the highest plan wins if multiple users share a tenant.
    """
    try:
        logger.info("🔄 Syncing Tenant Plan Cache to Redis...")
        
        # Priority order for plan resolution
        PLAN_PRIORITY = {"FREE": 0, "BASIC": 1, "Professional": 2, "FBR_PLAN": 3, "Enterprise": 4, "FULL_SUITE": 5}
        
        tenant_plans = {}
        
        # 1. Primary source: users collection (has plan_type field)
        cursor = db.users.find({"tenant_id": {"$exists": True, "$ne": None}}, {"tenant_id": 1, "plan_type": 1})
        async for user in cursor:
            tenant_id = user.get("tenant_id")
            plan = normalize_tenant_plan(user.get("plan_type", "FREE"))
            if tenant_id:
                existing = tenant_plans.get(tenant_id, "FREE")
                # Keep the highest-priority plan if multiple users share a tenant
                if PLAN_PRIORITY.get(plan, 0) > PLAN_PRIORITY.get(existing, 0):
                    tenant_plans[tenant_id] = plan
        
        # 2. Fallback: tenants collection (for any tenants not in users)
        cursor = db.tenants.find({})
        async for tenant in cursor:
            tenant_id = tenant.get("tenant_id")
            if tenant_id and tenant_id not in tenant_plans:
                plan = normalize_tenant_plan(tenant.get("plan") or tenant.get("plan_type", "FREE"))
                tenant_plans[tenant_id] = plan
        
        # 3. Push all resolved plans to Redis
        count = 0
        for tenant_id, plan in tenant_plans.items():
            await redis.set(f"{TENANT_CACHE_PREFIX}{tenant_id}", plan)
            count += 1
        
        logger.info(f"✅ Tenant Plan Cache Synchronized ({count} tenants cached).")
    except Exception as e:
        logger.error(f"Critical failure during tenant cache sync: {e}")
