import json
import logging
from redis.asyncio import Redis

logger = logging.getLogger(__name__)

# 💳 WarSOC Tenant Plan Cache (Enterprise S.R.O. 288/I/2026 Optimization)
# Moving plan verification to Redis ensures workers can process thousands of events/sec
# without creating a MongoDB bottleneck for hospitality/healthcare sectors.

TENANT_CACHE_PREFIX = "tenant_plan:"

async def get_tenant_plan(redis: Redis, tenant_id: str) -> str:
    """
    Retrieves the subscription plan for a tenant from Redis cache.
    Defaults to 'FREE' if not found.
    """
    try:
        plan = await redis.get(f"{TENANT_CACHE_PREFIX}{tenant_id}")
        return plan if plan else "FREE"
    except Exception as e:
        logger.error(f"Error fetching tenant plan from cache: {e}")
        return "FREE"

async def sync_tenant_cache(db, redis: Redis):
    """
    Synchronizes all tenant mappings from MongoDB to Redis.
    Should be called during API startup lifespan and periodically for updates.
    """
    try:
        logger.info("🔄 Syncing Tenant Plan Cache to Redis...")
        # Use simple find() to get all tenants
        cursor = db.tenants.find({})
        count = 0
        async for tenant in cursor:
            tenant_id = tenant.get("tenant_id")
            plan = tenant.get("plan", "FREE")
            if tenant_id:
                await redis.set(f"{TENANT_CACHE_PREFIX}{tenant_id}", plan)
                count += 1
        logger.info(f"✅ Tenant Plan Cache Synchronized ({count} tenants cached).")
    except Exception as e:
        logger.error(f"Critical failure during tenant cache sync: {e}")
