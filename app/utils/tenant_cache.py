import json
import logging
from redis.asyncio import Redis

logger = logging.getLogger(__name__)

TENANT_CACHE_PREFIX = "tenant_plan:"

# Canonical pack name aliases
_PACK_ALIASES = {
    "peca": "peca_forensic",
    "peca_vault": "peca_forensic",
    "peca_plan": "peca_forensic",
    "eto": "peca_forensic",
    "eto_forensic": "peca_forensic",
    "fbr": "fbr_pos",
    "fbr_pos_shield": "fbr_pos",
    "fbr_plan": "fbr_pos",
}


TENANT_RETENTION_PREFIX = "tenant_retention:"


def normalize_pack_id(pack: str) -> str:
    """Normalize a compliance pack name to its canonical form."""
    return _PACK_ALIASES.get(str(pack).strip().lower(), str(pack).strip().lower())


async def get_tenant_plan(redis: Redis, tenant_id: str) -> str:
    """
    Retrieves the plan name for a tenant from Redis.
    Returns 'FREE' if not found (no active plan).
    Example return: 'Enterprise'
    """
    try:
        val = await redis.get(f"{TENANT_CACHE_PREFIX}{tenant_id}")
        return val if val else "FREE"
    except Exception as e:
        logger.error(f"Error fetching tenant plan from cache: {e}")
        return "FREE"

async def get_tenant_features(redis: Redis, tenant_id: str) -> str:
    """
    Retrieves the feature-flag string for a tenant from Redis.
    Returns 'SIEM' if not found (default).
    Example return: 'SIEM,fbr_pos,peca_forensic'
    """
    try:
        val = await redis.get(f"tenant_features:{tenant_id}")
        return val if val else "SIEM"
    except Exception as e:
        logger.error(f"Error fetching tenant features from cache: {e}")
        return "SIEM"


async def get_tenant_retention(redis: Redis, tenant_id: str) -> int:
    """
    Retrieves the retention days for a tenant from Redis.
    Returns 90 (default) if not found.
    """
    try:
        val = await redis.get(f"{TENANT_RETENTION_PREFIX}{tenant_id}")
        return int(val) if val else 90
    except Exception as e:
        logger.error(f"Error fetching tenant retention from cache: {e}")
        return 90


async def sync_tenant_cache(db, redis: Redis):
    """
    Synchronizes all tenant feature-flags and retention days from MongoDB to Redis.
    """
    try:
        logger.info(" Syncing Tenant Feature-Flag & Retention Cache to Redis...")
        tenant_features: dict[str, set[str]] = {}
        tenant_retention: dict[str, int] = {}
        tenant_plans: dict[str, str] = {}

        # 1. Primary source: users collection
        cursor = db.users.find(
            {"tenant_id": {"$exists": True, "$ne": None}},
            {"tenant_id": 1, "compliance_packs": 1, "has_active_plan": 1, "plan_type": 1}
        )
        async for user in cursor:
            tenant_id = user.get("tenant_id")
            if not tenant_id:
                continue
            if tenant_id not in tenant_features:
                tenant_features[tenant_id] = set()
            # Collect and normalize all compliance packs
            for pack in (user.get("compliance_packs") or []):
                canonical = normalize_pack_id(pack)
                if canonical:
                    tenant_features[tenant_id].add(canonical)
            if "plan_type" in user:
                tenant_plans[tenant_id] = user.get("plan_type")

        # 2. Fallback: tenants collection (for tenants not in users)
        cursor = db.tenants.find({})
        async for tenant in cursor:
            tenant_id = tenant.get("tenant_id")
            if tenant_id:
                if tenant_id not in tenant_features:
                    tenant_features[tenant_id] = set()
                    for pack in (tenant.get("compliance_packs") or []):
                        canonical = normalize_pack_id(pack)
                        if canonical:
                            tenant_features[tenant_id].add(canonical)
                if "retention_days" in tenant:
                    tenant_retention[tenant_id] = tenant.get("retention_days", 90)
                if "plan" in tenant and tenant_id not in tenant_plans:
                    tenant_plans[tenant_id] = tenant.get("plan")

        # 3. Build and push to Redis
        count = 0
        for tenant_id, packs in tenant_features.items():
            packs.add("SIEM")
            feature_string = ",".join(sorted(packs))
            plan_name = tenant_plans.get(tenant_id) or "Free"

            await redis.set(f"{TENANT_CACHE_PREFIX}{tenant_id}", plan_name)
            await redis.set(f"tenant_features:{tenant_id}", feature_string)

            retention = tenant_retention.get(tenant_id, 90)
            await redis.set(f"{TENANT_RETENTION_PREFIX}{tenant_id}", str(retention))
            count += 1

        logger.info(f" Tenant Cache Synchronized ({count} tenants cached).")
    except Exception as e:
        logger.error(f"Critical failure during tenant cache sync: {e}")
