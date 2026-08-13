from fastapi import APIRouter, HTTPException, Depends, Security, Request
from fastapi.security.api_key import APIKeyHeader
from pydantic import BaseModel, Field, EmailStr, field_validator
from bson import ObjectId
import asyncio
import logging
import uuid
import secrets
from datetime import datetime, timezone
import hashlib
import os
from passlib.context import CryptContext

from app.database import get_db
from app.utils.limiter import limiter
from app.utils.tenant_cache import normalize_pack_id
from app.utils.security_policy import PLATFORM_MAX_AGENTS, StrongPassword

router = APIRouter()
logger = logging.getLogger(__name__)
# Strictly enforced environment-injected Super Admin Key (No hardcoded fallback)
ADMIN_SECRET_KEY = os.getenv("SUPER_ADMIN_API_KEY")
MAX_DAILY_INGEST_QUOTA_BYTES = int(
    os.getenv("INGEST_DAILY_BYTES_MAX", str(3 * 1024 * 1024 * 1024))
)
MAX_DAILY_INGEST_QUOTA_GIB = max(1, MAX_DAILY_INGEST_QUOTA_BYTES // (1024 * 1024 * 1024))
api_key_header = APIKeyHeader(name="X-Admin-Key", auto_error=True)
SENSITIVE_TENANT_FIELDS = {
    "agent_master_secret",
    "new_agent_master_secret",
    "admin_key",
    "api_key",
    "password",
    "private_key",
    "secret",
}

pwd_context = CryptContext(schemes=["pbkdf2_sha256", "bcrypt"], deprecated="auto")

def verify_admin(api_key: str = Security(api_key_header)):
    if not ADMIN_SECRET_KEY:
        raise HTTPException(status_code=503, detail="Super Admin Key is not configured on the server.")
    if not secrets.compare_digest(api_key, ADMIN_SECRET_KEY):
        raise HTTPException(status_code=403, detail="Forbidden: Invalid Admin Key")
    return api_key


class ProvisionRequest(BaseModel):
    company_name: str
    plan_type: str = Field(default="Customized")
    compliance_packs: list[str] = Field(default_factory=list)
    max_agents: int = Field(default=10, ge=1, le=PLATFORM_MAX_AGENTS)
    admin_email: EmailStr
    admin_name: str
    admin_password: StrongPassword
    retention_days: int = Field(default=90, ge=1, le=2190)
    daily_ingest_quota_bytes: int | None = Field(default=None, ge=1)

    @field_validator("daily_ingest_quota_bytes")
    @classmethod
    def enforce_platform_quota_ceiling(cls, value: int | None) -> int | None:
        if value is not None and value > MAX_DAILY_INGEST_QUOTA_BYTES:
            raise ValueError(
                f"daily_ingest_quota_bytes exceeds the current platform cap of "
                f"{MAX_DAILY_INGEST_QUOTA_GIB} GiB/day"
            )
        return value

class ProvisionResponse(BaseModel):
    tenant_id: str
    company_name: str
    plan_type: str
    admin_email: str
    message: str

@router.post("/provision", response_model=ProvisionResponse)
@limiter.limit("5/minute")
async def provision_tenant(request: Request, req: ProvisionRequest, db=Depends(get_db), _: str = Depends(verify_admin)):
    """
    Full B2B Onboarding: Creates the tenant, genesis block, agent identity,
    AND the admin user account so the client can log into the dashboard.
    """
    admin_email = str(req.admin_email).strip().lower()

    # 0. Prevent duplicate provisioning
    try:
        existing_user = await db["users"].find_one({"email": admin_email})
    except Exception as exc:
        logger.exception("Tenant provisioning preflight failed for %s", admin_email)
        raise HTTPException(
            status_code=503,
            detail="Tenant provisioning is temporarily unavailable.",
        ) from exc
    if existing_user:
        raise HTTPException(status_code=400, detail=f"User with email {admin_email} already exists.")

    tenant_id = f"WARSOC_{uuid.uuid4().hex[:8].upper()}"
    compliance_packs = sorted({normalize_pack_id(pack) for pack in req.compliance_packs if normalize_pack_id(pack)})
    features = sorted(set(compliance_packs) | {"SIEM"})
    
    # 1. Establish the Tenant Record
    tenant_doc = {
        "_id": ObjectId(),
        "tenant_id": tenant_id,
        "company_name": req.company_name,
        "plan_type": req.plan_type,
        "compliance_packs": compliance_packs,
        "max_agents": req.max_agents,
        "agent_limit": req.max_agents,
        "retention_days": req.retention_days,
        "daily_ingest_quota_bytes": req.daily_ingest_quota_bytes,
        "features": features,
        "created_at": datetime.now(timezone.utc),
        "active": True,
        "status": "active",
        "has_active_plan": True,
    }
    # 2. The Genesis Block (Zero-Day Forensic Anchor)
    genesis_root = hashlib.sha256(f"GENESIS:{tenant_id}".encode("utf-8")).hexdigest()
    
    genesis_block = {
        "_id": ObjectId(),
        "tenant_id": tenant_id,
        "date": "GENESIS",
        "daily_root_hash": genesis_root,
        "previous_root_hash": "NONE",
        "log_count": 0,
        "source_collections": ["peca_forensic_logs", "fbr_pos_logs"],
        "computed_at": datetime.now(timezone.utc).isoformat(),
        "worker_id": "admin_provisioning",
    }
    # 3. Create the Admin User Account
    hashed_password = pwd_context.hash(req.admin_password)
    admin_username = admin_email.split("@")[0]

    admin_user = {
        "_id": ObjectId(),
        "username": admin_username,
        "email": admin_email,
        "full_name": req.admin_name,
        "company": req.company_name,
        "hashed_password": hashed_password,
        "tenant_id": tenant_id,
        "plan_type": req.plan_type,
        "role": "admin",
        "compliance_packs": compliance_packs,
        "max_agents": req.max_agents,
        "agent_limit": req.max_agents,
        "retention_days": req.retention_days,
        "daily_ingest_quota_bytes": req.daily_ingest_quota_bytes,
        "has_active_plan": True,
        "created_at": datetime.now(timezone.utc)
    }
    try:
        await db["tenants"].insert_one(tenant_doc)
        await db["daily_forensic_ledgers"].insert_one(genesis_block)
        await db["users"].insert_one(admin_user)
    except Exception as exc:
        logger.exception(
            "Tenant provisioning write failed; rolling back tenant=%s admin=%s",
            tenant_id,
            admin_email,
        )
        rollback_failures = []
        # Client-generated document IDs make ambiguous write cleanup exact:
        # an older tenant can never be removed by a rare tenant-ID collision.
        for collection, query in (
            ("users", {"_id": admin_user["_id"]}),
            ("daily_forensic_ledgers", {"_id": genesis_block["_id"]}),
            ("tenants", {"_id": tenant_doc["_id"]}),
        ):
            try:
                await db[collection].delete_many(query)
            except Exception as rollback_exc:
                rollback_failures.append(f"{collection}: {rollback_exc!r}")
        if rollback_failures:
            logger.critical(
                "Tenant provisioning rollback incomplete tenant=%s failures=%s",
                tenant_id,
                "; ".join(rollback_failures),
            )
        raise HTTPException(
            status_code=500,
            detail="Tenant provisioning failed; no account was created.",
        ) from exc

    # 4. Sync plan to Redis cache for instant worker entitlement checks
    redis = getattr(request.app.state, "redis", None)
    if redis:
        try:
            async def _sync_cache():
                pipe = redis.pipeline(transaction=False)
                pipe.set(f"tenant_plan:{tenant_id}", req.plan_type)
                pipe.set(f"tenant_features:{tenant_id}", ",".join(features))
                pipe.set(f"tenant_agent_limit:{tenant_id}", str(req.max_agents))
                pipe.set(f"tenant_retention:{tenant_id}", str(req.retention_days))
                pipe.set(f"tenant_active:{tenant_id}", "1", ex=60)
                if req.daily_ingest_quota_bytes:
                    pipe.set(f"tenant_ingest_quota_bytes:{tenant_id}", str(req.daily_ingest_quota_bytes))
                await pipe.execute()

            await asyncio.wait_for(_sync_cache(), timeout=3)
        except Exception as exc:
            logger.warning("Tenant %s provisioned but Redis entitlement cache sync failed: %s", tenant_id, exc)
     
    return ProvisionResponse(
        tenant_id=tenant_id,
        company_name=req.company_name,
        plan_type=req.plan_type,
        admin_email=admin_email,
        message=f"Tenant provisioned. Admin account created for {admin_email}. Client can now log in at the dashboard."
    )

@router.get("/tenants")
async def list_tenants(db=Depends(get_db), _: str = Depends(verify_admin)):
    """
    Returns all active tenants and their lifecycle state.
    """
    # Strip sensitive fields from the output just in case
    projection = {"_id": 0, **{field: 0 for field in SENSITIVE_TENANT_FIELDS}}
    cursor = db["tenants"].find({}, projection)
    tenants = await cursor.to_list(length=1000)
    return {"tenants": tenants}

@router.post("/rotate-key/{tenant_id}")
async def rotate_tenant_key(tenant_id: str, db=Depends(get_db), _: str = Depends(verify_admin)):
    """
    Legacy secret rotation (Deprecated). 
    Agents now authenticate using ECDSA Public Key Infrastructure.
    """
    tenant = await db["tenants"].find_one({"tenant_id": tenant_id})
    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant not found")
        
    return {
        "tenant_id": tenant_id, 
        "message": "Symmetric secrets are deprecated. Please issue a new Agent Provisioning Token."
    }
