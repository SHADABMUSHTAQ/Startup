from fastapi import APIRouter, HTTPException, Depends, Security, Request
from fastapi.security.api_key import APIKeyHeader
from pydantic import BaseModel, Field, EmailStr
import uuid
import secrets
from datetime import datetime, timezone
import hashlib
import os
from passlib.context import CryptContext

from app.database import get_db
from app.utils.limiter import limiter
from app.utils.tenant_cache import normalize_pack_id

router = APIRouter()
# Strictly enforced environment-injected Super Admin Key (No hardcoded fallback)
ADMIN_SECRET_KEY = os.getenv("SUPER_ADMIN_API_KEY")
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
    if api_key != ADMIN_SECRET_KEY:
        raise HTTPException(status_code=403, detail="Forbidden: Invalid Admin Key")
    return api_key

class ProvisionRequest(BaseModel):
    company_name: str
    plan_type: str = Field(default="Customized")
    compliance_packs: list[str] = Field(default_factory=list)
    max_agents: int = Field(default=10, ge=1)
    admin_email: EmailStr
    admin_name: str
    admin_password: str

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
    # 0. Prevent duplicate provisioning
    existing_user = await db["users"].find_one({"email": req.admin_email})
    if existing_user:
        raise HTTPException(status_code=400, detail=f"User with email {req.admin_email} already exists.")

    tenant_id = f"WARSOC_{uuid.uuid4().hex[:8].upper()}"
    compliance_packs = sorted({normalize_pack_id(pack) for pack in req.compliance_packs if normalize_pack_id(pack)})
    features = sorted(set(compliance_packs) | {"SIEM"})
    
    # 1. Establish the Tenant Record
    tenant_doc = {
        "tenant_id": tenant_id,
        "company_name": req.company_name,
        "plan_type": req.plan_type,
        "compliance_packs": compliance_packs,
        "max_agents": req.max_agents,
        "agent_limit": req.max_agents,
        "features": features,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "active": True
    }
    await db["tenants"].insert_one(tenant_doc)
    
    # 2. Pre-Authorize the Tenant ID as a valid Agent Identity
    await db["agents"].insert_one({
        "agent_id": tenant_id,
        "tenant_id": tenant_id,
        "approved": True,
        "created_at": datetime.now(timezone.utc).isoformat()
    })

    # 3. The Genesis Block (Zero-Day Forensic Anchor)
    genesis_root = hashlib.sha256(f"GENESIS:{tenant_id}".encode("utf-8")).hexdigest()
    
    genesis_block = {
        "tenant_id": tenant_id,
        "date": "GENESIS",
        "daily_root_hash": genesis_root,
        "previous_root_hash": "NONE",
        "log_count": 0,
        "source_collections": ["peca_forensic_logs", "fbr_pos_logs"],
        "computed_at": datetime.now(timezone.utc).isoformat(),
        "worker_id": "admin_provisioning",
    }
    await db["daily_forensic_ledgers"].insert_one(genesis_block)

    # 4. Create the Admin User Account (THE MISSING PIECE)
    hashed_password = pwd_context.hash(req.admin_password)
    admin_username = req.admin_email.split("@")[0]

    admin_user = {
        "username": admin_username,
        "email": req.admin_email,
        "full_name": req.admin_name,
        "hashed_password": hashed_password,
        "tenant_id": tenant_id,
        "plan_type": req.plan_type,
        "role": "admin",
        "compliance_packs": compliance_packs,
        "max_agents": req.max_agents,
        "has_active_plan": True,
        "created_at": datetime.now(timezone.utc)
    }
    await db["users"].insert_one(admin_user)

    # 5. Sync plan to Redis cache for instant worker entitlement checks
    redis = getattr(request.app.state, "redis", None)
    if redis:
        await redis.set(f"tenant_plan:{tenant_id}", req.plan_type)
        await redis.set(f"tenant_features:{tenant_id}", ",".join(features))
        await redis.set(f"tenant_agent_limit:{tenant_id}", str(req.max_agents))
    
    return ProvisionResponse(
        tenant_id=tenant_id,
        company_name=req.company_name,
        plan_type=req.plan_type,
        admin_email=req.admin_email,
        message=f"Tenant provisioned. Admin account created for {req.admin_email}. Client can now log in at the dashboard."
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
