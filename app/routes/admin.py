from fastapi import APIRouter, HTTPException, Depends, Security
from fastapi.security.api_key import APIKeyHeader
from pydantic import BaseModel, Field
import uuid
import secrets
from datetime import datetime, timezone
import hashlib
import os

from app.database import get_db

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

def verify_admin(api_key: str = Security(api_key_header)):
    if not ADMIN_SECRET_KEY:
        raise HTTPException(status_code=503, detail="Super Admin Key is not configured on the server.")
    if api_key != ADMIN_SECRET_KEY:
        raise HTTPException(status_code=403, detail="Forbidden: Invalid Admin Key")
    return api_key

class ProvisionRequest(BaseModel):
    company_name: str
    plan_type: str = Field(default="Professional")

class ProvisionResponse(BaseModel):
    tenant_id: str
    company_name: str
    plan_type: str
    message: str

@router.post("/provision", response_model=ProvisionResponse)
async def provision_tenant(req: ProvisionRequest, db=Depends(get_db), _: str = Depends(verify_admin)):
    """
    Onboards a new tenant into the WarSOC infrastructure.
    """
    tenant_id = f"WARSOC_{uuid.uuid4().hex[:8].upper()}"
    
    # 1. Establish the Tenant Record
    tenant_doc = {
        "tenant_id": tenant_id,
        "company_name": req.company_name,
        "plan_type": req.plan_type,
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
    
    return ProvisionResponse(
        tenant_id=tenant_id,
        company_name=req.company_name,
        plan_type=req.plan_type,
        message="Tenant Provisioned Successfully. Genesis Block established. Agents must enroll via Provisioning Tokens."
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
