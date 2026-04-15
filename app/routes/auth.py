from fastapi import APIRouter, HTTPException, status, Depends, Request
from fastapi.responses import JSONResponse
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel, EmailStr
from app.database import get_db
from passlib.context import CryptContext
from datetime import datetime, timedelta, timezone
from typing import Optional
import jwt
import uuid
import hmac
from app.config.config import get_settings
from app.utils.limiter import limiter
from app.utils.rbac import RoleChecker

settings = get_settings()
router = APIRouter()

SECRET_KEY = settings.jwt_secret_key
AGENT_MASTER_SECRET = settings.agent_master_secret
ACCESS_TOKEN_EXPIRE_MINUTES = settings.access_token_expire_minutes
ALGORITHM = "HS256"

pwd_context = CryptContext(schemes=["pbkdf2_sha256", "bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login")

# --- MODELS ---
class UserCreate(BaseModel):
    username: str
    email: EmailStr
    password: str
    full_name: str
    plan_type: Optional[str] = "Free"
    role: Optional[str] = "admin"
    compliance_packs: Optional[list[str]] = []

class PlanUpdate(BaseModel):
    plan_name: str

class AgentLogin(BaseModel):
    agent_id: str
    agent_secret: str

class UpgradePlan(BaseModel):
    plan_type: str
    compliance_packs: list[str]
    endpoints: int
    storage_gb: int
    retention_months: int

# --- HELPER FUNCTIONS ---
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    try:
        if isinstance(password, str):
            pw_bytes = password.encode("utf-8")
            if len(pw_bytes) > 72:
                pw_bytes = pw_bytes[:72]
                password = pw_bytes.decode("utf-8", errors="ignore")
    except Exception:
        password = str(password)[:72]
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta if expires_delta else timedelta(minutes=15))
    jti = str(uuid.uuid4())
    to_encode.update({"exp": expire, "jti": jti})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


PLAN_ALIASES = {
    "free": "Free",
    "trial": "Free",
    "basic": "Basic",
    "starter": "Basic",
    "pro": "Professional",
    "professional": "Professional",
    "ent": "Enterprise",
    "enterprise": "Enterprise",
    "fbr_plan": "FBR_PLAN",
    "full_suite": "FULL_SUITE",
    "fullsuite": "FULL_SUITE",
}

DEFAULT_PACKS_BY_PLAN = {
    "Professional": ["peca_forensic"],
    "Enterprise": ["peca_forensic", "fbr_pos"],
}

DEFAULT_TENANT_RETENTION_DAYS = 90
PREMIUM_TENANT_RETENTION_DAYS = 365

# Phase 5 readiness: default remains 90, with plan aliases ready for premium retention.
RETENTION_DAYS_BY_PLAN = {
    "FULL_SUITE": PREMIUM_TENANT_RETENTION_DAYS,
}


def normalize_plan_type(plan: Optional[str]) -> str:
    if plan is None:
        return "Free"
    raw = str(plan).strip()
    if not raw:
        return "Free"
    return PLAN_ALIASES.get(raw.lower(), raw)


def default_packs_for_plan(plan: Optional[str]) -> list[str]:
    canonical_plan = normalize_plan_type(plan)
    return list(DEFAULT_PACKS_BY_PLAN.get(canonical_plan, []))


def resolve_compliance_packs(plan: Optional[str], packs: Optional[list[str]]) -> list[str]:
    provided = list(packs or [])
    if provided:
        return provided
    return default_packs_for_plan(plan)


def resolve_tenant_retention_days(
    plan: Optional[str],
    existing_retention_days: Optional[int] = None,
) -> int:
    if isinstance(existing_retention_days, int) and existing_retention_days > 0:
        return existing_retention_days

    canonical_plan = normalize_plan_type(plan)
    return int(RETENTION_DAYS_BY_PLAN.get(canonical_plan, DEFAULT_TENANT_RETENTION_DAYS))

# --- DEPENDENCIES ---
async def get_current_user(request: Request, token: str = Depends(oauth2_scheme), db=Depends(get_db)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        jti: str = payload.get("jti")
        username: str = payload.get("sub")
        
        # ✅ CTO FIX 1: Use Global Redis Pool for Lightning Fast Blacklist Checks
        redis = getattr(request.app.state, "redis", None)
        try:
            if redis:
                is_blacklisted = await redis.exists(f"warsoc:blacklist:{jti}")
                if is_blacklisted:
                    raise HTTPException(status_code=401, detail="Token has been revoked.")
        except Exception as e:
            # Redis may be unavailable; fail open for auth verification but log.
            print(f"⚠️ Redis blacklist check failed: {e}")

        if payload.get("type") == "agent":
            raise HTTPException(status_code=401, detail="Agent tokens cannot access user routes")
        if username is None:
            raise HTTPException(status_code=401, detail="Invalid token")
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Could not validate credentials")
    
    user = await db["users"].find_one({"username": username})
    if user is None:
        raise HTTPException(status_code=401, detail="User not found")
    
    # Attach token payload for revocation usage later
    user["current_jti"] = jti
    user["token_exp"] = payload.get("exp")
    return user

async def verify_agent_token(request: Request, token: str = Depends(oauth2_scheme), db=Depends(get_db)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        jti: str = payload.get("jti")
        agent_id: str = payload.get("sub")
        token_type: str = payload.get("type")

        # ✅ CTO FIX 1: Global Redis Pool
        redis = getattr(request.app.state, "redis", None)
        try:
            if redis and await redis.exists(f"warsoc:blacklist:{jti}"):
                raise HTTPException(status_code=401, detail="Agent token revoked.")
        except Exception as e:
            print(f"⚠️ Redis blacklist check failed: {e}")

        if agent_id is None or token_type != "agent":
            raise HTTPException(status_code=401, detail="Invalid agent token")

        # ✅ CTO FIX 2: Removed rogue DB connections. Rely strictly on `db` dependency.
        agent_doc = await db["agents"].find_one({"agent_id": agent_id})
        user = None

        if not agent_doc:
            user = await db["users"].find_one({"tenant_id": agent_id})

        if agent_doc:
            if not agent_doc.get("approved", True):
                raise HTTPException(status_code=403, detail="Agent not approved")
            mapped_tenant = agent_doc.get("tenant_id")
            if mapped_tenant and mapped_tenant != agent_id:
                raise HTTPException(status_code=403, detail="Agent tenant mismatch")
        else:
            if not user:
                raise HTTPException(status_code=401, detail="Unknown agent tenant")

        return agent_id
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Agent token expired.")
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Unauthorized Agent")
    except HTTPException:
        raise
    except Exception as e:
        print(f"🔴 Agent verification error: {e}")
        raise HTTPException(status_code=503, detail="Agent verification service unavailable")

from app.utils.audit import audit_log

@router.post("/signup", status_code=status.HTTP_201_CREATED)
@limiter.limit("5/minute")
@audit_log("User Signup")
async def signup(request: Request, user: UserCreate, db=Depends(get_db)):
    existing_user = await db["users"].find_one({"$or": [{"email": user.email}, {"username": user.username}]})
    if existing_user:
        raise HTTPException(status_code=400, detail="Username or Email already registered")

    hashed_password = get_password_hash(user.password)
    new_tenant_id = f"WARSOC_{str(uuid.uuid4())[:8].upper()}"
    canonical_plan = normalize_plan_type(user.plan_type)

    # ✅ MASTER BUILD: Auto-provision packs based on selected plan
    packs = resolve_compliance_packs(canonical_plan, user.compliance_packs)

    new_user = {
        "username": user.username,
        "email": user.email,
        "full_name": user.full_name,
        "hashed_password": hashed_password,
        "tenant_id": new_tenant_id,
        "plan_type": canonical_plan,
        "role": user.role or "admin",
        "compliance_packs": packs,
        "has_active_plan": True if canonical_plan != "Free" else False,
        "created_at": datetime.now(timezone.utc)
    }
    await db["users"].insert_one(new_user)

    new_tenant = {
        "tenant_id": new_tenant_id,
        "company_name": user.full_name,
        "plan": canonical_plan,
        "retention_days": resolve_tenant_retention_days(canonical_plan),
        "status": "active",
        "created_at": datetime.now(timezone.utc)
    }
    await db["tenants"].insert_one(new_tenant)

    # ✅ MASTER BUILD FIX: Immediate Cache Sync
    redis = request.app.state.redis
    if redis:
        await redis.set(f"tenant_plan:{new_tenant_id}", canonical_plan)

    return {"message": "User created successfully", "tenant_id": new_tenant_id, "plan": canonical_plan}

class LoginSchema(BaseModel):
    username: str
    password: str

@router.post("/login")
@limiter.limit("10/minute")
async def login(request: Request, user_data: LoginSchema, db=Depends(get_db)):
    db_user = await db["users"].find_one({"$or": [{"username": user_data.username}, {"email": user_data.username}]})
    if not db_user or not verify_password(user_data.password, db_user["hashed_password"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    tenant_id = db_user.get("tenant_id", "WARSOC_DEFAULT")
    access_token = create_access_token(
        data={"sub": db_user["username"], "type": "user", "tenant_id": tenant_id, "role": db_user.get("role", "admin")}, 
        expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    # 🔒 Unified Permission Logic (Self-Healing Contract)
    plan = normalize_plan_type(db_user.get("plan_type", "Free"))
    packs = resolve_compliance_packs(plan, db_user.get("compliance_packs", []))

    return {
        "access_token": access_token, 
        "token_type": "bearer",
        "username": db_user["username"],
        "tenant_id": tenant_id,
        "plan_type": plan,
        "has_active_plan": db_user.get("has_active_plan", False),
        "compliance_packs": packs
    }

# ✅ CTO FIX 3: Secure Logout Route for Token Revocation
@router.post("/logout")
async def logout(request: Request, current_user=Depends(get_current_user)):
    """Revokes the current user's token immediately."""
    try:
        jti = current_user.get("current_jti")
        exp = current_user.get("token_exp")
        
        if jti and exp:
            # Calculate remaining time until token naturally expires
            now = datetime.now(timezone.utc).timestamp()
            ttl = int(exp - now)

            if ttl > 0:
                redis = getattr(request.app.state, "redis", None)
                if redis:
                    # Store the token in the blacklist until its natural expiration time
                    try:
                        await redis.setex(f"warsoc:blacklist:{jti}", ttl, "revoked")
                    except Exception as e:
                        print(f"⚠️ Failed to write logout blacklist to Redis: {e}")
                
        return {"message": "Successfully logged out."}
    except Exception as e:
        print(f"🔴 Logout Error: {e}")
        raise HTTPException(status_code=500, detail="Error processing logout.")

@router.get("/me")
async def get_me(user: dict = Depends(get_current_user)):
    resp = user.copy()
    
    # 🔒 Source of Truth for Packs
    plan = normalize_plan_type(resp.get("plan_type", "Free"))
    packs = resolve_compliance_packs(plan, resp.get("compliance_packs", []))
    resp["plan_type"] = plan

    # 🚀 MASTER BUILD FIX: Convert non-serializable MongoDB types to strings
    if "_id" in resp:
        resp["_id"] = str(resp["_id"])

    # Remove sensitive/internal fields before returning to clients
    for _s in ("hashed_password", "agent_secret", "current_jti", "token_exp"):
        resp.pop(_s, None)

    for key, value in list(resp.items()):
        if isinstance(value, datetime):
            resp[key] = value.isoformat()  # Convert datetimes to ISO strings

    return JSONResponse({
        **resp,
        "has_active_plan": user.get("has_active_plan", False),
        "role": user.get("role", "admin"),
        "tenant_id": user.get("tenant_id"),
        "compliance_packs": packs,
    })

@router.get("/my-packs")
async def get_my_packs(user: dict = Depends(get_current_user)):
    """Dynamically computes active packs based on plan_type source of truth."""
    plan = normalize_plan_type(user.get("plan_type", "Free"))
    packs = resolve_compliance_packs(plan, user.get("compliance_packs", []))

    return JSONResponse({
        "compliance_packs": packs
    })

@router.post("/agent-login")
# @limiter.limit("100/minute")
async def agent_login(request: Request, data: AgentLogin, db=Depends(get_db)):
    try:
        agent_doc = None
        
        try:
            agent_doc = await db["agents"].find_one({"agent_id": data.agent_id})
        except Exception:
            agent_doc = None

        # 👑 MASTER KEY FAST-PATH: Skip DB lookup entirely if master secret matches
        if hmac.compare_digest(data.agent_secret, AGENT_MASTER_SECRET):
            mapped_tenant = data.agent_id
        else:
            # Standard path: verify tenant exists in DB first
            if agent_doc:
                if not agent_doc.get("approved", True):
                    raise HTTPException(status_code=403, detail="Agent not approved")
                mapped_tenant = agent_doc.get("tenant_id") or data.agent_id
            else:
                tenant_user = await db["users"].find_one({"tenant_id": data.agent_id})
                if not tenant_user:
                    raise HTTPException(status_code=401, detail="Unknown agent tenant")
                mapped_tenant = data.agent_id
                agent_doc = tenant_user

            expected_secret = (agent_doc or {}).get("agent_secret")
            if expected_secret:
                if isinstance(expected_secret, str) and expected_secret.startswith("$"):
                    ok = verify_password(data.agent_secret, expected_secret)
                else:
                    ok = hmac.compare_digest(data.agent_secret, expected_secret)
                if not ok:
                    raise HTTPException(status_code=401, detail="Invalid Agent Credentials")
            else:
                raise HTTPException(status_code=401, detail="Invalid Agent Credentials")

    except HTTPException:
        raise
    except Exception as e:
        print(f" Agent login DB error: {e}")
        raise HTTPException(status_code=503, detail="Agent verification service unavailable")

    access_token = create_access_token(
        data={"sub": data.agent_id, "type": "agent", "tenant_id": mapped_tenant}, 
        expires_delta=timedelta(hours=24)
    )
    return {"access_token": access_token, "token_type": "bearer"}

@router.post("/update-plan")
@audit_log("Plan Update")
async def update_plan(
    data: PlanUpdate, 
    db=Depends(get_db), 
    current_user=Depends(get_current_user),
    _: str = Depends(RoleChecker(["admin"]))
):
    secure_username = current_user["username"]
    canonical_plan = normalize_plan_type(data.plan_name)

    # ✅ MASTER BUILD FIX: Automatic Pack Provisioning
    packs = default_packs_for_plan(canonical_plan)

    await db["users"].update_one(
        {"username": secure_username},
        {"$set": {
            "plan_type": canonical_plan, 
            "has_active_plan": True,
            "compliance_packs": packs
        }}
    )
    
    # ✅ CTO FIX 5: Also update the plan in the tenants collection.
    db_user = await db["users"].find_one({"username": secure_username})
    tenant_id = db_user.get("tenant_id")
    if tenant_id:
        await db["tenants"].update_one(
            {"tenant_id": tenant_id},
            {
                "$set": {"plan": canonical_plan},
                "$setOnInsert": {
                    "retention_days": resolve_tenant_retention_days(canonical_plan)
                },
            },
            upsert=True
        )
        await db["tenants"].update_one(
            {"tenant_id": tenant_id, "retention_days": {"$exists": False}},
            {"$set": {"retention_days": resolve_tenant_retention_days(canonical_plan)}},
        )
        # ✅ MASTER BUILD FIX: Immediate Cache Sync
        redis = request.app.state.redis
        if redis:
            await redis.set(f"tenant_plan:{tenant_id}", canonical_plan)

@router.post("/upgrade")
@audit_log("Enterprise Upgrade")
async def upgrade_plan(
    data: UpgradePlan, 
    db=Depends(get_db), 
    current_user=Depends(get_current_user),
    _: str = Depends(RoleChecker(["admin"]))
):
    secure_username = current_user["username"]
    canonical_plan = normalize_plan_type(data.plan_type)
    resolved_packs = resolve_compliance_packs(canonical_plan, data.compliance_packs)
    
    await db["users"].update_one(
        {"username": secure_username},
        {"$set": {
            "plan_type": canonical_plan, 
            "has_active_plan": True,
            "compliance_packs": resolved_packs,
            "endpoints": data.endpoints,
            "storage_gb": data.storage_gb,
            "retention_months": data.retention_months
        }}
    )
    
    # ✅ CTO FIX 6: Also update the plan in the tenants collection.
    db_user = await db["users"].find_one({"username": secure_username})
    tenant_id = db_user.get("tenant_id")
    if tenant_id:
        await db["tenants"].update_one(
            {"tenant_id": tenant_id},
            {
                "$set": {"plan": canonical_plan},
                "$setOnInsert": {
                    "retention_days": resolve_tenant_retention_days(canonical_plan)
                },
            },
            upsert=True
        )
        await db["tenants"].update_one(
            {"tenant_id": tenant_id, "retention_days": {"$exists": False}},
            {"$set": {"retention_days": resolve_tenant_retention_days(canonical_plan)}},
        )
        # ✅ MASTER BUILD FIX: Immediate Cache Sync
        redis = request.app.state.redis
        if redis:
            await redis.set(f"tenant_plan:{tenant_id}", canonical_plan)

    tenant_id = db_user.get("tenant_id", "WARSOC_DEFAULT")
    access_token = create_access_token(
        data={"sub": db_user["username"], "type": "user", "tenant_id": tenant_id, "role": db_user.get("role", "admin")}, 
        expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    # 🔒 Final Identity Contract Verification
    plan = normalize_plan_type(db_user.get("plan_type", "Free"))
    packs = resolve_compliance_packs(plan, db_user.get("compliance_packs", resolved_packs))

    return {
        "access_token": access_token, 
        "token_type": "bearer",
        "username": db_user["username"],
        "tenant_id": tenant_id,
        "plan_type": plan,
        "has_active_plan": db_user.get("has_active_plan", False),
        "compliance_packs": packs
    }