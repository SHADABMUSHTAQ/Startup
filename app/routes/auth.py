from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import JSONResponse, Response
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel, EmailStr

from app.database import get_db
from passlib.context import CryptContext

from datetime import datetime, timedelta, timezone
from typing import Optional
import hashlib
import jwt
import logging
import secrets
import uuid

from pymongo import ReturnDocument
from app.config.config import get_settings
from app.utils.agent_crypto import (
    build_login_signature_string,
    parse_utc_timestamp,
    timestamp_age_seconds,
)
from app.utils.audit import audit_log
from app.utils.limiter import limiter
from app.utils.observability import record_auth_fail_closed
from app.utils.rbac import RoleChecker
from ecdsa import BadSignatureError, VerifyingKey

logger = logging.getLogger("auth")

settings = get_settings()
router = APIRouter()

SECRET_KEY = settings.jwt_secret_key
ACCESS_TOKEN_EXPIRE_MINUTES = settings.access_token_expire_minutes
AGENT_TOKEN_EXPIRE_MINUTES = settings.agent_token_expire_minutes
PROVISIONING_TOKEN_EXPIRE_MINUTES = settings.provisioning_token_expire_minutes
ALGORITHM = "HS256"
AGENT_SIGNATURE_WINDOW_SECONDS = 300

pwd_context = CryptContext(schemes=["pbkdf2_sha256", "bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login", auto_error=False)


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
    timestamp: str
    nonce: str
    signature: str


class AgentEnrollRequest(BaseModel):
    agent_id: str
    public_key: str
    hostname: Optional[str] = "Unknown"
    mac_address: Optional[str] = "Unknown"


class EnrollmentPayload(BaseModel):
    enrollment_token: str
    public_key: str


class ProvisioningTokenRequest(BaseModel):
    agent_id: Optional[str] = None


class UpgradePlan(BaseModel):
    plan_type: str
    compliance_packs: list[str]
    endpoints: int
    storage_gb: int
    retention_months: int
    billing_cycle: Optional[str] = "monthly"  # Backend now calculates price based on cycle


class InviteUserRequest(BaseModel):
    email: EmailStr
    password: Optional[str] = None
    temp_password: Optional[str] = None
    role: str
    allowed_packs: Optional[list[str]] = []

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


def _seconds_until_expiry(exp_value) -> int:
    if isinstance(exp_value, (int, float)):
        exp_dt = datetime.fromtimestamp(exp_value, tz=timezone.utc)
    elif isinstance(exp_value, datetime):
        exp_dt = exp_value.astimezone(timezone.utc)
    else:
        return 3600

    remaining = int((exp_dt - datetime.now(timezone.utc)).total_seconds())
    return max(60, remaining)


def _validate_public_key_pem(public_key: str) -> str:
    try:
        VerifyingKey.from_pem(public_key)
        return public_key
    except Exception as exc:
        raise HTTPException(status_code=400, detail="Invalid agent public key") from exc


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
    "Professional": ["eto_forensic"],
    "Enterprise": ["eto_forensic", "fbr_pos"],
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
        # ðŸ›¡ï¸ NORMALIZATION: Map legacy IDs to new SSOT standards
        aliases = {
            "peca": "eto_forensic",
            "peca_forensic": "eto_forensic",
            "peca_vault": "eto_forensic",
            "eto": "eto_forensic",
            "fbr": "fbr_pos",
            "fbr_pos_shield": "fbr_pos"
        }
        normalized = []
        for p in provided:
            normalized.append(aliases.get(p.lower(), p))
        return list(set(normalized))
    return default_packs_for_plan(plan)


def resolve_tenant_retention_days(
    plan: Optional[str],
    existing_retention_days: Optional[int] = None,
) -> int:
    if isinstance(existing_retention_days, int) and existing_retention_days > 0:
        return existing_retention_days

    canonical_plan = normalize_plan_type(plan)
    return int(RETENTION_DAYS_BY_PLAN.get(canonical_plan, DEFAULT_TENANT_RETENTION_DAYS))


async def _ensure_users_tenant_index(db) -> None:
    """Ensure tenants can have multiple users by removing any legacy unique tenant_id index."""
    try:
        indexes = await db["users"].index_information()
        for idx_name, idx_def in indexes.items():
            if idx_name == "_id_":
                continue
            if idx_def.get("key") != [("tenant_id", 1)]:
                continue
            if idx_def.get("unique"):
                await db["users"].drop_index(idx_name)
                break
        await db["users"].create_index([("tenant_id", 1)], name="idx_users_tenant_id_1", unique=False)
    except Exception as exc:
        logger.warning("users.tenant_id index normalization skipped: %s", exc)

# --- DEPENDENCIES ---
def _extract_token(request: Request, token: Optional[str]) -> Optional[str]:
    if token:
        return token
    return request.cookies.get("warsoc_token")


async def get_current_user(request: Request, token: str = Depends(oauth2_scheme), db=Depends(get_db)):
    if request.method in ["POST", "PUT", "DELETE", "PATCH"]:
        csrf_cookie = request.cookies.get("csrf_token")
        csrf_header = request.headers.get("x-csrf-token")
        if not csrf_cookie or not csrf_header or csrf_cookie != csrf_header:
            print(f"🛑 CSRF Validation Failed: Cookie={csrf_cookie}, Header={csrf_header}")
            raise HTTPException(status_code=403, detail="CSRF validation failed")

    try:
        token = _extract_token(request, token)
        if not token:
            raise HTTPException(status_code=401, detail="Could not validate credentials")

        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        jti: str = payload.get("jti")
        username: str = payload.get("sub")

        # âœ… CTO FIX 1: Use Global Redis Pool for Lightning Fast Blacklist Checks
        redis = getattr(request.app.state, "redis", None)
        # Fail-closed: if Redis is unavailable, deny access rather than allow revoked tokens.
        if not redis:
            logger.error("ðŸ”´ Redis blacklist unavailable: failing closed for auth verification.")
            record_auth_fail_closed()
            raise HTTPException(status_code=503, detail="Authentication service unavailable: revocation check failed")
        try:
            is_blacklisted = await redis.exists(f"warsoc:blacklist:{jti}")
            if is_blacklisted:
                raise HTTPException(status_code=401, detail="Token has been revoked.")
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"ðŸ”´ Redis blacklist check failed: {e}")
            record_auth_fail_closed()
            raise HTTPException(status_code=503, detail="Authentication service unavailable: revocation check failed")

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

async def require_premium_plan(current_user: dict = Depends(get_current_user)):
    """RBAC Entitlement Checker for Premium features."""
    plan_type = current_user.get("plan_type", "Free").lower()
    if plan_type in ["free", "basic", "trial", "starter"]:
        raise HTTPException(
            status_code=403,
            detail="This feature requires a Professional or Enterprise tier. Please upgrade."
        )
    return current_user

async def verify_agent_token(request: Request, token: str = Depends(oauth2_scheme), db=Depends(get_db)):

    try:
        token = _extract_token(request, token)
        if not token:
            raise HTTPException(status_code=401, detail="Unauthorized Agent")

        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        jti: str = payload.get("jti")
        agent_id: str = payload.get("sub")
        token_type: str = payload.get("type")

        # âœ… CTO FIX 1: Global Redis Pool
        redis = getattr(request.app.state, "redis", None)
        if not redis:
            logger.error("ðŸ”´ Redis blacklist unavailable: failing closed for agent verification.")
            record_auth_fail_closed()
            raise HTTPException(status_code=503, detail="Agent verification unavailable: revocation check failed")
        try:
            if await redis.exists(f"warsoc:blacklist:{jti}"):
                raise HTTPException(status_code=401, detail="Agent token revoked.")
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"ðŸ”´ Redis blacklist check failed: {e}")
            record_auth_fail_closed()
            raise HTTPException(status_code=503, detail="Agent verification unavailable: revocation check failed")

        if agent_id is None or token_type != "agent":
            raise HTTPException(status_code=401, detail="Invalid agent token")

        # ✅ CTO FIX 2: Removed rogue DB connections. Rely strictly on `db` dependency.
        # 🛡️ PERFORMANCE FIX: Added Redis Caching to prevent DB DDoS during Nuclear Stress Test
        mapped_tenant = None
        public_key = None
        agent_approved = True

        if redis:
            cached_agent = await redis.hgetall(f"warsoc:agent_cache:{agent_id}")
            if cached_agent:
                mapped_tenant = cached_agent.get("tenant_id")
                public_key = cached_agent.get("public_key")
                agent_approved = cached_agent.get("approved") == "True"

        if not mapped_tenant:
            agent_doc = await db["agents"].find_one({"agent_id": agent_id})
            if not agent_doc:
                raise HTTPException(status_code=401, detail="Unknown agent")
            if not agent_doc.get("approved", True):
                raise HTTPException(status_code=403, detail="Agent not approved")
            
            mapped_tenant = agent_doc.get("tenant_id")
            public_key = agent_doc.get("public_key")
            
            if redis and mapped_tenant and public_key:
                await redis.hset(f"warsoc:agent_cache:{agent_id}", mapping={
                    "tenant_id": mapped_tenant,
                    "public_key": public_key,
                    "approved": "True"
                })
                await redis.expire(f"warsoc:agent_cache:{agent_id}", 3600)
        elif not agent_approved:
            raise HTTPException(status_code=403, detail="Agent not approved")

        token_tenant = payload.get("tenant_id")
        if not mapped_tenant or token_tenant != mapped_tenant:
            raise HTTPException(status_code=403, detail="Agent tenant mismatch")

        return {
            "agent_id": agent_id,
            "tenant_id": mapped_tenant,
            "public_key": public_key,
        }
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Agent token expired.")
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Unauthorized Agent")
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Agent verification error: %s", e)
        raise HTTPException(status_code=503, detail="Agent verification service unavailable")
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

    # 🔑 SECURITY FIX: Generate access token for automatic login after signup
    access_token = create_access_token(
        data={"sub": user.username, "type": "user", "tenant_id": new_tenant_id, "role": user.role or "admin"},
        expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )

    # 🔑 Set HttpOnly cookie (browser sends automatically, JavaScript cannot access)
    response = JSONResponse(
        {"message": "User created successfully", "tenant_id": new_tenant_id, "plan": canonical_plan, "username": user.username},
        status_code=status.HTTP_201_CREATED
    )
    secure_cookie = request.url.scheme == "https"
    response.set_cookie(
        key="warsoc_token",
        value=access_token,
        max_age=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        secure=secure_cookie,
        httponly=True,  # JavaScript cannot access
        samesite="Lax"  # CSRF protection
    )
    return response

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
    # ðŸ”’ Unified Permission Logic (Self-Healing Contract)
    plan = normalize_plan_type(db_user.get("plan_type", "Free"))
    packs = resolve_compliance_packs(plan, db_user.get("compliance_packs", []))

    # CSRF Token Generation
    csrf_token = str(uuid.uuid4())

    # ðŸ”’ Set HttpOnly cookie (browser sends automatically, JavaScript cannot access)
    response = JSONResponse({
        "username": db_user["username"],
        "tenant_id": tenant_id,
        "plan_type": plan,
        "has_active_plan": db_user.get("has_active_plan", False),
        "compliance_packs": packs,
        "csrf_token": csrf_token
    })
    secure_cookie = request.url.scheme == "https"
    response.set_cookie(
        key="warsoc_token",
        value=access_token,
        max_age=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        secure=secure_cookie,
        httponly=True,  # JavaScript cannot access
        samesite="Lax"  # CSRF protection
    )
    # Double Submit Cookie for CSRF
    response.set_cookie(
        key="csrf_token",
        value=csrf_token,
        max_age=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        secure=secure_cookie,
        httponly=False,  # JS needs access to this to send as header
        samesite="Lax"
    )
    return response

# âœ… CTO FIX 3: Secure Logout Route for Token Revocation
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
                        print(f"âš ï¸ Failed to write logout blacklist to Redis: {e}")

        # ðŸ”’ SECURITY FIX: Clear HttpOnly cookie
        response = JSONResponse({"message": "Successfully logged out."})
        secure_cookie = request.url.scheme == "https"
        response.delete_cookie(
            key="warsoc_token",
            secure=secure_cookie,
            httponly=True,
            samesite="Lax"
        )
        return response
    except Exception as e:
        print(f"🔴 Logout Error: {e}")
        raise HTTPException(status_code=500, detail="Error processing logout.")

@router.get("/me")
async def get_me(request: Request, user: dict = Depends(get_current_user)):
    resp = user.copy()

    # 🛡️ Source of Truth for Packs
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
        "user": resp,
        "plan_type": plan,
        "role": resp.get("role", "admin"),
        "csrf_token": request.cookies.get("csrf_token")
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
@limiter.limit("100/minute")
async def agent_login(request: Request, data: AgentLogin, db=Depends(get_db)):
    try:
        agent_doc = await db["agents"].find_one({"agent_id": data.agent_id})
        if not agent_doc:
            raise HTTPException(status_code=401, detail="Agent not enrolled")
        if not agent_doc.get("approved", True):
            raise HTTPException(status_code=403, detail="Agent not approved")
        public_key = agent_doc.get("public_key")
        tenant_id = agent_doc.get("tenant_id")
        if not public_key or not tenant_id:
            raise HTTPException(status_code=401, detail="Agent enrollment incomplete")
        drift = timestamp_age_seconds(data.timestamp)
        if drift is None or abs(drift) > AGENT_SIGNATURE_WINDOW_SECONDS:
            raise HTTPException(status_code=401, detail="Agent login timestamp outside allowed drift window")
        if not data.nonce or len(data.nonce) < 16:
            raise HTTPException(status_code=400, detail="Agent login nonce is required")
        redis = getattr(request.app.state, "redis", None)
        if redis:
            nonce_key = f"warsoc:agent_login_nonce:{data.agent_id}:{data.nonce}"
            if await redis.exists(nonce_key):
                raise HTTPException(status_code=401, detail="Replay detected for agent login")
        canonical = build_login_signature_string(data.agent_id, data.timestamp, data.nonce)
        verifying_key = VerifyingKey.from_pem(public_key)
        try:
            verifying_key.verify(bytes.fromhex(data.signature), canonical.encode("utf-8"), hashfunc=hashlib.sha256)
        except (BadSignatureError, ValueError):
            raise HTTPException(status_code=401, detail="Invalid agent signature")
        if redis:
            await redis.set(f"warsoc:agent_login_nonce:{data.agent_id}:{data.nonce}", "1", ex=AGENT_SIGNATURE_WINDOW_SECONDS)
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Agent login error: %s", e)
        raise HTTPException(status_code=503, detail="Agent verification service unavailable")

    access_token = create_access_token(
        data={"sub": data.agent_id, "type": "agent", "tenant_id": tenant_id},
        expires_delta=timedelta(minutes=AGENT_TOKEN_EXPIRE_MINUTES)
    )
    return {"access_token": access_token, "token_type": "bearer", "expires_in_minutes": AGENT_TOKEN_EXPIRE_MINUTES}


# Legacy Route 1 endpoints (generate_agent_token and enroll_agent) have been deprecated and removed.
# All agent token generation and enrollment strictly go through Route 2 (JWT & MongoDB provisioning).

@router.post("/update-plan")
@audit_log("Plan Update")
async def update_plan(
    request: Request,
    data: PlanUpdate,
    db=Depends(get_db),
    current_user=Depends(get_current_user),
    _: str = Depends(RoleChecker(["admin"]))
):
    secure_username = current_user["username"]
    canonical_plan = normalize_plan_type(data.plan_name)

    # âœ… MASTER BUILD FIX: Automatic Pack Provisioning
    packs = default_packs_for_plan(canonical_plan)

    await db["users"].update_one(
        {"username": secure_username},
        {"$set": {
            "plan_type": canonical_plan,
            "has_active_plan": True,
            "compliance_packs": packs
        }}
    )

    # âœ… CTO FIX 5: Also update the plan in the tenants collection.
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
        # âœ… MASTER BUILD FIX: Immediate Cache Sync
        redis = request.app.state.redis
        if redis:
            await redis.set(f"tenant_plan:{tenant_id}", canonical_plan)

@router.post("/upgrade")
@audit_log("Enterprise Upgrade")
async def upgrade_plan(
    request: Request,
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

    # âœ… CTO FIX 6: Also update the plan in the tenants collection.
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
        # âœ… MASTER BUILD FIX: Immediate Cache Sync
        redis = request.app.state.redis
        if redis:
            await redis.set(f"tenant_plan:{tenant_id}", canonical_plan)

    tenant_id = db_user.get("tenant_id", "WARSOC_DEFAULT")
    access_token = create_access_token(
        data={"sub": db_user["username"], "type": "user", "tenant_id": tenant_id, "role": db_user.get("role", "admin")},
        expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    # ðŸ”’ Final Identity Contract Verification
    plan = normalize_plan_type(db_user.get("plan_type", "Free"))
    packs = resolve_compliance_packs(plan, db_user.get("compliance_packs", resolved_packs))

    # ðŸ›ï¸ CTO SECURITY FIX: Backend Price Calculator (SSOT)
    # Never trust the frontend with price. We calculate it here.
    ACTIVATION_FEE = 5000
    PRICE_PER_ENDPOINT = 1500
    PRICE_PER_GB = 200
    FBR_PRICE = 3000
    PECA_PRICE = 5000
    RETENTION_PRICES = {0: 0, 3: 6000, 6: 10000, 12: 18000}

    # Monthly Base Calculation
    ep_cost = max(0, data.endpoints - 1) * PRICE_PER_ENDPOINT
    st_cost = data.storage_gb * PRICE_PER_GB
    rt_cost = RETENTION_PRICES.get(data.retention_months, 0)

    # Pack Costs
    pk_cost = 0
    if "fbr_pos" in packs: pk_cost += FBR_PRICE
    if "eto_forensic" in packs: pk_cost += PECA_PRICE

    monthly_total = ep_cost + st_cost + rt_cost + pk_cost

    # Cycle Adjustment (Yearly = 10 months price)
    calculated_subtotal = monthly_total if data.billing_cycle == "monthly" else monthly_total * 10
    final_calculated_total = calculated_subtotal + ACTIVATION_FEE

    # ðŸ’³ NAYA: Record Transaction in the Permanent Billing Ledger (Using CALCULATED amount)
    billing_record = {
        "tenant_id": tenant_id,
        "username": secure_username,
        "amount": final_calculated_total,
        "plan": plan,
        "endpoints": data.endpoints,
        "storage": data.storage_gb,
        "retention": data.retention_months,
        "billing_cycle": data.billing_cycle,
        "packs": packs,
        "timestamp": datetime.now(timezone.utc)
    }
    await db["billing"].insert_one(billing_record)

    response = JSONResponse({
        "username": db_user["username"],
        "tenant_id": tenant_id,
        "plan_type": plan,
        "has_active_plan": db_user.get("has_active_plan", False),
        "compliance_packs": packs,
        "calculated_total": final_calculated_total,
        "transaction_recorded": True
    })
    
    secure_cookie = request.url.scheme == "https"
    response.set_cookie(
        key="warsoc_token",
        value=access_token,
        max_age=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        secure=secure_cookie,
        httponly=True,
        samesite="Lax"
    )
    return response

@router.post("/invite", status_code=status.HTTP_201_CREATED)
@audit_log("Team Provisioning")
async def invite_user(
    payload: InviteUserRequest,
    db=Depends(get_db),
    current_user=Depends(get_current_user),
    _: str = Depends(RoleChecker(["admin"]))
):
    await _ensure_users_tenant_index(db)

    invite_password = payload.password or payload.temp_password
    if not invite_password:
        raise HTTPException(status_code=400, detail="Password is required")

    if payload.role not in ["admin", "analyst", "auditor"]:
        raise HTTPException(status_code=400, detail="Invalid role specified. Must be admin, analyst, or auditor.")

    existing_user = await db["users"].find_one({"email": payload.email})
    if existing_user:
        raise HTTPException(status_code=400, detail="User with this email already exists")

    hashed_password = get_password_hash(invite_password)
    tenant_id = current_user.get("tenant_id")
    if not tenant_id:
        raise HTTPException(status_code=500, detail="Current admin lacks a valid tenant context.")

    packs = payload.allowed_packs if payload.role == "auditor" else ["internal_full"]
    packs = resolve_compliance_packs(current_user.get("plan_type", "Professional"), packs)

    new_user = {
        "username": payload.email.split("@")[0],
        "email": payload.email,
        "full_name": payload.email.split("@")[0],
        "hashed_password": hashed_password,
        "tenant_id": tenant_id,
        "plan_type": current_user.get("plan_type", "Professional"),
        "role": payload.role,
        "compliance_packs": packs,
        "has_active_plan": True,
        "created_at": datetime.now(timezone.utc)
    }
    await db["users"].insert_one(new_user)
    return {"message": f"User provisioned successfully as {payload.role}", "role": payload.role}


@router.get("/team")
@audit_log("Team List")
async def list_team_members(
    db=Depends(get_db),
    current_user=Depends(get_current_user),
    _: str = Depends(RoleChecker(["admin"]))
):
    tenant_id = current_user.get("tenant_id")
    if not tenant_id:
        raise HTTPException(status_code=403, detail="Unauthorized team access")

    cursor = db["users"].find(
        {"tenant_id": tenant_id},
        {
            "hashed_password": 0,
            "current_jti": 0,
            "token_exp": 0,
        },
    ).sort("created_at", -1)

    team = []
    async for member in cursor:
        member["_id"] = str(member["_id"])
        if "created_at" in member and member["created_at"] is not None:
            try:
                member["created_at"] = member["created_at"].isoformat()
            except Exception:
                member["created_at"] = str(member["created_at"])
        team.append(member)

    return {"team": team}

@router.delete("/team/{user_id}")
@audit_log("Team Revocation")
async def remove_team_member(
    user_id: str,
    db=Depends(get_db),
    current_user=Depends(get_current_user),
    _: str = Depends(RoleChecker(["admin"]))
):
    from bson import ObjectId
    try:
        obj_id = ObjectId(user_id)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid user ID format.")

    target_user = await db["users"].find_one({"_id": obj_id, "tenant_id": current_user.get("tenant_id")})
    if not target_user:
        raise HTTPException(status_code=404, detail="User not found in your team.")

    if target_user.get("role") == "admin":
        raise HTTPException(status_code=403, detail="Cannot revoke another admin's access.")

    await db["users"].delete_one({"_id": obj_id})
    return {"message": "Team member access revoked successfully."}

@router.post("/agents/generate-token")
@audit_log("Generate Provisioning Token")
async def generate_provisioning_token(
    data: ProvisioningTokenRequest | None = None,
    db=Depends(get_db),
    current_user=Depends(require_premium_plan),
    _: str = Depends(RoleChecker(["admin"]))
):
    """Generate a single-use, time-limited provisioning token for ECDSA agent enrollment."""
    tenant_id = current_user.get("tenant_id")
    if not tenant_id:
        raise HTTPException(status_code=400, detail="No tenant context.")

    expires = timedelta(minutes=PROVISIONING_TOKEN_EXPIRE_MINUTES)
    token = create_access_token(
        data={
            "sub": f"prov_{tenant_id}",
            "type": "provisioning",
            "tenant_id": tenant_id,
            "agent_id": (data.agent_id if data else None),
        },
        expires_delta=expires
    )

    payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    await db["used_provisioning_tokens"].insert_one(
        {
            "jti": payload["jti"],
            "tenant_id": tenant_id,
            "agent_id": (data.agent_id if data else None),
            "created_at": datetime.now(timezone.utc),
            "expires_at": datetime.fromtimestamp(payload["exp"], tz=timezone.utc),
        }
    )
    return {
        "provisioning_token": token,
        "expires_in_minutes": PROVISIONING_TOKEN_EXPIRE_MINUTES,
    }

@router.post("/agents/enroll", status_code=status.HTTP_201_CREATED)
@limiter.limit("50/minute")
@audit_log("Agent Enrollment")
async def enroll_agent(
    request: Request,
    data: AgentEnrollRequest,
    db=Depends(get_db),
    token: str = Depends(oauth2_scheme)
):
    """Stateless Enrollment: Validates Provisioning Token, stores ECDSA Public Key in MongoDB, and pushes to Redis Cache."""
    try:
        # 1. Validate the Provisioning Token
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        if payload.get("type") != "provisioning":
            raise HTTPException(status_code=403, detail="Invalid token type. Provisioning token required.")

        tenant_id = payload.get("tenant_id")
        if not tenant_id:
            raise HTTPException(status_code=400, detail="Provisioning token missing tenant_id")

        token_agent_id = payload.get("agent_id")
        if token_agent_id and token_agent_id != data.agent_id:
            raise HTTPException(status_code=403, detail="Provisioning token agent_id mismatch")

        verified_public_key = _validate_public_key_pem(data.public_key)

        # 2. Check Blacklist for Revoked Tokens
        redis = getattr(request.app.state, "redis", None)
        jti = payload.get("jti")
        if redis and jti:
            if await redis.exists(f"warsoc:blacklist:{jti}"):
                raise HTTPException(status_code=401, detail="Provisioning token revoked.")

        existing_agent = await db["agents"].find_one({"agent_id": data.agent_id})
        if existing_agent:
            existing_key = existing_agent.get("public_key")
            existing_tenant_id = existing_agent.get("tenant_id")
            if existing_tenant_id and existing_tenant_id != tenant_id:
                raise HTTPException(status_code=403, detail="Agent already belongs to another tenant")
            if existing_key and existing_key != verified_public_key:
                raise HTTPException(status_code=409, detail="Agent already enrolled with a different key")

        if jti:
            consumed = await db["used_provisioning_tokens"].find_one_and_update(
                {"jti": jti, "used_at": {"$exists": False}},
                {
                    "$set": {
                        "tenant_id": tenant_id,
                        "agent_id": data.agent_id,
                        "used_at": datetime.now(timezone.utc),
                    }
                },
                return_document=ReturnDocument.BEFORE,
            )
            if consumed is None:
                raise HTTPException(status_code=401, detail="Provisioning token invalid or already used.")

        # 3. Upsert to MongoDB (Idempotency)
        agent_doc = {
            "agent_id": data.agent_id,
            "tenant_id": tenant_id,
            "public_key": verified_public_key,
            "hostname": data.hostname,
            "mac_address": data.mac_address,
            "status": "active",
            "approved": True,
            "enrolled_at": datetime.now(timezone.utc),
            "bootstrap_disabled_at": datetime.now(timezone.utc),
        }

        await db["agents"].update_one(
            {"agent_id": data.agent_id},
            {"$set": agent_doc},
            upsert=True
        )

        # 4. Push to Redis Cache for Lightning Fast ECDSA checks in ingestion stream
        if redis:
            try:
                r1 = await redis.set(f"agent:pubkey:{data.agent_id}", verified_public_key)
                r2 = True
                if jti:
                    r2 = await redis.set(
                        f"warsoc:blacklist:{jti}",
                        "1",
                        ex=_seconds_until_expiry(payload.get("exp")),
                    )
                if not r1 or not r2:
                    raise RuntimeError("Redis cache write returned failed status")
            except Exception as e:
                logger.error("FAIL-CLOSED: Redis caching or blacklisting failed: %s. Rolling back MongoDB changes.", e)
                # Rollback agent record
                await db["agents"].delete_one({"agent_id": data.agent_id})
                # Rollback token consumption
                if jti:
                    await db["used_provisioning_tokens"].update_one(
                        {"jti": jti},
                        {"$unset": {"used_at": "", "agent_id": ""}}
                    )
                raise HTTPException(
                    status_code=500,
                    detail="Enrollment failed due to security cache synchronization failure"
                )

        return {
            "message": "Agent enrolled successfully",
            "agent_id": data.agent_id,
            "status": "active",
            "cryptography": "ECDSA SECP256R1 Enforced"
        }

    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Provisioning token expired.")
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid Provisioning Token.")
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Agent enrollment error: %s", e)
        raise HTTPException(status_code=500, detail="Internal Enrollment Error")
