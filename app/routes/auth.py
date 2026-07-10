from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import JSONResponse, Response
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel, EmailStr, Field

from app.database import get_db
from passlib.context import CryptContext

from datetime import datetime, timedelta, timezone
from typing import Optional
import jwt
import logging
import uuid

from app.config.config import get_settings
from app.utils.audit import audit_log
from app.utils.limiter import limiter
from app.utils.observability import record_auth_fail_closed
from app.utils.pricing import calculate_package_price
from app.utils.rbac import RoleChecker
from app.routes.admin import verify_admin
from app.utils.security_policy import PLATFORM_MAX_AGENTS, StrongPassword

logger = logging.getLogger("auth")

settings = get_settings()
router = APIRouter()

SECRET_KEY = settings.jwt_secret_key
ACCESS_TOKEN_EXPIRE_MINUTES = settings.access_token_expire_minutes
AGENT_TOKEN_EXPIRE_MINUTES = settings.agent_token_expire_minutes
ALGORITHM = "HS256"

pwd_context = CryptContext(schemes=["pbkdf2_sha256", "bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login", auto_error=False)


class UserCreate(BaseModel):
    username: str
    email: EmailStr
    password: StrongPassword
    full_name: str
    plan_type: Optional[str] = "Free"
    role: Optional[str] = "admin"
    compliance_packs: Optional[list[str]] = []


class PlanUpdate(BaseModel):
    plan_name: str


class UpgradePlan(BaseModel):
    plan_type: str
    compliance_packs: list[str]
    endpoints: int = Field(ge=1, le=PLATFORM_MAX_AGENTS)
    storage_gb: int = Field(ge=0)
    retention_months: int = Field(ge=0)
    billing_cycle: Optional[str] = "monthly"  # Backend now calculates price based on cycle


class InviteUserRequest(BaseModel):
    email: EmailStr
    password: Optional[StrongPassword] = None
    temp_password: Optional[StrongPassword] = None
    role: str
    allowed_packs: Optional[list[str]] = []

# --- HELPER FUNCTIONS ---
def verify_password(plain_password, hashed_password):
    try:
        if not hashed_password:
            return False
        return pwd_context.verify(plain_password, hashed_password)
    except Exception as exc:
        logger.warning("Password verification failed for stored hash: %s", exc)
        return False

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


def _redis_text(value):
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="ignore")
    return value


def _redis_hash_value(mapping: dict, key: str):
    return _redis_text(mapping.get(key) or mapping.get(key.encode("utf-8")))


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
        # ðŸ›¡ï¸ NORMALIZATION: Map legacy IDs to new SSOT standards
        aliases = {
            "peca": "peca_forensic",
            "peca_forensic": "peca_forensic",
            "peca_vault": "peca_forensic",
            "eto": "peca_forensic",
            "eto_forensic": "peca_forensic",
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
            logger.warning(
                "CSRF validation failed: cookie_present=%s header_present=%s",
                bool(csrf_cookie),
                bool(csrf_header),
            )
            raise HTTPException(status_code=403, detail="CSRF validation failed")

    try:
        token = _extract_token(request, token)
        if not token:
            raise HTTPException(status_code=401, detail="Could not validate credentials")

        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        jti: str = payload.get("jti")
        username: str = payload.get("sub")
        tenant_id: str = payload.get("tenant_id")
        token_type: str = payload.get("type")
        if token_type != "user" or not jti or not username or not tenant_id:
            raise HTTPException(status_code=401, detail="Invalid user token")

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

    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Could not validate credentials")

    user = await db["users"].find_one({"username": username, "tenant_id": tenant_id})
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
        if token_type != "agent" or not jti or not agent_id:
            raise HTTPException(status_code=401, detail="Invalid agent token")

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

        # ✅ CTO FIX 2: Removed rogue DB connections. Rely strictly on `db` dependency.
        # 🛡️ PERFORMANCE FIX: Added Redis Caching to prevent DB DDoS during Nuclear Stress Test
        status_key = f"warsoc:agent_status:{agent_id}"
        revoked_key = f"warsoc:agent_revoked:{agent_id}"
        try:
            if await redis.exists(revoked_key):
                raise HTTPException(status_code=403, detail="Agent has been revoked")
            live_status = _redis_text(await redis.get(status_key))
        except HTTPException:
            raise
        except Exception as e:
            logger.error("Agent live status check failed: %s", e)
            record_auth_fail_closed()
            raise HTTPException(status_code=503, detail="Agent verification unavailable: live status check failed")

        agent_doc = None
        if live_status:
            if str(live_status).strip().lower() != "active":
                raise HTTPException(status_code=403, detail="Agent is inactive")
        else:
            agent_doc = await db["agents"].find_one({"agent_id": agent_id})
            if not agent_doc:
                raise HTTPException(status_code=401, detail="Unknown agent")
            doc_status = str(agent_doc.get("status", "active")).strip().lower()
            if not agent_doc.get("approved", True) or doc_status != "active":
                await redis.set(status_key, doc_status or "inactive")
                await redis.set(revoked_key, "1")
                raise HTTPException(status_code=403, detail="Agent is inactive")
            await redis.set(status_key, "active")

        mapped_tenant = None
        public_key = None
        agent_approved = True

        if redis:
            cached_agent = await redis.hgetall(f"warsoc:agent_cache:{agent_id}")
            if cached_agent:
                mapped_tenant = _redis_hash_value(cached_agent, "tenant_id")
                public_key = _redis_hash_value(cached_agent, "public_key")
                cached_status = _redis_hash_value(cached_agent, "status")
                agent_approved = _redis_hash_value(cached_agent, "approved") == "True"
                if cached_status and str(cached_status).strip().lower() != "active":
                    raise HTTPException(status_code=403, detail="Agent is inactive")

        if not mapped_tenant:
            agent_doc = agent_doc or await db["agents"].find_one({"agent_id": agent_id})
            if not agent_doc:
                raise HTTPException(status_code=401, detail="Unknown agent")
            if not agent_doc.get("approved", True):
                raise HTTPException(status_code=403, detail="Agent not approved")
            doc_status = str(agent_doc.get("status", "active")).strip().lower()
            if doc_status != "active":
                await redis.set(status_key, doc_status or "inactive")
                await redis.set(revoked_key, "1")
                raise HTTPException(status_code=403, detail="Agent is inactive")

            mapped_tenant = agent_doc.get("tenant_id")
            public_key = agent_doc.get("public_key")

            if redis and mapped_tenant and public_key:
                await redis.hset(f"warsoc:agent_cache:{agent_id}", mapping={
                    "tenant_id": mapped_tenant,
                    "public_key": public_key,
                    "approved": "True",
                    "status": "active"
                })
                await redis.expire(f"warsoc:agent_cache:{agent_id}", 3600)
        elif not agent_approved:
            raise HTTPException(status_code=403, detail="Agent not approved")

        token_tenant = payload.get("tenant_id")
        if not mapped_tenant or token_tenant != mapped_tenant:
            raise HTTPException(status_code=403, detail="Agent tenant mismatch")

        tenant_active_key = f"tenant_active:{mapped_tenant}"
        cached_tenant_active = await redis.get(tenant_active_key)
        if cached_tenant_active is not None:
            cached_text = _redis_text(cached_tenant_active)
            if cached_text != "1":
                raise HTTPException(status_code=403, detail="Tenant subscription is inactive")
        else:
            tenant_doc = await db["tenants"].find_one(
                {"tenant_id": mapped_tenant},
                {"active": 1, "status": 1, "has_active_plan": 1},
            )
            if not tenant_doc:
                await redis.setex(tenant_active_key, 60, "0")
                raise HTTPException(status_code=403, detail="Tenant is inactive")

            tenant_status = str(tenant_doc.get("status") or "active").strip().lower()
            tenant_enabled = (
                tenant_doc.get("active", True) is not False
                and tenant_doc.get("has_active_plan", True) is not False
                and tenant_status not in {"inactive", "suspended", "cancelled", "canceled", "past_due"}
            )
            active_user = await db["users"].find_one(
                {"tenant_id": mapped_tenant, "has_active_plan": True},
                {"_id": 1},
            )
            plan_enabled = bool(active_user or tenant_doc.get("has_active_plan") is True)
            tenant_allowed = tenant_enabled and plan_enabled
            await redis.setex(tenant_active_key, 60, "1" if tenant_allowed else "0")
            if not tenant_allowed:
                raise HTTPException(status_code=403, detail="Tenant subscription is inactive")

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
    if not settings.enable_self_signup:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Self-service signup is disabled. Contact WarSOC sales for onboarding.",
        )

    existing_user = await db["users"].find_one({"$or": [{"email": user.email}, {"username": user.username}]})
    if existing_user:
        raise HTTPException(status_code=400, detail="Username or Email already registered")

    hashed_password = get_password_hash(user.password)
    new_tenant_id = f"WARSOC_{str(uuid.uuid4())[:8].upper()}"
    # Enterprise, FBR, and PECA access must be provisioned by an admin after a sale.
    canonical_plan = "Free"

    # Compliance packs are not granted through public signup.
    # Public signup remains non-commercial even if ENABLE_SELF_SIGNUP is enabled.
    packs = []

    new_user = {
        "username": user.username,
        "email": user.email,
        "full_name": user.full_name,
        "hashed_password": hashed_password,
        "tenant_id": new_tenant_id,
        "plan_type": canonical_plan,
        "role": "admin",
        "compliance_packs": packs,
        "has_active_plan": False,
        "created_at": datetime.now(timezone.utc)
    }
    await db["users"].insert_one(new_user)

    new_tenant = {
        "tenant_id": new_tenant_id,
        "company_name": user.full_name,
        "plan": canonical_plan,
        "retention_days": resolve_tenant_retention_days(canonical_plan),
        "status": "inactive",
        "active": False,
        "has_active_plan": False,
        "created_at": datetime.now(timezone.utc)
    }
    await db["tenants"].insert_one(new_tenant)

    # ✅ MASTER BUILD FIX: Immediate Cache Sync
    redis = request.app.state.redis
    if redis:
        await redis.set(f"tenant_plan:{new_tenant_id}", canonical_plan)

    # 🔑 SECURITY FIX: Generate access token for automatic login after signup
    access_token = create_access_token(
        data={"sub": user.username, "type": "user", "tenant_id": new_tenant_id, "role": "admin"},
        expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )

    # CSRF Token Generation (CRITICAL FIX: Prevent soft-lock on signup)
    csrf_token = str(uuid.uuid4())

    # 🔑 Set HttpOnly cookie (browser sends automatically, JavaScript cannot access)
    response = JSONResponse(
        {
            "message": "User created successfully",
            "tenant_id": new_tenant_id,
            "plan": canonical_plan,
            "username": user.username,
            "csrf_token": csrf_token
        },
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

class LoginSchema(BaseModel):
    username: str
    password: str

@router.post("/login")
@limiter.limit("5/minute")
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

    from datetime import datetime, timezone
    await db["users"].update_one(
        {"_id": db_user["_id"]},
        {"$set": {"last_login_at": datetime.now(timezone.utc)}}
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
                "$set": {"plan": canonical_plan, "plan_type": canonical_plan, "compliance_packs": packs},
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
            # Sync features so generate-activation gets it instantly
            features = []
            if "fbr_pos" in packs: features.append("FBR")
            if "peca_forensic" in packs: features.append("PECA")
            features_str = ",".join(features) if features else "SIEM"
            await redis.set(f"tenant_features:{tenant_id}", features_str)

@router.post("/upgrade")
@audit_log("Enterprise Upgrade")
async def upgrade_plan(
    request: Request,
    data: UpgradePlan,
    db=Depends(get_db),
    current_user=Depends(get_current_user),
    _role: str = Depends(RoleChecker(["admin"])),
    _admin_key: str = Depends(verify_admin),
):
    secure_username = current_user["username"]
    canonical_plan = normalize_plan_type(data.plan_type)
    resolved_packs = resolve_compliance_packs(canonical_plan, data.compliance_packs)

    retention_days_calc = max(90, data.retention_months * 30)

    await db["users"].update_one(
        {"username": secure_username},
        {"$set": {
            "plan_type": canonical_plan,
            "has_active_plan": True,
            "compliance_packs": resolved_packs,
            "endpoints": data.endpoints,
            "storage_gb": data.storage_gb,
            "retention_months": data.retention_months,
            "retention_days": retention_days_calc
        }}
    )

    # âœ… CTO FIX 6: Also update the plan in the tenants collection.
    db_user = await db["users"].find_one({"username": secure_username})
    tenant_id = db_user.get("tenant_id")
    if tenant_id:
        await db["tenants"].update_one(
            {"tenant_id": tenant_id},
            {
                "$set": {
                    "plan": canonical_plan,
                    "plan_type": canonical_plan,
                    "compliance_packs": resolved_packs,
                    "endpoints": data.endpoints,
                    "agent_limit": data.endpoints,
                    "max_agents": data.endpoints,
                    "storage_gb": data.storage_gb,
                    "retention_months": data.retention_months,
                    "retention_days": retention_days_calc
                }
            },
            upsert=True
        )
        # âœ… MASTER BUILD FIX: Immediate Cache Sync
        redis = request.app.state.redis
        if redis:
            await redis.set(f"tenant_plan:{tenant_id}", canonical_plan)
            # Sync features so generate-activation gets it instantly
            features = []
            if "fbr_pos" in resolved_packs: features.append("FBR")
            if "peca_forensic" in resolved_packs: features.append("PECA")
            features_str = ",".join(features) if features else "SIEM"
            await redis.set(f"tenant_features:{tenant_id}", features_str)
            await redis.set(f"tenant_agent_limit:{tenant_id}", str(data.endpoints))
            await redis.set(f"tenant_retention:{tenant_id}", str(retention_days_calc))

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
    price = calculate_package_price(
        endpoints=data.endpoints,
        compliance_packs=packs,
        billing_cycle=data.billing_cycle,
    )

    # ðŸ’³ NAYA: Record Transaction in the Permanent Billing Ledger (Using CALCULATED amount)
    billing_record = {
        "tenant_id": tenant_id,
        "username": secure_username,
        "amount": price.initial_payment,
        "plan": plan,
        "endpoints": data.endpoints,
        "storage": data.storage_gb,
        "retention": data.retention_months,
        "billing_cycle": price.billing_cycle,
        "packs": packs,
        "pricing_version": price.pricing_version,
        "monthly_total": price.monthly_total,
        "activation_fee": price.activation_fee,
        "price_breakdown": price.breakdown,
        "timestamp": datetime.now(timezone.utc)
    }
    await db["billing"].insert_one(billing_record)

    response = JSONResponse({
        "username": db_user["username"],
        "tenant_id": tenant_id,
        "plan_type": plan,
        "has_active_plan": db_user.get("has_active_plan", False),
        "compliance_packs": packs,
        "calculated_total": price.initial_payment,
        "monthly_total": price.monthly_total,
        "pricing_version": price.pricing_version,
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

    if payload.role not in ["admin", "manager", "analyst", "auditor"]:
        raise HTTPException(status_code=400, detail="Invalid role specified. Must be admin, manager, analyst, or auditor.")

    # Login accepts an email without tenant context, so email identity must
    # remain globally unique until the login contract includes a tenant slug.
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
        "username": f'{payload.email.split("@")[0]}-{str(uuid.uuid4())[:4]}',
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
