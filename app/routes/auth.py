from fastapi import APIRouter, HTTPException, status, Depends, Request
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel, EmailStr
from app.database import get_db
from passlib.context import CryptContext
from datetime import datetime, timedelta, timezone
from typing import Optional
import jwt
import uuid
import hmac
from slowapi import Limiter
from slowapi.util import get_remote_address
from app.config.config import get_settings

settings = get_settings()
router = APIRouter()

limiter = Limiter(key_func=get_remote_address, storage_uri=settings.redis_url)

SECRET_KEY = getattr(settings, 'jwt_secret_key', "warsoc_secret_key_change_this_in_production")
AGENT_MASTER_SECRET = getattr(settings, 'agent_master_secret', "warsoc_enterprise_agent_key_2026")
ACCESS_TOKEN_EXPIRE_MINUTES = getattr(settings, 'access_token_expire_minutes', 1440)
ALGORITHM = "HS256"

pwd_context = CryptContext(schemes=["pbkdf2_sha256", "bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login")

# --- MODELS ---
class UserCreate(BaseModel):
    username: str
    email: EmailStr
    password: str
    full_name: str

class PlanUpdate(BaseModel):
    username: str
    plan_name: str

class AgentLogin(BaseModel):
    agent_id: str
    agent_secret: str

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

# --- DEPENDENCIES ---
async def get_current_user(request: Request, token: str = Depends(oauth2_scheme), db=Depends(get_db)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        jti: str = payload.get("jti")
        username: str = payload.get("sub")
        
        # ✅ CTO FIX 1: Use Global Redis Pool for Lightning Fast Blacklist Checks
        redis = request.app.state.redis
        is_blacklisted = await redis.exists(f"warsoc:blacklist:{jti}")
        if is_blacklisted:
            raise HTTPException(status_code=401, detail="Token has been revoked.")

        if payload.get("type") == "agent":
            raise HTTPException(status_code=401, detail="Agent tokens cannot access user routes")
        if username is None:
            raise HTTPException(status_code=401, detail="Invalid token")
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Could not validate credentials")
    
    user = await db.users.find_one({"username": username})
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
        redis = request.app.state.redis
        if await redis.exists(f"warsoc:blacklist:{jti}"):
            raise HTTPException(status_code=401, detail="Agent token revoked.")

        if agent_id is None or token_type != "agent":
            raise HTTPException(status_code=401, detail="Invalid agent token")

        # ✅ CTO FIX 2: Removed rogue DB connections. Rely strictly on `db` dependency.
        db_inner = getattr(db, "db", db) # Handle varying db dependency structures cleanly
        agent_doc = await db_inner["agents"].find_one({"agent_id": agent_id})
        user = None

        if not agent_doc:
            user = await db_inner["users"].find_one({"tenant_id": agent_id})

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
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Unauthorized Agent")
    except HTTPException:
        raise
    except Exception as e:
        print(f"🔴 Agent verification error: {e}")
        raise HTTPException(status_code=503, detail="Agent verification service unavailable")

# --- ROUTES ---
@router.post("/signup", status_code=status.HTTP_201_CREATED)
@limiter.limit("5/minute")
async def signup(request: Request, user: UserCreate, db=Depends(get_db)):
    existing_user = await db.users.find_one({"$or": [{"email": user.email}, {"username": user.username}]})
    if existing_user:
        raise HTTPException(status_code=400, detail="Username or Email already registered")

    hashed_password = get_password_hash(user.password)
    new_tenant_id = f"WARSOC_{str(uuid.uuid4())[:8].upper()}"

    new_user = {
        "username": user.username,
        "email": user.email,
        "full_name": user.full_name,
        "hashed_password": hashed_password,
        "tenant_id": new_tenant_id,
        "plan_type": "Free",
        "has_active_plan": True,
        "created_at": datetime.now(timezone.utc)
    }
    await db.users.insert_one(new_user)
    return {"message": "User created successfully", "tenant_id": new_tenant_id}

class LoginSchema(BaseModel):
    username: str
    password: str

@router.post("/login")
@limiter.limit("10/minute")
async def login(request: Request, user_data: LoginSchema, db=Depends(get_db)):
    db_user = await db.users.find_one({"$or": [{"username": user_data.username}, {"email": user_data.username}]})
    if not db_user or not verify_password(user_data.password, db_user["hashed_password"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    tenant_id = db_user.get("tenant_id", "WARSOC_DEFAULT")
    access_token = create_access_token(
        data={"sub": db_user["username"], "type": "user", "tenant_id": tenant_id}, 
        expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    return {
        "access_token": access_token, 
        "token_type": "bearer",
        "username": db_user["username"],
        "tenant_id": tenant_id,
        "plan_type": db_user.get("plan_type", "Free"),
        "has_active_plan": db_user.get("has_active_plan", False)
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
                redis = request.app.state.redis
                # Store the token in the blacklist until its natural expiration time
                await redis.setex(f"warsoc:blacklist:{jti}", ttl, "revoked")
                
        return {"message": "Successfully logged out."}
    except Exception as e:
        print(f"🔴 Logout Error: {e}")
        raise HTTPException(status_code=500, detail="Error processing logout.")

@router.get("/me")
async def get_user_me(current_user=Depends(get_current_user)):
    return {
        "username": current_user["username"],
        "email": current_user["email"],
        "full_name": current_user.get("full_name", ""),
        "tenant_id": current_user.get("tenant_id"),
        "plan_type": current_user.get("plan_type", "Free"),
        "has_active_plan": current_user.get("has_active_plan", False)
    }

@router.post("/agent-login")
@limiter.limit("10/minute")
async def agent_login(request: Request, data: AgentLogin, db=Depends(get_db)):
    try:
        agent_doc = None
        db_inner = getattr(db, "db", db)
        
        try:
            agent_doc = await db_inner["agents"].find_one({"agent_id": data.agent_id})
        except Exception:
            agent_doc = None

        if agent_doc:
            if not agent_doc.get("approved", True):
                raise HTTPException(status_code=403, detail="Agent not approved")
            mapped_tenant = agent_doc.get("tenant_id") or data.agent_id
        else:
            tenant_user = await db_inner["users"].find_one({"tenant_id": data.agent_id})
            if not tenant_user:
                raise HTTPException(status_code=401, detail="Unknown agent tenant")
            mapped_tenant = data.agent_id
            agent_doc = tenant_user

        expected_secret = (agent_doc or {}).get("agent_secret")
        if expected_secret:
            if not hmac.compare_digest(data.agent_secret, expected_secret):
                raise HTTPException(status_code=401, detail="Invalid Agent Credentials")
        else:
            if not hmac.compare_digest(data.agent_secret, AGENT_MASTER_SECRET):
                raise HTTPException(status_code=401, detail="Invalid Agent Credentials")

    except HTTPException:
        raise
    except Exception as e:
        print(f"🔴 Agent login DB error: {e}")
        raise HTTPException(status_code=503, detail="Agent verification service unavailable")

    access_token = create_access_token(
        data={"sub": data.agent_id, "type": "agent", "tenant_id": mapped_tenant}, 
        expires_delta=timedelta(hours=24)
    )
    return {"access_token": access_token, "token_type": "bearer"}

@router.post("/update-plan")
async def update_plan(data: PlanUpdate, db=Depends(get_db), current_user=Depends(get_current_user)):
    secure_username = current_user["username"]
    
    await db.users.update_one(
        {"username": secure_username},
        {"$set": {
            "plan_type": data.plan_name, 
            "has_active_plan": True
        }}
    )
    
    db_user = await db.users.find_one({"username": secure_username})
    tenant_id = db_user.get("tenant_id", "WARSOC_DEFAULT")
    access_token = create_access_token(
        data={"sub": db_user["username"], "type": "user", "tenant_id": tenant_id}, 
        expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    return {
        "access_token": access_token, 
        "token_type": "bearer",
        "username": db_user["username"],
        "tenant_id": tenant_id,
        "plan_type": db_user.get("plan_type", "Free"),
        "has_active_plan": db_user.get("has_active_plan", False)
    }