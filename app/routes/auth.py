from fastapi import APIRouter, HTTPException, status, Depends
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel, EmailStr
from app.database import get_db
from passlib.context import CryptContext
from datetime import datetime, timedelta, timezone
from typing import Optional
import jwt
import uuid
import redis.asyncio as aioredis
from app.config.config import get_settings

settings = get_settings()
router = APIRouter()

# --- CONFIGURATION ---
# Secrets are now pulled securely from settings/.env
SECRET_KEY = settings.jwt_secret_key if hasattr(settings, 'jwt_secret_key') else "warsoc_secret_key_change_this_in_production"
AGENT_MASTER_SECRET = settings.agent_master_secret if hasattr(settings, 'agent_master_secret') else "warsoc_enterprise_agent_key_2026"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
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
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta if expires_delta else timedelta(minutes=15))
    jti = str(uuid.uuid4()) # Unique Token ID for precision blacklisting
    to_encode.update({"exp": expire, "jti": jti})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

# 🚨 FAIL-CLOSED REDIS BLACKLIST
async def is_token_blacklisted(jti: str) -> bool:
    try:
        r = await aioredis.from_url(settings.redis_url, decode_responses=True)
        is_blacklisted = await r.exists(f"warsoc:blacklist:{jti}")
        await r.close()
        return is_blacklisted > 0
    except Exception as e:
        print(f"🔴 CRITICAL: Redis Down - Failing SECURE. Locking out token.")
        return True # Fail-Closed: Deny access if Redis cannot verify

# --- DEPENDENCIES ---
async def get_current_user(token: str = Depends(oauth2_scheme), db=Depends(get_db)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        jti: str = payload.get("jti")
        username: str = payload.get("sub")
        
        if await is_token_blacklisted(jti):
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
    return user

async def verify_agent_token(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        jti: str = payload.get("jti")
        agent_id: str = payload.get("sub")
        token_type: str = payload.get("type")
        
        if await is_token_blacklisted(jti):
            raise HTTPException(status_code=401, detail="Agent token revoked.")

        if agent_id is None or token_type != "agent":
            raise HTTPException(status_code=401, detail="Invalid agent token")
        return agent_id
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Unauthorized Agent")

# --- ROUTES ---
@router.post("/signup", status_code=status.HTTP_201_CREATED)
async def signup(user: UserCreate, db=Depends(get_db)):
    existing_user = await db.users.find_one({"$or": [{"email": user.email}, {"username": user.username}]})
    if existing_user:
        raise HTTPException(status_code=400, detail="Username or Email already registered")

    hashed_password = get_password_hash(user.password)
    new_tenant_id = f"WARSOC_{str(uuid.uuid4())[:8].upper()}" # Generate isolated tenant ID

    new_user = {
        "username": user.username,
        "email": user.email,
        "full_name": user.full_name,
        "hashed_password": hashed_password,
        "tenant_id": new_tenant_id,
        "plan_type": "Free",
        "has_active_plan": False,
        "created_at": datetime.now(timezone.utc)
    }
    await db.users.insert_one(new_user)
    return {"message": "User created successfully", "tenant_id": new_tenant_id}

class LoginSchema(BaseModel):
    username: str
    password: str

@router.post("/login")
async def login(user_data: LoginSchema, db=Depends(get_db)):
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
        "plan_type": db_user.get("plan_type", "Free")
    }

@router.get("/me")
async def get_user_me(current_user=Depends(get_current_user)):
    return {
        "username": current_user["username"],
        "email": current_user["email"],
        "full_name": current_user.get("full_name", ""),
        "tenant_id": current_user.get("tenant_id"),
        "plan_type": current_user.get("plan_type", "Free"),
        "has_active_plan": current_user.get("has_active_plan", False) # 🚨 Added this back!
    }

@router.post("/agent-login")
async def agent_login(data: AgentLogin):
    if data.agent_secret != AGENT_MASTER_SECRET:
        raise HTTPException(status_code=401, detail="Invalid Agent Credentials")
    access_token = create_access_token(
        data={"sub": data.agent_id, "type": "agent"}, 
        expires_delta=timedelta(hours=24)
    )
    return {"access_token": access_token, "token_type": "bearer"}

# ---------------------------------------------------------
# SUBSCRIPTION / PLAN UPDATE
# ---------------------------------------------------------
@router.post("/update-plan")
async def update_plan(data: PlanUpdate, db=Depends(get_db), current_user=Depends(get_current_user)):
    """
    Updates the user's subscription plan after a successful payment.
    Locked down: Only updates the plan for the currently authenticated user.
    """
    # 🚨 CTO FIX: We ignore data.username from the frontend payload to prevent spoofing.
    # We ONLY trust the username cryptographically verified in the JWT.
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
        "has_active_plan": db_user.get("has_active_plan", False) # 🚨 Added this back!
    }