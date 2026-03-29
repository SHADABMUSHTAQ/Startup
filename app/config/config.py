import json
import os
from functools import lru_cache
from pathlib import Path

# --- FIX FOR PYDANTIC V2 COMPATIBILITY ---
try:
    from pydantic_settings import BaseSettings
except ImportError:
    from pydantic import BaseSettings

class Settings(BaseSettings):
    # --- INFRASTRUCTURE ---
    jwt_secret_key: str = os.getenv("JWT_SECRET_KEY", "")
    agent_master_secret: str = os.getenv("AGENT_MASTER_SECRET", "")
    mongodb_uri: str = os.getenv("MONGODB_URI", "mongodb://localhost:27017")
    mongodb_db_name: str = os.getenv("MONGODB_DB_NAME", "WarSOC_DB")
    redis_url: str = os.getenv("REDIS_URL", "redis://localhost:6379")
    
    # --- API SECURITY ---
    port: int = int(os.getenv("PORT", 8000))
    secret_key: str = os.getenv("SECRET_KEY", "")
    algorithm: str = "HS256"
    access_token_expire_minutes: int = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", 30))

    # --- SERVER ---
    backend_public_url: str = os.getenv("BACKEND_PUBLIC_URL", "http://127.0.0.1:8000")
    allowed_origins: str = os.getenv("ALLOWED_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173")

    # --- PRIVACY & ENCRYPTION ---
    encryption_key: str = os.getenv("ENCRYPTION_KEY", "")

    class Config:
        env_file = ".env"
        extra = "ignore"  # Extra env vars won't crash the app

@lru_cache()
def get_settings():
    s = Settings()
    # Fail fast: refuse to start if critical secrets are missing
    if not s.jwt_secret_key:
        raise RuntimeError("FATAL: JWT_SECRET_KEY is not set. Check your .env file.")
    if not s.agent_master_secret:
        raise RuntimeError("FATAL: AGENT_MASTER_SECRET is not set. Check your .env file.")
    return s

def load_config(config_file: str = "config.json") -> dict:
    """
    Loads config.json dynamically relative to this file's location.
    """
    # 1. Resolve Path: app/config/config.json
    base_dir = Path(__file__).resolve().parent
    config_path = base_dir / config_file
    
    # 2. Rich Default Configuration (Merged from Old Code)
    default_config = {
        "threat_intelligence": {
            "ips": [],
            "files": ["data/blacklist_ip.txt"]
        },
        "whitelist": {
            "ips": ["127.0.0.1", "::1"]
        },
        "detection": {
            "brute_force_threshold": 3,
            "port_scan_threshold": 10,
            # ✅ Rich Rules from Old Code Added Here
            "failed_login_patterns": [
                "failed password", "authentication failure", "login failed",
                "invalid user", "access denied", "authentication error", "wrong password"
            ],
            "suspicious_keywords": [
                "malware", "trojan", "exploit", "ransomware", "backdoor", 
                "cmd.exe", "/bin/sh", "wget", "curl", "base64"
            ]
        },
        "system": {
            "max_file_size_mb": 100,
            "log_level": "INFO"
        }
    }
    
    # 3. Merge Logic (User Config overrides Defaults)
    if config_path.exists():
        try:
            with open(config_path, 'r') as f:
                user_config = json.load(f)
                for section, settings in user_config.items():
                    if section in default_config and isinstance(settings, dict):
                        default_config[section].update(settings)
                    else:
                        default_config[section] = settings
            print(f"✅ [WarSOC Config] Loaded custom rules from {config_path}")
        except Exception as e:
            print(f"⚠️ Config Load Error: {e} - Using Defaults")
    else:
        print(f"ℹ️ Config file not found at {config_path}, running in SAFE MODE.")
    
    return default_config