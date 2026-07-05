import json
import os
from functools import lru_cache
from pathlib import Path
from urllib.parse import urlparse

# --- FIX FOR PYDANTIC V2 COMPATIBILITY ---
try:
    from pydantic_settings import BaseSettings
except ImportError:
    from pydantic import BaseSettings

class Settings(BaseSettings):
    # --- INFRASTRUCTURE ---
    jwt_secret_key: str = os.getenv("JWT_SECRET_KEY", "")
    mongodb_uri: str = os.getenv("MONGODB_URI", "mongodb://localhost:27017")
    mongodb_db_name: str = os.getenv("MONGODB_DB_NAME", "WarSOC_DB")
    redis_url: str = os.getenv("REDIS_URL", "redis://localhost:6379")

    # --- RETENTION / KEY MANAGEMENT ---
    # Number of days to retain forensic logs (used to create TTL index)
    log_retention_days: int = int(os.getenv("LOG_RETENTION_DAYS", 365))
    # Optionally provide private key material via an environment variable
    # (base64-encoded PEM). This is preferred for secure hosting environments.
    private_key_b64: str = os.getenv("PRIVATE_KEY_B64", "")
    public_key_b64: str = os.getenv("PUBLIC_KEY_B64", "")
    # If the private key PEM is password-protected, provide the passphrase here.
    private_key_password: str = os.getenv("PRIVATE_KEY_PASSWORD", "")

    # --- API SECURITY ---
    port: int = int(os.getenv("PORT", 8000))
    secret_key: str = os.getenv("SECRET_KEY", "")
    algorithm: str = "HS256"
    access_token_expire_minutes: int = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", 30))
    agent_token_expire_minutes: int = int(os.getenv("AGENT_TOKEN_EXPIRE_MINUTES", 525600))
    provisioning_token_expire_minutes: int = int(os.getenv("PROVISIONING_TOKEN_EXPIRE_MINUTES", 60))
    enable_self_signup: bool = os.getenv("ENABLE_SELF_SIGNUP", "false").strip().lower() in {"1", "true", "yes"}

    # --- SERVER ---
    environment: str = os.getenv("APP_ENV", "development")
    backend_public_url: str = os.getenv("BACKEND_PUBLIC_URL", "http://127.0.0.1:8000")
    allowed_origins: str = os.getenv("ALLOWED_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173")
    enable_legacy_routes: bool = os.getenv("ENABLE_LEGACY_ROUTES", "false").strip().lower() in {"1", "true", "yes"}
    metrics_allowlist_ips: str = os.getenv("METRICS_ALLOWLIST_IPS", "127.0.0.1,::1")
    metrics_bearer_token: str = os.getenv("METRICS_BEARER_TOKEN", "")

    # --- PRIVACY & ENCRYPTION ---
    encryption_key: str = os.getenv("ENCRYPTION_KEY", "")

    # --- EXTERNAL INTEGRATIONS ---
    vt_api_key: str = os.getenv("VT_API_KEY", "")
    agent_cdn_url: str = os.getenv("AGENT_CDN_URL", "")

    # --- TRANSACTIONAL EMAIL (Zoho Mail) ---
    zoho_smtp_host: str = os.getenv("ZOHO_SMTP_HOST", "smtp.zoho.com")
    zoho_smtp_port: int = int(os.getenv("ZOHO_SMTP_PORT", "587"))
    zoho_smtp_user: str = os.getenv("ZOHO_SMTP_USER", "")
    zoho_smtp_pass: str = os.getenv("ZOHO_SMTP_PASS", "")

    class Config:
        env_file = ".env"
        extra = "ignore"  # Extra env vars won't crash the app


def _looks_like_placeholder(value: str) -> bool:
    normalized = str(value or "").strip().upper()
    return (
        not normalized
        or normalized.startswith("REPLACE_WITH")
        or "REPLACE_WITH" in normalized
        or normalized in {"CHANGE_ME", "CHANGEME", "TODO", "PLACEHOLDER"}
        or "LOCALHOST" in normalized
        or "127.0.0.1" in normalized
    )


def _is_valid_agent_cdn_url(value: str) -> bool:
    parsed = urlparse(str(value or "").strip())
    return (
        parsed.scheme == "https"
        and bool(parsed.netloc)
        and parsed.path.lower().endswith(".exe")
    )


def ensure_keys_exist():
    """
    Ensure RSA key pair exists on disk (keys/private_key.pem and keys/public_key.pem).
    If they are missing and no environment variables (PRIVATE_KEY_B64 / PUBLIC_KEY_B64) are set,
    dynamically generate a new secure 2048-bit RSA key pair.
    """
    if os.getenv("PRIVATE_KEY_B64") or os.getenv("PUBLIC_KEY_B64"):
        return

    base_dir = Path(__file__).resolve().parent.parent.parent
    keys_dir = base_dir / "keys"
    priv_path = keys_dir / "private_key.pem"
    pub_path = keys_dir / "public_key.pem"

    if priv_path.exists() and pub_path.exists():
        return

    try:
        keys_dir.mkdir(parents=True, exist_ok=True)
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives import serialization

        print("[KEYS] RSA Master keys not found on disk. Generating fresh secure RSA-2048 key pair...")
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )

        pem_private = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )

        public_key = private_key.public_key()
        pem_public = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        priv_path.write_bytes(pem_private)
        pub_path.write_bytes(pem_public)
        print(f"[KEYS] Generated fresh Master Key pair at {priv_path} and {pub_path}")
    except Exception as e:
        print(f"[KEYS] [ERROR] Error generating dynamic Master Keys: {e}")


@lru_cache()
def get_settings():
    ensure_keys_exist()
    s = Settings()
    # Fail fast: refuse to start if critical secrets are missing
    if not s.jwt_secret_key:
        raise RuntimeError("FATAL: JWT_SECRET_KEY is not set. Check your .env file.")
    if s.environment.lower() == "production":
        required_values = {
            "JWT_SECRET_KEY": s.jwt_secret_key,
            "SUPER_ADMIN_API_KEY": os.getenv("SUPER_ADMIN_API_KEY", ""),
            "ENCRYPTION_KEY": s.encryption_key,
            "PRIVATE_KEY_B64": s.private_key_b64,
            "MONGODB_URI": s.mongodb_uri,
            "REDIS_URL": s.redis_url,
            "AGENT_CDN_URL": s.agent_cdn_url,
        }
        missing = [name for name, value in required_values.items() if _looks_like_placeholder(value)]
        if missing:
            raise RuntimeError(f"FATAL: Missing production secrets: {', '.join(missing)}")
        if not _is_valid_agent_cdn_url(s.agent_cdn_url):
            raise RuntimeError("FATAL: AGENT_CDN_URL must be an HTTPS URL that points directly to the Windows installer .exe.")
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
            print(f" [WarSOC Config] Loaded custom rules from {config_path}")
        except Exception as e:
            print(f" Config Load Error: {e} - Using Defaults")
    else:
        print(f" Config file not found at {config_path}, running in SAFE MODE.")

    return default_config
