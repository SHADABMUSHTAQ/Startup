import json
import os
import re
from functools import lru_cache
from packaging.version import InvalidVersion, Version
from pathlib import Path
from urllib.parse import urlparse

# --- FIX FOR PYDANTIC V2 COMPATIBILITY ---
try:
    from pydantic_settings import BaseSettings, SettingsConfigDict
except ImportError:
    from pydantic import BaseSettings
    SettingsConfigDict = None

class Settings(BaseSettings):
    if SettingsConfigDict is not None:
        model_config = SettingsConfigDict(env_file=".env", extra="ignore")

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
    enable_manual_log_injection: bool = os.getenv(
        "ENABLE_MANUAL_LOG_INJECTION", "false"
    ).strip().lower() in {"1", "true", "yes"}
    metrics_allowlist_ips: str = os.getenv("METRICS_ALLOWLIST_IPS", "127.0.0.1,::1")
    metrics_bearer_token: str = os.getenv("METRICS_BEARER_TOKEN", "")

    # --- PRIVACY & ENCRYPTION ---
    encryption_key: str = os.getenv("ENCRYPTION_KEY", "")
    source_envelope_encryption_key: str = os.getenv(
        "SOURCE_ENVELOPE_ENCRYPTION_KEY", ""
    )
    source_envelope_key_id: str = os.getenv(
        "SOURCE_ENVELOPE_KEY_ID", "source-envelope-v1"
    ).strip()
    source_envelope_key_version: int = int(
        os.getenv("SOURCE_ENVELOPE_KEY_VERSION", "1")
    )
    source_envelope_decryption_keys_json: str = os.getenv(
        "SOURCE_ENVELOPE_DECRYPTION_KEYS_JSON", "{}"
    ).strip()

    # --- EXTERNAL INTEGRATIONS ---
    vt_api_key: str = os.getenv("VT_API_KEY", "")
    agent_cdn_url: str = os.getenv("AGENT_CDN_URL", "")
    agent_event_signature_mode: str = os.getenv(
        "AGENT_EVENT_SIGNATURE_MODE", "observe"
    ).strip().lower()
    network_relay_enabled: bool = os.getenv(
        "NETWORK_RELAY_ENABLED", "false"
    ).strip().lower() in {"1", "true", "yes"}
    network_relay_activation_ttl_seconds: int = int(
        os.getenv("NETWORK_RELAY_ACTIVATION_TTL_SECONDS", "3600")
    )
    network_relay_max_batch_events: int = int(
        os.getenv("NETWORK_RELAY_MAX_BATCH_EVENTS", "200")
    )
    network_relay_max_body_bytes: int = int(
        os.getenv("NETWORK_RELAY_MAX_BODY_BYTES", str(1024 * 1024))
    )
    network_relay_max_per_tenant: int = int(
        os.getenv("NETWORK_RELAY_MAX_PER_TENANT", "2")
    )
    network_relay_device_silence_seconds: int = int(
        os.getenv("NETWORK_RELAY_DEVICE_SILENCE_SECONDS", "900")
    )
    network_relay_minimum_version: str = os.getenv(
        "NETWORK_RELAY_MINIMUM_VERSION", "0.0.0"
    ).strip()
    network_relay_installer_url: str = os.getenv(
        "NETWORK_RELAY_INSTALLER_URL", ""
    ).strip()
    network_relay_watchdog_interval_seconds: int = int(
        os.getenv("NETWORK_RELAY_WATCHDOG_INTERVAL_SECONDS", "300")
    )
    # Generic external detection remains isolated and disabled until every
    # shadow acceptance gate has passed. It never owns FBR or PECA evidence.
    wazuh_detection_mode: str = os.getenv(
        "WAZUH_DETECTION_MODE", "disabled"
    ).strip().lower()
    wazuh_connector_id: str = os.getenv("WAZUH_CONNECTOR_ID", "wazuh-shadow-01").strip()
    wazuh_engine_instance_id: str = os.getenv(
        "WAZUH_ENGINE_INSTANCE_ID", "wazuh-node-01"
    ).strip()
    wazuh_engine_version: str = os.getenv("WAZUH_ENGINE_VERSION", "4.14.7").strip()
    wazuh_ruleset_version: str = os.getenv("WAZUH_RULESET_VERSION", "").strip()
    wazuh_rule_registry_sha256: str = os.getenv(
        "WAZUH_RULE_REGISTRY_SHA256", ""
    ).strip().lower()
    wazuh_dispatch_url: str = os.getenv("WAZUH_DISPATCH_URL", "").strip()
    wazuh_dispatch_signing_secret: str = os.getenv(
        "WAZUH_DISPATCH_SIGNING_SECRET", ""
    )
    wazuh_candidate_signing_secret: str = os.getenv(
        "WAZUH_CANDIDATE_SIGNING_SECRET", ""
    )
    wazuh_outbox_encryption_key: str = os.getenv(
        "WAZUH_OUTBOX_ENCRYPTION_KEY", ""
    )
    wazuh_correlation_hmac_key: str = os.getenv(
        "WAZUH_CORRELATION_HMAC_KEY", ""
    )
    wazuh_correlation_key_version: str = os.getenv(
        "WAZUH_CORRELATION_KEY_VERSION", "corr-v1"
    ).strip()
    wazuh_max_batch_events: int = int(os.getenv("WAZUH_MAX_BATCH_EVENTS", "100"))
    wazuh_max_body_bytes: int = int(os.getenv("WAZUH_MAX_BODY_BYTES", str(512 * 1024)))
    wazuh_live_event_max_age_seconds: int = int(
        os.getenv("WAZUH_LIVE_EVENT_MAX_AGE_SECONDS", "60")
    )
    wazuh_projector_batch_size: int = int(os.getenv("WAZUH_PROJECTOR_BATCH_SIZE", "250"))
    wazuh_dispatch_batch_size: int = int(os.getenv("WAZUH_DISPATCH_BATCH_SIZE", "100"))
    wazuh_dispatch_max_attempts: int = int(os.getenv("WAZUH_DISPATCH_MAX_ATTEMPTS", "8"))
    wazuh_dispatch_timeout_seconds: int = int(os.getenv("WAZUH_DISPATCH_TIMEOUT_SECONDS", "10"))
    wazuh_outbox_max_bytes: int = int(
        os.getenv("WAZUH_OUTBOX_MAX_BYTES", str(256 * 1024 * 1024))
    )
    wazuh_outbox_record_ttl_days: int = int(os.getenv("WAZUH_OUTBOX_RECORD_TTL_DAYS", "30"))
    wazuh_shadow_retention_days: int = int(os.getenv("WAZUH_SHADOW_RETENTION_DAYS", "30"))
    wazuh_candidate_clock_skew_seconds: int = int(
        os.getenv("WAZUH_CANDIDATE_CLOCK_SKEW_SECONDS", "30")
    )
    wazuh_candidate_delivery_max_age_seconds: int = int(
        os.getenv("WAZUH_CANDIDATE_DELIVERY_MAX_AGE_SECONDS", "86400")
    )
    wazuh_dispatch_ca_file: str = os.getenv("WAZUH_DISPATCH_CA_FILE", "").strip()
    wazuh_dispatch_cert_file: str = os.getenv("WAZUH_DISPATCH_CERT_FILE", "").strip()
    wazuh_dispatch_key_file: str = os.getenv("WAZUH_DISPATCH_KEY_FILE", "").strip()
    wazuh_candidate_ca_file: str = os.getenv("WAZUH_CANDIDATE_CA_FILE", "").strip()
    wazuh_candidate_server_cert_file: str = os.getenv(
        "WAZUH_CANDIDATE_SERVER_CERT_FILE", ""
    ).strip()
    wazuh_candidate_server_key_file: str = os.getenv(
        "WAZUH_CANDIDATE_SERVER_KEY_FILE", ""
    ).strip()
    wazuh_primary_approved: bool = os.getenv(
        "WAZUH_PRIMARY_APPROVED", "false"
    ).strip().lower() in {"1", "true", "yes"}

    # --- TRANSACTIONAL EMAIL (Zoho Mail) ---
    zoho_smtp_host: str = os.getenv("ZOHO_SMTP_HOST", "smtp.zoho.com")
    zoho_smtp_port: int = int(os.getenv("ZOHO_SMTP_PORT", "587"))
    zoho_smtp_user: str = os.getenv("ZOHO_SMTP_USER", "")
    zoho_smtp_pass: str = os.getenv("ZOHO_SMTP_PASS", "")
    enable_security_alert_emails: bool = os.getenv(
        "ENABLE_SECURITY_ALERT_EMAILS", "false"
    ).strip().lower() in {"1", "true", "yes"}

    if SettingsConfigDict is None:
        class Config:
            env_file = ".env"
            extra = "ignore"


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


def _has_minimum_secret_length(value: str, minimum_bytes: int = 32) -> bool:
    """Validate opaque production secrets without logging their contents."""
    try:
        return len(str(value or "").encode("utf-8")) >= minimum_bytes
    except UnicodeEncodeError:
        return False


def _is_valid_agent_cdn_url(value: str) -> bool:
    return _is_valid_https_download_url(value, suffix=".exe")


def _is_valid_https_download_url(value: str, *, suffix: str) -> bool:
    parsed = urlparse(str(value or "").strip())
    return (
        parsed.scheme == "https"
        and bool(parsed.netloc)
        and parsed.path.lower().endswith(suffix)
        and not parsed.username
        and not parsed.password
        and not parsed.query
        and not parsed.fragment
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


def _validate_network_relay_version_gate(s: "Settings") -> None:
    """An enabled relay feature must always carry an explicit minimum relay
    version. The 0.0.0/empty default means "gate disabled", so starting with
    the feature on and the variable unset would silently accept every relay
    build — refuse to boot instead (fail-closed)."""
    if not s.network_relay_enabled:
        return
    minimum_version = (s.network_relay_minimum_version or "").strip()
    if minimum_version in {"", "0.0.0"}:
        raise RuntimeError(
            "FATAL: NETWORK_RELAY_ENABLED=true requires an explicit "
            "NETWORK_RELAY_MINIMUM_VERSION (e.g. 1.0.0) so the relay version "
            "gate cannot be silently disabled."
        )
    try:
        Version(minimum_version)
    except InvalidVersion as exc:
        raise RuntimeError(
            "FATAL: NETWORK_RELAY_MINIMUM_VERSION must be a valid PEP 440 version string."
        ) from exc


def _validate_network_relay_watchdog_settings(s: "Settings") -> None:
    if not s.network_relay_enabled:
        return
    interval = s.network_relay_watchdog_interval_seconds
    if not 30 <= interval <= 86400:
        raise RuntimeError(
            "FATAL: NETWORK_RELAY_WATCHDOG_INTERVAL_SECONDS must be between "
            "30 and 86400 when network relay is enabled."
        )


@lru_cache()
def get_settings():
    ensure_keys_exist()
    s = Settings()
    # Fail fast: refuse to start if critical secrets are missing
    if not s.jwt_secret_key:
        raise RuntimeError("FATAL: JWT_SECRET_KEY is not set. Check your .env file.")
    # The relay version gate must never silently default to disabled.
    _validate_network_relay_version_gate(s)
    _validate_network_relay_watchdog_settings(s)
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
        weak_secrets = [
            name
            for name, value in {
                "JWT_SECRET_KEY": s.jwt_secret_key,
                "SUPER_ADMIN_API_KEY": os.getenv("SUPER_ADMIN_API_KEY", ""),
            }.items()
            if not _has_minimum_secret_length(value)
        ]
        if weak_secrets:
            raise RuntimeError(
                "FATAL: Production secrets must be at least 32 UTF-8 bytes: "
                + ", ".join(weak_secrets)
            )
        from cryptography.fernet import Fernet

        try:
            Fernet((s.source_envelope_encryption_key or s.encryption_key).encode("ascii"))
        except (AttributeError, TypeError, ValueError) as exc:
            raise RuntimeError(
                "FATAL: SOURCE_ENVELOPE_ENCRYPTION_KEY or ENCRYPTION_KEY must be a Fernet key."
            ) from exc
        if not re.fullmatch(r"[A-Za-z0-9._-]{3,64}", s.source_envelope_key_id):
            raise RuntimeError("FATAL: SOURCE_ENVELOPE_KEY_ID is invalid.")
        if s.source_envelope_key_version < 1:
            raise RuntimeError("FATAL: SOURCE_ENVELOPE_KEY_VERSION must be at least 1.")
        try:
            historical_source_keys = json.loads(s.source_envelope_decryption_keys_json or "{}")
        except json.JSONDecodeError as exc:
            raise RuntimeError(
                "FATAL: SOURCE_ENVELOPE_DECRYPTION_KEYS_JSON must be valid JSON."
            ) from exc
        if not isinstance(historical_source_keys, dict):
            raise RuntimeError(
                "FATAL: SOURCE_ENVELOPE_DECRYPTION_KEYS_JSON must be a JSON object."
            )
        for historical_key_id, historical_entry in historical_source_keys.items():
            if not re.fullmatch(r"[A-Za-z0-9._-]{3,64}", str(historical_key_id)):
                raise RuntimeError(
                    "FATAL: SOURCE_ENVELOPE_DECRYPTION_KEYS_JSON contains an invalid key ID."
                )
            if isinstance(historical_entry, str):
                historical_key = historical_entry
            elif isinstance(historical_entry, dict):
                historical_key = historical_entry.get("key", "")
                historical_version = historical_entry.get("version", 1)
                if not isinstance(historical_version, int) or historical_version < 1:
                    raise RuntimeError(
                        "FATAL: Historical source-envelope key versions must be positive integers."
                    )
            else:
                raise RuntimeError(
                    "FATAL: Historical source-envelope keys must be strings or key/version objects."
                )
            try:
                Fernet(str(historical_key).encode("ascii"))
            except (AttributeError, TypeError, ValueError, UnicodeEncodeError) as exc:
                raise RuntimeError(
                    "FATAL: SOURCE_ENVELOPE_DECRYPTION_KEYS_JSON contains an invalid Fernet key."
                ) from exc
        if not _is_valid_agent_cdn_url(s.agent_cdn_url):
            raise RuntimeError("FATAL: AGENT_CDN_URL must be an HTTPS URL that points directly to the Windows installer .exe.")
        if s.agent_event_signature_mode not in {"observe", "required"}:
            raise RuntimeError("FATAL: AGENT_EVENT_SIGNATURE_MODE must be 'observe' or 'required'.")
        if not 300 <= s.network_relay_activation_ttl_seconds <= 86400:
            raise RuntimeError(
                "FATAL: NETWORK_RELAY_ACTIVATION_TTL_SECONDS must be between 300 and 86400."
            )
        if not 1 <= s.network_relay_max_batch_events <= 1000:
            raise RuntimeError(
                "FATAL: NETWORK_RELAY_MAX_BATCH_EVENTS must be between 1 and 1000."
            )
        if not 65536 <= s.network_relay_max_body_bytes <= 5 * 1024 * 1024:
            raise RuntimeError(
                "FATAL: NETWORK_RELAY_MAX_BODY_BYTES must be between 65536 and 5242880."
            )
        if not 1 <= s.network_relay_max_per_tenant <= 10:
            raise RuntimeError(
                "FATAL: NETWORK_RELAY_MAX_PER_TENANT must be between 1 and 10."
            )
        if not 180 <= s.network_relay_device_silence_seconds <= 86400:
            raise RuntimeError(
                "FATAL: NETWORK_RELAY_DEVICE_SILENCE_SECONDS must be between 180 and 86400."
            )
        try:
            Version(s.network_relay_minimum_version)
        except InvalidVersion as exc:
            raise RuntimeError(
                "FATAL: NETWORK_RELAY_MINIMUM_VERSION must be a valid PEP 440 version string."
            ) from exc
        if s.network_relay_installer_url and not _is_valid_https_download_url(
            s.network_relay_installer_url,
            suffix=".zip",
        ):
            raise RuntimeError(
                "FATAL: NETWORK_RELAY_INSTALLER_URL must be an HTTPS URL that "
                "points directly to the versioned relay setup .zip."
            )
        if s.wazuh_detection_mode not in {"disabled", "shadow", "primary"}:
            raise RuntimeError(
                "FATAL: WAZUH_DETECTION_MODE must be 'disabled', 'shadow', or 'primary'."
            )
        if s.wazuh_detection_mode == "primary" and not s.wazuh_primary_approved:
            raise RuntimeError(
                "FATAL: WAZUH primary mode requires WAZUH_PRIMARY_APPROVED=true."
            )
        if s.wazuh_detection_mode != "disabled":
            from cryptography.fernet import Fernet

            wazuh_required_values = {
                "WAZUH_RULESET_VERSION": s.wazuh_ruleset_version,
                "WAZUH_RULE_REGISTRY_SHA256": s.wazuh_rule_registry_sha256,
                "WAZUH_DISPATCH_URL": s.wazuh_dispatch_url,
                "WAZUH_DISPATCH_SIGNING_SECRET": s.wazuh_dispatch_signing_secret,
                "WAZUH_CANDIDATE_SIGNING_SECRET": s.wazuh_candidate_signing_secret,
                "WAZUH_OUTBOX_ENCRYPTION_KEY": s.wazuh_outbox_encryption_key,
                "WAZUH_CORRELATION_HMAC_KEY": s.wazuh_correlation_hmac_key,
                "WAZUH_DISPATCH_CA_FILE": s.wazuh_dispatch_ca_file,
                "WAZUH_DISPATCH_CERT_FILE": s.wazuh_dispatch_cert_file,
                "WAZUH_DISPATCH_KEY_FILE": s.wazuh_dispatch_key_file,
                "WAZUH_CANDIDATE_CA_FILE": s.wazuh_candidate_ca_file,
                "WAZUH_CANDIDATE_SERVER_CERT_FILE": s.wazuh_candidate_server_cert_file,
                "WAZUH_CANDIDATE_SERVER_KEY_FILE": s.wazuh_candidate_server_key_file,
            }
            missing_wazuh = [
                name for name, value in wazuh_required_values.items() if not str(value or "").strip()
            ]
            if missing_wazuh:
                raise RuntimeError(
                    f"FATAL: Missing Wazuh integration configuration: {', '.join(missing_wazuh)}"
                )
            parsed_wazuh_url = urlparse(s.wazuh_dispatch_url)
            if parsed_wazuh_url.scheme != "https" or not parsed_wazuh_url.netloc:
                raise RuntimeError("FATAL: WAZUH_DISPATCH_URL must be a private HTTPS URL.")
            if not re.fullmatch(r"[a-f0-9]{64}", s.wazuh_rule_registry_sha256):
                raise RuntimeError(
                    "FATAL: WAZUH_RULE_REGISTRY_SHA256 must be a SHA-256 hex digest."
                )
            if len(s.wazuh_dispatch_signing_secret.encode("utf-8")) < 32:
                raise RuntimeError("FATAL: WAZUH_DISPATCH_SIGNING_SECRET must be at least 32 bytes.")
            if len(s.wazuh_candidate_signing_secret.encode("utf-8")) < 32:
                raise RuntimeError("FATAL: WAZUH_CANDIDATE_SIGNING_SECRET must be at least 32 bytes.")
            if len(s.wazuh_correlation_hmac_key.encode("utf-8")) < 32:
                raise RuntimeError("FATAL: WAZUH_CORRELATION_HMAC_KEY must be at least 32 bytes.")
            try:
                Fernet(s.wazuh_outbox_encryption_key.encode("ascii"))
            except (TypeError, ValueError) as exc:
                raise RuntimeError("FATAL: WAZUH_OUTBOX_ENCRYPTION_KEY must be a Fernet key.") from exc
            if not 1 <= s.wazuh_max_batch_events <= 500:
                raise RuntimeError("FATAL: WAZUH_MAX_BATCH_EVENTS must be between 1 and 500.")
            if not 65536 <= s.wazuh_max_body_bytes <= 5 * 1024 * 1024:
                raise RuntimeError("FATAL: WAZUH_MAX_BODY_BYTES must be between 65536 and 5242880.")
            if not 10 <= s.wazuh_live_event_max_age_seconds <= 900:
                raise RuntimeError(
                    "FATAL: WAZUH_LIVE_EVENT_MAX_AGE_SECONDS must be between 10 and 900."
                )
            if not 1 <= s.wazuh_projector_batch_size <= 1000:
                raise RuntimeError("FATAL: WAZUH_PROJECTOR_BATCH_SIZE must be between 1 and 1000.")
            if not 1 <= s.wazuh_dispatch_batch_size <= s.wazuh_max_batch_events:
                raise RuntimeError(
                    "FATAL: WAZUH_DISPATCH_BATCH_SIZE must be between 1 and WAZUH_MAX_BATCH_EVENTS."
                )
            if not 1 <= s.wazuh_dispatch_max_attempts <= 20:
                raise RuntimeError("FATAL: WAZUH_DISPATCH_MAX_ATTEMPTS must be between 1 and 20.")
            if not 2 <= s.wazuh_dispatch_timeout_seconds <= 60:
                raise RuntimeError("FATAL: WAZUH_DISPATCH_TIMEOUT_SECONDS must be between 2 and 60.")
            if not 16 * 1024 * 1024 <= s.wazuh_outbox_max_bytes <= 2 * 1024 * 1024 * 1024:
                raise RuntimeError("FATAL: WAZUH_OUTBOX_MAX_BYTES must be between 16 MiB and 2 GiB.")
            if not 1 <= s.wazuh_outbox_record_ttl_days <= 365:
                raise RuntimeError("FATAL: WAZUH_OUTBOX_RECORD_TTL_DAYS must be between 1 and 365.")
            if not 1 <= s.wazuh_shadow_retention_days <= 180:
                raise RuntimeError("FATAL: WAZUH_SHADOW_RETENTION_DAYS must be between 1 and 180.")
            if not 0 <= s.wazuh_candidate_clock_skew_seconds <= 300:
                raise RuntimeError(
                    "FATAL: WAZUH_CANDIDATE_CLOCK_SKEW_SECONDS must be between 0 and 300."
                )
            if not 300 <= s.wazuh_candidate_delivery_max_age_seconds <= 7 * 24 * 60 * 60:
                raise RuntimeError(
                    "FATAL: WAZUH_CANDIDATE_DELIVERY_MAX_AGE_SECONDS must be between 300 and 604800."
                )
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
