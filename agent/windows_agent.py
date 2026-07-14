import win32evtlog
import win32security
import requests
import time
import socket
import subprocess
import os
import sys
import json
import ipaddress
import threading
import glob
import hashlib
import uuid
import copy
import xml.etree.ElementTree as ET
from pathlib import Path
from datetime import datetime, timezone # ADDED TIMEZONE

# ENV COMPLIANCE
from dotenv import load_dotenv, find_dotenv

# ==========================================
# 1. ENTERPRISE CONFIG & STATE
# ==========================================
def _get_runtime_dir():
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent

# HARDENED ENV DISCOVERY: Searching for the Source of Truth
_AGENT_DIR = _get_runtime_dir()
_POSSIBLE_ENV_PATHS = [
    _AGENT_DIR / ".env",                     # Local
    _AGENT_DIR.parent / ".env",              # Parent (Root)
    _AGENT_DIR.parent / "startup-backend" / ".env" # Sibling (Cross-Repo)
]

env_loaded = False
for path in _POSSIBLE_ENV_PATHS:
    if path.exists():
        print(f"[INFO] CONFIG FOUND: Loading secrets from -> {path}")
        load_dotenv(str(path), override=True)
        env_loaded = True
        break

if not env_loaded:
    print(f"[WARN] .env not found in any standard location. Using system environment variables.")

BACKEND_URL = os.getenv("BACKEND_URL", "http://127.0.0.1:8000").rstrip('/')
AGENT_VERSION = "4.2.1-Native"
TENANT_ID = os.getenv("TENANT_ID", "provision").strip() or "provision"
PROGRAM_DATA_DIR = Path(os.getenv("PROGRAMDATA", str(_AGENT_DIR))) / "WarSOC"
JWT_TOKEN_PATH = PROGRAM_DATA_DIR / ".agent_jwt"
AGENT_ID_PATH = PROGRAM_DATA_DIR / ".agent_id"
PRIVATE_KEY_PATH = PROGRAM_DATA_DIR / "agent_private_key.pem"
LEGACY_JWT_TOKEN_PATH = _AGENT_DIR / ".agent_jwt"
LEGACY_AGENT_ID_PATH = _AGENT_DIR / ".agent_id"
LEGACY_PRIVATE_KEY_PATH = _AGENT_DIR / "agent_private_key.pem"


def _read_state_text(primary_path, legacy_path):
    try:
        if primary_path.exists():
            return primary_path.read_text(encoding="utf-8").strip()
        if legacy_path.exists():
            value = legacy_path.read_text(encoding="utf-8").strip()
            try:
                PROGRAM_DATA_DIR.mkdir(parents=True, exist_ok=True)
                primary_path.write_text(value, encoding="utf-8")
                try:
                    legacy_path.unlink()
                except OSError:
                    pass
            except Exception:
                pass
            return value
    except Exception:
        pass
    return ""


_STORED_AGENT_ID = _read_state_text(AGENT_ID_PATH, LEGACY_AGENT_ID_PATH)

AGENT_ID = os.getenv("AGENT_ID", _STORED_AGENT_ID or TENANT_ID).strip() or TENANT_ID
ACTIVATION_CODE = os.getenv("ACTIVATION_CODE", "").strip()

# NEW: Web Server Log File Path (You can change this to your Apache/Nginx path later)
WEB_LOG_PATH = os.getenv("WEB_LOG_PATH", "access.log")
POS_AUDIT_LOG_PATH = PROGRAM_DATA_DIR / "pos_audit.log"
POS_AUDIT_QUARANTINE_PATH = PROGRAM_DATA_DIR / "quarantine" / "pos_audit_rejected.jsonl"
POS_AUDIT_OFFSET_PATH = PROGRAM_DATA_DIR / "pos_audit.offset"
TELEMETRY_DEPLOY_EVIDENCE_PATH = PROGRAM_DATA_DIR / "telemetry-deploy.json"

WHITELIST_IPS = set(["127.0.0.1", "localhost", "::1", "0.0.0.0"])
POLL_INTERVAL = float(os.getenv("WINDOWS_EVENT_POLL_INTERVAL", "2"))
HEARTBEAT_INTERVAL = 300
OUTBOUND_BATCH_SIZE = int(os.getenv("OUTBOUND_BATCH_SIZE", "25"))
OUTBOUND_BATCH_WAIT_SECONDS = float(os.getenv("OUTBOUND_BATCH_WAIT_SECONDS", "0.25"))
INGEST_URL = f"{BACKEND_URL}/api/v1/ingest/pulse"
LOCAL_IP = "127.0.0.1"
WEB_LOG_PATHS = [WEB_LOG_PATH, str(POS_AUDIT_LOG_PATH), "firewall.log"]
WINDOWS_CHANNELS = ["Security", "System"]
TELEMETRY_CONFIG_VERSION = "native-windows-v1"
CHANNEL_STATUS = {}
CHANNEL_STATUS_LOCK = threading.Lock()
SENSOR_COUNTERS = {
    "windows_parse_failures": 0,
    "pos_jsonl_rejections": 0,
    "channel_failures": 0,
    "spool_write_failures": 0,
    "spool_limit_hits": 0,
}
POS_AUDIT_REQUIRED_FIELDS = {
    "event_id",
    "event_uid",
    "invoice_id",
    "timestamp",
    "actor",
    "source_system",
}
POS_AUDIT_OPTIONAL_FIELDS = {
    "reason",
    "before_hash",
    "after_hash",
    "metadata",
}
POS_AUDIT_ALLOWED_EVENT_IDS = {"FBR-INV-MOD", "FBR-INV-DEL"}

_STORED_JWT_TOKEN = _read_state_text(JWT_TOKEN_PATH, LEGACY_JWT_TOKEN_PATH)

JWT_TOKEN = os.getenv("JWT_TOKEN", "").strip() or _STORED_JWT_TOKEN or None
BANNED_IPS = set()
BAN_LOCK = threading.Lock()
REQUEST_SESSION = requests.Session()

# ==========================================
# 2. HELPER FUNCTIONS & MITIGATION
# ==========================================
def _clear_cached_agent_identity(reason):
    global JWT_TOKEN, AGENT_ID
    JWT_TOKEN = None
    AGENT_ID = TENANT_ID
    for state_path in (
        JWT_TOKEN_PATH,
        AGENT_ID_PATH,
        LEGACY_JWT_TOKEN_PATH,
        LEGACY_AGENT_ID_PATH,
    ):
        try:
            if state_path.exists():
                state_path.unlink()
        except Exception:
            pass
    print(f"[WARN] Cleared cached agent identity: {reason}")


def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"

LOCAL_IP = get_local_ip()


def _load_or_create_signing_key():
    global JWT_TOKEN, AGENT_ID
    from cryptography.hazmat.primitives.asymmetric import ed25519
    from cryptography.hazmat.primitives import serialization
    PROGRAM_DATA_DIR.mkdir(parents=True, exist_ok=True)
    if not PRIVATE_KEY_PATH.exists() and LEGACY_PRIVATE_KEY_PATH.exists():
        try:
            PRIVATE_KEY_PATH.write_bytes(LEGACY_PRIVATE_KEY_PATH.read_bytes())
            LEGACY_PRIVATE_KEY_PATH.unlink()
        except Exception:
            pass
    readable_private_key_path = (
        PRIVATE_KEY_PATH
        if PRIVATE_KEY_PATH.exists()
        else LEGACY_PRIVATE_KEY_PATH
    )
    if not readable_private_key_path.exists() and JWT_TOKEN:
        _clear_cached_agent_identity("cached token existed without an agent signing key")

    try:
        if readable_private_key_path.exists():
            pem_data = readable_private_key_path.read_bytes()
            private_key = serialization.load_pem_private_key(pem_data, password=None)
            if isinstance(private_key, ed25519.Ed25519PrivateKey):
                return private_key

            backup_path = readable_private_key_path.with_suffix(
                readable_private_key_path.suffix + f".unsupported-{int(time.time())}.bak"
            )
            try:
                readable_private_key_path.replace(backup_path)
                print(f"[WARN] Replaced unsupported legacy agent signing key: {backup_path}")
            except Exception as exc:
                print(f"[WARN] Could not quarantine unsupported legacy signing key: {exc}")
            _clear_cached_agent_identity("legacy signing key was not Ed25519")
    except Exception:
        _clear_cached_agent_identity("agent signing key was unreadable")

    signing_key = ed25519.Ed25519PrivateKey.generate()
    pem = signing_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    PRIVATE_KEY_PATH.write_bytes(pem)
    return signing_key


def _consume_activation_secret():
    global ACTIVATION_CODE

    env_path = _AGENT_DIR / ".env"
    try:
        if env_path.exists():
            retained = [
                line
                for line in env_path.read_text(encoding="utf-8").splitlines()
                if not line.strip().upper().startswith("ACTIVATION_CODE=")
            ]
            temporary_path = env_path.with_suffix(".env.tmp")
            temporary_path.write_text("\n".join(retained) + "\n", encoding="utf-8")
            os.replace(temporary_path, env_path)
    except Exception as exc:
        print(f"[WARN] Could not remove consumed activation code from .env: {exc}")

    legacy_config_path = _AGENT_DIR / "config.json"
    try:
        if legacy_config_path.exists():
            config = json.loads(legacy_config_path.read_text(encoding="utf-8"))
            if isinstance(config, dict):
                config.pop("activation_code", None)
                legacy_config_path.write_text(
                    json.dumps(config, separators=(",", ":")),
                    encoding="utf-8",
                )
    except Exception as exc:
        print(f"[WARN] Could not scrub legacy activation config: {exc}")

    ACTIVATION_CODE = ""
    os.environ.pop("ACTIVATION_CODE", None)


def _canonical_json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)


def _build_event_payload_hash(payload):
    signable_payload = {
        "source_ip": payload.get("source_ip", ""),
        "user": payload.get("user", ""),
        "event_id": str(payload.get("event_id", "")),
        "message": payload.get("message", ""),
        "processed_data": payload.get("processed_data") or {},
        "raw_event_data": payload.get("raw_event_data") if payload.get("raw_event_data") is not None else payload.get("raw_data", {}),
    }
    canonical = _canonical_json(signable_payload)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _build_ingest_envelope(events):
    return {
        "nonce": uuid.uuid4().hex,
        "timestamp": int(time.time()),
        "payload": events,
    }


def _signed_agent_post(path, payload, signing_key, timeout=10):
    body = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    signature = signing_key.sign(body).hex()
    headers = {
        "Content-Type": "application/json",
        "X-WarSOC-Signature": signature,
    }
    return REQUEST_SESSION.post(
        f"{BACKEND_URL}{path}",
        data=body,
        headers=headers,
        timeout=timeout,
    )


def register_agent(signing_key):
    global JWT_TOKEN, AGENT_ID
    from cryptography.hazmat.primitives import serialization
    activation_code = ACTIVATION_CODE or os.getenv("ACTIVATION_CODE", "").strip()
    if not activation_code:
        print("[!] No ACTIVATION_CODE present. Agent cannot enroll automatically.")
        return False

    public_key = signing_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode("utf-8")

    resp = REQUEST_SESSION.post(
        f"{BACKEND_URL}/api/v1/agent/register",
        json={
            "activation_code": activation_code,
            "public_key": public_key
        },
        timeout=10,
    )
    if resp.status_code in (200, 201):
        data = resp.json()
        agent_jwt = data.get("agent_jwt")
        agent_id = data.get("agent_id")
        if not agent_jwt or not agent_id:
            print(f"[FAIL] Agent registration response missing token or agent_id: {data}")
            return False

        JWT_TOKEN = agent_jwt
        AGENT_ID = agent_id
        try:
            JWT_TOKEN_PATH.write_text(agent_jwt, encoding="utf-8")
            AGENT_ID_PATH.write_text(agent_id, encoding="utf-8")
        except Exception as exc:
            print(f"[WARN] Could not persist agent identity: {exc}")

        _consume_activation_secret()
        print("[OK] Agent registered with Ed25519 public key and JWT.")
        return True
    print(f"[FAIL] Agent enrollment failed: {resp.status_code} - {resp.text}")
    return False

import re as _re
_IP_PATTERN = _re.compile(r'^[\d.:a-fA-F]+(/\d{1,3})?$')
_IP_IN_TEXT_PATTERN = _re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')

def _load_monitoring_document():
    """Load monitoring document from tenant policy first, then app config."""
    agent_dir = _get_runtime_dir()
    policy_path = agent_dir / "tenant_policy.json"
    config_json_path = agent_dir.parent / "app" / "config" / "config.json"

    for cfg_path in [policy_path, config_json_path]:
        try:
            if not cfg_path.exists():
                continue
            with open(cfg_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            continue
    return {}

def load_target_event_ids():
    """Load monitorable Event IDs only from config sources (no hardcoded defaults)."""
    def _parse_target_ids(raw):
        try:
            parsed = {str(eid).strip() for eid in raw if str(eid).strip()}
            return parsed
        except Exception:
            return set()

    monitoring = _load_monitoring_document().get("monitoring", {})
    parsed = _parse_target_ids(monitoring.get("target_event_ids", []))
    if parsed:
        return parsed

    print("[!] No monitorable Event IDs found in tenant_policy.json or config.json")
    return set()

def load_capture_all_security_events():
    """Load whether to capture all security events from config sources."""
    monitoring = _load_monitoring_document().get("monitoring", {})
    return bool(monitoring.get("capture_all_security_events", False))

def load_capture_all_windows_channels():
    monitoring = _load_monitoring_document().get("monitoring", {})
    return bool(monitoring.get("capture_all_windows_channels", False))

def load_windows_channels():
    monitoring = _load_monitoring_document().get("monitoring", {})
    channels = monitoring.get("windows_channels", ["Security", "System"])
    parsed = [str(c).strip() for c in channels if str(c).strip()]
    if not parsed:
        parsed = ["Security", "System"]
    return list(dict.fromkeys(parsed))

def load_web_log_paths():
    monitoring = _load_monitoring_document().get("monitoring", {})
    configured = monitoring.get("web_log_paths", [])
    parsed = [os.path.expandvars(str(p).strip()) for p in configured if str(p).strip()]
    if not parsed:
        parsed = [WEB_LOG_PATH, str(POS_AUDIT_LOG_PATH)]
    return list(dict.fromkeys(parsed))

def load_heartbeat_interval():
    """Load the agent heartbeat interval from config sources, with env override."""
    env_value = os.getenv("HEARTBEAT_INTERVAL")
    if env_value:
        try:
            value = int(env_value)
            return value if value > 0 else 300
        except Exception:
            pass

    agent_settings = _load_monitoring_document().get("agent_settings", {})
    try:
        value = int(agent_settings.get("heartbeat_interval_seconds", 300))
        return value if value > 0 else 300
    except Exception:
        return 300

def load_max_payload_bytes():
    """Load max ingest payload bytes from config (fallback to 1MB)."""
    security = _load_monitoring_document().get("agent_security", {})
    try:
        value = int(security.get("max_payload_bytes", 1048576))
        return value if value > 0 else 1048576
    except Exception:
        return 1048576

TARGET_EVENT_IDS = load_target_event_ids()
CAPTURE_ALL_SECURITY_EVENTS = load_capture_all_security_events()
CAPTURE_ALL_WINDOWS_CHANNELS = load_capture_all_windows_channels()
WINDOWS_CHANNELS = load_windows_channels()
WEB_LOG_PATHS = load_web_log_paths()
HEARTBEAT_INTERVAL = load_heartbeat_interval()
MAX_PAYLOAD_BYTES = load_max_payload_bytes()
# Keep a safety margin to avoid borderline payloads after HTTP serialization overhead.
MAX_OUTBOUND_BYTES = int(MAX_PAYLOAD_BYTES * 0.90)

def extract_source_ip_from_line(line: str):
    """Try to recover client IP from a web log line; return None when unavailable."""
    for candidate in _IP_IN_TEXT_PATTERN.findall(line):
        try:
            ip_obj = ipaddress.ip_address(candidate)
            if ip_obj.is_multicast or ip_obj.is_unspecified:
                continue
            return candidate
        except ValueError:
            continue
    return None

KNOWN_BAD_IPS = set()
FAILED_BLOCK_IPS = set()

def enforce_block(ip):
    if ip in WHITELIST_IPS:
        print(f"[WARN] SAFETY OVERRIDE: {ip} is whitelisted. Ignored.")
        return

    # Check if already seen (valid or invalid) to avoid spamming
    if ip in KNOWN_BAD_IPS or ip in BANNED_IPS or ip in FAILED_BLOCK_IPS:
        return

    if not _IP_PATTERN.match(ip):
        KNOWN_BAD_IPS.add(ip)
        print(f"[!] INVALID IP rejected: {ip}")
        return

    with BAN_LOCK:
        if ip in BANNED_IPS: return
        try:
            subprocess.run(
                ["netsh", "advfirewall", "firewall", "add", "rule",
                 f"name=WarSOC_Block_{ip}", "dir=in", "action=block", f"remoteip={ip}"],
                check=True, capture_output=True, text=True
            )
            BANNED_IPS.add(ip)
            print(f"[INFO] MITIGATION SUCCESS: Block applied to {ip}")
        except Exception as e:
            FAILED_BLOCK_IPS.add(ip)
            print(f"[!] MITIGATION FAILED: {e}")

# ==========================================
# 3. ENTERPRISE AUTHENTICATION PIPELINE
# ==========================================
def authenticate_agent():
    global JWT_TOKEN
    if JWT_TOKEN:
        return True

    signing_key = _load_or_create_signing_key()
    print("[INFO] Registering agent with WarSOC activation service...")
    try:
        return register_agent(signing_key)
    except Exception as e:
        print(f"[!] Backbone Unreachable: {e}")
        return False

def secure_request(method, url, **kwargs):
    global JWT_TOKEN
    if not JWT_TOKEN:
        if not authenticate_agent(): return None

    headers = kwargs.get("headers", {})
    headers["Authorization"] = f"Bearer {JWT_TOKEN}"
    kwargs["headers"] = headers

    try:
        resp = REQUEST_SESSION.request(method, url, **kwargs)

        if method == "POST" and "ingest" in url and resp.status_code in (200, 202):
             pass # Silently succeed to avoid console spam

        if resp.status_code == 401:
            print("[WARN] Agent token rejected. Clearing cached token and retrying activation path...")
            JWT_TOKEN = None
            try:
                if JWT_TOKEN_PATH.exists():
                    JWT_TOKEN_PATH.unlink()
            except Exception:
                pass
            if authenticate_agent():
                headers["Authorization"] = f"Bearer {JWT_TOKEN}"
                kwargs["headers"] = headers
                resp = REQUEST_SESSION.request(method, url, **kwargs)

        elif resp.status_code not in (200, 202):
            print(f" Backend rejected payload {resp.status_code}: {resp.text}")

        return resp
    except Exception as e:
        print(f"[WARN] Connection Error to {url}: {e}")
        return None

# ==========================================
# 2.5 FORENSIC SPOOLER & PARSER (v3.1)
# ==========================================
import re as _re
import shutil


class SpoolWriteError(OSError):
    """Raised when an event cannot be made durable on local disk."""


class DiskSpooler:
    """
    MASTER BUILD: Atomic 'Rotate & Drain' Spooler.
    Ensures zero-loss resilience via OS-level renames (Renaming is atomic).
    """
    def __init__(
        self,
        spool_dir="spool",
        max_bytes=None,
        resume_bytes=None,
        min_free_bytes=None,
    ):
        self.spool_dir = Path(spool_dir)
        self.pending_file = self.spool_dir / "pending_logs.jsonl"
        self.dead_letter_file = self.spool_dir / "rejected_logs.jsonl"
        self.lock = threading.Lock()
        self.max_bytes = int(max_bytes or os.getenv("AGENT_SPOOL_MAX_BYTES", str(500 * 1024 * 1024)))
        self.resume_bytes = int(resume_bytes or os.getenv("AGENT_SPOOL_RESUME_BYTES", str(400 * 1024 * 1024)))
        self.min_free_bytes = int(min_free_bytes or os.getenv("AGENT_MIN_FREE_DISK_BYTES", str(2 * 1024 * 1024 * 1024)))
        if self.max_bytes <= 0:
            raise ValueError("AGENT_SPOOL_MAX_BYTES must be positive")
        if not 0 <= self.resume_bytes < self.max_bytes:
            raise ValueError("AGENT_SPOOL_RESUME_BYTES must be lower than AGENT_SPOOL_MAX_BYTES")
        if self.min_free_bytes < 0:
            raise ValueError("AGENT_MIN_FREE_DISK_BYTES cannot be negative")
        self.backpressure_active = False
        self.backpressure_reason = ""

        # Ensure spool environment exists
        self.spool_dir.mkdir(parents=True, exist_ok=True)
        print(f"[*] DiskSpooler Active: {self.pending_file}")

    def _usage_bytes_unlocked(self):
        total = 0
        for path in self.spool_dir.glob("*.jsonl"):
            try:
                if path.is_file():
                    total += path.stat().st_size
            except OSError:
                continue
        return total

    def _capacity_snapshot_unlocked(self):
        usage_bytes = self._usage_bytes_unlocked()
        try:
            free_bytes = shutil.disk_usage(self.spool_dir).free
        except OSError:
            free_bytes = 0
        return usage_bytes, free_bytes

    def _raise_backpressure_unlocked(self, reason):
        self.backpressure_active = True
        self.backpressure_reason = reason
        with CHANNEL_STATUS_LOCK:
            SENSOR_COUNTERS["spool_limit_hits"] += 1
        raise SpoolWriteError(reason)

    def _ensure_capacity_unlocked(self, additional_bytes):
        usage_bytes, free_bytes = self._capacity_snapshot_unlocked()
        projected_usage = usage_bytes + max(0, int(additional_bytes))
        projected_free = free_bytes - max(0, int(additional_bytes))

        if self.backpressure_active:
            recovered = usage_bytes <= self.resume_bytes and projected_free >= self.min_free_bytes
            if not recovered:
                self._raise_backpressure_unlocked(
                    self.backpressure_reason or "Agent spool remains above its safe resume boundary"
                )
            self.backpressure_active = False
            self.backpressure_reason = ""

        if projected_usage > self.max_bytes:
            self._raise_backpressure_unlocked(
                f"Agent spool hard limit reached ({projected_usage} > {self.max_bytes} bytes)"
            )
        if projected_free < self.min_free_bytes:
            self._raise_backpressure_unlocked(
                f"Agent disk reserve reached ({projected_free} < {self.min_free_bytes} free bytes)"
            )

    def status(self):
        with self.lock:
            usage_bytes, free_bytes = self._capacity_snapshot_unlocked()
            if (
                self.backpressure_active
                and usage_bytes <= self.resume_bytes
                and free_bytes >= self.min_free_bytes
            ):
                self.backpressure_active = False
                self.backpressure_reason = ""
            return {
                "usage_bytes": usage_bytes,
                "max_bytes": self.max_bytes,
                "resume_bytes": self.resume_bytes,
                "min_free_bytes": self.min_free_bytes,
                "free_bytes": free_bytes,
                "blocked": self.backpressure_active,
                "reason": self.backpressure_reason or None,
            }

    def append(self, log_dict):
        """Thread-safe append-only write to the pending buffer."""
        try:
            line = json.dumps(log_dict, default=str) + "\n"
            encoded_size = len(line.encode("utf-8"))
            with self.lock:
                self._ensure_capacity_unlocked(encoded_size)
                with open(self.pending_file, "a", encoding="utf-8") as f:
                    f.write(line)
                    f.flush()
                    os.fsync(f.fileno())
            return True
        except Exception as e:
            with CHANNEL_STATUS_LOCK:
                SENSOR_COUNTERS["spool_write_failures"] += 1
            print(f"[!] Spooler Append Error: {e}")
            raise SpoolWriteError(str(e)) from e

    def quarantine(self, log_dict, reason):
        """Durably retain events rejected by the backend for later inspection."""
        entry = {
            "quarantined_at": datetime.now(timezone.utc).isoformat(),
            "reason": str(reason)[:1000],
            "event": log_dict,
        }
        line = json.dumps(entry, ensure_ascii=False, default=str) + "\n"
        try:
            with self.lock:
                self._ensure_capacity_unlocked(len(line.encode("utf-8")))
                with open(self.dead_letter_file, "a", encoding="utf-8") as f:
                    f.write(line)
                    f.flush()
                    os.fsync(f.fileno())
        except Exception as exc:
            with CHANNEL_STATUS_LOCK:
                SENSOR_COUNTERS["spool_write_failures"] += 1
            raise SpoolWriteError(str(exc)) from exc

    def consume_batch(self):
        """
        THE ROTATE: Atomically renames pending to processing.
        Returns (logs_list, filename) if data exists, else (None, None).
        """
        # 1. Check for abandoned processing files from previous crashes
        existing_processing = list(self.spool_dir.glob("processing_*.jsonl"))
        if existing_processing:
            target_file = sorted(existing_processing)[0] # Process oldest first
            return self._read_file(target_file), str(target_file)

        # 2. Rotate pending to a new processing artifact
        with self.lock:
            if not self.pending_file.exists() or os.path.getsize(self.pending_file) == 0:
                return None, None

            timestamp = int(time.time() * 1000)
            processing_file = self.spool_dir / f"processing_{timestamp}.jsonl"

            try:
                os.rename(str(self.pending_file), str(processing_file))
            except Exception as e:
                print(f"[!] Spooler Rotation Error: {e}")
                return None, None

        return self._read_file(processing_file), str(processing_file)

    def _read_file(self, file_path):
        """Helper to read jsonl into list of dicts."""
        logs = []
        malformed_count = 0
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        parsed = json.loads(line)
                        if isinstance(parsed, dict):
                            logs.append(parsed)
                        else:
                            malformed_count += 1
                            self.quarantine(
                                {"raw_spool_record": parsed},
                                f"malformed_spool_record:{file_path}",
                            )
                    except json.JSONDecodeError:
                        malformed_count += 1
                        self.quarantine(
                            {"raw_spool_line": line},
                            f"malformed_spool_json:{file_path}",
                        )

            if malformed_count:
                print(f"[!] Spooler skipped {malformed_count} malformed JSONL records from {file_path}")
            return logs
        except Exception as e:
            print(f"[!] Spooler Read Error ({file_path}): {e}")
            return []

    def clear_batch(self, file_path):
        """Permanently deletes the processing artifact after 200 OK."""
        try:
            if os.path.exists(file_path):
                os.remove(file_path)
        except Exception as e:
            print(f"[!] Spooler Cleanup Error: {e}")

# Global Spooler Instance
SPOOLER = DiskSpooler(PROGRAM_DATA_DIR / "spool")

def _xml_local_name(tag):
    return str(tag or "").split("}", 1)[-1]


def parse_windows_event_xml(xml_text):
    """Parse Windows Event XML into locale-independent system and event fields."""
    root = ET.fromstring(xml_text)
    namespace = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
    system_node = root.find("e:System", namespace)
    if system_node is None:
        raise ValueError("Windows event XML has no System node")

    def _system_text(name, default=""):
        node = system_node.find(f"e:{name}", namespace)
        return str(node.text or default).strip() if node is not None else default

    provider_node = system_node.find("e:Provider", namespace)
    time_node = system_node.find("e:TimeCreated", namespace)
    security_node = system_node.find("e:Security", namespace)
    event_id = _system_text("EventID")
    system_data = {
        "provider": provider_node.attrib.get("Name", "") if provider_node is not None else "",
        "channel": _system_text("Channel"),
        "computer": _system_text("Computer"),
        "event_record_id": _system_text("EventRecordID"),
        "level": _system_text("Level"),
        "task": _system_text("Task"),
        "opcode": _system_text("Opcode"),
        "keywords": _system_text("Keywords"),
        "system_time": time_node.attrib.get("SystemTime", "") if time_node is not None else "",
        "user_id": security_node.attrib.get("UserID", "") if security_node is not None else "",
    }

    fields = {}
    event_data_node = root.find("e:EventData", namespace)
    if event_data_node is not None:
        unnamed_index = 0
        for data_node in list(event_data_node):
            if _xml_local_name(data_node.tag) != "Data":
                continue
            field_name = str(data_node.attrib.get("Name") or f"value_{unnamed_index}")
            unnamed_index += 1
            field_value = data_node.text or ""
            if field_name in fields:
                current = fields[field_name]
                fields[field_name] = current + [field_value] if isinstance(current, list) else [current, field_value]
            else:
                fields[field_name] = field_value

    user_data_node = root.find("e:UserData", namespace)
    if user_data_node is not None:
        for node in user_data_node.iter():
            if node is user_data_node or list(node):
                continue
            fields.setdefault(_xml_local_name(node.tag), node.text or "")

    processed = {
        "provider": system_data["provider"],
        "channel": system_data["channel"],
        "computer": system_data["computer"],
    }
    if event_id in {"4624", "4625"}:
        processed.update({
            "target_user": fields.get("TargetUserName") or fields.get("TargetUserSid"),
            "target_domain": fields.get("TargetDomainName"),
            "source_network_address": fields.get("IpAddress"),
            "source_port": fields.get("IpPort"),
            "logon_type": fields.get("LogonType"),
            "status": fields.get("Status"),
            "sub_status": fields.get("SubStatus"),
        })
    elif event_id == "4688":
        processed.update({
            "user": fields.get("SubjectUserName"),
            "new_process_name": fields.get("NewProcessName"),
            "new_process_id": fields.get("NewProcessId"),
            "parent_process_name": fields.get("ParentProcessName"),
            "command_line": fields.get("CommandLine"),
            "token_elevation_type": fields.get("TokenElevationType"),
        })
    elif event_id in {"1102", "4672"}:
        processed.update({
            "user": fields.get("SubjectUserName") or fields.get("SubjectUserSid"),
            "user_domain": fields.get("SubjectDomainName"),
            "subject_logon_id": fields.get("SubjectLogonId"),
            "privilege_list": fields.get("PrivilegeList"),
        })
    elif event_id == "4616":
        processed.update({
            "user": fields.get("SubjectUserName") or fields.get("SubjectUserSid"),
            "user_domain": fields.get("SubjectDomainName"),
            "previous_time": fields.get("PreviousTime"),
            "new_time": fields.get("NewTime"),
            "process_name": fields.get("ProcessName"),
        })
    elif event_id == "4648":
        processed.update({
            "user": fields.get("SubjectUserName") or fields.get("SubjectUserSid"),
            "user_domain": fields.get("SubjectDomainName"),
            "target_user": fields.get("TargetUserName") or fields.get("TargetUserSid"),
            "target_domain": fields.get("TargetDomainName"),
            "target_server": fields.get("TargetServerName"),
            "process_name": fields.get("ProcessName"),
            "source_network_address": fields.get("IpAddress"),
            "source_port": fields.get("IpPort"),
        })
    elif event_id in {"4720", "4726"}:
        processed.update({
            "user": fields.get("SubjectUserName") or fields.get("SubjectUserSid"),
            "user_domain": fields.get("SubjectDomainName"),
            "target_user": fields.get("TargetUserName") or fields.get("TargetSid"),
            "target_domain": fields.get("TargetDomainName"),
            "sam_account_name": fields.get("SamAccountName"),
        })
    elif event_id == "4732":
        processed.update({
            "user": fields.get("SubjectUserName") or fields.get("SubjectUserSid"),
            "user_domain": fields.get("SubjectDomainName"),
            "group_name": fields.get("TargetUserName") or fields.get("TargetSid"),
            "group_domain": fields.get("TargetDomainName"),
            "member_name": fields.get("MemberName") or fields.get("MemberSid"),
        })
    elif event_id == "4663":
        processed.update({
            "user": fields.get("SubjectUserName"),
            "object_type": fields.get("ObjectType"),
            "object_name": fields.get("ObjectName"),
            "handle_id": fields.get("HandleId"),
            "process_id": fields.get("ProcessId"),
            "process_name": fields.get("ProcessName"),
            "access_mask": fields.get("AccessMask"),
            "access_list": fields.get("AccessList"),
        })
    elif event_id == "4660":
        processed.update({
            "user": fields.get("SubjectUserName"),
            "handle_id": fields.get("HandleId"),
            "process_id": fields.get("ProcessId"),
            "process_name": fields.get("ProcessName"),
        })
    elif event_id == "4670":
        processed.update({
            "user": fields.get("SubjectUserName"),
            "object_type": fields.get("ObjectType"),
            "object_name": fields.get("ObjectName"),
            "handle_id": fields.get("HandleId"),
            "process_id": fields.get("ProcessId"),
            "process_name": fields.get("ProcessName"),
            "old_security_descriptor": fields.get("OldSd"),
            "new_security_descriptor": fields.get("NewSd"),
        })
    elif event_id == "4657":
        processed.update({
            "user": fields.get("SubjectUserName") or fields.get("SubjectUserSid"),
            "object_name": fields.get("ObjectName"),
            "object_value_name": fields.get("ObjectValueName"),
            "operation_type": fields.get("OperationType"),
            "old_value": fields.get("OldValue"),
            "new_value": fields.get("NewValue"),
            "process_name": fields.get("ProcessName"),
        })
    elif event_id in {"4697", "7045"}:
        processed.update({
            "user": fields.get("SubjectUserName") or fields.get("SubjectUserSid"),
            "service_name": fields.get("ServiceName"),
            "image_path": fields.get("ImagePath") or fields.get("ServiceFileName"),
            "service_type": fields.get("ServiceType"),
            "start_type": fields.get("StartType") or fields.get("ServiceStartType"),
            "service_account": fields.get("AccountName") or fields.get("ServiceAccount"),
        })
    elif event_id == "4698":
        processed.update({
            "user": fields.get("SubjectUserName") or fields.get("SubjectUserSid"),
            "task_name": fields.get("TaskName"),
            "task_content": fields.get("TaskContentNew") or fields.get("TaskContent"),
        })
    elif event_id == "4719":
        processed.update({
            "user": fields.get("SubjectUserName") or fields.get("SubjectUserSid"),
            "category_id": fields.get("CategoryId"),
            "subcategory_id": fields.get("SubcategoryId"),
            "audit_policy_changes": fields.get("AuditPolicyChanges"),
        })
    elif event_id == "4798":
        processed.update({
            "user": fields.get("SubjectUserName") or fields.get("SubjectUserSid"),
            "target_user": fields.get("TargetUserName") or fields.get("TargetSid"),
            "caller_process_name": fields.get("CallerProcessName"),
            "caller_process_id": fields.get("CallerProcessId"),
        })
    elif event_id in {"4768", "4769"}:
        processed.update({
            "user": fields.get("TargetUserName") or fields.get("TargetUserSid"),
            "target_user": fields.get("TargetUserName") or fields.get("TargetUserSid"),
            "service_name": fields.get("ServiceName"),
            "source_network_address": fields.get("IpAddress"),
            "source_port": fields.get("IpPort"),
            "status": fields.get("Status") or fields.get("FailureCode"),
            "ticket_options": fields.get("TicketOptions"),
            "pre_auth_type": fields.get("PreAuthType"),
        })
    elif event_id == "4776":
        processed.update({
            "user": fields.get("TargetUserName") or fields.get("TargetUserSid"),
            "target_user": fields.get("TargetUserName") or fields.get("TargetUserSid"),
            "workstation": fields.get("Workstation"),
            "status": fields.get("Status"),
            "authentication_package": fields.get("PackageName"),
        })
    elif event_id == "5140":
        processed.update({
            "user": fields.get("SubjectUserName") or fields.get("SubjectUserSid"),
            "source_network_address": fields.get("IpAddress"),
            "source_port": fields.get("IpPort"),
            "share_name": fields.get("ShareName"),
            "share_path": fields.get("ShareLocalPath"),
            "access_mask": fields.get("AccessMask"),
        })
    elif event_id in {"5156", "5157"}:
        processed.update({
            "user": fields.get("Application"),
            "application": fields.get("Application"),
            "source_network_address": fields.get("SourceAddress"),
            "source_port": fields.get("SourcePort"),
            "destination_address": fields.get("DestAddress"),
            "destination_port": fields.get("DestPort"),
            "protocol": fields.get("Protocol"),
        })

    processed = {key: value for key, value in processed.items() if value not in (None, "")}
    if event_id in {"4624", "4625"}:
        event_user = processed.get("target_user")
    else:
        event_user = processed.get("user") or processed.get("target_user")
    return {
        "event_id": event_id,
        "timestamp": system_data["system_time"] or datetime.now(timezone.utc).isoformat(),
        "event_uid": f"{system_data['channel']}:{system_data['event_record_id']}",
        "user": event_user or system_data["user_id"] or "SYSTEM",
        "source_ip": processed.get("source_network_address") or LOCAL_IP,
        "processed_data": processed,
        "raw_event_data": {
            "system": system_data,
            "event_data": fields,
            "event_xml": xml_text,
        },
    }


def build_windows_event_message(parsed):
    event_id = str(parsed.get("event_id") or "")
    processed = parsed.get("processed_data") or {}
    user = str(processed.get("user") or parsed.get("user") or "SYSTEM")
    target_user = str(processed.get("target_user") or "unknown account")
    source_ip = str(processed.get("source_network_address") or parsed.get("source_ip") or "local host")

    if event_id == "1100":
        return "Windows Event Log service stopped"
    if event_id == "1102":
        return f"Windows Security audit log cleared by {user}"
    if event_id == "4624":
        logon_type = processed.get("logon_type")
        suffix = f" (logon type {logon_type})" if logon_type else ""
        return f"Successful sign-in for {target_user} from {source_ip}{suffix}"
    if event_id == "4625":
        details = []
        if processed.get("logon_type"):
            details.append(f"logon type {processed['logon_type']}")
        if processed.get("status"):
            details.append(f"status {processed['status']}")
        suffix = f" ({', '.join(details)})" if details else ""
        return f"Failed sign-in for {target_user} from {source_ip}{suffix}"
    if event_id == "4672":
        return f"Administrative privileges assigned to {user}"
    if event_id == "4616":
        process_name = processed.get("process_name") or "unknown process"
        return f"System clock changed by {user} using {process_name}"
    if event_id == "4648":
        target = processed.get("target_user") or "unknown account"
        server = processed.get("target_server") or "unknown server"
        return f"Explicit credentials for {target} used by {user} against {server}"
    if event_id == "4688":
        process_name = processed.get("new_process_name") or "unknown process"
        message = f"Process started by {user}: {process_name}"
        if processed.get("command_line"):
            message += f"; command: {processed['command_line']}"
        if processed.get("parent_process_name"):
            message += f"; parent: {processed['parent_process_name']}"
        return message
    if event_id == "4720":
        return f"User account {target_user} created by {user}"
    if event_id == "4726":
        return f"User account {target_user} deleted by {user}"
    if event_id == "4732":
        member = processed.get("member_name") or "unknown member"
        group = processed.get("group_name") or "unknown local group"
        return f"{member} added to local group {group} by {user}"
    if event_id in {"4697", "7045"}:
        service = processed.get("service_name") or "unknown service"
        message = f"Windows service installed: {service}"
        if processed.get("image_path"):
            message += f"; executable: {processed['image_path']}"
        if processed.get("service_account"):
            message += f"; account: {processed['service_account']}"
        return message
    if event_id == "4719":
        change = processed.get("audit_policy_changes") or "audit policy changed"
        return f"Windows audit policy changed by {user}: {change}"
    if event_id in {"5156", "5157"}:
        destination = processed.get("destination_address") or "unknown destination"
        if processed.get("destination_port"):
            destination = f"{destination}:{processed['destination_port']}"
        source = source_ip
        if processed.get("source_port"):
            source = f"{source}:{processed['source_port']}"
        action = "permitted" if event_id == "5156" else "blocked"
        return f"Windows Firewall {action} connection from {source} to {destination}"
    if event_id == "4663":
        target = processed.get("object_name") or "protected object"
        return f"Delete access requested for {target} by {user}"
    if event_id == "4660":
        process_name = processed.get("process_name") or "unknown process"
        return f"Object deletion confirmed for handle {processed.get('handle_id') or 'unknown'} by {process_name}"
    if event_id == "4670":
        target = processed.get("object_name") or "protected object"
        return f"Permissions changed on {target} by {user}"
    if event_id == "4657":
        target = processed.get("object_name") or "registry value"
        value_name = processed.get("object_value_name")
        target_value = f"{target}\\{value_name}" if value_name else str(target)
        return f"Registry value changed by {user}: {target_value}"
    if event_id == "4698":
        return f"Scheduled task created by {user}: {processed.get('task_name') or 'unknown task'}"
    if event_id == "4798":
        process_name = processed.get("caller_process_name") or "unknown process"
        return f"Local group membership enumerated for {target_user} by {process_name}"
    if event_id == "4768":
        status = processed.get("status")
        suffix = f"; status {status}" if status else ""
        return f"Kerberos authentication ticket requested for {target_user} from {source_ip}{suffix}"
    if event_id == "4769":
        service = processed.get("service_name") or "unknown service"
        status = processed.get("status")
        suffix = f"; status {status}" if status else ""
        return f"Kerberos service ticket requested for {target_user} to {service} from {source_ip}{suffix}"
    if event_id == "4776":
        workstation = processed.get("workstation") or "unknown workstation"
        status = processed.get("status")
        suffix = f"; status {status}" if status else ""
        return f"Credential validation for {target_user} from {workstation}{suffix}"
    if event_id == "5140":
        share = processed.get("share_name") or "unknown network share"
        return f"Network share accessed by {user} from {source_ip}: {share}"

    event_fields = parsed.get("raw_event_data", {}).get("event_data", {})
    compact_fields = []
    for key, value in list(event_fields.items())[:4]:
        if value not in (None, "", "-"):
            compact_fields.append(f"{key}={value}")
    details = f": {', '.join(compact_fields)}" if compact_fields else ""
    return f"Windows event {event_id or 'unknown'}{details}"


def parse_pos_audit_line(line):
    try:
        record = json.loads(line)
    except json.JSONDecodeError as exc:
        raise ValueError("invalid JSON") from exc
    if not isinstance(record, dict):
        raise ValueError("record must be a JSON object")

    unknown_fields = set(record) - POS_AUDIT_REQUIRED_FIELDS - POS_AUDIT_OPTIONAL_FIELDS
    if unknown_fields:
        raise ValueError(f"unknown fields: {', '.join(sorted(unknown_fields))}")
    missing_fields = [
        field for field in sorted(POS_AUDIT_REQUIRED_FIELDS)
        if not str(record.get(field) or "").strip()
    ]
    if missing_fields:
        raise ValueError(f"missing fields: {', '.join(missing_fields)}")

    event_id = str(record["event_id"]).strip().upper()
    if event_id not in POS_AUDIT_ALLOWED_EVENT_IDS:
        raise ValueError("event_id is not an allowed invoice audit event")
    if "metadata" in record and not isinstance(record["metadata"], dict):
        raise ValueError("metadata must be an object")

    try:
        parsed_timestamp = datetime.fromisoformat(str(record["timestamp"]).replace("Z", "+00:00"))
        if parsed_timestamp.tzinfo is None:
            parsed_timestamp = parsed_timestamp.replace(tzinfo=timezone.utc)
    except Exception as exc:
        raise ValueError("timestamp must be ISO-8601") from exc

    normalized = dict(record)
    normalized["event_id"] = event_id
    normalized["event_uid"] = str(record["event_uid"]).strip()
    normalized["invoice_id"] = str(record["invoice_id"]).strip()
    normalized["actor"] = str(record["actor"]).strip()
    normalized["source_system"] = str(record["source_system"]).strip()
    normalized["timestamp"] = parsed_timestamp.astimezone(timezone.utc).isoformat()
    return normalized


def quarantine_pos_audit_line(line, reason, file_path):
    with CHANNEL_STATUS_LOCK:
        SENSOR_COUNTERS["pos_jsonl_rejections"] += 1
    try:
        POS_AUDIT_QUARANTINE_PATH.parent.mkdir(parents=True, exist_ok=True)
        if POS_AUDIT_QUARANTINE_PATH.exists() and POS_AUDIT_QUARANTINE_PATH.stat().st_size > 10 * 1024 * 1024:
            rotated = POS_AUDIT_QUARANTINE_PATH.with_suffix(".jsonl.1")
            if rotated.exists():
                rotated.unlink()
            POS_AUDIT_QUARANTINE_PATH.replace(rotated)
        entry = {
            "rejected_at": datetime.now(timezone.utc).isoformat(),
            "source_file": str(file_path),
            "reason": str(reason),
            "line_sha256": hashlib.sha256(line.encode("utf-8", errors="replace")).hexdigest(),
            "raw_line": line,
        }
        with open(POS_AUDIT_QUARANTINE_PATH, "a", encoding="utf-8") as quarantine:
            quarantine.write(json.dumps(entry, ensure_ascii=False, default=str) + "\n")
            quarantine.flush()
            os.fsync(quarantine.fileno())
    except Exception as exc:
        print(f"[WARN] Could not quarantine POS audit line: {exc}")
        raise SpoolWriteError(f"POS quarantine write failed: {exc}") from exc

def enqueue_payload(payload):
    """Make an outbound event durable before its source cursor can advance."""
    return SPOOLER.append(payload)

def _estimate_payload_bytes(batch):
    """Estimate encoded request size in bytes for a JSON batch."""
    try:
        return len(json.dumps(batch, default=str).encode("utf-8"))
    except Exception:
        return MAX_PAYLOAD_BYTES + 1

def _truncate_single_log_payload(single_log):
    """Best-effort compliance-safe truncation for a single oversize log."""
    marker = "[TRUNCATED_BY_AGENT_413_COMPLIANCE]"
    log = dict(single_log)

    if isinstance(log.get("raw_event_data"), str):
        log["raw_event_data"] = log["raw_event_data"][:300000] + "\n\n" + marker

    raw_data = log.get("raw_data")
    if isinstance(raw_data, str):
        log["raw_data"] = raw_data[:120000] + "\n\n" + marker
    elif isinstance(raw_data, dict):
        try:
            serialized_raw = json.dumps(raw_data, default=str)
            if len(serialized_raw.encode("utf-8")) > 200000:
                log["raw_data"] = {
                    "truncated": True,
                    "reason": marker,
                    "preview": serialized_raw[:120000],
                }
        except Exception:
            log["raw_data"] = {"truncated": True, "reason": marker}

    if isinstance(log.get("message"), str):
        log["message"] = log["message"][:4000]

    # Hard fallback if still too large after selective trimming.
    if _estimate_payload_bytes([log]) > MAX_OUTBOUND_BYTES:
        if "raw_event_data" in log:
            log["raw_event_data"] = marker
        log["raw_data"] = {"truncated": True, "reason": marker}
        if isinstance(log.get("message"), str):
            log["message"] = log["message"][:1000]

    return log

def ingest_sender_thread():
    global OUTBOUND_BATCH_SIZE, REQUEST_SESSION
    ORIGINAL_BATCH_SIZE = OUTBOUND_BATCH_SIZE # Store the baseline (e.g., 25)

    print(f"[*] Sender Online. Zero-Loss 'Rotate & Drain' Active. Batch Size: {OUTBOUND_BATCH_SIZE}")
    while True:
        try:
            # THE DRAIN: Fetch atomic processing batch
            batch, filename = SPOOLER.consume_batch()

            if batch is None:
                time.sleep(1) # Wait for new pending logs
                continue

            if not batch:
                # Clear empty/corrupt rotated artifact so it cannot deadlock sender loop.
                if filename:
                    SPOOLER.clear_batch(filename)
                time.sleep(1)
                continue

            all_success = True
            retain_original = False

            # CHUNK THE BATCH (dynamically uses updated OUTBOUND_BATCH_SIZE)
            for i in range(0, len(batch), OUTBOUND_BATCH_SIZE):
                chunk = batch[i:i + OUTBOUND_BATCH_SIZE]

                # Preflight split before network call to avoid 413/reset loops.
                chunk_bytes = _estimate_payload_bytes(chunk)
                if chunk_bytes > MAX_OUTBOUND_BYTES:
                    if len(chunk) > 1:
                        OUTBOUND_BATCH_SIZE = max(1, len(chunk) // 2)
                        print(f"[INFO] Preflight split: {len(chunk)} logs ({chunk_bytes} bytes) -> batch size {OUTBOUND_BATCH_SIZE}")
                        retain_original = True
                        all_success = False
                        break
                    else:
                        print(f"[WARN] Preflight single-log trim: {chunk_bytes} bytes > {MAX_OUTBOUND_BYTES} bytes")
                        chunk = [_truncate_single_log_payload(chunk[0])]

                # TRANSMISSION
                resp = secure_request("POST", INGEST_URL, json=_build_ingest_envelope(chunk), timeout=20)

                if resp and resp.status_code in (200, 202):
                    # SUCCESS: Reset batch size back to max if it was previously throttled
                    if OUTBOUND_BATCH_SIZE < ORIGINAL_BATCH_SIZE:
                        OUTBOUND_BATCH_SIZE = ORIGINAL_BATCH_SIZE
                    time.sleep(OUTBOUND_BATCH_WAIT_SECONDS)
                    continue

                elif resp and resp.status_code == 422:
                    # POISON PILL RECOVERY: Isolate malformed log
                    print(f"[WARN] Batch chunk rejected (422). Isolating broken records...")
                    transient_retry = False
                    for single_log in chunk:
                        sr = secure_request("POST", INGEST_URL, json=_build_ingest_envelope([single_log]), timeout=10)
                        if sr and sr.status_code in (200, 202):
                            continue

                        status = sr.status_code if sr else "timeout"
                        if sr and sr.status_code in (400, 422):
                            SPOOLER.quarantine(single_log, f"backend_rejected:{status}")
                            print(f"[QUARANTINE] Backend rejected forensic event: {single_log.get('event_id')}")
                        elif sr and sr.status_code == 413:
                            SPOOLER.append(_truncate_single_log_payload(single_log))
                            print(f"[WARN] Oversized isolated event trimmed and re-queued: {single_log.get('event_id')}")
                        else:
                            SPOOLER.append(single_log)
                            transient_retry = True
                            print(f"[WARN] Isolated event delivery deferred ({status}): {single_log.get('event_id')}")
                    if transient_retry:
                        time.sleep(5)
                    continue

                else:
                    # FAILURE RECOVERY STATE
                    code = resp.status_code if resp else "timeout"

                    if resp and resp.status_code == 413:
                        print(f"[FAIL] Backend rejected payload: 413.")

                        # Fix the Uvicorn Keep-Alive Socket Poisoning
                        # Uvicorn abruptly closes the socket on 413, poisoning our connection pool.
                        # This clears the broken socket to prevent the subsequent "timeout" error.
                        try:
                            REQUEST_SESSION.close()
                            REQUEST_SESSION = requests.Session()
                        except: pass

                        # -- STRATEGY 1: GLOBAL BATCH HALVING --
                        if len(chunk) > 1:
                            OUTBOUND_BATCH_SIZE = max(1, len(chunk) // 2)
                            print(f"[INFO] Halving OUTBOUND_BATCH_SIZE to {OUTBOUND_BATCH_SIZE} to respect 1MB limit...")
                            retain_original = True

                        # -- STRATEGY 2: SINGLE-LOG TRUNCATION --
                        else:
                            print(f"[WARN] Single log exceeds backend limit. Truncating and re-queuing it.")
                            SPOOLER.append(_truncate_single_log_payload(chunk[0]))
                            for remaining_log in batch[i + len(chunk):]:
                                SPOOLER.append(remaining_log)
                            OUTBOUND_BATCH_SIZE = ORIGINAL_BATCH_SIZE

                    else:
                        if resp and resp.status_code == 429:
                            print("[WARN] Backend rate limited (429). Backing off for 10s...")
                            retain_original = True
                            all_success = False
                            time.sleep(10)
                            break

                        # STANDARD UNAVAILABLE / TIMEOUT ERROR
                        print(f"[WARN] Backend Unavailable ({code}). Retrying in 5s...")
                        retain_original = True

                    all_success = False
                    time.sleep(5)
                    break

            # Keep the original artifact during transient failures. Re-reading may
            # redeliver an already accepted chunk, so backend event_uid idempotency
            # remains the final duplicate-suppression boundary.
            if not retain_original:
                SPOOLER.clear_batch(filename)

        except Exception as e:
            print(f"[!] Bulk Sender Crash: {e}")
            time.sleep(2)


def resolve_web_log_files():
    """Resolve configured web log files and glob patterns to concrete file paths."""
    resolved = []
    own_log_dir = (_AGENT_DIR / "logs").resolve()
    for path_pattern in WEB_LOG_PATHS:
        matches = glob.glob(path_pattern)
        if matches:
            resolved.extend(matches)
        elif os.path.exists(path_pattern):
            resolved.append(path_pattern)
    safe_paths = []
    for candidate in sorted(set(resolved)):
        try:
            resolved_candidate = Path(candidate).resolve()
            if resolved_candidate.parent == own_log_dir:
                continue
        except Exception:
            pass
        safe_paths.append(candidate)
    return safe_paths

# ==========================================
# 4. THREADS
# ==========================================
def heartbeat_thread():
    signing_key = None
    while True:
        retry_delay = HEARTBEAT_INTERVAL
        try:
            if signing_key is None:
                signing_key = _load_or_create_signing_key()

            with CHANNEL_STATUS_LOCK:
                channel_status = copy.deepcopy(CHANNEL_STATUS)
                sensor_counters = dict(SENSOR_COUNTERS)
            spool_status = SPOOLER.status()
            pos_audit_configured = any(
                os.path.basename(str(path)).lower() == "pos_audit.log"
                for path in WEB_LOG_PATHS
            )
            deployment_evidence = {}
            try:
                if TELEMETRY_DEPLOY_EVIDENCE_PATH.exists():
                    deployment_evidence = json.loads(
                        TELEMETRY_DEPLOY_EVIDENCE_PATH.read_text(encoding="utf-8-sig")
                    )
            except Exception:
                deployment_evidence = {}
            payload = {
                "agent_id": AGENT_ID,
                "current_version": AGENT_VERSION,
                "timestamp": time.time(),
                "sensor_status": {
                    "telemetry_config_version": TELEMETRY_CONFIG_VERSION,
                    "audit_policy_status": deployment_evidence.get("status", "unknown"),
                    "pos_sacl_path_count": int(deployment_evidence.get("pos_path_count", 0) or 0),
                    "channels": channel_status,
                    "counters": sensor_counters,
                    "spool": spool_status,
                    "pos_audit_log": {
                        "configured": pos_audit_configured,
                        "present": any(
                            os.path.basename(str(path)).lower() == "pos_audit.log" and os.path.exists(path)
                            for path in WEB_LOG_PATHS
                        ),
                    },
                },
            }
            resp = _signed_agent_post("/api/v1/agent/heartbeat", payload, signing_key, timeout=10)
            if resp and resp.status_code == 200:
                data = resp.json()
                for bad_ip in data.get("enforce_bans", []):
                    enforce_block(bad_ip)
            elif resp is not None:
                print(f"[WARN] Heartbeat rejected with HTTP {resp.status_code}; retrying later.")
                retry_delay = min(30, HEARTBEAT_INTERVAL)
        except Exception as exc:
            print(f"[WARN] Heartbeat delivery failed; retrying later: {exc}")
            retry_delay = min(30, HEARTBEAT_INTERVAL)
        time.sleep(retry_delay)

# NEW: WEB LOG HUNTER (Monitors text files live)
def web_hunter_thread():
    print(f"[*] Web Hunter Online. Monitoring paths: {WEB_LOG_PATHS}")
    file_positions = {}

    while True:
        log_files = resolve_web_log_files()

        for file_path in log_files:
            if not os.path.exists(file_path):
                continue

            if file_path not in file_positions:
                try:
                    file_size = os.path.getsize(file_path)
                    if os.path.basename(file_path).lower() == "pos_audit.log":
                        try:
                            stored_offset = int(POS_AUDIT_OFFSET_PATH.read_text(encoding="ascii").strip())
                        except Exception:
                            stored_offset = 0
                        file_positions[file_path] = stored_offset if 0 <= stored_offset <= file_size else 0
                    else:
                        file_positions[file_path] = file_size
                except Exception:
                    file_positions[file_path] = 0

            try:
                current_size = os.path.getsize(file_path)
                if current_size < file_positions[file_path]:
                    # Log rotated/truncated, restart from beginning of new file.
                    file_positions[file_path] = 0

                with open(file_path, "r", encoding="utf-8", errors="replace") as file:
                    file.seek(file_positions[file_path], 0)
                    while True:
                        line = file.readline()
                        if not line:
                            break

                        line = line.strip()
                        if not line:
                            continue

                        file_name = os.path.basename(file_path).lower()
                        if file_name == "pos_audit.log":
                            try:
                                record = parse_pos_audit_line(line)
                            except ValueError as exc:
                                quarantine_pos_audit_line(line, exc, file_path)
                                print(f"[WARN] Rejected POS audit record: {exc}")
                                continue

                            processed_data = {
                                key: record.get(key)
                                for key in (
                                    "invoice_id",
                                    "actor",
                                    "source_system",
                                    "reason",
                                    "before_hash",
                                    "after_hash",
                                    "metadata",
                                )
                                if record.get(key) not in (None, "")
                            }
                            payload = {
                                "agent_id": AGENT_ID,
                                "source_ip": LOCAL_IP,
                                "user": record["actor"],
                                "event_id": record["event_id"],
                                "event_type": "fbr_pos",
                                "event_uid": record["event_uid"],
                                "invoice_id": record["invoice_id"],
                                "source_system": record["source_system"],
                                "message": record.get("reason") or f"{record['event_id']} for invoice {record['invoice_id']}",
                                "timestamp": record["timestamp"],
                                "raw_data": record,
                                "raw_event_data": record,
                                "processed_data": processed_data,
                                "agent_version": AGENT_VERSION,
                            }
                            enqueue_payload(payload)
                            continue

                        print(f"[INFO] Web Event Detected: {line[:50]}...")
                        extracted_source_ip = extract_source_ip_from_line(line)
                        event_id = "WAF-BLOCK-01" if file_name == "firewall.log" else "APP-LOG-GENERIC"
                        event_type = "firewall" if file_name == "firewall.log" else "http_request"
                        payload = {
                            "agent_id": AGENT_ID,
                            "source_ip": extracted_source_ip or LOCAL_IP,
                            "user": "System",
                            "event_id": event_id,
                            "event_type": event_type,
                            "event_uid": uuid.uuid4().hex,
                            "message": line,
                            "timestamp": datetime.now(timezone.utc).isoformat(),
                            "raw_data": {"raw": line, "web_log_file": file_path},
                            "raw_event_data": {"raw": line, "web_log_file": file_path},
                            "processed_data": {},
                            "agent_version": AGENT_VERSION,
                        }
                        enqueue_payload(payload)

                    file_positions[file_path] = file.tell()
                    if os.path.basename(file_path).lower() == "pos_audit.log":
                        try:
                            PROGRAM_DATA_DIR.mkdir(parents=True, exist_ok=True)
                            offset_temp = POS_AUDIT_OFFSET_PATH.with_suffix(".offset.tmp")
                            offset_temp.write_text(str(file_positions[file_path]), encoding="ascii")
                            os.replace(offset_temp, POS_AUDIT_OFFSET_PATH)
                        except Exception as exc:
                            print(f"[WARN] Could not persist POS audit offset: {exc}")
            except Exception as e:
                print(f"[!] Web log read error ({file_path}): {e}")

        time.sleep(0.2)


def _event_record_id_from_xml(xml_text):
    """Extract the source cursor even when full event normalization fails."""
    match = _re.search(r"<EventRecordID>(\d+)</EventRecordID>", str(xml_text or ""))
    return int(match.group(1)) if match else 0


def _persist_watermarks(watermark_file, watermarks):
    """Atomically persist cursors; a failed write can cause duplicates, never loss."""
    watermark_file.parent.mkdir(parents=True, exist_ok=True)
    temporary_file = watermark_file.with_suffix(".tmp")
    with open(temporary_file, "w", encoding="utf-8") as watermark_handle:
        json.dump(watermarks, watermark_handle, sort_keys=True)
        watermark_handle.flush()
        os.fsync(watermark_handle.fileno())
    os.replace(temporary_file, watermark_file)


def _durably_enqueue_native_event(payload, record_id, current_watermark):
    """Advance a source cursor only after the event is durable in the spool."""
    enqueue_payload(payload)
    return max(current_watermark, record_id)


def native_log_hunter_thread():
    """Collect native Windows channels through the language-independent Event XML API."""
    print("[*] Native Windows Hunter Online. Streaming via Secure Tunnel...")
    print(f"[*] Monitoring Channels: {WINDOWS_CHANNELS}")
    print(f"[*] Monitoring Event IDs: {sorted(TARGET_EVENT_IDS)}")

    watermark_file = PROGRAM_DATA_DIR / "spool" / "watermarks.json"
    highest_record_seen = {}
    try:
        if watermark_file.exists():
            with open(watermark_file, "r", encoding="utf-8") as watermark_handle:
                highest_record_seen = json.load(watermark_handle)
    except Exception as exc:
        print(f"[WARN] Failed to load native event watermarks: {exc}")

    def set_channel_status(channel, status, error=None, last_event_at=None):
        with CHANNEL_STATUS_LOCK:
            current = dict(CHANNEL_STATUS.get(channel) or {})
            current["status"] = status
            current["last_checked_at"] = datetime.now(timezone.utc).isoformat()
            current["last_error"] = str(error)[:500] if error else None
            if last_event_at:
                current["last_event_at"] = last_event_at
            CHANNEL_STATUS[channel] = current

    def close_handle(handle):
        try:
            win32evtlog.EvtClose(handle)
        except Exception:
            pass

    def latest_record_id(channel):
        query_handle = None
        event_handles = []
        try:
            flags = win32evtlog.EvtQueryChannelPath | win32evtlog.EvtQueryReverseDirection
            query_handle = win32evtlog.EvtQuery(channel, flags, "*")
            event_handles = win32evtlog.EvtNext(query_handle, 1)
            if not event_handles:
                return 0
            xml_text = win32evtlog.EvtRender(event_handles[0], win32evtlog.EvtRenderEventXml)
            parsed = parse_windows_event_xml(xml_text)
            return int(parsed["raw_event_data"]["system"].get("event_record_id") or 0)
        finally:
            for event_handle in event_handles:
                close_handle(event_handle)
            if query_handle:
                close_handle(query_handle)

    for channel in WINDOWS_CHANNELS:
        if channel in highest_record_seen:
            continue
        try:
            highest_record_seen[channel] = latest_record_id(channel)
            set_channel_status(channel, "ok")
            print(f"[*] Synced channel '{channel}'. Watermark: {highest_record_seen[channel]}")
        except Exception as exc:
            highest_record_seen[channel] = 0
            set_channel_status(channel, "error", exc)
            print(f"[WARN] Channel open failed ({channel}): {exc}")

    while True:
        for channel in WINDOWS_CHANNELS:
            query_handle = None
            event_handles = []
            try:
                channel_watermark = int(highest_record_seen.get(channel, 0) or 0)
                current_batch_highest = channel_watermark
                query = f"*[System[EventRecordID > {channel_watermark}]]"
                flags = win32evtlog.EvtQueryChannelPath | win32evtlog.EvtQueryForwardDirection
                query_handle = win32evtlog.EvtQuery(channel, flags, query)
                spool_blocked = False

                while True:
                    event_handles = win32evtlog.EvtNext(query_handle, 64)
                    if not event_handles:
                        break
                    for event_handle in event_handles:
                        rendered_record_id = 0
                        try:
                            xml_text = win32evtlog.EvtRender(event_handle, win32evtlog.EvtRenderEventXml)
                            rendered_record_id = _event_record_id_from_xml(xml_text)
                            parsed = parse_windows_event_xml(xml_text)
                            event_id = str(parsed.get("event_id") or "").strip()
                            record_id = int(parsed["raw_event_data"]["system"].get("event_record_id") or 0)

                            include_event = CAPTURE_ALL_WINDOWS_CHANNELS
                            if not include_event:
                                if channel.lower() == "security" and CAPTURE_ALL_SECURITY_EVENTS:
                                    include_event = True
                                elif event_id in TARGET_EVENT_IDS:
                                    include_event = True
                            if not include_event or event_id == "0":
                                current_batch_highest = max(current_batch_highest, record_id)
                                continue

                            payload = {
                                "agent_id": AGENT_ID,
                                "source_ip": parsed["source_ip"],
                                "user": parsed["user"],
                                "event_id": event_id,
                                "event_uid": parsed["event_uid"],
                                "message": build_windows_event_message(parsed),
                                "timestamp": parsed["timestamp"],
                                "processed_data": parsed["processed_data"],
                                "raw_event_data": parsed["raw_event_data"],
                                "agent_version": AGENT_VERSION,
                            }
                            current_batch_highest = _durably_enqueue_native_event(
                                payload,
                                record_id,
                                current_batch_highest,
                            )
                            set_channel_status(channel, "ok", last_event_at=parsed["timestamp"])
                        except SpoolWriteError as exc:
                            spool_blocked = True
                            set_channel_status(channel, "degraded", exc)
                            print(
                                f"[ERROR] Native collection paused at {channel}:"
                                f"{rendered_record_id or 'unknown'} until spool storage recovers: {exc}"
                            )
                        except Exception as exc:
                            with CHANNEL_STATUS_LOCK:
                                SENSOR_COUNTERS["windows_parse_failures"] += 1
                            if rendered_record_id:
                                current_batch_highest = max(current_batch_highest, rendered_record_id)
                            set_channel_status(channel, "degraded", exc)
                            print(f"[WARN] Native event XML parse failed ({channel}): {exc}")
                        finally:
                            close_handle(event_handle)
                        if spool_blocked:
                            break
                    if spool_blocked:
                        break
                    event_handles = []

                if highest_record_seen.get(channel) != current_batch_highest:
                    highest_record_seen[channel] = current_batch_highest
                    try:
                        _persist_watermarks(watermark_file, highest_record_seen)
                    except Exception as exc:
                        set_channel_status(channel, "degraded", exc)
                        print(f"[WARN] Failed to persist native event watermarks: {exc}")
                if not spool_blocked:
                    set_channel_status(channel, "ok")
            except Exception as exc:
                with CHANNEL_STATUS_LOCK:
                    SENSOR_COUNTERS["channel_failures"] += 1
                set_channel_status(channel, "error", exc)
                print(f"[WARN] Native channel read failed ({channel}): {exc}")
            finally:
                for event_handle in event_handles:
                    close_handle(event_handle)
                if query_handle:
                    close_handle(query_handle)
        time.sleep(POLL_INTERVAL)

if __name__ == "__main__":
    print("==========================================")
    print(f"   WarSOC Windows Agent v{AGENT_VERSION}")
    print(f"   Tenant ID: {TENANT_ID}")
    print("==========================================")

    if (
        not TARGET_EVENT_IDS
        and not CAPTURE_ALL_SECURITY_EVENTS
        and not CAPTURE_ALL_WINDOWS_CHANNELS
    ):
        print("[FAIL] FATAL: No Event IDs configured. Set monitoring.target_event_ids in tenant_policy.json or app/config/config.json")
        sys.exit(1)

    authenticate_agent()

    # START ALL SENSORS
    threading.Thread(target=heartbeat_thread, daemon=True).start()
    threading.Thread(target=ingest_sender_thread, daemon=True).start()
    threading.Thread(target=native_log_hunter_thread, daemon=True).start()
    threading.Thread(target=web_hunter_thread, daemon=True).start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[INFO] Safe exit.")
        sys.exit(0)
