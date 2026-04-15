import asyncio
import json
import time
import hashlib
import logging
import os
import sys
from datetime import datetime, timezone
from motor.motor_asyncio import AsyncIOMotorClient
from redis import exceptions as redis_exceptions
from redis.asyncio import Redis
from app.config.config import get_settings

from app.utils.tenant_cache import get_tenant_plan

import base64
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
import copy

try:
    from canonicaljson import encode_canonical_json
    CANONICALJSON_AVAILABLE = True
except Exception:
    CANONICALJSON_AVAILABLE = False

# 🏗️ MASTER BUILD: PECA Compliance Worker (PECA 2016 Section 46)
# Strictly Decoupled, RSA-2048 Digital Signing, Senior Architect Hardened

logging.basicConfig(level=logging.INFO, format="%(asctime)s [PECA] %(message)s")
logger = logging.getLogger("PECA-Worker")

settings = get_settings()
RAW_LOGS_QUEUE = "raw_logs_queue"
PECA_GROUP = "peca_group"
SIGNER_ID = "WarSOC-PK-2026-v1" # Standardized key version for rotation control
PECA_CONSUMER = "peca_consumer_1"
RECLAIM_MIN_IDLE_MS = 60000
RECLAIM_BATCH_SIZE = 50

def load_dynamic_config():
    """Loads config.json using absolute path resolution (CTO FIX)."""
    # 🚨 FIX: Path resolved relative to the file's directory
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    config_path = os.path.join(base_dir, "config", "config.json")
    try:
        with open(config_path, "r") as f:
            return json.load(f)
    except Exception as e:
        logger.error(f"FAILED TO LOAD CONFIG AT {config_path}: {e}")
        return {}


def _normalize_timestamp_iso_utc(value) -> str:
    """Coerce timestamp-like values to timezone-aware UTC ISO 8601 strings."""
    if isinstance(value, datetime):
        dt = value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc).isoformat()

    if isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return parsed.astimezone(timezone.utc).isoformat()
        except Exception:
            return datetime.now(timezone.utc).isoformat()

    return datetime.now(timezone.utc).isoformat()


def _normalize_document_timestamps(document: dict):
    document["timestamp"] = _normalize_timestamp_iso_utc(document.get("timestamp"))
    if "ingested_at" in document:
        document["ingested_at"] = _normalize_timestamp_iso_utc(document.get("ingested_at"))
    # Keep _retention_ts as a datetime for Mongo TTL index; canonicalization will convert a copy when signing.
    return document


def _to_canonical_bytes(obj) -> bytes:
    """Return canonical bytes for signing. Prefer `canonicaljson` if available,
    otherwise fall back to deterministic JSON with sorted keys and compact separators.

    This will deep-copy the object and convert any datetime values to
    UTC ISO-8601 strings so canonicalization is stable.
    """
    o = copy.deepcopy(obj)

    def _convert(value):
        if isinstance(value, dict):
            for k, v in list(value.items()):
                if isinstance(v, datetime):
                    value[k] = v.astimezone(timezone.utc).isoformat()
                else:
                    _convert(v)
        elif isinstance(value, list):
            for i in range(len(value)):
                v = value[i]
                if isinstance(v, datetime):
                    value[i] = v.astimezone(timezone.utc).isoformat()
                else:
                    _convert(v)

    _convert(o)

    if CANONICALJSON_AVAILABLE:
        try:
            return encode_canonical_json(o)
        except Exception as e:
            logger.error(f"Canonical encoding failed: {e}")
    
    # Fallback to high-entropy deterministic JSON if package is missing (Non-Compliant)
    logger.warning("Using fallback deterministic JSON (Non-Compliant for PECA)")
    return json.dumps(o, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")


async def reclaim_stale_messages(redis_client: Redis):
    """Best-effort reclaim for stale pending stream entries."""
    try:
        pending_entries = await redis_client.xpending_range(
            RAW_LOGS_QUEUE,
            PECA_GROUP,
            "-",
            "+",
            RECLAIM_BATCH_SIZE,
            idle=RECLAIM_MIN_IDLE_MS,
        )
        if not pending_entries:
            return []

        stale_ids = []
        for entry in pending_entries:
            if not entry:
                continue
            if isinstance(entry, dict):
                message_id = entry.get("message_id")
            else:
                message_id = entry[0]
            if isinstance(message_id, bytes):
                message_id = message_id.decode()
            if message_id:
                stale_ids.append(message_id)

        if not stale_ids:
            return []

        reclaimed = await redis_client.xclaim(
            RAW_LOGS_QUEUE,
            PECA_GROUP,
            PECA_CONSUMER,
            RECLAIM_MIN_IDLE_MS,
            stale_ids,
        )
        if reclaimed:
            logger.info(f"[XCLAIM] Reclaimed {len(reclaimed)} stale PECA message(s).")
        return reclaimed or []

    except redis_exceptions.ResponseError as e:
        logger.warning(f"[XCLAIM] PECA reclaim skipped safely: {e}")
        return []
    except Exception as e:
        logger.error(f"[XCLAIM] PECA reclaim error (non-fatal): {e}")
        return []

async def peca_worker():
    """
    MASTER BUILD: Consumer for raw_logs_queue (PECA Logic).
    Implements RSA-2048 digital signatures to ensure non-repudiation (PECA Section 46).
    """
    # 🔐 Global Inits
    client = AsyncIOMotorClient(settings.mongodb_uri)
    db = client[settings.mongodb_db_name]
    redis = await Redis.from_url(settings.redis_url, decode_responses=True)

    # 🔑 Resolve Signing Keys (prefer env-provided key material)
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    repo_root = os.path.dirname(base_dir)
    private_key_path = os.path.join(repo_root, "keys", "private_key.pem")

    key_data = None
    # 1) Preferred: load base64-encoded PEM from environment (secure hosting)
    try:
        if getattr(settings, "private_key_b64", ""):
            key_data = base64.b64decode(settings.private_key_b64)
            logger.info("Loaded RSA Private Key from PRIVATE_KEY_B64 environment variable.")
    except Exception as e:
        logger.warning(f"Failed to decode PRIVATE_KEY_B64: {e}")

    # 2) Fallback to file on disk
    if key_data is None:
        if not os.path.exists(private_key_path):
            logger.critical(f"PECA non-compliant: signing key missing at {private_key_path}. Worker cannot start.")
            sys.exit(1)
        try:
            with open(private_key_path, "rb") as key_file:
                key_data = key_file.read()
            logger.warning("Loaded RSA Private Key from disk (keys/private_key.pem). Consider moving to a secure keystore.")
        except Exception as e:
            logger.critical(f"FAILED TO LOAD SIGNING KEY FROM FILE: {e}. Worker non-compliant.")
            sys.exit(1)

    # 3) Load key (supports optional passphrase)
    try:
        password = settings.private_key_password.encode() if getattr(settings, "private_key_password", None) else None
        private_key = serialization.load_pem_private_key(key_data, password=password)
        logger.info("Loaded RSA Private Key for PECA Signing")
    except Exception as e:
        logger.critical(f"FAILED TO LOAD SIGNING KEY: {e}. Worker non-compliant.")
        sys.exit(1)

    # 🛡️ PECA Consumer Group (Enterprise Baseline)
    while True:
        try:
            await redis.xgroup_create(RAW_LOGS_QUEUE, PECA_GROUP, mkstream=True)
            logger.info(f"✅ Created consumer group: {PECA_GROUP} on {RAW_LOGS_QUEUE}")
            break
        except redis_exceptions.ResponseError as e:
            if "BUSYGROUP" in str(e):
                logger.info(f"[*] Consumer group {PECA_GROUP} already exists. Resuming...")
                break
            logger.error(f"[!] Group Creation Error: {e}. Retrying...")
            await asyncio.sleep(2)
        except redis_exceptions.ConnectionError as e:
            logger.warning(f"[!] Redis connection error during group creation: {e}. Retrying in 2s...")
            await asyncio.sleep(2)
        except Exception as e:
            logger.error(f"[!] Unexpected error during group creation: {e}. Retrying in 2s...")
            await asyncio.sleep(2)

    last_config_load = 0
    PECA_TARGETS = set()
    buffer = []
    buffer_ack_ids = []
    last_flush_time = time.time()
    
    logger.info("⚡ WarSOC PECA Worker: Non-Repudiable Evidence Active (Section 46)...")
    
    while True:
        try:
            # 🔄 HOT-RELOAD: Sync Compliance Policy every 60 seconds (BUG-24 FIX)
            if time.time() - last_config_load > 60:
                config = load_dynamic_config()
                event_map = config.get("event_id_map", {})
                
                # Derive targets STRICTLY from SSOT tags
                new_targets = set()
                for eid_str, meta in event_map.items():
                    if "peca" in [str(t).lower() for t in meta.get("compliance_tags", [])]:
                        try:
                            new_targets.add(int(eid_str))
                        except ValueError: continue
                
                # Fallback to the dedicated list if tags are missing (Legacy Support)
                if not new_targets:
                    new_targets = set(config.get("compliance_targets", {}).get("peca", []))
                
                PECA_TARGETS = new_targets
                last_config_load = time.time()
                logger.info(f"[*] PECA Policy Synced: Monitoring {len(PECA_TARGETS)} Event IDs.")

            # ⚡ Optimized Read Performance: Fetch forensic batch
            streams = await redis.xreadgroup(PECA_GROUP, PECA_CONSUMER, {RAW_LOGS_QUEUE: ">"}, count=50, block=2000)
            
            if not streams:
                reclaimed_messages = await reclaim_stale_messages(redis)
                if not reclaimed_messages:
                    continue
                streams = [(RAW_LOGS_QUEUE, reclaimed_messages)]

            for _, messages in streams:
                if not messages:
                    continue

                forensic_batch = []
                forensic_ack_ids = []
                immediate_ack_ids = []

                for message_id, payload in messages:
                    try:
                        # BUG-STABILIZE: Handle malformed JSON Poison Pills
                        raw_payload = payload.get("payload", "")
                        if not raw_payload:
                            logger.warning(f"Skipping empty PECA payload {message_id}")
                            immediate_ack_ids.append(message_id)
                            continue

                        try:
                            log_data = json.loads(raw_payload)
                        except json.JSONDecodeError:
                            # Best effort cleanup for Python-style stringified dicts
                            try:
                                sanitized = raw_payload.replace("'", '"')
                                log_data = json.loads(sanitized)
                                logger.info(f"[*] Sanitized malformed PECA JSON: {message_id}")
                            except Exception:
                                logger.error(f"[POISON PILL] Permanent JSON parse failure for PECA message {message_id}. Discarding.")
                                immediate_ack_ids.append(message_id) # Acknowledge so it's removed from Redis
                                continue
                        
                        tenant_id = log_data.get("tenant_id")

                        # 🔍 1. Plan Verification
                        plan = await get_tenant_plan(redis, tenant_id)
                        if plan not in ["Professional", "Enterprise"]:
                            immediate_ack_ids.append(message_id)
                            continue

                        # 🔍 2. DYNAMIC TARGET ENFORCEMENT (SSOT-derived)
                        raw_event_id = log_data.get("event_id")
                        try:
                            event_id = int(str(raw_event_id).strip())
                        except Exception:
                            # Unknown or malformed event id: skip for PECA (SIEM keeps raw log)
                            immediate_ack_ids.append(message_id)
                            continue

                        if event_id not in PECA_TARGETS:
                            immediate_ack_ids.append(message_id)
                            continue

                        # 🏷️ 3. Tagging & RSA Signing
                        log_data["tags"] = "PECA_FORENSIC"
                        log_data["retention_policy"] = "365_DAYS"
                        log_data["ingested_at"] = datetime.now(timezone.utc).isoformat()
                        log_data["signer_id"] = SIGNER_ID
                        log_data["_retention_ts"] = datetime.now(timezone.utc)
                        _normalize_document_timestamps(log_data)

                        # Create a signing copy that converts datetimes to stable ISO strings
                        signing_doc = copy.deepcopy(log_data)
                        if isinstance(signing_doc.get("_retention_ts"), datetime):
                            signing_doc["_retention_ts"] = signing_doc["_retention_ts"].astimezone(timezone.utc).isoformat()

                        canonical_bytes = _to_canonical_bytes(signing_doc)

                        log_data["forensic_seal"] = hashlib.sha256(canonical_bytes).hexdigest()

                        signature = private_key.sign(
                            canonical_bytes,
                            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                            hashes.SHA256()
                        )

                        log_data["digital_signature"] = base64.b64encode(signature).decode("utf-8")
                        log_data["signed_payload"] = base64.b64encode(canonical_bytes).decode("utf-8")
                        log_data["canonicalization_version"] = "canonicaljson/v1"
                        
                        buffer.append(log_data)
                        forensic_ack_ids.append(message_id)
                    
                    except Exception as e:
                        logger.error(f"Error signing forensic log: {e}")
                        # Do not ack this message on processing/signing failure.
                        continue

                # 📥 4. BULK VAULT PERSISTENCE
                # Flush the in-memory `buffer` of signed logs into MongoDB.
                if buffer:
                    try:
                        forensic_batch = [_normalize_document_timestamps(item) for item in buffer]
                        await db.peca_forensic_logs.insert_many(forensic_batch)
                        logger.info(f"[*] PECA Signed and Vaulted {len(forensic_batch)} evidence logs.")
                    except Exception as e:
                        logger.error(f"[!] PECA vault flush failed: {e}")
                    else:
                        if forensic_ack_ids:
                            async with redis.pipeline(transaction=True) as pipe:
                                for mid in forensic_ack_ids:
                                    pipe.xack(RAW_LOGS_QUEUE, PECA_GROUP, mid)
                                await pipe.execute()
                        # Clear the buffer after successful persistence so we do not re-insert
                        buffer.clear()

                # Ack intentionally skipped/malformed records immediately.
                if immediate_ack_ids:
                    async with redis.pipeline(transaction=True) as pipe:
                        for mid in immediate_ack_ids:
                            pipe.xack(RAW_LOGS_QUEUE, PECA_GROUP, mid)
                        await pipe.execute()

        except Exception as e:
            logger.error(f"[!] PECA Pipeline crash: {str(e)}")
            await asyncio.sleep(1)

if __name__ == "__main__":
    try:
        asyncio.run(peca_worker())
    except KeyboardInterrupt:
        print("[*] PECA Worker shutting down gracefully.")
