#!/usr/bin/env python3
"""
Helper: create a PECA forensic document, sign it with local private key, and insert into MongoDB.
Prints INSERTED_ID:<hexid> on success.
"""
import argparse
import asyncio
import base64
import hashlib
import json
import copy
import sys
from datetime import datetime, timezone
from pathlib import Path

try:
    from canonicaljson import encode_canonical_json
    CANONICALJSON_AVAILABLE = True
except Exception:
    CANONICALJSON_AVAILABLE = False

from motor.motor_asyncio import AsyncIOMotorClient
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

# Local import of settings (allow running from scripts/ dir)
try:
    from app.config.config import get_settings
except Exception:
    repo_root = Path(__file__).resolve().parent.parent
    sys.path.append(str(repo_root))
    from app.config.config import get_settings


def _to_canonical_bytes(obj) -> bytes:
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
        except Exception:
            pass

    return json.dumps(o, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")


async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--tenant", required=True)
    parser.add_argument("--event", type=int, required=True)
    parser.add_argument("--message", default="PECA-sim-test")
    args = parser.parse_args()

    import os

    mongo_uri = os.getenv("MONGODB_URI")
    mongo_db = os.getenv("MONGODB_DB_NAME")

    if not mongo_uri or not mongo_db:
        try:
            settings = get_settings()
            mongo_uri = mongo_uri or settings.mongodb_uri
            mongo_db = mongo_db or settings.mongodb_db_name
        except Exception:
            print("Missing Mongo configuration. Set MONGODB_URI and MONGODB_DB_NAME env vars or configure app settings.")
            sys.exit(2)

    client = AsyncIOMotorClient(mongo_uri)
    db = client[mongo_db]

    repo_root = Path(__file__).resolve().parent.parent
    key_path = repo_root / "keys" / "private_key.pem"
    if not key_path.exists():
        print(f"Private key not found at {key_path}")
        sys.exit(2)

    with open(key_path, "rb") as f:
        key_data = f.read()

    try:
        private_key = serialization.load_pem_private_key(key_data, password=None)
    except Exception as e:
        print(f"Failed to load private key: {e}")
        sys.exit(3)

    doc = {
        "tenant_id": args.tenant,
        "event_id": args.event,
        "message": args.message,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "raw_event_data": {},
        "tags": "PECA_FORENSIC",
        "retention_policy": "365_DAYS",
        "ingested_at": datetime.now(timezone.utc).isoformat(),
        "signer_id": "WarSOC-PK-2026-v1",
        "_retention_ts": datetime.now(timezone.utc),
    }

    # Prepare signing copy
    signing_doc = copy.deepcopy(doc)
    if isinstance(signing_doc.get("_retention_ts"), datetime):
        signing_doc["_retention_ts"] = signing_doc["_retention_ts"].astimezone(timezone.utc).isoformat()

    canonical_bytes = _to_canonical_bytes(signing_doc)
    forensic_seal = hashlib.sha256(canonical_bytes).hexdigest()

    signature = private_key.sign(
        canonical_bytes,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )

    doc["forensic_seal"] = forensic_seal
    doc["digital_signature"] = base64.b64encode(signature).decode("utf-8")
    doc["signed_payload"] = base64.b64encode(canonical_bytes).decode("utf-8")
    doc["canonicalization_version"] = "canonicaljson/v1" if CANONICALJSON_AVAILABLE else "json/deterministic/v1"

    # Insert
    res = await db.peca_forensic_logs.insert_one(doc)

    # Extract hex id
    oid_str = str(res.inserted_id)
    import re
    m = re.search(r"[0-9a-fA-F]{24}", oid_str)
    hex_id = m.group(0) if m else oid_str
    print(f"INSERTED_ID:{hex_id}")


if __name__ == "__main__":
    asyncio.run(main())
