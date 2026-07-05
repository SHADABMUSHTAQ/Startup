import argparse
import asyncio
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cryptography.fernet import Fernet, InvalidToken
from motor.motor_asyncio import AsyncIOMotorClient
from pymongo import UpdateOne

from app.config.config import get_settings


SENSITIVE_FIELDS = (
    "message",
    "raw_event",
    "raw_data",
    "raw_event_data",
    "processed_data",
)


def encrypt_if_needed(fernet: Fernet, value):
    if value in (None, "", {}, []):
        return value, False
    if isinstance(value, str):
        try:
            fernet.decrypt(value.encode())
            return value, False
        except (InvalidToken, ValueError):
            plaintext = value
    else:
        plaintext = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
    return fernet.encrypt(plaintext.encode()).decode(), True


async def migrate(*, apply: bool, batch_size: int):
    settings = get_settings()
    fernet = Fernet(settings.encryption_key.encode())
    client = AsyncIOMotorClient(settings.mongodb_uri)
    collection = client[settings.mongodb_db_name]["fbr_pos_logs"]
    scanned = changed = 0

    try:
        projection = {field: 1 for field in SENSITIVE_FIELDS}
        projection["encryption_version"] = 1
        cursor = collection.find({}, projection).batch_size(batch_size)
        operations = []
        async for document in cursor:
            scanned += 1
            updates = {}
            for field in SENSITIVE_FIELDS:
                encrypted, was_changed = encrypt_if_needed(fernet, document.get(field))
                if was_changed:
                    updates[field] = encrypted
            if document.get("encryption_version") != "fernet-v1":
                updates["encryption_version"] = "fernet-v1"
            if updates:
                changed += 1
            if apply and updates:
                operations.append(UpdateOne({"_id": document["_id"]}, {"$set": updates}))
                if len(operations) >= batch_size:
                    await collection.bulk_write(operations, ordered=False)
                    operations = []

        if apply and operations:
            await collection.bulk_write(operations, ordered=False)
    finally:
        client.close()

    mode = "applied" if apply else "dry-run"
    print(f"FBR encryption migration {mode}: scanned={scanned} changed={changed}")


def main():
    parser = argparse.ArgumentParser(description="Encrypt legacy plaintext FBR vault fields.")
    parser.add_argument("--apply", action="store_true", help="Persist updates. Default is dry-run.")
    parser.add_argument("--batch-size", type=int, default=200)
    args = parser.parse_args()
    if args.batch_size < 1 or args.batch_size > 1000:
        parser.error("--batch-size must be between 1 and 1000")
    asyncio.run(migrate(apply=args.apply, batch_size=args.batch_size))


if __name__ == "__main__":
    main()
