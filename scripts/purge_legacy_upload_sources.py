"""Remove source CSV files retained by releases older than the temporary-file policy."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
from datetime import datetime, timezone
from pathlib import Path

from motor.motor_asyncio import AsyncIOMotorClient

from app.config.config import get_settings


def _safe_upload_path(raw_path: str, upload_root: Path) -> Path | None:
    if not raw_path:
        return None
    candidate = Path(raw_path)
    if not candidate.is_absolute():
        candidate = Path.cwd() / candidate
    candidate = candidate.resolve()
    try:
        candidate.relative_to(upload_root)
    except ValueError:
        return None
    return candidate


async def purge(*, apply: bool, minimum_age_minutes: int) -> dict:
    settings = get_settings()
    upload_root = Path(os.getenv("UPLOAD_DIR", "/app/uploaded_files")).resolve()
    cutoff = datetime.now(timezone.utc).timestamp() - (minimum_age_minutes * 60)
    client = AsyncIOMotorClient(settings.mongodb_uri)
    db = client[settings.mongodb_db_name]
    summary = {
        "mode": "apply" if apply else "dry-run",
        "referenced_files": 0,
        "orphan_files": 0,
        "deleted_files": 0,
        "unsafe_references": 0,
        "metadata_updates": 0,
    }

    try:
        referenced_paths: set[Path] = set()
        cursor = db["analysis_results"].find(
            {"file_path": {"$exists": True, "$nin": [None, ""]}},
            {"file_path": 1},
        )
        async for document in cursor:
            candidate = _safe_upload_path(str(document.get("file_path") or ""), upload_root)
            if candidate is None:
                summary["unsafe_references"] += 1
                continue
            referenced_paths.add(candidate)
            summary["referenced_files"] += 1
            old_enough = not candidate.exists() or candidate.stat().st_mtime <= cutoff
            if apply and old_enough:
                if candidate.exists():
                    candidate.unlink()
                    summary["deleted_files"] += 1
                await db["analysis_results"].update_one(
                    {"_id": document["_id"]},
                    {
                        "$unset": {"file_path": ""},
                        "$set": {
                            "source_file_retained": False,
                            "source_file_purged_at": datetime.now(timezone.utc),
                        },
                    },
                )
                summary["metadata_updates"] += 1

        if upload_root.exists():
            for candidate in upload_root.iterdir():
                if not candidate.is_file() or candidate.resolve() in referenced_paths:
                    continue
                if candidate.stat().st_mtime > cutoff:
                    continue
                summary["orphan_files"] += 1
                if apply:
                    candidate.unlink()
                    summary["deleted_files"] += 1
    finally:
        client.close()

    return summary


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--apply", action="store_true", help="Delete files and update metadata")
    parser.add_argument("--minimum-age-minutes", type=int, default=60)
    args = parser.parse_args()
    if args.minimum_age_minutes < 1:
        parser.error("--minimum-age-minutes must be at least 1")

    print(json.dumps(asyncio.run(purge(
        apply=args.apply,
        minimum_age_minutes=args.minimum_age_minutes,
    )), indent=2, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
