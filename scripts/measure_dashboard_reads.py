from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import sys
import time
from pathlib import Path

from motor.motor_asyncio import AsyncIOMotorClient

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.config.config import get_settings


COLLECTIONS = ("security_alerts", "siem_cold_vault")
PROJECTION = {
    "raw_event_data": 0,
    "raw_event": 0,
    "raw_data": 0,
    "processed_data": 0,
    "_retention_ts": 0,
    "_expire_at": 0,
}


def _plan_stages(plan) -> list[str]:
    stages: list[str] = []
    if isinstance(plan, dict):
        stage = plan.get("stage")
        if stage:
            stages.append(str(stage))
        for value in plan.values():
            stages.extend(_plan_stages(value))
    elif isinstance(plan, list):
        for value in plan:
            stages.extend(_plan_stages(value))
    return stages


async def _measure_collection(db, tenant_id: str, collection_name: str, limit: int) -> dict:
    command = {
        "explain": {
            "find": collection_name,
            "filter": {"tenant_id": tenant_id},
            "projection": PROJECTION,
            "sort": {"timestamp": -1},
            "limit": limit + 1,
        },
        "verbosity": "executionStats",
    }
    started = time.perf_counter()
    explain = await db.command(command)
    wall_ms = (time.perf_counter() - started) * 1000
    execution = explain.get("executionStats") or {}
    stages = sorted(set(_plan_stages(explain.get("queryPlanner", {}).get("winningPlan", {}))))
    index_names = sorted(
        name
        for name, details in (await db[collection_name].index_information()).items()
        if details.get("key")
    )
    return {
        "collection": collection_name,
        "limit": limit,
        "wall_ms": round(wall_ms, 3),
        "execution_ms": execution.get("executionTimeMillis"),
        "documents_returned": execution.get("nReturned"),
        "documents_examined": execution.get("totalDocsExamined"),
        "keys_examined": execution.get("totalKeysExamined"),
        "winning_plan_stages": stages,
        "uses_index": "IXSCAN" in stages or "EXPRESS_IXSCAN" in stages,
        "collection_scan": "COLLSCAN" in stages,
        "available_indexes": index_names,
    }


async def _run(args) -> dict:
    settings = get_settings()
    client = AsyncIOMotorClient(settings.mongodb_uri, serverSelectionTimeoutMS=5000)
    tenant_fingerprint = hashlib.sha256(args.tenant_id.encode("utf-8")).hexdigest()[:12]
    try:
        await client.admin.command("ping")
        db = client[settings.mongodb_db_name]
        measurements = [
            await _measure_collection(db, args.tenant_id, collection_name, args.limit)
            for collection_name in COLLECTIONS
        ]
        return {
            "tenant_fingerprint": tenant_fingerprint,
            "read_contract": "bounded-hot-live",
            "measurements": measurements,
            "pass": all(row["uses_index"] and not row["collection_scan"] for row in measurements),
        }
    finally:
        client.close()


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Read-only MongoDB execution-plan proof for WarSOC dashboard live feeds."
    )
    parser.add_argument("--tenant-id", required=True, help="Tenant to measure; output stores only a hash.")
    parser.add_argument("--limit", type=int, default=500, choices=range(1, 501), metavar="1..500")
    parser.add_argument("--output", type=Path, help="Optional JSON artifact path.")
    args = parser.parse_args()

    result = asyncio.run(_run(args))
    rendered = json.dumps(result, indent=2)
    print(rendered)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered + "\n", encoding="utf-8")
    return 0 if result["pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
