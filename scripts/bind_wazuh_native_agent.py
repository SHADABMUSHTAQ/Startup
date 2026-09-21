"""Bind one pre-enrolled Wazuh agent to an authoritative WarSOC endpoint."""

from __future__ import annotations

import argparse
import asyncio
import json
import re
from datetime import datetime, timezone

from pymongo.errors import DuplicateKeyError

from app.database import db_manager


IDENTIFIER = re.compile(r"^[A-Za-z0-9_.:-]{1,128}$")


def _identifier(value: str, label: str) -> str:
    normalized = str(value or "").strip()
    if not IDENTIFIER.fullmatch(normalized):
        raise argparse.ArgumentTypeError(f"{label} has an invalid format")
    return normalized


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Create an active, tenant-scoped Wazuh-to-WarSOC agent binding."
    )
    parser.add_argument("--tenant-id", required=True)
    parser.add_argument("--warsoc-agent-id", required=True)
    parser.add_argument("--wazuh-agent-id", required=True)
    parser.add_argument("--wazuh-agent-name", required=True)
    parser.add_argument("--engine-instance-id", default="wazuh-node-01")
    return parser.parse_args()


async def bind(args: argparse.Namespace) -> dict[str, str]:
    tenant_id = _identifier(args.tenant_id, "tenant ID")
    warsoc_agent_id = _identifier(args.warsoc_agent_id, "WarSOC agent ID")
    wazuh_agent_id = _identifier(args.wazuh_agent_id, "Wazuh agent ID")
    wazuh_agent_name = _identifier(args.wazuh_agent_name, "Wazuh agent name")
    engine_instance_id = _identifier(args.engine_instance_id, "engine instance ID")

    await db_manager.connect()
    db = db_manager.db
    if db is None:
        raise RuntimeError("MongoDB is unavailable")

    endpoint = await db.agents.find_one(
        {
            "tenant_id": tenant_id,
            "agent_id": warsoc_agent_id,
            "status": "active",
        },
        {"_id": 1},
    )
    if endpoint is None:
        raise RuntimeError("The requested active WarSOC endpoint does not exist")

    connector = await db.detection_engine_connectors.find_one(
        {
            "engine": "wazuh",
            "engine_instance_id": engine_instance_id,
            "status": "active",
        },
        {"_id": 1},
    )
    if connector is None:
        raise RuntimeError("The requested Wazuh engine instance is not active")

    conflicting = await db.detection_engine_agent_bindings.find_one(
        {
            "engine": "wazuh",
            "engine_instance_id": engine_instance_id,
            "wazuh_agent_id": wazuh_agent_id,
            "status": "active",
            "$or": [
                {"tenant_id": {"$ne": tenant_id}},
                {"warsoc_agent_id": {"$ne": warsoc_agent_id}},
            ],
        },
        {"_id": 1},
    )
    if conflicting is not None:
        raise RuntimeError("The Wazuh agent is already bound to another endpoint")

    now = datetime.now(timezone.utc)
    await db.detection_engine_agent_bindings.update_many(
        {
            "engine": "wazuh",
            "engine_instance_id": engine_instance_id,
            "tenant_id": tenant_id,
            "warsoc_agent_id": warsoc_agent_id,
            "wazuh_agent_id": {"$ne": wazuh_agent_id},
            "status": "active",
        },
        {
            "$set": {
                "status": "retired",
                "retired_at": now,
                "updated_at": now,
            }
        },
    )

    try:
        await db.detection_engine_agent_bindings.update_one(
            {
                "engine": "wazuh",
                "engine_instance_id": engine_instance_id,
                "wazuh_agent_id": wazuh_agent_id,
            },
            {
                "$set": {
                    "tenant_id": tenant_id,
                    "warsoc_agent_id": warsoc_agent_id,
                    "wazuh_agent_name": wazuh_agent_name,
                    "status": "active",
                    "updated_at": now,
                },
                "$setOnInsert": {
                    "created_at": now,
                },
            },
            upsert=True,
        )
    except DuplicateKeyError as exc:
        raise RuntimeError("An active binding conflict was detected") from exc

    return {
        "status": "BOUND",
        "tenant_id": tenant_id,
        "warsoc_agent_id": warsoc_agent_id,
        "wazuh_agent_id": wazuh_agent_id,
        "wazuh_agent_name": wazuh_agent_name,
        "engine_instance_id": engine_instance_id,
    }


async def main() -> None:
    args = parse_args()
    try:
        result = await bind(args)
        print(json.dumps(result, sort_keys=True))
    finally:
        await db_manager.close()


if __name__ == "__main__":
    asyncio.run(main())
