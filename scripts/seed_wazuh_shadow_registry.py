"""Seed one reviewed Wazuh shadow connector/ruleset. Never enables primary mode."""

from __future__ import annotations

import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

from pymongo import MongoClient

from app.config.config import get_settings
from app.wazuh_integration.registry import validate_registry_document


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--registry", required=True)
    parser.add_argument("--sha256", required=True)
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()

    settings = get_settings()
    if settings.wazuh_detection_mode != "shadow":
        raise SystemExit("WAZUH_DETECTION_MODE must be shadow; this tool never seeds primary mode")
    path = Path(args.registry)
    raw = path.read_bytes()
    actual_hash = hashlib.sha256(raw).hexdigest()
    if actual_hash.lower() != args.sha256.strip().lower():
        raise SystemExit("Rule registry SHA-256 mismatch")
    if actual_hash.lower() != settings.wazuh_rule_registry_sha256:
        raise SystemExit("Rule registry SHA-256 does not match WAZUH_RULE_REGISTRY_SHA256")
    registry = json.loads(raw)
    if registry.get("ruleset_version") != settings.wazuh_ruleset_version:
        raise SystemExit("Rule registry version does not match WAZUH_RULESET_VERSION")
    try:
        rules_by_id = validate_registry_document(registry)
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc
    rules = list(rules_by_id.values())

    summary = {
        "mode": "apply" if args.apply else "dry-run",
        "connector_id": settings.wazuh_connector_id,
        "engine_instance_id": settings.wazuh_engine_instance_id,
        "engine_version": settings.wazuh_engine_version,
        "ruleset_version": settings.wazuh_ruleset_version,
        "registry_sha256": actual_hash,
        "rules": [str(rule.get("rule_id") or "") for rule in rules],
    }
    if not args.apply:
        print(json.dumps(summary, indent=2))
        return

    now = datetime.now(timezone.utc)
    client = MongoClient(settings.mongodb_uri)
    db = client[settings.mongodb_db_name]
    try:
        db.detection_engine_connectors.update_one(
            {
                "connector_id": settings.wazuh_connector_id,
                "engine_instance_id": settings.wazuh_engine_instance_id,
            },
            {
                "$set": {
                    "status": "active",
                    "engine": "wazuh",
                    "engine_version": settings.wazuh_engine_version,
                    "ruleset_version": settings.wazuh_ruleset_version,
                    "registry_sha256": actual_hash,
                    "mode": "shadow",
                    "updated_at": now,
                },
                "$setOnInsert": {"created_at": now},
            },
            upsert=True,
        )
        for rule in rules:
            rule_id = str(rule.get("rule_id") or "").strip()
            if not rule_id:
                raise SystemExit("Rule registry contains an empty rule ID")
            document = {
                **rule,
                "engine": "wazuh",
                "status": "approved",
                "dispatch_enabled": True,
                "candidate_enabled": True,
                "ruleset_version": settings.wazuh_ruleset_version,
                "registry_sha256": actual_hash,
                "updated_at": now,
            }
            db.detection_rule_registry.update_one(
                {
                    "engine": "wazuh",
                    "ruleset_version": settings.wazuh_ruleset_version,
                    "rule_id": rule_id,
                },
                {"$set": document, "$setOnInsert": {"created_at": now}},
                upsert=True,
            )
    finally:
        client.close()
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
