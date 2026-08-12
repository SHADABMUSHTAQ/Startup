from datetime import datetime, timezone
from pathlib import Path

import orjson
import pytest
from cryptography.fernet import Fernet

from app.wazuh_integration.bridge_config import BridgeSettings
from app.wazuh_integration.bridge_runtime import tail_alerts_once
from app.wazuh_integration.bridge_spool import BridgeSpool, SpoolCapacityError
from app.wazuh_integration.contracts import DetectionCandidate


DISPATCH_UID = "WZD_0123456789ABCDEF0123456789ABCDEF"


def _settings(tmp_path: Path, alerts_path: Path) -> BridgeSettings:
    placeholder = tmp_path / "placeholder"
    placeholder.write_text("x", encoding="ascii")
    return BridgeSettings(
        connector_id="wazuh-shadow-01",
        engine_instance_id="wazuh-node-01",
        engine_version="4.14.7",
        ruleset_version="warsoc-lab-canary-v1",
        dispatch_signing_secret="d" * 64,
        candidate_signing_secret="c" * 64,
        spool_encryption_key=Fernet.generate_key().decode("ascii"),
        spool_path=tmp_path / "bridge.sqlite3",
        input_spool_max_bytes=16 * 1024 * 1024,
        candidate_spool_max_bytes=16 * 1024 * 1024,
        live_event_max_age_seconds=60,
        candidate_record_ttl_seconds=86400,
        receipt_retention_seconds=604800,
        health_retention_seconds=2592000,
        retry_base_seconds=2,
        retry_max_seconds=300,
        max_body_bytes=64 * 1024,
        max_batch_events=100,
        wazuh_host="127.0.0.1",
        wazuh_port=15140,
        wazuh_alerts_path=alerts_path,
        alerts_initial_position="beginning",
        rule_registry_path=placeholder,
        rule_registry_sha256="0" * 64,
        candidate_url="https://127.0.0.1:8443/candidates",
        health_url="https://127.0.0.1:8443/health",
        candidate_ca_file=placeholder,
        candidate_cert_file=placeholder,
        candidate_key_file=placeholder,
    )


def test_spool_is_encrypted_idempotent_and_rejects_identity_conflict(tmp_path):
    spool = BridgeSpool(tmp_path / "spool.sqlite3", Fernet.generate_key().decode("ascii"))
    try:
        assert spool.accept_input(DISPATCH_UID, b'{"value":1}', 16 * 1024 * 1024) == "accepted"
        assert spool.accept_input(DISPATCH_UID, b'{"value":1}', 16 * 1024 * 1024) == "duplicate"
        with pytest.raises(ValueError, match="different payload"):
            spool.accept_input(DISPATCH_UID, b'{"value":2}', 16 * 1024 * 1024)
        row = spool._db.execute("SELECT payload_ciphertext FROM input_spool").fetchone()
        assert "value" not in row["payload_ciphertext"]
    finally:
        spool.close()


def test_spool_capacity_refuses_new_data_without_deleting_accepted_data(tmp_path):
    spool = BridgeSpool(tmp_path / "spool.sqlite3", Fernet.generate_key().decode("ascii"))
    try:
        spool.accept_input(DISPATCH_UID, b"a" * 32, 40)
        with pytest.raises(SpoolCapacityError):
            spool.accept_input("WZD_FEDCBA9876543210FEDCBA9876543210", b"b" * 16, 40)
        assert len(spool.pending("input_spool", "dispatch_uid", 10)) == 1
    finally:
        spool.close()


def test_alert_tailer_spools_approved_candidate_before_checkpoint(tmp_path):
    alerts = tmp_path / "alerts.json"
    alert = {
        "id": "wazuh-alert-1",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "rule": {"id": "100500", "level": 3},
        "manager": {"name": "wazuh-node-01"},
        "data": {"warsoc_dispatch_uid": DISPATCH_UID},
    }
    alerts.write_bytes(orjson.dumps(alert) + b"\n")
    settings = _settings(tmp_path, alerts)
    spool = BridgeSpool(settings.spool_path, settings.spool_encryption_key)
    registry = {
        "100500": {
            "rule_id": "100500",
            "category": "integration_canary",
            "mitre_ids": [],
        }
    }
    try:
        assert tail_alerts_once(spool, settings, registry) == 0
        assert tail_alerts_once(spool, settings, registry) == 1
        rows = spool.pending("candidate_spool", "delivery_uid", 10)
        assert len(rows) == 1
        candidate = DetectionCandidate.model_validate_json(rows[0]["payload"])
        assert candidate.trigger_dispatch_uid == DISPATCH_UID
        checkpoint = spool.checkpoint("wazuh-alerts-json-v1")
        assert checkpoint["byte_offset"] == alerts.stat().st_size
    finally:
        spool.close()


def test_alert_tailer_recovers_from_same_file_truncation(tmp_path):
    alerts = tmp_path / "alerts.json"
    settings = _settings(tmp_path, alerts)
    registry = {
        "100500": {
            "rule_id": "100500",
            "category": "integration_canary",
            "severity": "INFO",
            "mitre_ids": [],
            "allowed_engine_levels": [3],
            "source_family": "windows_endpoint",
            "event_ids": ["4688"],
            "input_field_map": {
                "new_process_name": "processed_data.new_process_name"
            },
            "candidate_context_fields": ["wazuh_timestamp", "wazuh_manager"],
        }
    }
    first = {
        "id": "wazuh-alert-long-before-truncate",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "rule": {"id": "100500", "level": 3},
        "data": {"warsoc_dispatch_uid": DISPATCH_UID},
    }
    second = {
        "id": "short",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "rule": {"id": "100500", "level": 3},
        "data": {"warsoc_dispatch_uid": DISPATCH_UID},
    }
    alerts.write_bytes(orjson.dumps(first) + b"\n")
    spool = BridgeSpool(settings.spool_path, settings.spool_encryption_key)
    try:
        tail_alerts_once(spool, settings, registry)
        assert tail_alerts_once(spool, settings, registry) == 1
        alerts.write_bytes(orjson.dumps(second) + b"\n")
        assert tail_alerts_once(spool, settings, registry) == 1
        event_types = {
            row["event_type"] for row in spool.pending_health_events(10)
        }
        assert "ALERT_FILE_TRUNCATED" in event_types
    finally:
        spool.close()


def test_retry_backoff_and_expiry_are_bounded(tmp_path):
    spool = BridgeSpool(
        tmp_path / "spool.sqlite3",
        Fernet.generate_key().decode("ascii"),
    )
    try:
        spool.accept_input(DISPATCH_UID, b'{"value":1}', 16 * 1024 * 1024)
        attempts = spool.mark_retry(
            "input_spool",
            "dispatch_uid",
            DISPATCH_UID,
            "temporary failure",
            base_seconds=2,
            max_seconds=10,
        )
        assert attempts == 1
        assert spool.pending("input_spool", "dispatch_uid", 10) == []
        spool._db.execute(
            "UPDATE input_spool SET record_expires_epoch = 1 WHERE dispatch_uid = ?",
            (DISPATCH_UID,),
        )
        spool._db.commit()
        result = spool.maintenance()
        assert result["input_spool"] == 1
        assert "INPUT_SPOOL_EXPIRED" in {
            row["event_type"] for row in spool.pending_health_events(10)
        }
    finally:
        spool.close()
