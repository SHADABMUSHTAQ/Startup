"""Configuration boundary for the isolated Compute-B Wazuh bridge."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

from cryptography.fernet import Fernet


def _required(name: str) -> str:
    value = os.getenv(name, "").strip()
    if not value:
        raise RuntimeError(f"{name} is required for the Wazuh bridge")
    return value


@dataclass(frozen=True)
class BridgeSettings:
    connector_id: str
    engine_instance_id: str
    engine_version: str
    ruleset_version: str
    dispatch_signing_secret: str
    candidate_signing_secret: str
    spool_encryption_key: str
    spool_path: Path
    input_spool_max_bytes: int
    candidate_spool_max_bytes: int
    live_event_max_age_seconds: int
    candidate_record_ttl_seconds: int
    receipt_retention_seconds: int
    health_retention_seconds: int
    retry_base_seconds: int
    retry_max_seconds: int
    max_body_bytes: int
    max_batch_events: int
    wazuh_host: str
    wazuh_port: int
    wazuh_alerts_path: Path
    alerts_initial_position: str
    rule_registry_path: Path
    rule_registry_sha256: str
    candidate_url: str
    health_url: str
    candidate_ca_file: Path
    candidate_cert_file: Path
    candidate_key_file: Path

    @classmethod
    def from_env(cls) -> "BridgeSettings":
        if os.getenv("WAZUH_BRIDGE_ENABLED", "false").strip().lower() not in {
            "1",
            "true",
            "yes",
        }:
            raise RuntimeError("WAZUH_BRIDGE_ENABLED must be true")
        settings = cls(
            connector_id=_required("WAZUH_CONNECTOR_ID"),
            engine_instance_id=_required("WAZUH_ENGINE_INSTANCE_ID"),
            engine_version=_required("WAZUH_ENGINE_VERSION"),
            ruleset_version=_required("WAZUH_RULESET_VERSION"),
            dispatch_signing_secret=_required("WAZUH_DISPATCH_SIGNING_SECRET"),
            candidate_signing_secret=_required("WAZUH_CANDIDATE_SIGNING_SECRET"),
            spool_encryption_key=_required("WAZUH_BRIDGE_SPOOL_ENCRYPTION_KEY"),
            spool_path=Path(os.getenv("WAZUH_BRIDGE_SPOOL_PATH", "/var/lib/warsoc-wazuh/bridge.sqlite3")),
            input_spool_max_bytes=int(os.getenv("WAZUH_BRIDGE_INPUT_SPOOL_MAX_BYTES", str(512 * 1024 * 1024))),
            candidate_spool_max_bytes=int(os.getenv("WAZUH_BRIDGE_CANDIDATE_SPOOL_MAX_BYTES", str(256 * 1024 * 1024))),
            live_event_max_age_seconds=int(os.getenv("WAZUH_LIVE_EVENT_MAX_AGE_SECONDS", "60")),
            candidate_record_ttl_seconds=int(os.getenv("WAZUH_BRIDGE_CANDIDATE_RECORD_TTL_SECONDS", "86400")),
            receipt_retention_seconds=int(os.getenv("WAZUH_BRIDGE_RECEIPT_RETENTION_SECONDS", "604800")),
            health_retention_seconds=int(os.getenv("WAZUH_BRIDGE_HEALTH_RETENTION_SECONDS", "2592000")),
            retry_base_seconds=int(os.getenv("WAZUH_BRIDGE_RETRY_BASE_SECONDS", "2")),
            retry_max_seconds=int(os.getenv("WAZUH_BRIDGE_RETRY_MAX_SECONDS", "300")),
            max_body_bytes=int(os.getenv("WAZUH_MAX_BODY_BYTES", str(512 * 1024))),
            max_batch_events=int(os.getenv("WAZUH_MAX_BATCH_EVENTS", "100")),
            wazuh_host=os.getenv("WAZUH_BRIDGE_MANAGER_HOST", "127.0.0.1").strip(),
            wazuh_port=int(os.getenv("WAZUH_BRIDGE_MANAGER_PORT", "15140")),
            wazuh_alerts_path=Path(_required("WAZUH_ALERTS_JSON_PATH")),
            alerts_initial_position=os.getenv("WAZUH_ALERTS_INITIAL_POSITION", "end").strip().lower(),
            rule_registry_path=Path(_required("WAZUH_RULE_REGISTRY_PATH")),
            rule_registry_sha256=_required("WAZUH_RULE_REGISTRY_SHA256").lower(),
            candidate_url=_required("WAZUH_CANDIDATE_URL"),
            health_url=_required("WAZUH_HEALTH_URL"),
            candidate_ca_file=Path(_required("WAZUH_CANDIDATE_CA_FILE")),
            candidate_cert_file=Path(_required("WAZUH_CANDIDATE_CERT_FILE")),
            candidate_key_file=Path(_required("WAZUH_CANDIDATE_KEY_FILE")),
        )
        settings.validate()
        return settings

    def validate(self) -> None:
        if len(self.dispatch_signing_secret.encode("utf-8")) < 32:
            raise RuntimeError("WAZUH_DISPATCH_SIGNING_SECRET must be at least 32 bytes")
        if len(self.candidate_signing_secret.encode("utf-8")) < 32:
            raise RuntimeError("WAZUH_CANDIDATE_SIGNING_SECRET must be at least 32 bytes")
        try:
            Fernet(self.spool_encryption_key.encode("ascii"))
        except (TypeError, ValueError) as exc:
            raise RuntimeError("WAZUH_BRIDGE_SPOOL_ENCRYPTION_KEY must be a Fernet key") from exc
        if not 16 * 1024 * 1024 <= self.input_spool_max_bytes <= 4 * 1024 * 1024 * 1024:
            raise RuntimeError("WAZUH_BRIDGE_INPUT_SPOOL_MAX_BYTES is outside the approved range")
        if not 16 * 1024 * 1024 <= self.candidate_spool_max_bytes <= 2 * 1024 * 1024 * 1024:
            raise RuntimeError("WAZUH_BRIDGE_CANDIDATE_SPOOL_MAX_BYTES is outside the approved range")
        if not 65536 <= self.max_body_bytes <= 5 * 1024 * 1024:
            raise RuntimeError("WAZUH_MAX_BODY_BYTES is outside the approved range")
        if not 1 <= self.max_batch_events <= 500:
            raise RuntimeError("WAZUH_MAX_BATCH_EVENTS is outside the approved range")
        if not 10 <= self.live_event_max_age_seconds <= 900:
            raise RuntimeError("WAZUH_LIVE_EVENT_MAX_AGE_SECONDS is outside the approved range")
        if not 300 <= self.candidate_record_ttl_seconds <= 7 * 24 * 60 * 60:
            raise RuntimeError("WAZUH_BRIDGE_CANDIDATE_RECORD_TTL_SECONDS is outside the approved range")
        if not 3600 <= self.receipt_retention_seconds <= 30 * 24 * 60 * 60:
            raise RuntimeError("WAZUH_BRIDGE_RECEIPT_RETENTION_SECONDS is outside the approved range")
        if not 86400 <= self.health_retention_seconds <= 365 * 24 * 60 * 60:
            raise RuntimeError("WAZUH_BRIDGE_HEALTH_RETENTION_SECONDS is outside the approved range")
        if not 1 <= self.retry_base_seconds <= 60:
            raise RuntimeError("WAZUH_BRIDGE_RETRY_BASE_SECONDS is outside the approved range")
        if not self.retry_base_seconds <= self.retry_max_seconds <= 3600:
            raise RuntimeError("WAZUH_BRIDGE_RETRY_MAX_SECONDS is outside the approved range")
        if not 1 <= self.wazuh_port <= 65535:
            raise RuntimeError("WAZUH_BRIDGE_MANAGER_PORT is invalid")
        if self.alerts_initial_position not in {"beginning", "end"}:
            raise RuntimeError("WAZUH_ALERTS_INITIAL_POSITION must be beginning or end")
        for name, value in (
            ("WAZUH_CANDIDATE_URL", self.candidate_url),
            ("WAZUH_HEALTH_URL", self.health_url),
        ):
            parsed = urlparse(value)
            if parsed.scheme != "https" or not parsed.netloc:
                raise RuntimeError(f"{name} must use HTTPS")
        for path in (
            self.wazuh_alerts_path,
            self.rule_registry_path,
            self.candidate_ca_file,
            self.candidate_cert_file,
            self.candidate_key_file,
        ):
            if not path.is_file():
                raise RuntimeError(f"Required Wazuh bridge file is unavailable: {path}")
