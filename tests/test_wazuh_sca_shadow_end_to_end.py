from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from fastapi import HTTPException

from app.routes.sca import require_sca_enabled
from app.services.sca_service import get_agent_sca_posture, get_tenant_sca_summary
from app.wazuh_integration.bridge_runtime import _candidate_from_alert
from app.wazuh_integration.registry import validate_registry_document


class AsyncCursor:
    def __init__(self, documents):
        self.documents = list(documents)
        self.index = 0

    def sort(self, *_args, **_kwargs):
        return self

    def limit(self, value):
        self.documents = self.documents[:value]
        return self

    def __aiter__(self):
        self.index = 0
        return self

    async def __anext__(self):
        if self.index >= len(self.documents):
            raise StopAsyncIteration
        document = self.documents[self.index]
        self.index += 1
        return document

    async def to_list(self, length):
        return self.documents[:length]


def _bridge_settings():
    return SimpleNamespace(
        connector_id="wazuh-shadow-01",
        engine_instance_id="wazuh-node-01",
        engine_version="4.14.7",
        ruleset_version="warsoc-projected-shadow-v3",
    )


def _alert(rule_id: str, *, sca_type: str, result: str = "failed") -> dict:
    return {
        "timestamp": "2026-09-19T13:00:00.000+0000",
        "rule": {
            "level": 7,
            "description": "SCA candidate",
            "id": rule_id,
            "groups": ["sca"],
        },
        "agent": {"id": "007", "name": "server-2022"},
        "data": {
            "sca": {
                "type": sca_type,
                "scan_id": "scan-42",
                "policy": "CIS Microsoft Windows Server 2022 Benchmark",
                "policy_id": "cis_win2022",
                "check": {
                    "id": "10001",
                    "title": "Minimum password length",
                    "rationale": "Weak passwords increase authentication risk.",
                    "remediation": "Set the minimum password length to 14.",
                    "result": result,
                    "compliance": {
                        "cis": "1.1.1",
                        "cis_csc_v8": "5.2",
                        "pci_dss_v4": {"0": "8.3.6"},
                        "unsafe.key": "must-not-project",
                    },
                },
            }
        },
    }


def _registry() -> dict:
    path = Path("deploy/wazuh/registry/warsoc-projected-shadow-v3.json")
    return validate_registry_document(json.loads(path.read_text(encoding="utf-8")))


def test_sca_registry_uses_only_official_check_and_transition_rules():
    registry = _registry()
    expected_levels = {
        "19007": [7],
        "19008": [3],
        "19009": [3],
        "19010": [3],
        "19011": [9],
        "19012": [5],
        "19013": [5],
        "19014": [9],
        "19015": [3],
    }
    assert {rule_id for rule_id in registry if rule_id.startswith("190")} == set(
        expected_levels
    )
    for rule_id, levels in expected_levels.items():
        rule = registry[rule_id]
        assert rule["allowed_engine_levels"] == levels
        assert rule["category"] == "system_audit"
        assert rule["family"] == "configuration_assessment"
        assert rule["family_status"] == "shadow"
        assert rule["attack_level"] is False


def test_real_sca_check_rule_projects_bounded_check_fields():
    candidate = _candidate_from_alert(
        _alert("19007", sca_type="check"),
        _registry(),
        _bridge_settings(),
    )

    assert candidate.engine_rule_id == "19007"
    assert candidate.selected_security_fields["sca_type"] == "check"
    assert candidate.selected_security_fields["check_id"] == "10001"
    assert candidate.selected_security_fields["result"] == "failed"
    assert candidate.selected_security_fields["compliance_cis"] == "1.1.1"
    assert candidate.selected_security_fields["compliance_cis_csc_v8"] == "5.2"
    assert candidate.selected_security_fields["compliance_pci_dss_v4"] == "8.3.6"
    assert "compliance_unsafe_key" not in candidate.selected_security_fields


def test_sca_summary_rule_does_not_masquerade_as_a_check():
    candidate = _candidate_from_alert(
        _alert("19002", sca_type="summary"),
        _registry(),
        _bridge_settings(),
    )
    assert candidate is None


async def test_posture_uses_only_latest_scan_check_events():
    now = datetime.now(timezone.utc)
    new_scan = [
        {
            "tenant_id": "tenant-1",
            "wazuh_agent_id": "007",
            "category": "system_audit",
            "severity": severity,
            "engine_detected_at": now - timedelta(seconds=index),
            "selected_security_fields": {
                "sca_type": "check",
                "scan_id": "scan-new",
                "check_id": str(10000 + index),
                "check_title": f"Control {index}",
                "result": result,
                "policy": "CIS Windows Server 2022",
            },
        }
        for index, (result, severity) in enumerate(
            [
                ("failed", "HIGH"),
                ("passed", "INFO"),
                ("passed", "INFO"),
                ("passed", "INFO"),
                ("passed", "INFO"),
            ],
            start=1,
        )
    ]
    old_scan = {
        **new_scan[0],
        "engine_detected_at": now - timedelta(days=1),
        "selected_security_fields": {
            **new_scan[0]["selected_security_fields"],
            "scan_id": "scan-old",
            "check_id": "old-only",
            "result": "failed",
        },
    }

    db = MagicMock()
    db.detection_engine_agent_bindings.find.return_value = AsyncCursor(
        [{"tenant_id": "tenant-1", "warsoc_agent_id": "agent-1", "wazuh_agent_id": "007"}]
    )
    db.detection_engine_observations.find.return_value = AsyncCursor(
        [*new_scan, old_scan]
    )

    posture = await get_agent_sca_posture(db, "tenant-1", "agent-1")

    assert posture["compliance_score"] == 80.0
    assert posture["status"] == "COMPLIANT"
    assert posture["freshness"] == "CURRENT"
    assert posture["scan_id"] == "scan-new"
    assert posture["assessment_trust"] == "AGENT_REPORTED"
    assert posture["summary"] == {
        "total_checks": 5,
        "passed": 4,
        "failed": 1,
        "not_applicable": 0,
    }
    assert {finding["check_id"] for finding in posture["findings"]} == {"10001"}


async def test_old_sca_scan_is_reported_stale_not_compliant():
    db = MagicMock()
    db.detection_engine_agent_bindings.find.return_value = AsyncCursor(
        [{"tenant_id": "tenant-1", "warsoc_agent_id": "agent-1", "wazuh_agent_id": "007"}]
    )
    db.detection_engine_observations.find.return_value = AsyncCursor(
        [
            {
                "tenant_id": "tenant-1",
                "wazuh_agent_id": "007",
                "category": "system_audit",
                "severity": "INFO",
                "engine_detected_at": datetime.now(timezone.utc) - timedelta(hours=49),
                "selected_security_fields": {
                    "sca_type": "check",
                    "scan_id": "scan-stale",
                    "check_id": "10001",
                    "check_title": "Control 1",
                    "result": "passed",
                    "policy": "CIS Windows Server 2022",
                },
            }
        ]
    )

    posture = await get_agent_sca_posture(
        db, "tenant-1", "agent-1", stale_after_hours=36
    )

    assert posture["compliance_score"] == 100.0
    assert posture["status"] == "STALE"
    assert posture["freshness"] == "STALE"


async def test_tenant_summary_returns_bounded_endpoint_selector_contract():
    now = datetime.now(timezone.utc)
    db = MagicMock()
    db.agents.find.return_value = AsyncCursor(
        [{"agent_id": "agent-2"}, {"agent_id": "agent-1"}]
    )
    db.detection_engine_agent_bindings.find.return_value = AsyncCursor(
        [{"tenant_id": "tenant-1", "warsoc_agent_id": "agent-1", "wazuh_agent_id": "007"}]
    )
    db.detection_engine_observations.find.return_value = AsyncCursor(
        [
            {
                "tenant_id": "tenant-1",
                "wazuh_agent_id": "007",
                "category": "system_audit",
                "severity": "INFO",
                "engine_detected_at": now,
                "selected_security_fields": {
                    "sca_type": "check",
                    "scan_id": "scan-current",
                    "check_id": "10001",
                    "check_title": "Control 1",
                    "result": "passed",
                    "policy": "CIS Windows Server 2022",
                },
            }
        ]
    )

    summary = await get_tenant_sca_summary(db, "tenant-1")

    assert summary["total_endpoints"] == 2
    assert summary["assessed_endpoints"] == 1
    assert summary["endpoints"][0]["agent_id"] == "agent-1"
    assert summary["endpoints"][0]["status"] == "COMPLIANT"
    assert summary["endpoints"][1]["status"] == "NOT_ASSESSED"


def test_sca_routes_are_fail_closed_until_explicitly_enabled():
    with pytest.raises(HTTPException) as exc_info:
        require_sca_enabled(SimpleNamespace(wazuh_sca_enabled=False))
    assert exc_info.value.status_code == 503

    settings = SimpleNamespace(wazuh_sca_enabled=True)
    assert require_sca_enabled(settings) is settings
