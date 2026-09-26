from datetime import datetime, timezone

import pytest

from app.network_relay.health import relay_health_issues
from app.routes.network_relay import _device_public_status, _relay_public_status
from app.utils.endpoint_health import endpoint_health_issues
from app.utils.alert_context import build_alert_context
from app.utils.security_incidents import build_incident_identity


@pytest.mark.parametrize("health", ["OFFLINE", "RELAY_OFFLINE", "SILENT", "NOT_SEEN", "DEGRADED", "REVOKED", "INACTIVE"])
def test_relay_health_guidance_is_bounded_and_actionable(health):
    issue = relay_health_issues(health)[0]
    assert issue["code"] == health
    assert issue["summary"]
    assert 1 <= len(issue["remediation"]) <= 3
    assert relay_health_issues("ACTIVE") == []


def test_relay_status_keeps_parent_and_device_health_distinct():
    now = datetime.now(timezone.utc)
    relay = _relay_public_status({"relay_id": "R1", "status": "active"}, now)
    assert relay["health"] == "OFFLINE"
    assert relay["health_issues"][0]["code"] == "OFFLINE"
    device = _device_public_status({"device_id": "FW1"}, None, relay["health"], now)
    assert device["health"] == "RELAY_OFFLINE"
    assert device["health_issues"][0]["code"] == "RELAY_OFFLINE"


def test_offline_endpoint_does_not_present_stale_spool_as_current_cause():
    issues = endpoint_health_issues(
        online=False, sensor_status={"spool": {"blocked": True}},
        signing_required=True, signing_ready=False, server_required=True,
        server_health="PENDING", audit_configured=False,
    )
    assert [issue["code"] for issue in issues] == ["AGENT_OFFLINE"]


def test_health_grouping_never_merges_tenants_or_unrelated_attack_alerts():
    base = {
        "tenant_id": "T1", "source": "network_relay_watchdog",
        "alert_type": "RELAY_OFFLINE", "type": "RELAY_OFFLINE",
        "relay_id": "R1", "health_condition_id": "a" * 64,
        "timestamp": datetime(2026, 9, 26, 10, 0, tzinfo=timezone.utc),
    }
    first = build_incident_identity(base)["incident_id"]
    later = {**base, "timestamp": datetime(2026, 9, 26, 11, 0, tzinfo=timezone.utc)}
    assert first == build_incident_identity(later)["incident_id"]
    assert first != build_incident_identity({**later, "tenant_id": "T2"})["incident_id"]
    assert first != build_incident_identity({**later, "relay_id": "R2"})["incident_id"]
    attack = {**base, "source": "SIEM", "type": "SUSPICIOUS_PROCESS"}
    assert build_incident_identity(attack)["incident_id"] != build_incident_identity({**attack, "timestamp": later["timestamp"]})["incident_id"]


def test_health_guidance_context_is_bounded_and_secret_redacted():
    context = build_alert_context({
        "signal_kind": "telemetry_health",
        "remediation": ["password=do-not-expose", {"raw": "untrusted"}] + ["x" * 1000] * 20,
    })
    assert context["signal_kind"] == "telemetry_health"
    assert len(context["remediation"]) <= 6
    assert all(len(step) <= 300 for step in context["remediation"])
    assert "do-not-expose" not in " ".join(context["remediation"])
