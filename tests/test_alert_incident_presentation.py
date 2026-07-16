from datetime import datetime, timedelta, timezone

import pytest

from app.utils.alert_incidents import aggregate_security_alerts, operator_message
from app.utils.compliance_catalog import COMPLIANCE_CATALOG
from app.utils.siem_catalog import SIEM_RULES
from app.utils.siem_logic import SIEMEngine
from app.workers.siem_worker import _resolve_direct_event_severity


def _alert(*, alert_id, event_uid, alert_type, event_id, summary, seconds=0, severity="HIGH"):
    return {
        "_id": alert_id,
        "tenant_id": "TENANT-A",
        "event_uid": event_uid,
        "type": alert_type,
        "event_id": event_id,
        "summary": summary,
        "message": f"Windows Event {event_id}: {{\"noisy\": \"payload\"}}",
        "severity": severity,
        "status": "NEW",
        "source_ip": "10.0.0.9",
        "user": "operator",
        "agent_id": "AGENT-A",
        "timestamp": (datetime.now(timezone.utc) + timedelta(seconds=seconds)).isoformat(),
    }


def test_repeated_alerts_are_one_incident_with_unique_event_quantity():
    alerts = [
        _alert(
            alert_id="direct-1",
            event_uid="Security:100",
            alert_type="WIN_EVENT_1102_DETECTED",
            event_id="1102",
            summary="Security Event: Clear Logs",
        ),
        _alert(
            alert_id="advanced-1",
            event_uid="Security:100",
            alert_type="EVENT_ID_1102_CLEAR_LOGS",
            event_id="1102",
            summary="Clear Logs detected",
        ),
        _alert(
            alert_id="advanced-2",
            event_uid="Security:101",
            alert_type="EVENT_ID_1102_CLEAR_LOGS",
            event_id="1102",
            summary="Clear Logs detected",
            seconds=1,
        ),
    ]

    incidents = aggregate_security_alerts(alerts)

    assert len(incidents) == 1
    assert incidents[0]["occurrences"] == 2
    assert set(incidents[0]["related_alert_ids"]) == {"direct-1", "advanced-1", "advanced-2"}
    assert "noisy" not in incidents[0]["message"]


def test_specific_findings_replace_coarse_keyword_interpretation_only():
    alerts = [
        _alert(
            alert_id="coarse",
            event_uid="WEB:1",
            alert_type="WEB-WAF_KEYWORD_MATCH",
            event_id="80",
            summary="Generic web keyword match",
        ),
        _alert(
            alert_id="sql",
            event_uid="WEB:1",
            alert_type="SQL_INJECTION",
            event_id="80",
            summary="SQL injection attempt detected",
            severity="CRITICAL",
        ),
        _alert(
            alert_id="exfil",
            event_uid="WEB:1",
            alert_type="DATA_EXFILTRATION",
            event_id="80",
            summary="Data exfiltration pattern detected",
            severity="CRITICAL",
        ),
    ]

    incidents = aggregate_security_alerts(alerts)

    assert {incident["type"] for incident in incidents} == {"SQL_INJECTION", "DATA_EXFILTRATION"}
    assert all("coarse" in incident["related_alert_ids"] for incident in incidents)


def test_operator_message_never_uses_raw_windows_json_when_meaning_exists():
    message = operator_message(
        {
            "event_id": "4625",
            "event_id_meaning": "Failed Login",
            "message": 'Windows Event 4625: {"TargetUserName": "alice"}',
            "agent_id": "AGENT-A",
        }
    )
    assert message == "Failed Login on AGENT-A"


def test_fbr_incidents_do_not_merge_different_protected_targets():
    base = _alert(
        alert_id="fbr-1",
        event_uid="FBR:1",
        alert_type="FIM-DB-MOD",
        event_id="FIM-DB-MOD",
        summary="Database File Tamper Confirmed",
        severity="CRITICAL",
    )
    base.update({"pack": "fbr_pos", "target_fingerprint": "target-a"})
    other = dict(base)
    other.update({"_id": "fbr-2", "event_uid": "FBR:2", "target_fingerprint": "target-b"})

    incidents = aggregate_security_alerts([base, other])

    assert len(incidents) == 2


@pytest.mark.asyncio
async def test_direct_event_marker_prevents_duplicate_event_map_alert_but_keeps_regex():
    engine = SIEMEngine(
        {
            "event_id_map": {
                "1102": {
                    "event_type": "clear_logs",
                    "severity": "CRITICAL",
                    "alert_on_event": True,
                }
            },
            "detection": {
                "fp_controls": {"max_alerts_per_log": 5},
                "rules": {
                    "LOG_CLEAR_COMMAND": {
                        "regex": "(?i)wevtutil",
                        "sev": "CRITICAL",
                        "mitre": "T1070.001",
                        "min_message_length": 1,
                    }
                },
            },
        }
    )

    findings = await engine.analyze_single_log(
        {
            "event_id": "1102",
            "event_uid": "Security:1102",
            "message": "wevtutil cl security",
            "_direct_event_rule_alerted": True,
        }
    )

    assert [finding["type"] for finding in findings] == ["LOG_CLEAR_COMMAND"]


def test_fbr_catalog_contains_only_invoice_and_pos_file_integrity_controls():
    fbr_ids = {rule["event_id"] for rule in COMPLIANCE_CATALOG["fbr_pos"]["rules"]}
    assert "4657" not in fbr_ids
    assert "4698" not in fbr_ids
    assert SIEM_RULES["event_id_map"]["4657"]["frameworks"] == []
    assert SIEM_RULES["event_id_map"]["4698"]["frameworks"] == []


def test_direct_peca_control_severities_have_one_source_of_truth():
    expected = {
        "1100": "CRITICAL",
        "1102": "CRITICAL",
        "4697": "CRITICAL",
        "7045": "CRITICAL",
        "4719": "HIGH",
        "4720": "HIGH",
        "4726": "HIGH",
        "4732": "HIGH",
    }
    for event_id, severity in expected.items():
        rule = SIEM_RULES["event_id_map"][event_id]
        assert rule["alert_on_event"] is True
        assert rule["severity"] == severity
        assert _resolve_direct_event_severity(
            rule,
            SIEM_RULES["source_classification"]["Windows-Sec"],
            event_id,
        ) == severity

    firewall_block = SIEM_RULES["event_id_map"]["5157"]
    assert firewall_block["frameworks"] == ["peca_forensic"]
    assert firewall_block["alert_on_event"] is False
