"""Current production rule-catalog integrity contracts.

The executable rule behavior is exercised in ``test_core_engine_rule_contracts``
and the SIEM deep-dive suite. These checks prevent the catalog from advertising
rules that the Windows pilot cannot feed or from mixing web and native telemetry.
"""

from app.utils.siem_catalog import SIEM_RULES
from tests.test_core_engine_rule_contracts import SIEM_RULE_SAMPLES


WEB_RULES = {
    "SQL_INJECTION",
    "XSS_ATTACK",
    "COMMAND_INJECTION",
    "PATH_TRAVERSAL",
    "XXE_INJECTION",
    "WEB_SHELL_ACTIVITY",
}

PILOT_DISABLED_RULES = {
    "SIEM-FW-001",
    "LINUX_SYSTEM_TIMESTOMPING",
}


def test_enabled_catalog_rules_have_executable_contract_samples():
    rules = SIEM_RULES["detection"]["rules"]
    enabled = {name for name, rule in rules.items() if rule.get("enabled", True)}

    assert enabled == set(SIEM_RULE_SAMPLES) - PILOT_DISABLED_RULES


def test_windows_pilot_keeps_unsupported_rules_disabled():
    rules = SIEM_RULES["detection"]["rules"]

    for rule_name in PILOT_DISABLED_RULES:
        assert rules[rule_name]["enabled"] is False
        assert rules[rule_name].get("disabled_reason")


def test_web_rules_require_trusted_http_request_context():
    rules = SIEM_RULES["detection"]["rules"]

    for rule_name in WEB_RULES:
        assert rules[rule_name]["requires_context"] == ["http_request"]


def test_windows_firewall_event_semantics_are_evidence_first():
    event_map = SIEM_RULES["event_id_map"]

    assert event_map["5156"] == {
        "event_type": "network_connection_permitted",
        "severity": "INFO",
        "frameworks": [],
        "alert_on_event": False,
    }
    assert event_map["5157"] == {
        "event_type": "network_connection_blocked",
        "severity": "HIGH",
        "frameworks": ["peca_forensic"],
        "alert_on_event": False,
    }
