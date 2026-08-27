from __future__ import annotations

import json
import xml.etree.ElementTree as ET
from pathlib import Path

from app.wazuh_integration.registry import validate_registry_document


ROOT = Path(__file__).resolve().parents[1]
REGISTRY_PATH = (
    ROOT / "deploy" / "wazuh" / "registry" / "warsoc-projected-shadow-v1.json"
)
RULES_PATH = (
    ROOT / "deploy" / "wazuh" / "rules" / "warsoc_projected_shadow_rules.xml"
)


def test_projected_shadow_registry_matches_custom_wazuh_rules():
    document = json.loads(REGISTRY_PATH.read_text(encoding="utf-8"))
    registry = validate_registry_document(document)
    xml_root = ET.fromstring(RULES_PATH.read_text(encoding="utf-8"))
    xml_rules = {
        rule.attrib["id"]: rule
        for rule in xml_root.findall("rule")
    }

    assert document["ruleset_version"] == "warsoc-projected-shadow-v1"
    assert set(registry) == {"100511", "100512", "100513", "100514"}
    assert set(registry).issubset(xml_rules)
    assert "100510" in xml_rules
    assert all(rule["family_status"] == "shadow" for rule in registry.values())
    assert all(rule_id.startswith("1005") for rule_id in registry)

    for rule_id, item in registry.items():
        xml_rule = xml_rules[rule_id]
        assert xml_rule.attrib["level"] == str(item["allowed_engine_levels"][0])
        assert xml_rule.findtext("if_sid") == item["parent_rule_id"]
        assert xml_rule.findtext("field") == f"^{item['event_ids'][0]}$"


def test_projected_shadow_rule_pack_has_privacy_minimized_base_contract():
    xml_root = ET.fromstring(RULES_PATH.read_text(encoding="utf-8"))
    base = next(rule for rule in xml_root.findall("rule") if rule.attrib["id"] == "100510")

    assert base.attrib["level"] == "0"
    assert base.findtext("decoded_as") == "json"
    schema_field = base.find("field")
    assert schema_field is not None
    assert schema_field.attrib["name"] == "warsoc_schema"
    assert schema_field.text == "^warsoc.wazuh-local-input/v1$"
