from __future__ import annotations

import json
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

from app.wazuh_integration.registry import validate_registry_document


ROOT = Path(__file__).resolve().parents[1]
REGISTRY_PATH = (
    ROOT / "deploy" / "wazuh" / "registry" / "warsoc-projected-shadow-v2.json"
)
RULES_PATH = (
    ROOT / "deploy" / "wazuh" / "rules" / "warsoc_projected_shadow_rules.xml"
)
CANDIDATE_IDS = {str(rule_id) for rule_id in range(100611, 100633)}
CORRELATION_SEEDS = {"100650", "100651", "100652", "100653"}


def _documents():
    document = json.loads(REGISTRY_PATH.read_text(encoding="utf-8"))
    registry = validate_registry_document(document)
    root = ET.fromstring(RULES_PATH.read_text(encoding="utf-8"))
    xml_rules = {rule.attrib["id"]: rule for rule in root.findall("rule")}
    return document, registry, xml_rules


def _mitre_ids(rule: ET.Element) -> list[str]:
    return [node.text or "" for node in rule.findall("mitre/id")]


def _options(rule: ET.Element) -> set[str]:
    return {node.text or "" for node in rule.findall("options")}


def test_v2_registry_matches_the_custom_wazuh_rules():
    document, registry, xml_rules = _documents()

    assert document["ruleset_version"] == "warsoc-projected-shadow-v2"
    assert document["projection_profile"] == "derived_features_only"
    assert document["authority_mode"] == "shadow_only"
    assert set(registry) == CANDIDATE_IDS
    assert CANDIDATE_IDS.issubset(xml_rules)
    assert {"100600", *CORRELATION_SEEDS}.issubset(xml_rules)
    assert all(rule["family_status"] == "shadow" for rule in registry.values())

    for rule_id, item in registry.items():
        xml_rule = xml_rules[rule_id]
        assert xml_rule.attrib["level"] == str(item["allowed_engine_levels"][0])
        assert _mitre_ids(xml_rule) == item["mitre_ids"]
        assert "no_full_log" in _options(xml_rule)
        if "correlation" in item:
            assert xml_rule.findtext("if_matched_sid") == item["parent_rule_id"]
            assert xml_rule.findtext("same_field") == item["correlation"]["same_field"]
            assert xml_rule.attrib["frequency"] == str(item["correlation"]["frequency"])
            assert xml_rule.attrib["timeframe"] == str(
                item["correlation"]["timeframe_seconds"]
            )
        else:
            assert xml_rule.findtext("if_sid") == item["parent_rule_id"]


def test_v2_projection_is_derived_and_privacy_minimized():
    document, registry, xml_rules = _documents()
    del document, xml_rules

    source_paths = {
        source_path
        for rule in registry.values()
        for source_path in rule["input_field_map"].values()
    }
    assert source_paths
    assert all(path.startswith("detection_features.") for path in source_paths)

    serialized = REGISTRY_PATH.read_text(encoding="utf-8").lower()
    forbidden = {
        "processed_data.command_line",
        "processed_data.image_path",
        "processed_data.task_content",
        "processed_data.object_name",
        "source_ip",
        "destination_ip",
        "target_user",
    }
    assert all(value not in serialized for value in forbidden)


def test_frequency_seeds_are_retained_without_logging_and_tenant_scoped():
    _, registry, xml_rules = _documents()

    for seed_id in CORRELATION_SEEDS:
        seed = xml_rules[seed_id]
        assert seed.attrib["level"] == "1"
        assert "no_log" in _options(seed)

    for item in registry.values():
        correlation = item.get("correlation")
        if correlation is None:
            continue
        same_field = correlation["same_field"]
        assert same_field.startswith("warsoc_corr_tenant")
        seed = xml_rules[item["parent_rule_id"]]
        seed_fields = {
            field.attrib["name"]: field.text for field in seed.findall("field")
        }
        assert seed_fields[same_field] == "^[a-f0-9]{64}$"


def test_rule_pack_avoids_cross_tenant_and_global_suppression_constructs():
    root = ET.fromstring(RULES_PATH.read_text(encoding="utf-8"))

    assert root.findall(".//global_frequency") == []
    assert all("ignore" not in rule.attrib for rule in root.findall("rule"))
    assert root.findall(".//different_field") == []
    assert root.findall(".//not_same_field") == []


def test_base_rule_has_the_expected_schema_contract():
    _, _, xml_rules = _documents()
    base = xml_rules["100600"]

    assert base.attrib["level"] == "0"
    assert base.findtext("decoded_as") == "json"
    schema_field = next(
        field for field in base.findall("field") if field.attrib["name"] == "warsoc_schema"
    )
    assert schema_field.text == "^warsoc.wazuh-local-input/v1$"


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (
            lambda doc: doc["rules"][0].update(family_status="approved"),
            "shadow-only authority",
        ),
        (
            lambda doc: doc["rules"][0]["input_field_map"].update(
                leaked="processed_data.command_line"
            ),
            "derived-feature-only",
        ),
        (
            lambda doc: doc["rules"][-1]["correlation"].update(
                same_field="warsoc_event_id"
            ),
            "unsafe correlation field",
        ),
    ],
)
def test_registry_rejects_unsafe_v2_mutations(mutation, message):
    document = json.loads(REGISTRY_PATH.read_text(encoding="utf-8"))
    mutation(document)

    with pytest.raises(ValueError, match=message):
        validate_registry_document(document)
