from datetime import datetime, timedelta, timezone

import pytest
from fastapi import HTTPException

from app.routes.data import _is_fresh_agent_timestamp
from app.routes.ingest_pulse import _enforce_raw_stream_capacity
from app.utils.siem_catalog import SIEM_RULES
from app.workers.siem_worker import _keyword_sources_for_family, _trusted_telemetry_family


def _windows_event(event_id="4798", message="Administrator was enumerated"):
    return {
        "event_id": event_id,
        "message": message,
        "raw_event_data": {"system": {"channel": "Security"}},
    }


def test_windows_event_cannot_enter_web_keyword_rules():
    event = _windows_event()
    family = _trusted_telemetry_family(event, event["event_id"], "user_enumeration")
    assert family == "windows"
    assert "Web-WAF" not in _keyword_sources_for_family(family)
    assert "Windows-Sec" in _keyword_sources_for_family(family)


def test_web_rules_require_structured_http_file_origin():
    untrusted = {"event_id": "APP-LOG-GENERIC", "event_type": "http_request", "message": "union select"}
    trusted = {
        **untrusted,
        "raw_data": {"web_log_file": r"C:\\inetpub\\logs\\u_ex.log"},
    }
    assert _trusted_telemetry_family(untrusted, untrusted["event_id"], "http_request") == "unknown"
    assert _trusted_telemetry_family(trusted, trusted["event_id"], "http_request") == "web"


def test_unsupported_pilot_rules_are_not_advertised_as_enabled():
    rule_names = {
        "new_location_access",
        "data_exfiltration_volume",
        "beaconing_c2",
        "long_duration_connection",
        "rare_port_usage",
    }
    configured = SIEM_RULES["stateful_detection_rules"]
    discovered = {}
    for category in configured.values():
        for name, rule in category.items():
            if name in rule_names:
                discovered[name] = rule
    assert set(discovered) == rule_names
    assert all(rule["enabled"] is False and rule.get("disabled_reason") for rule in discovered.values())


def test_agent_online_status_requires_fresh_timestamp():
    now = datetime.now(timezone.utc)
    assert _is_fresh_agent_timestamp((now - timedelta(seconds=30)).isoformat(), now=now)
    assert not _is_fresh_agent_timestamp((now - timedelta(minutes=11)).isoformat(), now=now)
    assert not _is_fresh_agent_timestamp("active", now=now)


class _QueueLengthRedis:
    def __init__(self, length):
        self.length = length

    async def xlen(self, _stream):
        return self.length


@pytest.mark.asyncio
async def test_raw_stream_pressure_fails_closed(monkeypatch):
    monkeypatch.setattr("app.routes.ingest_pulse.RAW_STREAM_MAX_ENTRIES", 10)
    await _enforce_raw_stream_capacity(_QueueLengthRedis(9))
    with pytest.raises(HTTPException) as exc:
        await _enforce_raw_stream_capacity(_QueueLengthRedis(10))
    assert exc.value.status_code == 503
