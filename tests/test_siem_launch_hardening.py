import pytest

from app.utils.siem_logic import SIEMEngine
from app.workers.siem_worker import (
    _extract_tenant_id_from_raw_payload,
    _is_whitelisted_source,
    _should_persist_alert_under_bouncer,
)


class FakeRedis:
    def __init__(self):
        self.store = {}
        self.members = {}

    async def get(self, key):
        return self.store.get(key)

    async def setex(self, key, seconds, value):
        self.store[key] = value
        return True

    async def exists(self, key):
        return 1 if key in self.store else 0

    async def sismember(self, key, value):
        return value in self.members.get(key, set())


@pytest.mark.asyncio
async def test_regex_cooldown_is_scoped_to_same_payload():
    config = {
        "detection": {
            "fp_controls": {
                "max_alerts_per_log": 5,
                "rule_cooldown_seconds": 60,
            },
            "rules": {
                "CUSTOM_ATTACK": {
                    "regex": "(?i)attack",
                    "sev": "HIGH",
                    "mitre": "T0000",
                    "min_message_length": 1,
                }
            },
        }
    }
    redis = FakeRedis()
    engine = SIEMEngine(config)
    engine.set_redis_client(redis)

    first = await engine.analyze_single_log(
        {"tenant_id": "TENANT-A", "source_ip": "10.0.0.9", "event_type": "http_request", "message": "attack probe"}
    )
    duplicate = await engine.analyze_single_log(
        {"tenant_id": "TENANT-A", "source_ip": "10.0.0.9", "event_type": "http_request", "message": "attack probe"}
    )
    changed_payload = await engine.analyze_single_log(
        {"tenant_id": "TENANT-A", "source_ip": "10.0.0.9", "event_type": "http_request", "message": "attack destructive payload"}
    )

    assert [finding["type"] for finding in first] == ["CUSTOM_ATTACK"]
    assert duplicate == []
    assert [finding["type"] for finding in changed_payload] == ["CUSTOM_ATTACK"]
    assert len(redis.store) == 2


def test_bouncer_only_suppresses_low_and_medium_alerts():
    assert _should_persist_alert_under_bouncer(False, "MEDIUM") is True
    assert _should_persist_alert_under_bouncer(True, "INFO") is False
    assert _should_persist_alert_under_bouncer(True, "MEDIUM") is False
    assert _should_persist_alert_under_bouncer(True, "HIGH") is True
    assert _should_persist_alert_under_bouncer(True, "CRITICAL") is True


@pytest.mark.asyncio
async def test_worker_whitelist_helper_checks_soar_and_static_lists():
    redis = FakeRedis()
    redis.members["warsoc:soar_whitelist:TENANT-A"] = {"10.0.0.8"}
    engine = SIEMEngine(
        {
            "whitelist": {
                "ips": ["10.0.0.10"],
                "service_accounts": ["svc_backup"],
            },
            "detection": {"rules": {}},
        }
    )

    assert await _is_whitelisted_source(redis, "TENANT-A", "10.0.0.8", "normal_user", engine) is True
    assert await _is_whitelisted_source(redis, "TENANT-A", "10.0.0.10", "normal_user", engine) is True
    assert await _is_whitelisted_source(redis, "TENANT-A", "10.0.0.11", "svc_backup", engine) is True
    assert await _is_whitelisted_source(redis, "TENANT-A", "10.0.0.11", "normal_user", engine) is False


def test_dlq_tenant_extraction_handles_malformed_payload():
    raw_payload = """{"tenant_id": "TENANT-A", "message": "mimikatz payload", broken"""
    assert _extract_tenant_id_from_raw_payload(raw_payload) == "TENANT-A"
    assert _extract_tenant_id_from_raw_payload("no tenant here") is None
