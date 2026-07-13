"""
Dynamic SIEM rule engine tests.

These tests exercise the config-driven correlation path directly so the suite
covers unique-field tracking and time-window rules without needing the full
worker loop.
"""
from datetime import datetime, timezone

import pytest

from app.utils.siem_catalog import SIEM_RULES
from app.utils.siem_logic import CorrelationEngine
from app.workers import siem_worker


class FakePipeline:
    def __init__(self, redis):
        self.redis = redis
        self.ops = []

    def sadd(self, key, value):
        self.ops.append(("sadd", key, value))
        return self

    def expire(self, key, ttl):
        self.ops.append(("expire", key, ttl))
        return self

    def scard(self, key):
        self.ops.append(("scard", key))
        return self

    def incr(self, key):
        self.ops.append(("incr", key))
        return self

    def hincrby(self, key, field, amount):
        self.ops.append(("hincrby", key, field, amount))
        return self

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def execute(self):
        results = []
        for op in self.ops:
            if op[0] == "sadd":
                _, key, value = op
                bucket = self.redis.sets.setdefault(key, set())
                bucket.add(str(value))
                results.append(1)
            elif op[0] == "expire":
                results.append(True)
            elif op[0] == "scard":
                _, key = op
                results.append(len(self.redis.sets.get(key, set())))
            elif op[0] == "incr":
                _, key = op
                self.redis.counters[key] = self.redis.counters.get(key, 0) + 1
                results.append(self.redis.counters[key])
            elif op[0] == "hincrby":
                _, key, field, amount = op
                bucket = self.redis.hashes.setdefault(key, {})
                bucket[field] = bucket.get(field, 0) + int(amount)
                results.append(bucket[field])
        return results


class FakeRedis:
    def __init__(self):
        self.values = {}
        self.sets = {}
        self.counters = {}
        self.hashes = {}
        self.published = []

    def pipeline(self, transaction=True):
        return FakePipeline(self)

    async def set(self, key, value, nx=False, ex=None):
        if nx and key in self.values:
            return False
        self.values[key] = value
        return True

    async def get(self, key):
        return self.values.get(key)

    async def sadd(self, key, value):
        bucket = self.sets.setdefault(key, set())
        before = len(bucket)
        bucket.add(str(value))
        return 1 if len(bucket) > before else 0

    async def sismember(self, key, value):
        return str(value) in self.sets.get(key, set())

    async def scard(self, key):
        return len(self.sets.get(key, set()))

    async def expire(self, key, ttl):
        return True

    async def incr(self, key):
        self.counters[key] = self.counters.get(key, 0) + 1
        return self.counters[key]

    async def publish(self, channel, message):
        self.published.append((channel, message))
        return 1


def test_correlation_alert_uses_security_alerts_absolute_expiry():
    alert = CorrelationEngine._alert(
        alert_type="test",
        severity="HIGH",
        summary="Retention contract",
        tenant_id="TENANT-RETENTION",
        source_ip="10.0.0.5",
        user="analyst",
        event_id=4625,
        mitre="T1110",
    )

    assert "_retention_ts" not in alert
    assert isinstance(alert["_expire_at"], datetime)
    assert alert["_expire_at"] > datetime.now(timezone.utc)


def test_siem_cold_vault_uses_the_indexed_absolute_expiry_field():
    assert siem_worker.RAW_RETENTION_ANCHOR_FIELD == "_expire_at"


@pytest.mark.asyncio
async def test_unique_field_rule_triggers_on_distinct_values():
    redis = FakeRedis()
    config = {
        "stateful_detection_rules": {
            "auth_identity": {
                "password_spraying": {
                    "enabled": True,
                    "threshold_users": 3,
                    "window_seconds": 300,
                    "mitre_id": "T1110.003",
                    "severity": "HIGH",
                    "description": "Password spraying attack detected",
                    "group_by": "source_ip",
                    "unique_field": "username",
                    "event_filter": "failed_login",
                }
            }
        }
    }

    engine = CorrelationEngine(redis, config=config)

    alerts_1 = await engine.run_dynamic_rules(
        tenant_id="TENANT1",
        source_ip="10.0.0.5",
        user="alice",
        event_id="4625",
        event_type="failed_login",
        timestamp_iso="2026-05-06T10:00:00+00:00",
        log_entry={"username": "user1"},
    )
    alerts_2 = await engine.run_dynamic_rules(
        tenant_id="TENANT1",
        source_ip="10.0.0.5",
        user="alice",
        event_id="4625",
        event_type="failed_login",
        timestamp_iso="2026-05-06T10:01:00+00:00",
        log_entry={"username": "user2"},
    )
    alerts_3 = await engine.run_dynamic_rules(
        tenant_id="TENANT1",
        source_ip="10.0.0.5",
        user="alice",
        event_id="4625",
        event_type="failed_login",
        timestamp_iso="2026-05-06T10:02:00+00:00",
        log_entry={"username": "user3"},
    )

    assert alerts_1 == []
    assert alerts_2 == []
    assert len(alerts_3) == 1
    assert alerts_3[0]["type"] == "Password spraying attack detected"
    assert alerts_3[0]["severity"] == "HIGH"


@pytest.mark.asyncio
async def test_after_hours_rule_triggers_by_timestamp():
    redis = FakeRedis()
    config = {
        "stateful_detection_rules": {
            "auth_identity": {
                "after_hours_activity": {
                    "enabled": True,
                    "start_hour": 2,
                    "end_hour": 5,
                    "mitre_id": "T1078",
                    "severity": "MEDIUM",
                    "description": "After-hours suspicious activity",
                    "event_filter": "successful_login",
                }
            }
        }
    }

    engine = CorrelationEngine(redis, config=config)

    alerts = await engine.run_dynamic_rules(
        tenant_id="TENANT2",
        source_ip="10.0.0.9",
        user="bob",
        event_id="4624",
        event_type="successful_login",
        timestamp_iso="2026-05-06T03:15:00+00:00",
        log_entry={"user": "bob"},
    )

    assert len(alerts) == 1
    assert alerts[0]["type"] == "After-hours suspicious activity"
    assert alerts[0]["severity"] == "MEDIUM"


@pytest.mark.asyncio
async def test_catalog_password_spray_triggers_after_five_users_in_five_minutes():
    redis = FakeRedis()
    engine = CorrelationEngine(redis, config=SIEM_RULES)
    alerts = []

    for index in range(5):
        alerts = await engine.run_dynamic_rules(
            tenant_id="TENANT-SPRAY",
            source_ip="10.0.0.55",
            user=f"user{index}",
            event_id="4625",
            event_type="failed_login",
            timestamp_iso="2026-05-06T10:00:00+00:00",
            log_entry={"username": f"user{index}"},
        )

    assert len(alerts) == 1
    assert alerts[0]["type"] == "Password spraying attack detected"
    assert "10.0.0.55" in redis.sets["warsoc:banned_ips:TENANT-SPRAY"]

    duplicate_alerts = await engine.run_dynamic_rules(
        tenant_id="TENANT-SPRAY",
        source_ip="10.0.0.55",
        user="user5",
        event_id="4625",
        event_type="failed_login",
        timestamp_iso="2026-05-06T10:00:01+00:00",
        log_entry={"username": "user5"},
    )
    assert duplicate_alerts == []


@pytest.mark.asyncio
async def test_auto_revocation_skips_invalid_and_whitelisted_sources():
    redis = FakeRedis()
    engine = CorrelationEngine(redis, config={})

    redis.sets["warsoc:soar_whitelist:TENANT-SAFE"] = {"10.0.0.8"}

    assert await engine._trigger_auto_revocation("TENANT-SAFE", "unknown", reason="test") is False
    assert await engine._trigger_auto_revocation("TENANT-SAFE", "127.0.0.1", reason="test") is False
    assert await engine._trigger_auto_revocation("TENANT-SAFE", "10.0.0.8", reason="test") is False
    assert await engine._trigger_auto_revocation("TENANT-SAFE", "10.0.0.9", reason="test") is True
    assert redis.sets["warsoc:banned_ips:TENANT-SAFE"] == {"10.0.0.9"}


@pytest.mark.asyncio
async def test_native_mass_deletion_rule_uses_4660_without_auto_banning_endpoint():
    redis = FakeRedis()
    config = {
        "event_id_map": {
            "4660": {
                "event_type": "object_deleted",
                "severity": "MEDIUM",
                "alert_on_event": False,
            }
        },
        "stateful_detection_rules": {
            "filesystem_ransomware": {
                "mass_file_deletion": {
                    "enabled": True,
                    "threshold": 2,
                    "window_seconds": 60,
                    "mitre_id": "T1485",
                    "severity": "CRITICAL",
                    "description": "Mass file deletion detected",
                    "group_by": "username",
                    "event_filter": "file_delete",
                }
            }
        },
    }
    engine = CorrelationEngine(redis, config=config)

    first = await engine.run_dynamic_rules(
        tenant_id="TENANT-RANSOM",
        source_ip="",
        user="alice",
        event_id="4660",
        event_type="object_deleted",
        log_entry={"agent_id": "AGENT-1", "username": "alice"},
    )
    second = await engine.run_dynamic_rules(
        tenant_id="TENANT-RANSOM",
        source_ip="",
        user="alice",
        event_id="4660",
        event_type="object_deleted",
        log_entry={"agent_id": "AGENT-1", "username": "alice"},
    )

    assert first == []
    assert len(second) == 1
    assert second[0]["type"] == "Mass file deletion detected"
    assert "warsoc:banned_ips:TENANT-RANSOM" not in redis.sets


@pytest.mark.asyncio
async def test_ransomware_extension_rule_requires_an_actual_ransomware_suffix():
    redis = FakeRedis()
    config = {
        "event_id_map": {
            "4663": {
                "event_type": "object_access",
                "severity": "LOW",
                "alert_on_event": False,
            }
        },
        "stateful_detection_rules": {
            "filesystem_ransomware": {
                "ransomware_extensions": {
                    "enabled": True,
                    "threshold": 1,
                    "window_seconds": 60,
                    "mitre_id": "T1486",
                    "severity": "CRITICAL",
                    "description": "Ransomware file extension detected",
                    "group_by": "username",
                    "event_filter": "file_write",
                    "ransomware_extensions": [".locked", ".encrypted"],
                }
            }
        },
    }
    engine = CorrelationEngine(redis, config=config)

    normal_database_write = await engine.run_dynamic_rules(
        tenant_id="TENANT-RANSOM",
        source_ip="",
        user="pos-user",
        event_id="4663",
        event_type="object_access",
        log_entry={
            "username": "pos-user",
            "processed_data": {"object_name": r"C:\POS\data\sales.db"},
        },
    )
    encrypted_file_write = await engine.run_dynamic_rules(
        tenant_id="TENANT-RANSOM",
        source_ip="",
        user="pos-user",
        event_id="4663",
        event_type="object_access",
        log_entry={
            "username": "pos-user",
            "processed_data": {"object_name": r"C:\Users\pos-user\invoice.xlsx.locked"},
        },
    )

    assert normal_database_write == []
    assert len(encrypted_file_write) == 1
    assert encrypted_file_write[0]["type"] == "Ransomware file extension detected"
