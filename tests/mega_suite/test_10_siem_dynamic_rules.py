"""
Dynamic SIEM rule engine tests.

These tests exercise the config-driven correlation path directly so the suite
covers unique-field tracking and time-window rules without needing the full
worker loop.
"""
import pytest

from app.utils.siem_logic import CorrelationEngine


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
        return results


class FakeRedis:
    def __init__(self):
        self.values = {}
        self.sets = {}
        self.counters = {}
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

    async def expire(self, key, ttl):
        return True

    async def publish(self, channel, message):
        self.published.append((channel, message))
        return 1


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
