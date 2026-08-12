from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock

import httpx
import orjson
import pytest

from app.wazuh_integration import candidate_api
from app.wazuh_integration.contracts import BridgeHealthBatch, BridgeHealthEvent
from app.wazuh_integration.security import build_signed_headers


CONNECTOR_ID = "wazuh-shadow-01"
ENGINE_ID = "wazuh-node-01"
SECRET = "candidate-secret-" + "x" * 48
REGISTRY_HASH = "a" * 64


class _HealthDb:
    def __init__(self):
        self.detection_engine_connectors = SimpleNamespace(
            find_one=AsyncMock(return_value={"_id": "connector"}),
            update_one=AsyncMock(),
        )
        self.detection_engine_health_events = SimpleNamespace(update_one=AsyncMock())
        self.detection_coverage_gaps = SimpleNamespace(update_one=AsyncMock())


class _MongoHealth:
    def __init__(self, *, healthy=True):
        self.admin = SimpleNamespace(
            command=AsyncMock(return_value={"ok": 1})
            if healthy
            else AsyncMock(side_effect=RuntimeError("unavailable"))
        )


def _settings():
    return SimpleNamespace(
        wazuh_max_body_bytes=64 * 1024,
        wazuh_candidate_signing_secret=SECRET,
        wazuh_connector_id=CONNECTOR_ID,
        wazuh_engine_instance_id=ENGINE_ID,
        wazuh_engine_version="4.14.7",
        wazuh_ruleset_version="warsoc-lab-canary-v1",
        wazuh_rule_registry_sha256=REGISTRY_HASH,
    )


@pytest.mark.asyncio
async def test_signed_bridge_health_is_stored_and_opens_coverage_gap():
    now = datetime.now(timezone.utc)
    event = BridgeHealthEvent(
        event_uid="b" * 64,
        event_type="ALERT_ROTATION_GAP",
        severity="critical",
        detail="Previous Wazuh alert file was unavailable",
        occurrence_count=1,
        first_seen_at=now,
        last_seen_at=now,
    )
    batch = BridgeHealthBatch(
        batch_id="WZB_0123456789ABCDEF0123456789ABCDEF",
        connector_id=CONNECTOR_ID,
        engine_instance_id=ENGINE_ID,
        engine_version="4.14.7",
        ruleset_version="warsoc-lab-canary-v1",
        registry_sha256=REGISTRY_HASH,
        created_at=now,
        state="degraded",
        input_spool_bytes=0,
        candidate_spool_bytes=1024,
        retry_records=1,
        alert_file_lag_bytes=2048,
        counters={"wazuh_alert_rotation_gaps": 1},
        events=[event],
    )
    body = orjson.dumps(batch.model_dump(mode="json", by_alias=True))
    headers = build_signed_headers(
        secret=SECRET,
        connector_id=CONNECTOR_ID,
        body=body,
        nonce="f" * 32,
    )
    db = _HealthDb()
    candidate_api.app.state.settings = _settings()
    candidate_api.app.state.redis = SimpleNamespace(set=AsyncMock(return_value=True))
    candidate_api.app.state.db = db
    transport = httpx.ASGITransport(app=candidate_api.app)

    async with httpx.AsyncClient(transport=transport, base_url="https://compute-a.test") as client:
        response = await client.post(
            "/api/v1/internal/detection-engines/wazuh/health",
            content=body,
            headers=headers,
        )

    assert response.status_code == 200
    db.detection_engine_health_events.update_one.assert_awaited_once()
    db.detection_coverage_gaps.update_one.assert_awaited_once()
    connector_update = db.detection_engine_connectors.update_one.await_args_list[-1]
    assert connector_update.args[1]["$set"]["last_health_state"] == "degraded"


@pytest.mark.asyncio
async def test_bridge_health_replay_is_rejected_before_storage():
    now = datetime.now(timezone.utc)
    batch = BridgeHealthBatch(
        batch_id="WZB_FEDCBA9876543210FEDCBA9876543210",
        connector_id=CONNECTOR_ID,
        engine_instance_id=ENGINE_ID,
        engine_version="4.14.7",
        ruleset_version="warsoc-lab-canary-v1",
        registry_sha256=REGISTRY_HASH,
        created_at=now,
        state="healthy",
        input_spool_bytes=0,
        candidate_spool_bytes=0,
        retry_records=0,
        alert_file_lag_bytes=0,
        counters={},
        events=[],
    )
    body = orjson.dumps(batch.model_dump(mode="json", by_alias=True))
    headers = build_signed_headers(
        secret=SECRET,
        connector_id=CONNECTOR_ID,
        body=body,
        nonce="e" * 32,
    )
    db = _HealthDb()
    candidate_api.app.state.settings = _settings()
    candidate_api.app.state.redis = SimpleNamespace(set=AsyncMock(return_value=False))
    candidate_api.app.state.db = db
    transport = httpx.ASGITransport(app=candidate_api.app)

    async with httpx.AsyncClient(transport=transport, base_url="https://compute-a.test") as client:
        response = await client.post(
            "/api/v1/internal/detection-engines/wazuh/health",
            content=body,
            headers=headers,
        )

    assert response.status_code == 409
    db.detection_engine_health_events.update_one.assert_not_awaited()


@pytest.mark.asyncio
async def test_candidate_health_is_truthful_without_exposing_exception_details():
    candidate_api.app.state.mongo = _MongoHealth(healthy=False)
    candidate_api.app.state.redis = SimpleNamespace(ping=AsyncMock(return_value=True))
    transport = httpx.ASGITransport(app=candidate_api.app)

    async with httpx.AsyncClient(transport=transport, base_url="https://compute-a.test") as client:
        response = await client.get("/health")

    assert response.status_code == 503
    assert response.json() == {
        "status": "unhealthy",
        "dependencies": {"mongodb": "unhealthy", "redis": "healthy"},
    }
    assert "unavailable" not in response.text
