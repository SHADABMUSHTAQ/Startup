from __future__ import annotations

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock

import httpx
import orjson
import pytest
from cryptography.fernet import Fernet

from app.wazuh_integration import bridge_runtime, dispatcher
from app.wazuh_integration.bridge_spool import BridgeSpool
from app.wazuh_integration.contracts import (
    DetectionInput,
    DetectionInputBatch,
    DetectionInputReceipt,
)
from app.wazuh_integration.security import build_signed_headers, encrypt_payload


NOW = datetime.now(timezone.utc)
DISPATCH_UID = "WZD_0123456789ABCDEF0123456789ABCDEF"
CONNECTOR_ID = "wazuh-shadow-01"
SIGNING_SECRET = "dispatch-secret-" + "x" * 48


def _input() -> DetectionInput:
    return DetectionInput(
        dispatch_uid=DISPATCH_UID,
        event_uid="event-transport-0001",
        tenant_scope="a" * 64,
        source_family="windows_endpoint",
        source_assurance="endpoint_signed",
        original_event_time=NOW - timedelta(seconds=2),
        receipt_time=NOW - timedelta(seconds=1),
        dispatch_time=NOW,
        event_age_ms=2000,
        event_id="4688",
        endpoint_id="WARSOC_AGENT_TEST",
        correlation_key_version="corr-v1",
        correlation_keys={"corr_tenant": "b" * 64},
        security_fields={"new_process_name": r"C:\Windows\System32\whoami.exe"},
    )


def _input_batch() -> DetectionInputBatch:
    return DetectionInputBatch(
        batch_id="WZB_0123456789ABCDEF0123456789ABCDEF",
        connector_id=CONNECTOR_ID,
        created_at=NOW,
        inputs=[_input()],
    )


def _bridge_settings(tmp_path):
    return SimpleNamespace(
        connector_id=CONNECTOR_ID,
        dispatch_signing_secret=SIGNING_SECRET,
        max_body_bytes=64 * 1024,
        input_spool_max_bytes=16 * 1024 * 1024,
        live_event_max_age_seconds=60,
    )


@pytest.mark.asyncio
async def test_bridge_receipt_means_durable_spool_and_replay_is_rejected(tmp_path):
    settings = _bridge_settings(tmp_path)
    spool = BridgeSpool(tmp_path / "bridge.sqlite3", Fernet.generate_key().decode("ascii"))
    bridge_runtime.app.state.settings = settings
    bridge_runtime.app.state.spool = spool
    body = orjson.dumps(
        _input_batch().model_dump(mode="json", by_alias=True),
        option=orjson.OPT_SORT_KEYS,
    )
    headers = build_signed_headers(
        secret=SIGNING_SECRET,
        connector_id=CONNECTOR_ID,
        body=body,
        nonce="a" * 32,
    )
    transport = httpx.ASGITransport(app=bridge_runtime.app)
    try:
        async with httpx.AsyncClient(transport=transport, base_url="https://bridge.test") as client:
            first = await client.post(
                "/api/v1/internal/detection-inputs",
                content=body,
                headers=headers,
            )
            assert first.status_code == 200
            receipt = DetectionInputReceipt.model_validate_json(first.content)
            assert receipt.accepted_dispatch_uids == [DISPATCH_UID]
            assert len(spool.pending("input_spool", "dispatch_uid", 10)) == 1

            replay = await client.post(
                "/api/v1/internal/detection-inputs",
                content=body,
                headers=headers,
            )
            assert replay.status_code == 409

            retry_headers = build_signed_headers(
                secret=SIGNING_SECRET,
                connector_id=CONNECTOR_ID,
                body=body,
                nonce="b" * 32,
            )
            duplicate = await client.post(
                "/api/v1/internal/detection-inputs",
                content=body,
                headers=retry_headers,
            )
            assert duplicate.status_code == 200
            duplicate_receipt = DetectionInputReceipt.model_validate_json(duplicate.content)
            assert duplicate_receipt.duplicate_dispatch_uids == [DISPATCH_UID]
            assert len(spool.pending("input_spool", "dispatch_uid", 10)) == 1
    finally:
        spool.close()


@pytest.mark.asyncio
async def test_bridge_rejects_tampered_signed_body_before_spooling(tmp_path):
    settings = _bridge_settings(tmp_path)
    spool = BridgeSpool(tmp_path / "bridge.sqlite3", Fernet.generate_key().decode("ascii"))
    bridge_runtime.app.state.settings = settings
    bridge_runtime.app.state.spool = spool
    original = orjson.dumps(_input_batch().model_dump(mode="json", by_alias=True))
    headers = build_signed_headers(
        secret=SIGNING_SECRET,
        connector_id=CONNECTOR_ID,
        body=original,
        nonce="c" * 32,
    )
    transport = httpx.ASGITransport(app=bridge_runtime.app)
    try:
        async with httpx.AsyncClient(transport=transport, base_url="https://bridge.test") as client:
            response = await client.post(
                "/api/v1/internal/detection-inputs",
                content=original + b" ",
                headers=headers,
            )
        assert response.status_code == 401
        assert spool.pending("input_spool", "dispatch_uid", 10) == []
    finally:
        spool.close()


class _ResponseClient:
    response: httpx.Response

    def __init__(self, **_kwargs):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_args):
        return None

    async def post(self, *_args, **_kwargs):
        return self.response


class _DispatchDb:
    def __init__(self):
        self.detection_dispatch_outbox = SimpleNamespace(update_one=AsyncMock())
        self.detection_dispatch_dlq = SimpleNamespace(update_one=AsyncMock())
        self.detection_coverage_gaps = SimpleNamespace(update_one=AsyncMock())


def _dispatch_settings(encryption_key: str):
    return SimpleNamespace(
        wazuh_outbox_encryption_key=encryption_key,
        wazuh_connector_id=CONNECTOR_ID,
        wazuh_max_body_bytes=64 * 1024,
        wazuh_dispatch_signing_secret=SIGNING_SECRET,
        wazuh_dispatch_timeout_seconds=5,
        wazuh_dispatch_url="https://bridge.test/api/v1/internal/detection-inputs",
        wazuh_dispatch_max_attempts=3,
    )


def _outbox_document(encryption_key: str):
    payload = orjson.dumps(
        _input().model_dump(mode="json", by_alias=True),
        option=orjson.OPT_SORT_KEYS,
    )
    return {
        "dispatch_uid": DISPATCH_UID,
        "tenant_id": "WARSOC_TENANT_TEST",
        "event_uid": "event-transport-0001",
        "source_collection": "siem_cold_vault",
        "source_record_id": "canonical-1",
        "source_record_hash": "d" * 64,
        "ruleset_version": "warsoc-lab-canary-v1",
        "payload_ciphertext": encrypt_payload(encryption_key, payload),
        "payload_sha256": __import__("hashlib").sha256(payload).hexdigest(),
        "payload_bytes": len(payload),
        "attempt_count": 1,
        "lease_token": "lease-1",
    }


@pytest.mark.asyncio
async def test_dispatcher_accepts_only_signed_matching_receipt(monkeypatch):
    encryption_key = Fernet.generate_key().decode("ascii")
    settings = _dispatch_settings(encryption_key)
    document = _outbox_document(encryption_key)
    receipt = DetectionInputReceipt(
        batch_id="WZB_11111111111111111111111111111111",
        connector_id=CONNECTOR_ID,
        accepted_dispatch_uids=[DISPATCH_UID],
    )
    response_body = orjson.dumps(
        receipt.model_dump(mode="json", by_alias=True),
        option=orjson.OPT_SORT_KEYS,
    )
    headers = build_signed_headers(
        secret=SIGNING_SECRET,
        connector_id=CONNECTOR_ID,
        body=response_body,
    )
    _ResponseClient.response = httpx.Response(
        200,
        content=response_body,
        headers=headers,
        request=httpx.Request("POST", settings.wazuh_dispatch_url),
    )
    monkeypatch.setattr(dispatcher.httpx, "AsyncClient", _ResponseClient)
    monkeypatch.setattr(dispatcher, "_tls_options", lambda _settings: ("ca.pem", ("cert.pem", "key.pem")))
    monkeypatch.setattr(dispatcher, "_batch_id", lambda: receipt.batch_id)
    db = _DispatchDb()

    result = await dispatcher.dispatch_claimed(db, [document], settings)

    assert result == {"delivered": 1, "rejected": 0, "retry": 0}
    update = db.detection_dispatch_outbox.update_one.await_args.args[1]
    assert update["$set"]["status"] == "delivered"
    db.detection_dispatch_dlq.update_one.assert_not_awaited()


@pytest.mark.asyncio
async def test_dispatcher_retries_when_receipt_omits_dispatch(monkeypatch):
    encryption_key = Fernet.generate_key().decode("ascii")
    settings = _dispatch_settings(encryption_key)
    document = _outbox_document(encryption_key)
    receipt = DetectionInputReceipt(
        batch_id="WZB_22222222222222222222222222222222",
        connector_id=CONNECTOR_ID,
    )
    response_body = orjson.dumps(
        receipt.model_dump(mode="json", by_alias=True),
        option=orjson.OPT_SORT_KEYS,
    )
    headers = build_signed_headers(
        secret=SIGNING_SECRET,
        connector_id=CONNECTOR_ID,
        body=response_body,
    )
    _ResponseClient.response = httpx.Response(
        200,
        content=response_body,
        headers=headers,
        request=httpx.Request("POST", settings.wazuh_dispatch_url),
    )
    monkeypatch.setattr(dispatcher.httpx, "AsyncClient", _ResponseClient)
    monkeypatch.setattr(dispatcher, "_tls_options", lambda _settings: ("ca.pem", ("cert.pem", "key.pem")))
    monkeypatch.setattr(dispatcher, "_batch_id", lambda: receipt.batch_id)
    db = _DispatchDb()

    result = await dispatcher.dispatch_claimed(db, [document], settings)

    assert result == {"delivered": 0, "rejected": 0, "retry": 1}
    update = db.detection_dispatch_outbox.update_one.await_args.args[1]
    assert update["$set"]["status"] == "retry"
