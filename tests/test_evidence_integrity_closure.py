import json
import inspect
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
from cryptography.fernet import Fernet

from app.utils.fbr_retention import (
    FBR_ACTIVE_RETENTION_MODEL,
    apply_fbr_tenant_retention,
)
from app.utils.peca_retention import (
    PECA_ACTIVE_RETENTION_MODEL,
    apply_peca_tenant_retention,
)
from app.utils.source_evidence import (
    SOURCE_OUTBOX_COLLECTION,
    SourceEvidenceConflict,
    _decode_package,
    _dispatch_evidence_hash,
    _encode_package,
    persist_source_envelope,
    publish_source_outbox,
)
from app.utils.source_provenance import (
    LEGACY_SYSLOG,
    apply_source_provenance,
    compliance_source_allowed,
)
from app.workers.storage_archiver import (
    _archive_query,
    _batch_vault_retention,
)
from app.db.init_db import init_compliance_db


@pytest.mark.asyncio
async def test_source_envelope_is_encrypted_idempotent_and_published(db, redis_client):
    payload = json.dumps({"event_uid": "evt-durable-001", "event_id": "4625"})
    kwargs = {
        "tenant_id": "WARSOC_TEST_SOURCE",
        "source_principal_type": "windows_agent",
        "source_principal_id": "WARSOC_AGENT_SOURCE",
        "source_channel": "windows_endpoint",
        "source_envelope_uid": "nonce-source-001:peca",
        "source_payload": b'{"signed":"material"}',
        "dispatch_events": [
            {
                "event_uid": "evt-durable-001",
                "serialized_payload": payload,
                "target_streams": ["raw_logs_queue"],
            }
        ],
        "retention_class": "PECA",
        "auth_metadata": {
            "scheme": "ed25519-v1",
            "signature_verified_count": 1,
        },
        "source_timestamp": datetime.now(timezone.utc),
        "retention_metadata": {"tenant_retention_days_at_ingest": 180},
    }

    first = await persist_source_envelope(db, **kwargs)
    second = await persist_source_envelope(db, **kwargs)
    assert first == second
    assert await db.source_envelopes_peca.count_documents({}) == 1
    assert await db.source_evidence_outbox.count_documents({}) == 1

    envelope = await db.source_envelopes_peca.find_one({})
    assert envelope["state"] == "COMMITTED"
    assert envelope["encryption_key_version"] >= 1
    serialized = json.dumps(envelope, default=str)
    assert '"signed":"material"' not in serialized
    assert "evt-durable-001" not in envelope["encrypted_package"]

    assert await publish_source_outbox(db, redis_client, first, limit=1) == 1
    assert await redis_client.xlen("raw_logs_queue") == 1
    assert await publish_source_outbox(db, redis_client, first, limit=1) == 0
    assert await redis_client.xlen("raw_logs_queue") == 1
    envelope = await db.source_envelopes_peca.find_one({})
    assert envelope["dispatch_complete"] is True
    assert envelope["retention_model"] == PECA_ACTIVE_RETENTION_MODEL
    assert envelope["tenant_retention_days_at_ingest"] == 180


@pytest.mark.asyncio
async def test_new_peca_source_envelope_requires_tenant_retention_metadata():
    with pytest.raises(ValueError, match="requires tenant retention metadata"):
        await persist_source_envelope(
            object(),
            tenant_id="WARSOC_TEST_SOURCE",
            source_principal_type="windows_agent",
            source_principal_id="WARSOC_AGENT_SOURCE",
            source_channel="windows_endpoint",
            source_envelope_uid="nonce-source-missing-retention:peca",
            source_payload=b'{"signed":"material"}',
            dispatch_events=[
                {
                    "event_uid": "evt-missing-retention",
                    "serialized_payload": '{"event_uid":"evt-missing-retention"}',
                    "target_streams": ["raw_logs_queue"],
                }
            ],
            retention_class="PECA",
            auth_metadata={"scheme": "ed25519-v1"},
            source_timestamp=datetime.now(timezone.utc),
        )


def test_source_envelope_key_rotation_preserves_historical_decryption(monkeypatch):
    old_key = Fernet.generate_key().decode("ascii")
    new_key = Fernet.generate_key().decode("ascii")
    old_settings = SimpleNamespace(
        source_envelope_encryption_key=old_key,
        encryption_key="",
        source_envelope_key_id="source-envelope-old",
        source_envelope_key_version=3,
        source_envelope_decryption_keys_json="{}",
    )
    monkeypatch.setattr("app.utils.key_lifecycle.get_settings", lambda: old_settings)
    token, key_id, key_version = _encode_package(b"signed-source", ['{"event":1}'])

    rotated_settings = SimpleNamespace(
        source_envelope_encryption_key=new_key,
        encryption_key="",
        source_envelope_key_id="source-envelope-current",
        source_envelope_key_version=4,
        source_envelope_decryption_keys_json=json.dumps(
            {
                "source-envelope-old": {
                    "key": old_key,
                    "version": 3,
                }
            }
        ),
    )
    monkeypatch.setattr("app.utils.key_lifecycle.get_settings", lambda: rotated_settings)

    decoded = _decode_package(token, key_id=key_id, key_version=key_version)
    assert decoded["source_payload_b64"]
    assert decoded["dispatch_payloads"] == ['{"event":1}']


def test_source_envelope_key_rotation_fails_closed_without_retired_key(monkeypatch):
    old_key = Fernet.generate_key().decode("ascii")
    new_key = Fernet.generate_key().decode("ascii")
    old_settings = SimpleNamespace(
        source_envelope_encryption_key=old_key,
        encryption_key="",
        source_envelope_key_id="source-envelope-old",
        source_envelope_key_version=1,
        source_envelope_decryption_keys_json="{}",
    )
    monkeypatch.setattr("app.utils.key_lifecycle.get_settings", lambda: old_settings)
    token, key_id, key_version = _encode_package(b"source", ['{"event":1}'])

    rotated_settings = SimpleNamespace(
        source_envelope_encryption_key=new_key,
        encryption_key="",
        source_envelope_key_id="source-envelope-current",
        source_envelope_key_version=2,
        source_envelope_decryption_keys_json="{}",
    )
    monkeypatch.setattr("app.utils.key_lifecycle.get_settings", lambda: rotated_settings)

    with pytest.raises(RuntimeError, match="is not configured"):
        _decode_package(token, key_id=key_id, key_version=key_version)


@pytest.mark.asyncio
async def test_source_envelope_rejects_uid_reuse_with_different_payload(db):
    common = {
        "tenant_id": "WARSOC_TEST_SOURCE_CONFLICT",
        "source_principal_type": "windows_agent",
        "source_principal_id": "WARSOC_AGENT_SOURCE_CONFLICT",
        "source_channel": "windows_endpoint",
        "source_envelope_uid": "same-envelope",
        "dispatch_events": [
            {
                "event_uid": "same-event-uid",
                "serialized_payload": '{"value":1}',
                "target_streams": ["raw_logs_queue"],
            }
        ],
        "retention_class": "SIEM",
        "auth_metadata": {"scheme": "ed25519-v1"},
    }
    await persist_source_envelope(db, source_payload=b"one", **common)
    with pytest.raises(SourceEvidenceConflict):
        await persist_source_envelope(db, source_payload=b"two", **common)


@pytest.mark.asyncio
async def test_identical_event_retry_with_new_envelope_does_not_create_orphan(db):
    common = {
        "tenant_id": "WARSOC_TEST_SOURCE_REDELIVERY",
        "source_principal_type": "windows_agent",
        "source_principal_id": "WARSOC_AGENT_SOURCE_REDELIVERY",
        "source_channel": "windows_endpoint",
        "source_payload": b'{"signed":"same"}',
        "dispatch_events": [
            {
                "event_uid": "same-durable-event",
                "serialized_payload": '{"event_uid":"same-durable-event"}',
                "target_streams": ["raw_logs_queue"],
            }
        ],
        "retention_class": "SIEM",
        "auth_metadata": {"scheme": "ed25519-v2"},
    }

    first = await persist_source_envelope(
        db,
        source_envelope_uid="delivery-nonce-one:siem",
        **common,
    )
    second = await persist_source_envelope(
        db,
        source_envelope_uid="delivery-nonce-two:siem",
        **common,
    )

    assert first == second
    assert await db.source_envelopes_siem.count_documents({}) == 1
    assert await db.source_evidence_outbox.count_documents({}) == 1


@pytest.mark.asyncio
async def test_retry_ignores_only_server_generated_dispatch_metadata(db):
    first_payload = {
        "event_uid": "Security:epoch-1:100",
        "event_id": "5157",
        "message": "connection allowed",
        "payload_hash": "a" * 64,
        "agent_signature": "b" * 128,
        "signature_verified_at": "2026-08-31T19:00:00+00:00",
        "source_envelope_uid": "nonce-one:siem",
        "source_envelope_collection": "source_envelopes_siem",
        "source_envelope_state": "COMMITTED",
    }
    second_payload = {
        **first_payload,
        "signature_verified_at": "2026-08-31T19:01:00+00:00",
        "source_envelope_uid": "nonce-two:siem",
    }
    assert _dispatch_evidence_hash(json.dumps(first_payload)) == _dispatch_evidence_hash(
        json.dumps(second_payload)
    )

    common = {
        "tenant_id": "WARSOC_TEST_VOLATILE_RETRY",
        "source_principal_type": "windows_agent",
        "source_principal_id": "WARSOC_AGENT_VOLATILE_RETRY",
        "source_channel": "windows_endpoint",
        "retention_class": "SIEM",
        "auth_metadata": {"scheme": "ed25519-v2"},
    }
    first = await persist_source_envelope(
        db,
        source_envelope_uid="nonce-one:siem",
        source_payload=b'{"signed":"same"}',
        dispatch_events=[
            {
                "event_uid": first_payload["event_uid"],
                "serialized_payload": json.dumps(first_payload),
                "target_streams": ["raw_logs_queue", "siem_hot_queue"],
            }
        ],
        **common,
    )
    await db.source_evidence_outbox.update_one(
        {"outbox_uid": first[0]},
        {"$unset": {"evidence_hash": ""}},
    )
    second = await persist_source_envelope(
        db,
        source_envelope_uid="nonce-two:siem",
        source_payload=b'{"signed":"same"}',
        dispatch_events=[
            {
                "event_uid": second_payload["event_uid"],
                "serialized_payload": json.dumps(second_payload),
                "target_streams": ["raw_logs_queue", "siem_hot_queue"],
            }
        ],
        **common,
    )

    assert first == second
    assert await db.source_envelopes_siem.count_documents({}) == 1
    outbox = await db.source_evidence_outbox.find_one({"outbox_uid": first[0]})
    assert outbox["evidence_hash"] == _dispatch_evidence_hash(json.dumps(first_payload))


@pytest.mark.asyncio
async def test_retry_still_rejects_changed_evidence_content(db):
    common = {
        "tenant_id": "WARSOC_TEST_CHANGED_RETRY",
        "source_principal_type": "windows_agent",
        "source_principal_id": "WARSOC_AGENT_CHANGED_RETRY",
        "source_channel": "windows_endpoint",
        "retention_class": "SIEM",
        "auth_metadata": {"scheme": "ed25519-v2"},
    }
    await persist_source_envelope(
        db,
        source_envelope_uid="nonce-one:siem",
        source_payload=b'{"signed":"one"}',
        dispatch_events=[
            {
                "event_uid": "Security:epoch-2:200",
                "serialized_payload": json.dumps(
                    {
                        "event_uid": "Security:epoch-2:200",
                        "message": "original",
                        "payload_hash": "c" * 64,
                    }
                ),
                "target_streams": ["raw_logs_queue"],
            }
        ],
        **common,
    )

    with pytest.raises(SourceEvidenceConflict):
        await persist_source_envelope(
            db,
            source_envelope_uid="nonce-two:siem",
            source_payload=b'{"signed":"two"}',
            dispatch_events=[
                {
                    "event_uid": "Security:epoch-2:200",
                    "serialized_payload": json.dumps(
                        {
                            "event_uid": "Security:epoch-2:200",
                            "message": "changed",
                            "payload_hash": "d" * 64,
                        }
                    ),
                    "target_streams": ["raw_logs_queue"],
                }
            ],
            **common,
        )


@pytest.mark.asyncio
async def test_source_outbox_retries_without_losing_committed_envelope(db, redis_client):
    outbox_uids = await persist_source_envelope(
        db,
        tenant_id="WARSOC_TEST_SOURCE_RETRY",
        source_principal_type="windows_agent",
        source_principal_id="WARSOC_AGENT_SOURCE_RETRY",
        source_channel="windows_endpoint",
        source_envelope_uid="retry-envelope",
        source_payload=b"retry-source",
        dispatch_events=[
            {
                "event_uid": "retry-event-uid",
                "serialized_payload": '{"retry":true}',
                "target_streams": ["raw_logs_queue"],
            }
        ],
        retention_class="SIEM",
        auth_metadata={"scheme": "ed25519-v1"},
    )

    class FailingPipeline:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return False

        async def xadd(self, *_args, **_kwargs):
            return self

        async def execute(self):
            raise ConnectionError("simulated Redis dispatch failure")

    class FailingRedis:
        async def xlen(self, _stream):
            return 0

        def pipeline(self, **_kwargs):
            return FailingPipeline()

    assert await publish_source_outbox(db, FailingRedis(), outbox_uids, limit=1) == 0
    outbox = await db[SOURCE_OUTBOX_COLLECTION].find_one({"outbox_uid": outbox_uids[0]})
    assert outbox["status"] == "retry"
    assert await db.source_envelopes_siem.count_documents({"state": "COMMITTED"}) == 1

    await db[SOURCE_OUTBOX_COLLECTION].update_one(
        {"outbox_uid": outbox_uids[0]},
        {"$set": {"next_attempt_at": datetime.now(timezone.utc) - timedelta(seconds=1)}},
    )
    assert await publish_source_outbox(db, redis_client, outbox_uids, limit=1) == 1
    assert await redis_client.xlen("raw_logs_queue") == 1


def test_legacy_syslog_is_never_compliance_evidence():
    event = apply_source_provenance(
        {
            "type": "network_log",
            "source_assurance": "agent_signed",
            "signature_verified": True,
            "event_id": "4625",
        }
    )
    assert event["source_class"] == LEGACY_SYSLOG
    assert event["compliance_source_eligible"] is False
    assert compliance_source_allowed(event, "peca") is False
    assert compliance_source_allowed(event, "fbr") is False


def test_fbr_retention_uses_tenant_entitlement_without_tax_expiry():
    document = apply_fbr_tenant_retention(
        {
            "event_uid": "fbr-tenant-retention-1",
            "_expire_at": datetime.now(timezone.utc),
            "tax_period_id": "PK-ST-2026-08",
        },
        180,
    )
    assert document["retention_model"] == FBR_ACTIVE_RETENTION_MODEL
    assert document["retention_state"] == "TENANT_POLICY"
    assert document["retention_basis"] == "TENANT_RETENTION_ENTITLEMENT"
    assert document["tenant_retention_days_at_ingest"] == 180
    assert "_expire_at" not in document
    assert "tax_period_id" not in document
    assert "legal_hold" not in document
    assert _batch_vault_retention("fbr_pos_logs", [document], 180) == (180, None)


def test_peca_retention_uses_tenant_entitlement_without_fixed_expiry():
    document = apply_peca_tenant_retention(
        {
            "event_uid": "peca-tenant-retention-1",
            "_expire_at": datetime.now(timezone.utc),
            "retention_policy": "365_DAYS",
        },
        270,
    )
    assert document["retention_model"] == PECA_ACTIVE_RETENTION_MODEL
    assert document["retention_state"] == "TENANT_POLICY"
    assert document["retention_basis"] == "TENANT_RETENTION_ENTITLEMENT"
    assert document["retention_policy"] == "TENANT_ENTITLEMENT"
    assert document["tenant_retention_days_at_ingest"] == 270
    assert "_expire_at" not in document
    assert _batch_vault_retention("peca_forensic_logs", [document], 270) == (270, None)


def test_source_envelope_archival_requires_completed_dispatch():
    query = _archive_query(
        "WARSOC_TEST_SOURCE",
        "source_envelopes_siem",
        datetime.now(timezone.utc),
        datetime.now(timezone.utc),
    )
    assert query["tenant_id"] == "WARSOC_TEST_SOURCE"
    assert query["dispatch_complete"] is True


def test_legacy_fbr_records_are_not_rewritten_or_selected_for_new_archival():
    assert "_legacy_backfill_fbr_tax_retention_state" not in inspect.getsource(
        init_compliance_db
    )
    query = _archive_query(
        "WARSOC_TEST_FBR_LEGACY",
        "fbr_pos_logs",
        datetime.now(timezone.utc),
        datetime.now(timezone.utc),
    )
    assert query["retention_model"] == FBR_ACTIVE_RETENTION_MODEL


def test_legacy_peca_records_are_not_rewritten_or_selected_for_new_archival():
    assert "_backfill_expire_at(db.peca_forensic_logs" not in inspect.getsource(
        init_compliance_db
    )
    query = _archive_query(
        "WARSOC_TEST_PECA_LEGACY",
        "peca_forensic_logs",
        datetime.now(timezone.utc),
        datetime.now(timezone.utc),
    )
    assert query["retention_model"] == PECA_ACTIVE_RETENTION_MODEL
    source_query = _archive_query(
        "WARSOC_TEST_PECA_LEGACY",
        "source_envelopes_peca",
        datetime.now(timezone.utc),
        datetime.now(timezone.utc),
    )
    assert source_query["retention_model"] == PECA_ACTIVE_RETENTION_MODEL
    assert source_query["dispatch_complete"] is True
