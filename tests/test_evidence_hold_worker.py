from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

from app.workers.evidence_hold_worker import reconcile_once


class FakeBlob:
    def __init__(self, state: dict, key: tuple):
        self.state = state
        self.key = key

    async def get_blob_properties(self):
        return SimpleNamespace(
            has_legal_hold=bool(self.state.get(self.key, False)),
            version_id=self.key[2],
            last_modified=datetime.now(timezone.utc),
        )

    async def set_legal_hold(self, value: bool):
        self.state[self.key] = bool(value)


class FakeContainer:
    def __init__(self, state: dict, name: str):
        self.state = state
        self.name = name

    def get_blob_client(self, name: str, version_id: str | None = None):
        return FakeBlob(self.state, (self.name, name, version_id))


class FakeBlobService:
    def __init__(self, state: dict | None = None):
        self.state = state if state is not None else {}

    def get_container_client(self, name: str):
        return FakeContainer(self.state, name)


async def _seed_archived_hold(db, *, preexisting: bool = False):
    now = datetime.now(timezone.utc)
    archive = {
        "tenant_id": "TENANT-HOLD-WORKER",
        "collection": "security_alerts",
        "archive_key": "ARCHIVE-HOLD-WORKER",
        "container_name": "evidence-vault",
        "blob_name": "batch.json",
        "hash_blob_name": "batch.sha256",
        "event_uids": ["EVENT-HOLD-WORKER"],
        "status": "archived_hot_deleted",
        "created_at": now,
    }
    await db.storage_archives.insert_one(archive)
    hold = {
        "hold_id": "HOLD-WORKER",
        "tenant_id": archive["tenant_id"],
        "scope_type": "EVENT",
        "collection": archive["collection"],
        "event_uid": archive["event_uids"][0],
        "status": "ACTIVE",
        "archive_protection_status": "PENDING",
        "reason": "Preserve the archived event for an authorized investigation.",
        "authority": "Tenant administrator",
        "created_at": now,
        "updated_at": now,
    }
    await db.legal_holds.insert_one(hold)
    state = {}
    if preexisting:
        state[(archive["container_name"], archive["blob_name"], None)] = True
        state[(archive["container_name"], archive["hash_blob_name"], None)] = True
    return hold, archive, state


@pytest.mark.asyncio
@pytest.mark.parametrize("preexisting", [False, True])
async def test_hold_worker_protects_and_fail_closed_releases_archives(db, preexisting):
    hold, archive, state = await _seed_archived_hold(db, preexisting=preexisting)
    service = FakeBlobService(state)

    assert await reconcile_once(db, service) is True
    protected = await db.legal_holds.find_one({"hold_id": hold["hold_id"]})
    assert protected["archive_protection_status"] == "PROTECTED"
    assert state[(archive["container_name"], archive["blob_name"], None)] is True
    assert state[(archive["container_name"], archive["hash_blob_name"], None)] is True
    binding = await db.evidence_archive_hold_bindings.find_one({"hold_id": hold["hold_id"]})
    assert binding["status"] == "PROTECTED"
    assert binding["json_hold_preexisting"] is preexisting

    operation_id = "release-hold-worker"
    now = datetime.now(timezone.utc)
    await db.evidence_hold_audit.insert_one(
        {
            "operation_id": operation_id,
            "hold_id": hold["hold_id"],
            "tenant_id": hold["tenant_id"],
            "action": "RELEASE",
            "status": "PENDING",
            "created_at": now,
            "updated_at": now,
        }
    )
    await db.legal_holds.update_one(
        {"hold_id": hold["hold_id"]},
        {
            "$set": {
                "status": "PENDING_RELEASE",
                "archive_protection_status": "RELEASE_PENDING",
                "release_operation_id": operation_id,
                "release_requested_at": now,
                "release_reason": "Release after authorized final disposition.",
                "release_authority": "Tenant administrator",
            }
        },
    )

    assert await reconcile_once(db, service) is True
    released = await db.legal_holds.find_one({"hold_id": hold["hold_id"]})
    assert released["status"] == "RELEASED"
    audit = await db.evidence_hold_audit.find_one({"operation_id": operation_id})
    assert audit["status"] == "COMMITTED"
    assert state[(archive["container_name"], archive["blob_name"], None)] is preexisting
    assert state[(archive["container_name"], archive["hash_blob_name"], None)] is preexisting


@pytest.mark.asyncio
async def test_release_preserves_archive_for_applicable_unbound_active_hold(db):
    hold, archive, state = await _seed_archived_hold(db)
    service = FakeBlobService(state)

    assert await reconcile_once(db, service) is True
    now = datetime.now(timezone.utc)
    await db.legal_holds.insert_one(
        {
            "hold_id": "HOLD-SECOND-UNBOUND",
            "tenant_id": hold["tenant_id"],
            "scope_type": "TENANT",
            "status": "ACTIVE",
            "archive_protection_status": "PENDING",
            "created_at": now,
            "updated_at": now,
        }
    )
    operation_id = "release-first-with-second-unbound"
    await db.evidence_hold_audit.insert_one(
        {
            "operation_id": operation_id,
            "hold_id": hold["hold_id"],
            "tenant_id": hold["tenant_id"],
            "action": "RELEASE",
            "status": "PENDING",
            "created_at": now,
            "updated_at": now,
        }
    )
    await db.legal_holds.update_one(
        {"hold_id": hold["hold_id"]},
        {
            "$set": {
                "status": "PENDING_RELEASE",
                "archive_protection_status": "RELEASE_PENDING",
                "release_operation_id": operation_id,
                "release_requested_at": now,
            }
        },
    )

    assert await reconcile_once(db, service) is True
    assert state[(archive["container_name"], archive["blob_name"], None)] is True
    assert state[(archive["container_name"], archive["hash_blob_name"], None)] is True
    binding = await db.evidence_archive_hold_bindings.find_one({"hold_id": hold["hold_id"]})
    assert binding["status"] == "RELEASED"
    assert binding["preserved_for_other_hold"] is True
