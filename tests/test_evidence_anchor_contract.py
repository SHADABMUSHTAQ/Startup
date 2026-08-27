from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from azure.core.exceptions import ResourceExistsError

from app.utils.compliance_chain import CHAIN_VERSION, HASH_ALGORITHM, compute_daily_root
from app.utils.evidence_anchor import anchor_daily_ledger, build_anchor_payload


class _Policy:
    def __init__(self, expiry, mode="Locked"):
        self.expiry_time = expiry
        self.policy_mode = mode


class _Properties:
    def __init__(self, expiry, mode="Locked"):
        self.has_legal_hold = False
        self.immutability_policy = _Policy(expiry, mode)


class _Download:
    def __init__(self, payload):
        self.payload = payload

    async def readall(self):
        return self.payload


class _Blob:
    def __init__(self, store, name, expiry, mode="Locked"):
        self.store = store
        self.name = name
        self.expiry = expiry
        self.mode = mode

    async def upload_blob(self, payload, **_kwargs):
        if self.name in self.store:
            raise ResourceExistsError("exists")
        self.store[self.name] = payload

    async def download_blob(self):
        return _Download(self.store[self.name])

    async def get_blob_properties(self):
        return _Properties(self.expiry, self.mode)


class _Container:
    def __init__(self, store, expiry, mode="Locked"):
        self.store = store
        self.expiry = expiry
        self.mode = mode

    async def get_container_properties(self):
        return object()

    def get_blob_client(self, name):
        return _Blob(self.store, name, self.expiry, self.mode)


class _Service:
    def __init__(self, *, expiry, mode="Locked"):
        self.store = {}
        self.expiry = expiry
        self.mode = mode

    def get_container_client(self, _name):
        return _Container(self.store, self.expiry, self.mode)


def _ledger():
    evidence_digest = "a" * 64
    source_counts = {"fbr_pos_logs": 2, "peca_forensic_logs": 1}
    root = compute_daily_root(
        tenant_id="TENANT-A",
        date_str="2026-08-19",
        previous_root_hash="b" * 64,
        evidence_digest=evidence_digest,
        log_count=3,
        source_counts=source_counts,
    )
    return {
        "tenant_id": "TENANT-A",
        "date": "2026-08-19",
        "chain_version": CHAIN_VERSION,
        "hash_algorithm": HASH_ALGORITHM,
        "daily_root_hash": root,
        "previous_root_hash": "b" * 64,
        "evidence_digest": evidence_digest,
        "log_count": 3,
        "source_counts": source_counts,
    }


@pytest.mark.asyncio
async def test_daily_anchor_is_small_deterministic_idempotent_and_worm_verified():
    ledger = _ledger()
    assert len(build_anchor_payload(ledger)) < 2048
    service = _Service(expiry=datetime.now(timezone.utc) + timedelta(days=3000))
    first = await anchor_daily_ledger(
        service,
        container_name="warsoc-daily-anchors",
        ledger=ledger,
        fallback_days=2555,
    )
    second = await anchor_daily_ledger(
        service,
        container_name="warsoc-daily-anchors",
        ledger=ledger,
        fallback_days=2555,
    )
    assert first["status"] == "VERIFIED"
    assert first["payload_sha256"] == second["payload_sha256"]
    assert len(service.store) == 1


@pytest.mark.asyncio
async def test_daily_anchor_rejects_existing_conflicting_bytes():
    ledger = _ledger()
    service = _Service(expiry=datetime.now(timezone.utc) + timedelta(days=3000))
    service.store[
        "daily-roots/" + __import__("hashlib").sha256(b"TENANT-A").hexdigest() + "/2026-08-19.json"
    ] = b"conflict"
    with pytest.raises(RuntimeError, match="conflicts"):
        await anchor_daily_ledger(
            service,
            container_name="warsoc-daily-anchors",
            ledger=ledger,
            fallback_days=2555,
        )


@pytest.mark.asyncio
async def test_daily_anchor_rejects_unlocked_or_short_immutability():
    ledger = _ledger()
    service = _Service(
        expiry=datetime.now(timezone.utc) + timedelta(days=100),
        mode="Unlocked",
    )
    with pytest.raises(RuntimeError, match="immutability"):
        await anchor_daily_ledger(
            service,
            container_name="warsoc-daily-anchors",
            ledger=ledger,
            fallback_days=2555,
        )
