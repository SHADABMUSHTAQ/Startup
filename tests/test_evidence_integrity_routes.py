from datetime import datetime, timezone
from types import SimpleNamespace

from app.routes.evidence_integrity import verify_case, verify_daily_ledger
from app.utils.compliance_chain import (
    CHAIN_VERSION,
    HASH_ALGORITHM,
    compute_daily_root,
    genesis_root,
)
from app.utils.evidence_custody import CUSTODY_CHAIN_VERSION, custody_event_hash


class Cursor:
    def __init__(self, documents):
        self.documents = list(documents)

    def sort(self, *_args, **_kwargs):
        return self

    async def to_list(self, length=None):
        return self.documents if length is None else self.documents[:length]


class Collection:
    def __init__(self, *, one=None, documents=None):
        self.one = one
        self.documents = list(documents or [])

    def find(self, *_args, **_kwargs):
        return Cursor(self.documents)

    async def find_one(self, *_args, **_kwargs):
        return self.one


class Database:
    def __init__(self, **collections):
        self.collections = collections

    def __getattr__(self, name):
        return self.collections[name]

    def __getitem__(self, name):
        return self.collections[name]


async def test_daily_integrity_uses_real_daily_ledger_collection():
    root = compute_daily_root(
        tenant_id="tenant-1",
        date_str="2026-09-19",
        previous_root_hash=genesis_root("tenant-1"),
        evidence_digest="a" * 64,
        log_count=1,
        source_counts={"peca_forensic_logs": 1},
    )
    entry = {
        "tenant_id": "tenant-1",
        "date": "2026-09-19",
        "chain_version": CHAIN_VERSION,
        "hash_algorithm": HASH_ALGORITHM,
        "previous_root_hash": genesis_root("tenant-1"),
        "evidence_digest": "a" * 64,
        "daily_root_hash": root,
        "log_count": 1,
        "source_counts": {"peca_forensic_logs": 1},
    }
    db = Database(daily_forensic_ledgers=Collection(documents=[entry]))

    result = await verify_daily_ledger.__wrapped__(
        request=SimpleNamespace(),
        start_date="2026-09-19",
        end_date="2026-09-19",
        current_user={"tenant_id": "tenant-1"},
        db=db,
    )

    assert result["verification_result"]["status"] == "VERIFIED"
    assert result["verification_scope"] == "stored_daily_ledger_chain"


async def test_archived_case_item_is_partial_not_a_false_tamper_alarm():
    occurred_at = datetime.now(timezone.utc)
    event = {
        "custody_event_id": "CUSTODY-1",
        "chain_version": CUSTODY_CHAIN_VERSION,
        "tenant_id": "tenant-1",
        "case_id": "case-001",
        "sequence": 1,
        "action": "CASE_CREATED",
        "actor_user_id": "user-1",
        "actor_email": "auditor@example.test",
        "actor_role": "auditor",
        "reason": "Create an integrity verification test case",
        "request_id": "request-1",
        "metadata": {},
        "occurred_at": occurred_at,
        "previous_custody_hash": "0" * 64,
        "state": "COMMITTED",
    }
    event["current_custody_hash"] = custody_event_hash(event)
    case = {
        "tenant_id": "tenant-1",
        "case_id": "case-001",
        "custody_head_hash": event["current_custody_hash"],
    }
    item = {
        "tenant_id": "tenant-1",
        "case_id": "case-001",
        "case_item_id": "ITEM-1",
        "collection": "security_alerts",
        "document_id": "missing-hot-document",
        "event_uid": "event-001",
        "evidence_record_hash": "b" * 64,
        "state": "COMMITTED",
    }
    db = Database(
        evidence_cases=Collection(one=case),
        evidence_custody_events=Collection(documents=[event]),
        evidence_case_items=Collection(documents=[item]),
        security_alerts=Collection(one=None),
        storage_archives=Collection(
            one={
                "_id": "archive-1",
                "archive_key": "tenant-1/security_alerts/archive-1",
                "readback_verified": True,
                "physical_worm_verified": True,
            }
        ),
    )

    result = await verify_case.__wrapped__(
        request=SimpleNamespace(),
        case_id="case-001",
        current_user={"tenant_id": "tenant-1"},
        db=db,
    )

    assert result["overall_status"] == "PARTIALLY_VERIFIED"
    assert result["evidence_items"][0]["status"] == (
        "ARCHIVED_LEDGER_PRESENT_NOT_REHASHED"
    )
    assert result["evidence_items"][0]["hash_match"] is None
