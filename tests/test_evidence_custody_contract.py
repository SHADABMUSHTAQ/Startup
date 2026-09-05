from datetime import datetime, timezone

import pytest

from app.utils.evidence_custody import append_custody_event, verify_custody_chain


@pytest.mark.asyncio
async def test_case_references_evidence_without_copying_and_verifies_custody(
    async_client,
    auth_headers,
    db,
):
    created = await async_client.post(
        "/api/v1/compliance/cases",
        headers=auth_headers,
        json={
            "title": "Authentication investigation",
            "description": "Preserve and review the failed authentication evidence.",
        },
    )
    assert created.status_code == 201, created.text
    case = created.json()["case"]
    case_id = case["case_id"]
    tenant_id = case["tenant_id"]
    source = {
        "tenant_id": tenant_id,
        "agent_id": "AGENT-CASE-A",
        "event_uid": "EVENT-CASE-A",
        "event_id": "4625",
        "timestamp": datetime.now(timezone.utc),
        "message": "Safe list summary",
    }
    inserted = await db.siem_cold_vault.insert_one(source)

    attached = await async_client.post(
        f"/api/v1/compliance/cases/{case_id}/items",
        headers=auth_headers,
        json={
            "collection": "siem_cold_vault",
            "document_id": str(inserted.inserted_id),
            "reason": "Attach the original event to the active investigation.",
        },
    )
    assert attached.status_code == 201, attached.text
    item = attached.json()["item"]
    assert item["document_id"] == str(inserted.inserted_id)
    assert item["evidence_record_hash"]
    assert "message" not in item

    viewed = await async_client.post(
        f"/api/v1/compliance/cases/{case_id}/custody",
        headers=auth_headers,
        json={
            "action": "VIEW",
            "case_item_id": item["case_item_id"],
            "reason": "Review the referenced evidence during investigation triage.",
        },
    )
    assert viewed.status_code == 201, viewed.text

    detail = await async_client.get(
        f"/api/v1/compliance/cases/{case_id}",
        headers=auth_headers,
    )
    assert detail.status_code == 200, detail.text
    assert detail.json()["custody"]["status"] == "VERIFIED"
    assert detail.json()["custody"]["event_count"] == 3
    assert len(detail.json()["custody_events"]) == 3
    assert all("actor_user_id" not in event for event in detail.json()["custody_events"])
    assert await db.siem_cold_vault.count_documents({"_id": inserted.inserted_id}) == 1


@pytest.mark.asyncio
async def test_case_attachment_rejects_cross_tenant_evidence(async_client, auth_headers, db):
    foreign = await db.siem_cold_vault.insert_one(
        {
            "tenant_id": "FOREIGN-TENANT",
            "event_uid": "FOREIGN-EVENT",
            "event_id": "4625",
            "timestamp": datetime.now(timezone.utc),
        }
    )
    created = await async_client.post(
        "/api/v1/compliance/cases",
        headers=auth_headers,
        json={
            "title": "Tenant boundary test",
            "description": "Verify that evidence references cannot cross tenant boundaries.",
        },
    )
    case_id = created.json()["case"]["case_id"]
    attached = await async_client.post(
        f"/api/v1/compliance/cases/{case_id}/items",
        headers=auth_headers,
        json={
            "collection": "siem_cold_vault",
            "document_id": str(foreign.inserted_id),
            "reason": "Attempt to attach evidence belonging to another tenant.",
        },
    )
    assert attached.status_code == 404


@pytest.mark.asyncio
async def test_custody_verifier_detects_tampering(async_client, auth_headers, db):
    created = await async_client.post(
        "/api/v1/compliance/cases",
        headers=auth_headers,
        json={
            "title": "Custody tamper test",
            "description": "Generate a custody event and prove mutation is detectable.",
        },
    )
    case = created.json()["case"]
    case_id = case["case_id"]
    tenant_id = case["tenant_id"]
    events = await db.evidence_custody_events.find(
        {"tenant_id": tenant_id, "case_id": case_id, "state": "COMMITTED"}
    ).sort("sequence", 1).to_list(10)
    assert verify_custody_chain(events)["verified"] is True

    events[0]["reason"] = "mutated"
    result = verify_custody_chain(events)
    assert result["verified"] is False
    assert result["invalid_event_ids"]


@pytest.mark.asyncio
async def test_case_cannot_close_without_committed_evidence(async_client, auth_headers):
    created = await async_client.post(
        "/api/v1/compliance/cases",
        headers=auth_headers,
        json={
            "title": "Empty closure test",
            "description": "Prevent an evidence case from closing without evidence.",
        },
    )
    case_id = created.json()["case"]["case_id"]
    closed = await async_client.post(
        f"/api/v1/compliance/cases/{case_id}/close",
        headers=auth_headers,
        json={"action": "VERIFY", "reason": "Try to close an empty evidence case."},
    )
    assert closed.status_code == 409


@pytest.mark.asyncio
async def test_case_cannot_close_with_tampered_custody(async_client, auth_headers, db):
    created = await async_client.post(
        "/api/v1/compliance/cases",
        headers=auth_headers,
        json={
            "title": "Tampered closure test",
            "description": "Prevent closure when the custody chain no longer verifies.",
        },
    )
    case = created.json()["case"]
    source = await db.siem_cold_vault.insert_one(
        {
            "tenant_id": case["tenant_id"],
            "event_uid": "EVENT-TAMPER-CLOSE",
            "timestamp": datetime.now(timezone.utc),
        }
    )
    attached = await async_client.post(
        f"/api/v1/compliance/cases/{case['case_id']}/items",
        headers=auth_headers,
        json={
            "collection": "siem_cold_vault",
            "document_id": str(source.inserted_id),
            "reason": "Attach evidence before exercising closure verification.",
        },
    )
    assert attached.status_code == 201, attached.text
    await db.evidence_custody_events.update_one(
        {"tenant_id": case["tenant_id"], "case_id": case["case_id"], "sequence": 1},
        {"$set": {"reason": "tampered"}},
    )
    closed = await async_client.post(
        f"/api/v1/compliance/cases/{case['case_id']}/close",
        headers=auth_headers,
        json={"action": "VERIFY", "reason": "Attempt closure after custody tampering."},
    )
    assert closed.status_code == 409


@pytest.mark.asyncio
async def test_case_closure_records_verified_chain_and_item_count(async_client, auth_headers, db):
    created = await async_client.post(
        "/api/v1/compliance/cases",
        headers=auth_headers,
        json={
            "title": "Verified closure test",
            "description": "Close only after evidence and custody verification succeed.",
        },
    )
    case = created.json()["case"]
    await db.security_alerts.insert_one(
        {
            "tenant_id": case["tenant_id"],
            "event_uid": "EVENT-VERIFIED-CLOSE",
            "timestamp": datetime.now(timezone.utc),
        }
    )
    attached = await async_client.post(
        f"/api/v1/compliance/cases/{case['case_id']}/items",
        headers=auth_headers,
        json={
            "collection": "security_alerts",
            "event_uid": "EVENT-VERIFIED-CLOSE",
            "reason": "Attach the alert required for verified case closure.",
        },
    )
    assert attached.status_code == 201, attached.text
    closed = await async_client.post(
        f"/api/v1/compliance/cases/{case['case_id']}/close",
        headers=auth_headers,
        json={"action": "VERIFY", "reason": "Custody and source evidence were reviewed."},
    )
    assert closed.status_code == 200, closed.text
    metadata = closed.json()["custody_event"]["metadata"]
    assert metadata["committed_item_count"] == 1
    assert metadata["verified_event_count"] == 2
    detail = await async_client.get(
        f"/api/v1/compliance/cases/{case['case_id']}",
        headers=auth_headers,
    )
    assert detail.json()["case"]["status"] == "CLOSED"
    assert detail.json()["custody"]["status"] == "VERIFIED"


@pytest.mark.asyncio
async def test_case_read_recovers_committed_head_left_pending(async_client, auth_headers, db):
    created = await async_client.post(
        "/api/v1/compliance/cases",
        headers=auth_headers,
        json={
            "title": "Custody recovery test",
            "description": "Recover a custody commit interrupted after the case-head update.",
        },
    )
    case = created.json()["case"]
    event = await db.evidence_custody_events.find_one(
        {"tenant_id": case["tenant_id"], "case_id": case["case_id"], "sequence": 1}
    )
    await db.evidence_custody_events.update_one(
        {"_id": event["_id"]},
        {"$set": {"state": "PENDING"}, "$unset": {"committed_at": ""}},
    )
    await db.evidence_cases.update_one(
        {"tenant_id": case["tenant_id"], "case_id": case["case_id"]},
        {"$set": {"custody_pending_event_id": event["custody_event_id"]}},
    )

    detail = await async_client.get(
        f"/api/v1/compliance/cases/{case['case_id']}", headers=auth_headers
    )
    assert detail.status_code == 200, detail.text
    assert detail.json()["custody"]["status"] == "VERIFIED"
    recovered = await db.evidence_custody_events.find_one({"_id": event["_id"]})
    assert recovered["state"] == "COMMITTED"


@pytest.mark.asyncio
async def test_case_read_finalizes_item_after_committed_custody_event(
    async_client,
    auth_headers,
    db,
):
    created = await async_client.post(
        "/api/v1/compliance/cases",
        headers=auth_headers,
        json={
            "title": "Item recovery test",
            "description": "Recover an item interrupted after its custody event committed.",
        },
    )
    case = created.json()["case"]
    operation_id = "recover-item-operation"
    item = {
        "case_item_id": "ITEM-RECOVERY",
        "tenant_id": case["tenant_id"],
        "case_id": case["case_id"],
        "collection": "siem_cold_vault",
        "document_id": "document-recovery",
        "event_uid": "event-recovery",
        "evidence_record_hash": "a" * 64,
        "reason": "Exercise item commit recovery after a simulated process interruption.",
        "state": "PENDING",
        "operation_id": operation_id,
        "added_at": datetime.now(timezone.utc),
    }
    await db.evidence_case_items.insert_one(item)
    event = await append_custody_event(
        db,
        tenant_id=case["tenant_id"],
        case_id=case["case_id"],
        case_item_id=item["case_item_id"],
        action="EVIDENCE_ADDED",
        actor={"_id": "user-a", "email": "admin@example.com", "role": "admin"},
        reason=item["reason"],
        request_id=operation_id,
        metadata={"operation_id": operation_id},
    )

    detail = await async_client.get(
        f"/api/v1/compliance/cases/{case['case_id']}", headers=auth_headers
    )
    assert detail.status_code == 200, detail.text
    assert [entry["case_item_id"] for entry in detail.json()["items"]] == ["ITEM-RECOVERY"]
    recovered = await db.evidence_case_items.find_one({"case_item_id": "ITEM-RECOVERY"})
    assert recovered["state"] == "COMMITTED"
    assert recovered["custody_event_id"] == event["custody_event_id"]


@pytest.mark.asyncio
async def test_case_read_finalizes_close_after_committed_custody_event(
    async_client,
    auth_headers,
    db,
):
    created = await async_client.post(
        "/api/v1/compliance/cases",
        headers=auth_headers,
        json={
            "title": "Close recovery test",
            "description": "Recover closure interrupted after its custody event committed.",
        },
    )
    case = created.json()["case"]
    operation_id = "recover-close-operation"
    await db.evidence_cases.update_one(
        {"tenant_id": case["tenant_id"], "case_id": case["case_id"]},
        {
            "$set": {
                "close_operation": {
                    "operation_id": operation_id,
                    "started_at": datetime.now(timezone.utc),
                }
            }
        },
    )
    await append_custody_event(
        db,
        tenant_id=case["tenant_id"],
        case_id=case["case_id"],
        action="CASE_CLOSED",
        actor={"_id": "user-a", "email": "admin@example.com", "role": "admin"},
        reason="Close the case after verifying the complete evidence custody chain.",
        request_id=operation_id,
        metadata={"operation_id": operation_id},
    )

    detail = await async_client.get(
        f"/api/v1/compliance/cases/{case['case_id']}", headers=auth_headers
    )
    assert detail.status_code == 200, detail.text
    assert detail.json()["case"]["status"] == "CLOSED"
