from datetime import datetime, timedelta, timezone

import pytest

from app.utils.alert_context import build_alert_context
from app.utils.security_incidents import (
    build_incident_identity,
    project_security_incident,
    serialize_incident,
    should_project_security_incident,
)
from app.utils.telemetry_groups import aggregate_endpoint_events


def _alert(**overrides):
    alert = {
        "tenant_id": "TENANT-A",
        "alert_uid": "alert-1",
        "event_uid": "Security:100",
        "event_id": "4688",
        "type": "SUSPICIOUS_PROCESS",
        "severity": "HIGH",
        "status": "NEW",
        "timestamp": datetime(2026, 7, 17, 12, 30, 10, tzinfo=timezone.utc),
        "agent_id": "AGENT-A",
        "source_ip": "203.0.113.8",
        "processed_data": {
            "SubjectUserName": "alice",
            "TargetUserName": "service-account",
            "NewProcessName": "C:\\Windows\\System32\\cmd.exe",
            "CommandLine": "cmd.exe /c whoami",
        },
    }
    alert.update(overrides)
    return alert


def test_incident_identity_groups_same_context_only_within_one_utc_minute():
    base = _alert()
    repeated = _alert(
        alert_uid="alert-2",
        event_uid="Security:101",
        timestamp=base["timestamp"] + timedelta(seconds=40),
        status="ACKNOWLEDGED",
        severity="CRITICAL",
    )
    next_minute = _alert(
        alert_uid="alert-3",
        event_uid="Security:102",
        timestamp=base["timestamp"] + timedelta(seconds=55),
    )

    first_identity = build_incident_identity(base)
    repeat_identity = build_incident_identity(repeated)
    next_identity = build_incident_identity(next_minute)

    assert first_identity["incident_id"] == repeat_identity["incident_id"]
    assert first_identity["incident_id"] != next_identity["incident_id"]


def test_incident_identity_never_merges_different_process_or_target():
    base = _alert()
    different_process = _alert(
        processed_data={
            **base["processed_data"],
            "NewProcessName": "C:\\Windows\\System32\\powershell.exe",
        }
    )
    different_target = _alert(
        processed_data={
            **base["processed_data"],
            "TargetUserName": "administrator",
        }
    )

    identities = {
        build_incident_identity(document)["incident_id"]
        for document in (base, different_process, different_target)
    }
    assert len(identities) == 3


def test_service_install_channels_form_one_service_specific_incident():
    security_event = _alert(
        alert_uid="service-4697",
        event_uid="Security:4697:100",
        event_id="4697",
        type="WIN_EVENT_4697_DETECTED",
        timestamp=datetime(2026, 7, 17, 12, 30, 10, tzinfo=timezone.utc),
        processed_data={
            "SubjectUserName": "installer-admin",
            "ServiceName": "WarSOC-Test-Service",
            "ServiceFileName": r"C:\Program Files\WarSOC\service.exe",
        },
    )
    system_event = _alert(
        alert_uid="service-7045",
        event_uid="System:7045:101",
        event_id="7045",
        type="WIN_EVENT_7045_DETECTED",
        timestamp=security_event["timestamp"] + timedelta(minutes=2),
        processed_data={
            "ServiceName": "WarSOC-Test-Service",
            "ImagePath": r"C:\Program Files\WarSOC\service.exe",
        },
    )
    different_service = _alert(
        alert_uid="service-7045-other",
        event_uid="System:7045:102",
        event_id="7045",
        type="WIN_EVENT_7045_DETECTED",
        timestamp=security_event["timestamp"] + timedelta(minutes=2),
        processed_data={"ServiceName": "Another-Service"},
    )

    security_identity = build_incident_identity(security_event)
    system_identity = build_incident_identity(system_event)
    other_identity = build_incident_identity(different_service)

    assert security_identity["rule_id"] == "WINDOWS_SERVICE_INSTALLED"
    assert security_identity["incident_id"] == system_identity["incident_id"]
    assert security_identity["incident_id"] != other_identity["incident_id"]
    assert security_identity["bucket_end"] - security_identity["bucket_start"] == timedelta(minutes=5)


def test_fbr_projection_accepts_only_actionable_native_or_invoice_controls():
    assert should_project_security_incident(
        _alert(pack="fbr_pos", event_id="FIM-DB-MOD")
    )
    assert should_project_security_incident(
        _alert(pack="fbr_pos", event_id="FBR-INV-DEL")
    )
    assert not should_project_security_incident(
        _alert(pack="fbr_pos", event_id="4663")
    )


def test_operator_context_separates_actor_and_target_and_redacts_secrets():
    context = build_alert_context(
        _alert(
            processed_data={
                "SubjectUserName": "alice",
                "TargetUserName": "administrator",
                "CommandLine": "tool.exe --api-key super-secret",
            }
        )
    )
    assert context["actor"] == "alice"
    assert context["target_user"] == "administrator"
    assert "super-secret" not in context["command_line"]
    assert "[REDACTED]" in context["command_line"]


def test_endpoint_feed_groups_repeats_but_preserves_process_context():
    first = _alert(_id="row-1")
    second = _alert(
        _id="row-2",
        alert_uid="alert-2",
        event_uid="Security:101",
        timestamp=first["timestamp"] + timedelta(seconds=20),
    )
    other_process = _alert(
        _id="row-3",
        alert_uid="alert-3",
        event_uid="Security:102",
        processed_data={
            **first["processed_data"],
            "NewProcessName": "C:\\Windows\\System32\\powershell.exe",
        },
    )

    groups = aggregate_endpoint_events([first, second, other_process])

    assert len(groups) == 2
    assert sorted(group["occurrences"] for group in groups) == [1, 2]
    assert all(group["record_type"] == "endpoint_event_group" for group in groups)


def test_incident_serialization_reports_visible_occurrences_only():
    serialized = serialize_incident(
        {
            "incident_id": "INC-1",
            "incident_key": "private-key",
            "occurrences": 4,
            "visible_occurrences": 3,
            "severity_rank": 4,
            "superseded_event_uids": ["event-1"],
        }
    )
    assert serialized["occurrences"] == 3
    assert "incident_key" not in serialized
    assert "severity_rank" not in serialized
    assert "superseded_event_uids" not in serialized


@pytest.mark.asyncio
async def test_incident_api_groups_evidence_isolates_tenant_and_persists_workflow(
    async_client,
    auth_headers,
    db,
):
    current_user = await db.users.find_one({"email": {"$regex": "^test_integ_"}})
    assert current_user is not None
    tenant_id = current_user["tenant_id"]
    indexes = await db.security_incident_occurrences.index_information()
    has_occurrence_index = any(
        index.get("key") == [("tenant_id", 1), ("occurrence_uid", 1)]
        and bool(index.get("unique"))
        for index in indexes.values()
    )
    if not has_occurrence_index:
        await db.security_incident_occurrences.create_index(
            [("tenant_id", 1), ("occurrence_uid", 1)],
            unique=True,
            name="uq_security_incident_occurrence",
        )

    minute = datetime.now(timezone.utc).replace(second=5, microsecond=0)
    alerts = [
        _alert(
            tenant_id=tenant_id,
            alert_uid=f"api-alert-{index}",
            event_uid=f"Security:api-{index}",
            timestamp=minute + timedelta(seconds=index * 15),
        )
        for index in (0, 1)
    ]
    for alert in alerts:
        await db.security_alerts.insert_one(alert)
        await project_security_incident(db, alert)

    await project_security_incident(
        db,
        _alert(
            tenant_id="OTHER-TENANT",
            alert_uid="other-alert",
            event_uid="Security:other",
            timestamp=minute,
        ),
    )

    listed = await async_client.get("/api/v1/incidents", headers=auth_headers)
    assert listed.status_code == 200, listed.text
    incidents = listed.json()["data"]
    assert len(incidents) == 1
    assert incidents[0]["tenant_id"] == tenant_id
    assert incidents[0]["occurrences"] == 2
    incident_id = incidents[0]["incident_id"]

    summary = await async_client.get("/api/v1/incidents/summary", headers=auth_headers)
    assert summary.status_code == 200, summary.text
    assert summary.json()["data"]["open_total"] == 1

    detail = await async_client.get(
        f"/api/v1/incidents/{incident_id}",
        headers=auth_headers,
    )
    assert detail.status_code == 200, detail.text
    detail_data = detail.json()["data"]
    assert detail_data["evidence_returned"] == 2
    assert {row["storage_tier"] for row in detail_data["evidence"]} == {"hot"}
    assert detail_data["evidence_coverage"] == {
        "occurrence_total": 2,
        "reference_total": 2,
        "returned": 2,
        "hot": 2,
        "cold_archive": 0,
        "unresolved_references": 0,
        "tracking_bounded": False,
        "tracking_limit": 100,
        "preview_limit": 50,
    }
    assert len(detail_data["workflow_history"]) == 1
    assert detail_data["workflow_history"][0]["action"] == "detected"
    assert "evidence_refs" not in incidents[0]
    assert "event_uids" not in incidents[0]
    assert "alert_uids" not in incidents[0]

    rejected_close = await async_client.patch(
        f"/api/v1/incidents/{incident_id}/status",
        headers=auth_headers,
        json={"status": "CLOSED"},
    )
    assert rejected_close.status_code == 400

    closed = await async_client.patch(
        f"/api/v1/incidents/{incident_id}/status",
        headers=auth_headers,
        json={"status": "CLOSED", "resolution_notes": "Reviewed and contained."},
    )
    assert closed.status_code == 200, closed.text
    assert closed.json()["data"]["status"] == "CLOSED"
    assert await db.security_alerts.count_documents(
        {"tenant_id": tenant_id, "status": "CLOSED"}
    ) == 2
    assert await db.incident_audit_log.count_documents(
        {"tenant_id": tenant_id, "incident_id": incident_id}
    ) == 1

    closed_detail = await async_client.get(
        f"/api/v1/incidents/{incident_id}",
        headers=auth_headers,
    )
    assert closed_detail.status_code == 200
    workflow = closed_detail.json()["data"]["workflow_history"]
    assert len(workflow) == 2
    assert [entry["action"] for entry in workflow] == ["detected", "closed"]
    assert workflow[1]["operator"]
    assert workflow[1]["changes"]["status"] == {"from": "NEW", "to": "CLOSED"}
    assert closed_detail.json()["data"]["incident"]["workflow_version"] == 1

    repeated_close = await async_client.patch(
        f"/api/v1/incidents/{incident_id}/status",
        headers=auth_headers,
        json={"status": "CLOSED", "resolution_notes": "Reviewed and contained."},
    )
    assert repeated_close.status_code == 200
    assert await db.incident_audit_log.count_documents(
        {"tenant_id": tenant_id, "incident_id": incident_id}
    ) == 1

    assignees = await async_client.get("/api/v1/incidents/assignees", headers=auth_headers)
    assert assignees.status_code == 200
    assert all(
        member["role"] in {"admin", "manager", "analyst"}
        for member in assignees.json()["data"]
    )

    current_assignee = next(
        member for member in assignees.json()["data"] if member["email"] == current_user["email"]
    )
    assigned = await async_client.patch(
        f"/api/v1/incidents/{incident_id}/status",
        headers=auth_headers,
        json={"assignee_id": current_assignee["id"]},
    )
    assert assigned.status_code == 200
    assert assigned.json()["data"]["assignee_id"] == current_assignee["id"]

    unassigned = await async_client.patch(
        f"/api/v1/incidents/{incident_id}/status",
        headers=auth_headers,
        json={"assignee_id": None},
    )
    assert unassigned.status_code == 200
    assert unassigned.json()["data"].get("assignee_id") is None

    open_only = await async_client.get("/api/v1/incidents", headers=auth_headers)
    assert open_only.status_code == 200
    assert open_only.json()["data"] == []
