from datetime import datetime, timezone

from app.utils.detection_provenance import attach_detection_provenance


def test_detector_provenance_is_bounded_and_excludes_raw_evidence():
    finding = {
        "type": "WINDOWS_SERVICE_INSTALLED",
        "event_id": "7045",
        "raw_message": "secret raw message",
    }
    source = {
        "event_uid": "System:7045:42",
        "event_id": "7045",
        "agent_id": "AGENT-A",
        "channel": "System",
        "event_record_id": "42",
        "timestamp": datetime(2026, 8, 2, 9, 30, tzinfo=timezone.utc),
        "raw_event_data": {"ServiceName": "Example"},
    }

    result = attach_detection_provenance(
        finding,
        source,
        detector_module="siem.native_event",
    )

    assert result["rule_id"] == "WINDOWS_SERVICE_INSTALLED"
    assert result["rule_version"] == "2026.08.02.1"
    assert result["detector_module"] == "siem.native_event"
    assert result["required_telemetry_family"] == "windows_native"
    assert result["detection_provenance"]["schema_version"] == "detector-provenance-v1"
    assert result["detection_provenance"]["evidence_refs"] == [
        {
            "event_uid": "System:7045:42",
            "event_id": "7045",
            "agent_id": "AGENT-A",
            "channel": "System",
            "record_id": "42",
            "timestamp": "2026-08-02 09:30:00+00:00",
        }
    ]
    assert "raw_message" not in result["detection_provenance"]
    assert "raw_event_data" not in result["detection_provenance"]


def test_fbr_provenance_distinguishes_pos_truth_from_native_fim():
    invoice = attach_detection_provenance(
        {"event_id": "FBR-INV-DEL"},
        detector_module="fbr.evidence",
    )
    fim = attach_detection_provenance(
        {"event_id": "FIM-DB-MOD"},
        detector_module="fbr.evidence",
    )

    assert invoice["required_telemetry_family"] == "pos_jsonl"
    assert fim["required_telemetry_family"] == "windows_native"
