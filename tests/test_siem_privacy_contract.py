from cryptography.fernet import Fernet

from app.utils.siem_privacy import decrypt_siem_value, protect_siem_document


def test_siem_persistence_encrypts_raw_fields_and_sensitive_command_line():
    key = Fernet.generate_key().decode("ascii")
    source = {
        "tenant_id": "TENANT-A",
        "agent_id": "AGENT-A",
        "event_uid": "EVENT-A",
        "event_id": "4688",
        "telemetry_family": "windows_native",
        "event_id_meaning": "Process creation",
        "message": "Command: powershell.exe -Password TopSecret123!",
        "raw_event_data": {"event_data": {"CommandLine": "powershell.exe -enc AAA"}},
        "processed_data": {"command_line": "powershell.exe -enc AAA"},
        "context": {"command_line": "powershell.exe -Password TopSecret123!"},
    }

    protected = protect_siem_document(source, key)
    cipher = Fernet(key.encode("ascii"))

    assert protected["message"] == "Process creation"
    assert "TopSecret123" not in str(protected)
    assert protected["raw_message"].startswith("fernet-v1:")
    assert protected["raw_event_data"].startswith("fernet-v1:")
    assert protected["processed_data"].startswith("fernet-v1:")
    assert "command_line" not in protected["context"]
    assert decrypt_siem_value(protected["raw_message"], cipher).startswith("Command:")
    assert decrypt_siem_value(protected["raw_event_data"], cipher)["event_data"]
    assert decrypt_siem_value(protected["command_line_ciphertext"], cipher).startswith(
        "powershell.exe"
    )


def test_siem_persistence_fails_closed_without_valid_encryption_key():
    for key in ("", "not-a-fernet-key"):
        try:
            protect_siem_document({"event_id": "4624"}, key)
        except RuntimeError:
            pass
        else:
            raise AssertionError("SIEM persistence accepted an invalid encryption key")


def test_siem_operational_identity_remains_exact_match_searchable():
    key = Fernet.generate_key().decode("ascii")
    protected = protect_siem_document(
        {
            "tenant_id": "TENANT-A",
            "agent_id": "AGENT-A",
            "event_uid": "EVENT-A",
            "event_id": "4625",
            "timestamp": "2026-08-20T12:00:00Z",
            "source_ip": "192.0.2.25",
            "user": "operator-a",
            "message": "Failed logon details",
        },
        key,
    )

    assert protected["tenant_id"] == "TENANT-A"
    assert protected["agent_id"] == "AGENT-A"
    assert protected["event_uid"] == "EVENT-A"
    assert protected["event_id"] == "4625"
    assert protected["timestamp"] == "2026-08-20T12:00:00Z"
    assert protected["source_ip"] == "192.0.2.25"
    assert protected["user"] == "operator-a"
