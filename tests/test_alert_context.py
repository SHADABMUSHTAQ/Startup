from app.utils.alert_context import build_alert_context, operator_alert_document


def test_operator_alert_context_extracts_and_redacts_native_command():
    source_event = {
        "event_id": "4688",
        "event_uid": "Security:123",
        "agent_id": "AGENT-A",
        "computer": "POS-01",
        "user": "operator",
        "raw_message": (
            "Windows Event 4688; command: powershell.exe "
            "--password SuperSecret --api-key=abc123 whoami"
        ),
        "raw_data": {
            "new_process_name": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            "creator_process_name": r"C:\Windows\explorer.exe",
        },
    }
    alert = {
        "tenant_id": "TENANT-A",
        "type": "RECON_COMMANDS",
        "severity": "MEDIUM",
        "summary": "Reconnaissance command detected",
        "raw_message": source_event["raw_message"],
    }

    context = build_alert_context(alert, source_event)

    assert context["endpoint"] == "POS-01"
    assert context["event_id"] == "4688"
    assert context["process_name"].endswith("powershell.exe")
    assert "SuperSecret" not in context["command_line"]
    assert "abc123" not in context["command_line"]
    assert context["command_line"].count("[REDACTED]") == 2


def test_operator_document_strips_raw_evidence_but_keeps_safe_context():
    alert = {
        "tenant_id": "TENANT-A",
        "type": "LOG_EVASION",
        "severity": "HIGH",
        "summary": "Potential log evasion activity detected",
        "raw_message": "command: wevtutil cl Security --access-token=secret-token",
        "raw_event_data": {"secret": "raw"},
        "processed_data": {"command_line": "wevtutil cl Security --access-token=secret-token"},
        "_expire_at": "internal",
    }

    result = operator_alert_document(alert)

    assert result["message"] == "Potential log evasion activity detected"
    assert result["context"]["command_line"].endswith("--access-token=[REDACTED]")
    assert "raw_message" not in result
    assert "raw_event_data" not in result
    assert "processed_data" not in result
    assert "_expire_at" not in result
