"""Safe recovery guidance for existing relay/device health states."""


def relay_health_issues(health: str) -> list[dict]:
    guidance = {
        "OFFLINE": (
            "Firewall log relay is offline. WarSOC cannot confirm current firewall activity.",
            [
                "Power on the relay host and check its WarSOC relay service.",
                "Restore HTTPS connectivity to the backend and check relay spool/delivery diagnostics.",
                "Confirm fresh accepted batches in Firewall Relays before closing the warning.",
            ],
        ),
        "RELAY_OFFLINE": (
            "Device visibility is unavailable because its relay is offline.",
            ["Restore the parent relay first, then verify incoming device logs."],
        ),
        "SILENT": (
            "The relay is reachable but this device has stopped sending log evidence. Silence alone is not proof of an attack.",
            [
                "Check the firewall is online and remote syslog is enabled for the required log categories.",
                "Check destination IP, port, transport, source allowlist and listener firewall rules.",
                "Generate an approved harmless logged event and confirm its device timestamp advances.",
            ],
        ),
        "NOT_SEEN": (
            "No log evidence has been received from this device yet.",
            ["Verify the device syslog route and send an approved harmless logged event."],
        ),
        "DEGRADED": (
            "Log delivery is degraded. Reported failures, drops or stale batches may reduce visibility.",
            [
                "Review relay/device delivery diagnostics, spool capacity and source/listener configuration.",
                "Correct the reported failure and verify fresh accepted evidence; do not discard the spool.",
            ],
        ),
        "REVOKED": (
            "This relay identity is revoked and cannot deliver evidence.",
            ["Use the tenant-admin relay enrollment workflow if monitoring is required again."],
        ),
        "INACTIVE": (
            "This relay is inactive and monitoring is not running.",
            ["Review the tenant-admin relay lifecycle before resuming monitoring."],
        ),
    }
    if health not in guidance:
        return []
    summary, remediation = guidance[health]
    return [{"code": health, "summary": summary, "remediation": remediation}]
