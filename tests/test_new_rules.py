import pytest
import asyncio
from app.utils.siem_logic import SIEMEngine
from app.utils.siem_catalog import SIEM_RULES

@pytest.mark.asyncio
async def test_sigma_rules():
    engine = SIEMEngine(SIEM_RULES)
    
    # 1. Test Ransomware
    log1 = {"message": "vssadmin.exe Delete Shadows /All /Quiet", "event_type": "process_create"}
    findings1 = await engine.analyze_single_log(log1)
    assert any(f["type"] == "SIGMA_RANSOMWARE_SHADOW_DELETE" for f in findings1), "Ransomware detection failed"
    print("[+] Ransomware detected")

    # 2. Test Credential Dumping
    log2 = {"message": "procdump -ma lsass.exe lsass.dmp", "event_type": "process_create"}
    findings2 = await engine.analyze_single_log(log2)
    assert any(f["type"] == "SIGMA_CREDENTIAL_DUMPING" for f in findings2), "Credential dumping failed"
    print("[+] Credential dumping detected")

    # 3. Test Defense Evasion
    log3 = {"message": "Set-MpPreference -DisableRealtimeMonitoring $true", "event_type": "powershell"}
    findings3 = await engine.analyze_single_log(log3)
    assert any(f["type"] == "DEFENSE_EVASION_DEFENDER" for f in findings3), "Defense evasion failed"
    print("[+] Defense evasion detected")
