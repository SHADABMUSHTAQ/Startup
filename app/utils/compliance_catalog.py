#  WarSOC Compliance Master Catalog (SSOT)
# This file is the Single Source of Truth for all PECA/FBR rules.
# Both the API and the Workers MUST reference this catalog.

COMPLIANCE_CATALOG = {
    "peca_forensic": {
        "name": "PECA Forensic Trail (Section 46)",
        "description": "Non-repudiable log integrity and court-admissible forensic evidence (PECA 2016).",
        "retention": {"local_hot_days": 30, "vault_days": 365},
        "rules": [
            {"id": "PECA-101 (4625)", "event_id": "4625", "name": "Unauthorized Access Attempt (Failed Logon)", "severity": "High"},
            {"id": "PECA-102 (1102)", "event_id": "1102", "name": "Forensic Log Deletion (Audit Cleared)", "severity": "Critical"},
            {"id": "PECA-103 (4624)", "event_id": "4624", "name": "Success Logon", "severity": "Informational"},
            {"id": "PECA-104 (4688)", "event_id": "4688", "name": "Suspicious Process Creation", "severity": "Medium"},
            {"id": "PECA-105 (4672)", "event_id": "4672", "name": "Special Privileges Assigned", "severity": "Medium"},
            {"id": "PECA-106 (4720)", "event_id": "4720", "name": "Rogue Account Created", "severity": "High"},
            {"id": "PECA-107 (4726)", "event_id": "4726", "name": "Account Deleted", "severity": "High"},
            {"id": "PECA-108 (4732)", "event_id": "4732", "name": "Privilege Escalation (Group Added)", "severity": "High"},
            {"id": "PECA-109 (4697)", "event_id": "4697", "name": "Hidden Service Installation", "severity": "Critical"}
        ]
    },
    "fbr_pos": {
        "name": "FBR Point-of-Sale (SRO 288)",
        "description": "Mandatory real-time sales and modification tracking as per FBR S.R.O. 288(I)/2026.",
        "retention": {"local_hot_days": 7, "vault_days": 2190},
        "rules": [
            {"id": "FBR-101 (FBR-INV-DEL)", "event_id": "FBR-INV-DEL", "name": "Financial Record Deletion", "severity": "Warning"},
            {"id": "FBR-102 (FBR-INV-MOD)", "event_id": "FBR-INV-MOD", "name": "Financial Record Modification", "severity": "Critical"},
            {"id": "FBR-103 (4660)", "event_id": "4660", "name": "Object Deleted", "severity": "Warning"},
            {"id": "FBR-104 (4663)", "event_id": "4663", "name": "File System Modification", "severity": "Alert"},
            {"id": "FBR-105 (4670)", "event_id": "4670", "name": "Permissions Changed", "severity": "High"},
            {"id": "FBR-106 (4657)", "event_id": "4657", "name": "Registry Value Modified", "severity": "High"},
            {"id": "FBR-107 (4698)", "event_id": "4698", "name": "Scheduled Task Created", "severity": "Medium"}
        ]
    }
}

def get_rule_by_event_id(event_id: str):
    """Helper to find which compliance rule an event ID belongs to."""
    for pack_id, pack in COMPLIANCE_CATALOG.items():
        for rule in pack["rules"]:
            if str(rule["event_id"]) == str(event_id):
                return pack_id, rule
    return None, None
