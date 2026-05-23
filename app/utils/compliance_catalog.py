# 🛡️ WarSOC Compliance Master Catalog (SSOT)
# This file is the Single Source of Truth for all PECA/FBR rules.
# Both the API and the Workers MUST reference this catalog.

COMPLIANCE_CATALOG = {
    "peca_forensic": {
        "name": "PECA Forensic Trail (Section 46)",
        "description": "Non-repudiable log integrity and court-admissible forensic evidence (PECA 2016).",
        "retention": {"local_hot_days": 30, "vault_days": 365},
        "rules": [
            {"id": "PECA-101 (4625)", "event_id": 4625, "name": "Unauthorized Access Attempt (Failed Logon)", "severity": "High"},
            {"id": "PECA-102 (1102)", "event_id": 1102, "name": "Forensic Log Deletion (Audit Cleared)", "severity": "Critical"},
            {"id": "PECA-103 (4624)", "event_id": 4624, "name": "Success Logon", "severity": "Informational"},
            {"id": "PECA-104 (4688)", "event_id": 4688, "name": "Suspicious Process Creation", "severity": "Medium"},
            {"id": "PECA-105 (4672)", "event_id": 4672, "name": "Special Privileges Assigned", "severity": "Medium"},
            {"id": "PECA-106 (4720)", "event_id": 4720, "name": "Rogue Account Created", "severity": "High"},
            {"id": "PECA-107 (4726)", "event_id": 4726, "name": "Account Deleted", "severity": "High"},
            {"id": "PECA-108 (4732)", "event_id": 4732, "name": "Privilege Escalation (Group Added)", "severity": "High"},
            {"id": "PECA-109 (4697)", "event_id": 4697, "name": "Hidden Service Installation", "severity": "Critical"}
        ]
    },
    "fbr_pos": {
        "name": "FBR Point-of-Sale (SRO 288)",
        "description": "Mandatory real-time sales and modification tracking as per FBR S.R.O. 288(I)/2026.",
        "retention": {"local_hot_days": 7, "vault_days": 30},
        "rules": [
            {"id": "FBR-101 (4660)", "event_id": 4660, "name": "Object Deleted", "severity": "Warning"},
            {"id": "FBR-102 (4663)", "event_id": 4663, "name": "File System Modification", "severity": "Alert"},
            {"id": "FBR-103 (4670)", "event_id": 4670, "name": "Permissions Changed", "severity": "High"},
            {"id": "FBR-104 (4657)", "event_id": 4657, "name": "Registry Value Modified", "severity": "High"},
            {"id": "FBR-105 (4698)", "event_id": 4698, "name": "Scheduled Task Created", "severity": "Medium"}
        ]
    },
    "smb_threat_detection": {
        "name": "SMB Threat Detection Coverage",
        "description": "Lateral movement, enumeration, ransomware, and persistence coverage for SMB environments.",
        "retention": {"local_hot_days": 30, "vault_days": 365},
        "rules": [
            {"id": "SMB-101 (4648)", "event_id": 4648, "name": "Explicit Credential Use (Pass-the-Hash Indicator)", "severity": "High"},
            {"id": "SMB-102 (4776)", "event_id": 4776, "name": "NTLM Authentication", "severity": "High"},
            {"id": "SMB-103 (5140)", "event_id": 5140, "name": "Network Share Accessed", "severity": "Medium"},
            {"id": "SMB-104 (4768)", "event_id": 4768, "name": "Kerberos Authentication Ticket Requested", "severity": "Medium"},
            {"id": "SMB-105 (4769)", "event_id": 4769, "name": "Kerberos Service Ticket Requested", "severity": "Medium"},
            {"id": "SMB-106 (7)", "event_id": 7, "name": "Image Loaded", "severity": "Medium"},
            {"id": "SMB-107 (8)", "event_id": 8, "name": "Create Remote Thread", "severity": "Critical"},
            {"id": "SMB-108 (9)", "event_id": 9, "name": "Raw Access Read", "severity": "Critical"},
            {"id": "SMB-109 (10)", "event_id": 10, "name": "Process Access", "severity": "Critical"},
            {"id": "SMB-110 (13)", "event_id": 13, "name": "Registry Set", "severity": "High"},
            {"id": "SMB-111 (17)", "event_id": 17, "name": "Named Pipe Created", "severity": "Medium"},
            {"id": "SMB-112 (18)", "event_id": 18, "name": "Named Pipe Connected", "severity": "Medium"}
        ]
    }
}

def get_rule_by_event_id(event_id: int):
    """Helper to find which compliance rule an event ID belongs to."""
    for pack_id, pack in COMPLIANCE_CATALOG.items():
        for rule in pack["rules"]:
            if rule["event_id"] == event_id:
                return pack_id, rule
    return None, None
