import json
import os
import sys

# Add parent directory to path so we can import app modules if run standalone
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from app.utils.siem_catalog import SIEM_RULES
from app.utils.compliance_catalog import COMPLIANCE_CATALOG

def generate_tenant_policy():
    """
    Compiles the target_event_ids from the two SSOTs (SIEM and Compliance)
    to ensure the Windows agent never misses a required event.
    """
    target_event_ids = set()

    # 1. Ingest SIEM Event IDs
    event_id_map = SIEM_RULES.get("event_id_map", {})
    for eid in event_id_map.keys():
        try:
            target_event_ids.add(int(eid))
        except ValueError:
            pass

    source_class = SIEM_RULES.get("source_classification", {})
    for sc, sc_data in source_class.items():
        if "trigger_event_ids" in sc_data:
            for eid in sc_data["trigger_event_ids"]:
                try:
                    target_event_ids.add(int(eid))
                except ValueError:
                    pass

    # 2. Ingest Compliance Event IDs
    for framework, data in COMPLIANCE_CATALOG.items():
        for rule in data.get("rules", []):
            if "event_id" in rule and rule["event_id"] is not None:
                try:
                    target_event_ids.add(int(rule["event_id"]))
                except ValueError:
                    pass

    # 3. Add base infrastructure failsafe events
    base_ids = {
        1100, 4624, 4625, 4672, 4720, 4726, 1102,
        4663, 4660, 4657, 4698, 4732, 4670,
        4616, 4697, 4719, 4798, 4648, 4776, 4768, 
        4769, 5140, 7045, 5157, 4688
    }
    target_event_ids.update(base_ids)

    final_ids = sorted(list(target_event_ids))
    
    # 4. Generate the Agent payload
    payload = {
        "monitoring": {
            "target_event_ids": final_ids,
            "capture_all_security_events": False,
            "capture_all_windows_channels": False,
            "windows_channels": [
                "Security",
                "System"
            ],
            "web_log_paths": [
                "access.log",
                "C:/inetpub/logs/LogFiles/W3SVC*/u_ex*.log",
                "%ProgramData%/WarSOC/pos_audit.log"
            ]
        }
    }
    
    # Write to agent/tenant_policy.json
    # The file should be at Startup-backend/agent/tenant_policy.json
    root_dir = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
    agent_dir = os.path.join(root_dir, "agent")
    os.makedirs(agent_dir, exist_ok=True)
    
    policy_path = os.path.join(agent_dir, "tenant_policy.json")
    with open(policy_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=4)
        
    print(f" SSOT Sync Complete. Compiled {len(final_ids)} target event IDs into {policy_path}.")

if __name__ == "__main__":
    generate_tenant_policy()
