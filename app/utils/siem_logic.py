import re
import uuid
import os
from pathlib import Path
from datetime import datetime, timezone

class SIEMEngine:
    def __init__(self, config: dict = None):
        self.config = config if config else {}
        
        # Smart Cache Setup for Physical File
        base_dir = Path(__file__).resolve().parent.parent.parent
        self.blacklist_file = base_dir / "data" / "blacklist_ip.txt"
        self._last_ti_update = 0.0
        
        # Load Static Configs
        self.static_blacklist_ips = set(self.config.get("threat_intelligence", {}).get("ips", []))
        self.blacklist_ips = set(self.static_blacklist_ips) 
        
        self.whitelist_users = set(self.config.get("whitelist", {}).get("service_accounts", []))
        self.whitelist_ips = set(self.config.get("whitelist", {}).get("ips", []))
        
        # Load rules
        self.rules = {}
        rules_data = self.config.get("detection", {}).get("rules", {})
        for rule_name, rule_meta in rules_data.items():
            try:
                self.rules[rule_name] = {
                    "pattern": re.compile(rule_meta["regex"]),
                    "severity": rule_meta.get("sev", "MEDIUM"),
                    "mitre": rule_meta.get("mitre", "N/A")
                }
            except Exception as e:
                print(f"⚠️ Rule Error ({rule_name}): {e}")

        print(f"✅ Stateless Engine Loaded: {len(self.rules)} Rules.")
        self._sync_threat_intel_file()

    def _sync_threat_intel_file(self):
        """SMART CACHE: Only reads from disk if the text file was modified."""
        if not self.blacklist_file.exists():
            return
        
        current_mtime = os.path.getmtime(self.blacklist_file)
        if current_mtime > self._last_ti_update:
            try:
                with open(self.blacklist_file, 'r') as f:
                    file_ips = {line.strip() for line in f if line.strip()}
                self.blacklist_ips = self.static_blacklist_ips.union(file_ips)
                self._last_ti_update = current_mtime
                print(f"🔄 Threat Intel Synced! Tracking {len(self.blacklist_ips)} Bad IPs.")
            except Exception as e:
                print(f"⚠️ Failed to read blacklist file: {e}")

    def analyze_single_log(self, log_entry: dict):
        self._sync_threat_intel_file()
        findings = []
        
        ip = log_entry.get("source_ip", log_entry.get("ip", "0.0.0.0"))
        user = log_entry.get("user", "unknown")
        msg = log_entry.get("message", "")
        
        # 1. Grab the exact Event ID we passed from the worker
        event_id = str(log_entry.get("event_id", ""))

        if user in self.whitelist_users or ip in self.whitelist_ips:
            return []

        if ip in self.blacklist_ips:
            findings.append(self._create_alert("THREAT_INTEL_MATCH", "CRITICAL", f"Blacklist IP: {ip}", log_entry, "T1071"))
            return findings

        # ---------------------------------------------------------
        # 2. WINDOWS EVENT ID ENGINE (The B2B Standard)
        # ---------------------------------------------------------
        if event_id == "1102":
            findings.append(self._create_alert("DEFENSE_EVASION", "CRITICAL", "Audit Logs Cleared (Event 1102)", log_entry, "T1070"))
        elif event_id == "4720":
            findings.append(self._create_alert("PERSISTENCE", "HIGH", "Rogue Account Created (Event 4720)", log_entry, "T1136"))
        elif event_id == "4726":
            findings.append(self._create_alert("PERSISTENCE", "MEDIUM", "Account Deleted (Event 4726)", log_entry, "T1136"))
        elif event_id == "4625":
            findings.append(self._create_alert("BRUTE_FORCE_PATTERN", "MEDIUM", "Failed Login (Event 4625)", log_entry, "T1110"))

        # ---------------------------------------------------------
        # 3. REGEX ENGINE (For Web/Linux/Text logs)
        # ---------------------------------------------------------
        for name, rule in self.rules.items():
            if rule["pattern"].search(msg):
                findings.append(self._create_alert(name, rule["severity"], f"Detected {name}", log_entry, rule["mitre"]))
        
        return findings

    def _create_alert(self, type_str, sev, summary, row, mitre):
        ts = row.get("timestamp", datetime.now(timezone.utc).isoformat())
        return {
            "id": uuid.uuid4().hex[:12],
            "type": type_str,
            "severity": sev,
            "summary": summary,
            "ip": row.get("source_ip", row.get("ip", "N/A")),
            "user": row.get("user", "N/A"),
            "mitre": mitre,
            "timestamp": ts,
            "engine_source": "Stateless"
        }