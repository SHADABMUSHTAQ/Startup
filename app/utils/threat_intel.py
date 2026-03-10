import os
import ipaddress
import logging
from functools import lru_cache
from typing import Dict, Set, Tuple

class ThreatIntelligenceManager:
    """Consolidated Memory: Handles CIDRs, Files, and IP Blacklists with Zero Overlap"""
    
    def __init__(self, config: Dict):
        self.threat_data = self._load_all_intel(config)
        self.whitelist_ips = set(config.get("whitelist", {}).get("ips", []))
        self.whitelist_users = set(config.get("whitelist", {}).get("service_accounts", []))

    def _load_all_intel(self, config: Dict) -> Dict:
        """Pipeline Stage: Aggregates intel from JSON and External Files"""
        intel = {"ips": set(), "cidrs": set(), "domains": set()}
        ti_cfg = config.get("threat_intelligence", {})

        # 1. Load Direct IPs
        for ip in ti_cfg.get("ips", []):
            if self._validate_ip(ip): intel["ips"].add(ip)

        # 2. Load External Files (Advanced logic from your old util)
        for rel_path in ti_cfg.get("files", []):
            try:
                # Resolve path relative to the app root
                abs_path = os.path.abspath(os.path.join(os.getcwd(), rel_path))
                if os.path.exists(abs_path):
                    with open(abs_path, 'r') as f:
                        for line in f:
                            val = line.strip()
                            if not val or val.startswith('#'): continue
                            if self._validate_ip(val): intel["ips"].add(val)
                            elif '/' in val: intel["cidrs"].add(val)
                            else: intel["domains"].add(val)
            except Exception as e:
                logging.error(f"TI File Load Error: {e}")
        
        return intel

    @staticmethod
    def _validate_ip(ip: str) -> bool:
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False

    @lru_cache(maxsize=10000)
    def check_reputation(self, ip: str) -> Tuple[bool, str]:
        """High-Performance Lookup: Checks Whitelist -> Blacklist -> CIDRs"""
        if not self._validate_ip(ip): return False, "Invalid Format"
        if ip in self.whitelist_ips: return False, "Whitelisted"
        
        # O(1) Blacklist Check
        if ip in self.threat_data['ips']: return True, "Known Malicious IP"

        # CIDR Network Check
        ip_obj = ipaddress.ip_address(ip)
        for cidr in self.threat_data['cidrs']:
            try:
                if ip_obj in ipaddress.ip_network(cidr):
                    return True, f"Matches Malicious Network: {cidr}"
            except: continue

        return False, "Neutral"

    def is_service_account(self, user: str) -> bool:
        """Excludes administrative/service users from triggering alerts"""
        return user in self.whitelist_users
