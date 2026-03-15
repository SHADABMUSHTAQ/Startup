import os
import ipaddress
import logging
from functools import lru_cache
from typing import Dict, Tuple

class ThreatIntelligenceManager:
    """Consolidated Memory: Handles CIDRs, Files, and IP Blacklists with Zero Overlap"""
    
    def __init__(self, config: Dict):
        ti_cfg = config.get("threat_intelligence", {})
        ti_options = ti_cfg.get("options", {}) if isinstance(ti_cfg, dict) else {}

        self.ignore_private_ips = bool(ti_options.get("ignore_private_ips", True))
        self.minimum_confidence = int(ti_options.get("minimum_confidence", 70))
        self.confidence = {
            "direct_ip": int(ti_options.get("confidence", {}).get("direct_ip", 95)),
            "file_ip": int(ti_options.get("confidence", {}).get("file_ip", 90)),
            "cidr": int(ti_options.get("confidence", {}).get("cidr", 75)),
        }

        self.trusted_networks = self._parse_networks(ti_options.get("trusted_networks", []))
        self.private_ip_allowlist = {ip for ip in ti_options.get("private_ip_allowlist", []) if self._validate_ip(ip)}

        self.threat_data = self._load_all_intel(config)
        self.whitelist_ips = set(config.get("whitelist", {}).get("ips", []))
        self.whitelist_users = set(config.get("whitelist", {}).get("service_accounts", []))

    def _parse_networks(self, values):
        networks = []
        for value in values:
            try:
                networks.append(ipaddress.ip_network(value, strict=False))
            except ValueError:
                continue
        return networks

    def _load_all_intel(self, config: Dict) -> Dict:
        """Pipeline Stage: Aggregates intel from JSON and External Files"""
        intel = {
            "ips": set(),
            "cidrs": set(),
            "domains": set(),
            "ip_scores": {},
            "cidr_scores": {},
        }
        ti_cfg = config.get("threat_intelligence", {})

        # 1. Load Direct IPs
        for ip in ti_cfg.get("ips", []):
            if self._validate_ip(ip):
                intel["ips"].add(ip)
                intel["ip_scores"][ip] = self.confidence["direct_ip"]

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
                            parts = [p.strip() for p in val.split(",")]
                            indicator = parts[0]
                            custom_score = None
                            if len(parts) > 1 and parts[1].isdigit():
                                custom_score = int(parts[1])

                            if self._validate_ip(indicator):
                                intel["ips"].add(indicator)
                                intel["ip_scores"][indicator] = custom_score if custom_score is not None else self.confidence["file_ip"]
                            elif '/' in indicator:
                                intel["cidrs"].add(indicator)
                                intel["cidr_scores"][indicator] = custom_score if custom_score is not None else self.confidence["cidr"]
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

        ip_obj = ipaddress.ip_address(ip)
        
        # O(1) Blacklist Check
        if ip in self.threat_data['ips']:
            score = int(self.threat_data["ip_scores"].get(ip, self.confidence["direct_ip"]))
            if score >= self.minimum_confidence:
                return True, f"Known Malicious IP (confidence={score})"
            return False, f"Low Confidence Indicator (confidence={score})"

        # CIDR Network Check
        for cidr in self.threat_data['cidrs']:
            try:
                if ip_obj in ipaddress.ip_network(cidr):
                    score = int(self.threat_data["cidr_scores"].get(cidr, self.confidence["cidr"]))
                    if score >= self.minimum_confidence:
                        return True, f"Matches Malicious Network: {cidr} (confidence={score})"
                    return False, f"Low Confidence Network Match: {cidr} (confidence={score})"
            except: continue

        # Suppress unknown traffic in low-signal trusted scopes only when no strong indicator matched.
        if self.ignore_private_ips and ip_obj.is_private and ip not in self.private_ip_allowlist:
            return False, "Private IP ignored"

        for trusted_net in self.trusted_networks:
            if ip_obj in trusted_net and ip not in self.private_ip_allowlist:
                return False, f"Trusted Network: {trusted_net}"

        return False, "Neutral"

    def is_service_account(self, user: str) -> bool:
        """Excludes administrative/service users from triggering alerts"""
        return user in self.whitelist_users
