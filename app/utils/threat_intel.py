import os
import ipaddress
import logging
import time
import httpx
from typing import Dict, Tuple

from app.config.config import get_settings

class ThreatIntelligenceManager:
    """Consolidated Memory: Handles CIDRs, Files, and IP Blacklists with Zero Overlap"""
    
    def __init__(self, config: Dict):
        self.settings = get_settings()
        self.vt_api_key = self.settings.vt_api_key
        self._vt_cache = {}
        self._vt_requests = []
        
        ti_cfg = config.get("threat_intelligence", {})
        self.ti_cfg = ti_cfg
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

    async def check_reputation(self, ip: str) -> Tuple[bool, str]:
        """High-Performance Lookup: Checks Whitelist -> Blacklist -> CIDRs -> VirusTotal"""
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
            except Exception: continue

        # Suppress unknown traffic in low-signal trusted scopes only when no strong indicator matched.
        if self.ignore_private_ips and ip_obj.is_private and ip not in self.private_ip_allowlist:
            return False, "Private IP ignored"

        for trusted_net in self.trusted_networks:
            if ip_obj in trusted_net and ip not in self.private_ip_allowlist:
                return False, f"Trusted Network: {trusted_net}"

        # --- VirusTotal Check (With Rate Limiting) ---
        if not self.vt_api_key or ip in self._vt_cache:
            # If cached or no API key, return cached result or Neutral
            cached_res = self._vt_cache.get(ip)
            if cached_res is not None:
                is_malicious, msg = cached_res
                return is_malicious, msg
            return False, "Neutral"

        # Leaky bucket rate limit: 4 requests per minute
        now = time.time()
        self._vt_requests = [req_time for req_time in self._vt_requests if now - req_time < 60]
        if len(self._vt_requests) >= 4:
            # Rate limit reached, fallback to neutral and DON'T cache
            return False, "Neutral"

        self._vt_requests.append(now)

        try:
            async with httpx.AsyncClient() as client:
                headers = {"x-apikey": self.vt_api_key}
                response = await client.get(f"https://www.virustotal.com/api/v3/ip_addresses/{ip}", headers=headers, timeout=5.0)
                
                if response.status_code == 200:
                    data = response.json()
                    stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                    malicious_count = stats.get("malicious", 0)
                    suspicious_count = stats.get("suspicious", 0)

                    if malicious_count > 0 or suspicious_count > 1:
                        msg = f"VirusTotal Malicious IP (malicious={malicious_count}, suspicious={suspicious_count})"
                        self._vt_cache[ip] = (True, msg)
                        
                        # Dynamically add to current run
                        self.threat_data["ips"].add(ip)
                        self.threat_data["ip_scores"][ip] = self.confidence["file_ip"]
                        
                        # Add to persistent local file using organic learning
                        try:
                            primary_file = self.ti_cfg.get("files", [])
                            if primary_file:
                                abs_path = os.path.abspath(os.path.join(os.getcwd(), primary_file[0]))
                                with open(abs_path, 'a') as f:
                                    f.write(f"\n{ip},{self.confidence['file_ip']}\n")
                                logging.info(f"✅ Organically learned Malicious IP from VT: {ip} -> saved to {primary_file[0]}")
                        except Exception as e:
                            logging.error(f"Error appending organically learned IP to file: {e}")

                        return True, msg
                    
                    # Store benign result in memory cache only
                    self._vt_cache[ip] = (False, "VirusTotal Clean")
                    return False, "VirusTotal Clean"
                else:
                    logging.warning(f"VirusTotal API Error for {ip}: {response.status_code}")
        except Exception as e:
            logging.error(f"VirusTotal Async Request Failed: {e}")

        return False, "Neutral"

    def is_service_account(self, user: str) -> bool:
        """Excludes administrative/service users from triggering alerts"""
        return user in self.whitelist_users
