import ipaddress
import logging
import time
from datetime import datetime, timezone
import httpx
from typing import Dict, Tuple, Optional

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
        """Pipeline Stage: Aggregates intel from JSON config only."""
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

        return intel

    @staticmethod
    def _validate_ip(ip: str) -> bool:
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False

    async def _persist_learned_ip(self, ip: str, db=None, redis_client=None, source: str = "heuristic_engine") -> None:
        """Persist a learned malicious IP and fan it out to other runtimes."""
        if not db:
            logging.warning(f"[THREAT-INTEL] Mongo DB unavailable; skipping persistence for {ip}")
            return

        learned_ips = db["threat_intel_learned_ips"]
        now = datetime.now(timezone.utc)

        await learned_ips.update_one(
            {"ip": ip},
            {
                "$setOnInsert": {
                    "ip": ip,
                    "timestamp": now,
                    "source": source,
                },
                "$set": {
                    "last_seen_at": now,
                    "source": source,
                },
            },
            upsert=True,
        )

        if redis_client:
            try:
                await redis_client.publish("threat_intel_updates", ip)
            except Exception as exc:
                logging.warning(f"[THREAT-INTEL] Redis publish failed for {ip}: {exc}")

    async def check_reputation(self, ip: str, db=None, redis_client=None) -> Tuple[bool, str]:
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

                        try:
                            await self._persist_learned_ip(ip, db=db, redis_client=redis_client, source="heuristic_engine")
                        except Exception as exc:
                            logging.error(f"Error persisting organically learned IP for {ip}: {exc}")

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
