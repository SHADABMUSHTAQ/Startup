import os
import re
import uuid
import time
from urllib.parse import urlparse
from datetime import datetime, timezone
import redis.asyncio as aioredis

class SIEMEngine:
    def __init__(self, config: dict = None):
        self.redis = None  # Will be set via set_redis_client()
        self.refresh_config(config)

    def refresh_config(self, config: dict):
        """
        🚀 RE-ENTRY MANDATE: Re-initializes all rules, patterns, and threat intel sets.
        Fixes BUG-23 (Ghost Reloading) by ensuring regex is re-compiled on config change.
        """
        self.config = config if config else {}
        self._initialize_from_config()
        print(f"✅ SIEM Engine Hot-Reloaded: {len(self.rules)} Regex Rules, {len(self.event_id_rules)} Event ID Rules.")

    def _initialize_from_config(self):
        # 1. Basic Whitelists
        self.whitelist_users = set(self.config.get("whitelist", {}).get("service_accounts", []))
        self.whitelist_ips = set(self.config.get("whitelist", {}).get("ips", []))

        # 2. Thresholds & FP Controls
        fp_controls = self.config.get("detection", {}).get("fp_controls", {})
        self.default_min_message_length = int(fp_controls.get("default_min_message_length", 12))
        self.max_alerts_per_log = int(fp_controls.get("max_alerts_per_log", 3))
        self.rule_cooldown_seconds = int(fp_controls.get("rule_cooldown_seconds", 20))
        self.global_suppress_tokens = [s.lower() for s in fp_controls.get("suppress_if_message_contains", [])]

        # 3. Threat Intelligence (Static + File Based)
        ti_config = self.config.get("threat_intelligence", {})
        self.blacklisted_ips = set(ti_config.get("ips", []))
        self._load_ti_files(ti_config.get("files", []))

        # 4. Event ID Mapping
        self.event_id_rules = self.config.get("event_id_map", {}) or self.config.get("detection", {}).get("event_id_rules", {})

        # 5. Phishing Logic
        phishing_cfg = self.config.get("detection", {}).get("phishing_detection", {})
        self.phishing_enabled = bool(phishing_cfg.get("enabled", False))
        self.phishing_threshold = int(phishing_cfg.get("score_threshold", 60))
        self.phishing_min_signals = int(phishing_cfg.get("minimum_signals", 2))
        self.phishing_weights = phishing_cfg.get("weights", {})
        self.phishing_keywords = [k.lower() for k in phishing_cfg.get("credential_lure_keywords", [])]
        self.phishing_shorteners = set(k.lower() for k in phishing_cfg.get("url_shorteners", []))
        self.phishing_trusted_domains = set(k.lower() for k in phishing_cfg.get("trusted_domains", []))
        self.phishing_suspicious_tlds = set(k.lower() for k in phishing_cfg.get("suspicious_tlds", []))
        self.phishing_risky_attachments = set(k.lower() for k in phishing_cfg.get("risky_attachment_extensions", []))
        self.phishing_lolbins = [k.lower() for k in phishing_cfg.get("lolbin_indicators", [])]
        
        self._url_pattern = re.compile(r"https?://[^\s'\"]+", flags=re.IGNORECASE)
        self._email_pattern = re.compile(r"\b[a-zA-Z0-9._%+-]+@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\b")
        self._ip_url_pattern = re.compile(r"https?://(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?(?:/|$)", flags=re.IGNORECASE)
        
        # 6. Regex Detection Rules (Compiled for Performance)
        self.rules = {}
        rules_data = self.config.get("detection", {}).get("rules", {})
        for rule_name, rule_meta in rules_data.items():
            try:
                self.rules[rule_name] = {
                    "pattern": re.compile(rule_meta["regex"]),
                    "severity": rule_meta.get("sev", "MEDIUM"),
                    "mitre": rule_meta.get("mitre", "N/A"),
                    "summary": rule_meta.get("summary", ""),
                    "requires_context": set(rule_meta.get("requires_context", [])),
                    "must_include_any": [s.lower() for s in rule_meta.get("must_include_any", [])],
                    "min_message_length": int(rule_meta.get("min_message_length", self.default_min_message_length)),
                    "cooldown_seconds": int(rule_meta.get("cooldown_seconds", self.rule_cooldown_seconds)),
                }
            except Exception as e:
                print(f"⚠️ Rule Error ({rule_name}): {e}")

    def _load_ti_files(self, file_paths):
        """🕵️ BUG-21 FIX: Injects IP-based threat intelligence from disk files."""
        # Path resolution relative to the app root
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        
        for rel_path in file_paths:
            abs_path = os.path.join(base_dir, rel_path)
            if not os.path.exists(abs_path):
                print(f"[⚠️] Threat Intel file skipping: {abs_path} not found.")
                continue
                
            try:
                with open(abs_path, "r") as f:
                    count = 0
                    for line in f:
                        ip = line.strip()
                        if ip and not ip.startswith("#"):
                            self.blacklisted_ips.add(ip)
                            count += 1
                print(f"✅ Threat Intel File Loaded: {rel_path} ({count} IPs)")
            except Exception as e:
                print(f"[!] Threat Intel Load Fail ({rel_path}): {e}")

    def set_redis_client(self, redis_client):
        """Inject Redis client for persistent cooldown tracking across worker restarts."""
        self.redis = redis_client

    async def analyze_single_log(self, log_entry: dict):
        findings = []
        
        ip = log_entry.get("source_ip", log_entry.get("ip", "0.0.0.0"))
        user = log_entry.get("user", "unknown")
        msg = log_entry.get("message", "")
        msg_lower = msg.lower()
        event_type = str(log_entry.get("event_type", "unknown")).lower()
        
        event_id = str(log_entry.get("event_id", ""))

        if user in self.whitelist_users or ip in self.whitelist_ips:
            return []

        # ---------------------------------------------------------
        # WINDOWS EVENT ID ENGINE
        # ---------------------------------------------------------
        if event_id and event_id in self.event_id_rules:
            rule = self.event_id_rules[event_id]
            findings.append(self._create_alert(
                f"EVENT_ID_{event_id}_{rule.get('event_type', 'ANOMALY').upper()}",
                rule.get("severity", "MEDIUM"),
                f"{rule.get('event_type', 'suspicious event').replace('_', ' ').title()} detected",
                log_entry,
                rule.get("mitre", "N/A")
            ))

        # ---------------------------------------------------------
        # REGEX ENGINE
        # ---------------------------------------------------------
        if self.global_suppress_tokens and any(token in msg_lower for token in self.global_suppress_tokens):
            return findings

        phishing_alert = self._detect_phishing(log_entry, msg_lower, event_type)
        if phishing_alert:
            findings.append(phishing_alert)

        for name, rule in self.rules.items():
            if len(findings) >= self.max_alerts_per_log:
                break

            required_context = rule.get("requires_context", set())
            if required_context and event_type not in required_context:
                continue

            if len(msg) < rule.get("min_message_length", self.default_min_message_length):
                continue

            token_hints = rule.get("must_include_any", [])
            if token_hints and not any(token in msg_lower for token in token_hints):
                continue

            # 🚀 REDIS COOLDOWN: Persistent across worker restarts
            cooldown_seconds = rule.get("cooldown_seconds", self.rule_cooldown_seconds)
            cooldown_key = f"warsoc:siem_cooldown:{name}:{ip}:{event_type}"

            # Check Redis for existing cooldown (non-blocking, graceful fallback)
            is_on_cooldown = False
            if self.redis:
                try:
                    last_fire_exists = await self.redis.get(cooldown_key)
                    is_on_cooldown = last_fire_exists is not None
                except Exception:
                    # Redis unavailable, skip cooldown check (prevents cascading failures)
                    pass

            if is_on_cooldown:
                continue

            if rule["pattern"].search(msg):
                # ✅ ZERO HARDCODING: Uses config summary or an extremely dumb fallback
                summary = rule["summary"] if rule["summary"] else self._fallback_summary(name)
                findings.append(self._create_alert(name, rule["severity"], summary, log_entry, rule["mitre"]))

                # Set Redis cooldown key with expiration
                if self.redis:
                    try:
                        await self.redis.setex(cooldown_key, cooldown_seconds, "1")
                    except Exception:
                        # Silently fail if Redis is down, alert still fires
                        pass

        return findings

    def _detect_phishing(self, log_entry: dict, msg_lower: str, event_type: str):
        if not self.phishing_enabled:
            return None

        signals = []
        score = 0

        if self.phishing_keywords and any(k in msg_lower for k in self.phishing_keywords):
            signals.append("credential_lure")
            score += int(self.phishing_weights.get("credential_lure", 20))

        urls = self._url_pattern.findall(log_entry.get("message", ""))
        for url in urls:
            parsed = urlparse(url)
            host = (parsed.hostname or "").lower()
            if not host:
                continue

            if self._ip_url_pattern.search(url):
                signals.append("raw_ip_url")
                score += int(self.phishing_weights.get("raw_ip_url", 30))

            if host.startswith("xn--"):
                signals.append("punycode_domain")
                score += int(self.phishing_weights.get("punycode_domain", 35))

            if any(host == s or host.endswith(f".{s}") for s in self.phishing_shorteners):
                signals.append("url_shortener")
                score += int(self.phishing_weights.get("url_shortener", 20))

            if self.phishing_trusted_domains and any(host == d or host.endswith(f".{d}") for d in self.phishing_trusted_domains):
                continue

            if "." in host:
                tld = host.rsplit(".", 1)[-1]
                if tld in self.phishing_suspicious_tlds:
                    signals.append("suspicious_domain")
                    score += int(self.phishing_weights.get("suspicious_domain", 20))

        file_path = str(log_entry.get("file_path") or (log_entry.get("raw_data") or {}).get("file_path") or "").lower()
        for ext in self.phishing_risky_attachments:
            if ext and (ext in file_path or ext in msg_lower):
                signals.append("risky_attachment")
                score += int(self.phishing_weights.get("risky_attachment", 30))
                break

        if event_type in {"process_creation", "unknown"} and self.phishing_lolbins:
            if any(ind in msg_lower for ind in self.phishing_lolbins):
                signals.append("lolbin_execution")
                score += int(self.phishing_weights.get("lolbin_execution", 35))

        email_domains = [m.group(1).lower() for m in self._email_pattern.finditer(log_entry.get("message", ""))]
        if email_domains and self.phishing_trusted_domains:
            for domain in email_domains:
                if not any(domain == d or domain.endswith(f".{d}") for d in self.phishing_trusted_domains):
                    signals.append("sender_spoof_hint")
                    score += int(self.phishing_weights.get("sender_spoof_hint", 25))
                    break

        unique_signals = sorted(set(signals))
        if score < self.phishing_threshold or len(unique_signals) < self.phishing_min_signals:
            return None

        sev = "HIGH" if score < 90 else "CRITICAL"
        return self._create_alert("PHISHING_PATTERN", sev, "Possible phishing activity detected", log_entry, "T1566")

    def _fallback_summary(self, rule_name: str) -> str:
        # ✅ FIX: Dumb generic string format, no custom dict mapping
        readable = str(rule_name or "suspicious").replace("_", " ").strip().lower()
        return f"Potential {readable} activity detected"

    def _create_alert(self, type_str, sev, summary, row, mitre):
        event_id_value = row.get("event_id", 0)
        event_id_str = str(event_id_value or "").strip()
        normalized_event_id = int(event_id_str) if event_id_str.isdigit() else 0

        mapped_meaning = ""
        if event_id_str and event_id_str in self.event_id_rules:
            mapped_type = self.event_id_rules[event_id_str].get("event_type")
            if mapped_type:
                mapped_meaning = str(mapped_type).replace("_", " ").strip().title()

        provided_meaning = str(row.get("event_id_meaning") or "").strip()
        event_id_meaning = provided_meaning or mapped_meaning
        raw_message = str(row.get("raw_message") or row.get("message") or "Unknown Event")

        return {
            "id": uuid.uuid4().hex[:12],
            "type": type_str,
            "severity": sev,
            "summary": summary,
            "event_id": normalized_event_id,
            "event_id_meaning": event_id_meaning,
            "message": raw_message,
            "raw_message": raw_message,
            "ip": row.get("source_ip", row.get("ip", "N/A")),
            "user": row.get("user", "N/A"),
            "mitre": mitre,
            "timestamp": row.get("timestamp", datetime.now(timezone.utc).isoformat()),
            "engine_source": row.get("engine_source", "Stateless")
        }