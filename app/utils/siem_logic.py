import re
import uuid
import time
from urllib.parse import urlparse
from datetime import datetime, timezone

class SIEMEngine:
    def __init__(self, config: dict = None):
        self.config = config if config else {}
        
        self.whitelist_users = set(self.config.get("whitelist", {}).get("service_accounts", []))
        self.whitelist_ips = set(self.config.get("whitelist", {}).get("ips", []))

        fp_controls = self.config.get("detection", {}).get("fp_controls", {})
        self.default_min_message_length = int(fp_controls.get("default_min_message_length", 12))
        self.max_alerts_per_log = int(fp_controls.get("max_alerts_per_log", 3))
        self.rule_cooldown_seconds = int(fp_controls.get("rule_cooldown_seconds", 20))
        self.global_suppress_tokens = [s.lower() for s in fp_controls.get("suppress_if_message_contains", [])]
        self._last_rule_fires = {}

        # ✅ ZERO HARDCODING: Windows Event ID Rules pulled strictly from Config
        self.event_id_rules = self.config.get("detection", {}).get("event_id_rules", {})

        phishing_cfg = self.config.get("detection", {}).get("phishing_detection", {})
        self.phishing_enabled = bool(phishing_cfg.get("enabled", False))
        self.phishing_threshold = int(phishing_cfg.get("score_threshold", 60))
        self.phishing_min_signals = int(phishing_cfg.get("minimum_signals", 2))
        
        # ✅ ZERO HARDCODING: Phishing weights pulled strictly from Config
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
        
        # Load Regex Rules (Now relies on config for "summary")
        self.rules = {}
        rules_data = self.config.get("detection", {}).get("rules", {})
        for rule_name, rule_meta in rules_data.items():
            try:
                self.rules[rule_name] = {
                    "pattern": re.compile(rule_meta["regex"]),
                    "severity": rule_meta.get("sev", "MEDIUM"),
                    "mitre": rule_meta.get("mitre", "N/A"),
                    "summary": rule_meta.get("summary", ""), # ✅ Added config-driven summary
                    "requires_context": set(rule_meta.get("requires_context", [])),
                    "must_include_any": [s.lower() for s in rule_meta.get("must_include_any", [])],
                    "min_message_length": int(rule_meta.get("min_message_length", self.default_min_message_length)),
                    "cooldown_seconds": int(rule_meta.get("cooldown_seconds", self.rule_cooldown_seconds)),
                }
            except Exception as e:
                print(f"⚠️ Rule Error ({rule_name}): {e}")

        print(f"✅ Config-Driven SIEM Loaded: {len(self.rules)} Regex Rules, {len(self.event_id_rules)} Event ID Rules.")

    def analyze_single_log(self, log_entry: dict):
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
        if event_id in self.event_id_rules:
            rule = self.event_id_rules[event_id]
            findings.append(self._create_alert(
                rule.get("type", "ANOMALY"), 
                rule.get("severity", "MEDIUM"), 
                rule.get("summary", f"Suspicious Event ID {event_id} detected"), 
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

            now = time.time()
            cooldown_key = f"{name}:{ip}:{event_type}"
            last_fired = self._last_rule_fires.get(cooldown_key, 0.0)
            if now - last_fired < rule.get("cooldown_seconds", self.rule_cooldown_seconds):
                continue

            if rule["pattern"].search(msg):
                # ✅ ZERO HARDCODING: Uses config summary or an extremely dumb fallback
                summary = rule["summary"] if rule["summary"] else self._fallback_summary(name)
                findings.append(self._create_alert(name, rule["severity"], summary, log_entry, rule["mitre"]))
                self._last_rule_fires[cooldown_key] = now
        
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
        return {
            "id": uuid.uuid4().hex[:12],
            "type": type_str,
            "severity": sev,
            "summary": summary,
            "ip": row.get("source_ip", row.get("ip", "N/A")),
            "user": row.get("user", "N/A"),
            "mitre": mitre,
            "timestamp": row.get("timestamp", datetime.now(timezone.utc).isoformat()),
            "engine_source": row.get("engine_source", "Stateless")
        }