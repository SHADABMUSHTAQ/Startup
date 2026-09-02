import math
import logging
import asyncio
import hashlib
import ipaddress
import json
import os
import re
import uuid
import time
from urllib.parse import unquote_plus, urlparse
from datetime import datetime, timedelta, timezone
import redis.asyncio as aioredis
from app.utils.siem_catalog import SIEM_RULES

corr_logger = logging.getLogger("SIEM-Correlation")




class SIEMEngine:
    def __init__(self, config: dict = None):
        self.redis = None  # Will be set via set_redis_client()
        self.refresh_config(config)

    def refresh_config(self, config: dict = None):
        """
         RE-ENTRY MANDATE: Re-initializes all rules, patterns, and threat intel sets.
        Fixes BUG-23 (Ghost Reloading) by ensuring regex is re-compiled on config change.
        """
        self.config = config or SIEM_RULES
        self._initialize_from_config()
        print(f" SIEM Engine Hot-Reloaded: {len(self.rules)} Regex Rules, {len(self.event_id_rules)} Event ID Rules.")

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

        # 4. Event ID Mapping
        raw_event_id_rules = self.config.get("event_id_map", {}) or self.config.get("detection", {}).get("event_id_rules", {})
        self.event_id_rules = {str(key): value for key, value in raw_event_id_rules.items()}

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
        self.phishing_delivery_event_types = {
            str(value).strip().lower()
            for value in phishing_cfg.get(
                "delivery_event_types",
                [
                    "email",
                    "email_gateway",
                    "email_message",
                    "browser_download",
                    "url_click",
                    "web_proxy",
                    "http_request",
                ],
            )
            if str(value).strip()
        }
        
        self._url_pattern = re.compile(r"https?://[^\s'\"]+", flags=re.IGNORECASE)
        self._email_pattern = re.compile(r"\b[a-zA-Z0-9._%+-]+@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\b")
        self._ip_url_pattern = re.compile(r"https?://(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?(?:/|$)", flags=re.IGNORECASE)
        
        # 6. Regex Detection Rules (Compiled for Performance)
        self.rules = {}
        rules_data = self.config.get("detection", {}).get("rules", {})
        for rule_name, rule_meta in rules_data.items():
            if not rule_meta.get("enabled", True):
                continue
            try:
                self.rules[rule_name] = {
                    "pattern": re.compile(rule_meta["regex"]),
                    "severity": rule_meta.get("sev", "MEDIUM"),
                    "mitre": rule_meta.get("mitre", "N/A"),
                    "summary": rule_meta.get("summary", ""),
                    "requires_context": {str(ctx).lower() for ctx in rule_meta.get("requires_context", [])},
                    "must_include_any": [s.lower() for s in rule_meta.get("must_include_any", [])],
                    "min_message_length": int(rule_meta.get("min_message_length", self.default_min_message_length)),
                    "cooldown_seconds": int(rule_meta.get("cooldown_seconds", self.rule_cooldown_seconds)),
                }
            except Exception as e:
                print(f" Rule Error ({rule_name}): {e}")

    def set_redis_client(self, redis_client):
        """Inject Redis client for persistent cooldown tracking across worker restarts."""
        self.redis = redis_client

    @staticmethod
    def _cooldown_fingerprint(message: str) -> str:
        normalized = " ".join(str(message or "").lower().split())
        return hashlib.sha256(normalized.encode("utf-8")).hexdigest()[:16]

    async def analyze_single_log(self, log_entry: dict):
        findings = []
        
        ip = log_entry.get("source_ip", log_entry.get("ip", "0.0.0.0"))
        user = log_entry.get("user", "unknown")
        msg = log_entry.get("message", "")
        msg_lower = msg.lower()
        event_type = str(log_entry.get("event_type", "unknown")).lower()
        
        event_id = str(log_entry.get("event_id", ""))
        raw_data = log_entry.get("raw_data") if isinstance(log_entry.get("raw_data"), dict) else {}
        # Web rules may only inspect records produced by the reviewed web-log
        # collector. A caller-provided event_type alone is not trusted context.
        trusted_web_origin = bool(raw_data.get("web_log_file"))

        # Tenant-aware SOAR whitelist: check per-tenant whitelist in Redis (if available)
        tenant_id = log_entry.get("tenant_id")
        if tenant_id and self.redis:
            try:
                is_protected = await self.redis.sismember(f"warsoc:soar_whitelist:{tenant_id}", ip)
                if is_protected:
                    return []
            except Exception as e:
                corr_logger.error(f"SOAR whitelist redis check failed for tenant {tenant_id}: {e}")

        if user in self.whitelist_users or ip in self.whitelist_ips:
            return []

        # THREAT INTEL: 30-Day TTL Stateful Check
        if self.redis and ip and ip not in {"0.0.0.0", "127.0.0.1", "::1"}:
            try:
                is_malicious = await self.redis.exists(f"threat_intel:ip:{ip}")
                if is_malicious:
                    findings.append(self._create_alert(
                        "KNOWN_MALICIOUS_IP",
                        "CRITICAL",
                        f"Communication with known malicious IP detected: {ip}",
                        log_entry,
                        "T1071" # Standard C2/Malicious connection
                    ))
                    # We don't return early; we want to capture other alerts for this IP too
            except Exception as e:
                corr_logger.error(f"Threat Intel redis check failed for {ip}: {e}")

        # ---------------------------------------------------------
        # WINDOWS EVENT ID ENGINE
        # ---------------------------------------------------------
        if (
            event_id
            and event_id in self.event_id_rules
            and not log_entry.get("_direct_event_rule_alerted")
        ):
            rule = self.event_id_rules[event_id]
            if rule.get("alert_on_event", True):
                findings.append(self._create_alert(
                    f"EVENT_ID_{event_id}_{rule.get('event_type', 'ANOMALY').upper()}",
                    rule.get("severity", "MEDIUM"),
                    f"{rule.get('event_type', 'suspicious event').replace('_', ' ').title()} detected",
                    log_entry,
                    rule.get("mitre", "N/A")
                ))

        # REGEX ENGINE
        
        if self.global_suppress_tokens and any(token in msg_lower for token in self.global_suppress_tokens):
            return findings

        elevated_powershell_alert = self._detect_elevated_powershell(log_entry, event_id)
        if elevated_powershell_alert:
            findings.append(elevated_powershell_alert)

        phishing_alert = self._detect_phishing(
            log_entry,
            msg_lower,
            event_type,
            trusted_web_origin=trusted_web_origin,
        )
        if phishing_alert:
            findings.append(phishing_alert)

        for name, rule in self.rules.items():
            if len(findings) >= self.max_alerts_per_log:
                break

            required_context = rule.get("requires_context", set())
            if required_context and event_type not in required_context:
                continue
            if event_type in {"http_request", "http_404", "http_500"} and not trusted_web_origin:
                continue

            if len(msg) < rule.get("min_message_length", self.default_min_message_length):
                continue

            token_hints = rule.get("must_include_any", [])
            if token_hints and not any(token in msg_lower for token in token_hints):
                continue

            #  REDIS COOLDOWN: Persistent across worker restarts
            cooldown_seconds = rule.get("cooldown_seconds", self.rule_cooldown_seconds)
            message_fingerprint = self._cooldown_fingerprint(msg)
            cooldown_key = f"warsoc:siem_cooldown:{name}:{ip}:{event_type}:{message_fingerprint}"

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
                #  ZERO HARDCODING: Uses config summary or an extremely dumb fallback
                summary = rule["summary"] if rule["summary"] else self._fallback_summary(name)
                findings.append(self._create_alert(name, rule["severity"], summary, log_entry, rule["mitre"]))

                # Set Redis cooldown key with expiration
                if self.redis:
                    try:
                        await self.redis.set(cooldown_key, "1", ex=cooldown_seconds)
                    except Exception:
                        # Silently fail if Redis is down, alert still fires
                        pass

        return findings

    def _detect_phishing(
        self,
        log_entry: dict,
        msg_lower: str,
        event_type: str,
        *,
        trusted_web_origin: bool = False,
    ):
        if not self.phishing_enabled:
            return None
        if event_type not in self.phishing_delivery_event_types:
            return None
        if event_type in {"http_request", "http_404", "http_500"} and not trusted_web_origin:
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

        raw_data = log_entry.get("raw_data")
        raw_dict = raw_data if isinstance(raw_data, dict) else {}
        file_path = str(log_entry.get("file_path") or raw_dict.get("file_path") or "").lower()
        for ext in self.phishing_risky_attachments:
            if ext and (ext in file_path or ext in msg_lower):
                signals.append("risky_attachment")
                score += int(self.phishing_weights.get("risky_attachment", 30))
                break

        if event_type in {"process_create", "process_creation", "unknown"} and self.phishing_lolbins:
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

    def _detect_elevated_powershell(self, log_entry: dict, event_id: str):
        native_cfg = self.config.get("detection", {}).get("native_windows_detection", {})
        cfg = native_cfg.get("elevated_powershell", {})
        if not cfg.get("enabled", False) or event_id != "4688":
            return None

        processed = log_entry.get("processed_data") if isinstance(log_entry.get("processed_data"), dict) else {}
        raw_data = log_entry.get("raw_data") if isinstance(log_entry.get("raw_data"), dict) else {}
        process_name = str(
            processed.get("new_process_name")
            or raw_data.get("NewProcessName")
            or raw_data.get("new_process_name")
            or ""
        ).strip().lower()
        if not re.search(r"(?:^|[\\/])(powershell|pwsh)(?:\.exe)?$", process_name):
            return None

        token_elevation = str(
            processed.get("token_elevation_type")
            or raw_data.get("TokenElevationType")
            or raw_data.get("token_elevation_type")
            or ""
        ).strip().lower()
        full_token_values = {
            str(value).strip().lower()
            for value in cfg.get("full_token_values", [])
            if str(value).strip()
        }
        if token_elevation not in full_token_values:
            return None

        return self._create_alert(
            "WINDOWS_ELEVATED_POWERSHELL",
            cfg.get("severity", "MEDIUM"),
            "Elevated PowerShell launched",
            log_entry,
            cfg.get("mitre_id", "T1059.001"),
        )

    def _fallback_summary(self, rule_name: str) -> str:
        #  FIX: Dumb generic string format, no custom dict mapping
        readable = str(rule_name or "suspicious").replace("_", " ").strip().lower()
        return f"Potential {readable} activity detected"

    def _create_alert(self, type_str, sev, summary, row, mitre):
        event_id_value = row.get("event_id", "")
        event_id_str = "" if event_id_value is None else str(event_id_value).strip()
        normalized_event_id = event_id_str

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


# ============================================================
# CORRELATION ENGINE — Stateful Redis-backed multi-event rules
# ============================================================

class CorrelationEngine:
    """
    Three production-grade stateful attack correlations:
      1. Low-and-Slow Password Spray  (T1110.003)
      2. Impossible Travel             (T1078)
      3. Ghost Admin Sequence          (T1548 + T1070)
    """

    SPRAY_WINDOW      = 300    # 5-minute detection window
    SPRAY_THRESHOLD   = 5      # distinct usernames from one IP
    TRAVEL_WINDOW     = 3600   # 1 hour look-back for previous login
    TRAVEL_SPEED_KMH  = 1000   # km/h — faster than any commercial aircraft
    GHOST_WINDOW      = 300    # 5-minute sequence window for 4732 -> 1102

    def __init__(self, redis_client, config: dict = None):
        self.redis = redis_client
        self.refresh_config(config)

    def refresh_config(self, config: dict | None = None):
        self.config = SIEM_RULES if config is None else config
        self.stateful_rules = self.config.get("stateful_detection_rules", {})
        # Map of builtin handler tokens -> callables. Allows config to refer to
        # handlers using `handler` or `type` without relying on rule names.
        self.builtin_handlers = {
            "impossible_travel": self.check_impossible_travel,
            "ghost_admin_sequence": self.check_ghost_admin,
            "ghost_admin": self.check_ghost_admin,
            "password_spray": self.check_password_spray,
            "password-spray": self.check_password_spray,
            "spray": self.check_password_spray,
            "smb_lateral_movement": self.check_smb_lateral_movement,
            "smb_lateral": self.check_smb_lateral_movement,
            "smb_enumeration": self.check_smb_enumeration,
            "smb-enumeration": self.check_smb_enumeration,
            "registry_persistence": self.check_registry_persistence,
            "phishing_kill_chain": self.check_phishing_kill_chain,
            "after_hours_activity": self.check_after_hours_activity,
            "dormant_account_activation": self.check_dormant_account_activation,
        }

    @staticmethod
    def _normalize_token(value: str | None) -> str:
        return str(value or "").strip().lower().replace(" ", "_")

    def _event_filter_matches(self, event_filter: str | None, event_id: str, event_type: str) -> bool:
        if not event_filter:
            return True

        filter_token = self._normalize_token(event_filter)
        if filter_token == "all":
            return True
        event_type_token = self._normalize_token(event_type)
        if event_type_token and event_type_token == filter_token:
            return True

        # Use SSOT event_id_map to prevent logic drift
        ssot_map = getattr(self, "config", {}).get("event_id_map", {})
        if event_id in ssot_map:
            mapped_type = self._normalize_token(ssot_map[event_id].get("event_type"))
            if mapped_type == filter_token:
                return True
                
        # Handle synonym groups commonly used in stateful rules
        synonyms = {
            "failed_login": {"failed_login", "ntlm_authentication"},
            "file_modify": {"object_access", "file_modify", "file_write"},
            "file_delete": {"object_deleted", "file_delete"},
            "file_access": {"object_access", "file_access", "file_read", "file_write"},
            "network_connect": {"network_connect", "network_connection", "firewall_block"},
        }
        
        for key, aliases in synonyms.items():
            if filter_token in aliases:
                if event_type_token in aliases:
                    return True
                if event_id in ssot_map and self._normalize_token(ssot_map[event_id].get("event_type")) in aliases:
                    return True

        return False

    def _dynamic_rule_payload_matches(
        self,
        rule_name: str,
        rule: dict,
        log_entry: dict | None,
    ) -> bool:
        """Apply content predicates declared by a dynamic rule before counting it."""
        if not isinstance(log_entry, dict):
            return not any(
                rule.get(field)
                for field in (
                    "ransomware_extensions",
                    "sensitive_keywords",
                    "keywords",
                    "sql_patterns",
                    "xss_patterns",
                    "target_path_prefix",
                    "logon_types",
                )
            )

        searchable_fields = (
            "file_path",
            "object_name",
            "target_filename",
            "path",
            "message",
            "command_line",
            "process_command_line",
        )
        searchable_values = [
            str(self._extract_field(log_entry, field) or "").strip().lower()
            for field in searchable_fields
        ]
        searchable_text = unquote_plus(" ".join(value for value in searchable_values if value))

        allowed_logon_types = {
            str(logon_type).strip()
            for logon_type in rule.get("logon_types", [])
            if str(logon_type).strip()
        }
        if allowed_logon_types:
            actual_logon_type = str(self._extract_field(log_entry, "logon_type") or "").strip()
            if actual_logon_type not in allowed_logon_types:
                return False

        sql_patterns = {
            str(pattern).strip().lower()
            for pattern in rule.get("sql_patterns", [])
            if len(str(pattern).strip()) > 1
        }
        if sql_patterns:
            structural_sql = (
                re.search(r"\bunion(?:\s+all)?\s+select\b", searchable_text)
                or re.search(r"\bselect\b.{0,80}\bfrom\b", searchable_text)
                or re.search(r"\binsert\b.{0,80}\binto\b", searchable_text)
                or re.search(r"\bdelete\b.{0,80}\bfrom\b", searchable_text)
                or re.search(r"\bdrop\b.{0,40}\b(?:table|database)\b", searchable_text)
                or re.search(r"(?:'|\")\s*(?:or|and)\s+[^\s]+\s*=\s*[^\s]+", searchable_text)
                or "information_schema" in searchable_text
                or "benchmark(" in searchable_text
                or "sleep(" in searchable_text
            )
            matched_tokens = sum(pattern in searchable_text for pattern in sql_patterns)
            if not structural_sql and matched_tokens < 2:
                return False

        xss_patterns = {
            str(pattern).strip().lower()
            for pattern in rule.get("xss_patterns", [])
            if str(pattern).strip()
        }
        if xss_patterns and not any(pattern in searchable_text for pattern in xss_patterns):
            return False

        target_path_prefix = str(rule.get("target_path_prefix") or "").strip().lower()
        if target_path_prefix and target_path_prefix not in searchable_text:
            return False

        configured_extensions = {
            str(extension).strip().lower()
            for extension in rule.get("ransomware_extensions", [])
            if str(extension).strip()
        }
        if configured_extensions:
            file_candidates = searchable_values[:4]
            return any(
                candidate.endswith(extension)
                for candidate in file_candidates
                for extension in configured_extensions
                if candidate
            )

        sensitive_keywords = {
            str(keyword).strip().lower()
            for keyword in rule.get("sensitive_keywords", [])
            if str(keyword).strip()
        }
        if sensitive_keywords and not any(keyword in searchable_text for keyword in sensitive_keywords):
            return False

        required_keywords = {
            str(keyword).strip().lower()
            for keyword in rule.get("keywords", [])
            if str(keyword).strip()
        }
        if required_keywords and not any(keyword in searchable_text for keyword in required_keywords):
            return False

        return True

    @classmethod
    def _builtin_handler_relevant(
        cls,
        handler_token: str,
        event_id: str,
        event_type: str,
        log_entry: dict | None,
    ) -> bool:
        token = cls._normalize_token(handler_token)
        event_id = str(event_id or "").strip()
        event_type = cls._normalize_token(event_type)
        message = str((log_entry or {}).get("message") or "").lower()

        if token in ("password_spray", "password-spraying", "spray", "password-spray"):
            return event_id in {"4625", "4776"} or event_type in {"failed_login", "ntlm_authentication"}

        if token in ("impossible_travel", "after_hours_activity", "dormant_account_activation"):
            return event_id == "4624" or event_type == "successful_login"

        if token in ("ghost_admin_sequence", "ghost_admin"):
            return event_id in {"4732", "1102"} or event_type in {"group_membership_change", "log_cleared"}

        if token in ("smb_lateral_movement", "smb_lateral"):
            return event_id in {"4648", "4769"}

        if token in ("smb_enumeration", "smb-enumeration"):
            return event_id == "5140" or event_type == "network_share_accessed"

        if token in ("registry_persistence",):
            return event_id == "4657" or event_type == "registry_modified"

        if token in ("phishing_kill_chain",):
            if not message:
                return False
            quick_tokens = (
                "http://",
                "https://",
                "verify your account",
                "invoice attached",
                "urgent payment",
                "cmd.exe",
                "powershell.exe",
                "wscript.exe",
                "cscript.exe",
                "mshta.exe",
            )
            return any(marker in message for marker in quick_tokens)

        return True

    @staticmethod
    def _extract_field(log_entry: dict | None, field_name: str | None):
        if not field_name or not isinstance(log_entry, dict):
            return None

        normalized = str(field_name).strip().lower()
        processed = log_entry.get("processed_data") if isinstance(log_entry.get("processed_data"), dict) else {}
        raw_event = log_entry.get("raw_event_data") if isinstance(log_entry.get("raw_event_data"), dict) else {}
        raw_system = raw_event.get("system") if isinstance(raw_event.get("system"), dict) else {}
        raw_data = log_entry.get("raw_data") if isinstance(log_entry.get("raw_data"), dict) else {}

        candidate_groups = {
            "username": [log_entry.get("username"), log_entry.get("user"), processed.get("username"), processed.get("user"), raw_event.get("username"), raw_event.get("user"), raw_data.get("username"), raw_data.get("user")],
            "user": [log_entry.get("user"), log_entry.get("username"), processed.get("user"), processed.get("username"), raw_event.get("user"), raw_event.get("username"), raw_data.get("user"), raw_data.get("username")],
            "source_ip": [log_entry.get("source_ip"), log_entry.get("ip"), processed.get("source_network_address"), processed.get("source_ip"), raw_event.get("source_ip"), raw_event.get("ip"), raw_data.get("source_ip"), raw_data.get("ip")],
            "src_ip": [log_entry.get("source_ip"), log_entry.get("ip"), processed.get("source_network_address"), processed.get("source_ip"), raw_event.get("source_ip"), raw_event.get("ip"), raw_data.get("source_ip"), raw_data.get("ip")],
            "destination_ip": [log_entry.get("destination_ip"), log_entry.get("dst_ip"), log_entry.get("destination_address"), processed.get("destination_ip"), processed.get("dst_ip"), processed.get("destination_address"), raw_event.get("destination_ip"), raw_event.get("dst_ip"), raw_event.get("destination_address"), raw_data.get("destination_ip"), raw_data.get("dst_ip"), raw_data.get("destination_address")],
            "dest_ip": [log_entry.get("destination_ip"), log_entry.get("dst_ip"), log_entry.get("destination_address"), processed.get("destination_ip"), processed.get("dst_ip"), processed.get("destination_address"), raw_event.get("destination_ip"), raw_event.get("dst_ip"), raw_event.get("destination_address"), raw_data.get("destination_ip"), raw_data.get("dst_ip"), raw_data.get("destination_address")],
            "destination_port": [log_entry.get("destination_port"), log_entry.get("dst_port"), processed.get("destination_port"), processed.get("dst_port"), raw_event.get("destination_port"), raw_event.get("dst_port"), raw_data.get("destination_port"), raw_data.get("dst_port")],
            "dest_port": [log_entry.get("destination_port"), log_entry.get("dst_port"), processed.get("destination_port"), processed.get("dst_port"), raw_event.get("destination_port"), raw_event.get("dst_port"), raw_data.get("destination_port"), raw_data.get("dst_port")],
            "timestamp": [log_entry.get("timestamp"), log_entry.get("ingested_at")],
            "event_type": [log_entry.get("event_type"), log_entry.get("event_id_meaning")],
            "agent_id": [log_entry.get("agent_id"), processed.get("agent_id"), raw_event.get("agent_id"), raw_data.get("agent_id")],
            "computer": [log_entry.get("computer"), processed.get("computer"), raw_system.get("computer"), raw_event.get("computer"), raw_data.get("computer")],
        }

        candidates = candidate_groups.get(normalized, [log_entry.get(field_name), processed.get(field_name), raw_event.get(field_name), raw_data.get(field_name)])
        for candidate in candidates:
            if candidate is None:
                continue
            text = str(candidate).strip()
            if text:
                return text
        return None

    @staticmethod
    def _is_after_hours(timestamp_iso: str, start_hour: int, end_hour: int) -> bool:
        try:
            parsed = datetime.fromisoformat(str(timestamp_iso or "").replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            hour = parsed.astimezone(timezone.utc).hour
        except Exception:
            hour = datetime.now(timezone.utc).hour

        start_hour = int(start_hour)
        end_hour = int(end_hour)
        if start_hour == end_hour:
            return True
        if start_hour < end_hour:
            return start_hour <= hour < end_hour
        return hour >= start_hour or hour < end_hour

    # ----------------------------------------------------------
    # HELPER: haversine distance between two (lat, lon) pairs
    # ----------------------------------------------------------
    @staticmethod
    def _haversine_km(lat1, lon1, lat2, lon2) -> float:
        R = 6371.0
        phi1, phi2 = math.radians(lat1), math.radians(lat2)
        dphi = math.radians(lat2 - lat1)
        dlam = math.radians(lon2 - lon1)
        a = math.sin(dphi / 2) ** 2 + math.cos(phi1) * math.cos(phi2) * math.sin(dlam / 2) ** 2
        return 2 * R * math.asin(math.sqrt(a))

    # ----------------------------------------------------------
    # HELPER: build a structured alert matching siem_worker schema
    # ----------------------------------------------------------
    @staticmethod
    def _alert(alert_type: str, severity: str, summary: str, tenant_id: str,
                source_ip: str, user: str, event_id: int, mitre: str, extra: dict = None) -> dict:
        payload = {
            "id":              uuid.uuid4().hex[:12],
            "tenant_id":       tenant_id,
            "type":            alert_type,
            "severity":        severity,
            "summary":         summary,
            "event_id":        event_id,
            "event_id_meaning": "",
            "source_ip":       source_ip,
            "message":         summary,
            "raw_message":     summary,
            "ip":              source_ip,
            "user":            user,
            "mitre":           mitre,
            "timestamp":       datetime.now(timezone.utc).isoformat(),
            "engine_source":   "CorrelationEngine",
            "_expire_at":      datetime.now(timezone.utc) + timedelta(days=7),
        }
        if extra:
            payload.update(extra)
        return payload

    @staticmethod
    def _is_bannable_ip(source_ip: str) -> bool:
        candidate = str(source_ip or "").strip()
        if not candidate or candidate.lower() in {"unknown", "none", "null", "-", "0.0.0.0", "::", "::1", "127.0.0.1"}:
            return False
        try:
            ip = ipaddress.ip_address(candidate)
        except ValueError:
            return False
        return not (ip.is_loopback or ip.is_unspecified or ip.is_multicast)

    @staticmethod
    def _source_ip_has_remote_evidence(log_entry: dict | None, source_ip: str) -> bool:
        if not isinstance(log_entry, dict) or not source_ip:
            return False

        processed = log_entry.get("processed_data") if isinstance(log_entry.get("processed_data"), dict) else {}
        raw_data = log_entry.get("raw_data") if isinstance(log_entry.get("raw_data"), dict) else {}
        raw_processed = raw_data.get("processed_data") if isinstance(raw_data.get("processed_data"), dict) else {}
        raw_event = log_entry.get("raw_event_data") if isinstance(log_entry.get("raw_event_data"), dict) else {}

        evidence_candidates = [
            processed.get("source_network_address"),
            raw_processed.get("source_network_address"),
            raw_event.get("source_network_address"),
        ]
        normalized_source = str(source_ip).strip()
        return any(str(candidate or "").strip() == normalized_source for candidate in evidence_candidates)

    @staticmethod
    def _hybrid_ip(value: object, *, require_public: bool = False) -> str | None:
        candidate = str(value or "").strip()
        try:
            parsed = ipaddress.ip_address(candidate)
        except ValueError:
            return None
        if parsed.is_loopback or parsed.is_unspecified or parsed.is_multicast:
            return None
        if require_public and not parsed.is_global:
            return None
        return str(parsed)

    @staticmethod
    def _hybrid_identity(value: object) -> str | None:
        identity = str(value or "").strip().lower()
        if identity in {"", "-", "*", "unknown", "network_device", "none", "null"}:
            return None
        return identity

    @staticmethod
    def _hybrid_key_token(value: str) -> str:
        return hashlib.sha256(str(value).encode("utf-8")).hexdigest()[:32]

    @staticmethod
    def _hybrid_event_epoch(value: object, *, fallback: int | None = None) -> int:
        try:
            if isinstance(value, datetime):
                parsed = value
            else:
                parsed = datetime.fromisoformat(str(value or "").replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return int(parsed.astimezone(timezone.utc).timestamp())
        except (TypeError, ValueError, OverflowError):
            return int(fallback if fallback is not None else datetime.now(timezone.utc).timestamp())

    @staticmethod
    def _verified_relay_event(log_entry: dict | None) -> bool:
        return bool(
            isinstance(log_entry, dict)
            and log_entry.get("telemetry_family") == "network"
            and log_entry.get("source_type") == "network_device"
            and log_entry.get("source_assurance") == "relay_attested"
            and log_entry.get("signature_verified") is True
        )

    async def check_hybrid_network_correlations(
        self,
        tenant_id: str,
        source_ip: str,
        user: str,
        event_id: str,
        event_type: str,
        timestamp_iso: str,
        log_entry: dict | None,
    ) -> list[dict]:
        """Correlate only verified relay metadata with native Windows evidence.

        A successful VPN-to-Windows sequence is attached as evidence context and
        does not become a threat by itself. Alerts require either a real
        multi-user VPN rejection pattern or a high-risk host event followed by
        a permitted public-network connection from the same endpoint address.
        """
        if not self.redis or not isinstance(log_entry, dict):
            return []
        if os.getenv("NETWORK_RELAY_ENABLED", "false").strip().lower() not in {
            "1",
            "true",
            "yes",
        }:
            return []
        config = self.config.get("hybrid_network_correlation", {}) or {}
        if not config.get("enabled", False):
            return []

        family = str(log_entry.get("telemetry_family") or "").strip().lower()
        event_id = str(event_id or "").strip()
        event_type = self._normalize_token(event_type)
        processed = (
            log_entry.get("processed_data")
            if isinstance(log_entry.get("processed_data"), dict)
            else {}
        )
        processing_epoch = int(datetime.now(timezone.utc).timestamp())
        event_epoch = self._hybrid_event_epoch(timestamp_iso, fallback=processing_epoch)
        triggered: list[dict] = []

        if self._verified_relay_event(log_entry):
            clock_confidence = str(log_entry.get("time_confidence") or "unknown").lower()
            correlation_confidence = (
                "high" if clock_confidence in {"high", "medium"} else "medium"
            )
            action = self._normalize_token(processed.get("action"))
            remote_ip = self._hybrid_ip(processed.get("src_ip"))
            identity = self._hybrid_identity(processed.get("user") or user)

            spray = config.get("vpn_password_spray", {}) or {}
            if (
                event_type == "vpn_authentication"
                and action == "rejected"
                and remote_ip
                and identity
            ):
                window = max(60, int(spray.get("window_seconds", 300)))
                threshold = max(2, int(spray.get("threshold_users", 5)))
                source_token = self._hybrid_key_token(remote_ip)
                spray_key = f"warsoc:hybrid:vpn_spray:{tenant_id}:{source_token}"
                try:
                    unique_count = int(
                        await self.redis.eval(
                            "redis.call('ZADD',KEYS[1],ARGV[1],ARGV[2]); "
                            "redis.call('ZREMRANGEBYSCORE',KEYS[1],'-inf',ARGV[3]); "
                            "redis.call('EXPIRE',KEYS[1],ARGV[4]); "
                            "return redis.call('ZCARD',KEYS[1])",
                            1,
                            spray_key,
                            event_epoch,
                            identity,
                            event_epoch - window,
                            window,
                        )
                    )
                except Exception as exc:
                    corr_logger.warning(f"[CORR][HYBRID][VPN-SPRAY] Redis error: {exc}")
                    unique_count = 0
                if unique_count >= threshold:
                    bucket = event_epoch // window
                    event_uid = (
                        "hybrid-vpn-spray-"
                        + self._hybrid_key_token(f"{tenant_id}:{remote_ip}:{bucket}")
                    )
                    triggered.append(
                        self._alert(
                            alert_type="HYBRID_VPN_PASSWORD_SPRAY",
                            severity=str(spray.get("severity") or "HIGH").upper(),
                            summary=(
                                f"VPN password spray observed: {remote_ip} targeted "
                                f"{unique_count} distinct accounts within {window // 60} minutes."
                            ),
                            tenant_id=tenant_id,
                            source_ip=remote_ip,
                            user=identity,
                            event_id=event_id,
                            mitre="T1110.003",
                            extra={
                                "event_uid": event_uid,
                                "unique_targets": unique_count,
                                "window_seconds": window,
                                "source_assurance": "relay_attested",
                                "confidence": correlation_confidence,
                                "clock_confidence": clock_confidence,
                                "compliance_context": ["peca_oriented"],
                                "recommended_action": (
                                    "Review the VPN device and source before using the guarded Block action."
                                ),
                            },
                        )
                    )

            vpn_logon = config.get("vpn_to_windows_logon", {}) or {}
            if (
                event_type == "vpn_authentication"
                and action == "successful"
                and remote_ip
                and identity
            ):
                window = max(60, int(vpn_logon.get("window_seconds", 600)))
                identity_token = self._hybrid_key_token(identity)
                marker = {
                    "remote_ip": remote_ip,
                    "user": identity,
                    "event_uid": log_entry.get("event_uid"),
                    "network_device_id": log_entry.get("network_device_id"),
                    "timestamp": timestamp_iso,
                    "event_epoch": event_epoch,
                }
                try:
                    await self.redis.set(
                        f"warsoc:hybrid:vpn_success:{tenant_id}:{identity_token}",
                        json.dumps(marker, separators=(",", ":"), default=str),
                        ex=window,
                    )
                except Exception as exc:
                    corr_logger.warning(f"[CORR][HYBRID][VPN-LOGON] Redis error: {exc}")

            host_network = config.get("high_risk_host_to_public_network", {}) or {}
            if event_type == "network_connection_permitted" and remote_ip:
                destination_ip = self._hybrid_ip(
                    processed.get("dst_ip"), require_public=True
                )
                if destination_ip:
                    window = max(60, int(host_network.get("window_seconds", 300)))
                    source_token = self._hybrid_key_token(remote_ip)
                    for host_event_id, rule in (host_network.get("events", {}) or {}).items():
                        marker_key = (
                            f"warsoc:hybrid:host_marker:{tenant_id}:"
                            f"{source_token}:{host_event_id}"
                        )
                        try:
                            raw_marker = await self.redis.get(marker_key)
                            if not raw_marker:
                                continue
                            marker = json.loads(raw_marker)
                            marker_epoch = self._hybrid_event_epoch(
                                marker.get("timestamp"), fallback=event_epoch
                            )
                            if not 0 <= event_epoch - marker_epoch <= window:
                                continue
                        except Exception as exc:
                            corr_logger.warning(
                                f"[CORR][HYBRID][HOST-NETWORK] Marker read error: {exc}"
                            )
                            continue
                        marker_uid = str(marker.get("event_uid") or marker_key)
                        kind = str(rule.get("kind") or "high_risk_host_event")
                        triggered.append(
                            self._alert(
                                alert_type=f"HYBRID_{kind.upper()}_TO_PUBLIC_NETWORK",
                                severity=str(rule.get("severity") or "HIGH").upper(),
                                summary=(
                                    f"{kind.replace('_', ' ').title()} was followed by a permitted "
                                    f"connection from {remote_ip} to {destination_ip} within "
                                    f"{window // 60} minutes."
                                ),
                                tenant_id=tenant_id,
                                source_ip=remote_ip,
                                user=str(marker.get("user") or user or "unknown"),
                                event_id=event_id,
                                mitre="T1071",
                                extra={
                                    "event_uid": (
                                        "hybrid-host-network-"
                                        + self._hybrid_key_token(
                                            f"{tenant_id}:{marker_uid}:{kind}"
                                        )
                                    ),
                                    "host_event_id": str(host_event_id),
                                    "host_event_uid": marker.get("event_uid"),
                                    "network_event_uid": log_entry.get("event_uid"),
                                    "agent_id": marker.get("agent_id"),
                                    "computer": marker.get("computer"),
                                    "destination_ip": destination_ip,
                                    "destination_port": processed.get("dst_port"),
                                    "source_assurance": "relay_attested",
                                    "confidence": correlation_confidence,
                                    "clock_confidence": clock_confidence,
                                    "compliance_context": ["peca_oriented"],
                                    "recommended_action": (
                                        "Validate the host change and destination before containment."
                                    ),
                                },
                            )
                        )
            return triggered

        if family != "windows":
            return []

        vpn_logon = config.get("vpn_to_windows_logon", {}) or {}
        if event_id == "4624":
            window = max(60, int(vpn_logon.get("window_seconds", 600)))
            identity = self._hybrid_identity(processed.get("user") or user)
            logon_type = str(processed.get("logon_type") or "").strip()
            allowed_types = {
                str(value) for value in vpn_logon.get("allowed_logon_types", ["3", "10"])
            }
            endpoint_source = self._hybrid_ip(
                processed.get("source_network_address") or source_ip
            )
            if identity and endpoint_source and logon_type in allowed_types:
                identity_token = self._hybrid_key_token(identity)
                try:
                    raw_marker = await self.redis.get(
                        f"warsoc:hybrid:vpn_success:{tenant_id}:{identity_token}"
                    )
                    marker = json.loads(raw_marker) if raw_marker else None
                except Exception as exc:
                    corr_logger.warning(f"[CORR][HYBRID][VPN-LOGON] Marker read error: {exc}")
                    marker = None
                if marker and marker.get("remote_ip") == endpoint_source:
                    marker_epoch = self._hybrid_event_epoch(
                        marker.get("timestamp"), fallback=event_epoch
                    )
                    if 0 <= event_epoch - marker_epoch <= window:
                        log_entry.setdefault("hybrid_correlations", []).append(
                            {
                                "type": "vpn_to_windows_logon",
                                "outcome": "observed",
                                "source_assurance": "relay_attested",
                                "vpn_event_uid": marker.get("event_uid"),
                                "network_device_id": marker.get("network_device_id"),
                                "remote_ip": endpoint_source,
                            }
                        )

        host_network = config.get("high_risk_host_to_public_network", {}) or {}
        host_rule = (host_network.get("events", {}) or {}).get(event_id)
        endpoint_ip = self._hybrid_ip(source_ip)
        if host_rule and endpoint_ip:
            window = max(60, int(host_network.get("window_seconds", 300)))
            source_token = self._hybrid_key_token(endpoint_ip)
            marker = {
                "event_id": event_id,
                "event_uid": log_entry.get("event_uid"),
                "agent_id": log_entry.get("agent_id"),
                "computer": self._extract_field(log_entry, "computer"),
                "user": user,
                "timestamp": timestamp_iso,
                "event_epoch": event_epoch,
            }
            try:
                await self.redis.set(
                    f"warsoc:hybrid:host_marker:{tenant_id}:{source_token}:{event_id}",
                    json.dumps(marker, separators=(",", ":"), default=str),
                    ex=window,
                )
            except Exception as exc:
                corr_logger.warning(f"[CORR][HYBRID][HOST-NETWORK] Redis error: {exc}")
        return triggered

    # ----------------------------------------------------------
    # HELPER: Automated SOAR Mitigation (Multi-Login Revocation)
    # ----------------------------------------------------------
    async def _trigger_auto_revocation(
        self,
        tenant_id: str,
        source_ip: str,
        *,
        reason: str = "correlation_rule",
        rule_id: str | None = None,
        evidence_ref: str | None = None,
    ) -> bool:
        """Instantly bans the IP at the edge via Windows Agent Firewall Heartbeat."""
        tenant_id = str(tenant_id or "").strip()
        source_ip = str(source_ip or "").strip()
        if not tenant_id:
            corr_logger.warning(f"[SOAR] Auto-Mitigation skipped: missing tenant_id reason={reason}")
            return False
        if not self.redis:
            corr_logger.warning(f"[SOAR] Auto-Mitigation skipped: Redis unavailable tenant={tenant_id} ip={source_ip} reason={reason}")
            return False
        if not self._is_bannable_ip(source_ip):
            corr_logger.warning(f"[SOAR] Auto-Mitigation skipped: non-bannable source tenant={tenant_id} ip={source_ip} reason={reason}")
            return False
        ban_key = f"warsoc:banned_ips:{tenant_id}"
        try:
            if await self.redis.sismember(f"warsoc:soar_whitelist:{tenant_id}", source_ip):
                corr_logger.warning(f"[SOAR] Auto-Mitigation skipped: whitelisted source tenant={tenant_id} ip={source_ip} reason={reason}")
                return False
            await self.redis.sadd(ban_key, source_ip)
        except Exception as e:
            corr_logger.error(f"[SOAR] Auto-Mitigation failed tenant={tenant_id} ip={source_ip} reason={reason}: {e}")
            return False

        corr_logger.critical(
            f"[SOAR] Auto-Mitigation Triggered tenant={tenant_id} ip={source_ip} "
            f"reason={reason} rule_id={rule_id or 'N/A'} evidence_ref={evidence_ref or 'N/A'}"
        )
        return True

    # ==========================================================
    # CORRELATION 1 — Low-and-Slow Password Spray (T1110.003)
    # ==========================================================
    async def check_password_spray(
        self,
        tenant_id: str,
        source_ip: str,
        target_user: str,
        event_id: str,
        threshold: int | None = None,
        window_seconds: int | None = None,
    ) -> dict | None:
        """
        Tracks distinct usernames targeted from one source over a five-minute
        window using a Redis SET with a TTL. Triggers at five distinct users.
        """
        if event_id not in {"4625", "4776"}:
            return None
            
        if not source_ip or not target_user:
            corr_logger.debug(f"[SPRAY] Bailing: missing source_ip({source_ip}) or user({target_user})")
            return None

        spray_window = int(window_seconds or self.SPRAY_WINDOW)
        spray_threshold = int(threshold or self.SPRAY_THRESHOLD)
        spray_key = f"warsoc:corr:spray:{tenant_id}:{source_ip}"
        try:
            pipe = self.redis.pipeline()
            pipe.sadd(spray_key, target_user)
            pipe.expire(spray_key, spray_window)
            pipe.scard(spray_key)
            results = await pipe.execute()
            unique_count = int(results[2])
            
            corr_logger.info(f"[CORR][SPRAY] Tracking: {source_ip} -> {target_user} (Unique targets: {unique_count}/{spray_threshold})")
        except Exception as e:
            corr_logger.warning(f"[CORR][SPRAY] Redis error: {e}")
            return None

        if unique_count >= spray_threshold:
            alert_key = f"warsoc:corr:alerted:spray:{tenant_id}:{source_ip}"
            try:
                first_alert = await self.redis.set(
                    alert_key,
                    "1",
                    nx=True,
                    ex=spray_window,
                )
            except Exception as e:
                corr_logger.warning(f"[CORR][SPRAY] Alert claim failed: {e}")
                return None

            if not first_alert:
                corr_logger.debug(
                    f"[CORR][SPRAY] Suppressed duplicate alert for {source_ip} within active window"
                )
                return None

            corr_logger.critical(f"[CORR][SPRAY] TRIGGERED: {source_ip} sprayed {unique_count} users!")
            return self._alert(
                alert_type="Password spraying attack detected",
                severity="HIGH",
                summary=(
                    f"Password spray detected: {source_ip} targeted "
                    f"{unique_count} unique accounts in {spray_window // 60} minutes."
                ),
                tenant_id=tenant_id,
                source_ip=source_ip,
                user=target_user,
                event_id=int(event_id) if str(event_id).isdigit() else event_id,
                mitre="T1110.003",
                extra={
                    "unique_targets": unique_count,
                    "window_minutes": spray_window // 60,
                    "recommended_action": "Review the source and use the guarded Block action if containment is approved.",
                },
            )
        return None

    # ==========================================================
    # CORRELATION 2 — Impossible Travel (T1078)
    # ==========================================================
    async def check_impossible_travel(
        self,
        tenant_id: str,
        source_ip: str,
        user: str,
        event_id: str,
        lat: float | None,
        lon: float | None,
        timestamp_iso: str,
        window_seconds: int | None = None,
        max_travel_time_hours: float | None = None,
        min_distance_km: float | None = None,
    ) -> dict | None:
        """
        On every 4624 (Successful Logon), stores {lat, lon, ts, ip} in Redis.
        On subsequent logins, computes the haversine distance and required speed.
        If speed > 1000 km/h → CRITICAL credential compromise alert.
        """
        if event_id != "4624":
            return None
            
        if not user or lat is None or lon is None:
            corr_logger.info(f"[CORR][TRAVEL] Bailing: missing user({user}) or geo({lat},{lon})")
            return None

        travel_window = int(window_seconds or self.TRAVEL_WINDOW)
        travel_key = f"warsoc:corr:travel:{tenant_id}:{user}"
        try:
            prev_raw = await self.redis.get(travel_key)

            # Store current login (overwrite after comparison)
            current_data = json.dumps({"lat": lat, "lon": lon, "ip": source_ip, "ts": timestamp_iso})
            await self.redis.set(travel_key, current_data, ex=travel_window)

            if not prev_raw:
                corr_logger.info(f"[CORR][TRAVEL] First login for {user} recorded baseline.")
                return None  # First ever login — no baseline to compare against

            prev = json.loads(prev_raw)
            prev_lat, prev_lon = float(prev["lat"]), float(prev["lon"])
            prev_ts_str  = prev["ts"]
            prev_ip      = prev.get("ip", "unknown")

            # Parse timestamps (Support both Z and +00:00 formats)
            try:
                t_now = timestamp_iso.replace("Z", "+00:00")
                t_prev = prev_ts_str.replace("Z", "+00:00")
                ts_now  = datetime.fromisoformat(t_now)
                ts_prev = datetime.fromisoformat(t_prev)
            except Exception as e:
                corr_logger.warning(f"[CORR][TRAVEL] Timestamp parse error: {e}")
                return None

            elapsed_hours = max((ts_now - ts_prev).total_seconds() / 3600, 0.001)
            distance_km   = self._haversine_km(prev_lat, prev_lon, lat, lon)
            required_speed = distance_km / elapsed_hours
            
            corr_logger.info(f"[CORR][TRAVEL] Analyzing {user}: {distance_km:.1f}km in {elapsed_hours:.2f}h ({required_speed:.1f} km/h)")

            if max_travel_time_hours is not None or min_distance_km is not None:
                time_limit = float(max_travel_time_hours if max_travel_time_hours is not None else 2)
                distance_limit = float(min_distance_km if min_distance_km is not None else 500)
                if elapsed_hours > time_limit or distance_km < distance_limit:
                    return None
            elif required_speed <= self.TRAVEL_SPEED_KMH or distance_km <= 100:
                return None

            corr_logger.critical(
                f"[CORR][TRAVEL] T1078 — {user} impossible travel: "
                f"{distance_km:.0f}km in {elapsed_hours:.2f}h = {required_speed:.0f}km/h"
            )

            return self._alert(
                alert_type="Impossible travel detected",
                severity="CRITICAL",
                summary=(
                    f"Impossible travel: user '{user}' logged in from {prev_ip} "
                    f"then {source_ip} — {distance_km:.0f}km in "
                    f"{elapsed_hours * 60:.0f}min ({required_speed:.0f}km/h required)."
                ),
                tenant_id=tenant_id,
                source_ip=source_ip,
                user=user,
                event_id=4624,
                mitre="T1078",
                extra={
                    "distance_km":     round(distance_km, 1),
                    "elapsed_minutes": round(elapsed_hours * 60, 1),
                    "required_speed_kmh": round(required_speed, 0),
                    "prev_ip":         prev_ip,
                    "prev_location":   {"lat": prev_lat, "lon": prev_lon},
                    "curr_location":   {"lat": lat, "lon": lon},
                    "recommended_action": "Validate identity and location before using the guarded Block action.",
                },
            )
        except Exception as e:
            corr_logger.warning(f"[CORR][TRAVEL] Redis error: {e}")
        return None

    # ==========================================================
    # CORRELATION 3 — Ghost Admin Sequence (T1548 + T1070)
    # ==========================================================
    async def check_ghost_admin(
        self,
        tenant_id: str,
        source_ip: str,
        user: str,
        event_id: str,
        window_seconds: int | None = None,
        log_entry: dict | None = None,
    ) -> dict | None:
        """
        Pattern: EventID 4732 (Added to Administrators) followed by
                 EventID 1102 (Audit Log Cleared) within 5 minutes,
                 BOTH from the same source_ip.

        On 4732: Set a marker key with 5-min TTL.
        On 1102: If the 4732 marker exists for that IP → CRITICAL active breach.
        """
        ghost_window = int(window_seconds or self.GHOST_WINDOW)
        endpoint_subject = self._extract_field(log_entry, "agent_id") or source_ip or "unknown"
        ghost_key = f"warsoc:state:4732:{tenant_id}:{endpoint_subject}"
        try:
            if event_id == "4732":
                # Stage 1: Admin grant detected — arm the trigger
                await self.redis.set(ghost_key, "armed", ex=ghost_window)
                corr_logger.info(
                    f"[CORR][GHOST] Stage-1 armed: 4732 by {user} for {tenant_id}. "
                    f"Watching for 1102 within {ghost_window}s..."
                )
                return None

            if event_id == "1102":
                # Stage 2: Audit log cleared — check if 4732 preceded it
                armed = await self.redis.get(ghost_key)
                if armed:
                    await self.redis.delete(ghost_key)  # Disarm — alert fires once
                    corr_logger.critical(
                        f"[CORR][GHOST] T1548+T1070 — GHOST ADMIN SEQUENCE CONFIRMED: "
                        f"{source_ip} escalated then cleared logs within {ghost_window}s for {tenant_id}"
                    )

                    return self._alert(
                        alert_type="Ghost Admin Sequence Detected",
                        severity="CRITICAL",
                        summary=(
                            f"ACTIVE BREACH: '{source_ip}' granted admin rights (EventID 4732) "
                            f"then erased audit logs (EventID 1102) within "
                            f"{ghost_window // 60} minutes. Cover-up confirmed."
                        ),
                        tenant_id=tenant_id,
                        source_ip=source_ip,
                        user=user,
                        event_id=1102,
                        mitre="T1548+T1070",
                        extra={
                            "stage_1_event": "4732 — Member Added to Administrators",
                            "stage_2_event": "1102 — Security Audit Log Cleared",
                            "window_seconds": ghost_window,
                            "agent_id": endpoint_subject,
                            "recommended_action": "Isolate the endpoint and review the admin-group change before blocking any IP.",
                        },
                    )
        except Exception as e:
            corr_logger.warning(f"[CORR][GHOST] Redis error: {e}")
        return None

    # ==========================================================
    # CORRELATION 4 — SMB Lateral Movement / Credential Abuse
    # ==========================================================
    async def check_smb_lateral_movement(
        self,
        tenant_id: str,
        source_ip: str,
        user: str,
        event_id: str,
        threshold_users: int | None = None,
        window_seconds: int | None = None,
        log_entry: dict | None = None,
    ) -> dict | None:
        """Detect explicit credentials or CIFS tickets fanning out across SMB hosts."""
        if event_id not in {"4648", "4769"}:
            return None

        agent_id = self._extract_field(log_entry, "agent_id")
        actor_subject = agent_id or source_ip or user
        if not actor_subject:
            return None

        lateral_window = int(window_seconds or 7200)
        lateral_threshold = int(threshold_users or 2)
        if event_id == "4769":
            service_name = str(self._extract_field(log_entry, "service_name") or "").strip()
            if not service_name.lower().startswith("cifs/"):
                return None
            target_host = service_name.split("/", 1)[1].split(":", 1)[0]
        else:
            target_host = str(self._extract_field(log_entry, "target_server") or "").strip()

        normalized_target = target_host.rstrip(".").lower()
        computer = str(self._extract_field(log_entry, "computer") or "").rstrip(".").lower()
        local_names = {"", "-", "localhost", "127.0.0.1", "::1"}
        if normalized_target in local_names:
            return None
        if computer and normalized_target.split(".", 1)[0] == computer.split(".", 1)[0]:
            return None

        lateral_key = f"warsoc:corr:smb_lateral:{tenant_id}:{actor_subject}"

        try:
            pipe = self.redis.pipeline()
            pipe.sadd(lateral_key, normalized_target)
            pipe.sadd(f"{lateral_key}:events", event_id)
            pipe.expire(lateral_key, lateral_window)
            pipe.expire(f"{lateral_key}:events", lateral_window)
            pipe.scard(lateral_key)
            results = await pipe.execute()
            unique_targets = int(results[4]) if len(results) > 4 else 0
        except Exception as e:
            corr_logger.warning(f"[CORR][SMB-LM] Redis error: {e}")
            return None

        if unique_targets < lateral_threshold:
            return None

        alert_key = f"warsoc:corr:alerted:smb_lateral:{tenant_id}:{actor_subject}"
        try:
            if not await self.redis.set(alert_key, "1", nx=True, ex=lateral_window):
                return None
        except Exception as e:
            corr_logger.warning(f"[CORR][SMB-LM] Alert claim failed: {e}")
            return None

        corr_logger.critical(
            f"[CORR][SMB-LM] Lateral movement pattern confirmed for {source_ip}; targets={unique_targets}"
        )
        return self._alert(
            alert_type="SMB lateral movement detected",
            severity="HIGH",
            summary=(
                f"SMB credential abuse detected: {source_ip} touched {unique_targets} distinct targets "
                f"across credential or ticket events in {lateral_window // 60} minutes."
            ),
            tenant_id=tenant_id,
            source_ip=source_ip,
            user=user,
            event_id=int(event_id) if str(event_id).isdigit() else event_id,
            mitre="T1021.002",
            extra={
                "unique_targets": unique_targets,
                "window_minutes": lateral_window // 60,
                "recommended_action": "Validate the SMB targets, then isolate the endpoint or use guarded IP blocking.",
            },
        )

    # ==========================================================
    # CORRELATION 5 — SMB Share Enumeration
    # ==========================================================
    async def check_smb_enumeration(
        self,
        tenant_id: str,
        source_ip: str,
        user: str,
        event_id: str,
        threshold: int | None = None,
        window_seconds: int | None = None,
        log_entry: dict | None = None,
    ) -> dict | None:
        if event_id != "5140":
            return None

        if not source_ip:
            return None

        shares_window = int(window_seconds or 300)
        shares_threshold = int(threshold or 5)
        share_name = (
            self._extract_field(log_entry, "share_name")
            or self._extract_field(log_entry, "share_path")
            or self._extract_field(log_entry, "object_name")
            or self._extract_field(log_entry, "resource")
            or "unknown_share"
        )
        enum_key = f"warsoc:corr:smb_enum:{tenant_id}:{source_ip}"

        try:
            pipe = self.redis.pipeline()
            pipe.sadd(enum_key, share_name)
            pipe.expire(enum_key, shares_window)
            pipe.scard(enum_key)
            results = await pipe.execute()
            unique_shares = int(results[2])
        except Exception as e:
            corr_logger.warning(f"[CORR][SMB-ENUM] Redis error: {e}")
            return None

        if unique_shares < shares_threshold:
            return None

        corr_logger.warning(
            f"[CORR][SMB-ENUM] SMB enumeration confirmed for {source_ip}; shares={unique_shares}"
        )
        return self._alert(
            alert_type="SMB share enumeration detected",
            severity="MEDIUM",
            summary=(
                f"SMB enumeration detected: {source_ip} accessed {unique_shares} shares in {shares_window // 60} minutes."
            ),
            tenant_id=tenant_id,
            source_ip=source_ip,
            user=user,
            event_id=5140,
            mitre="T1135",
            extra={"unique_shares": unique_shares, "window_minutes": shares_window // 60},
        )

    # ==========================================================
    # CORRELATION 6 — Ransomware Raw Access / Mass Mutation
    # ==========================================================
    async def check_ransomware_pattern(
        self,
        tenant_id: str,
        source_ip: str,
        user: str,
        event_id: str,
        threshold: int | None = None,
        window_seconds: int | None = None,
        log_entry: dict | None = None,
    ) -> dict | None:
        if event_id not in {"4663", "4660", "4657"}:
            return None

        mutation_window = int(window_seconds or 300)
        mutation_threshold = int(threshold or 20)
        subject = (
            source_ip
            or self._extract_field(log_entry, "agent_id")
            or user
            or "unknown-endpoint"
        )
        ransomware_key = f"warsoc:corr:ransomware:{tenant_id}:{subject}"
        modify_delta = 1 if event_id in {"4663", "4657"} else 0
        delete_delta = 1 if event_id == "4660" else 0

        try:
            pipe = self.redis.pipeline()
            pipe.hincrby(ransomware_key, "mutations", modify_delta)
            pipe.hincrby(ransomware_key, "deletions", delete_delta)
            pipe.expire(ransomware_key, mutation_window)
            mutation_count, deletion_count, _ = await pipe.execute()
        except Exception as e:
            corr_logger.warning(f"[CORR][RANSOMWARE] Redis error: {e}")
            return None

        total_mutations = int(mutation_count) + int(deletion_count)
        if total_mutations < mutation_threshold:
            return None

        corr_logger.critical(
            f"[CORR][RANSOMWARE] Bulk native file mutation confirmed for {subject}; total={total_mutations}"
        )
        extra = {
            "mutation_count": int(mutation_count),
            "deletion_count": int(deletion_count),
            "window_seconds": mutation_window,
        }
        if self._source_ip_has_remote_evidence(log_entry, source_ip):
            banned = await self._trigger_auto_revocation(
                tenant_id,
                source_ip,
                reason="ransomware_mass_mutation",
                rule_id="T1486",
                evidence_ref=str((log_entry or {}).get("event_uid") or ""),
            )
            extra["soar_action"] = "auto_ban" if banned else "guardrail_skip"
        else:
            extra["soar_action_recommended"] = "endpoint_isolation"
            extra["soar_auto_ban_skipped_reason"] = "unverified_remote_source"

        return self._alert(
            alert_type="Ransomware mass-mutation pattern detected",
            severity="CRITICAL",
            summary=(
                f"Ransomware pattern detected: {subject} generated {total_mutations} native file mutations/deletions."
            ),
            tenant_id=tenant_id,
            source_ip=source_ip,
            user=user,
            event_id=int(event_id) if str(event_id).isdigit() else event_id,
            mitre="T1486",
            extra=extra,
        )

    # ==========================================================
    # CORRELATION 8 — After-Hours Activity
    # ==========================================================
    async def check_after_hours_activity(
        self,
        tenant_id: str,
        source_ip: str,
        user: str,
        event_id: str,
        timestamp_iso: str | None = None,
        rule_name: str = "after_hours_activity",
        rule: dict = None,
    ) -> dict | None:
        if not rule:
            rule = {}
        start_hour = int(rule.get("start_hour", 0))
        end_hour = int(rule.get("end_hour", 0))
        if self._is_after_hours(timestamp_iso, start_hour, end_hour):
            alert_key = f"warsoc:dyn:alerted:{rule_name}:{tenant_id}:{user}"
            window = int(rule.get("window_seconds") or 300)
            try:
                if await self.redis.set(alert_key, "1", nx=True, ex=max(window, 300)):
                    return self._alert(
                        alert_type=rule.get("description", rule_name),
                        severity=rule.get("severity", "MEDIUM"),
                        summary=f"{rule.get('description', 'Behavioral anomaly detected')}: {user} at {timestamp_iso or 'current time'}",
                        tenant_id=tenant_id,
                        source_ip=source_ip,
                        user=user,
                        event_id=int(event_id) if str(event_id).isdigit() else 0,
                        mitre=rule.get("mitre_id", "N/A"),
                        extra={"dynamic_rule": rule_name, "hour_window": [start_hour, end_hour]},
                    )
            except Exception as e:
                corr_logger.warning(f"[CORR][AFTER-HOURS] Redis error: {e}")
        return None

    # ==========================================================
    # CORRELATION 9 — Dormant Account Activation
    # ==========================================================
    async def check_dormant_account_activation(
        self,
        tenant_id: str,
        source_ip: str,
        user: str,
        event_id: str,
        timestamp_iso: str | None = None,
        rule_name: str = "dormant_account_activation",
        rule: dict = None,
    ) -> dict | None:
        if not rule:
            rule = {}
        dormant_days = int(rule.get("dormant_days", 30))
        if event_id != "4624":
            return None
        
        last_login_key = f"warsoc:dyn:last_login:{tenant_id}:{user}"
        now_dt = datetime.fromisoformat((timestamp_iso or datetime.now(timezone.utc).isoformat()).replace("Z", "+00:00"))
        if now_dt.tzinfo is None:
            now_dt = now_dt.replace(tzinfo=timezone.utc)
        prev_raw = None
        try:
            prev_raw = await self.redis.get(last_login_key)
        except Exception:
            prev_raw = None

        if prev_raw:
            try:
                prev_dt = datetime.fromisoformat(prev_raw.replace("Z", "+00:00"))
                if prev_dt.tzinfo is None:
                    prev_dt = prev_dt.replace(tzinfo=timezone.utc)
                if (now_dt - prev_dt).days >= dormant_days:
                    alert_key = f"warsoc:dyn:alerted:{rule_name}:{tenant_id}:{user}"
                    window = int(rule.get("window_seconds") or 300)
                    if await self.redis.set(alert_key, "1", nx=True, ex=max(window, 300)):
                        return self._alert(
                            alert_type=rule.get("description", rule_name),
                            severity=rule.get("severity", "MEDIUM"),
                            summary=f"{rule.get('description', 'Behavioral anomaly detected')}: {user} logged in after {(now_dt - prev_dt).days} days",
                            tenant_id=tenant_id,
                            source_ip=source_ip,
                            user=user,
                            event_id=4624,
                            mitre=rule.get("mitre_id", "N/A"),
                            extra={"dynamic_rule": rule_name, "dormant_days_detected": (now_dt - prev_dt).days},
                        )
            except Exception:
                pass

        # Always update last login
        try:
            await self.redis.set(last_login_key, now_dt.isoformat())
        except Exception:
            pass

        return None

    # ==========================================================
    # EVALUATE DYNAMIC RULES
    # ==========================================================
    async def check_process_injection(
        self,
        tenant_id: str,
        source_ip: str,
        user: str,
        event_id: str,
        log_entry: dict | None = None,
        window_seconds: int | None = None,
    ) -> dict | None:
        if event_id != "4688":
            return None

        command_line = (
            self._extract_field(log_entry, "command_line")
            or self._extract_field(log_entry, "process_command_line")
            or str((log_entry or {}).get("message") or "")
        ).lower()
        source_image = (
            self._extract_field(log_entry, "new_process_name")
            or self._extract_field(log_entry, "source_image")
            or self._extract_field(log_entry, "image")
            or ""
        ).lower()

        injection_indicators = (
            "invoke-reflectivepeinjection",
            "invoke-dllinjection",
            "createremotethread",
            "ntcreatethreadex",
            "virtualallocex",
            "writeprocessmemory",
        )
        if not any(indicator in command_line for indicator in injection_indicators):
            return None

        corr_logger.critical(
            f"[CORR][INJECT] Process-injection tooling appeared in native 4688 telemetry from {source_ip}"
        )
        return self._alert(
            alert_type="Process injection tooling detected",
            severity="CRITICAL",
            summary=(
                f"Process injection tooling detected in command-line telemetry from {source_ip or 'an endpoint'}."
            ),
            tenant_id=tenant_id,
            source_ip=source_ip,
            user=user,
            event_id=4688,
            mitre="T1055",
            extra={
                "source_image": source_image,
                "command_line": command_line,
                "soar_action_recommended": "endpoint_isolation",
            },
        )

    # ==========================================================
    # CORRELATION 8 — Registry Persistence
    # ==========================================================
    async def check_registry_persistence(
        self,
        tenant_id: str,
        source_ip: str,
        user: str,
        event_id: str,
        log_entry: dict | None = None,
        window_seconds: int | None = None,
    ) -> dict | None:
        if event_id != "4657":
            return None

        target_object = (
            self._extract_field(log_entry, "target_object")
            or self._extract_field(log_entry, "registry_path")
            or self._extract_field(log_entry, "object_name")
            or ""
        ).lower()
        persistence_paths = ("\\run\\", "\\runonce\\", "\\services\\", "image file execution options", "startupapproved")
        if not any(path in target_object for path in persistence_paths):
            return None

        corr_logger.warning(f"[CORR][REGISTRY] Persistence registry change detected from {source_ip}")
        return self._alert(
            alert_type="Registry persistence detected",
            severity="HIGH",
            summary=(
                f"Registry persistence detected: {source_ip} modified a known autorun or service path ({target_object or 'unknown path'})."
            ),
            tenant_id=tenant_id,
            source_ip=source_ip,
            user=user,
            event_id=4657,
            mitre="T1112",
            extra={"target_object": target_object},
        )

    # ==========================================================
    # MASTER RUNNER — Config-Driven Correlations
    # ==========================================================
    # ==========================================================
    # CORRELATION - Phishing Kill Chain (T1566)
    # ==========================================================
    async def check_phishing_kill_chain(
        self,
        tenant_id: str,
        source_ip: str,
        user: str,
        event_id: str,
        log_entry: dict,
        event_type: str = "",
        window_seconds: int = 900
    ) -> dict | None:
        log_entry = log_entry or {}
        message = str(log_entry.get("message") or "").lower()
        actor = str(user or "").strip()
        actor_token = actor.lower()
        if not message or not actor:
            return None

        rule_cfg = (
            self.stateful_rules.get("auth_identity", {}).get("phishing_kill_chain", {})
            if isinstance(self.stateful_rules.get("auth_identity"), dict)
            else {}
        )
        ignored_identities = {
            str(value).strip().lower()
            for value in rule_cfg.get(
                "ignored_identities",
                ["system", "local service", "network service", "anonymous logon", "unknown"],
            )
            if str(value).strip()
        }
        if actor_token in ignored_identities or actor_token.endswith("$"):
            return None

        processed = log_entry.get("processed_data") if isinstance(log_entry.get("processed_data"), dict) else {}
        raw_event_data = log_entry.get("raw_event_data") if isinstance(log_entry.get("raw_event_data"), dict) else {}
        raw_system = raw_event_data.get("system") if isinstance(raw_event_data.get("system"), dict) else {}
        raw_data = log_entry.get("raw_data") if isinstance(log_entry.get("raw_data"), dict) else {}
        agent_scope = str(
            log_entry.get("agent_id")
            or processed.get("computer")
            or raw_system.get("computer")
            or ""
        ).strip()
        if not agent_scope:
            return None

        event_type_token = self._normalize_token(event_type or log_entry.get("event_type"))
        delivery_event_types = {
            self._normalize_token(value)
            for value in rule_cfg.get(
                "delivery_event_types",
                ["email", "email_gateway", "email_message", "browser_download", "url_click", "web_proxy", "http_request"],
            )
            if str(value).strip()
        }
        lure_keywords = [
            str(value).strip().lower()
            for value in rule_cfg.get(
                "lure_keywords",
                ["verify your account", "password expired", "invoice attached", "urgent action required", "security alert"],
            )
            if str(value).strip()
        ]
        risky_attachments = (".hta", ".js", ".jse", ".vbs", ".vbe", ".lnk", ".iso", ".img")
        has_url = "http://" in message or "https://" in message
        has_lure_language = any(keyword in message for keyword in lure_keywords)
        has_risky_attachment = any(extension in message for extension in risky_attachments)
        trusted_web_origin = bool(raw_data.get("web_log_file"))
        is_delivery = (
            event_type_token in delivery_event_types
            and (event_type_token != "http_request" or trusted_web_origin)
            and ((has_lure_language and has_url) or (has_risky_attachment and (has_lure_language or has_url)))
        )

        execution_keywords = [
            str(value).strip().lower()
            for value in rule_cfg.get(
                "execution_keywords",
                ["powershell", "mshta", "wscript", "cscript", "rundll32", "regsvr32", "certutil", "bitsadmin"],
            )
            if str(value).strip()
        ]
        suspicious_markers = [
            str(value).strip().lower()
            for value in rule_cfg.get(
                "suspicious_execution_markers",
                ["-enc", "-encodedcommand", "downloadstring", "invoke-webrequest", "frombase64string", "-windowstyle hidden", "http://", "https://", ".js", ".jse", ".vbs", ".vbe", ".hta", "javascript:"],
            )
            if str(value).strip()
        ]
        parent_process = str(processed.get("parent_process_name") or "").lower()
        suspicious_parents = [
            str(value).strip().lower()
            for value in rule_cfg.get("suspicious_parent_processes", [])
            if str(value).strip()
        ]
        is_process_event = str(event_id or "") == "4688" or event_type_token in {
            "process_create",
            "process_creation",
            "command_line",
            "powershell",
        }
        is_execution = (
            is_process_event
            and any(keyword in message for keyword in execution_keywords)
            and (
                any(marker in message for marker in suspicious_markers)
                or any(parent.endswith(parent_name) for parent_name in suspicious_parents for parent in [parent_process])
            )
        )
        if not is_delivery and not is_execution:
            return None

        scope_digest = hashlib.sha256(
            f"{tenant_id}\x00{agent_scope}\x00{actor_token}".encode("utf-8")
        ).hexdigest()[:32]
        delivery_key = f"warsoc:dyn:phish_delivery:{scope_digest}"
        alert_key = f"warsoc:dyn:alerted:phishing:{scope_digest}"

        try:
            if is_delivery:
                delivery_context = json.dumps(
                    {
                        "event_uid": log_entry.get("event_uid"),
                        "timestamp": log_entry.get("timestamp") or log_entry.get("ingested_at"),
                    },
                    separators=(",", ":"),
                )
                await self.redis.set(delivery_key, delivery_context, ex=window_seconds)
                return None

            delivery_context = await self.redis.get(delivery_key)
            if delivery_context is None:
                return None
        except Exception as e:
            corr_logger.error(f"[CORR][PHISHING] Redis error: {e}")
            return None

        try:
            if await self.redis.set(alert_key, "1", nx=True, ex=window_seconds):
                return self._alert(
                    alert_type="Correlated phishing kill-chain detected",
                    severity="CRITICAL",
                    summary=f"Phishing delivery followed by suspicious execution for {actor}",
                    tenant_id=tenant_id,
                    source_ip=source_ip,
                    user=actor,
                    event_id=int(event_id) if str(event_id).isdigit() else event_id,
                    mitre="T1566",
                    extra={
                        "dynamic_rule": "phishing_kill_chain",
                        "stages": 2,
                        "agent_id": agent_scope,
                    },
                )
        except Exception as e:
            corr_logger.error(f"[CORR][PHISHING] Redis alert deduplication error: {e}")

        return None

    async def run_all(
        self,
        tenant_id: str,
        source_ip: str,
        user: str,
        event_id: str,
        lat: float | None = None,
        lon: float | None = None,
        timestamp_iso: str = "",
        event_type: str = "",
        log_entry: dict | None = None,
    ) -> list[dict]:
        """
        Executes config-driven stateful behavioral rules.
        """
        hybrid_alerts = await self.check_hybrid_network_correlations(
            tenant_id,
            source_ip,
            user,
            event_id,
            event_type,
            timestamp_iso,
            log_entry,
        )
        dynamic_alerts = await self.run_dynamic_rules(
            tenant_id,
            source_ip,
            user,
            event_id,
            event_type=event_type,
            timestamp_iso=timestamp_iso,
            log_entry=log_entry,
            lat=lat,
            lon=lon,
        )
        return [*hybrid_alerts, *dynamic_alerts]

    async def run_dynamic_rules(
        self,
        tenant_id: str,
        source_ip: str,
        user: str,
        event_id: str,
        *,
        event_type: str = "",
        timestamp_iso: str = "",
        log_entry: dict | None = None,
        lat: float | None = None,
        lon: float | None = None,
    ) -> list[dict]:
        """
        Logical Hub: Iterates through config.json rules and executes 
        generic Redis tracking logic based on schema parameters.
        """
        triggered = []
        
        # Ensure timestamp_iso is a string (prevents datetime .replace exception)
        from datetime import datetime
        if isinstance(timestamp_iso, datetime):
            timestamp_iso = timestamp_iso.isoformat()
        else:
            timestamp_iso = str(timestamp_iso or "")

        # Safe float coercion for geo-coordinates
        try:
            if lat is not None:
                lat = float(lat)
            if lon is not None:
                lon = float(lon)
        except (ValueError, TypeError):
            lat = None
            lon = None
        
        # Flatten all categories (auth_identity, filesystem_ransomware, etc)
        all_rules = {}
        for category in self.stateful_rules.values():
            if isinstance(category, dict):
                all_rules.update(category)

        for rule_name, rule in all_rules.items():
            if not rule.get("enabled", True):
                continue

            # Filtering: Does this rule care about this event?
            event_filter = rule.get("event_filter")
            if not self._event_filter_matches(event_filter, event_id, event_type):
                continue
            if str(event_filter or "").lower().startswith("http"):
                raw_data = log_entry.get("raw_data") if isinstance(log_entry, dict) and isinstance(log_entry.get("raw_data"), dict) else {}
                if not raw_data.get("web_log_file"):
                    continue
            if not self._dynamic_rule_payload_matches(rule_name, rule, log_entry):
                continue

            threshold = rule.get("threshold")
            threshold_users = rule.get("threshold_users")
            unique_field = rule.get("unique_field")
            window = rule.get("window_seconds", 300)
            group_by = rule.get("group_by")

            # Allow config to specify an explicit builtin handler token via
            # `handler` or `type`. Fallback to the rule name if not provided.
            handler_token = str(rule.get("handler") or rule.get("type") or rule_name).strip().lower()

            if handler_token in self.builtin_handlers and not self._builtin_handler_relevant(
                handler_token,
                event_id,
                event_type,
                log_entry,
            ):
                continue

            # Builtin handlers: invoke with the right shaped parameters when
            # requested by config. This removes hardcoding of rule-name checks
            # and lets config drive behavior.
            if handler_token in self.builtin_handlers:
                # Only throttle wildcard handlers after a cheap relevance check.
                if str(event_filter).strip().lower() == "all":
                    throttle_key = f"warsoc:throttle:siem:all:{tenant_id}:{source_ip}:{rule_name}"
                    current_rate = await self.redis.incr(throttle_key)
                    if current_rate == 1:
                        await self.redis.expire(throttle_key, 60)
                    if current_rate > 100:
                        continue
                try:
                    if handler_token in ("impossible_travel", "builtin:impossible_travel"):
                        alert = await self.check_impossible_travel(
                            tenant_id,
                            source_ip,
                            user,
                            event_id,
                            lat,
                            lon,
                            timestamp_iso,
                            window_seconds=int(rule.get("window_seconds") or 0) or None,
                            max_travel_time_hours=rule.get("max_travel_time_hours"),
                            min_distance_km=rule.get("min_distance_km"),
                        )
                        if alert:
                            triggered.append(alert)
                        continue

                    if handler_token in ("ghost_admin_sequence", "ghost_admin", "builtin:ghost_admin_sequence"):
                        alert = await self.check_ghost_admin(
                            tenant_id,
                            source_ip,
                            user,
                            event_id,
                            window_seconds=int(window or self.GHOST_WINDOW),
                            log_entry=log_entry,
                        )
                        if alert:
                            triggered.append(alert)
                        continue

                    if handler_token in ("password_spray", "spray", "password-spray", "builtin:password_spray"):
                        alert = await self.check_password_spray(
                            tenant_id,
                            source_ip,
                            user,
                            event_id,
                            threshold=threshold_users or threshold,
                            window_seconds=int(window or self.SPRAY_WINDOW) or None,
                        )
                        if alert:
                            triggered.append(alert)
                        continue

                    if handler_token in ("smb_lateral_movement", "smb_lateral", "builtin:smb_lateral_movement"):
                        alert = await self.check_smb_lateral_movement(
                            tenant_id,
                            source_ip,
                            user,
                            event_id,
                            threshold_users=threshold_users or threshold,
                            window_seconds=int(window or 7200) or None,
                            log_entry=log_entry,
                        )
                        if alert:
                            triggered.append(alert)
                        continue

                    if handler_token in ("smb_enumeration", "smb-enumeration", "builtin:smb_enumeration"):
                        alert = await self.check_smb_enumeration(
                            tenant_id,
                            source_ip,
                            user,
                            event_id,
                            threshold=threshold,
                            window_seconds=int(window or 300) or None,
                            log_entry=log_entry,
                        )
                        if alert:
                            triggered.append(alert)
                        continue

                    if handler_token in ("registry_persistence", "builtin:registry_persistence"):
                        alert = await self.check_registry_persistence(
                            tenant_id,
                            source_ip,
                            user,
                            event_id,
                            log_entry=log_entry,
                            window_seconds=int(window or 300) or None,
                        )
                        if alert:
                            triggered.append(alert)
                        continue

                    if handler_token in ("phishing_kill_chain", "builtin:phishing_kill_chain"):
                        alert = await self.check_phishing_kill_chain(
                            tenant_id,
                            source_ip,
                            user,
                            event_id,
                            log_entry=log_entry,
                            event_type=event_type,
                            window_seconds=int(window or 900),
                        )
                        if alert:
                            triggered.append(alert)
                        continue

                    if handler_token in ("after_hours_activity", "builtin:after_hours_activity"):
                        alert = await self.check_after_hours_activity(
                            tenant_id,
                            source_ip,
                            user,
                            event_id,
                            timestamp_iso=timestamp_iso,
                            rule_name=rule_name,
                            rule=rule,
                        )
                        if alert:
                            triggered.append(alert)
                        continue

                    if handler_token in ("dormant_account_activation", "builtin:dormant_account_activation"):
                        alert = await self.check_dormant_account_activation(
                            tenant_id,
                            source_ip,
                            user,
                            event_id,
                            timestamp_iso=timestamp_iso,
                            rule_name=rule_name,
                            rule=rule,
                        )
                        if alert:
                            triggered.append(alert)
                        continue
                except Exception as e:
                    corr_logger.warning(f"[CORR] Builtin handler {handler_token} failed: {e}")
                    continue

            if not group_by:
                group_by = "source_ip"
            
            if (threshold or threshold_users or unique_field) and window:
                agent_id = self._extract_field(log_entry, "agent_id") or "unknown-agent"
                if group_by == "tenant":
                    subject = tenant_id
                elif group_by == "source_ip":
                    subject = source_ip
                elif group_by in {"agent", "agent_id"}:
                    subject = agent_id
                elif group_by == "agent_user":
                    subject = f"{agent_id}:{user}"
                else:
                    subject = user
                alert_key = f"warsoc:dyn:alerted:{rule_name}:{tenant_id}:{subject}"

                if threshold_users or unique_field:
                    tracked_value = self._extract_field(log_entry, unique_field or "username")
                    if not tracked_value:
                        if unique_field and unique_field.lower() == "username":
                            tracked_value = user
                        elif unique_field and unique_field.lower() in {"source_ip", "src_ip"}:
                            tracked_value = source_ip
                    if not tracked_value:
                        continue

                    redis_key = f"warsoc:dyn:uniq:{rule_name}:{tenant_id}:{subject}"

                    try:
                        async with self.redis.pipeline(transaction=True) as pipe:
                            pipe.sadd(redis_key, tracked_value)
                            pipe.expire(redis_key, window)
                            pipe.scard(redis_key)
                            res = await pipe.execute()
                            count = int(res[2])
                    except Exception:
                        continue

                    threshold_value = int(threshold_users or threshold)
                    if count >= threshold_value:
                        try:
                            if await self.redis.set(alert_key, "1", nx=True, ex=window):
                                triggered.append(self._alert(
                                    alert_type=rule.get("description", rule_name),
                                    severity=rule.get("severity", "MEDIUM"),
                                    summary=f"{rule.get('description', 'Behavioral anomaly detected')}: {count} unique {unique_field or 'values'} for {subject}",
                                    tenant_id=tenant_id,
                                    source_ip=source_ip,
                                    user=user,
                                    event_id=int(event_id) if event_id.isdigit() else 0,
                                    mitre=rule.get("mitre_id", "N/A"),
                                    extra={"dynamic_rule": rule_name, "count": count, "window": window, "unique_field": unique_field or "username"},
                                ))
                        except Exception:
                            continue
                    continue

                redis_key = f"warsoc:dyn:{rule_name}:{tenant_id}:{subject}"
                
                try:
                    # Atomic Increment + Sliding Window
                    async with self.redis.pipeline(transaction=True) as pipe:
                        pipe.incr(redis_key)
                        pipe.expire(redis_key, window)
                        res = await pipe.execute()
                        count = int(res[0])
                except Exception:
                    continue

                if count >= int(threshold):
                    try:
                        if await self.redis.set(alert_key, "1", nx=True, ex=window):
                            triggered.append(self._alert(
                                alert_type=rule.get("description", rule_name),
                                severity=rule.get("severity", "MEDIUM"),
                                summary=f"{rule.get('description', 'Behavioral anomaly detected')}: {count} events for {subject}",
                                tenant_id=tenant_id,
                                source_ip=source_ip,
                                user=user,
                                event_id=int(event_id) if event_id.isdigit() else 0,
                                mitre=rule.get("mitre_id", "N/A"),
                                extra={"dynamic_rule": rule_name, "count": count, "window": window}
                            ))
                    except Exception:
                        continue

        return triggered
