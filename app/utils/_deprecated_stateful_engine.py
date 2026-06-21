import asyncio
import json
import logging
import re
from typing import Dict, Any, List
from pathlib import Path
from datetime import datetime, timezone
import redis.asyncio as aioredis

logger = logging.getLogger(__name__)

class StatefulThreatEngine:
    """Enterprise-Grade Dynamic Stateful Engine for WarSOC"""
    
    def __init__(self, config_path: str = "app/config/config.json"):
        self.config_path = Path(config_path)
        self.rules = {}
        self.event_id_map = {}
        self.alert_title_map = {}
        self.redis = None
        self.key_prefix = "warsoc:stateful:"
        self._load_config()

    def _load_config(self):
        try:
            if not self.config_path.exists():
                return
            with open(self.config_path, 'r', encoding='utf-8') as f:
                config = json.load(f)
                self.rules = config.get('stateful_detection_rules', {})
                self.event_id_map = config.get('event_id_map', {})
                self.alert_title_map = config.get('alert_title_map', {})
                self.key_prefix = config.get('redis', {}).get('key_prefix', 'warsoc:stateful:')
        except Exception as e:
            logger.error(f"Config Load Error: {e}")

    def _infer_handler_type(self, rule_name: str, rule_config: Dict[str, Any]) -> str:
        """Infer handler type for backward compatibility when handler_type is absent."""
        configured = str(rule_config.get("handler_type", "")).strip().lower()
        if configured:
            return configured

        inferred = {
            "password_spraying": "password_spraying",
            "concurrent_sessions": "concurrent_sessions",
            "vertical_port_scan": "unique_field_counter",
            "horizontal_port_scan": "unique_field_counter",
            "phishing_kill_chain": "phishing_kill_chain",
            "after_hours_activity": "after_hours",
            "ransomware_extensions": "ransomware_extensions",
            "rare_port_usage": "rare_port",
            "dns_tunneling": "dns_tunneling",
            "data_exfiltration_volume": "data_exfiltration_volume",
            "sensitive_file_touch": "sensitive_file",
            "impossible_travel": "requires_geoip",
            "new_location_access": "requires_geoip",
            "dormant_account_activation": "requires_history",
            "long_duration_connection": "requires_session_tracking",
            "beaconing_c2": "requires_session_tracking",
            "log_clearing_sequence": "requires_sequence_tracking",
        }
        return inferred.get(rule_name, "counter")

    async def _dispatch(self, handler_type: str, rule_name: str, rule_config: Dict[str, Any], normalized_log: Dict[str, Any], window: int):
        dispatch_map = {
            "counter": self._generic_counter,
            "password_spraying": self._handle_password_spraying,
            "concurrent_sessions": self._handle_concurrent_sessions,
            "unique_field_counter": self._handle_unique_field_counter,
            "phishing_kill_chain": self._handle_phishing_kill_chain,
            "after_hours": self._handle_after_hours,
            "ransomware_extensions": self._handle_ransomware_extensions,
            "rare_port": self._handle_rare_port_usage,
            "dns_tunneling": self._handle_dns_tunneling,
            "data_exfiltration_volume": self._handle_data_exfiltration_volume,
            "sensitive_file": self._handle_sensitive_file,
        }
        handler = dispatch_map.get(handler_type)
        if handler is None:
            logger.warning(f"Unknown handler_type '{handler_type}' for rule '{rule_name}'")
            return None

        if handler_type in {"after_hours", "ransomware_extensions", "rare_port"}:
            return await handler(rule_name, rule_config, normalized_log)
        return await handler(rule_name, rule_config, normalized_log, window)

    async def start(self, redis_url="redis://localhost:6379"):
        try:
            self.redis = await aioredis.from_url(redis_url, decode_responses=True)
            await self.redis.ping()
            print(" Stateful Engine: Redis Connected")
        except Exception as e:
            self.redis = None
            print(f" Stateful Engine Redis Error: {e}")

    async def stop(self):
        if self.redis: 
            await self.redis.close()

    # ─── SPECIALIZED HANDLERS ──────────────────────────────

    async def _handle_password_spraying(self, rule_name, rule_config, log, window):
        """Track unique usernames per source_ip — true spray detection"""
        ip = log.get("source_ip", "unknown")
        user = log.get("user", "unknown")
        tenant_id = log.get("tenant_id")
        if not tenant_id:
            raise ValueError("tenant_id missing in log for stateful engine")
        key = f"{self.key_prefix}{tenant_id}:{rule_name}:users:{ip}"
        threshold_users = rule_config.get("threshold_users", 10)

        await self.redis.sadd(key, user)
        await self.redis.expire(key, window)
        unique_count = await self.redis.scard(key)

        if unique_count >= threshold_users:
            return self._build_alert(rule_config, rule_name, log, {"unique_users": unique_count, "threshold": threshold_users})
        return None

    async def _handle_concurrent_sessions(self, rule_name, rule_config, log, window):
        """Track unique IPs per username"""
        user = log.get("user", "unknown")
        ip = log.get("source_ip", "unknown")
        tenant_id = log.get("tenant_id")
        if not tenant_id:
            raise ValueError("tenant_id missing in log for stateful engine")
        key = f"{self.key_prefix}{tenant_id}:{rule_name}:ips:{user}"
        threshold = rule_config.get("threshold", 3)

        await self.redis.sadd(key, ip)
        await self.redis.expire(key, window)
        unique_ips = await self.redis.scard(key)

        if unique_ips >= threshold:
            return self._build_alert(rule_config, rule_name, log, {"unique_ips": unique_ips, "threshold": threshold})
        return None

    async def _handle_after_hours(self, rule_name, rule_config, log):
        """Check if event occurs during suspicious hours"""
        start = rule_config.get("start_hour", 2)
        end = rule_config.get("end_hour", 5)
        try:
            ts = log.get("timestamp", "")
            if isinstance(ts, str):
                dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            else:
                dt = datetime.now(timezone.utc)
            hour = dt.hour
            if start <= hour < end:
                return self._build_alert(rule_config, rule_name, log, {"hour": hour, "suspicious_window": f"{start}:00-{end}:00"})
        except Exception:
            pass
        return None

    async def _handle_ransomware_extensions(self, rule_name, rule_config, log):
        """Check file path/message for known ransomware extensions"""
        bad_exts = rule_config.get("ransomware_extensions", [])
        msg = log.get("message", "").lower()
        for ext in bad_exts:
            if ext.lower() in msg:
                return self._build_alert(rule_config, rule_name, log, {"matched_extension": ext})
        return None

    async def _handle_sensitive_file(self, rule_name, rule_config, log, window):
        """Count accesses that match sensitive keywords"""
        keywords = rule_config.get("sensitive_keywords", [])
        msg = log.get("message", "").lower()
        has_match = any(kw.lower() in msg for kw in keywords)
        if not has_match:
            return None
        # Only count if message contains sensitive keyword
        return await self._generic_counter(rule_name, rule_config, log, window)

    async def _handle_rare_port_usage(self, rule_name, rule_config, log):
        """Flag suspicious destination ports defined in policy."""
        suspicious_ports = {int(p) for p in rule_config.get("suspicious_ports", [])}
        if not suspicious_ports:
            return None

        raw_port = log.get("destination_port") or log.get("dest_port")
        if raw_port is None:
            msg = log.get("message", "")
            match = re.search(r"\bport\s*[:=]?\s*(\d{1,5})\b", msg, flags=re.IGNORECASE)
            if match:
                raw_port = match.group(1)

        try:
            port = int(raw_port)
        except (TypeError, ValueError):
            return None

        if port in suspicious_ports:
            return self._build_alert(rule_config, rule_name, log, {"destination_port": port})
        return None

    async def _handle_dns_tunneling(self, rule_name, rule_config, log, window):
        """Count suspiciously long DNS labels per source over time."""
        min_len = int(rule_config.get("subdomain_min_length", 50))
        threshold = int(rule_config.get("threshold", 50))

        dns_text = str(
            log.get("query")
            or log.get("dns_query")
            or log.get("domain")
            or log.get("message", "")
        )

        labels = re.findall(r"[A-Za-z0-9_-]{%d,}" % min_len, dns_text)
        if not labels:
            return None

        group_val = log.get("source_ip", "unknown")
        tenant_id = log.get("tenant_id")
        if not tenant_id:
            raise ValueError("tenant_id missing in log for stateful engine")
        key = f"{self.key_prefix}{tenant_id}:{rule_name}:{group_val}"
        async with self.redis.pipeline(transaction=True) as pipe:
            await pipe.incr(key)
            await pipe.expire(key, window)
            results = await pipe.execute()
            count = int(results[0])

        if count >= threshold:
            return self._build_alert(
                rule_config,
                rule_name,
                log,
                {"count": count, "threshold": threshold, "sample_label": labels[0][:64]},
            )
        return None

    async def _handle_data_exfiltration_volume(self, rule_name, rule_config, log, window):
        """Accumulate outbound bytes and trigger when threshold is crossed."""
        threshold = int(rule_config.get("threshold_bytes", 104857600))
        group_field = rule_config.get("group_by", "user")
        group_val = log.get(group_field, "unknown")

        raw_bytes = (
            log.get("bytes_out")
            or log.get("outbound_bytes")
            or (log.get("raw_data") or {}).get("bytes_out")
            or (log.get("raw_data") or {}).get("outbound_bytes")
        )

        if raw_bytes is None:
            msg = str(log.get("message", ""))
            match = re.search(r"(\d+)\s*(bytes|kb|mb|gb)\b", msg, flags=re.IGNORECASE)
            if match:
                value = int(match.group(1))
                unit = match.group(2).lower()
                multiplier = {"bytes": 1, "kb": 1024, "mb": 1024 * 1024, "gb": 1024 * 1024 * 1024}[unit]
                raw_bytes = value * multiplier

        try:
            bytes_out = int(raw_bytes)
        except (TypeError, ValueError):
            return None

        if bytes_out <= 0:
            return None

        tenant_id = log.get("tenant_id")
        if not tenant_id:
            raise ValueError("tenant_id missing in log for stateful engine")
        key = f"{self.key_prefix}{tenant_id}:{rule_name}:bytes:{group_val}"
        async with self.redis.pipeline(transaction=True) as pipe:
            await pipe.incrby(key, bytes_out)
            await pipe.expire(key, window)
            results = await pipe.execute()
            cumulative = int(results[0])

        if cumulative >= threshold:
            return self._build_alert(
                rule_config,
                rule_name,
                log,
                {"bytes_window": cumulative, "threshold_bytes": threshold},
            )
        return None

    async def _handle_phishing_kill_chain(self, rule_name, rule_config, log, window):
        """Correlate phishing lifecycle: lure -> click -> execution within window."""
        actor_field = rule_config.get("group_by", "user")
        actor = str(log.get(actor_field) or log.get("source_ip") or "unknown")
        if actor == "unknown":
            return None

        msg = str(log.get("message", "")).lower()
        event_type = str(log.get("event_type", "unknown")).lower()

        lure_keywords = [k.lower() for k in rule_config.get("lure_keywords", [])]
        click_keywords = [k.lower() for k in rule_config.get("click_keywords", [])]
        exec_keywords = [k.lower() for k in rule_config.get("execution_keywords", [])]
        min_stages = int(rule_config.get("minimum_stages", 2))

        stage = None
        if lure_keywords and any(k in msg for k in lure_keywords):
            stage = "lure"
        elif event_type == "http_request" and click_keywords and any(k in msg for k in click_keywords):
            stage = "click"
        elif (event_type in {"process_creation", "unknown"}) and exec_keywords and any(k in msg for k in exec_keywords):
            stage = "execution"

        if not stage:
            return None

        tenant_id = log.get("tenant_id")
        if not tenant_id:
            raise ValueError("tenant_id missing in log for stateful engine")
        stage_key = f"{self.key_prefix}{tenant_id}:{rule_name}:stages:{actor}"
        lock_key = f"{self.key_prefix}{tenant_id}:{rule_name}:fired:{actor}"

        await self.redis.sadd(stage_key, stage)
        await self.redis.expire(stage_key, window)
        stage_count = await self.redis.scard(stage_key)

        if stage_count < min_stages:
            return None

        already_fired = await self.redis.get(lock_key)
        if already_fired:
            return None

        await self.redis.setex(lock_key, max(30, window // 2), "1")
        stages = sorted(await self.redis.smembers(stage_key))
        return self._build_alert(
            rule_config,
            rule_name,
            log,
            {"actor": actor, "stages": stages, "minimum_stages": min_stages},
        )

    async def _handle_unique_field_counter(self, rule_name, rule_config, log, window):
        """Count unique values of a field (ports, IPs) per group — for scans"""
        group_field = rule_config.get("group_by", "source_ip")
        unique_field = rule_config.get("unique_field", "destination_port")
        group_val = log.get(group_field, "unknown")
        unique_val = log.get(unique_field, log.get("message", ""))

        tenant_id = log.get("tenant_id")
        if not tenant_id:
            raise ValueError("tenant_id missing in log for stateful engine")
        key = f"{self.key_prefix}{tenant_id}:{rule_name}:uniq:{group_val}"
        threshold = rule_config.get("threshold", 10)

        await self.redis.sadd(key, str(unique_val))
        await self.redis.expire(key, window)
        count = await self.redis.scard(key)

        if count >= threshold:
            return self._build_alert(rule_config, rule_name, log, {"unique_count": count, "threshold": threshold})
        return None

    async def _generic_counter(self, rule_name, rule_config, log, window):
        """Simple threshold counter — works for brute force, storms, floods"""
        group_field = rule_config.get("group_by", "source_ip")
        group_val = log.get(group_field, "unknown")
        if not group_val:
            return None

        tenant_id = log.get("tenant_id")
        if not tenant_id:
            raise ValueError("tenant_id missing in log for stateful engine")
        key = f"{self.key_prefix}{tenant_id}:{rule_name}:{group_val}"
        threshold = rule_config.get("threshold", 5)

        async with self.redis.pipeline(transaction=True) as pipe:
            await pipe.incr(key)
            await pipe.expire(key, window)
            results = await pipe.execute()
            count = results[0]

        if count >= threshold:
            return self._build_alert(rule_config, rule_name, log, {"count": count, "threshold": threshold})
        return None

    # ─── MAIN ANALYZE ──────────────────────────────────────

    async def analyze(self, normalized_log: Dict[str, Any]) -> List[Dict[str, Any]]:
        if not self.redis:
            return []
        
        alerts = []
        event_type = str(normalized_log.get('event_type', 'unknown')).lower()
        # Fallback: if event_type is unknown, derive from event_id using event_id_map
        if event_type == "unknown":
            event_id = str(normalized_log.get("event_id", ""))
            mapped = self.event_id_map.get(event_id, {})
            if mapped:
                event_type = str(mapped.get("event_type", "unknown")).lower()

        for category, category_rules in self.rules.items():
            for rule_name, rule_config in category_rules.items():
                if not rule_config.get('enabled'):
                    continue

                handler_type = self._infer_handler_type(rule_name, rule_config)
                if handler_type in {
                    "requires_geoip",
                    "requires_history",
                    "requires_session_tracking",
                    "requires_sequence_tracking",
                }:
                    continue

                target_filter = str(rule_config.get('event_filter', 'all')).lower()
                if target_filter != 'all' and target_filter not in event_type:
                    continue

                window = rule_config.get('window_seconds', 60)

                try:
                    result = await self._dispatch(handler_type, rule_name, rule_config, normalized_log, window)

                    if result:
                        alerts.append(result)
                except Exception as e:
                    logger.error(f"Stateful rule error [{rule_name}]: {e}")

        return alerts

    # ─── ALERT BUILDER ─────────────────────────────────────

    def _friendly_stateful_title(self, title: str, rule_name: str) -> str:
        raw = (title or "").strip()
        if raw in self.alert_title_map:
            return self.alert_title_map[raw]

        if raw:
            return raw

        normalized = str(rule_name or "activity").replace("_", " ").strip().lower()
        return f"Unusual {normalized} was detected"

    def _build_alert(self, rule_config, rule_name, log, metadata):
        source_engine = log.get("engine_source", "Stateful")
        severity = str(rule_config.get('severity', 'HIGH')).upper()
        severity_risk = {
            "LOW": 20,
            "MEDIUM": 40,
            "HIGH": 70,
            "CRITICAL": 90,
        }
        base_title = rule_config.get('description', f'Behavior Anomaly: {rule_name}')
        alert = {
            'type': rule_name,
            'summary': self._friendly_stateful_title(base_title, rule_name),
            'ip': log.get('source_ip', 'unknown'),
            'user': log.get('user', 'N/A'),
            'mitre': rule_config.get('mitre_id', 'Unknown'),
            'severity': severity,
            'risk_score': severity_risk.get(severity, 50),
            'engine_source': source_engine,
            'timestamp': log.get('timestamp', datetime.now(timezone.utc).isoformat()),
            'metadata': metadata,
        }
        compliance_tag = rule_config.get("compliance_tag") or log.get("compliance_tag")
        if compliance_tag:
            alert["compliance_tag"] = compliance_tag
        return alert
