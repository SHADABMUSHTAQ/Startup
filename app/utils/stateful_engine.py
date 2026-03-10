import asyncio
import json
import logging
from typing import Dict, Any, List
from pathlib import Path
import redis.asyncio as aioredis

logger = logging.getLogger(__name__)

class StatefulThreatEngine:
    """Enterprise-Grade Dynamic Stateful Engine for WarSOC"""
    
    def __init__(self, config_path: str = "app/config/config.json"):
        self.config_path = Path(config_path)
        self.rules = {}
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
                self.key_prefix = config.get('redis', {}).get('key_prefix', 'warsoc:stateful:')
        except Exception as e:
            logger.error(f"Config Load Error: {e}")

    async def start(self, redis_url="redis://localhost:6379"):
        try:
            self.redis = await aioredis.from_url(redis_url, decode_responses=True)
            await self.redis.ping()
            print("✅ Stateful Engine: Redis Connected")
        except Exception as e:
            print(f"❌ Stateful Engine Redis Error: {e}")

    async def stop(self):
        if self.redis: 
            await self.redis.close()

    async def analyze(self, normalized_log: Dict[str, Any]) -> List[Dict[str, Any]]:
        if not self.redis: return []
        
        alerts = []
        event_type = normalized_log.get('event_type', 'unknown')

        for category, category_rules in self.rules.items():
            for rule_name, rule_config in category_rules.items():
                if not rule_config.get('enabled'): continue

                target_filter = rule_config.get('event_filter', 'all')
                if target_filter != 'all' and target_filter not in event_type:
                    continue

                group_field = rule_config.get('group_by', 'source_ip')
                group_val = normalized_log.get(group_field)
                if not group_val: continue

                key = f"{self.key_prefix}{rule_name}:{group_val}"
                threshold = rule_config.get('threshold', 5)
                window = rule_config.get('window_seconds', 60)

                try:
                    async with self.redis.pipeline(transaction=True) as pipe:
                        await pipe.incr(key)
                        await pipe.expire(key, window)
                        results = await pipe.execute()
                        count = results[0]

                    if count >= threshold:
                        # ✅ FIX: Get dynamic source from normalized log
                        source_engine = normalized_log.get("engine_source", "Stateful")
                        
                        alerts.append({
                            'title': rule_config.get('description', f'Behavior Anomaly: {rule_name}'),
                            'mitre_id': rule_config.get('mitre_id', 'Unknown'),
                            'severity': rule_config.get('severity', 'HIGH'),
                            'risk_score': 30, 
                            'source_ip': normalized_log.get('source_ip', 'unknown'),
                            'engine_source': source_engine, # ✅ DYNAMIC
                            'metadata': {'count': count, 'threshold': threshold}
                        })
                except Exception as e:
                    logger.error(f"Redis Engine Error: {e}")

        return alerts
