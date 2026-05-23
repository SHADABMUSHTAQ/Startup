import asyncio
import json
import logging
import traceback
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '.')))

from app.config.config import get_settings
from app.utils.siem_logic import CorrelationEngine
from redis.asyncio import Redis

logging.basicConfig(level=logging.INFO)

async def test_correlation():
    settings = get_settings()
    redis = await Redis.from_url(settings.redis_url, decode_responses=True)
    
    # Load config
    base_dir = os.path.dirname(os.path.abspath(__file__))
    config_path = os.path.join(base_dir, "app", "config", "config.json")
    with open(config_path, "r") as f:
        config = json.load(f)
        
    corr_engine = CorrelationEngine(redis, config=config)
    
    # problematic logon event payload from the logs:
    # 2026-05-21 15:32:51,687 [SIEM-Worker] [*] Processing log 1779377571685-0 | tenant=WARSOC_TEST_898F | event=4624
    log_data = {
        "tenant_id": "WARSOC_TEST_898F",
        "event_id": "4624",
        "source_ip": "203.0.113.10",
        "user": "finance_lead",
        "geo_lat": 24.86,
        "geo_lon": 67.00,
        "message": "Successful Logon (Karachi)",
        "ingested_at": "2026-05-21T15:32:51.687Z"
    }
    
    try:
        print("Running run_all for first log_data...")
        corr_alerts = await corr_engine.run_all(
            tenant_id=log_data["tenant_id"],
            source_ip=log_data["source_ip"],
            user=log_data["user"],
            event_id=log_data["event_id"],
        lat=None,
        lon=None,
            timestamp_iso=log_data["ingested_at"],
            event_type="successful_login",
            log_entry=log_data,
        )
        print("Success for first log! Corr alerts:", corr_alerts)
    except Exception as e:
        print("Failed with exception on first log:", e)
        traceback.print_exc()

    # Second login
    log_data_2 = {
        "tenant_id": "WARSOC_TEST_898F",
        "event_id": "4624",
        "source_ip": "185.10.20.30",
        "user": "finance_lead",
        "geo_lat": 55.75,
        "geo_lon": 37.61,
        "message": "Successful Logon (Moscow)",
        "ingested_at": "2026-05-21T15:32:53.687Z"
    }

    try:
        print("\nRunning run_all for second log_data...")
        corr_alerts_2 = await corr_engine.run_all(
            tenant_id=log_data_2["tenant_id"],
            source_ip=log_data_2["source_ip"],
            user=log_data_2["user"],
            event_id=log_data_2["event_id"],
            lat=log_data_2["geo_lat"],
            lon=log_data_2["geo_lon"],
            timestamp_iso=log_data_2["ingested_at"],
            event_type="successful_login",
            log_entry=log_data_2,
        )
        print("Success for second log! Corr alerts:", corr_alerts_2)
    except Exception as e:
        print("Failed with exception on second log:", e)
        traceback.print_exc()
        
    await redis.aclose()

if __name__ == "__main__":
    asyncio.run(test_correlation())
