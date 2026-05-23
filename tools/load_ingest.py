#!/usr/bin/env python3
"""Lightweight async load generator that writes to the Redis stream used by workers.

Usage:
  python tools/load_ingest.py --rate 100 --duration 30
"""
import asyncio
import json
import time
import argparse
import uuid
from datetime import datetime, timezone

from redis.asyncio import Redis
from app.config.config import get_settings


async def produce(rate: int, duration: int, tenant_id: str):
    settings = get_settings()
    redis = await Redis.from_url(settings.redis_url, decode_responses=True)
    stream = "raw_logs_queue"
    total = rate * duration
    interval = 1.0 / rate
    sent = 0
    start = time.time()
    try:
        while sent < total:
            now = datetime.now(timezone.utc).isoformat()
            payload = {
                "tenant_id": tenant_id,
                "event_id": 4625,
                "message": f"Failed login attempt {uuid.uuid4().hex[:8]}",
                "timestamp": now,
                "source_ip": "10.0.0.1",
                "user": "admin",
            }
            entry = {"payload": json.dumps(payload)}
            await redis.xadd(stream, entry)
            sent += 1
            await asyncio.sleep(interval)
    finally:
        await redis.close()
    elapsed = time.time() - start
    print(f"Sent {sent} messages in {elapsed:.2f}s")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--rate", type=int, default=100, help="events per second")
    parser.add_argument("--duration", type=int, default=30, help="duration seconds")
    parser.add_argument("--tenant", type=str, default="TEST_TENANT", help="tenant id")
    args = parser.parse_args()
    asyncio.run(produce(args.rate, args.duration, args.tenant))


if __name__ == "__main__":
    main()
