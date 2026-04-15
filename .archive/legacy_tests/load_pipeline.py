"""Async Redis XADD load generator for pipeline-level stress testing.

Usage:
  PYTHONPATH=. python scripts/load_pipeline.py --total 1000 --concurrency 1000 --tenant perf-tenant --event 4688

This script writes JSON payloads into the Redis stream used by the workers.
"""
import asyncio
import argparse
import json
import os
import time
from datetime import datetime, timezone
try:
    from redis.asyncio import Redis
except Exception:
    raise


async def worker_task(redis_url, stream, tenant_id, event_id, count, task_id, semaphore):
    redis = Redis.from_url(redis_url, decode_responses=True)
    sent = 0
    async with semaphore:
        for i in range(count):
            payload = {
                "agent_id": tenant_id,
                "source_ip": "127.0.0.1",
                "user": "load-generator",
                "event_id": event_id,
                "message": f"load-test {task_id} #{i}",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "raw_data": {"seq": i}
            }
            try:
                await redis.xadd(stream, {"payload": json.dumps(payload)}, maxlen=100000, approximate=True)
                sent += 1
            except Exception as e:
                print(f"[task {task_id}] XADD failed: {e}")
    try:
        await redis.close()
    except Exception:
        pass
    return sent


async def run(total, concurrency, redis_url, stream, tenant, event_id):
    concurrency = min(concurrency, total)
    per_task = total // concurrency
    remainder = total % concurrency

    semaphore = asyncio.Semaphore(1000)  # allow many tasks, but bound some internal concurrency
    tasks = []
    start = time.time()
    for t in range(concurrency):
        c = per_task + (1 if t < remainder else 0)
        if c <= 0:
            continue
        tasks.append(asyncio.create_task(worker_task(redis_url, stream, tenant, event_id, c, t, semaphore)))

    results = await asyncio.gather(*tasks, return_exceptions=True)
    sent = 0
    for r in results:
        if isinstance(r, Exception):
            print(f"Task error: {r}")
        else:
            sent += int(r)
    elapsed = time.time() - start
    print(f"Sent {sent}/{total} events in {elapsed:.2f}s ({sent/elapsed if elapsed>0 else 0:.2f} ops/s)")
    # persist a small results file
    try:
        import pathlib
        pathlib.Path("tmp/phase2").mkdir(parents=True, exist_ok=True)
        with open("tmp/phase2/load_pipeline_results.json", "w", encoding="utf-8") as fh:
            json.dump({"total": total, "sent": sent, "elapsed": elapsed}, fh)
    except Exception:
        pass


def main():
    parser = argparse.ArgumentParser(description="Redis XADD pipeline load generator")
    parser.add_argument("--total", type=int, default=1000)
    parser.add_argument("--concurrency", "-c", type=int, default=100)
    parser.add_argument("--redis-url", type=str, default=os.environ.get("REDIS_URL", "redis://localhost:6379"))
    parser.add_argument("--stream", type=str, default=os.environ.get("RAW_LOGS_QUEUE", "raw_logs_queue"))
    parser.add_argument("--tenant", type=str, default="perf-tenant")
    parser.add_argument("--event", type=int, default=4688)
    args = parser.parse_args()

    asyncio.run(run(args.total, args.concurrency, args.redis_url, args.stream, args.tenant, args.event))


if __name__ == "__main__":
    main()
