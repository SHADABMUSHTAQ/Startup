"""Async HTTP load generator for end-to-end ingestion testing.

Usage:
  PYTHONPATH=. python scripts/load_http.py --total 1000 --concurrency 1000 --tenant perf-tenant

This script obtains an agent token (uses AGENT_MASTER_SECRET environment variable)
and posts ingestion payloads to the API ingestion endpoint.
"""
import asyncio
import argparse
import json
import os
import time
from datetime import datetime, timezone
import httpx
import jwt
import uuid
from datetime import timedelta


async def obtain_token(api_url, tenant_id, master_secret, jwt_secret=None):
    """Try agent-login first; if that fails and `jwt_secret` is provided,
    generate a JWT locally matching the server's token contract.
    """
    # Prefer agent-login endpoint if master secret is provided
    if master_secret:
        try:
            url = f"{api_url.rstrip('/')}/api/v1/auth/agent-login"
            async with httpx.AsyncClient() as client:
                r = await client.post(url, json={"agent_id": tenant_id, "agent_secret": master_secret}, timeout=10.0)
                if r.status_code == 200:
                    return r.json().get("access_token")
                else:
                    print(f"Agent-login returned {r.status_code}: {r.text}")
        except Exception as e:
            print(f"Agent-login request failed: {e}")

    # Fallback: generate JWT locally if secret provided
    if jwt_secret:
        now = datetime.now(timezone.utc)
        exp = now + timedelta(hours=24)
        jti = str(uuid.uuid4())
        payload = {"sub": tenant_id, "type": "agent", "tenant_id": tenant_id, "jti": jti, "exp": int(exp.timestamp())}
        token = jwt.encode(payload, jwt_secret, algorithm="HS256")
        return token

    return None


async def sender_task(api_url, token, batch_size, count, tenant_id, event_id, task_id):
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    async with httpx.AsyncClient(timeout=30.0) as client:
        sent = 0
        for i in range(count):
            payloads = []
            for b in range(batch_size):
                payloads.append({
                    "agent_id": tenant_id,
                    "source_ip": "127.0.0.1",
                    "user": "load-http",
                    "event_id": event_id,
                    "message": f"http-load {task_id} #{i}-{b}",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "raw_data": {"seq": f"{task_id}-{i}-{b}"},
                    "agent_version": "loadgen/1.0"
                })
            try:
                r = await client.post(f"{api_url.rstrip('/')}/api/v1/ingest/windows", json=payloads, headers=headers)
                if r.status_code == 200:
                    sent += len(payloads)
                else:
                    print(f"[task {task_id}] HTTP {r.status_code} - {r.text}")
            except Exception as e:
                print(f"[task {task_id}] request error: {e}")
    return sent


async def run(api_url, total, concurrency, batch_size, tenant_id, event_id, master_secret):
    concurrency = min(concurrency, total)
    per_task = total // concurrency
    remainder = total % concurrency

    jwt_secret = os.environ.get("JWT_SECRET_KEY") or os.environ.get("JWT_SECRET")
    token = await obtain_token(api_url, tenant_id, master_secret, jwt_secret=jwt_secret)
    if not token:
        raise RuntimeError("Failed to obtain agent token; ensure AGENT_MASTER_SECRET or JWT_SECRET_KEY is set and valid")

    tasks = []
    start = time.time()
    for t in range(concurrency):
        c = per_task + (1 if t < remainder else 0)
        if c <= 0:
            continue
        tasks.append(asyncio.create_task(sender_task(api_url, token, batch_size, c, tenant_id, event_id, t)))

    results = await asyncio.gather(*tasks, return_exceptions=True)
    sent = 0
    for r in results:
        if isinstance(r, Exception):
            print(f"Task error: {r}")
        else:
            sent += int(r)
    elapsed = time.time() - start
    print(f"HTTP Sent {sent}/{total} events in {elapsed:.2f}s ({sent/elapsed if elapsed>0 else 0:.2f} ops/s)")
    try:
        import pathlib
        pathlib.Path("tmp/phase2").mkdir(parents=True, exist_ok=True)
        with open("tmp/phase2/load_http_results.json", "w", encoding="utf-8") as fh:
            json.dump({"total": total, "sent": sent, "elapsed": elapsed}, fh)
    except Exception:
        pass


def main():
    parser = argparse.ArgumentParser(description="HTTP load generator for ingestion endpoint")
    parser.add_argument("--api-url", type=str, default=os.environ.get("API_URL", "http://localhost:8000"))
    parser.add_argument("--total", type=int, default=1000)
    parser.add_argument("--concurrency", "-c", type=int, default=100)
    parser.add_argument("--batch-size", type=int, default=1, help="Number of logs per POST request")
    parser.add_argument("--tenant", type=str, default="perf-tenant")
    parser.add_argument("--event", type=int, default=4688)
    args = parser.parse_args()

    master_secret = os.environ.get("AGENT_MASTER_SECRET")
    if not master_secret:
        raise RuntimeError("AGENT_MASTER_SECRET must be set in the environment for token pre-warm")

    asyncio.run(run(args.api_url, args.total, args.concurrency, args.batch_size, args.tenant, args.event, master_secret))


if __name__ == "__main__":
    main()
