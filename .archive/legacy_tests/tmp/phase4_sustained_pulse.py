import json
import os
import time
from datetime import datetime, timezone

import requests

API_BASE = os.environ.get("API_BASE", "http://localhost:8000")
MASTER_SECRET = os.environ.get("AGENT_MASTER_SECRET", "W4rS0c_Ag3nt_M4st3r_2026!_k7Lp5nBwS1")
BATCHES = int(os.environ.get("PULSE_BATCHES", "120"))
BATCH_SIZE = int(os.environ.get("PULSE_BATCH_SIZE", "25"))
INTERVAL_SEC = float(os.environ.get("PULSE_INTERVAL_SEC", "0.15"))


def iso_now_micro_z() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def signup_and_login(session: requests.Session):
    suffix = int(time.time())
    username = f"p4pulse_{suffix}"
    payload = {
        "username": username,
        "email": f"{username}@example.com",
        "password": "WarSOC_Strong_2026!",
        "full_name": "Phase4 Pulse User",
        "plan_type": "Enterprise",
    }
    s = session.post(f"{API_BASE}/api/v1/auth/signup", json=payload, timeout=20)
    if s.status_code not in (200, 201):
        raise RuntimeError(f"signup failed: {s.status_code} {s.text[:200]}")

    l = session.post(
        f"{API_BASE}/api/v1/auth/login",
        json={"username": username, "password": "WarSOC_Strong_2026!"},
        timeout=20,
    )
    if l.status_code != 200:
        raise RuntimeError(f"login failed: {l.status_code} {l.text[:200]}")

    data = l.json()
    return username, data["tenant_id"]


def agent_login(session: requests.Session, tenant_id: str) -> str:
    r = session.post(
        f"{API_BASE}/api/v1/auth/agent-login",
        json={"agent_id": tenant_id, "agent_secret": MASTER_SECRET},
        timeout=20,
    )
    if r.status_code != 200:
        raise RuntimeError(f"agent-login failed: {r.status_code} {r.text[:200]}")
    return r.json()["access_token"]


def build_batch(tenant_id: str, batch_index: int, batch_size: int):
    events = []
    for i in range(batch_size):
        event_id = [4624, 4625, 4688, 4670][(batch_index + i) % 4]
        events.append(
            {
                "agent_id": tenant_id,
                "source_ip": f"10.10.{batch_index % 25}.{(i % 240) + 10}",
                "user": f"pulse_user_{i % 50}",
                "event_id": event_id,
                "message": f"Phase4 pulse batch={batch_index} idx={i} event={event_id}",
                "timestamp": iso_now_micro_z(),
                "raw_data": {"batch": batch_index, "idx": i},
                "agent_version": "phase4-pulse",
            }
        )
    return events


def main():
    session = requests.Session()

    username, tenant_id = signup_and_login(session)
    token = agent_login(session, tenant_id)

    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

    counts = {"200": 0, "401": 0, "403": 0, "413": 0, "429": 0, "5xx": 0, "other": 0}
    samples = []

    start = time.time()
    for b in range(BATCHES):
        payload = build_batch(tenant_id, b, BATCH_SIZE)
        resp = session.post(f"{API_BASE}/api/v1/ingest/windows", headers=headers, json=payload, timeout=30)

        code = resp.status_code
        if code == 200:
            counts["200"] += 1
        elif code == 401:
            counts["401"] += 1
        elif code == 403:
            counts["403"] += 1
        elif code == 413:
            counts["413"] += 1
        elif code == 429:
            counts["429"] += 1
        elif code >= 500:
            counts["5xx"] += 1
        else:
            counts["other"] += 1

        if len(samples) < 8:
            samples.append({"batch": b, "code": code, "body": resp.text[:180]})

        time.sleep(INTERVAL_SEC)

    duration = time.time() - start
    total_events = BATCHES * BATCH_SIZE

    summary = {
        "username": username,
        "tenant_id": tenant_id,
        "batches": BATCHES,
        "batch_size": BATCH_SIZE,
        "total_events": total_events,
        "duration_sec": round(duration, 2),
        "request_rate_per_sec": round(BATCHES / duration, 2),
        "event_rate_per_sec": round(total_events / duration, 2),
        "http_counts": counts,
        "samples": samples,
    }

    print(json.dumps(summary, indent=2))

    if counts["5xx"] > 0 or counts["401"] > 0 or counts["403"] > 0:
        raise SystemExit(2)


if __name__ == "__main__":
    main()
