#!/usr/bin/env python3
import os
import socket
import time
import sys
from urllib.parse import urlparse


def get_redis_host_port():
    url = os.getenv("REDIS_URL", "")
    if not url:
        host = os.getenv("REDIS_HOST", "redis")
        port = int(os.getenv("REDIS_PORT", "6379"))
        return host, port
    parsed = urlparse(url)
    host = parsed.hostname or 'redis'
    port = parsed.port or 6379
    return host, port


def wait(host, port, timeout=60, interval=1):
    deadline = time.time() + int(os.getenv("WAIT_FOR_REDIS_TIMEOUT", str(timeout)))
    while time.time() < deadline:
        try:
            with socket.create_connection((host, port), timeout=3):
                print(f"✅ Redis reachable at {host}:{port}", flush=True)
                return 0
        except Exception as e:
            print(f"Waiting for redis at {host}:{port}: {e}", flush=True)
            time.sleep(interval)
    print(f"Timed out waiting for redis at {host}:{port}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    host, port = get_redis_host_port()
    rc = wait(host, port)
    sys.exit(rc)
