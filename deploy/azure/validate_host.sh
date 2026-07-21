#!/usr/bin/env bash
set -Eeuo pipefail

PROJECT_DIR="${PROJECT_DIR:-/opt/warsoc/Startup-backend}"
ENV_FILE="${ENV_FILE:-${PROJECT_DIR}/.env.prod}"
COMPOSE_FILE="${COMPOSE_FILE:-${PROJECT_DIR}/docker-compose.prod.yml}"
PUBLIC_HEALTH_URL="${PUBLIC_HEALTH_URL:-https://api.warsoc.tech/health}"

cd "${PROJECT_DIR}"
docker compose --env-file "${ENV_FILE}" -f "${COMPOSE_FILE}" config --quiet
docker compose --env-file "${ENV_FILE}" -f "${COMPOSE_FILE}" ps

health="$(curl --fail --silent --show-error --max-time 15 "${PUBLIC_HEALTH_URL}")"
python3 - "${health}" <<'PY'
import json
import sys

payload = json.loads(sys.argv[1])
if payload.get("status") != "healthy":
    raise SystemExit("WarSOC public health did not report healthy")
dependencies = payload.get("dependencies") or {}
for name in ("mongodb", "redis"):
    if dependencies.get(name) != "healthy":
        raise SystemExit(f"WarSOC dependency is unhealthy: {name}")
print("Public API, MongoDB, and Redis health: PASS")
PY

for port in 27017 6379 8000; do
    if ss -lnt | awk '{print $4}' | grep -Eq "(^|:)${port}$"; then
        echo "Private port ${port} is unexpectedly bound on the Azure host." >&2
        exit 1
    fi
done
echo "Host-level private-port exposure check: PASS"
