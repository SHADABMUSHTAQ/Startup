#!/bin/sh
set -e

# Wait for Redis to be reachable (script exits non-zero on timeout)
python /app/scripts/wait_for_redis.py

# Provision default admin ONLY for the API container
if [ "$1" = "uvicorn" ] || { [ "$1" = "python" ] && [ "$2" = "-m" ] && [ "$3" = "uvicorn" ]; }; then
    python /app/create_admin.py || true
fi

# Exec the container's main process (CMD)
echo "Starting WarSOC process: $*"
exec "$@"
