#!/bin/sh
set -e

# Wait for Redis to be reachable (script exits non-zero on timeout)
python /app/scripts/wait_for_redis.py

# Provision default admin ONLY for the API container
if [ "$1" = "uvicorn" ] || { [ "$1" = "python" ] && [ "$2" = "-m" ] && [ "$3" = "uvicorn" ]; }; then
    if [ -f /app/create_admin.py ]; then
        python /app/create_admin.py || true
    else
        echo "Skipping local default admin helper: /app/create_admin.py not present"
    fi
fi

# Exec the container's main process (CMD)
echo "Starting WarSOC process: $*"
exec "$@"
