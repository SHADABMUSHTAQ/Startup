import os
import sys
import asyncio
import subprocess
import redis.asyncio as redis
from motor.motor_asyncio import AsyncIOMotorClient
import httpx

# WarSOC Local CI Validation Script
# Performs a "Triple Lock" confirmation for Production Readiness.

async def check_redis(url):
    print(f"[*] Testing Redis Connectivity...")
    try:
        r = redis.from_url(url, decode_responses=True)
        await r.ping()
        print("[PASS] Redis: Connected and responsive.")
        await r.aclose()
        return True
    except Exception as e:
        print(f"[FAIL] Redis: Connection failed: {e}")
        return False

async def check_mongodb(uri, db_name):
    print(f"[*] Testing MongoDB Connectivity...")
    try:
        client = AsyncIOMotorClient(uri)
        db = client[db_name]
        await client.admin.command('ping')
        print(f"[PASS] MongoDB: Connected to '{db_name}'.")
        client.close()
        return True
    except Exception as e:
        print(f"[FAIL] MongoDB: Connection failed: {e}")
        return False

async def check_api_health(url):
    print("[*] Testing API health (/health)...")
    try:
        async with httpx.AsyncClient() as client:
            resp = await client.get(f"{url}/health", timeout=5.0)
            if resp.status_code == 200:
                print("[PASS] API: Health endpoint is available.")
                return True
            else:
                print(f"[FAIL] API: Returned status {resp.status_code}")
                return False
    except Exception as e:
        print(f"[FAIL] API: Unreachable: {e}")
        return False

def check_git_sanitization():
    print(f"[*] Checking Git Sanitization...")
    # This checks the LOCAL index. The permanent history purge is a separate manual step.
    forbidden = [".env", "keys/private_key.pem", "keys/public_key.pem"]
    leaks = []

    for f in forbidden:
        result = subprocess.run(
            ["git", "ls-files", "--error-unmatch", "--", f],
            check=False,
            capture_output=True,
            text=True,
        )
        if result.returncode == 0 and result.stdout.strip():
            leaks.append(f)

    if leaks:
        print(f"[FAIL] Git sanitization: tracked sensitive files: {leaks}")
        print("   >>> Run the Purge Command to cleanse history.")
        return False
    else:
        print("[PASS] Git sanitization: no forbidden files in the index.")
        return True

async def main():
    print("====================================================")
    print("      WarSOC 3.0 Production Validation CI")
    print("====================================================\n")

    # Load secrets from local .env context
    from dotenv import load_dotenv
    load_dotenv()

    redis_url = os.getenv("REDIS_URL")
    mongo_uri = os.getenv("MONGODB_URI")
    db_name = os.getenv("MONGODB_DB_NAME", "WarSOC_DB")
    api_url = os.getenv("BACKEND_PUBLIC_URL", "http://127.0.0.1:8000")

    results = [
        await check_redis(redis_url),
        await check_mongodb(mongo_uri, db_name),
        await check_api_health(api_url),
        check_git_sanitization()
    ]

    print("\n----------------------------------------------------")
    if all(results):
        print("SYSTEM STATUS: LOCAL VALIDATION CHECKS PASSED.")
        print("----------------------------------------------------")
        sys.exit(0)
    else:
        print("SYSTEM STATUS: LOCAL VALIDATION CHECKS FAILED.")
        print("----------------------------------------------------")
        sys.exit(1)

if __name__ == "__main__":
    asyncio.run(main())
