import asyncio
import logging
import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from motor.motor_asyncio import AsyncIOMotorClient
import redis.asyncio as redis
from dotenv import load_dotenv

from app.workers.siem_worker import siem_worker
from app.workers.fbr_worker import fbr_worker
from app.workers.peca_worker import peca_worker
from app.workers.email_daemon import run_email_daemon

load_dotenv()

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
logger = logging.getLogger("unified_worker")

async def safe_worker_runner(worker_func, worker_name):
    """
    Wraps a worker in a continuous loop. If a worker crashes, it catches the exception,
    logs it, and restarts the worker after a short delay so the other streams are never affected.
    """
    while True:
        try:
            logger.info(f"Starting {worker_name}...")
            await worker_func()
        except asyncio.CancelledError:
            logger.info(f"{worker_name} cancelled. Shutting down.")
            break
        except Exception as e:
            logger.error(f"CRITICAL: {worker_name} crashed: {e}. Restarting in 5s...")
            await asyncio.sleep(5)

async def unified_worker_main():
    """
    Modular Monolith Worker: Runs all three independent streaming components
    (SIEM, FBR, and PECA) concurrently on a single async event loop.
    This saves massive memory overhead by avoiding 3 separate container/interpreter bootups.
    """
    logger.info("===============================================================")
    logger.info(" STARTING WARSOC UNIFIED WORKER (4-CONTAINER MONOLITH MODE) ")
    logger.info("===============================================================")

    # Run all stream loops simultaneously with isolation wrappers
    results = await asyncio.gather(
        safe_worker_runner(siem_worker, "SIEM Engine"),
        safe_worker_runner(fbr_worker, "FBR Archiver"),
        safe_worker_runner(peca_worker, "PECA Forensic"),
        safe_worker_runner(run_email_daemon, "Email Daemon"),
        return_exceptions=True
    )

    for result in results:
        if isinstance(result, Exception):
            logger.error(f"Worker gathering failed with exception: {result}")

if __name__ == "__main__":
    try:
        asyncio.run(unified_worker_main())
    except KeyboardInterrupt:
        logger.info("Unified Worker shutting down gracefully.")
