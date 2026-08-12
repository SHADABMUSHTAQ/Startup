"""Optional post-persistence Wazuh projector and dispatcher worker."""

from __future__ import annotations

import asyncio
import logging

from motor.motor_asyncio import AsyncIOMotorClient

from app.config.config import get_settings
from app.wazuh_integration.dispatcher import claim_dispatches, dispatch_claimed, expire_stale_dispatches
from app.wazuh_integration.projector import project_new_canonical_events


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("warsoc.wazuh-dispatch")


async def run_worker() -> None:
    settings = get_settings()
    if settings.wazuh_detection_mode == "disabled":
        logger.info("Wazuh detection is disabled; worker will not start.")
        return

    client = AsyncIOMotorClient(settings.mongodb_uri)
    db = client[settings.mongodb_db_name]
    try:
        while True:
            try:
                projection = await project_new_canonical_events(db, settings)
                expired = await expire_stale_dispatches(db)
                claimed = await claim_dispatches(db, settings)
                delivery = await dispatch_claimed(db, claimed, settings)
                if claimed or expired or projection.get("created"):
                    logger.info(
                        "Wazuh cycle projection=%s expired=%s delivery=%s",
                        projection,
                        expired,
                        delivery,
                    )
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.exception("Wazuh dispatch cycle failed; canonical pipelines remain independent.")
            await asyncio.sleep(1)
    finally:
        client.close()


if __name__ == "__main__":
    asyncio.run(run_worker())
