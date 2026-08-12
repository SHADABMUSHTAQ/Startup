"""Private mTLS service for signed Wazuh candidate batches."""

from __future__ import annotations

from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone

import orjson
from fastapi import FastAPI, HTTPException, Request, Response
from motor.motor_asyncio import AsyncIOMotorClient
from redis.asyncio import Redis

from app.config.config import get_settings
from app.wazuh_integration.candidate_service import admit_candidate_batch
from app.wazuh_integration.contracts import (
    BridgeHealthBatch,
    BridgeHealthReceipt,
    DetectionCandidateBatch,
)
from app.wazuh_integration.security import (
    ConnectorBodyTooLarge,
    ConnectorSecurityError,
    build_signed_headers,
    read_bounded_request_body,
    verify_signed_request,
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    if settings.wazuh_detection_mode == "disabled":
        raise RuntimeError("Wazuh candidate service cannot start while detection is disabled")
    mongo = AsyncIOMotorClient(settings.mongodb_uri)
    redis = Redis.from_url(settings.redis_url, decode_responses=True)
    await mongo.admin.command("ping")
    await redis.ping()
    app.state.settings = settings
    app.state.mongo = mongo
    app.state.db = mongo[settings.mongodb_db_name]
    app.state.redis = redis
    try:
        yield
    finally:
        await redis.aclose()
        mongo.close()


app = FastAPI(
    title="WarSOC Private Detection Candidate Service",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
    lifespan=lifespan,
)


@app.get("/health")
async def health(request: Request, response: Response):
    dependencies = {"mongodb": "healthy", "redis": "healthy"}
    try:
        await request.app.state.mongo.admin.command("ping")
    except Exception:
        dependencies["mongodb"] = "unhealthy"
    try:
        await request.app.state.redis.ping()
    except Exception:
        dependencies["redis"] = "unhealthy"
    status = "healthy" if all(value == "healthy" for value in dependencies.values()) else "unhealthy"
    if status != "healthy":
        response.status_code = 503
    return {"status": status, "dependencies": dependencies}


@app.post("/api/v1/internal/detection-engines/wazuh/candidates")
async def receive_candidates(request: Request):
    settings = request.app.state.settings
    try:
        body = await read_bounded_request_body(
            request,
            max_bytes=settings.wazuh_max_body_bytes,
        )
    except ConnectorBodyTooLarge as exc:
        raise HTTPException(status_code=413, detail="Request rejected") from exc
    except ConnectorSecurityError as exc:
        raise HTTPException(status_code=400, detail="Request rejected") from exc
    try:
        nonce, _ = verify_signed_request(
            secret=settings.wazuh_candidate_signing_secret,
            expected_connector_id=settings.wazuh_connector_id,
            headers=request.headers,
            body=body,
        )
    except ConnectorSecurityError as exc:
        raise HTTPException(status_code=401, detail="Request rejected") from exc
    replay_key = f"warsoc:wazuh:candidate-nonce:{settings.wazuh_connector_id}:{nonce}"
    replay_ok = await request.app.state.redis.set(replay_key, "1", ex=600, nx=True)
    if not replay_ok:
        raise HTTPException(status_code=409, detail="Request rejected")
    try:
        batch = DetectionCandidateBatch.model_validate_json(body)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail="Request rejected") from exc
    if batch.connector_id != settings.wazuh_connector_id:
        raise HTTPException(status_code=401, detail="Request rejected")

    receipt = await admit_candidate_batch(request.app.state.db, batch, settings)
    response_body = orjson.dumps(
        receipt.model_dump(mode="json", by_alias=True),
        option=orjson.OPT_SORT_KEYS,
    )
    headers = build_signed_headers(
        secret=settings.wazuh_candidate_signing_secret,
        connector_id=settings.wazuh_connector_id,
        body=response_body,
    )
    return Response(content=response_body, media_type="application/json", headers=headers)


@app.post("/api/v1/internal/detection-engines/wazuh/health")
async def receive_bridge_health(request: Request):
    settings = request.app.state.settings
    try:
        body = await read_bounded_request_body(
            request,
            max_bytes=settings.wazuh_max_body_bytes,
        )
    except ConnectorBodyTooLarge as exc:
        raise HTTPException(status_code=413, detail="Request rejected") from exc
    except ConnectorSecurityError as exc:
        raise HTTPException(status_code=400, detail="Request rejected") from exc
    try:
        nonce, _ = verify_signed_request(
            secret=settings.wazuh_candidate_signing_secret,
            expected_connector_id=settings.wazuh_connector_id,
            headers=request.headers,
            body=body,
        )
    except ConnectorSecurityError as exc:
        raise HTTPException(status_code=401, detail="Request rejected") from exc
    replay_key = f"warsoc:wazuh:health-nonce:{settings.wazuh_connector_id}:{nonce}"
    replay_ok = await request.app.state.redis.set(replay_key, "1", ex=600, nx=True)
    if not replay_ok:
        raise HTTPException(status_code=409, detail="Request rejected")
    try:
        batch = BridgeHealthBatch.model_validate_json(body)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail="Request rejected") from exc
    if (
        batch.connector_id != settings.wazuh_connector_id
        or batch.engine_instance_id != settings.wazuh_engine_instance_id
        or batch.engine_version != settings.wazuh_engine_version
        or batch.ruleset_version != settings.wazuh_ruleset_version
        or batch.registry_sha256 != settings.wazuh_rule_registry_sha256
    ):
        raise HTTPException(status_code=401, detail="Request rejected")

    connector = await request.app.state.db.detection_engine_connectors.find_one(
        {
            "connector_id": batch.connector_id,
            "engine_instance_id": batch.engine_instance_id,
            "status": "active",
            "engine_version": batch.engine_version,
            "ruleset_version": batch.ruleset_version,
            "registry_sha256": batch.registry_sha256,
        },
        {"_id": 1},
    )
    if connector is None:
        raise HTTPException(status_code=401, detail="Request rejected")

    now = datetime.now(timezone.utc)
    accepted: list[str] = []
    for event in batch.events:
        await request.app.state.db.detection_engine_health_events.update_one(
            {
                "connector_id": batch.connector_id,
                "engine_instance_id": batch.engine_instance_id,
                "event_uid": event.event_uid,
            },
            {
                "$setOnInsert": {
                    "connector_id": batch.connector_id,
                    "engine_instance_id": batch.engine_instance_id,
                    "event_uid": event.event_uid,
                    "event_type": event.event_type,
                    "first_seen_at": event.first_seen_at,
                    "created_at": now,
                },
                "$set": {
                    "severity": event.severity,
                    "detail": event.detail,
                    "occurrence_count": event.occurrence_count,
                    "last_seen_at": event.last_seen_at,
                    "last_received_at": now,
                    "engine_version": batch.engine_version,
                    "ruleset_version": batch.ruleset_version,
                    "registry_sha256": batch.registry_sha256,
                    "status": "open",
                    "record_expires_at": now + timedelta(days=90),
                },
            },
            upsert=True,
        )
        await request.app.state.db.detection_coverage_gaps.update_one(
            {
                "gap_type": f"wazuh_bridge_{event.event_type.lower()}",
                "tenant_id": None,
                "event_uid": event.event_uid,
                "ruleset_version": batch.ruleset_version,
            },
            {
                "$setOnInsert": {
                    "created_at": now,
                    "source_collection": "detection_engine_health_events",
                    "connector_id": batch.connector_id,
                    "engine_instance_id": batch.engine_instance_id,
                },
                "$set": {
                    "last_seen_at": event.last_seen_at,
                    "status": "open",
                    "reason_code": event.event_type,
                    "severity": event.severity,
                    "occurrence_count": event.occurrence_count,
                },
            },
            upsert=True,
        )
        accepted.append(event.event_uid)

    await request.app.state.db.detection_engine_connectors.update_one(
        {
            "connector_id": batch.connector_id,
            "engine_instance_id": batch.engine_instance_id,
        },
        {
            "$set": {
                "last_health_at": now,
                "last_health_state": batch.state,
                "registry_sha256": batch.registry_sha256,
                "last_health_snapshot": {
                    "input_spool_bytes": batch.input_spool_bytes,
                    "candidate_spool_bytes": batch.candidate_spool_bytes,
                    "retry_records": batch.retry_records,
                    "alert_file_lag_bytes": batch.alert_file_lag_bytes,
                },
                "updated_at": now,
            }
        },
    )
    receipt = BridgeHealthReceipt(
        batch_id=batch.batch_id,
        connector_id=batch.connector_id,
        accepted_event_uids=accepted,
    )
    response_body = orjson.dumps(
        receipt.model_dump(mode="json", by_alias=True),
        option=orjson.OPT_SORT_KEYS,
    )
    headers = build_signed_headers(
        secret=settings.wazuh_candidate_signing_secret,
        connector_id=settings.wazuh_connector_id,
        body=response_body,
    )
    return Response(content=response_body, media_type="application/json", headers=headers)
