import logging
import orjson
from fastapi import APIRouter, HTTPException, Depends, Request
from fastapi.responses import ORJSONResponse
from datetime import datetime, timezone
import uuid

from app.utils.rate_limiter import redis_ingest_rate_limit
from app.routes.auth import verify_agent_token

logger = logging.getLogger("fbr_pos")
router = APIRouter()

RAW_LOGS_QUEUE = "raw_logs_queue"
RAW_LOGS_QUEUE_MAXLEN = 100000
MAX_INGEST_BODY_BYTES = 5 * 1024 * 1024

@router.post("/ingest", status_code=202, response_class=ORJSONResponse)
async def ingest_pos_logs(
    request: Request,
    agent_context: dict = Depends(verify_agent_token),
    _rate_limit=Depends(redis_ingest_rate_limit)
):
    try:
        verified_tenant_id = agent_context["tenant_id"]
        verified_agent_id = agent_context["agent_id"]

        buffer = bytearray()
        async for chunk in request.stream():
            if not chunk:
                continue
            buffer.extend(chunk)
            if len(buffer) > MAX_INGEST_BODY_BYTES:
                raise HTTPException(status_code=413, detail="Payload too large")

        if not buffer:
            raise HTTPException(status_code=400, detail="Invalid JSON payload")

        try:
            raw_payload = orjson.loads(buffer)
        except orjson.JSONDecodeError as exc:
            raise HTTPException(status_code=400, detail="Invalid JSON payload") from exc

        events_data = raw_payload.get("payload", []) if isinstance(raw_payload, dict) and "payload" in raw_payload else raw_payload
        raw_events = [events_data] if isinstance(events_data, dict) else events_data

        redis = request.app.state.redis
        if not redis:
            raise HTTPException(status_code=503, detail="Redis unavailable for ingest queue")

        queued_count = 0
        async with redis.pipeline(transaction=True) as pipe:
            for event in raw_events:
                if not isinstance(event, dict):
                    continue
                
                # FBR POS events must have specific event IDs
                event_id = str(event.get("event_id", "")).strip().upper()
                if event_id not in ("FBR-INV-DEL", "FBR-INV-MOD"):
                    continue

                event.setdefault("timestamp", datetime.now(timezone.utc).isoformat())
                event["tenant_id"] = verified_tenant_id
                event["agent_id"] = verified_agent_id
                event["event_uid"] = event.get("event_uid") or uuid.uuid4().hex
                event["type"] = "fbr_pos"
                event.pop("agent_hmac_signature", None)
                event["agent_signature"] = None

                payload_to_stream = {"payload": orjson.dumps(event).decode("utf-8")}
                
                await pipe.xadd(
                    RAW_LOGS_QUEUE,
                    payload_to_stream,
                    maxlen=RAW_LOGS_QUEUE_MAXLEN,
                    approximate=True,
                )
                queued_count += 1

            if queued_count > 0:
                await pipe.execute()

        if queued_count == 0:
            raise HTTPException(status_code=400, detail="No valid FBR POS events found in payload")

        return ORJSONResponse({
            "status": "success",
            "queued": queued_count,
            "message": f"Successfully queued {queued_count} FBR POS events.",
        })
    except HTTPException:
        raise
    except Exception as exc:
        logger.error("FBR POS ingestion error: %s", exc)
        raise HTTPException(status_code=500, detail="Failed to queue POS logs")
