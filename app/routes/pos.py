import logging
import orjson
from fastapi import APIRouter, HTTPException, Depends, Request
from fastapi.responses import ORJSONResponse
from datetime import datetime, timezone
from typing import Any, Literal
from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.utils.rate_limiter import redis_ingest_rate_limit
from app.routes.auth import verify_agent_token

logger = logging.getLogger("fbr_pos")
router = APIRouter()

RAW_LOGS_QUEUE = "raw_logs_queue"
MAX_INGEST_BODY_BYTES = 5 * 1024 * 1024
MAX_POS_EVENTS_PER_REQUEST = 500


class PosAuditEvent(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    event_id: Literal["FBR-INV-DEL", "FBR-INV-MOD"]
    event_uid: str = Field(min_length=8, max_length=200)
    invoice_id: str = Field(min_length=1, max_length=200)
    timestamp: datetime
    actor: str = Field(min_length=1, max_length=200)
    source_system: str = Field(min_length=1, max_length=200)
    reason: str | None = Field(default=None, max_length=2000)
    before_hash: str | None = None
    after_hash: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("before_hash", "after_hash")
    @classmethod
    def validate_sha256(cls, value: str | None):
        if value is None:
            return value
        normalized = value.strip().lower()
        if len(normalized) != 64 or any(char not in "0123456789abcdef" for char in normalized):
            raise ValueError("hash fields must be 64-character SHA-256 hex strings")
        return normalized

    @field_validator("timestamp")
    @classmethod
    def require_timezone(cls, value: datetime):
        if value.tzinfo is None:
            raise ValueError("timestamp must include a timezone")
        return value.astimezone(timezone.utc)

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

        if isinstance(raw_payload, dict) and "payload" in raw_payload:
            if set(raw_payload) != {"payload"}:
                raise HTTPException(status_code=422, detail="Envelope may contain only the payload field")
            events_data = raw_payload.get("payload", [])
        else:
            events_data = raw_payload
        raw_events = [events_data] if isinstance(events_data, dict) else events_data
        if not isinstance(raw_events, list):
            raise HTTPException(status_code=422, detail="Payload must be an event, a list, or an object containing payload")
        if len(raw_events) > MAX_POS_EVENTS_PER_REQUEST:
            raise HTTPException(status_code=413, detail=f"Maximum {MAX_POS_EVENTS_PER_REQUEST} POS events per request")

        redis = request.app.state.redis
        if not redis:
            raise HTTPException(status_code=503, detail="Redis unavailable for ingest queue")

        queued_count = 0
        async with redis.pipeline(transaction=True) as pipe:
            for event in raw_events:
                if not isinstance(event, dict):
                    raise HTTPException(status_code=422, detail="Every POS event must be an object")

                try:
                    validated = PosAuditEvent.model_validate(event)
                except Exception as exc:
                    errors = exc.errors() if hasattr(exc, "errors") else [{"msg": str(exc)}]
                    raise HTTPException(status_code=422, detail=errors) from exc

                event_data = validated.model_dump(mode="json")
                event_data["tenant_id"] = verified_tenant_id
                event_data["agent_id"] = verified_agent_id
                event_data["type"] = "fbr_pos"
                event_data["event_type"] = "fbr_pos"
                event_data["source_ip"] = request.client.host if request.client else "unknown"
                event_data["user"] = validated.actor
                event_data["message"] = validated.reason or (
                    f"{validated.event_id} for invoice {validated.invoice_id}"
                )
                event_data["processed_data"] = {
                    "invoice_id": validated.invoice_id,
                    "actor": validated.actor,
                    "source_system": validated.source_system,
                    "reason": validated.reason,
                    "before_hash": validated.before_hash,
                    "after_hash": validated.after_hash,
                    "metadata": validated.metadata,
                }
                event_data["raw_event_data"] = validated.model_dump(mode="json")
                event_data["agent_signature"] = None

                payload_to_stream = {"payload": orjson.dumps(event_data).decode("utf-8")}
                
                await pipe.xadd(
                    RAW_LOGS_QUEUE,
                    payload_to_stream,
                )
                queued_count += 1

            if queued_count > 0:
                await pipe.execute()

        if queued_count == 0:
            raise HTTPException(status_code=400, detail="No POS events were supplied")

        return ORJSONResponse(
            {
                "status": "success",
                "queued": queued_count,
                "message": f"Successfully queued {queued_count} FBR POS events.",
            },
            status_code=202,
        )
    except HTTPException:
        raise
    except Exception as exc:
        logger.error("FBR POS ingestion error: %s", exc)
        raise HTTPException(status_code=500, detail="Failed to queue POS logs")
