import hashlib
import logging
import math
import re
import time
import orjson
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from fastapi import APIRouter, HTTPException, Depends, Header, Request
from fastapi.responses import ORJSONResponse
from datetime import datetime, timezone
from typing import Any, Literal
from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.utils.rate_limiter import redis_ingest_rate_limit
from app.routes.auth import verify_agent_token
from app.database import get_db
from app.routes.ingest_pulse import _enforce_daily_ingest_quota, _enforce_raw_stream_capacity
from app.utils.agent_crypto import AgentEventSignatureError, public_key_id
from app.utils.source_provenance import apply_source_provenance
from app.utils.source_evidence import (
    SourceEvidenceConflict,
    persist_source_envelope,
    publish_source_outbox,
)
from app.utils.fbr_retention import tenant_fbr_retention_metadata

logger = logging.getLogger("fbr_pos")
router = APIRouter()

RAW_LOGS_QUEUE = "raw_logs_queue"
MAX_INGEST_BODY_BYTES = 5 * 1024 * 1024
MAX_POS_EVENTS_PER_REQUEST = 500
POS_NONCE_TTL_SECONDS = 300
POS_SIGNATURE_VERSION = "ed25519-http-body-v1"
_NONCE_PATTERN = re.compile(r"^[A-Za-z0-9_-]{16,128}$")


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
    x_warsoc_signature: str = Header(..., alias="X-WarSOC-Signature"),
    agent_context: dict = Depends(verify_agent_token),
    db=Depends(get_db),
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

        signature_hex = str(x_warsoc_signature or "").strip().lower()
        public_key_pem = str(agent_context.get("public_key") or "")
        try:
            if len(signature_hex) != 128 or any(ch not in "0123456789abcdef" for ch in signature_hex):
                raise ValueError("invalid signature encoding")
            public_key = serialization.load_pem_public_key(public_key_pem.encode("utf-8"))
            if not isinstance(public_key, ed25519.Ed25519PublicKey):
                raise ValueError("invalid signing key type")
            public_key.verify(bytes.fromhex(signature_hex), bytes(buffer))
        except (InvalidSignature, TypeError, ValueError, AgentEventSignatureError) as exc:
            logger.warning(
                "Rejected unsigned or invalid POS request: agent_id=%s",
                verified_agent_id,
            )
            raise HTTPException(status_code=401, detail="POS request signature verification failed") from exc
        except Exception as exc:
            logger.warning(
                "Rejected unreadable POS signing key: agent_id=%s",
                verified_agent_id,
            )
            raise HTTPException(status_code=401, detail="POS request signature verification failed") from exc

        try:
            raw_payload = orjson.loads(buffer)
        except orjson.JSONDecodeError as exc:
            raise HTTPException(status_code=400, detail="Invalid JSON payload") from exc

        if not isinstance(raw_payload, dict) or set(raw_payload) != {"nonce", "timestamp", "payload"}:
            raise HTTPException(
                status_code=422,
                detail="Envelope must contain only nonce, timestamp, and payload",
            )

        nonce = str(raw_payload.get("nonce") or "")
        timestamp = raw_payload.get("timestamp")
        if not _NONCE_PATTERN.fullmatch(nonce):
            raise HTTPException(status_code=422, detail="Invalid request nonce")
        if isinstance(timestamp, bool) or not isinstance(timestamp, (int, float)) or not math.isfinite(timestamp):
            raise HTTPException(status_code=422, detail="Invalid request timestamp")
        if abs(time.time() - float(timestamp)) > POS_NONCE_TTL_SECONDS:
            raise HTTPException(status_code=401, detail="POS request timestamp outside the allowed window")

        events_data = raw_payload.get("payload")
        raw_events = [events_data] if isinstance(events_data, dict) else events_data
        if not isinstance(raw_events, list):
            raise HTTPException(status_code=422, detail="Payload must be an event or a list of events")
        if len(raw_events) > MAX_POS_EVENTS_PER_REQUEST:
            raise HTTPException(status_code=413, detail=f"Maximum {MAX_POS_EVENTS_PER_REQUEST} POS events per request")

        redis = request.app.state.redis
        if not redis:
            raise HTTPException(status_code=503, detail="Redis unavailable for ingest queue")

        payload_hash = hashlib.sha256(bytes(buffer)).hexdigest()
        signing_key_id = public_key_id(public_key_pem)
        tenant_retention = await db.tenants.find_one(
            {"tenant_id": verified_tenant_id},
            {"_id": 0, "retention_days": 1},
        )
        retention_metadata = tenant_fbr_retention_metadata(
            (tenant_retention or {}).get("retention_days")
        )

        stream_payloads = []
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
            event_data.update({
                "agent_signature": signature_hex,
                "payload_hash": payload_hash,
                "signature_version": POS_SIGNATURE_VERSION,
                "signature_algorithm": "Ed25519",
                "signing_key_id": signing_key_id,
                "signature_verified": True,
                "source_assurance": "agent_signed",
                "signature_verification_status": "verified",
                "signature_verified_at": datetime.now(timezone.utc).isoformat(),
                "source_envelope_uid": nonce,
                "source_envelope_collection": "source_envelopes_fbr",
                "source_envelope_state": "COMMITTED",
            })
            event_data.update(retention_metadata)
            apply_source_provenance(event_data)

            stream_payloads.append(orjson.dumps(event_data).decode("utf-8"))

        if not stream_payloads:
            raise HTTPException(status_code=400, detail="No POS events were supplied")

        stream_bytes = sum(len(payload.encode("utf-8")) for payload in stream_payloads)
        await _enforce_raw_stream_capacity(
            redis,
            incoming_entries=len(stream_payloads),
            incoming_stream_bytes=stream_bytes,
            incoming_redis_bytes=stream_bytes,
        )

        nonce_key = f"warsoc:pos_nonce:{verified_agent_id}:{nonce}"
        try:
            nonce_claimed = await redis.set(
                nonce_key,
                f"processing:{payload_hash}",
                ex=POS_NONCE_TTL_SECONDS,
                nx=True,
            )
        except Exception as exc:
            raise HTTPException(status_code=503, detail="Replay protection unavailable") from exc
        if not nonce_claimed:
            existing_hash = await redis.get(nonce_key)
            if isinstance(existing_hash, bytes):
                existing_hash = existing_hash.decode("utf-8", errors="replace")
            if str(existing_hash) != f"processing:{payload_hash}":
                raise HTTPException(status_code=409, detail="POS request replay detected")

        if nonce_claimed:
            try:
                await _enforce_daily_ingest_quota(redis, verified_tenant_id, len(buffer), db)
            except Exception:
                await redis.delete(nonce_key)
                raise

        outbox_uids = await persist_source_envelope(
            db,
            tenant_id=verified_tenant_id,
            source_principal_type="windows_agent",
            source_principal_id=verified_agent_id,
            source_channel="fbr_pos",
            source_envelope_uid=nonce,
            source_payload=bytes(buffer),
            dispatch_events=[
                {
                    "event_uid": str(event.get("event_uid")),
                    "serialized_payload": serialized_payload,
                    "target_streams": [RAW_LOGS_QUEUE],
                }
                for event, serialized_payload in zip(raw_events, stream_payloads)
            ],
            retention_class="FBR",
            auth_metadata={
                "scheme": POS_SIGNATURE_VERSION,
                "signature_algorithm": "Ed25519",
                "signature": signature_hex,
                "payload_hash": payload_hash,
                "signing_key_id": signing_key_id,
                "verification_version": "pos-http-body-v1",
            },
            source_timestamp=raw_payload.get("timestamp"),
            retention_metadata=retention_metadata,
        )
        await redis.set(
            nonce_key,
            f"completed:{payload_hash}",
            xx=True,
            ex=POS_NONCE_TTL_SECONDS,
        )
        published_count = await publish_source_outbox(
            db,
            redis,
            outbox_uids=outbox_uids,
            limit=len(outbox_uids),
        )
        queued_count = len(outbox_uids)

        return ORJSONResponse(
            {
                "status": "success",
                "queued": queued_count,
                "dispatch_published": published_count,
                "dispatch_pending": queued_count - published_count,
                "message": f"Durably accepted {queued_count} FBR POS events.",
            },
            status_code=202,
        )
    except SourceEvidenceConflict as exc:
        logger.warning("[SECURITY] POS source evidence identity conflict: agent=%s", locals().get("verified_agent_id"))
        raise HTTPException(status_code=409, detail="Source evidence identity conflict") from exc
    except HTTPException:
        raise
    except Exception as exc:
        if "maxmemory" in str(exc).lower() or "out of memory" in str(exc).lower():
            logger.error("Redis rejected POS ingest at its memory ceiling")
            raise HTTPException(
                status_code=503,
                detail="Ingest queue is under pressure. Agent must retain and retry the batch.",
            ) from exc
        logger.error("FBR POS ingestion error: %s", exc)
        raise HTTPException(status_code=500, detail="Failed to queue POS logs")
