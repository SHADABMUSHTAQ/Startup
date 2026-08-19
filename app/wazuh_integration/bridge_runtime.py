"""Private Compute-B bridge between WarSOC dispatch and Wazuh alerts."""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import secrets
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import httpx
import orjson
from fastapi import FastAPI, HTTPException, Request, Response

from app.wazuh_integration.bridge_config import BridgeSettings
from app.wazuh_integration.bridge_spool import BridgeSpool, SpoolCapacityError
from app.wazuh_integration.contracts import (
    BridgeHealthBatch,
    BridgeHealthEvent,
    BridgeHealthReceipt,
    DetectionCandidate,
    DetectionCandidateBatch,
    DetectionCandidateReceipt,
    DetectionInput,
    DetectionInputBatch,
    DetectionInputReceipt,
    RejectedDispatch,
)
from app.wazuh_integration.security import (
    ConnectorBodyTooLarge,
    ConnectorSecurityError,
    build_mtls_client_context,
    build_signed_headers,
    read_bounded_request_body,
    verify_signed_request,
)
from app.wazuh_integration.registry import validate_registry_document


logger = logging.getLogger("warsoc.wazuh-bridge")
CHECKPOINT_NAME = "wazuh-alerts-json-v1"


def _batch_id() -> str:
    return f"WZB_{secrets.token_hex(16).upper()}"


def _load_rule_registry(settings: BridgeSettings) -> dict[str, dict[str, Any]]:
    raw = settings.rule_registry_path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != settings.rule_registry_sha256:
        raise RuntimeError("Wazuh rule registry hash mismatch")
    document = json.loads(raw)
    if document.get("ruleset_version") != settings.ruleset_version:
        raise RuntimeError("Wazuh rule registry version mismatch")
    try:
        return validate_registry_document(document)
    except ValueError as exc:
        raise RuntimeError(str(exc)) from exc


def _wazuh_line(item: DetectionInput) -> bytes:
    record: dict[str, Any] = {
        "warsoc_schema": "warsoc.wazuh-local-input/v1",
        "warsoc_dispatch_uid": item.dispatch_uid,
        "warsoc_event_uid": item.event_uid,
        "warsoc_event_id": item.event_id,
        "warsoc_source_family": item.source_family,
        "warsoc_dispatch_mode": item.dispatch_mode,
        "warsoc_original_event_time": item.original_event_time.isoformat(),
        "warsoc_correlation_key_version": item.correlation_key_version,
    }
    for name, value in item.correlation_keys.model_dump().items():
        if value:
            record[f"warsoc_{name}"] = value
    for name, value in item.security_fields.items():
        record[f"warsoc_field_{name}"] = value
    return orjson.dumps(record, option=orjson.OPT_SORT_KEYS) + b"\n"


async def _send_to_wazuh(settings: BridgeSettings, payload: bytes) -> None:
    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(settings.wazuh_host, settings.wazuh_port),
        timeout=5,
    )
    del reader
    try:
        writer.write(payload)
        await asyncio.wait_for(writer.drain(), timeout=5)
    finally:
        writer.close()
        await writer.wait_closed()


async def drain_input_spool(spool: BridgeSpool, settings: BridgeSettings) -> int:
    sent = 0
    for row in spool.pending("input_spool", "dispatch_uid", settings.max_batch_events):
        try:
            item = DetectionInput.model_validate_json(row["payload"])
            if item.dispatch_uid != row["identity"]:
                raise ValueError("input spool identity mismatch")
            await _send_to_wazuh(settings, _wazuh_line(item))
            spool.mark_complete("input_spool", "dispatch_uid", row["identity"])
            spool.increment_counter("wazuh_inputs_handed_off")
            sent += 1
        except Exception as exc:
            spool.increment_counter("wazuh_input_handoff_failures")
            spool.mark_retry(
                "input_spool",
                "dispatch_uid",
                row["identity"],
                str(exc),
                base_seconds=settings.retry_base_seconds,
                max_seconds=settings.retry_max_seconds,
            )
            break
    return sent


def _file_identity(path: Path) -> str:
    stat = path.stat()
    return f"{stat.st_dev}:{stat.st_ino}"


def _find_rotated_file(current: Path, file_identity: str) -> Path | None:
    for candidate in current.parent.glob(f"{current.name}*"):
        try:
            if candidate.is_file() and _file_identity(candidate) == file_identity:
                return candidate
        except OSError:
            continue
    return None


def _extract_dispatch_uid(alert: dict[str, Any]) -> str | None:
    data = alert.get("data") if isinstance(alert.get("data"), dict) else {}
    value = data.get("warsoc_dispatch_uid")
    if value:
        return str(value)
    full_log = alert.get("full_log")
    if isinstance(full_log, str) and full_log.lstrip().startswith("{"):
        try:
            parsed = json.loads(full_log)
            value = parsed.get("warsoc_dispatch_uid")
            return str(value) if value else None
        except ValueError:
            return None
    return None


def _candidate_from_alert(
    alert: dict[str, Any],
    registry: dict[str, dict[str, Any]],
    settings: BridgeSettings,
) -> DetectionCandidate | None:
    wazuh_rule = alert.get("rule") if isinstance(alert.get("rule"), dict) else {}
    rule_id = str(wazuh_rule.get("id") or "").strip()
    rule = registry.get(rule_id)
    if rule is None:
        return None
    dispatch_uid = _extract_dispatch_uid(alert)
    agent_info = alert.get("agent") if isinstance(alert.get("agent"), dict) else {}
    wazuh_agent_id = str(agent_info.get("id") or "").strip() or None
    wazuh_agent_name = str(agent_info.get("name") or "").strip() or None

    if not dispatch_uid and not wazuh_agent_id:
        raise ValueError("approved Wazuh alert is missing both WarSOC dispatch lineage and Wazuh agent identity")

    alert_id = str(alert.get("id") or "").strip()
    if not alert_id:
        alert_id = hashlib.sha256(
            orjson.dumps(alert, option=orjson.OPT_SORT_KEYS)
        ).hexdigest()

    win_data = (alert.get("data") or {}).get("win") if isinstance(alert.get("data"), dict) else {}
    win_system = win_data.get("system", {}) if isinstance(win_data, dict) else {}
    windows_event_id = str(win_system.get("eventID") or "").strip() or None
    windows_event_record_id = str(win_system.get("eventRecordID") or "").strip() or None
    windows_channel = str(win_system.get("channel") or win_system.get("Channel") or "").strip() or None

    win_eventdata = win_data.get("eventdata", {}) if isinstance(win_data, dict) else {}
    selected_fields: dict[str, Any] = {}
    if isinstance(win_eventdata, dict):
        for k, v in win_eventdata.items():
            if isinstance(v, (str, int, float, bool)) and len(selected_fields) < 32:
                selected_fields[str(k)[:64]] = v

    mitre_list = rule.get("mitre_ids") or []
    if not mitre_list:
        rule_mitre = wazuh_rule.get("mitre", {}).get("id") if isinstance(wazuh_rule.get("mitre"), dict) else []
        if isinstance(rule_mitre, list):
            mitre_list = [str(m).strip().upper() for m in rule_mitre if str(m).strip()]

    return DetectionCandidate(
        connector_id=settings.connector_id,
        engine_instance_id=settings.engine_instance_id,
        engine_version=settings.engine_version,
        ruleset_version=settings.ruleset_version,
        engine_alert_id=alert_id,
        engine_rule_id=rule_id,
        engine_rule_level=int(wazuh_rule.get("level") or 0),
        engine_detected_at=alert.get("timestamp"),
        trigger_dispatch_uid=dispatch_uid,
        wazuh_agent_id=wazuh_agent_id,
        wazuh_agent_name=wazuh_agent_name,
        windows_event_id=windows_event_id,
        windows_event_record_id=windows_event_record_id,
        windows_channel=windows_channel,
        selected_security_fields=selected_fields,
        engine_reported_category=str(rule["category"]),
        engine_reported_mitre_ids=list(mitre_list),
        engine_context={
            "wazuh_timestamp": str(alert.get("timestamp") or "")[:128],
            "wazuh_manager": str((alert.get("manager") or {}).get("name") or "")[:128],
        },
    )


def _process_alert_file(
    path: Path,
    offset: int,
    file_identity: str,
    spool: BridgeSpool,
    settings: BridgeSettings,
    registry: dict[str, dict[str, Any]],
    *,
    max_lines: int,
) -> tuple[int, int]:
    processed = 0
    with path.open("rb") as handle:
        handle.seek(offset)
        while processed < max_lines:
            line_start = handle.tell()
            line = handle.readline(settings.max_body_bytes + 1)
            if not line:
                break
            if len(line) > settings.max_body_bytes:
                while line and not line.endswith(b"\n"):
                    line = handle.readline(settings.max_body_bytes + 1)
                spool.health_event("ALERT_LINE_TOO_LARGE", f"{path}:{line_start}")
                spool.increment_counter("wazuh_alert_lines_oversize")
                offset = handle.tell()
                spool.save_checkpoint(
                    CHECKPOINT_NAME,
                    file_identity,
                    str(path),
                    offset,
                )
                processed += 1
                continue
            if not line.endswith(b"\n"):
                break
            spool.increment_counter("wazuh_alert_lines_seen")
            try:
                alert = orjson.loads(line)
                candidate = _candidate_from_alert(alert, registry, settings)
                if candidate is not None:
                    payload = orjson.dumps(
                        candidate.model_dump(mode="json", by_alias=True),
                        option=orjson.OPT_SORT_KEYS,
                    )
                    delivery_uid = "\x00".join(
                        (
                            candidate.engine_instance_id,
                            candidate.engine_alert_id,
                            candidate.ruleset_version,
                        )
                    )
                    outcome = spool.accept_candidate(
                        delivery_uid,
                        payload,
                        settings.candidate_spool_max_bytes,
                        expires_epoch=int(candidate.engine_detected_at.timestamp())
                        + settings.candidate_record_ttl_seconds,
                    )
                    spool.increment_counter(
                        "wazuh_candidates_spooled"
                        if outcome == "accepted"
                        else "wazuh_candidate_spool_duplicates"
                    )
                else:
                    spool.increment_counter("wazuh_unapproved_rule_matches")
            except SpoolCapacityError:
                spool.health_event("CANDIDATE_SPOOL_SATURATED", f"{path}:{line_start}")
                spool.increment_counter("wazuh_candidate_spool_refusals")
                break
            except Exception as exc:
                spool.health_event("ALERT_PARSE_OR_LINEAGE_FAILURE", f"{path}:{line_start}:{exc}")
                spool.increment_counter("wazuh_alert_parse_failures")
            offset = handle.tell()
            spool.save_checkpoint(
                CHECKPOINT_NAME,
                file_identity,
                str(path),
                offset,
                last_record_start=line_start,
                last_record_sha256=hashlib.sha256(line).hexdigest(),
            )
            processed += 1
    return offset, processed


def tail_alerts_once(
    spool: BridgeSpool,
    settings: BridgeSettings,
    registry: dict[str, dict[str, Any]],
    *,
    max_lines: int = 500,
) -> int:
    current = settings.wazuh_alerts_path
    current_identity = _file_identity(current)
    checkpoint = spool.checkpoint(CHECKPOINT_NAME)
    if checkpoint is None:
        initial_offset = current.stat().st_size if settings.alerts_initial_position == "end" else 0
        spool.save_checkpoint(CHECKPOINT_NAME, current_identity, str(current), initial_offset)
        return 0

    source = Path(checkpoint["file_path"])
    offset = int(checkpoint["byte_offset"])
    expected_identity = str(checkpoint["file_identity"])
    if expected_identity != current_identity:
        rotated = _find_rotated_file(current, expected_identity)
        if rotated is not None:
            rotated_offset, processed = _process_alert_file(
                rotated,
                offset,
                expected_identity,
                spool,
                settings,
                registry,
                max_lines=max_lines,
            )
            if processed >= max_lines or rotated_offset < rotated.stat().st_size:
                return processed
        else:
            spool.health_event(
                "ALERT_ROTATION_GAP",
                f"Previous alerts.json identity {expected_identity} is no longer available",
            )
            spool.increment_counter("wazuh_alert_rotation_gaps")
        spool.save_checkpoint(CHECKPOINT_NAME, current_identity, str(current), 0)
        source = current
        offset = 0
        expected_identity = current_identity
    elif not source.exists() or _file_identity(source) != expected_identity:
        source = current

    source_size = source.stat().st_size
    if offset < 0 or offset > source_size:
        spool.health_event(
            "ALERT_FILE_TRUNCATED",
            "The Wazuh alert file became shorter than the committed checkpoint",
            severity="critical",
        )
        spool.increment_counter("wazuh_alert_file_truncations")
        spool.save_checkpoint(CHECKPOINT_NAME, expected_identity, str(source), 0)
        offset = 0
    else:
        last_start = checkpoint.get("last_record_start")
        last_digest = checkpoint.get("last_record_sha256")
        if last_start is not None and last_digest and 0 <= int(last_start) < offset:
            with source.open("rb") as handle:
                handle.seek(int(last_start))
                committed_line = handle.read(offset - int(last_start))
            if hashlib.sha256(committed_line).hexdigest() != last_digest:
                spool.health_event(
                    "ALERT_CHECKPOINT_ROLLBACK",
                    "Committed Wazuh alert bytes no longer match the checkpoint digest",
                    severity="critical",
                )
                spool.increment_counter("wazuh_alert_checkpoint_rollbacks")
                spool.save_checkpoint(CHECKPOINT_NAME, expected_identity, str(source), 0)
                offset = 0

    _, processed = _process_alert_file(
        source,
        offset,
        expected_identity,
        spool,
        settings,
        registry,
        max_lines=max_lines,
    )
    return processed


async def export_candidates(spool: BridgeSpool, settings: BridgeSettings) -> int:
    rows = spool.pending("candidate_spool", "delivery_uid", settings.max_batch_events)
    if not rows:
        return 0
    candidates: list[DetectionCandidate] = []
    selected: list[dict[str, Any]] = []
    for row in rows:
        candidate = DetectionCandidate.model_validate_json(row["payload"])
        trial = DetectionCandidateBatch(
            batch_id="WZB_00000000000000000000000000000000",
            connector_id=settings.connector_id,
            created_at=datetime.now(timezone.utc),
            candidates=[*candidates, candidate],
        )
        trial_body = orjson.dumps(trial.model_dump(mode="json", by_alias=True))
        if len(trial_body) > settings.max_body_bytes:
            break
        candidates.append(candidate)
        selected.append(row)
    if not candidates:
        raise ValueError("single candidate exceeds bridge body limit")

    batch = DetectionCandidateBatch(
        batch_id=_batch_id(),
        connector_id=settings.connector_id,
        created_at=datetime.now(timezone.utc),
        candidates=candidates,
    )
    body = orjson.dumps(batch.model_dump(mode="json", by_alias=True), option=orjson.OPT_SORT_KEYS)
    headers = build_signed_headers(
        secret=settings.candidate_signing_secret,
        connector_id=settings.connector_id,
        body=body,
    )
    try:
        tls_context = build_mtls_client_context(
            ca_file=settings.candidate_ca_file,
            cert_file=settings.candidate_cert_file,
            key_file=settings.candidate_key_file,
        )
        async with httpx.AsyncClient(
            verify=tls_context,
            timeout=10,
            trust_env=False,
        ) as client:
            response = await client.post(
                settings.candidate_url,
                content=body,
                headers={**headers, "Content-Type": "application/json"},
            )
        response.raise_for_status()
        if len(response.content) > settings.max_body_bytes:
            raise ValueError("candidate receipt exceeds byte limit")
        verify_signed_request(
            secret=settings.candidate_signing_secret,
            expected_connector_id=settings.connector_id,
            headers=response.headers,
            body=response.content,
        )
        receipt = DetectionCandidateReceipt.model_validate_json(response.content)
        if receipt.batch_id != batch.batch_id or receipt.connector_id != batch.connector_id:
            raise ValueError("candidate receipt identity mismatch")
        outcomes = {item.engine_alert_id: item for item in receipt.outcomes}
        for row, candidate in zip(selected, candidates):
            outcome = outcomes.get(candidate.engine_alert_id)
            if outcome is None:
                raise ValueError("candidate omitted from receipt")
            spool.mark_complete("candidate_spool", "delivery_uid", row["identity"])
            spool.increment_counter("wazuh_candidates_exported")
            if outcome.outcome == "quarantined":
                spool.increment_counter("wazuh_candidates_quarantined")
        return len(candidates)
    except Exception as exc:
        for row in selected:
            spool.mark_retry(
                "candidate_spool",
                "delivery_uid",
                row["identity"],
                str(exc),
                base_seconds=settings.retry_base_seconds,
                max_seconds=settings.retry_max_seconds,
            )
        raise


def _bridge_health_snapshot(spool: BridgeSpool, settings: BridgeSettings) -> dict[str, Any]:
    stats = spool.stats()
    input_active = sum(value["bytes"] for value in stats["input_spool"].values())
    candidate_active = sum(value["bytes"] for value in stats["candidate_spool"].values())
    retry_records = sum(
        int(stats[table].get("retry", {}).get("count", 0))
        for table in ("input_spool", "candidate_spool")
    )
    alert_file_lag = 0
    alert_file_missing = not settings.wazuh_alerts_path.is_file()
    if not alert_file_missing:
        checkpoint = spool.checkpoint(CHECKPOINT_NAME)
        if checkpoint and str(checkpoint.get("file_identity")) == _file_identity(
            settings.wazuh_alerts_path
        ):
            alert_file_lag = max(
                0,
                settings.wazuh_alerts_path.stat().st_size
                - int(checkpoint.get("byte_offset") or 0),
            )
    degraded = (
        stats["unresolved_health_events"] > 0
        or retry_records > 0
        or input_active >= int(settings.input_spool_max_bytes * 0.9)
        or candidate_active >= int(settings.candidate_spool_max_bytes * 0.9)
        or alert_file_missing
    )
    return {
        "status": "degraded" if degraded else "healthy",
        "input_spool_bytes": input_active,
        "candidate_spool_bytes": candidate_active,
        "retry_records": retry_records,
        "alert_file_lag_bytes": alert_file_lag,
        "pending_health_exports": stats["pending_health_exports"],
        "counters": stats["counters"],
    }


async def export_health_events(
    spool: BridgeSpool,
    settings: BridgeSettings,
    *,
    force: bool = False,
) -> int:
    rows = spool.pending_health_events(settings.max_batch_events)
    snapshot = _bridge_health_snapshot(spool, settings)
    if not rows and not force and snapshot["status"] == "healthy":
        return 0
    events = [
        BridgeHealthEvent(
            event_uid=row["event_uid"],
            event_type=row["event_type"],
            severity=row["severity"],
            detail=row["detail"],
            occurrence_count=row["occurrence_count"],
            first_seen_at=row["created_at"],
            last_seen_at=row["last_seen_at"],
        )
        for row in rows
    ]
    batch = BridgeHealthBatch(
        batch_id=_batch_id(),
        connector_id=settings.connector_id,
        engine_instance_id=settings.engine_instance_id,
        engine_version=settings.engine_version,
        ruleset_version=settings.ruleset_version,
        registry_sha256=settings.rule_registry_sha256,
        created_at=datetime.now(timezone.utc),
        state=snapshot["status"],
        input_spool_bytes=snapshot["input_spool_bytes"],
        candidate_spool_bytes=snapshot["candidate_spool_bytes"],
        retry_records=snapshot["retry_records"],
        alert_file_lag_bytes=snapshot["alert_file_lag_bytes"],
        counters=snapshot["counters"],
        events=events,
    )
    body = orjson.dumps(batch.model_dump(mode="json", by_alias=True), option=orjson.OPT_SORT_KEYS)
    if len(body) > settings.max_body_bytes:
        raise ValueError("bridge health batch exceeds byte limit")
    headers = build_signed_headers(
        secret=settings.candidate_signing_secret,
        connector_id=settings.connector_id,
        body=body,
    )
    tls_context = build_mtls_client_context(
        ca_file=settings.candidate_ca_file,
        cert_file=settings.candidate_cert_file,
        key_file=settings.candidate_key_file,
    )
    async with httpx.AsyncClient(
        verify=tls_context,
        timeout=10,
        trust_env=False,
    ) as client:
        response = await client.post(
            settings.health_url,
            content=body,
            headers={**headers, "Content-Type": "application/json"},
        )
    response.raise_for_status()
    if len(response.content) > settings.max_body_bytes:
        raise ValueError("bridge health receipt exceeds byte limit")
    verify_signed_request(
        secret=settings.candidate_signing_secret,
        expected_connector_id=settings.connector_id,
        headers=response.headers,
        body=response.content,
    )
    receipt = BridgeHealthReceipt.model_validate_json(response.content)
    expected = {event.event_uid for event in events}
    if (
        receipt.batch_id != batch.batch_id
        or receipt.connector_id != batch.connector_id
        or set(receipt.accepted_event_uids) != expected
    ):
        raise ValueError("bridge health receipt identity mismatch")
    spool.mark_health_exported(receipt.accepted_event_uids)
    return len(events)


async def _background_loop(app: FastAPI) -> None:
    last_health_export = 0.0
    while True:
        try:
            app.state.spool.maintenance()
            await drain_input_spool(app.state.spool, app.state.settings)
            tail_alerts_once(app.state.spool, app.state.settings, app.state.registry)
            await export_candidates(app.state.spool, app.state.settings)
            now = asyncio.get_running_loop().time()
            force_health = now - last_health_export >= 30
            exported = await export_health_events(
                app.state.spool,
                app.state.settings,
                force=force_health,
            )
            if force_health or exported:
                last_health_export = now
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            logger.warning("Wazuh bridge cycle degraded: %s", exc)
        await asyncio.sleep(1)


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = BridgeSettings.from_env()
    spool = BridgeSpool(
        settings.spool_path,
        settings.spool_encryption_key,
        input_record_ttl_seconds=settings.live_event_max_age_seconds,
        candidate_record_ttl_seconds=settings.candidate_record_ttl_seconds,
        receipt_retention_seconds=settings.receipt_retention_seconds,
        health_retention_seconds=settings.health_retention_seconds,
    )
    registry = _load_rule_registry(settings)
    app.state.settings = settings
    app.state.spool = spool
    app.state.registry = registry
    task = asyncio.create_task(_background_loop(app))
    try:
        yield
    finally:
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)
        spool.close()


app = FastAPI(
    title="WarSOC Private Wazuh Bridge",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
    lifespan=lifespan,
)


@app.get("/health")
async def health(request: Request, response: Response):
    snapshot = _bridge_health_snapshot(
        request.app.state.spool,
        request.app.state.settings,
    )
    if snapshot["status"] == "degraded":
        response.status_code = 503
    return snapshot


@app.post("/api/v1/internal/detection-inputs")
async def receive_inputs(request: Request):
    settings: BridgeSettings = request.app.state.settings
    try:
        body = await read_bounded_request_body(request, max_bytes=settings.max_body_bytes)
    except ConnectorBodyTooLarge as exc:
        raise HTTPException(status_code=413, detail="Request rejected") from exc
    except ConnectorSecurityError as exc:
        raise HTTPException(status_code=400, detail="Request rejected") from exc
    try:
        nonce, received_at = verify_signed_request(
            secret=settings.dispatch_signing_secret,
            expected_connector_id=settings.connector_id,
            headers=request.headers,
            body=body,
        )
    except ConnectorSecurityError as exc:
        raise HTTPException(status_code=401, detail="Request rejected") from exc
    if not request.app.state.spool.remember_nonce(
        settings.connector_id,
        nonce,
        int(received_at.timestamp()) + 600,
    ):
        raise HTTPException(status_code=409, detail="Request rejected")
    try:
        batch = DetectionInputBatch.model_validate_json(body)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail="Request rejected") from exc
    if batch.connector_id != settings.connector_id:
        raise HTTPException(status_code=401, detail="Request rejected")

    accepted: list[str] = []
    duplicates: list[str] = []
    rejected: list[RejectedDispatch] = []
    for item in batch.inputs:
        item_payload = orjson.dumps(
            item.model_dump(mode="json", by_alias=True),
            option=orjson.OPT_SORT_KEYS,
        )
        try:
            live_expiry = item.original_event_time + timedelta(
                seconds=settings.live_event_max_age_seconds
            )
            if live_expiry <= received_at:
                request.app.state.spool.increment_counter(
                    "dispatch_input_live_expiry_rejections"
                )
                rejected.append(
                    RejectedDispatch(
                        dispatch_uid=item.dispatch_uid,
                        reason_code="LIVE_WINDOW_EXPIRED",
                    )
                )
                continue
            outcome = request.app.state.spool.accept_input(
                item.dispatch_uid,
                item_payload,
                settings.input_spool_max_bytes,
                expires_epoch=int(live_expiry.timestamp()),
            )
            (accepted if outcome == "accepted" else duplicates).append(item.dispatch_uid)
            request.app.state.spool.increment_counter(
                "dispatch_inputs_accepted"
                if outcome == "accepted"
                else "dispatch_input_duplicates"
            )
        except SpoolCapacityError:
            request.app.state.spool.increment_counter("dispatch_input_capacity_refusals")
            rejected.append(
                RejectedDispatch(dispatch_uid=item.dispatch_uid, reason_code="SPOOL_CAPACITY")
            )
        except ValueError:
            request.app.state.spool.increment_counter("dispatch_input_identity_rejections")
            rejected.append(
                RejectedDispatch(dispatch_uid=item.dispatch_uid, reason_code="IDENTITY_CONFLICT")
            )
    receipt = DetectionInputReceipt(
        batch_id=batch.batch_id,
        connector_id=batch.connector_id,
        accepted_dispatch_uids=accepted,
        duplicate_dispatch_uids=duplicates,
        rejected=rejected,
    )
    response_body = orjson.dumps(
        receipt.model_dump(mode="json", by_alias=True),
        option=orjson.OPT_SORT_KEYS,
    )
    response_headers = build_signed_headers(
        secret=settings.dispatch_signing_secret,
        connector_id=settings.connector_id,
        body=response_body,
    )
    return Response(content=response_body, media_type="application/json", headers=response_headers)
