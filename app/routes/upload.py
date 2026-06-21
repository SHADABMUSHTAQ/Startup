import os
import json
import csv
import re
import logging
import aiofiles
from pathlib import Path
from datetime import datetime, timezone
from fastapi import APIRouter, UploadFile, File, HTTPException, Depends, Request
from fastapi.responses import JSONResponse, Response, StreamingResponse
from bson import ObjectId
from slowapi import Limiter
from slowapi.util import get_remote_address

from app.database import get_db
from app.routes.auth import get_current_user
from app.config.config import get_settings, load_config

router = APIRouter()
logger = logging.getLogger("upload")
UPLOAD_DIR = "uploaded_files"
os.makedirs(UPLOAD_DIR, exist_ok=True)
MAX_UPLOAD_BYTES = 50 * 1024 * 1024  # 50 MB hard limit
settings = get_settings()
limiter = Limiter(key_func=get_remote_address, storage_uri=settings.redis_url)
ALLOWED_CSV_EXTENSIONS = {".csv"}
ALLOWED_CSV_CONTENT_TYPES = {
    "text/csv",
    "application/csv",
    "application/vnd.ms-excel",
    "text/plain",
}


def _load_runtime_config() -> dict:
    try:
        return load_config("config.json")
    except Exception:
        try:
            cfg_path = Path("app/config/config.json")
            with open(cfg_path, "r", encoding="utf-8") as fh:
                return json.load(fh)
        except Exception:
            return {}


_RUNTIME_CONFIG = _load_runtime_config()
_SOURCE_CLASSIFICATION = _RUNTIME_CONFIG.get("source_classification", {})
_EVENT_ID_MAP = _RUNTIME_CONFIG.get("event_id_map", {})
RAW_RETENTION_ANCHOR_FIELD = "_retention_ts"


def _build_retention_anchor(value: str) -> datetime:
    """Create a Date anchor used by Mongo TTL indexes."""
    if isinstance(value, datetime):
        dt = value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)

    if isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return parsed.astimezone(timezone.utc)
        except Exception:
            return datetime.now(timezone.utc)

    return datetime.now(timezone.utc)


def _resolve_request_ip(request: Request) -> str:
    forwarded_for = (request.headers.get("x-forwarded-for") or "").strip()
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    if request.client and request.client.host:
        return request.client.host
    return "unknown"


async def log_audit_action(
    db,
    user_id: str,
    action: str,
    target_file: str,
    tenant_id: str,
    ip_address: str = "unknown",
):
    tombstone = {
        "user": user_id,
        "tenant_id": tenant_id,
        "action": action,
        "target": target_file,
        "ip_address": ip_address,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    await db["system_audit"].insert_one(tombstone)

#  COLUMN NAME RESOLVER
COLUMN_ALIASES = {
    "timestamp": ["timestamp", "timestamp (utc)", "time", "date", "datetime", "event_time", "log_time", "created_at", "occurred_at"],
    "source_ip": ["source_ip", "src_ip", "ip", "ip_address", "sourceip", "source", "sourcedevice", "source_device", "host", "hostname", "src", "client_ip", "remote_ip"],
    "event_id": ["event_id", "eventid", "event", "id", "eid", "event_code", "signature_id"],
    "message": ["message", "msg", "description", "detail", "details", "log", "action", "commandline_or_target", "command", "commandline", "command_line", "activity", "info"],
    "severity": ["severity", "severityscore", "severity_score", "level", "priority", "risk", "status"],
    "user": ["user", "username", "actor", "account", "subject", "user_name", "account_name", "src_user", "dst_user"],
}

def resolve_columns(fieldnames):
    if not fieldnames:
        return {}
    lower_map = {col.strip().lower(): col for col in fieldnames}
    resolved = {}
    for standard, aliases in COLUMN_ALIASES.items():
        for alias in aliases:
            if alias in lower_map:
                resolved[standard] = lower_map[alias]
                break
    return resolved

def guess_columns_by_content(csv_lines: list, fieldnames: list, resolved: dict) -> dict:
    """Smart Fallback: If headers are missing, guess columns based on the actual data inside them."""
    if not csv_lines or not fieldnames:
        return resolved
        
    date_pattern = re.compile(r'\d{4}-\d{2}-\d{2}|\d{2}/\d{2}/\d{4}|\b(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\b', re.IGNORECASE)
    ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
    sev_pattern = re.compile(r'\b(critical|high|medium|low|info|warn|error|fatal|warning)\b', re.IGNORECASE)
    
    col_stats = {col: {'date': 0, 'ip': 0, 'sev': 0, 'length': 0} for col in fieldnames}
    rows_to_check = min(20, len(csv_lines))
    valid_rows = 0
    
    for row in csv_lines[:rows_to_check]:
        if not isinstance(row, dict): continue
        valid_rows += 1
        for col in fieldnames:
            val = str(row.get(col, '')).strip()
            if not val: continue
            if date_pattern.search(val): col_stats[col]['date'] += 1
            if ip_pattern.search(val): col_stats[col]['ip'] += 1
            if sev_pattern.search(val): col_stats[col]['sev'] += 1
            col_stats[col]['length'] += len(val)
            
    if valid_rows == 0: return resolved
    new_resolved = dict(resolved)
    
    if "timestamp" not in new_resolved:
        best_date = max(fieldnames, key=lambda c: col_stats[c]['date'])
        if col_stats[best_date]['date'] > 0: new_resolved["timestamp"] = best_date
            
    if "source_ip" not in new_resolved:
        best_ip = max(fieldnames, key=lambda c: col_stats[c]['ip'])
        if col_stats[best_ip]['ip'] > 0: new_resolved["source_ip"] = best_ip
            
    if "severity" not in new_resolved:
        best_sev = max(fieldnames, key=lambda c: col_stats[c]['sev'])
        if col_stats[best_sev]['sev'] > 0: new_resolved["severity"] = best_sev
            
    if "message" not in new_resolved:
        assigned = set(new_resolved.values())
        unassigned_cols = [c for c in fieldnames if c not in assigned and col_stats[c]['length'] > 0]
        if unassigned_cols:
            best_msg = max(unassigned_cols, key=lambda c: col_stats[c]['length'])
            new_resolved["message"] = best_msg

    return new_resolved

def get_field(row, resolved, standard, default=""):
    col = resolved.get(standard)
    if col:
        return row.get(col, default)
    return default

def is_csv_upload(file: UploadFile) -> bool:
    filename = (file.filename or "").strip().lower()
    if any(filename.endswith(ext) for ext in ALLOWED_CSV_EXTENSIONS):
        return True
    content_type = (file.content_type or "").strip().lower()
    return content_type in ALLOWED_CSV_CONTENT_TYPES

def analyze_log_context(event_id_int: int, msg_lower: str):
    """Return config-driven severity/source/compliance for uploaded logs."""
    severity = "INFO"
    source_type = "Syslog"
    compliance_tag = None

    event_id_cfg = _EVENT_ID_MAP.get(str(event_id_int), {})
    if event_id_cfg:
        severity = str(event_id_cfg.get("severity", severity)).upper()
        compliance_tag = event_id_cfg.get("compliance_tag")

    for src_name, src_cfg in _SOURCE_CLASSIFICATION.items():
        trigger_keywords = [str(k).lower() for k in src_cfg.get("trigger_keywords", [])]
        trigger_event_ids = {int(i) for i in src_cfg.get("trigger_event_ids", []) if str(i).isdigit()}

        id_match = event_id_int > 0 and event_id_int in trigger_event_ids
        keyword_match = any(k in msg_lower for k in trigger_keywords)
        if not (id_match or keyword_match):
            continue

        source_type = src_name

        severity_by_event_id = src_cfg.get("severity_by_event_id", {})
        if str(event_id_int) in severity_by_event_id:
            severity = str(severity_by_event_id[str(event_id_int)]).upper()
            break

        severity_by_keyword = src_cfg.get("severity_by_keyword", {})
        for pattern, sev in severity_by_keyword.items():
            if str(pattern).lower() in msg_lower:
                severity = str(sev).upper()
        break

    return severity, source_type, compliance_tag


def resolve_event_id_meaning(event_id_int: int) -> str:
    event_id_cfg = _EVENT_ID_MAP.get(str(event_id_int), {})
    event_type = str(event_id_cfg.get("event_type", "")).strip()
    if not event_type:
        return ""
    return event_type.replace("_", " ").title()


def _iter_clean_csv_lines(file_path: str):
    with open(file_path, "r", encoding="utf-8", errors="replace", newline="") as file_handle:
        for line in file_handle:
            yield line.replace("\x00", "")


def _build_csv_reader(file_path: str, delimiter: str = ","):
    reader = csv.DictReader(_iter_clean_csv_lines(file_path), delimiter=delimiter)
    if reader.fieldnames:
        reader.fieldnames = [field.strip() for field in reader.fieldnames if field]
    return reader


def _sample_csv_rows(file_path: str, delimiter: str = ",", limit: int = 20):
    reader = _build_csv_reader(file_path, delimiter=delimiter)
    sample_rows = []
    for row in reader:
        sample_rows.append(row)
        if len(sample_rows) >= limit:
            break
    return reader.fieldnames or [], sample_rows


def _detect_csv_structure(file_path: str):
    """Pick the delimiter that produces the most recognizable CSV structure."""
    best = (",", [], [])
    best_score = -1

    for delimiter in [",", ";", "\t"]:
        fieldnames, sample_rows = _sample_csv_rows(file_path, delimiter=delimiter)
        resolved = resolve_columns(fieldnames)
        resolved = guess_columns_by_content(sample_rows, fieldnames, resolved)

        score = len(resolved) * 10 + len(fieldnames or [])
        if len(fieldnames or []) < 2:
            score -= 20

        if score > best_score:
            best = (delimiter, fieldnames, sample_rows)
            best_score = score

    return best

@router.post("/analyze")
@limiter.limit("5/minute")
async def analyze_log_file(request: Request, file: UploadFile = File(...), db=Depends(get_db), current_user=Depends(get_current_user)):
    # Phase 4 policy: manual CSV backfills remain exempt from live /ingest/windows skew guard.
    try:
        raw_tenant_id = current_user.get("tenant_id", "")
        secure_tenant_id = re.sub(r'[^a-zA-Z0-9_-]', '', raw_tenant_id)

        if not is_csv_upload(file):
            raise HTTPException(status_code=400, detail="Please upload a CSV file. Supported format: .csv")
        
        file_id = str(os.urandom(12).hex())
        secure_original_name = os.path.basename(file.filename or "")
        safe_filename = f"WarSOC_{secure_tenant_id}_{file_id}_{secure_original_name}"
        file_path = os.path.join(UPLOAD_DIR, safe_filename)
        
        #  Async stream file to disk in chunks with hard size limit
        total_bytes = 0
        try:
            async with aiofiles.open(file_path, "wb") as buffer:
                while chunk := await file.read(1024 * 1024):  # Read in 1MB chunks
                    total_bytes += len(chunk)
                    if total_bytes > MAX_UPLOAD_BYTES:
                        raise HTTPException(
                            status_code=413,
                            detail=f"File too large. Maximum allowed size is {MAX_UPLOAD_BYTES // (1024 * 1024)}MB."
                        )
                    await buffer.write(chunk)
        except HTTPException:
            if os.path.exists(file_path):
                os.remove(file_path)
            raise
                
        parsed_rows = 0
        batch_size = 1000
        logs_batch = []
        analysis_tag = file_id

        try:
            #  STREAMING PARSE: inspect a bounded sample, then replay the on-disk file row-by-row
            delimiter_used, fieldnames, sample_rows = _detect_csv_structure(file_path)

            if not fieldnames:
                raise HTTPException(status_code=400, detail="CSV header is missing.")

            resolved = resolve_columns(fieldnames)
            
            # --- START SMART DETECTION HOOK ---
            resolved = guess_columns_by_content(sample_rows, fieldnames, resolved)
            # --- END SMART DETECTION HOOK ---
            
            minimum_required = {"timestamp", "message"}
            if not any(key in resolved for key in minimum_required):
                raise HTTPException(status_code=400, detail="CSV format completely unrecognized. No Dates or Log text found.")

            field_lookup = {c.lower(): c for c in fieldnames}

            csv_reader = _build_csv_reader(file_path, delimiter=delimiter_used)

            for row in csv_reader:
                #  Normalize row keys by stripping whitespace
                row = {(k.strip() if k else k): v for k, v in row.items()}
                
                if not isinstance(row, dict) or not any((str(v).strip() if v is not None else "") for v in row.values()):
                    continue

                raw_event_id = get_field(row, resolved, "event_id", "0")
                try:
                    event_id_int = int(raw_event_id)
                except (TypeError, ValueError):
                    event_id_int = 0

                msg = get_field(row, resolved, "message", "")
                commandline_col = next((field_lookup[alias] for alias in ["commandline_or_target", "commandline", "command_line", "command"] if alias in field_lookup), None)

                if commandline_col and commandline_col != resolved.get("message"):
                    extra = row.get(commandline_col, "").strip()
                    if extra:
                        msg = f"{msg} | {extra}" if msg else extra
                if not msg:
                    msg = "Unknown Event"

                msg_lower = msg.lower()
                csv_severity = get_field(row, resolved, "severity", "").strip()
                smart_severity, smart_source, compliance_tag = analyze_log_context(event_id_int, msg_lower)
                event_id_meaning = resolve_event_id_meaning(event_id_int)

                if csv_severity and csv_severity.upper() in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
                    smart_severity = csv_severity.upper()

                raw_time = get_field(row, resolved, "timestamp", "").strip()
                if not raw_time:
                    final_ts = datetime.now(timezone.utc).isoformat()
                elif len(raw_time) <= 8:
                    today_date = datetime.now(timezone.utc).strftime("%Y-%m-%d")
                    final_ts = f"{today_date}T{raw_time}Z"
                else:
                    final_ts = raw_time

                log_entry = {
                    "tenant_id": secure_tenant_id,
                    "timestamp": final_ts,
                    "source_ip": get_field(row, resolved, "source_ip", "0.0.0.0"),
                    "event_id": event_id_int,
                    "message": msg,
                    "raw_message": msg,
                    "severity": smart_severity,
                    "engine_source": smart_source,
                    "user": get_field(row, resolved, "user", "system"),
                    "source": "csv_upload",
                    "analysis_tag": analysis_tag,
                    RAW_RETENTION_ANCHOR_FIELD: _build_retention_anchor(final_ts),
                }
                if event_id_meaning:
                    log_entry["event_id_meaning"] = event_id_meaning
                if compliance_tag:
                    log_entry["compliance_tag"] = compliance_tag

                logs_batch.append(log_entry)
                parsed_rows += 1

                #  CTO FIX 3: Batch Insert to MongoDB (CSV to separate collection)
                if len(logs_batch) >= batch_size:
                    result = await db["csv_uploads"].insert_many(logs_batch)
                    logger.debug("CSV upload batch inserted %s rows", len(result.inserted_ids))
                    logs_batch.clear()

            # Insert any remaining logs
            if logs_batch:
                result = await db["csv_uploads"].insert_many(logs_batch)
                logger.debug("CSV upload final batch inserted %s rows", len(result.inserted_ids))

            logger.info("CSV upload parsed %s event rows", parsed_rows)

            if parsed_rows == 0:
                raise HTTPException(status_code=400, detail="No valid log rows were found in the CSV.")
                
        except HTTPException:
            raise
        except Exception as csv_err:
            logger.warning("CSV upload parse failed: %s", csv_err)
            raise HTTPException(status_code=400, detail="Unable to read this CSV file. Please check the format.")
        
        #  CTO FIX 4: Store METADATA ONLY in analysis_results (No embedded findings array)
        analysis_doc = {
            "tenant_id": secure_tenant_id,
            "filename": secure_original_name,
            "file_path": file_path,
            "status": "completed", 
            "uploaded_at": datetime.now(timezone.utc),
            "total_events": parsed_rows,
            "analysis_tag": analysis_tag
        }
        
        result = await db["analysis_results"].insert_one(analysis_doc)
        
        return {
            "status": "completed",
            "analysis_id": str(result.inserted_id),
            "message": f"CSV file uploaded successfully. Processed {parsed_rows} events."
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error("CSV upload failed: %s", e)
        raise HTTPException(status_code=500, detail="Ingestion failed. Please try again or contact support.")


@router.get("/results")
async def get_upload_history(db=Depends(get_db), current_user=Depends(get_current_user)):
    try:
        secure_tenant_id = re.sub(r'[^a-zA-Z0-9_-]', '', current_user.get("tenant_id", ""))
        query = {"tenant_id": secure_tenant_id}
        fresh_start_at = current_user.get("agent_issued_at")
        if fresh_start_at:
            try:
                fresh_dt = datetime.fromisoformat(fresh_start_at.replace("Z", "+00:00"))
                query["uploaded_at"] = {"$gte": fresh_dt}
            except Exception:
                pass

        cursor = db["analysis_results"].find(query).sort("uploaded_at", -1)
        results = []
        async for doc in cursor:
            doc["_id"] = str(doc["_id"])
            doc["analysisId"] = doc["_id"]
            results.append(doc)
        return {"status": "success", "data": results}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/results/{analysis_id}")
async def get_analysis_result(analysis_id: str, db=Depends(get_db), current_user=Depends(get_current_user)):
    raw_tenant_id = current_user.get("tenant_id", "")
    secure_tenant_id = re.sub(r'[^a-zA-Z0-9_-]', '', raw_tenant_id)


    if not ObjectId.is_valid(analysis_id):
        raise HTTPException(status_code=404, detail="Invalid analysis ID")

    # Check if analysis record exists
    query = {"_id": ObjectId(analysis_id), "tenant_id": secure_tenant_id}
    result = await db["analysis_results"].find_one(query)

    if not result:
        # Debug check remains tenant-scoped to avoid cross-tenant metadata disclosure.
        any_result = await db["analysis_results"].find_one({"_id": ObjectId(analysis_id), "tenant_id": secure_tenant_id})
        if any_result:
            logger.warning("Tenant-scoped analysis lookup filtered an existing record")
        else:
            logger.debug("Tenant-scoped analysis lookup returned no record")
        raise HTTPException(status_code=404, detail="Report not found")

    # Get analysis metadata
    tag = result.get("analysis_tag")
    total_events = result.get("total_events", 0)
    logger.debug("Tenant-scoped analysis found with %s total events", total_events)

    # Try to retrieve findings
    findings = []
    if tag:
        query = {"tenant_id": secure_tenant_id, "analysis_tag": tag}
        count = await db["csv_uploads"].count_documents(query)
        logger.debug("Tenant-scoped CSV findings count: %s", count)

        cursor = db["csv_uploads"].find(query).limit(1000)
        async for log in cursor:
            log["_id"] = str(log["_id"])
            log.pop(RAW_RETENTION_ANCHOR_FIELD, None)
            findings.append(log)

        logger.debug("Tenant-scoped CSV findings retrieved: %s", len(findings))

    result["_id"] = str(result["_id"])
    result["analysisId"] = str(result["_id"])
    result["findings"] = findings

    return result


@router.delete("/results/{analysis_id}")
async def delete_log(analysis_id: str, request: Request, db=Depends(get_db), current_user=Depends(get_current_user)):
    secure_tenant_id = re.sub(r'[^a-zA-Z0-9_-]', '', current_user.get("tenant_id", ""))
    if not ObjectId.is_valid(analysis_id):
        raise HTTPException(status_code=404, detail="Invalid analysis ID")

    doc = await db["analysis_results"].find_one({"_id": ObjectId(analysis_id), "tenant_id": secure_tenant_id})
    if not doc:
        raise HTTPException(status_code=403, detail="Forbidden")

    tag = doc.get("analysis_tag")
    if tag:
        await db["csv_uploads"].delete_many({"tenant_id": secure_tenant_id, "analysis_tag": tag})

    # Clean up the physical file from disk
    file_path = doc.get("file_path")
    if file_path and os.path.exists(file_path):
        try:
            os.remove(file_path)
        except OSError:
            pass

    await db["analysis_results"].delete_one({"_id": doc["_id"], "tenant_id": secure_tenant_id})

    await log_audit_action(
        db=db,
        user_id=current_user.get("username", "unknown"),
        action="DELETE_UPLOAD",
        target_file=doc.get("filename", "unknown"),
        tenant_id=secure_tenant_id,
        ip_address=_resolve_request_ip(request),
    )

    return {"status": "deleted", "id": analysis_id}

@router.delete("/delete/{analysis_id}")
async def delete_log_alias(analysis_id: str, request: Request, db=Depends(get_db), current_user=Depends(get_current_user)):
    return await delete_log(analysis_id, request, db, current_user)


@router.get("/report/{analysis_id}")
async def download_report(analysis_id: str, db=Depends(get_db), current_user=Depends(get_current_user)):
    secure_tenant_id = re.sub(r'[^a-zA-Z0-9_-]', '', current_user.get("tenant_id", ""))
    if not ObjectId.is_valid(analysis_id):
        raise HTTPException(status_code=404, detail="Invalid analysis ID")

    result = await db["analysis_results"].find_one({"_id": ObjectId(analysis_id), "tenant_id": secure_tenant_id})
    if not result:
        raise HTTPException(status_code=404, detail="Report not found")

    # For export, fetch up to 5000 to keep the JSON download reasonable.
    tag = result.get("analysis_tag")
    findings = []
    if tag:
        cursor = db["csv_uploads"].find({"tenant_id": secure_tenant_id, "analysis_tag": tag}).limit(5000)
        async for log in cursor:
            log["_id"] = str(log["_id"])
            log.pop(RAW_RETENTION_ANCHOR_FIELD, None)
            findings.append(log)
            
    result["_id"] = str(result["_id"])
    result["analysisId"] = result["_id"]
    result["findings"] = findings
    
    report_json = json.dumps(result, default=str, indent=2)
    filename = f"WarSOC_Report_{analysis_id}.json"
    
    return Response(
        content=report_json,
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'}
    )
