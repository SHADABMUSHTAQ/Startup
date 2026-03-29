import os
import json
import csv
import io
import re
import aiofiles
from datetime import datetime, timezone
from fastapi import APIRouter, UploadFile, File, HTTPException, Depends, Request
from fastapi.responses import JSONResponse, Response, StreamingResponse
from bson import ObjectId
from slowapi import Limiter
from slowapi.util import get_remote_address

from app.database import get_db
from app.routes.auth import get_current_user
from app.config.config import get_settings

router = APIRouter()
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

# 🔄 COLUMN NAME RESOLVER
COLUMN_ALIASES = {
    "timestamp": ["timestamp", "timestamp (utc)", "time", "date", "datetime", "event_time", "log_time", "created_at"],
    "source_ip": ["source_ip", "src_ip", "ip", "ip_address", "sourceip", "source", "sourcedevice", "source_device", "host", "hostname"],
    "event_id": ["event_id", "eventid", "event", "id", "eid", "event_code"],
    "message": ["message", "msg", "description", "detail", "details", "log", "action", "commandline_or_target", "command", "commandline", "command_line"],
    "severity": ["severity", "severityscore", "severity_score", "level", "priority", "risk"],
    "user": ["user", "username", "actor", "account", "subject", "user_name", "account_name"],
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

def analyze_log_context(event_id_int, msg_lower):
    severity = "INFO"
    source_type = "Syslog"

    if event_id_int > 0 or "event" in msg_lower or "logon" in msg_lower or "account" in msg_lower:
        source_type = "Windows-Sec"
        if event_id_int == 4625 or "failed" in msg_lower:
            severity = "HIGH"
        elif event_id_int == 1102 or "cleared" in msg_lower:
            severity = "CRITICAL"
        elif event_id_int in [4720, 4732, 4726]:
            severity = "MEDIUM"
    elif "get /" in msg_lower or "post /" in msg_lower or "http" in msg_lower or "union select" in msg_lower or "xss" in msg_lower:
        source_type = "Web-WAF"
        if "union select" in msg_lower or "drop table" in msg_lower or "xss" in msg_lower or "<script>" in msg_lower:
            severity = "CRITICAL"
        elif "admin" in msg_lower and "failed" in msg_lower:
            severity = "HIGH"
    elif "sudo" in msg_lower or "root" in msg_lower or "/etc/" in msg_lower or "sshd" in msg_lower or "invalid user" in msg_lower:
        source_type = "Linux-Auth"
        if "failed password" in msg_lower or "invalid user" in msg_lower:
            severity = "HIGH"
        elif "without permission" in msg_lower or "root access" in msg_lower:
            severity = "CRITICAL"
    elif "miner" in msg_lower or "xmrig" in msg_lower or "crypto" in msg_lower:
        source_type = "Endpoint-EDR"
        severity = "CRITICAL"
    elif "port scan" in msg_lower or "syn packet" in msg_lower:
        source_type = "Network-IDS"
        severity = "MEDIUM"
    elif "file encrypted" in msg_lower or "ransomware" in msg_lower:
        source_type = "Endpoint-EDR"
        severity = "CRITICAL"

    return severity, source_type

@router.post("/analyze")
@limiter.limit("5/minute")
async def analyze_log_file(request: Request, file: UploadFile = File(...), db=Depends(get_db), current_user=Depends(get_current_user)):
    try:
        secure_tenant_id = re.sub(r'[^a-zA-Z0-9_-]', '', current_user.get("tenant_id", ""))

        if not is_csv_upload(file):
            raise HTTPException(status_code=400, detail="Please upload a CSV file. Supported format: .csv")
        
        file_id = str(os.urandom(12).hex())
        secure_original_name = os.path.basename(file.filename or "")
        safe_filename = f"WarSOC_{secure_tenant_id}_{file_id}_{secure_original_name}"
        file_path = os.path.join(UPLOAD_DIR, safe_filename)
        
        # ✅ Async stream file to disk in chunks with hard size limit
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
        batch_size = 2000
        logs_batch = []
        analysis_tag = file_id
        
        try:
            # ✅ CTO FIX 2: Async read from disk using aiofiles, sanitize NULs, and parse via csv.DictReader
            async with aiofiles.open(file_path, "r", encoding="utf-8", errors="replace") as f:
                content = await f.read()
            clean_content = content.replace('\x00', '')
            csv_reader = csv.DictReader(io.StringIO(clean_content))

            if not csv_reader.fieldnames:
                raise HTTPException(status_code=400, detail="CSV header is missing.")

            resolved = resolve_columns(csv_reader.fieldnames)
            minimum_required = {"timestamp", "message"}
            if not any(key in resolved for key in minimum_required):
                raise HTTPException(status_code=400, detail="CSV format not recognized. Missing timestamp/message columns.")

            field_lookup = {c.strip().lower(): c for c in (csv_reader.fieldnames or [])}

            for row in csv_reader:
                if not isinstance(row, dict) or not any((str(v).strip() if v is not None else "") for v in row.values()):
                    continue

                raw_event_id = get_field(row, resolved, "event_id", "0")
                try:
                    event_id_int = int(raw_event_id)
                except ValueError:
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
                smart_severity, smart_source = analyze_log_context(event_id_int, msg_lower)

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
                    "severity": smart_severity,
                    "engine_source": smart_source,
                    "user": get_field(row, resolved, "user", "system"),
                    "source": "csv_upload",
                    "analysis_tag": analysis_tag
                }

                logs_batch.append(log_entry)
                parsed_rows += 1

                # ✅ CTO FIX 3: Batch Insert to MongoDB to respect the 16MB document limit
                if len(logs_batch) >= batch_size:
                    await db.logs.insert_many(logs_batch)
                    logs_batch.clear()

            # Insert any remaining logs
            if logs_batch:
                await db.logs.insert_many(logs_batch)

            if parsed_rows == 0:
                raise HTTPException(status_code=400, detail="No valid log rows were found in the CSV.")
                
        except HTTPException:
            raise
        except Exception as csv_err:
            print(f"❌ Error parsing CSV: {csv_err}")
            raise HTTPException(status_code=400, detail="Unable to read this CSV file. Please check the format.")
        
        # ✅ CTO FIX 4: Store METADATA ONLY in analysis_results (No embedded findings array)
        analysis_doc = {
            "tenant_id": secure_tenant_id,
            "filename": secure_original_name,
            "file_path": file_path,
            "status": "completed", 
            "uploaded_at": datetime.now(timezone.utc),
            "total_events": parsed_rows,
            "analysis_tag": analysis_tag
        }
        
        result = await db.analysis_results.insert_one(analysis_doc)
        
        return {
            "status": "completed",
            "analysis_id": str(result.inserted_id),
            "message": f"CSV file uploaded successfully. Processed {parsed_rows} events."
        }
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"❌ Upload Error: {e}")
        raise HTTPException(status_code=500, detail="Ingestion failed. Please try again or contact support.")


@router.get("/results")
async def get_upload_history(db=Depends(get_db), current_user=Depends(get_current_user)):
    try:
        secure_tenant_id = current_user.get("tenant_id")
        query = {"tenant_id": secure_tenant_id}
        fresh_start_at = current_user.get("agent_issued_at")
        if fresh_start_at:
            try:
                fresh_dt = datetime.fromisoformat(fresh_start_at.replace("Z", "+00:00"))
                query["uploaded_at"] = {"$gte": fresh_dt}
            except Exception:
                pass

        cursor = db.analysis_results.find(query).sort("uploaded_at", -1)
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
    secure_tenant_id = current_user.get("tenant_id")
    if not ObjectId.is_valid(analysis_id):
        raise HTTPException(status_code=404, detail="Invalid analysis ID")
        
    result = await db.analysis_results.find_one({"_id": ObjectId(analysis_id), "tenant_id": secure_tenant_id})
    if not result:
        raise HTTPException(status_code=404, detail="Report not found")
    
    # ✅ CTO FIX 5: Dynamically fetch findings, limited to 1,000 to prevent React browser crash
    tag = result.get("analysis_tag")
    findings = []
    if tag:
        cursor = db.logs.find({"tenant_id": secure_tenant_id, "analysis_tag": tag}).limit(1000)
        async for log in cursor:
            log["_id"] = str(log["_id"])
            findings.append(log)
            
    result["_id"] = str(result["_id"])
    result["analysisId"] = str(result["_id"]) 
    result["findings"] = findings 
    
    return result


@router.delete("/results/{analysis_id}")
async def delete_log(analysis_id: str, db=Depends(get_db), current_user=Depends(get_current_user)):
    secure_tenant_id = current_user.get("tenant_id")
    if not ObjectId.is_valid(analysis_id):
        raise HTTPException(status_code=404, detail="Invalid analysis ID")
        
    doc = await db.analysis_results.find_one({"_id": ObjectId(analysis_id), "tenant_id": secure_tenant_id})
    if not doc:
        raise HTTPException(status_code=404, detail="File not found or unauthorized")

    tag = doc.get("analysis_tag")
    if tag:
        await db.logs.delete_many({"tenant_id": secure_tenant_id, "analysis_tag": tag})

    # Clean up the physical file from disk
    file_path = doc.get("file_path")
    if file_path and os.path.exists(file_path):
        try:
            os.remove(file_path)
        except OSError:
            pass

    await db.analysis_results.delete_one({"_id": doc["_id"]})
    return {"status": "deleted", "id": analysis_id}

@router.delete("/delete/{analysis_id}")
async def delete_log_alias(analysis_id: str, db=Depends(get_db), current_user=Depends(get_current_user)):
    return await delete_log(analysis_id, db, current_user)


@router.get("/report/{analysis_id}")
async def download_report(analysis_id: str, db=Depends(get_db), current_user=Depends(get_current_user)):
    secure_tenant_id = current_user.get("tenant_id")
    if not ObjectId.is_valid(analysis_id):
        raise HTTPException(status_code=404, detail="Invalid analysis ID")
        
    result = await db.analysis_results.find_one({"_id": ObjectId(analysis_id), "tenant_id": secure_tenant_id})
    if not result:
        raise HTTPException(status_code=404, detail="Report not found")
    
    # For export, fetch up to 5000 to keep the JSON download reasonable.
    tag = result.get("analysis_tag")
    findings = []
    if tag:
        cursor = db.logs.find({"tenant_id": secure_tenant_id, "analysis_tag": tag}).limit(5000)
        async for log in cursor:
            log["_id"] = str(log["_id"])
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