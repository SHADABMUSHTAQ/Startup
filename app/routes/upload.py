import os
import json
import csv
import io
from datetime import datetime, timezone
from fastapi import APIRouter, UploadFile, File, HTTPException, Depends
from bson import ObjectId

from app.database import get_db
from app.routes.auth import get_current_user

router = APIRouter()
UPLOAD_DIR = "uploaded_files"
os.makedirs(UPLOAD_DIR, exist_ok=True)

# 🧠 ENTERPRISE LOGIC: Context-Aware Parser
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
async def analyze_log_file(file: UploadFile = File(...), db=Depends(get_db), current_user=Depends(get_current_user)):
    try:
        secure_tenant_id = current_user.get("tenant_id")
        
        file_id = str(os.urandom(12).hex())
        safe_filename = f"WarSOC_{secure_tenant_id}_{file_id}_{file.filename}"
        file_path = os.path.join(UPLOAD_DIR, safe_filename)
        
        content = await file.read()
        
        with open(file_path, "wb") as buffer:
            buffer.write(content)
            
        findings = []
        
        try:
            decoded_content = content.decode('utf-8-sig')
            csv_file = io.StringIO(decoded_content)
            csv_reader = csv.DictReader(csv_file)
            
            for row in csv_reader:
                raw_event_id = row.get("event_id", "0")
                try:
                    event_id_int = int(raw_event_id)
                except ValueError:
                    event_id_int = 0

                msg_lower = row.get("message", "").lower()
                smart_severity, smart_source = analyze_log_context(event_id_int, msg_lower)

                # 🚀 NEW: SMART TIMESTAMP FORMATTER (Fixes "Last 24 Hours" Issue)
                raw_time = row.get("timestamp", "").strip()
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
                    "source_ip": row.get("source_ip", "0.0.0.0"),
                    "event_id": event_id_int,
                    "message": row.get("message", "Unknown Event"),
                    "severity": smart_severity,       
                    "engine_source": smart_source,    
                    "user": row.get("user", "system")
                }
                
                findings.append(log_entry)
                
        except Exception as csv_err:
            print(f"❌ Error parsing CSV: {csv_err}")
            raise HTTPException(status_code=400, detail="Invalid CSV format.")
        
        # 🤫 SILENT INJECTOR: Data ko Global Search (db.logs) mein push karta hai
        if findings:
            logs_to_insert = [dict(f) for f in findings]
            await db.logs.insert_many(logs_to_insert)
        
        # Save Analysis Record (For Offline View)
        analysis_doc = {
            "tenant_id": secure_tenant_id,
            "filename": file.filename,
            "file_path": file_path,
            "status": "completed", 
            "uploaded_at": datetime.now(timezone.utc),
            "findings": findings,
            "total_events": len(findings)
        }
        
        result = await db.analysis_results.insert_one(analysis_doc)
        
        return {
            "status": "completed",
            "analysis_id": str(result.inserted_id),
            "message": "File professionally parsed."
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Ingestion failed: {str(e)}")

# GET ALL UPLOADS
@router.get("/results")
async def get_upload_history(db=Depends(get_db), current_user=Depends(get_current_user)):
    try:
        secure_tenant_id = current_user.get("tenant_id")
        cursor = db.analysis_results.find({"tenant_id": secure_tenant_id}).sort("uploaded_at", -1)
        results = []
        async for doc in cursor:
            doc["_id"] = str(doc["_id"])
            results.append(doc)
        return results
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# GET SINGLE UPLOAD
@router.get("/results/{analysis_id}")
async def get_analysis_result(analysis_id: str, db=Depends(get_db), current_user=Depends(get_current_user)):
    secure_tenant_id = current_user.get("tenant_id")
    result = await db.analysis_results.find_one({"_id": ObjectId(analysis_id), "tenant_id": secure_tenant_id})
    if not result:
        raise HTTPException(status_code=404, detail="Report not found")
    
    result["_id"] = str(result["_id"])
    result["analysisId"] = str(result["_id"]) 
    return result

# DELETE UPLOAD
@router.delete("/results/{analysis_id}")
async def delete_log(analysis_id: str, db=Depends(get_db), current_user=Depends(get_current_user)):
    secure_tenant_id = current_user.get("tenant_id")
    result = await db.analysis_results.delete_one({"_id": ObjectId(analysis_id), "tenant_id": secure_tenant_id})
    
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="File not found or unauthorized")
    
    return {"status": "deleted", "id": analysis_id}