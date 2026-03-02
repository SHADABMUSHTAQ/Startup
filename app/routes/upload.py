import os
import json
import shutil
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

# ---------------------------------------------------------
# 1. UPLOAD & INSTANT ANALYZE
# ---------------------------------------------------------
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
            csv_reader = csv.DictReader(io.StringIO(decoded_content))
            
            for row in csv_reader:
                findings.append({
                    "timestamp": row.get("timestamp", datetime.now(timezone.utc).isoformat()),
                    "source_ip": row.get("source_ip", "0.0.0.0"),
                    "event_id": row.get("event_id", "Unknown"),
                    "severity": row.get("severity", "INFO"),
                    "title": row.get("message", "Unknown Event"),
                    "engine_source": row.get("engine_source", "Forensic File"),
                    "tenant_id": secure_tenant_id
                })
        except Exception as csv_err:
            print(f"❌ Error parsing CSV: {csv_err}")
            raise HTTPException(status_code=400, detail="Invalid CSV format. Please ensure headers match.")
        
        analysis_doc = {
            "tenant_id": secure_tenant_id,
            "filename": file.filename,
            "file_path": file_path,
            "status": "completed", 
            "uploaded_at": datetime.now(timezone.utc),
            "findings": findings,
            "total_events": len(findings)
        }
        
        # 🚨 FIXED: Now explicitly saving to 'analysis_results'
        result = await db.analysis_results.insert_one(analysis_doc)
        analysis_id = str(result.inserted_id)
        
        return {
            "status": "completed",
            "analysis_id": analysis_id,
            "message": "File instantly analyzed and ready for viewing."
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Ingestion failed: {str(e)}")

# ---------------------------------------------------------
# 2. GET HISTORY LIST (/results)
# ---------------------------------------------------------
@router.get("/results")
async def get_upload_history(db=Depends(get_db), current_user=Depends(get_current_user)):
    try:
        secure_tenant_id = current_user.get("tenant_id")
        # 🚨 FIXED: Now explicitly fetching from 'analysis_results'
        cursor = db.analysis_results.find({"tenant_id": secure_tenant_id}).sort("uploaded_at", -1)
        results = []
        async for doc in cursor:
            doc["_id"] = str(doc["_id"])
            results.append(doc)
        return results
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# ---------------------------------------------------------
# 3. GET SINGLE RESULT DETAILS
# ---------------------------------------------------------
@router.get("/results/{analysis_id}")
async def get_analysis_result(analysis_id: str, db=Depends(get_db), current_user=Depends(get_current_user)):
    secure_tenant_id = current_user.get("tenant_id")
    # 🚨 FIXED: Now explicitly fetching from 'analysis_results'
    result = await db.analysis_results.find_one({"_id": ObjectId(analysis_id), "tenant_id": secure_tenant_id})
    if not result:
        raise HTTPException(status_code=404, detail="Report not found")
    
    result["_id"] = str(result["_id"])
    result["analysisId"] = str(result["_id"]) 
    return result

# ---------------------------------------------------------
# 4. DELETE LOG
# ---------------------------------------------------------
@router.delete("/delete/{analysis_id}")
async def delete_log(analysis_id: str, db=Depends(get_db), current_user=Depends(get_current_user)):
    secure_tenant_id = current_user.get("tenant_id")
    # 🚨 FIXED: Now explicitly deleting from 'analysis_results'
    result = await db.analysis_results.delete_one({"_id": ObjectId(analysis_id), "tenant_id": secure_tenant_id})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="File not found or unauthorized")
    return {"status": "deleted", "id": analysis_id}