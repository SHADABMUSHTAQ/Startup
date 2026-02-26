import os
import json
import shutil
import redis.asyncio as aioredis  
from datetime import datetime, timezone
from fastapi import APIRouter, UploadFile, File, HTTPException, Depends
from bson import ObjectId

from app.database import get_db
# 🚨 Required to lock the routes down
from app.routes.auth import get_current_user

router = APIRouter()

REDIS_HOST = os.getenv("REDIS_HOST", "localhost")
UPLOAD_DIR = "uploaded_files"
os.makedirs(UPLOAD_DIR, exist_ok=True)

# ---------------------------------------------------------
# 1. UPLOAD & ANALYZE
# ---------------------------------------------------------
@router.post("/analyze")
async def analyze_log_file(file: UploadFile = File(...), db=Depends(get_db), current_user=Depends(get_current_user)):
    try:
        secure_tenant_id = current_user.get("tenant_id")
        
        file_id = str(os.urandom(12).hex())
        safe_filename = f"WarSOC_{secure_tenant_id}_{file_id}_{file.filename}"
        file_path = os.path.join(UPLOAD_DIR, safe_filename)
        
        with open(file_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)
        
        analysis_doc = {
            "tenant_id": secure_tenant_id,
            "filename": file.filename,
            "file_path": file_path,
            "status": "pending",
            "uploaded_at": datetime.now(timezone.utc),
            "findings": [],
            "total_events": 0
        }
        result = await db.analyses.insert_one(analysis_doc)
        analysis_id = str(result.inserted_id)
        
        job_data = {
            "tenant_id": secure_tenant_id,
            "file_path": file_path,
            "analysis_id": analysis_id,
            "filename": file.filename
        }
        
        redis_client = await aioredis.from_url(f"redis://{REDIS_HOST}:6379", decode_responses=True)
        await redis_client.rpush('file_jobs', json.dumps(job_data))
        await redis_client.close()
        
        return {
            "status": "queued",
            "analysis_id": analysis_id,
            "message": "File accepted for analysis."
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
        cursor = db.analyses.find({"tenant_id": secure_tenant_id}).sort("uploaded_at", -1)
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
    result = await db.analyses.find_one({"_id": ObjectId(analysis_id), "tenant_id": secure_tenant_id})
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
    result = await db.analyses.delete_one({"_id": ObjectId(analysis_id), "tenant_id": secure_tenant_id})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="File not found or unauthorized")
    return {"status": "deleted", "id": analysis_id}

# ---------------------------------------------------------
# 5. SERVER SIDE REPORT (Backup)
# ---------------------------------------------------------
@router.get("/report/{analysis_id}")
async def download_server_report(analysis_id: str, db=Depends(get_db), current_user=Depends(get_current_user)):
    secure_tenant_id = current_user.get("tenant_id")
    result = await db.analyses.find_one({"_id": ObjectId(analysis_id), "tenant_id": secure_tenant_id})
    if not result: raise HTTPException(status_code=404, detail="Not Found")
    return {"message": "Use frontend generator"}