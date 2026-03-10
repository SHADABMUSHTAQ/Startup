from fastapi import APIRouter, Depends, HTTPException
from datetime import datetime, timedelta, timezone
from app.database import get_db
from app.routes.auth import get_current_user

router = APIRouter()

@router.get("/search")
async def global_search(q: str = "", days: str = "", db=Depends(get_db), current_user=Depends(get_current_user)):
    try:
        tenant_id = current_user.get("tenant_id")
        query = {"tenant_id": tenant_id}
        
        # 🕒 1. Time Filter Setup
        cutoff_date = None
        if days and days.isdigit():
            cutoff_date = datetime.now(timezone.utc) - timedelta(days=int(days))
            query["timestamp"] = {"$gte": cutoff_date.isoformat()}
            
        # 🔍 2. Text Search Setup
        if q and q.strip() != "":
            search_term = q.strip()
            query["$or"] = [
                {"source_ip": {"$regex": search_term, "$options": "i"}},
                {"ip": {"$regex": search_term, "$options": "i"}},
                {"message": {"$regex": search_term, "$options": "i"}},
                {"engine_source": {"$regex": search_term, "$options": "i"}},
                {"severity": {"$regex": search_term, "$options": "i"}}
            ]
        
        # 📥 3. Search in Live Logs (db.logs)
        cursor = db.logs.find(query).sort("timestamp", -1)
        logs_docs = await cursor.to_list(length=500)
        
        combined_results = []
        for doc in logs_docs:
            doc["_id"] = str(doc["_id"])
            combined_results.append(doc)
            
        # 🚀 4. THE MAGIC: Search INSIDE Offline Files (db.analysis_results)
        offline_cursor = db.analysis_results.find({"tenant_id": tenant_id})
        offline_docs = await offline_cursor.to_list(length=100)
        
        for file_doc in offline_docs:
            findings = file_doc.get("findings", [])
            for f in findings:
                # Time Check
                if cutoff_date:
                    log_time_str = f.get("timestamp", "")
                    try:
                        log_time = datetime.fromisoformat(log_time_str.replace("Z", "+00:00"))
                        if log_time < cutoff_date:
                            continue # Skip purana log
                    except:
                        pass 
                        
                # Text/IP Search Check
                if q and q.strip() != "":
                    st = q.lower().strip()
                    if not (st in str(f.get("source_ip", "")).lower() or 
                            st in str(f.get("message", "")).lower() or 
                            st in str(f.get("engine_source", "")).lower() or 
                            st in str(f.get("severity", "")).lower()):
                        continue # Skip un-matched log
                        
                # Agar pass ho gaya toh add kar do
                f["_id"] = str(f.get("id", len(combined_results)))
                combined_results.append(f)
        
        # 📊 5. Sort & Return the best results
        combined_results.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
        final_results = combined_results[:500]
        
        return {"count": len(final_results), "results": final_results}
        
    except Exception as e:
        print(f"❌ Omni-Search Error: {e}")
        raise HTTPException(status_code=500, detail=str(e))