from fastapi import APIRouter, Depends, HTTPException
from app.database import get_db
from app.routes.auth import get_current_user
from bson import ObjectId

router = APIRouter()

# ---------------------------------------------------------
# GET ANALYSES (/analyses)
# ---------------------------------------------------------
@router.get("/analyses")
async def get_analyses(limit: int = 10, db=Depends(get_db), current_user=Depends(get_current_user)):
    try:
        secure_tenant_id = current_user.get("tenant_id")
        cursor = db.analyses.find({"tenant_id": secure_tenant_id}).sort("uploaded_at", -1).limit(limit)
        results = []
        async for doc in cursor:
            doc["_id"] = str(doc["_id"])
            results.append(doc)
        return results
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# ---------------------------------------------------------
# GET SINGLE ANALYSIS (/analyses/{id})
# ---------------------------------------------------------
@router.get("/analyses/{analysis_id}")
async def get_analysis(analysis_id: str, db=Depends(get_db), current_user=Depends(get_current_user)):
    try:
        secure_tenant_id = current_user.get("tenant_id")
        analysis = await db.analyses.find_one({"_id": ObjectId(analysis_id), "tenant_id": secure_tenant_id})
        if not analysis:
            raise HTTPException(status_code=404, detail="Analysis not found")
        analysis["_id"] = str(analysis["_id"])
        return analysis
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# ---------------------------------------------------------
# GET STATS
# ---------------------------------------------------------
@router.get("/stats")
async def get_stats(db=Depends(get_db), current_user=Depends(get_current_user)):
    try:
        secure_tenant_id = current_user.get("tenant_id")
        cursor = db.analyses.find({"tenant_id": secure_tenant_id})
        analyses = await cursor.to_list(length=1000)
        
        total_analyses = len(analyses)
        total_findings = sum(analysis.get("statistics", {}).get("total_findings", 0) for analysis in analyses)
        
        severity_counts = {}
        type_counts = {}
        
        for analysis in analyses:
            for severity, count in analysis.get("statistics", {}).get("findings_by_severity", {}).items():
                severity_counts[severity] = severity_counts.get(severity, 0) + count
            
            for attack_type, count in analysis.get("statistics", {}).get("findings_by_type", {}).items():
                type_counts[attack_type] = type_counts.get(attack_type, 0) + count
        
        return {
            "total_analyses": total_analyses,
            "total_findings": total_findings,
            "severity_counts": severity_counts,
            "type_counts": type_counts
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))