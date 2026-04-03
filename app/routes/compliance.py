from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse
from app.routes.auth import get_current_user

router = APIRouter()

@router.get("/packs", dependencies=[Depends(get_current_user)])
async def get_compliance_packs():
    """Returns the full catalog of regulatory compliance frameworks."""
    mock_packs = [
        {
            "pack_id": "fbr_pos",
            "name": "FBR Point-of-Sale (SRO 288)",
            "description": "Mandatory real-time sales and modification tracking as per FBR S.R.O. 288(I)/2026.",
            "retention": {"vault_days": 30}
        },
        {
            "pack_id": "peca_forensic",
            "name": "PECA Forensic Trail (Section 46)",
            "description": "Non-repudiable log integrity and court-admissible forensic evidence (PECA 2016).",
            "retention": {"vault_days": 365}
        }
    ]
    return mock_packs

@router.get("/packs/{pack_id}", dependencies=[Depends(get_current_user)])
async def get_pack_details(pack_id: str):
    """Returns granular controls and event monitoring rules for a specific pack."""
    if pack_id == "fbr_pos":
        return {
            "pack_id": "fbr_pos",
            "name": "FBR Point-of-Sale (SRO 288)",
            "retention": {"local_hot_days": 7, "vault_days": 30},
            "monitored_events": [
                {"id": 4660, "name": "Object Deleted", "severity": "Warning"},
                {"id": 4663, "name": "File System Modification", "severity": "Alert"},
                {"id": 4670, "name": "Permissions Changed", "severity": "High"}
            ]
        }
    elif pack_id == "peca_forensic":
        return {
            "pack_id": "peca_forensic",
            "name": "PECA Forensic Trail (Section 46)",
            "retention": {"local_hot_days": 30, "vault_days": 365},
            "monitored_events": [
                {"id": 4624, "name": "Success Logon", "severity": "Informational"},
                {"id": 4625, "name": "Failed Logon", "severity": "Critical"},
                {"id": 1102, "name": "Audit Log Cleared", "severity": "Security Alert"},
                {"id": 4688, "name": "Process Creation", "severity": "High"}
            ]
        }
    return JSONResponse(status_code=404, content={"detail": "Pack not found"})
