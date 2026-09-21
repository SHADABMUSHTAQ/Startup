"""WarSOC Endpoint Configuration Assessment (SCA) & CIS Benchmark Router.

Tenant-isolated compliance endpoints for retrieving endpoint hardening posture,
CIS benchmark scorecards, and failed security controls.
"""

from __future__ import annotations

import re
from typing import Any
from fastapi import APIRouter, Depends, HTTPException, Path, Request
from app.config.config import Settings, get_settings
from app.database import get_db
from app.routes.auth import get_current_user
from app.services.sca_service import get_agent_sca_posture, get_tenant_sca_summary
from app.utils.limiter import limiter
from app.utils.rbac import RoleChecker

router = APIRouter(tags=["compliance-sca"])

AGENT_ID_REGEX = re.compile(r"^[A-Za-z0-9_.:-]{3,128}$")


def require_sca_enabled(settings: Settings = Depends(get_settings)) -> Settings:
    if not settings.wazuh_sca_enabled:
        raise HTTPException(
            status_code=503,
            detail="Configuration assessment is not enabled",
        )
    return settings


@router.get("/summary")
@limiter.limit("60/minute")
async def get_sca_summary(
    request: Request,
    current_user: dict[str, Any] = Depends(get_current_user),
    _role: str = Depends(RoleChecker(["admin", "manager", "analyst", "auditor"])),
    sca_settings: Settings = Depends(require_sca_enabled),
    db: Any = Depends(get_db),
):
    """
    Returns organization-wide CIS benchmark compliance summary across all active endpoints.
    Strictly tenant-isolated and RBAC protected.
    """
    tenant_id = str(current_user.get("tenant_id") or "")
    if not tenant_id:
        raise HTTPException(status_code=403, detail="Tenant context missing")
    return await get_tenant_sca_summary(
        db, tenant_id, sca_settings.wazuh_sca_stale_after_hours
    )


@router.get("/posture/{agent_id}")
@limiter.limit("60/minute")
async def get_agent_posture(
    request: Request,
    agent_id: str = Path(..., min_length=3, max_length=128),
    current_user: dict[str, Any] = Depends(get_current_user),
    _role: str = Depends(RoleChecker(["admin", "manager", "analyst", "auditor"])),
    sca_settings: Settings = Depends(require_sca_enabled),
    db: Any = Depends(get_db),
):
    """
    Returns endpoint-level CIS benchmark compliance posture, score, and failed controls.
    Strictly tenant-isolated, validated, and RBAC protected.
    """
    if not AGENT_ID_REGEX.fullmatch(agent_id):
        raise HTTPException(status_code=400, detail="Invalid endpoint identifier format")

    tenant_id = str(current_user.get("tenant_id") or "")
    if not tenant_id:
        raise HTTPException(status_code=403, detail="Tenant context missing")

    # Verify agent exists for tenant to enforce strict isolation & prevent IDOR
    agents_col = getattr(db, "agents", None)
    if agents_col is not None:
        agent_doc = await agents_col.find_one(
            {"tenant_id": tenant_id, "agent_id": agent_id},
            {"_id": 1},
        )
        if not agent_doc:
            bindings_col = getattr(db, "detection_engine_agent_bindings", None)
            binding_doc = None
            if bindings_col is not None:
                binding_doc = await bindings_col.find_one(
                    {
                        "tenant_id": tenant_id,
                        "$or": [
                            {"warsoc_agent_id": agent_id},
                            {"wazuh_agent_id": agent_id},
                        ],
                    },
                    {"_id": 1},
                )
            if not binding_doc:
                obs_col = getattr(db, "detection_engine_observations", None)
                obs_doc = None
                if obs_col is not None:
                    obs_doc = await obs_col.find_one(
                        {
                            "tenant_id": tenant_id,
                            "$or": [
                                {"wazuh_agent_id": agent_id},
                                {"selected_security_fields.agent_id": agent_id},
                            ],
                        },
                        {"_id": 1},
                    )
                if not obs_doc:
                    raise HTTPException(status_code=404, detail="Endpoint not found for tenant")

    posture = await get_agent_sca_posture(
        db, tenant_id, agent_id, sca_settings.wazuh_sca_stale_after_hours
    )
    return posture
