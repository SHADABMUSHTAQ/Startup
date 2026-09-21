"""Tenant-scoped projection of accepted Wazuh SCA check observations."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any


MAX_SCA_OBSERVATIONS_PER_REQUEST = 50_000
_RESULTS = {
    "pass": "passed",
    "passed": "passed",
    "fail": "failed",
    "failed": "failed",
    "n/a": "not_applicable",
    "na": "not_applicable",
    "not applicable": "not_applicable",
    "not_applicable": "not_applicable",
}
_SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


def _normalise_result(value: Any) -> str | None:
    return _RESULTS.get(str(value or "").strip().lower())


def _as_text_time(value: Any) -> str:
    return value.isoformat() if isinstance(value, datetime) else str(value or "")


def _as_utc_datetime(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str) and value.strip():
        try:
            parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
        except ValueError:
            return None
    else:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _posture_from_checks(
    *,
    tenant_id: str,
    agent_id: str,
    checks: dict[str, dict[str, Any]],
    policy: str,
    scan_id: str | None,
    latest_scan_at: Any,
    stale_after_hours: int,
) -> dict[str, Any]:
    if not checks:
        return _empty_posture(tenant_id, agent_id)

    passed_count = sum(1 for check in checks.values() if check["result"] == "passed")
    failed_count = sum(1 for check in checks.values() if check["result"] == "failed")
    na_count = sum(
        1 for check in checks.values() if check["result"] == "not_applicable"
    )
    evaluated_count = passed_count + failed_count
    score = (
        round((passed_count / evaluated_count) * 100, 1)
        if evaluated_count
        else 0.0
    )
    status = (
        "COMPLIANT"
        if score >= 80.0
        else "AT_RISK"
        if evaluated_count
        else "NOT_ASSESSED"
    )
    latest_scan_utc = _as_utc_datetime(latest_scan_at)
    stale = bool(
        latest_scan_utc
        and datetime.now(timezone.utc) - latest_scan_utc
        > timedelta(hours=stale_after_hours)
    )
    if stale and evaluated_count:
        status = "STALE"
    findings = [check for check in checks.values() if check["result"] == "failed"]
    findings.sort(key=lambda item: _SEVERITY_ORDER.get(item["severity"], 5))

    return {
        "tenant_id": tenant_id,
        "agent_id": agent_id,
        "assessor": "WarSOC Configuration Assessor",
        "assessment_trust": "AGENT_REPORTED",
        "claim_boundary": "Endpoint configuration evidence; not independent certification.",
        "benchmark": policy,
        "scan_id": scan_id,
        "compliance_score": score,
        "status": status,
        "freshness": "STALE" if stale else "CURRENT",
        "summary": {
            "total_checks": len(checks),
            "passed": passed_count,
            "failed": failed_count,
            "not_applicable": na_count,
        },
        "findings": findings,
        "last_scanned_at": _as_text_time(latest_scan_at) or None,
    }


async def get_all_agents_sca_postures(
    db: Any,
    tenant_id: str,
    agent_ids: list[str],
    stale_after_hours: int = 36,
) -> dict[str, dict[str, Any]]:
    """Build current-scan postures with one bounded observation query."""
    requested_ids = list(dict.fromkeys(str(value) for value in agent_ids if value))
    if not requested_ids:
        return {}

    results = {
        agent_id: _empty_posture(tenant_id, agent_id)
        for agent_id in requested_ids
    }
    observations = getattr(db, "detection_engine_observations", None)
    if observations is None:
        return results

    alias_to_requested = {agent_id: agent_id for agent_id in requested_ids}
    bindings = getattr(db, "detection_engine_agent_bindings", None)
    if bindings is not None:
        binding_cursor = bindings.find(
            {
                "tenant_id": tenant_id,
                "$or": [
                    {"warsoc_agent_id": {"$in": requested_ids}},
                    {"wazuh_agent_id": {"$in": requested_ids}},
                ],
            }
        )
        async for binding in binding_cursor:
            warsoc_id = str(binding.get("warsoc_agent_id") or "")
            wazuh_id = str(binding.get("wazuh_agent_id") or "")
            if warsoc_id in results and wazuh_id:
                alias_to_requested[wazuh_id] = warsoc_id
            elif wazuh_id in results:
                alias_to_requested[wazuh_id] = wazuh_id

    aliases = list(alias_to_requested)
    query = {
        "tenant_id": tenant_id,
        "category": "system_audit",
        "selected_security_fields.sca_type": "check",
        "selected_security_fields.check_id": {"$exists": True, "$ne": ""},
        "selected_security_fields.result": {"$in": list(_RESULTS)},
        "$or": [
            {"wazuh_agent_id": {"$in": aliases}},
            {"wazuh_agent_name": {"$in": requested_ids}},
            {"selected_security_fields.agent_id": {"$in": requested_ids}},
        ],
    }
    cursor = (
        observations.find(query)
        .sort("engine_detected_at", -1)
        .limit(MAX_SCA_OBSERVATIONS_PER_REQUEST)
    )

    checks_by_agent: dict[str, dict[str, dict[str, Any]]] = {
        agent_id: {} for agent_id in requested_ids
    }
    policy_by_agent: dict[str, str] = {}
    scan_by_agent: dict[str, str] = {}
    latest_scan_by_agent: dict[str, Any] = {}

    async for document in cursor:
        fields = document.get("selected_security_fields") or {}
        candidates = (
            str(document.get("wazuh_agent_id") or ""),
            str(document.get("wazuh_agent_name") or ""),
            str(fields.get("agent_id") or ""),
        )
        agent_id = next(
            (
                alias_to_requested.get(candidate, candidate)
                for candidate in candidates
                if alias_to_requested.get(candidate, candidate) in checks_by_agent
            ),
            None,
        )
        if not agent_id:
            continue

        scan_id = str(fields.get("scan_id") or "__NO_SCAN_ID__")
        if agent_id not in scan_by_agent:
            scan_by_agent[agent_id] = scan_id
        elif scan_by_agent[agent_id] != scan_id:
            continue

        check_id = str(fields.get("check_id") or "").strip()
        result = _normalise_result(fields.get("result"))
        if not check_id or result is None or check_id in checks_by_agent[agent_id]:
            continue

        policy = str(fields.get("policy") or "").strip()
        if policy and agent_id not in policy_by_agent:
            policy_by_agent[agent_id] = policy
        detected_at = document.get("engine_detected_at") or document.get("received_at")
        if agent_id not in latest_scan_by_agent and detected_at:
            latest_scan_by_agent[agent_id] = detected_at

        cis_control = (
            fields.get("compliance_cis")
            or fields.get("compliance_cis_csc_v8")
            or "CIS-Baseline"
        )
        checks_by_agent[agent_id][check_id] = {
            "check_id": check_id,
            "title": str(fields.get("check_title") or check_id),
            "result": result,
            "severity": str(document.get("severity") or "MEDIUM").upper(),
            "policy": policy_by_agent.get(agent_id, "CIS Security Benchmark"),
            "cis_control": str(cis_control),
            "rationale": str(fields.get("rationale") or ""),
            "remediation": str(fields.get("remediation") or ""),
            "evaluated_at": _as_text_time(detected_at),
        }

    for agent_id in requested_ids:
        results[agent_id] = _posture_from_checks(
            tenant_id=tenant_id,
            agent_id=agent_id,
            checks=checks_by_agent[agent_id],
            policy=policy_by_agent.get(agent_id, "CIS Security Benchmark"),
            scan_id=scan_by_agent.get(agent_id),
            latest_scan_at=latest_scan_by_agent.get(agent_id),
            stale_after_hours=stale_after_hours,
        )
    return results


async def get_agent_sca_posture(
    db: Any,
    tenant_id: str,
    agent_id: str,
    stale_after_hours: int = 36,
) -> dict[str, Any]:
    postures = await get_all_agents_sca_postures(
        db, tenant_id, [agent_id], stale_after_hours
    )
    return postures.get(agent_id) or _empty_posture(tenant_id, agent_id)


async def get_tenant_sca_summary(
    db: Any, tenant_id: str, stale_after_hours: int = 36
) -> dict[str, Any]:
    agents = getattr(db, "agents", None)
    if agents is None:
        agent_documents = []
    else:
        agent_documents = await agents.find(
            {"tenant_id": tenant_id, "status": "active"},
            {"_id": 0, "agent_id": 1},
        ).limit(1000).to_list(length=1000)
    agent_ids = [
        str(document.get("agent_id") or "")
        for document in agent_documents
        if document.get("agent_id")
    ]
    postures = await get_all_agents_sca_postures(
        db, tenant_id, agent_ids, stale_after_hours
    )
    assessed = [
        posture
        for posture in postures.values()
        if posture["summary"]["total_checks"] > 0
    ]
    scores = [float(posture["compliance_score"]) for posture in assessed]
    endpoint_summaries = [
        {
            "agent_id": agent_id,
            "status": posture["status"],
            "freshness": posture["freshness"],
            "compliance_score": posture["compliance_score"],
            "benchmark": posture["benchmark"],
            "last_scanned_at": posture["last_scanned_at"],
        }
        for agent_id, posture in postures.items()
    ]
    endpoint_summaries.sort(
        key=lambda item: (
            item["status"] == "NOT_ASSESSED",
            str(item["agent_id"]),
        )
    )
    return {
        "tenant_id": tenant_id,
        "total_endpoints": len(agent_ids),
        "assessed_endpoints": len(assessed),
        "average_compliance_score": round(sum(scores) / len(scores), 1) if scores else 0.0,
        "compliant_endpoints": sum(
            1 for posture in assessed if posture["status"] == "COMPLIANT"
        ),
        "at_risk_endpoints": sum(
            1 for posture in assessed if posture["status"] == "AT_RISK"
        ),
        "stale_endpoints": sum(
            1 for posture in assessed if posture["status"] == "STALE"
        ),
        "assessment_trust": "AGENT_REPORTED",
        "claim_boundary": "Endpoint configuration evidence; not independent certification.",
        "endpoints": endpoint_summaries,
    }


def _empty_posture(tenant_id: str, agent_id: str) -> dict[str, Any]:
    return {
        "tenant_id": tenant_id,
        "agent_id": agent_id,
        "assessor": "WarSOC Configuration Assessor",
        "assessment_trust": "AGENT_REPORTED",
        "claim_boundary": "Endpoint configuration evidence; not independent certification.",
        "benchmark": "CIS Security Benchmark",
        "scan_id": None,
        "compliance_score": 0.0,
        "status": "NOT_ASSESSED",
        "freshness": "NOT_ASSESSED",
        "summary": {
            "total_checks": 0,
            "passed": 0,
            "failed": 0,
            "not_applicable": 0,
        },
        "findings": [],
        "last_scanned_at": None,
    }
