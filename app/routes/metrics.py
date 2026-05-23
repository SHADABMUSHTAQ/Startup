from fastapi import APIRouter, HTTPException, Request, Response
import ipaddress
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest

from app.config.config import get_settings
from app.utils.observability import (
    get_auth_fail_closed_total,
    get_dlq_depth,
    get_redis_health,
    get_worker_heartbeat_age,
    get_worker_staleness_seconds,
)

router = APIRouter()
settings = get_settings()


def _parse_allowlist(raw_ips: str) -> list[str]:
    return [entry.strip() for entry in raw_ips.split(",") if entry.strip()]


def _client_ip_allowed(client_ip: str, allowlist: list[str]) -> bool:
    if not client_ip:
        return False

    for entry in allowlist:
        if entry == client_ip:
            return True
        if "/" in entry:
            try:
                if ipaddress.ip_address(client_ip) in ipaddress.ip_network(entry, strict=False):
                    return True
            except ValueError:
                continue
    return False


@router.get("/metrics")
async def metrics(request: Request):
    """Expose raw Prometheus metrics for platform monitoring."""
    allowlist = _parse_allowlist(settings.metrics_allowlist_ips)
    client_ip = request.client.host if request.client else ""
    bearer_token = ""
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        bearer_token = auth_header.removeprefix("Bearer ").strip()

    token_allowed = bool(settings.metrics_bearer_token and bearer_token == settings.metrics_bearer_token)
    ip_allowed = _client_ip_allowed(client_ip, allowlist)
    if not (ip_allowed or token_allowed):
        raise HTTPException(status_code=403, detail="Forbidden: metrics access denied")

    redis_client = getattr(request.app.state, "redis", None)
    redis_health = await get_redis_health(redis_client)
    dlq_depth = await get_dlq_depth(redis_client)
    auth_fail_closed_total = get_auth_fail_closed_total()
    peca_worker_age_seconds = get_worker_heartbeat_age("peca_worker")
    detection_worker_age_seconds = get_worker_heartbeat_age("detection_worker")
    worker_staleness_seconds = get_worker_staleness_seconds()

    dlq_ejections_total = 0
    if redis_client:
        try:
            value = await redis_client.get("warsoc_dlq_ejections_total")
            dlq_ejections_total = int(value or 0)
        except Exception:
            dlq_ejections_total = 0

    base_metrics = generate_latest().decode("utf-8", errors="replace")
    custom_metrics = "\n".join(
        [
            "# HELP warsoc_redis_health Redis reachability (1 reachable, 0 unreachable).",
            "# TYPE warsoc_redis_health gauge",
            f"warsoc_redis_health {redis_health}",
            "# HELP warsoc_dlq_depth Current total depth across tenant DLQ streams.",
            "# TYPE warsoc_dlq_depth gauge",
            f"warsoc_dlq_depth {dlq_depth}",
            "# HELP warsoc_auth_fail_closed_total Count of auth denials caused by Redis revocation-check failures.",
            "# TYPE warsoc_auth_fail_closed_total counter",
            f"warsoc_auth_fail_closed_total {auth_fail_closed_total}",
            "# HELP warsoc_dlq_ejections_total Count of DLQ ejections written by workers.",
            "# TYPE warsoc_dlq_ejections_total counter",
            f"warsoc_dlq_ejections_total {dlq_ejections_total}",
            "# HELP warsoc_worker_staleness_seconds Age of the oldest registered worker heartbeat.",
            "# TYPE warsoc_worker_staleness_seconds gauge",
            f"warsoc_worker_staleness_seconds {worker_staleness_seconds}",
            "# HELP warsoc_peca_worker_age_seconds Age in seconds since the PECA worker heartbeat.",
            "# TYPE warsoc_peca_worker_age_seconds gauge",
            f"warsoc_peca_worker_age_seconds {peca_worker_age_seconds if peca_worker_age_seconds is not None else 0}",
            "# HELP warsoc_detection_worker_age_seconds Age in seconds since the detection worker heartbeat.",
            "# TYPE warsoc_detection_worker_age_seconds gauge",
            f"warsoc_detection_worker_age_seconds {detection_worker_age_seconds if detection_worker_age_seconds is not None else 0}",
            "",
        ]
    )
    return Response(content=base_metrics + "\n" + custom_metrics, media_type=CONTENT_TYPE_LATEST)
