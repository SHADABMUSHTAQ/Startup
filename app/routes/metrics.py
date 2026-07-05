from fastapi import APIRouter, HTTPException, Request, Response
import ipaddress
import json
import time
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest

from app.config.config import get_settings
from app.utils.observability import (
    get_auth_fail_closed_total,
    get_dlq_depth,
    get_redis_health,
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
    worker_ages = {
        "siem_worker": None,
        "fbr_worker": None,
        "peca_worker": None,
    }

    dlq_ejections_total = 0
    redis_counters = {
        "warsoc_fim_delete_intents_total": 0,
        "warsoc_fim_correlations_total": 0,
        "warsoc_fim_correlation_misses_total": 0,
        "warsoc_fim_4663_writes_ignored_total": 0,
        "warsoc_fim_external_events_rejected_total": 0,
        "warsoc_email_delivered_total": 0,
        "warsoc_email_retries_total": 0,
        "warsoc_email_dlq_total": 0,
    }
    email_queue_depth = 0
    email_processing_depth = 0
    email_dead_letter_depth = 0
    agent_parse_failures = 0
    agent_channel_failures = 0
    detection_latency_seconds = 0.0
    if redis_client:
        try:
            value = await redis_client.get("warsoc_dlq_ejections_total")
            dlq_ejections_total = int(value or 0)
        except Exception:
            dlq_ejections_total = 0
        try:
            values = await redis_client.mget(list(redis_counters))
            for key, value in zip(redis_counters, values):
                redis_counters[key] = int(value or 0)
            detection_latency_seconds = float(
                await redis_client.get("warsoc_detection_latency_seconds") or 0
            )
            email_queue_depth, email_processing_depth, email_dead_letter_depth = [
                int(value or 0)
                for value in await redis_client.pipeline(transaction=False)
                .llen("email_alert_queue")
                .llen("email_alert_queue:processing")
                .llen("email_alert_queue:dead")
                .execute()
            ]
        except Exception:
            pass
        try:
            heartbeat_keys = [
                f"warsoc:worker_heartbeat:{worker_name}"
                for worker_name in worker_ages
            ]
            heartbeat_values = await redis_client.mget(heartbeat_keys)
            now_epoch = time.time()
            for worker_name, heartbeat_value in zip(worker_ages, heartbeat_values):
                if heartbeat_value is not None:
                    worker_ages[worker_name] = max(
                        0.0,
                        now_epoch - float(heartbeat_value),
                    )
        except Exception:
            pass
        try:
            cursor = 0
            while True:
                cursor, keys = await redis_client.scan(
                    cursor=cursor,
                    match="warsoc:agent_sensor:*",
                    count=200,
                )
                if keys:
                    for raw_status in await redis_client.mget(keys):
                        if not raw_status:
                            continue
                        status = json.loads(raw_status)
                        counters = status.get("counters") or {}
                        agent_parse_failures += int(counters.get("windows_parse_failures") or 0)
                        agent_parse_failures += int(counters.get("pos_jsonl_rejections") or 0)
                        agent_channel_failures += int(counters.get("channel_failures") or 0)
                if cursor == 0:
                    break
        except Exception:
            pass
    observed_ages = [age for age in worker_ages.values() if age is not None]
    worker_staleness_seconds = max(observed_ages) if observed_ages else 0.0

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
            "# HELP warsoc_fim_delete_intents_total Native 4663 delete intents cached in Redis.",
            "# TYPE warsoc_fim_delete_intents_total counter",
            f"warsoc_fim_delete_intents_total {redis_counters['warsoc_fim_delete_intents_total']}",
            "# HELP warsoc_fim_correlations_total Confirmed native database tamper correlations.",
            "# TYPE warsoc_fim_correlations_total counter",
            f"warsoc_fim_correlations_total {redis_counters['warsoc_fim_correlations_total']}",
            "# HELP warsoc_fim_correlation_misses_total Native 4660 events without usable Redis context.",
            "# TYPE warsoc_fim_correlation_misses_total counter",
            f"warsoc_fim_correlation_misses_total {redis_counters['warsoc_fim_correlation_misses_total']}",
            "# HELP warsoc_fim_4663_writes_ignored_total Non-delete 4663 events ignored by FBR.",
            "# TYPE warsoc_fim_4663_writes_ignored_total counter",
            f"warsoc_fim_4663_writes_ignored_total {redis_counters['warsoc_fim_4663_writes_ignored_total']}",
            "# HELP warsoc_fim_external_events_rejected_total Externally supplied FIM-DB-MOD events rejected by FBR.",
            "# TYPE warsoc_fim_external_events_rejected_total counter",
            f"warsoc_fim_external_events_rejected_total {redis_counters['warsoc_fim_external_events_rejected_total']}",
            "# HELP warsoc_email_delivered_total Email jobs acknowledged after SMTP delivery.",
            "# TYPE warsoc_email_delivered_total counter",
            f"warsoc_email_delivered_total {redis_counters['warsoc_email_delivered_total']}",
            "# HELP warsoc_email_retries_total Transient email failures requeued for delivery.",
            "# TYPE warsoc_email_retries_total counter",
            f"warsoc_email_retries_total {redis_counters['warsoc_email_retries_total']}",
            "# HELP warsoc_email_dlq_total Email jobs quarantined after exhausting retries.",
            "# TYPE warsoc_email_dlq_total counter",
            f"warsoc_email_dlq_total {redis_counters['warsoc_email_dlq_total']}",
            "# HELP warsoc_email_queue_depth Email jobs waiting for a delivery attempt.",
            "# TYPE warsoc_email_queue_depth gauge",
            f"warsoc_email_queue_depth {email_queue_depth}",
            "# HELP warsoc_email_processing_depth Email jobs currently reserved by a worker.",
            "# TYPE warsoc_email_processing_depth gauge",
            f"warsoc_email_processing_depth {email_processing_depth}",
            "# HELP warsoc_email_dead_letter_depth Email jobs requiring operator review.",
            "# TYPE warsoc_email_dead_letter_depth gauge",
            f"warsoc_email_dead_letter_depth {email_dead_letter_depth}",
            "# HELP warsoc_agent_parse_failures_total Agent XML and POS JSONL parse failures.",
            "# TYPE warsoc_agent_parse_failures_total gauge",
            f"warsoc_agent_parse_failures_total {agent_parse_failures}",
            "# HELP warsoc_agent_channel_failures_total Native Windows channel read failures.",
            "# TYPE warsoc_agent_channel_failures_total gauge",
            f"warsoc_agent_channel_failures_total {agent_channel_failures}",
            "# HELP warsoc_detection_latency_seconds Last observed event-to-alert latency.",
            "# TYPE warsoc_detection_latency_seconds gauge",
            f"warsoc_detection_latency_seconds {detection_latency_seconds}",
            "# HELP warsoc_worker_staleness_seconds Age of the oldest registered worker heartbeat.",
            "# TYPE warsoc_worker_staleness_seconds gauge",
            f"warsoc_worker_staleness_seconds {worker_staleness_seconds}",
            "# HELP warsoc_siem_worker_age_seconds Age in seconds since the SIEM worker heartbeat.",
            "# TYPE warsoc_siem_worker_age_seconds gauge",
            f"warsoc_siem_worker_age_seconds {worker_ages['siem_worker'] if worker_ages['siem_worker'] is not None else 0}",
            "# HELP warsoc_fbr_worker_age_seconds Age in seconds since the FBR worker heartbeat.",
            "# TYPE warsoc_fbr_worker_age_seconds gauge",
            f"warsoc_fbr_worker_age_seconds {worker_ages['fbr_worker'] if worker_ages['fbr_worker'] is not None else 0}",
            "# HELP warsoc_peca_worker_age_seconds Age in seconds since the PECA worker heartbeat.",
            "# TYPE warsoc_peca_worker_age_seconds gauge",
            f"warsoc_peca_worker_age_seconds {worker_ages['peca_worker'] if worker_ages['peca_worker'] is not None else 0}",
            "",
        ]
    )
    return Response(content=base_metrics + "\n" + custom_metrics, media_type=CONTENT_TYPE_LATEST)
