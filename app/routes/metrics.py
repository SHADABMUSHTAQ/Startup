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
        "stream_retention_worker": None,
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
        "warsoc_security_alert_email_suppressed_total": 0,
        "warsoc_endpoint_event_signatures_verified_total": 0,
        "warsoc_endpoint_event_signatures_unsigned_total": 0,
        "warsoc_endpoint_event_signatures_rejected_total": 0,
        "warsoc_raw_stream_trimmed_total": 0,
        "warsoc_siem_hot_stream_trimmed_total": 0,
        "warsoc_network_relay_batches_accepted_total": 0,
        "warsoc_network_relay_batches_duplicate_total": 0,
        "warsoc_network_relay_batches_rejected_total": 0,
        "warsoc_network_relay_events_accepted_total": 0,
        "warsoc_network_relay_control_records_total": 0,
        "warsoc_network_relay_reported_drops_total": 0,
        "warsoc_network_relay_reported_dropped_bytes_total": 0,
    }
    email_queue_depth = 0
    email_processing_depth = 0
    email_dead_letter_depth = 0
    agent_parse_failures = 0
    agent_channel_failures = 0
    agent_spool_limit_hits = 0
    agent_spool_blocked = 0
    agent_spool_usage_bytes = 0
    raw_stream_depth = 0
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
            raw_stream_depth = int(await redis_client.xlen("raw_logs_queue"))
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
                        agent_spool_limit_hits += int(counters.get("spool_limit_hits") or 0)
                        spool = status.get("spool") or {}
                        agent_spool_usage_bytes += int(spool.get("usage_bytes") or 0)
                        agent_spool_blocked += 1 if spool.get("blocked") else 0
                if cursor == 0:
                    break
        except Exception:
            pass
    observed_ages = [age for age in worker_ages.values() if age is not None]
    worker_staleness_seconds = max(observed_ages) if observed_ages else 0.0
    worker_up = {
        worker_name: int(age is not None and age <= 120)
        for worker_name, age in worker_ages.items()
    }
    required_workers_healthy = int(all(worker_up.values()))

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
            "# HELP warsoc_security_alert_email_suppressed_total Security-alert emails intentionally suppressed while dashboard alerts remain active.",
            "# TYPE warsoc_security_alert_email_suppressed_total counter",
            f"warsoc_security_alert_email_suppressed_total {redis_counters['warsoc_security_alert_email_suppressed_total']}",
            "# HELP warsoc_endpoint_event_signatures_verified_total Endpoint telemetry events admitted with a valid Ed25519 signature.",
            "# TYPE warsoc_endpoint_event_signatures_verified_total counter",
            f"warsoc_endpoint_event_signatures_verified_total {redis_counters['warsoc_endpoint_event_signatures_verified_total']}",
            "# HELP warsoc_endpoint_event_signatures_unsigned_total Legacy endpoint events admitted during observe-mode rollout.",
            "# TYPE warsoc_endpoint_event_signatures_unsigned_total counter",
            f"warsoc_endpoint_event_signatures_unsigned_total {redis_counters['warsoc_endpoint_event_signatures_unsigned_total']}",
            "# HELP warsoc_endpoint_event_signatures_rejected_total Endpoint events rejected for invalid or required-but-missing signatures.",
            "# TYPE warsoc_endpoint_event_signatures_rejected_total counter",
            f"warsoc_endpoint_event_signatures_rejected_total {redis_counters['warsoc_endpoint_event_signatures_rejected_total']}",
            "# HELP warsoc_network_relay_batches_accepted_total Signed relay batches durably admitted and receipted.",
            "# TYPE warsoc_network_relay_batches_accepted_total counter",
            f"warsoc_network_relay_batches_accepted_total {redis_counters['warsoc_network_relay_batches_accepted_total']}",
            "# HELP warsoc_network_relay_batches_duplicate_total Signed relay retries acknowledged without duplicate queue writes.",
            "# TYPE warsoc_network_relay_batches_duplicate_total counter",
            f"warsoc_network_relay_batches_duplicate_total {redis_counters['warsoc_network_relay_batches_duplicate_total']}",
            "# HELP warsoc_network_relay_batches_rejected_total Relay batches rejected for identity, chain, or signature failures.",
            "# TYPE warsoc_network_relay_batches_rejected_total counter",
            f"warsoc_network_relay_batches_rejected_total {redis_counters['warsoc_network_relay_batches_rejected_total']}",
            "# HELP warsoc_network_relay_events_accepted_total Relay evidence and control records durably admitted to the raw stream.",
            "# TYPE warsoc_network_relay_events_accepted_total counter",
            f"warsoc_network_relay_events_accepted_total {redis_counters['warsoc_network_relay_events_accepted_total']}",
            "# HELP warsoc_network_relay_control_records_total Signed relay health and loss records durably admitted.",
            "# TYPE warsoc_network_relay_control_records_total counter",
            f"warsoc_network_relay_control_records_total {redis_counters['warsoc_network_relay_control_records_total']}",
            "# HELP warsoc_network_relay_reported_drops_total LAN syslog records the relay reports dropping or quarantining.",
            "# TYPE warsoc_network_relay_reported_drops_total counter",
            f"warsoc_network_relay_reported_drops_total {redis_counters['warsoc_network_relay_reported_drops_total']}",
            "# HELP warsoc_network_relay_reported_dropped_bytes_total LAN syslog bytes the relay reports dropping or quarantining.",
            "# TYPE warsoc_network_relay_reported_dropped_bytes_total counter",
            f"warsoc_network_relay_reported_dropped_bytes_total {redis_counters['warsoc_network_relay_reported_dropped_bytes_total']}",
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
            "# HELP warsoc_agent_spool_limit_hits_total Agent spool admission failures reported by active agents.",
            "# TYPE warsoc_agent_spool_limit_hits_total gauge",
            f"warsoc_agent_spool_limit_hits_total {agent_spool_limit_hits}",
            "# HELP warsoc_agent_spool_blocked Active agents currently paused by spool or disk boundaries.",
            "# TYPE warsoc_agent_spool_blocked gauge",
            f"warsoc_agent_spool_blocked {agent_spool_blocked}",
            "# HELP warsoc_agent_spool_usage_bytes Total durable spool bytes reported by active agents.",
            "# TYPE warsoc_agent_spool_usage_bytes gauge",
            f"warsoc_agent_spool_usage_bytes {agent_spool_usage_bytes}",
            "# HELP warsoc_raw_stream_depth Current entries in the shared raw ingest stream.",
            "# TYPE warsoc_raw_stream_depth gauge",
            f"warsoc_raw_stream_depth {raw_stream_depth}",
            "# HELP warsoc_raw_stream_trimmed_total Fully acknowledged raw-stream entries safely reclaimed.",
            "# TYPE warsoc_raw_stream_trimmed_total counter",
            f"warsoc_raw_stream_trimmed_total {redis_counters['warsoc_raw_stream_trimmed_total']}",
            "# HELP warsoc_siem_hot_stream_trimmed_total Fully acknowledged SIEM hot-stream entries safely reclaimed.",
            "# TYPE warsoc_siem_hot_stream_trimmed_total counter",
            f"warsoc_siem_hot_stream_trimmed_total {redis_counters['warsoc_siem_hot_stream_trimmed_total']}",
            "# HELP warsoc_detection_latency_seconds Last observed event-to-alert latency.",
            "# TYPE warsoc_detection_latency_seconds gauge",
            f"warsoc_detection_latency_seconds {detection_latency_seconds}",
            "# HELP warsoc_worker_staleness_seconds Age of the oldest registered worker heartbeat.",
            "# TYPE warsoc_worker_staleness_seconds gauge",
            f"warsoc_worker_staleness_seconds {worker_staleness_seconds}",
            "# HELP warsoc_required_workers_healthy All required SIEM/FBR/PECA/retention workers have a recent heartbeat.",
            "# TYPE warsoc_required_workers_healthy gauge",
            f"warsoc_required_workers_healthy {required_workers_healthy}",
            "# HELP warsoc_siem_worker_age_seconds Age in seconds since the SIEM worker heartbeat.",
            "# TYPE warsoc_siem_worker_age_seconds gauge",
            f"warsoc_siem_worker_age_seconds {worker_ages['siem_worker'] if worker_ages['siem_worker'] is not None else 0}",
            "# HELP warsoc_siem_worker_up SIEM worker heartbeat is present and no older than 120 seconds.",
            "# TYPE warsoc_siem_worker_up gauge",
            f"warsoc_siem_worker_up {worker_up['siem_worker']}",
            "# HELP warsoc_fbr_worker_age_seconds Age in seconds since the FBR worker heartbeat.",
            "# TYPE warsoc_fbr_worker_age_seconds gauge",
            f"warsoc_fbr_worker_age_seconds {worker_ages['fbr_worker'] if worker_ages['fbr_worker'] is not None else 0}",
            "# HELP warsoc_fbr_worker_up FBR worker heartbeat is present and no older than 120 seconds.",
            "# TYPE warsoc_fbr_worker_up gauge",
            f"warsoc_fbr_worker_up {worker_up['fbr_worker']}",
            "# HELP warsoc_peca_worker_age_seconds Age in seconds since the PECA worker heartbeat.",
            "# TYPE warsoc_peca_worker_age_seconds gauge",
            f"warsoc_peca_worker_age_seconds {worker_ages['peca_worker'] if worker_ages['peca_worker'] is not None else 0}",
            "# HELP warsoc_peca_worker_up PECA worker heartbeat is present and no older than 120 seconds.",
            "# TYPE warsoc_peca_worker_up gauge",
            f"warsoc_peca_worker_up {worker_up['peca_worker']}",
            "# HELP warsoc_stream_retention_worker_age_seconds Age in seconds since the safe stream-retention heartbeat.",
            "# TYPE warsoc_stream_retention_worker_age_seconds gauge",
            f"warsoc_stream_retention_worker_age_seconds {worker_ages['stream_retention_worker'] if worker_ages['stream_retention_worker'] is not None else 0}",
            "# HELP warsoc_stream_retention_worker_up Safe stream-retention heartbeat is present and no older than 120 seconds.",
            "# TYPE warsoc_stream_retention_worker_up gauge",
            f"warsoc_stream_retention_worker_up {worker_up['stream_retention_worker']}",
            "",
        ]
    )
    return Response(content=base_metrics + "\n" + custom_metrics, media_type=CONTENT_TYPE_LATEST)
