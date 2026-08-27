from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def _read(relative_path: str) -> str:
    return (ROOT / relative_path).read_text(encoding="utf-8", errors="replace")


def test_production_gateway_uses_real_domain_certbot_and_health_proxy():
    nginx = _read("nginx/nginx.prod.conf")
    assert "server_name api.warsoc.tech;" in nginx
    assert "/etc/nginx/ssl/live/api.warsoc.tech/fullchain.pem" in nginx
    assert "/etc/nginx/ssl/live/api.warsoc.tech/privkey.pem" in nginx
    assert "location = /health" in nginx
    assert "location = /metrics" in nginx
    assert "proxy_pass http://warsoc_api/metrics;" in nginx
    assert "access_log /dev/stdout;" in nginx
    assert "error_log /dev/stderr warn;" in nginx
    assert "server.crt" not in nginx
    assert "server.key" not in nginx
    assert "proxy_connect_timeout 30s;" in nginx
    assert "proxy_read_timeout 120s;" in nginx
    assert "proxy_send_timeout 120s;" in nginx


def test_production_compose_is_private_fail_fast_and_sized_for_pilot():
    compose = _read("docker-compose.prod.yml")
    assert "image: mongo:7" in compose
    assert "/etc/letsencrypt:/etc/nginx/ssl:ro" in compose
    assert "./certbot/www:/var/www/certbot:ro" in compose
    assert "- /var/run" in compose
    assert 'profiles: ["network-syslog"]' in compose
    assert "${SYSLOG_BIND:-127.0.0.1}:5140:5140/udp" in compose
    assert "SYSLOG_ALLOWED_SOURCES" in compose
    assert "AZURE_IMMUTABILITY_REQUIRED" in compose
    assert "0.0.0.0}:5140" not in compose
    assert "AGENT_CDN_URL required" in compose
    assert "ENABLE_MANUAL_LOG_INJECTION: ${ENABLE_MANUAL_LOG_INJECTION:-false}" in compose
    assert "SALES_EMAIL required" in compose
    assert "ZOHO_SMTP_USER required" in compose
    assert "ZOHO_SMTP_PASS required" in compose
    assert "--maxmemory-policy noeviction" in compose
    assert "INGEST_DAILY_BYTES_FLOOR: ${INGEST_DAILY_BYTES_FLOOR:-52428800}" in compose
    assert "RAW_STREAM_MAX_BYTES: ${RAW_STREAM_MAX_BYTES:-201326592}" in compose
    assert "REDIS_INGEST_MEMORY_HIGH_WATERMARK_PERCENT" in compose
    assert "REDIS_INGEST_MEMORY_RESERVE_BYTES" in compose
    assert 'max-size: "10m"' in compose
    assert 'max-file: "5"' in compose
    assert compose.count("logging: *warsoc-logging") >= 10
    assert 'profiles: ["wazuh-detection"]' in compose
    assert "container_name: warsoc-wazuh-dispatch-prod" in compose
    assert "container_name: warsoc-wazuh-candidate-api-prod" in compose
    assert '${WAZUH_CANDIDATE_BIND_IP:-127.0.0.1}:${WAZUH_CANDIDATE_PORT:-8443}:8010' in compose
    assert 'container_name: warsoc-evidence-export-worker-prod\n    profiles: ["evidence-export"]' in compose


def test_backend_contains_only_the_cdn_agent_download_route():
    orchestration = _read("app/routes/agent_orchestration.py")
    config = _read("app/config/config.py")
    threat_intel = _read("app/routes/threat_intel.py")
    dockerfile = _read("Dockerfile")
    dockerignore = _read(".dockerignore")

    assert '@router.get("/download")' in orchestration
    assert "settings.agent_cdn_url" in orchestration
    assert "parsed.scheme == \"https\"" in orchestration
    assert 'parsed.path.lower().endswith(".exe")' in orchestration
    assert '"AGENT_CDN_URL": s.agent_cdn_url' in config
    assert "must be an HTTPS URL that points directly" in config
    assert 'detail="Agent download is temporarily unavailable."' in orchestration
    assert '"Cache-Control": "no-store"' in orchestration
    assert '"Referrer-Policy": "no-referrer"' in orchestration
    assert '"/agent/download"' not in threat_intel
    assert "StreamingResponse" not in threat_intel
    assert "COPY ./agent ./agent" not in dockerfile
    assert "COPY ./scripts/launch_readiness_validator.py" in dockerfile
    assert "COPY ./scripts/seed_wazuh_shadow_registry.py" in dockerfile
    assert "COPY ./deploy/wazuh/registry /app/deploy/wazuh/registry" in dockerfile
    assert "!scripts/launch_readiness_validator.py" in dockerignore
    assert "agent/" in dockerignore


def test_normal_exports_are_explicitly_hot_tier_only():
    export = _read("app/routes/export.py")
    compliance = _read("app/routes/compliance.py")

    assert '"X-WarSOC-Data-Scope": "hot-tier"' in export
    assert '"X-WarSOC-Data-Scope": "hot-tier"' in compliance
    assert '"X-WarSOC-Archive-Retrieval-Required"' in export
    assert '"X-WarSOC-Archive-Retrieval-Required"' in compliance
    assert "[*hot_docs, *archived_docs]" not in export
    assert "[*hot_docs, *archived_docs]" not in compliance
    assert "This PDF does not read those cold records" in export


def test_pilot_manifest_covers_complete_executable_installation_chain():
    manifest_script = _read("scripts/generate_pilot_hash_manifest.ps1")
    assert '[string]$Version = "4.2.9"' in manifest_script
    assert '"Output\\warsoc_installer-$Version.exe"' in manifest_script
    assert '"Output\\pilot_hash_manifest-$Version.json"' in manifest_script
    assert "warsoc_agent.exe" in manifest_script
    assert "tools\\nssm\\nssm.exe" in manifest_script
    assert "agent\\deploy_warsoc_telemetry.ps1" in manifest_script
    assert "agent\\tenant_policy.json" in manifest_script
    assert "windows-service-manager" in manifest_script
    assert "native-telemetry-configuration" in manifest_script
    assert "tenant-monitoring-policy" in manifest_script


def test_production_requires_signed_endpoint_events_by_default():
    compose = _read("docker-compose.prod.yml")
    assert compose.count("AGENT_EVENT_SIGNATURE_MODE: ${AGENT_EVENT_SIGNATURE_MODE:-required}") == 2


def test_wazuh_bridge_initializes_spool_for_non_root_runtime():
    compose = _read("docker-compose.wazuh-bridge.yml")
    assert "warsoc-wazuh-bridge-init:" in compose
    assert "install -d -o 1000 -g 1000 -m 0700 /var/lib/warsoc-wazuh" in compose
    assert 'user: "0:0"' in compose
    assert "- CHOWN" in compose
    assert "- DAC_OVERRIDE" in compose
    assert "- FOWNER" in compose
    assert "condition: service_completed_successfully" in compose
    assert "warsoc_wazuh_bridge_spool:/var/lib/warsoc-wazuh" in compose


def test_database_backup_is_encrypted_offsite_and_fail_closed():
    backup_script = _read("scripts/backup_mongodb.sh")
    assert "mongodump" in backup_script
    assert "--archive" in backup_script
    assert "--gzip" in backup_script
    assert "aes-256-cbc" in backup_script
    assert "BACKUP_ENCRYPTION_PASSPHRASE" in backup_script
    assert "AZURE_BACKUP_CONTAINER_SAS_URL" in backup_script
    assert 'x-ms-blob-type: BlockBlob' in backup_script
    assert "curl" in backup_script

    restore_drill = _read("scripts/run_backup_restore_drill.ps1")
    assert "--network none" in restore_drill
    assert "type=volume,source=$restoreVolume,target=/data/db" in restore_drill
    assert "docker volume rm -f $restoreVolume" in restore_drill
    assert "mongorestore" in restore_drill
    assert "Get-FileHash" in restore_drill
    assert 'requiredCollection in @("tenants", "users")' in restore_drill


def test_auth_and_websocket_contracts_do_not_leak_or_overgrant():
    main = _read("app/main.py")
    auth = _read("app/routes/auth.py")

    assert 'RoleChecker(["admin", "manager", "analyst"])' in main
    assert "await request.body()" not in main
    assert "cookie_present=%s header_present=%s" in auth
    assert "Cookie=" not in auth
    assert "Header=" not in auth


def test_provisioning_and_health_only_count_registered_agents():
    admin = _read("app/routes/admin.py")
    data = _read("app/routes/data.py")
    compliance = _read("app/routes/compliance.py")

    assert 'db["agents"].insert_one' not in admin
    for source in (data, compliance):
        assert '"status": {"$ne": "revoked"}' in source
        assert '"public_key": {"$exists": True, "$ne": ""}' in source
    assert '"max_agents": max_agents' in data
    assert '"services_healthy": redis_client is not None' in data
    assert '"tenant_id": tenant_id' in data


def test_mitigation_is_fail_closed_compensated_and_agent_visible():
    threat_intel = _read("app/routes/threat_intel.py")

    assert '@router.get("/agent/heartbeat/{tenant_id}")' in threat_intel
    assert "Redis is not connected" in threat_intel
    assert "Redis sync failed" in threat_intel
    assert "Mitigation rollback failed after database error" in threat_intel
    assert "Revoke rollback failed after database error" in threat_intel
    assert 'f"warsoc:banned_ips:{secure_tenant_id}"' in threat_intel
    assert "left_network.overlaps(right_network)" in threat_intel
    assert 'f"warsoc:soar_whitelist:{tenant_id}"' in threat_intel


def test_production_acceptance_is_gated_and_verifies_real_artifacts():
    coordinator = _read("scripts/run_production_acceptance.ps1")
    validator = _read("scripts/launch_readiness_validator.py")

    for phase in ("Preflight", "Platform", "NativeGenerate", "NativeVerify", "Soak"):
        assert f'"{phase}"' in coordinator
    assert "ConfirmProductionDataCreation" in coordinator
    assert "ConfirmDisposableVm" in coordinator
    assert "Frontend production API binding" in coordinator
    assert "Frontend API proxy" in coordinator
    assert "Frontend no development API" in coordinator
    assert "Frontend contact uses WarSOC backend" in coordinator
    assert "Frontend/backend CORS" in coordinator
    assert "Azure installer artifact" in coordinator
    assert "foreach ($port in @(27017, 6379, 8000))" in coordinator
    assert "Get-TlsCertificateInfo" in coordinator
    assert "--admin-key" not in coordinator
    assert "--metrics-token" not in coordinator

    assert "NoRedirectHandler" in validator
    assert "Agent installer CDN redirect" in validator
    assert "Agent installer CDN hash" in validator
    assert "warsoc_email_delivered_total" in validator
    assert "--manifest-path" in validator
    assert "--report-path" in validator


def test_legacy_grand_master_harness_is_fail_closed_and_isolated():
    harness = _read("tests/test_grand_master_e2e.py")

    assert 'E2E_API_BASE_URL", ""' in harness
    assert "YES_I_CREATED_AN_ISOLATED_STACK" in harness
    assert 'E2E_DATABASE_NAME.startswith("WarSOC_DB_e2e_")' in harness
    assert 'redis_db == "0"' in harness
    assert "E2E_WORKER_CONTAINER" in harness
    assert "startup-backend-worker-siem-1" not in harness
    assert 'E2E_ENABLE_SYSLOG", "false"' in harness
    assert 'event_id = 4688' in harness
    assert 'event_id = 4672' in harness
    assert 'event_id = 9' not in harness
    assert 'event_id = 10' not in harness


def test_network_relay_is_separate_bounded_and_not_public_cloud_syslog():
    config = _read("deploy/network-relay-config.example.json")
    installer = _read("scripts/install_warsoc_relay.ps1")
    uninstaller = _read("scripts/uninstall_warsoc_relay.ps1")
    runtime = _read("app/network_relay/runtime.py")
    compose = _read("docker-compose.prod.yml")

    assert '"vendor": "pfsense"' in config
    assert '"bind_host": "192.0.2.10"' in config
    assert '"evidence_spool_bytes": 2147483648' in config
    assert "$serviceName = \"WarSOC_Relay\"" in installer
    assert "[switch]$AllowEndpointColocation" in installer
    assert "if ($endpointService -and -not $AllowEndpointColocation)" in installer
    assert "Set-RelayDirectorySecurity" in installer
    assert "New-NetFirewallRule" in installer
    assert "RemoteAddress $sources" in installer
    assert "evidence were preserved intentionally" in uninstaller
    assert "relay listeners must bind an explicit approved interface address" in runtime
    assert "profiles: [\"network-syslog\"]" in compose
    assert "127.0.0.1}:5140:5140/udp" in compose
