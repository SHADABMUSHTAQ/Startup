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
    assert 'max-size: "10m"' in compose
    assert 'max-file: "5"' in compose
    assert compose.count("logging: *warsoc-logging") == 9


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
    assert '"/agent/download"' not in threat_intel
    assert "StreamingResponse" not in threat_intel
    assert "COPY ./agent ./agent" not in dockerfile
    assert "COPY ./scripts/launch_readiness_validator.py" in dockerfile
    assert "!scripts/launch_readiness_validator.py" in dockerignore
    assert "agent/" in dockerignore


def test_pilot_manifest_covers_complete_executable_installation_chain():
    manifest_script = _read("scripts/generate_pilot_hash_manifest.ps1")
    assert "warsoc_installer-4.2.6.exe" in manifest_script
    assert "warsoc_agent.exe" in manifest_script
    assert "tools\\nssm\\nssm.exe" in manifest_script
    assert "agent\\deploy_warsoc_telemetry.ps1" in manifest_script
    assert "agent\\tenant_policy.json" in manifest_script
    assert "windows-service-manager" in manifest_script
    assert "native-telemetry-configuration" in manifest_script
    assert "tenant-monitoring-policy" in manifest_script


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
