#!/usr/bin/env bash
set -Eeuo pipefail

readonly RELEASE_ID="${2:-${WARSOC_RELEASE_ID:-d92fb65}}"
readonly PUBLIC_IP="139.185.60.39"
readonly API_HOST="api.warsoc.tech"
readonly MIGRATION_DIR="/home/ubuntu/warsoc-migration"
readonly RELEASE_ROOT="/opt/warsoc/releases"
readonly RELEASE_DIR="${RELEASE_ROOT}/${RELEASE_ID}"
readonly CURRENT_LINK="/opt/warsoc/Startup-backend"
readonly ARCHIVE="${MIGRATION_DIR}/warsoc-backend-${RELEASE_ID}.tar.gz"
readonly CHECKSUM_FILE="${ARCHIVE}.sha256"
readonly SOURCE_ENV="${MIGRATION_DIR}/.env.prod"
readonly SOURCE_KEYS="${MIGRATION_DIR}/keys"
readonly COMPOSE_FILE="docker-compose.prod.yml"
readonly COMPOSE_PROJECT="warsoc-production"

log() {
    printf '[WarSOC OCI deploy] %s\n' "$*"
}

fail() {
    printf '[WarSOC OCI deploy] ERROR: %s\n' "$*" >&2
    exit 1
}

compose() {
    docker compose \
        --project-name "${COMPOSE_PROJECT}" \
        --env-file .env.prod \
        -f "${COMPOSE_FILE}" \
        "$@"
}

require_root() {
    [[ "${EUID}" -eq 0 ]] || fail "Run with sudo."
}

validate_release_id() {
    [[ "${RELEASE_ID}" =~ ^[A-Za-z0-9._-]{7,64}$ ]] || \
        fail "Release ID must be 7-64 safe filename characters."
}

verify_host() {
    [[ "$(dpkg --print-architecture)" == "arm64" ]] || fail "OCI host is not ARM64."
    systemctl is-active --quiet docker.service || fail "Docker is not active."
    systemctl is-active --quiet warsoc-docker-firewall.service || fail "WarSOC Docker firewall guard is not active."
}

validate_secret_file() {
    local env_file="$1"
    local required_name
    local required_names=(
        MONGO_USER
        MONGO_PASSWORD
        MONGODB_DB_NAME
        REDIS_PASSWORD
        ALLOWED_ORIGINS
        JWT_SECRET_KEY
        AGENT_MASTER_SECRET
        SUPER_ADMIN_API_KEY
        ENCRYPTION_KEY
        PRIVATE_KEY_B64
        METRICS_BEARER_TOKEN
        AGENT_CDN_URL
        SALES_EMAIL
        ZOHO_SMTP_USER
        ZOHO_SMTP_PASS
        AZURE_STORAGE_CONNECTION_STRING
    )

    [[ -s "${env_file}" ]] || fail "Missing production environment file: ${env_file}"
    for required_name in "${required_names[@]}"; do
        if ! grep -Eq "^${required_name}=.+" "${env_file}"; then
            fail "Required variable ${required_name} is absent or empty in the production environment file."
        fi
    done
    if grep -Eqi '^EVIDENCE_EXPORT_ENABLED=(true|1|yes|on)$' "${env_file}"; then
        local export_name
        for export_name in \
            EVIDENCE_EXPORT_CONTAINER \
            EVIDENCE_PACKAGE_PRIVATE_KEY_B64 \
            EVIDENCE_PACKAGE_SIGNING_KEY_ID \
            EVIDENCE_PACKAGE_SIGNING_KEY_VERSION; do
            grep -Eq "^${export_name}=.+" "${env_file}" || \
                fail "Evidence export is enabled but ${export_name} is absent or empty."
        done
    fi

    if grep -Eqi '^AZURE_EXACT_RETENTION_ROUTE_REQUIRED=(true|1|yes|on)$' "${env_file}"; then
        local archive_name
        for archive_name in \
            AZURE_STORAGE_CONTAINER_SIEM_90 \
            AZURE_STORAGE_CONTAINER_GENERAL_90 \
            AZURE_STORAGE_TIER_SIEM_90 \
            AZURE_STORAGE_TIER_GENERAL_90 \
            AZURE_IMMUTABILITY_SCOPE_SIEM_90 \
            AZURE_IMMUTABILITY_SCOPE_GENERAL_90 \
            AZURE_CONTAINER_IMMUTABILITY_LOCKED_SIEM_90 \
            AZURE_CONTAINER_IMMUTABILITY_DAYS_SIEM_90 \
            AZURE_CONTAINER_IMMUTABILITY_LOCKED_GENERAL_90 \
            AZURE_CONTAINER_IMMUTABILITY_DAYS_GENERAL_90; do
            grep -Eq "^${archive_name}=.+" "${env_file}" || \
                fail "Exact Azure retention routing is enabled but ${archive_name} is absent or empty."
        done

        grep -Eqi '^AZURE_IMMUTABILITY_REQUIRED=(true|1|yes|on)$' "${env_file}" || \
            fail "Exact Azure retention routing requires AZURE_IMMUTABILITY_REQUIRED=true."
        grep -Eqi '^AZURE_BLOB_VERSION_ID_REQUIRED=(true|1|yes|on)$' "${env_file}" || \
            fail "Exact Azure retention routing requires AZURE_BLOB_VERSION_ID_REQUIRED=true."
        grep -Eqi '^AZURE_STORAGE_TIER_SIEM_90=cold$' "${env_file}" || \
            fail "The SIEM 90-day route must use the verified Cold tier."
        grep -Eqi '^AZURE_STORAGE_TIER_GENERAL_90=cold$' "${env_file}" || \
            fail "The general 90-day route must use the verified Cold tier."
        grep -Eqi '^AZURE_IMMUTABILITY_SCOPE_SIEM_90=blob$' "${env_file}" || \
            fail "The SIEM 90-day route must verify version-level blob immutability."
        grep -Eqi '^AZURE_IMMUTABILITY_SCOPE_GENERAL_90=blob$' "${env_file}" || \
            fail "The general 90-day route must verify version-level blob immutability."
        grep -Eqi '^AZURE_CONTAINER_IMMUTABILITY_LOCKED_SIEM_90=(true|1|yes|on)$' "${env_file}" || \
            fail "The SIEM 90-day route must declare its independently verified locked policy."
        grep -Eqi '^AZURE_CONTAINER_IMMUTABILITY_LOCKED_GENERAL_90=(true|1|yes|on)$' "${env_file}" || \
            fail "The general 90-day route must declare its independently verified locked policy."
        grep -Eq '^AZURE_CONTAINER_IMMUTABILITY_DAYS_SIEM_90=90$' "${env_file}" || \
            fail "The SIEM 90-day route must declare exactly 90 immutable days."
        grep -Eq '^AZURE_CONTAINER_IMMUTABILITY_DAYS_GENERAL_90=90$' "${env_file}" || \
            fail "The general 90-day route must declare exactly 90 immutable days."

        local siem_container general_container
        siem_container="$(sed -n 's/^AZURE_STORAGE_CONTAINER_SIEM_90=//p' "${env_file}" | tail -n 1 | tr -d "'\"\r")"
        general_container="$(sed -n 's/^AZURE_STORAGE_CONTAINER_GENERAL_90=//p' "${env_file}" | tail -n 1 | tr -d "'\"\r")"
        [[ "${siem_container}" != "${general_container}" ]] || \
            fail "SIEM and general evidence must use separate Azure containers."
    fi
}

normalize_container_entrypoint() {
    local entrypoint_path="${RELEASE_DIR}/scripts/entrypoint.sh"

    [[ -f "${entrypoint_path}" ]] || fail "Container entrypoint is missing: ${entrypoint_path}"

    # Git archives produced from a Windows checkout may retain CRLF bytes. Linux
    # then interprets the shebang as /bin/sh\r and reports a misleading missing-file error.
    if LC_ALL=C grep -q $'\r' "${entrypoint_path}"; then
        log "Normalizing the container entrypoint to Unix line endings."
        sed -i 's/\r$//' "${entrypoint_path}"
    fi

    [[ "$(head -n 1 "${entrypoint_path}")" == '#!/bin/sh' ]] || \
        fail "Container entrypoint has an invalid interpreter line."
    chmod 0755 "${entrypoint_path}"
}

prepare_release() {
    require_root
    validate_release_id
    verify_host

    [[ -s "${ARCHIVE}" ]] || fail "Missing release archive: ${ARCHIVE}"
    [[ -s "${CHECKSUM_FILE}" ]] || fail "Missing release checksum: ${CHECKSUM_FILE}"
    [[ -d "${SOURCE_KEYS}" ]] || fail "Missing signing-key directory: ${SOURCE_KEYS}"
    validate_secret_file "${SOURCE_ENV}"

    log "Verifying immutable release archive ${RELEASE_ID}."
    (
        cd "${MIGRATION_DIR}"
        sha256sum --check "$(basename "${CHECKSUM_FILE}")"
    )

    install -d -m 0750 /opt/warsoc "${RELEASE_ROOT}"
    if [[ ! -d "${RELEASE_DIR}" ]]; then
        temporary_release_dir="${RELEASE_DIR}.extracting"
        rm -rf "${temporary_release_dir}"
        install -d -m 0750 "${temporary_release_dir}"
        tar -xzf "${ARCHIVE}" -C "${temporary_release_dir}"
        printf '%s\n' "${RELEASE_ID}" >"${temporary_release_dir}/.warsoc-release-id"
        mv "${temporary_release_dir}" "${RELEASE_DIR}"
    elif [[ ! -f "${RELEASE_DIR}/.warsoc-release-id" ]] || \
         [[ "$(cat "${RELEASE_DIR}/.warsoc-release-id")" != "${RELEASE_ID}" ]]; then
        fail "Existing release directory is incomplete or has the wrong identity: ${RELEASE_DIR}"
    fi

    normalize_container_entrypoint

    install -m 0600 "${SOURCE_ENV}" "${RELEASE_DIR}/.env.prod"
    install -d -m 0750 "${RELEASE_DIR}/keys"
    cp -a "${SOURCE_KEYS}/." "${RELEASE_DIR}/keys/"
    chown -R 1000:1000 "${RELEASE_DIR}/keys"
    find "${RELEASE_DIR}/keys" -type f -exec chmod 0600 {} +
    install -d -m 0755 "${RELEASE_DIR}/certbot/www"

    ln -sfn "${RELEASE_DIR}" "${CURRENT_LINK}"
    cd "${CURRENT_LINK}"

    log "Validating the production Compose model without printing secrets."
    compose config --quiet

    log "Pulling ARM64 database and edge images."
    compose pull mongodb redis nginx

    log "Building the exact WarSOC ${RELEASE_ID} application image on ARM64."
    compose build warsoc-api unified-worker compliance-cron storage-archiver evidence-hold-worker evidence-export-worker

    log "Starting private persistence services."
    compose up -d mongodb redis

    log "Starting the private API. Nginx is intentionally still stopped."
    compose up -d warsoc-api

    for _ in $(seq 1 36); do
        api_health="$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' warsoc-api-prod 2>/dev/null || true)"
        if [[ "${api_health}" == "healthy" ]]; then
            break
        fi
        sleep 5
    done
    [[ "${api_health:-}" == "healthy" ]] || {
        compose logs --tail 150 warsoc-api mongodb redis
        fail "Private API did not become healthy."
    }

    compose exec -T warsoc-api curl -fsS http://127.0.0.1:8000/health
    printf '\n'

    log "Starting the core workers."
    compose up -d unified-worker compliance-cron storage-archiver evidence-hold-worker evidence-export-worker
    compose ps

    log "Prepare stage passed. Change ${API_HOST} A record to ${PUBLIC_IP}, then run:"
    log "sudo bash ${MIGRATION_DIR}/deploy_warsoc_release.sh activate ${RELEASE_ID}"
}

activate_edge() {
    require_root
    validate_release_id
    verify_host
    [[ -L "${CURRENT_LINK}" ]] || fail "Prepared release link is missing. Run prepare first."
    [[ "$(readlink -f "${CURRENT_LINK}")" == "${RELEASE_DIR}" ]] || \
        fail "Prepared release link does not identify requested release ${RELEASE_ID}."
    cd "${CURRENT_LINK}"
    validate_secret_file .env.prod
    compose config --quiet

    resolved_ips="$(getent ahostsv4 "${API_HOST}" | awk '{print $1}' | sort -u)"
    if ! grep -Fxq "${PUBLIC_IP}" <<<"${resolved_ips}"; then
        printf 'Current IPv4 answers for %s:\n%s\n' "${API_HOST}" "${resolved_ips:-none}" >&2
        fail "DNS does not resolve ${API_HOST} to ${PUBLIC_IP}."
    fi

    if docker ps --format '{{.Names}}' | grep -Fxq 'warsoc-nginx-proxy'; then
        log "Stopping the WarSOC edge briefly for standalone certificate validation."
        compose stop nginx
    fi
    if ss -lntH | awk '{print $4}' | grep -Eq '(^|:)(80)$'; then
        fail "Port 80 is occupied by a process other than the stopped WarSOC edge."
    fi

    cert_email="$(sed -n 's/^SALES_EMAIL=//p' .env.prod | head -n 1 | tr -d "'\"")"
    [[ -n "${cert_email}" ]] || fail "SALES_EMAIL is unavailable for Certbot registration."

    log "Obtaining or reusing the TLS certificate for ${API_HOST}."
    certbot certonly \
        --standalone \
        --non-interactive \
        --agree-tos \
        --no-eff-email \
        --keep-until-expiring \
        --pre-hook 'docker stop warsoc-nginx-proxy >/dev/null 2>&1 || true' \
        --post-hook 'docker start warsoc-nginx-proxy >/dev/null 2>&1 || true' \
        --email "${cert_email}" \
        -d "${API_HOST}"

    [[ -s "/etc/letsencrypt/live/${API_HOST}/fullchain.pem" ]] || fail "TLS certificate is missing."
    [[ -s "/etc/letsencrypt/live/${API_HOST}/privkey.pem" ]] || fail "TLS private key is missing."

    log "Starting the public Nginx edge."
    compose up -d nginx

    for _ in $(seq 1 12); do
        if curl --resolve "${API_HOST}:443:127.0.0.1" -fsS "https://${API_HOST}/health" >/tmp/warsoc-health.json; then
            break
        fi
        sleep 5
    done
    [[ -s /tmp/warsoc-health.json ]] || {
        compose logs --tail 150 nginx warsoc-api
        fail "HTTPS health validation failed."
    }

    cat /tmp/warsoc-health.json
    printf '\n'
    rm -f /tmp/warsoc-health.json

    compose ps
    log "OCI edge activation passed. Continue with external acceptance before changing any frontend configuration."
}

show_status() {
    require_root
    validate_release_id
    verify_host
    [[ -L "${CURRENT_LINK}" ]] || fail "Prepared release link is missing."
    [[ "$(readlink -f "${CURRENT_LINK}")" == "${RELEASE_DIR}" ]] || \
        fail "Active release does not identify requested release ${RELEASE_ID}."
    cd "${CURRENT_LINK}"
    compose ps
    printf '\nHost listeners:\n'
    ss -lntup
    printf '\nFirewall:\n'
    ufw status verbose
    printf '\nDocker firewall guard:\n'
    iptables -S DOCKER-USER
}

case "${1:-}" in
    prepare)
        prepare_release
        ;;
    activate)
        activate_edge
        ;;
    status)
        show_status
        ;;
    *)
        fail "Usage: sudo bash $0 {prepare|activate|status} [release-id]"
        ;;
esac
