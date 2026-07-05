#!/usr/bin/env bash
set -Eeuo pipefail

umask 077

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd -- "${SCRIPT_DIR}/.." && pwd)"
COMPOSE_FILE="${COMPOSE_FILE:-${PROJECT_DIR}/docker-compose.prod.yml}"
ENV_FILE="${ENV_FILE:-${PROJECT_DIR}/.env.prod}"
BACKUP_ENV_FILE="${BACKUP_ENV_FILE:-/etc/warsoc/backup.env}"
LOCAL_BACKUP_DIR="${LOCAL_BACKUP_DIR:-/var/backups/warsoc}"
LOCAL_RETENTION_DAYS="${LOCAL_RETENTION_DAYS:-7}"

for command_name in docker openssl curl sha256sum; do
    command -v "${command_name}" >/dev/null 2>&1 || {
        echo "Required command is unavailable: ${command_name}" >&2
        exit 1
    }
done

[[ -f "${COMPOSE_FILE}" ]] || {
    echo "Compose file not found: ${COMPOSE_FILE}" >&2
    exit 1
}
[[ -f "${ENV_FILE}" ]] || {
    echo "Production environment file not found: ${ENV_FILE}" >&2
    exit 1
}
[[ -f "${BACKUP_ENV_FILE}" ]] || {
    echo "Backup environment file not found: ${BACKUP_ENV_FILE}" >&2
    exit 1
}

# This file is root-owned and contains only backup credentials, never API secrets.
set -a
# shellcheck disable=SC1090
source "${BACKUP_ENV_FILE}"
set +a

: "${AZURE_BACKUP_CONTAINER_SAS_URL:?AZURE_BACKUP_CONTAINER_SAS_URL is required}"
: "${BACKUP_ENCRYPTION_PASSPHRASE:?BACKUP_ENCRYPTION_PASSPHRASE is required}"

if [[ "${AZURE_BACKUP_CONTAINER_SAS_URL}" != https://* || "${AZURE_BACKUP_CONTAINER_SAS_URL}" != *"?"* ]]; then
    echo "AZURE_BACKUP_CONTAINER_SAS_URL must be an HTTPS container SAS URL." >&2
    exit 1
fi
if (( ${#BACKUP_ENCRYPTION_PASSPHRASE} < 32 )); then
    echo "BACKUP_ENCRYPTION_PASSPHRASE must contain at least 32 characters." >&2
    exit 1
fi
if ! [[ "${LOCAL_RETENTION_DAYS}" =~ ^[0-9]+$ ]]; then
    echo "LOCAL_RETENTION_DAYS must be a non-negative integer." >&2
    exit 1
fi

database_name="$(
    awk -F= '
        $1 == "MONGODB_DB_NAME" {
            sub(/^[^=]*=/, "")
            gsub(/\r$/, "")
            print
            exit
        }
    ' "${ENV_FILE}"
)"
: "${database_name:?MONGODB_DB_NAME is missing from the production environment file}"

mkdir -p "${LOCAL_BACKUP_DIR}"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
host_id="$(hostname | tr -cd 'A-Za-z0-9._-' | cut -c1-64)"
base_name="warsoc_mongodb_${timestamp}"
raw_archive="${LOCAL_BACKUP_DIR}/${base_name}.archive.gz"
encrypted_archive="${raw_archive}.enc"
hash_file="${encrypted_archive}.sha256"

cleanup() {
    rm -f -- "${raw_archive}"
}
trap cleanup EXIT

echo "Creating MongoDB dump for ${database_name}..."
docker compose \
    --env-file "${ENV_FILE}" \
    -f "${COMPOSE_FILE}" \
    exec -T mongodb \
    sh -eu -c '
        mongodump \
            --host 127.0.0.1 \
            --port 27017 \
            --username "$MONGO_INITDB_ROOT_USERNAME" \
            --password "$MONGO_INITDB_ROOT_PASSWORD" \
            --authenticationDatabase admin \
            --db "$1" \
            --archive \
            --gzip
    ' sh "${database_name}" > "${raw_archive}"

[[ -s "${raw_archive}" ]] || {
    echo "MongoDB produced an empty backup archive." >&2
    exit 1
}

openssl enc \
    -aes-256-cbc \
    -salt \
    -pbkdf2 \
    -iter 200000 \
    -pass env:BACKUP_ENCRYPTION_PASSPHRASE \
    -in "${raw_archive}" \
    -out "${encrypted_archive}"

(
    cd -- "${LOCAL_BACKUP_DIR}"
    sha256sum "$(basename -- "${encrypted_archive}")"
) > "${hash_file}"

container_url="${AZURE_BACKUP_CONTAINER_SAS_URL%%\?*}"
sas_query="${AZURE_BACKUP_CONTAINER_SAS_URL#*\?}"
remote_prefix="${host_id}/$(date -u +%Y/%m/%d)"

upload_blob() {
    local source_path="$1"
    local content_type="$2"
    local blob_name="${remote_prefix}/$(basename -- "${source_path}")"
    curl \
        --fail \
        --silent \
        --show-error \
        --retry 3 \
        --request PUT \
        --header "x-ms-blob-type: BlockBlob" \
        --header "x-ms-version: 2023-11-03" \
        --header "Content-Type: ${content_type}" \
        --upload-file "${source_path}" \
        "${container_url%/}/${blob_name}?${sas_query}" \
        >/dev/null
}

echo "Uploading encrypted backup to private Azure storage..."
upload_blob "${encrypted_archive}" "application/octet-stream"
upload_blob "${hash_file}" "text/plain"

find "${LOCAL_BACKUP_DIR}" \
    -maxdepth 1 \
    -type f \
    \( -name 'warsoc_mongodb_*.archive.gz.enc' -o -name 'warsoc_mongodb_*.archive.gz.enc.sha256' \) \
    -mtime "+${LOCAL_RETENTION_DAYS}" \
    -delete

echo "Backup completed: $(basename -- "${encrypted_archive}")"
