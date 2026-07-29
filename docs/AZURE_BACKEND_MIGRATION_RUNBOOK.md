# WarSOC Backend Migration: DigitalOcean to Azure VM

**Status:** Authoritative cutover runbook
**Updated:** 2026-07-29
**Scope:** Move the existing Docker Compose backend from DigitalOcean to one hardened Azure Ubuntu VM without changing the public API hostname or the application topology.

This is a stateful migration, not a fresh deployment. MongoDB, Redis, customer uploads, generated reports, TLS material, cryptographic keys, secrets, archive configuration and release identity must cross the boundary together.

**Execution timing:** Deferred until the current pilot trial ends. Until a cutover window is approved, DigitalOcean remains the writable production backend, the Azure VM must not accept production writes, and this document is preparation only.

**Current project decision:** Pilot tenants and pilot evidence are disposable. If no pilot contract requires continuity, the preferred Azure path is a clean production launch with new tenant IDs and no pilot Mongo/Redis restore. The stateful procedure in Sections 5-8 remains available only if a signed contract, investigation or retention obligation later requires existing data to move.

## 0. Non-Negotiable Boundaries

- `warsoc.tech` remains on Vercel.
- `api.warsoc.tech` remains the API hostname; only its DNS A record changes.
- The public Azure agent-artifact account and private Azure evidence account remain where they are.
- MongoDB and Redis remain private Docker services on the Azure VM for this cutover.
- Do not rotate JWT, encryption, RSA signing, agent-auth, Mongo, Redis or administrator secrets during the migration.
- Do not introduce a new retention policy, application release or agent build during the cutover window.
- Do not run DigitalOcean and Azure as writable WarSOC backends at the same time.
- Keep DigitalOcean stopped but intact for at least 24 hours after acceptance.
- A failed migration must preserve evidence. Abort before DNS cutover whenever a pre-cutover gate fails.
- Retention-container separation is a separate post-pilot operation. Complete and prove it before migration or leave the current locked 2,190-day fallback unchanged until after migration; never combine both changes in one cutover.
- Treat archived telemetry, backups, uploads, reports and Mongo volumes as potentially containing PII. Do not place them in the public agent-artifact account.

### 0.1 PII and Azure security boundary

WarSOC may store security telemetry containing usernames, endpoint names, IP addresses, process details, file paths, incident context and tenant identifiers. Azure Storage encrypts stored data at rest and WarSOC uses HTTPS/TLS in transit, but these controls do not anonymize readable SIEM metadata. FBR and PECA sensitive payload fields are application-encrypted; general SIEM evidence is not uniformly field-encrypted before archival.

Required migration controls:

1. Keep artifacts and evidence in separate storage accounts. Only the versioned installer is public.
2. Keep evidence, database backups, reports and uploads private with anonymous blob access disabled.
3. Select and record an Azure geography approved for the tenant data and redundancy model. A region decision is a data-residency decision, not only a latency decision.
4. Require TLS, least-privilege RBAC, MFA for administrators, diagnostic logging and access reviews.
5. Restrict the evidence account to the Azure backend network using a private endpoint or an explicitly approved storage firewall design before final cutover.
6. Store secrets in root-owned files during staging; never commit connection strings, storage keys, backup keys or Fernet/RSA/Ed25519 material.
7. After the backend is on Azure, replace Shared Key/connection-string access with Microsoft Entra managed identity and least-privilege Blob roles when the application supports that path. The current connection-string implementation must not be described as managed identity.
8. Preserve the existing Fernet and signing keys through migration. Rotating them during cutover can make retained evidence unreadable or break continuity verification.
9. Maintain an audited list of who can retrieve raw evidence. Support access does not bypass tenant RBAC or evidence-access auditing.
10. Do not archive general packet payloads, credentials, email bodies or unrelated customer content. Network expansion remains metadata-only.

Azure immutability prevents alteration and early deletion; it does not remove privacy obligations. Approve purpose, retention and tenant terms before locking a policy because a locked WORM record cannot be removed on demand during the retention interval.

## 1. Cutover Record

Fill this record before starting. A blank release or infrastructure value blocks the migration.

```text
Approved backend commit:     <full 40-character commit>
Approved frontend commit:    <Vercel production commit>
DigitalOcean public IP:      <old API IP>
Azure static public IP:      <new API IP>
Cutover UTC window:          <start/end>
Operator:                    <name>
Final Mongo backup file:     <set during cutover>
Final Redis archive hash:    <set during cutover>
Acceptance artifact folder: <set after validation>
```

Never use a branch name such as `main` as the release identity. Push the approved changes, record the resulting commit and deploy that exact commit with detached HEAD.

### Current release evidence

- Windows agent: `4.2.6-Native-Signed`.
- Installer: `warsoc_installer-4.2.6.exe`.
- Installer size: `17,471,600` bytes.
- Installer SHA-256: `F80C22FCD65FD5755B8483F105FCA4AA3FFFFFBAB4E29B807828D4CC406CDAE0`.
- Agent URL: `https://warsocartifacts.blob.core.windows.net/warsoc-agent-public/warsoc_installer-4.2.6.exe`.
- Local manifest: `output/pilot_hash_manifest-4.2.6.json`.
- Backend regression: `369 passed`, `3 skipped`, zero failures (2026-07-29 maintained-suite run).
- Frontend ESLint and production build: passed.

These facts describe the approved working release. The commit fields above must identify the commits that actually contain it.

## 2. Readiness Gates

Complete every gate before provisioning or changing DNS.

### 2.0 Select the cutover mode

Record one mode before any Azure backend is made writable:

- **Clean production launch (current preference):** provision fresh MongoDB/Redis volumes, preserve the approved application cryptographic configuration required by the release, provision new contracted tenants, install backup automation from day one, run acceptance, then change DNS. Pilot tenants and evidence remain on the stopped DigitalOcean host only for the short rollback window and are destroyed through an approved cleanup record afterward.
- **Stateful migration:** use the complete backup, drain, restore and verification procedure in this runbook. This mode is mandatory if any existing tenant data has contractual, investigative or legal retention value.

A clean launch does not require importing the disposable pilot database, but it still requires a backup/restore capability test on Azure before accepting contracted customer data. Do not confuse "no pilot restore" with "no production backup."

### 2.1 Repository and artifact gate

1. Commit and push the approved backend and frontend working trees.
2. Record both commit IDs in the cutover record.
3. Confirm the Vercel production deployment uses the recorded frontend commit.
4. Confirm the Azure installer bytes match the size and SHA-256 above.
5. Confirm the backend `AGENT_CDN_URL` points to the same versioned object.
6. Do not rebuild the agent after recording the hash.

### 2.2 Retention gate

Retention must be either fully enabled and proven on DigitalOcean before migration, or left on the current locked 2,190-day fallback. Do not change retention routing during compute cutover.

The project decision is to perform retention separation after the current pilot trial. At cutover planning time, select exactly one state and record it in the cutover record:

- **Separated and proven:** all target containers are locked, routing is enabled, class-by-class upload/readback passed, and production has completed at least one clean archive cycle; or
- **Fallback unchanged:** every class continues to the existing locked 2,190-day container through the migration, with separation scheduled as a later isolated change.

An in-between state blocks migration.

The intended private Azure containers are:

| Container | Locked policy | Routing |
|---|---:|---|
| `warsoc-retention-90` | 90 days | `SIEM_90`, `GENERAL_90` |
| `warsoc-retention-180` | 180 days | `SIEM_180`, `GENERAL_180` |
| `warsoc-retention-270` | 270 days | `SIEM_270`, `GENERAL_270` |
| `warsoc-retention-360` | 360 days | `SIEM_360`, `GENERAL_360` |
| `warsoc-peca-365` | 365 days | `PECA` |
| `warsoc-fbr-2190` | 2,190 days | `FBR` |

If these routes are enabled, `.env.prod` must contain the corresponding `AZURE_STORAGE_CONTAINER_*`, `AZURE_CONTAINER_IMMUTABILITY_LOCKED_*` and `AZURE_CONTAINER_IMMUTABILITY_DAYS_*` variables documented in `.env.example`. Unsupported tenant durations must continue falling back to the existing locked `AZURE_STORAGE_CONTAINER`.

Before migration, run the archiver on DigitalOcean and confirm that:

- no archive log contains `Failed to archive`;
- each enabled route writes to the intended container;
- a known archived record can be retrieved through an authorized compliance/search/export route;
- Mongo records are deleted only after the archive ledger is written;
- existing blobs in the original six-year container remain untouched.

### 2.3 Backup gate

1. Create the separate private `warsoc-db-backups` Azure container.
2. Install `/etc/warsoc/backup.env` as root-owned mode `600` on DigitalOcean.
3. Run `scripts/backup_mongodb.sh` successfully.
4. Confirm the encrypted `.enc` archive and `.sha256` sidecar exist in Azure.
5. Run `scripts/run_backup_restore_drill.ps1` against that downloaded archive.
6. Require a passing restore with `tenants`, `users`, agents, SIEM, FBR, PECA, incidents and indexes present.

Azure cold evidence is not a database backup. The encrypted MongoDB backup is mandatory.

### 2.4 DNS and operational gate

- Lower the `api.warsoc.tech` A-record TTL to `300` at least 24 hours before cutover.
- Freeze tenant provisioning, team invitations and activation-code generation for the cutover window.
- Notify pilot users of a short ingestion interruption. Agents should spool locally while the API is unavailable.
- Ensure the DigitalOcean VM has enough free disk for the final encrypted backup and volume archives.
- Pull `alpine:3.20` on both hosts before the outage; it is used only to transfer Docker volume contents.

## 3. Provision Azure Without Changing Production

Run from a trusted Linux shell with Azure CLI installed:

```bash
export AZURE_SUBSCRIPTION_ID='<subscription-id>'
export ADMIN_SSH_PUBLIC_KEY="$HOME/.ssh/id_ed25519.pub"
export ADMIN_SOURCE_CIDR='<administrator-public-ip>/32'
export LOCATION='southeastasia'

bash deploy/azure/provision_warsoc_vm.sh
```

The repository script creates:

- resource group `rg-warsoc-backend-prod`;
- `Standard_F4s_v2` VM with 4 vCPU and 8 GiB RAM;
- Ubuntu 24.04 Trusted Launch with secure boot and vTPM;
- 240 GB Premium LRS OS disk;
- static public IPv4 address;
- VNet, subnet, NIC and NSG;
- SSH restricted to `ADMIN_SOURCE_CIDR`;
- public ports 80/443 only;
- Docker, UFW, fail2ban and unattended upgrades.

Connect and verify bootstrap:

```bash
ssh warsocops@<azure-static-ip>
sudo cloud-init status --wait
sudo systemctl is-active docker fail2ban unattended-upgrades
sudo ufw status verbose
```

MongoDB, Redis and FastAPI ports `27017`, `6379` and `8000` must not exist in the Azure NSG.

Create a 4 GiB emergency swap file if the VM has no active swap:

```bash
if ! sudo swapon --show --noheadings | grep -q .; then
  sudo fallocate -l 4G /swapfile
  sudo chmod 600 /swapfile
  sudo mkswap /swapfile
  sudo swapon /swapfile
  echo '/swapfile none swap sw 0 0' | sudo tee -a /etc/fstab
  echo 'vm.swappiness=10' | sudo tee /etc/sysctl.d/98-warsoc-swap.conf
  sudo sysctl --system
fi

sudo swapon --show
```

Swap is an OOM buffer, not capacity. Sustained swapping after cutover is a resource alarm.

## 4. Stage the Exact Release on Azure

On the Azure VM:

```bash
BACKEND_COMMIT='<approved-backend-commit>'

sudo apt-get update
sudo apt-get install -y certbot
sudo git clone https://github.com/SHADABMUSHTAQ/Startup.git /opt/warsoc/Startup-backend
sudo chown -R "$USER:$USER" /opt/warsoc/Startup-backend
cd /opt/warsoc/Startup-backend
git fetch --all --tags --prune
git checkout --detach "$BACKEND_COMMIT"
test "$(git rev-parse HEAD)" = "$BACKEND_COMMIT"
test -z "$(git status --porcelain)"
mkdir -p certbot/www
docker pull alpine:3.20
```

### 4.1 Transfer secrets and certificates

Transfer these over SSH through a trusted operator machine, never through Git:

- the exact DigitalOcean `.env.prod`;
- the complete `/etc/letsencrypt` tree;
- `/etc/warsoc/backup.env`;
- the current encrypted Mongo backup and its sidecar for rehearsal.

Create a certificate archive on DigitalOcean:

```bash
sudo install -d -m 700 /root/warsoc-transfer
sudo tar --numeric-owner -C / -czf /root/warsoc-transfer/letsencrypt.tgz etc/letsencrypt
sudo sh -eu -c 'cd /root/warsoc-transfer && sha256sum letsencrypt.tgz > letsencrypt.tgz.sha256'
```

After secure transfer, install on Azure:

```bash
cd /opt/warsoc/Startup-backend
sudo install -m 600 /secure-transfer/.env.prod .env.prod
sudo install -d -m 700 /etc/warsoc
sudo install -m 600 /secure-transfer/backup.env /etc/warsoc/backup.env

cd /secure-transfer
sha256sum --check letsencrypt.tgz.sha256
sudo tar --numeric-owner -C / -xzf letsencrypt.tgz
sudo chown -R root:root /etc/letsencrypt
```

The copied `.env.prod` must preserve the existing values for at least:

- `JWT_SECRET_KEY`;
- `ENCRYPTION_KEY`;
- `PRIVATE_KEY_B64` and `PUBLIC_KEY_B64`;
- `SUPER_ADMIN_API_KEY` and `METRICS_BEARER_TOKEN`;
- Mongo and Redis credentials;
- Azure evidence and backup settings;
- agent authentication/signature settings;
- SMTP settings;
- retention-container routing.

Do not generate a new PECA RSA key on Azure. Existing evidence must remain verifiable with the same signing identity.

Validate and build without starting production:

```bash
cd /opt/warsoc/Startup-backend
sudo docker compose --env-file .env.prod -f docker-compose.prod.yml config --quiet
sudo docker compose --env-file .env.prod -f docker-compose.prod.yml build
```

## 5. Azure Restore Rehearsal Before Cutover

Use a recent encrypted DigitalOcean backup. This rehearsal occurs while DigitalOcean still owns production DNS.

Start only MongoDB:

```bash
cd /opt/warsoc/Startup-backend
sudo docker compose --env-file .env.prod -f docker-compose.prod.yml up -d mongodb
sudo docker compose --env-file .env.prod -f docker-compose.prod.yml ps mongodb
```

Verify and stream-decrypt the archive directly into MongoDB. No plaintext archive is written to disk:

```bash
set -o pipefail
BACKUP_FILE='/secure-transfer/warsoc_mongodb_<timestamp>.archive.gz.enc'
HASH_FILE="${BACKUP_FILE}.sha256"

cd "$(dirname "$BACKUP_FILE")"
sha256sum --check "$(basename "$HASH_FILE")"
read -rsp 'Backup passphrase: ' BACKUP_ENCRYPTION_PASSPHRASE; echo
export BACKUP_ENCRYPTION_PASSPHRASE

openssl enc -d -aes-256-cbc -pbkdf2 -iter 200000 \
  -pass env:BACKUP_ENCRYPTION_PASSPHRASE \
  -in "$BACKUP_FILE" \
| sudo docker compose \
    --env-file /opt/warsoc/Startup-backend/.env.prod \
    -f /opt/warsoc/Startup-backend/docker-compose.prod.yml \
    exec -T mongodb sh -eu -c '
      mongorestore \
        --host 127.0.0.1 \
        --port 27017 \
        --username "$MONGO_INITDB_ROOT_USERNAME" \
        --password "$MONGO_INITDB_ROOT_PASSWORD" \
        --authenticationDatabase admin \
        --archive \
        --gzip \
        --drop
    '

unset BACKUP_ENCRYPTION_PASSPHRASE
```

Verify restored identity collections:

```bash
cd /opt/warsoc/Startup-backend
DB_NAME="$(awk -F= '$1 == "MONGODB_DB_NAME" {sub(/^[^=]*=/, ""); gsub(/\r$/, ""); print; exit}' .env.prod)"

sudo docker compose --env-file .env.prod -f docker-compose.prod.yml \
  exec -T mongodb sh -eu -c '
    mongosh \
      --host 127.0.0.1 \
      --port 27017 \
      --username "$MONGO_INITDB_ROOT_USERNAME" \
      --password "$MONGO_INITDB_ROOT_PASSWORD" \
      --authenticationDatabase admin \
      "$1" \
      --quiet \
      --eval "JSON.stringify({collections: db.getCollectionNames().length, tenants: db.tenants.countDocuments({}), users: db.users.countDocuments({})})"
  ' sh "$DB_NAME"
```

Require non-zero tenants and users. Record collection/index counts and compare them with the isolated restore drill.

Remove only the Azure rehearsal state after confirming the host and IP are the Azure target:

```bash
hostname
curl -fsS https://api.ipify.org; echo
cd /opt/warsoc/Startup-backend
sudo docker compose --env-file .env.prod -f docker-compose.prod.yml down -v
```

Never run `down -v` on DigitalOcean.

## 6. DigitalOcean Cutover Freeze

Run all commands from `/opt/warsoc/Startup-backend` on DigitalOcean.

### 6.1 Confirm the source release

```bash
cd /opt/warsoc/Startup-backend
git rev-parse HEAD
git status --porcelain
docker compose --env-file .env.prod -f docker-compose.prod.yml config --quiet
curl -fsS https://api.warsoc.tech/health
```

The commit must match the cutover record and the working tree must be clean.

### 6.2 Stop public ingress first

```bash
sudo docker compose --env-file .env.prod -f docker-compose.prod.yml stop nginx
```

At this point browsers and agents cannot create new backend writes. Windows agents retain undelivered telemetry in their bounded local spools.

### 6.3 Drain evidence streams and inspect queues

Keep `warsoc-api`, `unified-worker`, MongoDB and Redis running. Execute:

```bash
sudo docker compose --env-file .env.prod -f docker-compose.prod.yml \
  exec -T warsoc-api python - <<'PY'
import asyncio
import os
from redis.asyncio import Redis
from redis.exceptions import ResponseError

STREAMS = {
    "raw_logs_queue": {"siem_group", "fbr_group", "eto_group"},
    "siem_hot_queue": {"siem_hot_group"},
}
LISTS = (
    "email_alert_queue",
    "email_alert_queue:processing",
    "email_alert_queue:dead",
)
STREAM_DEPTHS = ("raw_logs_queue_dlq",)

async def main():
    client = Redis.from_url(os.environ["REDIS_URL"], decode_responses=True)
    blocked = False
    try:
        for stream, required_groups in STREAMS.items():
            try:
                groups = {row["name"]: row for row in await client.xinfo_groups(stream)}
            except ResponseError as exc:
                print(f"BLOCK {stream}: {exc}")
                blocked = True
                continue
            for group in sorted(required_groups):
                row = groups.get(group)
                if row is None:
                    print(f"BLOCK {stream}/{group}: group missing")
                    blocked = True
                    continue
                pending = int(row.get("pending") or 0)
                lag = row.get("lag")
                lag = int(lag) if lag is not None else -1
                print(f"{stream}/{group}: pending={pending} lag={lag}")
                if pending != 0 or lag != 0:
                    blocked = True
        for key in LISTS:
            print(f"{key}: depth={await client.llen(key)}")
        for key in STREAM_DEPTHS:
            print(f"{key}: depth={await client.xlen(key)}")
        await client.save()
    finally:
        await client.aclose()
    if blocked:
        raise SystemExit("Evidence streams are not drained. Abort cutover and retry.")

asyncio.run(main())
PY
```

Repeat until every required consumer reports `pending=0 lag=0`. Email/DLQ depths are recorded rather than discarded because the Redis volume is migrated. Do not proceed if a required evidence group is missing or behind.

### 6.4 Stop writers and create the final Mongo backup

```bash
sudo docker compose --env-file .env.prod -f docker-compose.prod.yml \
  stop unified-worker compliance-cron storage-archiver warsoc-api

sudo ./scripts/backup_mongodb.sh

FINAL_BACKUP="$(ls -1t /var/backups/warsoc/warsoc_mongodb_*.archive.gz.enc | head -n 1)"
test -s "$FINAL_BACKUP"
test -s "${FINAL_BACKUP}.sha256"
echo "Final backup: $FINAL_BACKUP"

sudo docker compose --env-file .env.prod -f docker-compose.prod.yml stop redis mongodb
```

Record the final backup filename in the cutover record.

### 6.5 Export Redis, uploads and reports

Resolve volume names from fixed production containers and create immutable transfer archives:

```bash
sudo install -d -m 700 /root/warsoc-transfer

REDIS_VOLUME="$(sudo docker inspect warsoc-redis-prod --format '{{range .Mounts}}{{if eq .Destination "/data"}}{{.Name}}{{end}}{{end}}')"
UPLOADS_VOLUME="$(sudo docker inspect warsoc-api-prod --format '{{range .Mounts}}{{if eq .Destination "/app/uploaded_files"}}{{.Name}}{{end}}{{end}}')"
REPORTS_VOLUME="$(sudo docker inspect warsoc-api-prod --format '{{range .Mounts}}{{if eq .Destination "/app/data/reports"}}{{.Name}}{{end}}{{end}}')"

test -n "$REDIS_VOLUME"
test -n "$UPLOADS_VOLUME"
test -n "$REPORTS_VOLUME"

sudo docker run --rm -v "$REDIS_VOLUME:/source:ro" -v /root/warsoc-transfer:/backup alpine:3.20 \
  sh -eu -c 'cd /source && tar -czf /backup/redis-data.tgz .'
sudo docker run --rm -v "$UPLOADS_VOLUME:/source:ro" -v /root/warsoc-transfer:/backup alpine:3.20 \
  sh -eu -c 'cd /source && tar -czf /backup/uploads-data.tgz .'
sudo docker run --rm -v "$REPORTS_VOLUME:/source:ro" -v /root/warsoc-transfer:/backup alpine:3.20 \
  sh -eu -c 'cd /source && tar -czf /backup/reports-data.tgz .'

sudo cp "$FINAL_BACKUP" "${FINAL_BACKUP}.sha256" /root/warsoc-transfer/
sudo cp .env.prod /root/warsoc-transfer/.env.prod
sudo chmod 600 /root/warsoc-transfer/.env.prod

cd /root/warsoc-transfer
sudo sha256sum redis-data.tgz uploads-data.tgz reports-data.tgz .env.prod \
  > cutover-files.sha256
sudo sha256sum --check cutover-files.sha256
```

Transfer `/root/warsoc-transfer` to `/secure-transfer` on Azure through the trusted operator channel. Do not delete the DigitalOcean copies.

Redis migration preserves stream state, sessions, activation/invitation tokens, mitigation sets, whitelists, FIM correlation state and email queues. The same Redis password and application cryptographic secrets are therefore mandatory on Azure.

## 7. Final Restore on Azure

First verify every transferred hash:

```bash
cd /secure-transfer
sha256sum --check cutover-files.sha256
sha256sum --check warsoc_mongodb_<timestamp>.archive.gz.enc.sha256
```

Install the final environment file and verify the release again:

```bash
sudo install -m 600 /secure-transfer/.env.prod /opt/warsoc/Startup-backend/.env.prod
cd /opt/warsoc/Startup-backend
test "$(git rev-parse HEAD)" = '<approved-backend-commit>'
test -z "$(git status --porcelain)"
sudo docker compose --env-file .env.prod -f docker-compose.prod.yml config --quiet
```

Create fresh Azure volumes without starting application writers:

```bash
sudo docker compose --env-file .env.prod -f docker-compose.prod.yml \
  create mongodb redis warsoc-api

REDIS_VOLUME="$(sudo docker inspect warsoc-redis-prod --format '{{range .Mounts}}{{if eq .Destination "/data"}}{{.Name}}{{end}}{{end}}')"
UPLOADS_VOLUME="$(sudo docker inspect warsoc-api-prod --format '{{range .Mounts}}{{if eq .Destination "/app/uploaded_files"}}{{.Name}}{{end}}{{end}}')"
REPORTS_VOLUME="$(sudo docker inspect warsoc-api-prod --format '{{range .Mounts}}{{if eq .Destination "/app/data/reports"}}{{.Name}}{{end}}{{end}}')"

sudo docker run --rm -v "$REDIS_VOLUME:/target" -v /secure-transfer:/backup:ro alpine:3.20 \
  sh -eu -c 'tar -xzf /backup/redis-data.tgz -C /target'
sudo docker run --rm -v "$UPLOADS_VOLUME:/target" -v /secure-transfer:/backup:ro alpine:3.20 \
  sh -eu -c 'tar -xzf /backup/uploads-data.tgz -C /target'
sudo docker run --rm -v "$REPORTS_VOLUME:/target" -v /secure-transfer:/backup:ro alpine:3.20 \
  sh -eu -c 'tar -xzf /backup/reports-data.tgz -C /target'
```

These must be fresh Azure volumes created after the rehearsal `down -v`. Never extract over a populated production volume.

Start MongoDB and restore the final encrypted archive, then start Redis:

```bash
set -o pipefail
cd /opt/warsoc/Startup-backend
sudo docker compose --env-file .env.prod -f docker-compose.prod.yml up -d mongodb

BACKUP_FILE='/secure-transfer/warsoc_mongodb_<final-timestamp>.archive.gz.enc'
HASH_FILE="${BACKUP_FILE}.sha256"
cd "$(dirname "$BACKUP_FILE")"
sha256sum --check "$(basename "$HASH_FILE")"
read -rsp 'Backup passphrase: ' BACKUP_ENCRYPTION_PASSPHRASE; echo
export BACKUP_ENCRYPTION_PASSPHRASE

openssl enc -d -aes-256-cbc -pbkdf2 -iter 200000 \
  -pass env:BACKUP_ENCRYPTION_PASSPHRASE \
  -in "$BACKUP_FILE" \
| sudo docker compose \
    --env-file /opt/warsoc/Startup-backend/.env.prod \
    -f /opt/warsoc/Startup-backend/docker-compose.prod.yml \
    exec -T mongodb sh -eu -c '
      mongorestore \
        --host 127.0.0.1 \
        --port 27017 \
        --username "$MONGO_INITDB_ROOT_USERNAME" \
        --password "$MONGO_INITDB_ROOT_PASSWORD" \
        --authenticationDatabase admin \
        --archive \
        --gzip \
        --drop
    '

unset BACKUP_ENCRYPTION_PASSPHRASE

cd /opt/warsoc/Startup-backend
sudo docker compose --env-file .env.prod -f docker-compose.prod.yml up -d redis
sudo docker compose --env-file .env.prod -f docker-compose.prod.yml ps mongodb redis
```

Require both services to report healthy. Repeat the Mongo tenant/user/count check.

Start the API without public Nginx:

```bash
sudo docker compose --env-file .env.prod -f docker-compose.prod.yml up -d warsoc-api
sudo docker compose --env-file .env.prod -f docker-compose.prod.yml \
  exec -T warsoc-api curl -fsS http://127.0.0.1:8000/health
```

Start all required services:

```bash
sudo docker compose --env-file .env.prod -f docker-compose.prod.yml up -d --build
sudo docker compose --env-file .env.prod -f docker-compose.prod.yml ps
```

Do not enable the optional `network-syslog` or `legacy-detection` profiles during this Windows pilot migration.

Before changing DNS, test Azure directly while keeping the hostname and TLS contract:

```bash
AZURE_IP='<azure-static-ip>'
curl --fail --silent --show-error \
  --resolve "api.warsoc.tech:443:${AZURE_IP}" \
  https://api.warsoc.tech/health
```

Require `status=healthy` with MongoDB and Redis healthy. Inspect API, worker and archiver logs for startup failures.

## 8. DNS Cutover

Change only this record:

```text
api.warsoc.tech A <DigitalOcean-IP> -> <Azure-static-IP>
```

Do not change:

- the `warsoc.tech` Vercel records;
- frontend environment variables;
- the public agent-artifact URL;
- Azure evidence or backup endpoints.

Because the API hostname is unchanged, the Vercel frontend and installed agents do not require a new build or configuration.

Verify propagation:

```bash
dig +short api.warsoc.tech @1.1.1.1
dig +short api.warsoc.tech @8.8.8.8
```

Both must return the Azure static IP before public acceptance.

## 9. Production Acceptance

### 9.1 Azure host checks

On Azure:

```bash
cd /opt/warsoc/Startup-backend
sudo bash deploy/azure/validate_host.sh
sudo docker compose --env-file .env.prod -f docker-compose.prod.yml logs --since 20m \
  warsoc-api unified-worker storage-archiver
```

Reject any dependency, signature, consumer-group, archive, tenant-isolation or cryptographic-key failure.

### 9.2 Public preflight from Windows

Run from the approved local backend repository with Docker not required:

```powershell
cd C:\Users\Lenovo\Desktop\Startup-backend

.\scripts\run_production_acceptance.ps1 `
  -Phase Preflight `
  -FrontendUrl "https://warsoc.tech" `
  -BackendUrl "https://api.warsoc.tech" `
  -ManifestPath ".\output\pilot_hash_manifest-4.2.6.json" `
  -InstallerPath ".\output\warsoc_installer-4.2.6.exe" `
  -ArtifactUrl "https://warsocartifacts.blob.core.windows.net/warsoc-agent-public/warsoc_installer-4.2.6.exe"
```

Require zero failures for TLS, DNS isolation, Vercel assets, frontend API binding, CORS, backend health, security headers, private ports and installer hash.

### 9.3 Platform acceptance

The platform phase creates a disposable tenant and test evidence. Run only with explicit approval:

```powershell
$adminSecure = Read-Host "Super admin API key" -AsSecureString
$adminKey = [System.Net.NetworkCredential]::new("", $adminSecure).Password
$metricsSecure = Read-Host "Metrics bearer token" -AsSecureString
$metricsToken = [System.Net.NetworkCredential]::new("", $metricsSecure).Password

.\scripts\run_production_acceptance.ps1 `
  -Phase Platform `
  -BackendUrl "https://api.warsoc.tech" `
  -FrontendUrl "https://warsoc.tech" `
  -AdminKey $adminKey `
  -MetricsToken $metricsToken `
  -ManifestPath ".\output\pilot_hash_manifest-4.2.6.json" `
  -InstallerPath ".\output\warsoc_installer-4.2.6.exe" `
  -ArtifactUrl "https://warsocartifacts.blob.core.windows.net/warsoc-agent-public/warsoc_installer-4.2.6.exe" `
  -ConfirmProductionDataCreation

$adminKey = $null
$metricsToken = $null
```

If SMTP quota is still unavailable, pass `-SkipEmailDeliveryCheck` and record email delivery as an explicit accepted limitation. Do not convert an SMTP failure into a SIEM/FBR/PECA failure.

### 9.4 Real agent and archive checks

Before accepting cutover:

1. Confirm one existing 4.2.6 Windows agent reconnects without reinstalling.
2. Confirm its heartbeat becomes current and endpoint health is Active.
3. Generate one harmless native Windows event and confirm new SIEM evidence and an appropriate incident when the rule conditions are met.
4. Confirm a PECA-entitled tenant receives a fresh entitled PECA control record.
5. Confirm a configured FBR test path/JSONL source produces the expected FBR evidence; do not claim line-item monitoring without the JSONL contract.
6. Open one known Azure-archived record through compliance/search.
7. Export one CSV and one PDF containing verified hot/cold data.
8. Acknowledge and close a disposable incident, then refresh to confirm persistence.
9. Confirm an existing blocked-IP policy and whitelist still exist after Redis migration.

### 9.5 Acceptance thresholds

Initiate rollback when any of these occurs after DNS cutover:

- public health is unavailable or unhealthy for more than five minutes;
- TLS, CORS or tenant isolation fails once;
- MongoDB or Redis repeatedly becomes unhealthy;
- three consecutive active agents fail to reconnect or heartbeat;
- required Redis consumer lag does not decrease for five minutes;
- fresh SIEM, FBR or PECA evidence does not appear within 60 seconds under normal load;
- endpoint signatures are rejected unexpectedly;
- archive retrieval/hash verification fails;
- restored tenant/user/agent counts differ materially from the final backup proof.

Do not decommission DigitalOcean until every required acceptance item has a saved artifact and Azure has remained stable for at least 24 hours.

## 10. Post-Cutover Operations

### 10.1 Certificate renewal

The initial certificate tree is copied from DigitalOcean. After DNS points to Azure, verify renewal through the Nginx webroot:

```bash
sudo certbot renew --dry-run \
  --webroot \
  -w /opt/warsoc/Startup-backend/certbot/www \
  --deploy-hook 'docker exec warsoc-nginx-proxy nginx -s reload'
```

Do not accept migration if the dry run fails. The live certificate files remain mounted read-only at `/etc/nginx/ssl/live/api.warsoc.tech/` inside Nginx.

### 10.2 Backup schedule

Run one Azure-hosted backup immediately:

```bash
cd /opt/warsoc/Startup-backend
sudo ./scripts/backup_mongodb.sh
```

Install the root cron entry:

```cron
17 2 * * * cd /opt/warsoc/Startup-backend && ./scripts/backup_mongodb.sh >> /var/log/warsoc-backup.log 2>&1
```

Confirm a new archive appears in the private Azure backup container and schedule a new isolated restore drill. Enable Azure VM Backup as a second infrastructure-recovery layer; it does not replace the encrypted Mongo backup.

### 10.3 Monitoring

For the first 24 hours, watch:

- API/Mongo/Redis health;
- worker heartbeats and Redis consumer lag;
- agent heartbeat freshness and spool growth;
- endpoint signature verified/rejected counters;
- SIEM/FBR/PECA processing latency and DLQs;
- archiver failures and hot-storage growth;
- disk, memory and swap;
- TLS expiry and backup completion.

Keep the DigitalOcean stack stopped. Do not leave its Nginx or workers running after Azure accepts production traffic.

## 11. Rollback

Rollback always moves the latest accepted state back; it never simply restarts stale DigitalOcean data.

1. Stop Azure Nginx immediately.
2. Drain Azure evidence streams where possible.
3. Stop Azure writers.
4. Run an encrypted Mongo backup on Azure.
5. Export Azure Redis, uploads and reports using the Phase 6 volume procedure.
6. Transfer and hash-verify the rollback set on DigitalOcean.
7. Restore the Azure Mongo backup into DigitalOcean with `--drop`.
8. Replace the stopped DigitalOcean Redis/uploads/reports volumes with the Azure rollback archives.
9. Start DigitalOcean MongoDB, Redis, API, workers and Nginx.
10. Validate DigitalOcean health locally.
11. Point `api.warsoc.tech` back to the recorded DigitalOcean IP.
12. Re-run public preflight and one real-agent heartbeat.

Never start DigitalOcean Nginx before Azure Nginx is stopped. Never restore an old pre-cutover backup over newer Azure writes.

## 12. Known Limitations

- This is a single-VM deployment, not high availability.
- Azure VM Backup is not application-consistent evidence backup by itself.
- Preserve the approved release setting `AGENT_EVENT_SIGNATURE_MODE=required` during migration. Do not weaken admission to observe mode to accommodate stale agents; upgrade or revoke those endpoints before cutover.
- The unsigned pilot installer still requires customer-managed hash allowlisting or a future code-signing certificate.
- Existing blobs locked in the original 2,190-day container cannot have their retention shortened.
- Security-alert email remains disabled. Transactional email acceptance depends on provider quota.
- Network syslog relay, hybrid network correlation and external exposure scanning are future scope and are not enabled by this migration.
- The migration does not make unproven FBR or PECA legal claims. It preserves the current Windows evidence scope described in `WARSOC_CURRENT_STATE_ARCHITECTURE.md`.
