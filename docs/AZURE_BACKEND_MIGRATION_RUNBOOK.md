# WarSOC Backend Migration: DigitalOcean to Azure VM

**Status:** Authoritative cutover runbook
**Updated:** 2026-07-30
**Scope:** Move the complete Docker Compose application and every shipped capability from DigitalOcean to one hardened Azure Ubuntu VM without changing the public API hostname or application topology. Start with fresh production data because the business has declared the pilot identities and operational data disposable.

This is a clean production launch for application data. The approved backend release, TLS configuration, production secrets, archive configuration and release identity cross the boundary; the pilot MongoDB/Redis data, pilot accounts, pilot agents, uploads and generated reports do not enter the new production database.

**Execution timing:** Emergency continuity migration before the DigitalOcean entitlement ends. DigitalOcean remains the only writable production backend until the final cutover freeze. Azure must not accept production writes before the restore rehearsal passes.

**Default project decision:** Use the clean production launch because the business owner has declared the pilot accounts and operational data disposable. This declaration does not override a locked Azure immutability policy: already-archived pilot evidence remains isolated in its legacy account until the policy expires.

## 0. Non-Negotiable Boundaries

- `warsoc.tech` remains on Vercel.
- `api.warsoc.tech` remains the API hostname; only its DNS A record changes.
- Replace the pilot artifact account with the approved production artifact account and versioned installer URL before deleting the old public artifact object/account.
- Create and validate the new private production evidence account. Stop new writes to the legacy pilot evidence account after cutover.
- MongoDB and Redis remain private Docker services on the Azure VM for this cutover.
- Generate fresh production tenant/database credentials for the clean environment. Preserve only release-level keys that are intentionally required to verify a retained chain or approved artifact; record every such exception.
- Do not introduce a new retention policy, application release or agent build during the cutover window.
- Do not run DigitalOcean and Azure as writable WarSOC backends at the same time.
- Keep DigitalOcean stopped but intact for at least 24 hours after acceptance, then execute the approved pilot-disposal record.
- A failed migration must preserve evidence. Abort before DNS cutover whenever a pre-cutover gate fails.
- Create and prove the production retention containers before accepting contracted data. The legacy 2,190-day pilot container is not imported into the production evidence account.
- Treat archived telemetry, backups, uploads, reports and Mongo volumes as potentially containing PII. Do not place them in the public agent-artifact account.
- Migrate the network-relay API, parsers, workers, installers, tests and configuration, but keep `NETWORK_RELAY_ENABLED=false` until an approved activation.
- Migrate the archive-retrieval routes, ledger, worker, tests and configuration, but keep `ARCHIVE_RETRIEVAL_ENABLED=false` until staging, RBAC, lifecycle and rehydration acceptance pass.
- A false feature flag means the capability is deployed but inactive. It never authorizes omitting its files, dependencies, Compose profile, indexes or configuration from the release.
- A DigitalOcean snapshot and encrypted final pilot backup remain short-term rollback/disposal evidence. They are not restored into the clean production database.
- Promotional Azure credit is not a production continuity guarantee. Create a T-7/T-3/T-1 exit plan before the credit expiry date.

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

- Current source candidate: Windows agent `4.2.8-Native-Signed`.
- Last locally available approved binary: `warsoc_installer-4.2.6.exe`, 17,471,600 bytes, SHA-256 `F80C22FCD65FD5755B8483F105FCA4AA3FFFFFBAB4E29B807828D4CC406CDAE0`.
- A `4.2.8` production artifact does not exist merely because source files say `4.2.8`. Build, manifest, Azure upload, and public hash acceptance must complete before recording `4.2.8` as the release.
- Backend regression: `380 passed`, `3 skipped`, zero failures (latest maintained-suite run before this document update).
- Frontend ESLint and production build: passed.

The cutover record must identify one exact backend commit and one exact installer version/hash. Do not mix a newer source commit with an older unrecorded artifact claim.

## 2. Readiness Gates

Complete every gate before provisioning or changing DNS.

### 2.0 Confirm the cutover mode

Record one mode before any Azure backend is made writable:

- **Clean production launch (selected):** provision fresh MongoDB/Redis volumes and new tenant IDs after recording the pilot-disposal decision. Install backup automation from day one, run acceptance, then change DNS. Do not restore the pilot Mongo archive or Redis state.
- **Stateful migration (not selected):** use the complete drain, restore and continuity procedure only if the business reverses the disposal decision before cutover and must preserve accounts, agents, evidence, queues, reports and workflow state.

A clean launch does not require importing the disposable pilot database, but it still requires a backup/restore capability test on Azure before accepting contracted customer data. Do not confuse "no pilot restore" with "no production backup."

The old public artifact can be deleted only after the new versioned artifact and manifest pass the production preflight. Old Azure evidence protected by a locked policy cannot be deleted early. Remove it from application routing, deny routine access, label it as a legacy pilot archive, and delete it only after every protected blob has expired.

Sections that create and verify encrypted source backups remain mandatory as rollback and disposal evidence. Sections that restore pilot MongoDB, Redis, uploads or reports are skipped in the selected clean-launch path; instead, initialize fresh volumes and run the empty-environment acceptance suite.

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
- a known archived record is visible in the tenant-scoped archive ledger;
- if retrieval is enabled, a request reaches `READY`, produces a short-lived user-delegation SAS URL, and the downloaded bytes match the ledger SHA-256;
- Mongo records are deleted only after the archive ledger is written;
- existing blobs in the original six-year container remain untouched.

Archive retrieval additionally requires a private `warsoc-retrieval-staging` container with no immutability policy and a lifecycle rule that deletes staged blobs after three days. The backend identity requires least-privilege Blob Data Contributor access to evidence/staging plus permission to generate user-delegation keys. Do not enable the `archive-retrieval` Compose profile until those controls are proven.

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

### 2.5 Temporary Azure subscription gate

The compute subscription must be `Enabled`, have enough remaining credit for the migration window, and have a documented exit date. Microsoft states that an expired credit or reached spending limit can disable the subscription and deallocate VMs.

```bash
az login --use-device-code
az account set --subscription '<temporary-compute-subscription-id>'
az account show --query '{name:name,id:id,state:state,tenantId:tenantId}' --output table
az consumption budget list --output table
```

For an entitlement ending on 2026-08-19:

- T-7 (2026-08-12): choose a durable commercial destination or controlled shutdown; verify a fresh encrypted off-host backup.
- T-3 (2026-08-16): rehearse restore in the destination and lower DNS TTL.
- T-1 (2026-08-18): cut over or stop accepting new production writes.
- Expiry day: do not assume the VM remains allocated or writable.

Serial promotional-account migration is not an operating model. It repeats identity, DNS, secret, evidence, and backup risk and may violate offer eligibility. A paying customer must use a durable commercial subscription.

## 3. Provision Azure Without Changing Production

Subscription enrollment itself is a browser/billing operation. After the subscription exists, run this section from Azure Cloud Shell or a trusted Linux shell with Azure CLI installed:

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

Do not copy the pilot `.env.prod` into the clean production environment. Use it only as an inventory so no required variable is forgotten. Build a new root-owned `/opt/warsoc/Startup-backend/.env.prod` with this decision matrix:

| Environment group | Clean-launch action | Required result |
|---|---|---|
| `APP_ENV`, public URL and CORS | Set explicitly | `APP_ENV=production`, `BACKEND_PUBLIC_URL=https://api.warsoc.tech`, and only approved Vercel origins in `ALLOWED_ORIGINS`. Do not retain temporary localhost origins. |
| MongoDB and Redis | Generate fresh passwords and URLs | New private Docker volumes, authenticated internal service URLs, Redis memory limits and no public host ports. Do not restore pilot data. |
| JWT and API administration | Generate fresh high-entropy values | New `JWT_SECRET_KEY`, matching `SECRET_KEY` where required by the release, `SUPER_ADMIN_API_KEY`, `METRICS_BEARER_TOKEN` and agent master/authentication secret. |
| Evidence encryption/signing | Generate a recorded production key set | New `ENCRYPTION_KEY`, PECA `PRIVATE_KEY_B64`/`PUBLIC_KEY_B64`, and optional private-key password. Store the private material outside Git and back it up securely. The isolated legacy pilot archive keeps its historical verification material until expiry. |
| Agent distribution | Replace | `AGENT_CDN_URL` points to the new versioned production artifact whose bytes match the approved manifest. |
| Agent event admission | Preserve the approved release policy | `AGENT_EVENT_SIGNATURE_MODE=required`. New production agents must enroll and sign; do not import stale pilot identities. |
| Network relay | Deploy inactive | Include all relay code/configuration and set `NETWORK_RELAY_ENABLED=false`; retain bounded batch/body/tenant limits from `.env.example`. |
| Archive retrieval | Deploy inactive | Include routes/ledger/worker/profile and set `ARCHIVE_RETRIEVAL_ENABLED=false`. Set the new storage account URL and staging container, but do not start the profile before acceptance. |
| Azure archive routing | Replace with new production account values | New private evidence connection/identity, fallback container, FBR/PECA fixed containers, duration-specific SIEM/general containers and matching locked-policy declarations. |
| Ingestion protection | Set explicitly | Keep the 50-agent aggregate operating boundary and the approved tenant/platform daily-byte ceilings from `.env.example`. |
| Email | Keep non-alert delivery optional | `ENABLE_SECURITY_ALERT_EMAILS=false`. Configure SMTP only if quote/contact/invitation delivery has quota and acceptance proof. |
| Dangerous compatibility flags | Force off | `ENABLE_SELF_SIGNUP=false`, `ENABLE_LEGACY_ROUTES=false`, and `ENABLE_MANUAL_LOG_INJECTION=false`. |
| Metrics | Restrict | New bearer token and loopback/private monitoring allowlist only. |

Before starting Compose, compare the new file to `.env.example`, resolve every production placeholder, then run `docker compose ... config --quiet`. Never print the resulting secret values into the terminal transcript or migration artifact.

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

### 6.6 Create a powered-off DigitalOcean snapshot

This is an additional rollback image only. It does not replace the encrypted Mongo backup, and this runbook does not treat a DigitalOcean snapshot as an importable Azure VM image.

Install and authenticate `doctl` on the trusted operator machine, not inside the stopped Droplet:

```bash
sudo snap install doctl
doctl auth init --context warsoc-cutover
doctl account get --context warsoc-cutover
doctl compute droplet list --context warsoc-cutover
```

Record the Droplet ID. Then power down cleanly from the DigitalOcean SSH session:

```bash
sudo shutdown -h now
```

Wait until the Droplet is off, then run on the operator machine:

```bash
export DO_DROPLET_ID='<digitalocean-droplet-id>'
export SNAPSHOT_NAME="warsoc-pre-azure-$(date -u +%Y%m%dT%H%M%SZ)"

doctl compute droplet-action snapshot "$DO_DROPLET_ID" \
  --snapshot-name "$SNAPSHOT_NAME" \
  --wait \
  --context warsoc-cutover

doctl compute droplet snapshots "$DO_DROPLET_ID" \
  --context warsoc-cutover \
  --output table
```

DigitalOcean recommends powering off database hosts before snapshotting for consistency. Record the snapshot ID and completion time. If the source must remain available for rollback, power it on but keep Nginx and all writers stopped. Never expose both backends as writable.

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
$AgentVersion = '<approved-version>'

.\scripts\run_production_acceptance.ps1 `
  -Phase Preflight `
  -FrontendUrl "https://warsoc.tech" `
  -BackendUrl "https://api.warsoc.tech" `
  -ManifestPath ".\output\pilot_hash_manifest-$AgentVersion.json" `
  -InstallerPath ".\output\warsoc_installer-$AgentVersion.exe" `
  -ArtifactUrl "https://warsocartifacts.blob.core.windows.net/warsoc-agent-public/warsoc_installer-$AgentVersion.exe"
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
  -ManifestPath ".\output\pilot_hash_manifest-$AgentVersion.json" `
  -InstallerPath ".\output\warsoc_installer-$AgentVersion.exe" `
  -ArtifactUrl "https://warsocartifacts.blob.core.windows.net/warsoc-agent-public/warsoc_installer-$AgentVersion.exe" `
  -ConfirmProductionDataCreation

$adminKey = $null
$metricsToken = $null
```

If SMTP quota is still unavailable, pass `-SkipEmailDeliveryCheck` and record email delivery as an explicit accepted limitation. Do not convert an SMTP failure into a SIEM/FBR/PECA failure.

### 9.4 Real agent and archive checks

Before accepting cutover:

1. Confirm one existing agent running the exact approved version reconnects without reinstalling.
2. Confirm its heartbeat becomes current and endpoint health is Active.
3. Generate one harmless native Windows event and confirm new SIEM evidence and an appropriate incident when the rule conditions are met.
4. Confirm a PECA-entitled tenant receives a fresh entitled PECA control record.
5. Confirm a configured FBR test path/JSONL source produces the expected FBR evidence; do not claim line-item monitoring without the JSONL contract.
6. Confirm one known Azure archive ledger entry and SHA-256. If archive retrieval is deliberately disabled for cutover, record that state rather than enabling it.
7. Export one hot-data CSV and one hot-data PDF. Historical archive download has a separate asynchronous acceptance gate.
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
- Network relay and hybrid-correlation code migrate in full but remain disabled. External exposure scanning is separate future scope and is not part of this release.
- The migration does not make unproven FBR or PECA legal claims. It preserves the current Windows evidence scope described in `WARSOC_CURRENT_STATE_ARCHITECTURE.md`.
- The temporary Azure-credit subscription can stop the VM when credit expires or the spending limit is reached. Cost alerts do not provide failover.
- A DigitalOcean snapshot remains in DigitalOcean and is only a short rollback aid. The encrypted off-host Mongo backup is the portable recovery source.

### 12.1 Network capability closure after migration

Azure cutover does not complete the physical network-device acceptance. The following remain explicit activation gates, not hidden migration work:

1. Build the exact relay release in the pinned environment, code-sign it or approve its SHA-256 through customer IT, and repeat malware scanning on those exact bytes.
2. Install `WarSOC_Relay` as its separate Windows service and prove service ACLs, DPAPI key protection, bounded evidence/control spools, restart recovery and uninstall behavior.
3. Validate real metadata from every vendor offered commercially: Fortinet, Cisco ASA, MikroTik and pfSense. An untested parser is not a supported-device claim.
4. Prove tenant source allowlists, clock-skew handling, device EPS circuit breakers, duplicate suppression, outage replay, spool saturation/loss reporting and Redis backpressure.
5. Prove metadata-only retention and source-assurance wording. UDP input is `relay_attested`, not cryptographically `device_authenticated`; packet payload capture remains out of scope.
6. Run a non-POS relay for at least 24 hours and review drops, disk growth, detection latency, false positives and quota behavior.
7. Complete the frontend relay activation/status/revoke and network-coverage views before offering self-service network onboarding.
8. Only after these gates pass may operations set `NETWORK_RELAY_ENABLED=true`, recreate the API/worker services and run the network acceptance suite. No public UDP port is opened on the Azure VM; customer devices send local syslog to the relay, and the relay forwards signed HTTPS batches over port 443.

## 13. Official References

- [Azure Linux VM creation with CLI](https://learn.microsoft.com/en-us/azure/virtual-machines/linux/quick-create-cli)
- [Azure subscription states](https://learn.microsoft.com/en-us/azure/cost-management-billing/manage/subscription-states)
- [Azure spending limits](https://learn.microsoft.com/en-us/azure/cost-management-billing/manage/spending-limit)
- [DigitalOcean powered-off snapshots](https://docs.digitalocean.com/products/snapshots/how-to/snapshot-droplets/)
- [DigitalOcean `doctl` snapshot command](https://docs.digitalocean.com/reference/doctl/reference/compute/droplet-action/snapshot/)
