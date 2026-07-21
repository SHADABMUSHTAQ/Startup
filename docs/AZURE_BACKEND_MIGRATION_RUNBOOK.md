# WarSOC Backend Migration: DigitalOcean to Azure VM

## Scope

This runbook moves the existing Docker Compose backend to one hardened Azure
Ubuntu VM. It does not move the Vercel frontend or the public Azure agent
artifact. It does not replace MongoDB or Redis with new managed products during
the cutover. That conservative boundary keeps the application topology and
failure behavior unchanged.

The migration is not complete until the Azure VM has passed production
acceptance and DigitalOcean has remained available for rollback for at least
24 hours.

## Required Inputs

- An authenticated Azure CLI session and target subscription ID.
- An administrator SSH public key and a restricted source CIDR.
- The current `.env.prod`, transferred outside Git.
- The current `/etc/letsencrypt` tree, transferred as root and never committed.
- A fresh encrypted MongoDB backup plus its SHA-256 sidecar.
- The backup encryption passphrase from the independent secret store.
- Access to update only the `api.warsoc.tech` DNS A record.

## 1. Provision Azure Without Changing Production

Install Azure CLI, authenticate, then run from a trusted Linux shell:

```bash
export AZURE_SUBSCRIPTION_ID='<subscription-id>'
export ADMIN_SSH_PUBLIC_KEY="$HOME/.ssh/id_ed25519.pub"
export ADMIN_SOURCE_CIDR='<administrator-public-ip>/32'
export LOCATION='southeastasia'
bash deploy/azure/provision_warsoc_vm.sh
```

The script creates a static public IP, VNet, NSG, NIC, Trusted Launch Ubuntu
24.04 VM, 240 GB Premium OS disk, Docker, UFW, fail2ban and unattended security
updates. Azure exposes only SSH from the approved CIDR and public HTTP/HTTPS.
MongoDB, Redis, FastAPI and syslog remain private.

## 2. Stage the Application

On the Azure VM:

```bash
sudo git clone https://github.com/SHADABMUSHTAQ/Startup.git /opt/warsoc/Startup-backend
cd /opt/warsoc/Startup-backend
sudo install -m 600 /secure-transfer/.env.prod .env.prod
sudo install -d -m 700 /etc/letsencrypt
sudo rsync -a --chown=root:root /secure-transfer/letsencrypt/ /etc/letsencrypt/
sudo docker compose --env-file .env.prod -f docker-compose.prod.yml config --quiet
```

Do not start Nginx before the certificate tree exists. Do not place secrets,
certificates, backups, or private keys in Git.

Keep `AGENT_EVENT_SIGNATURE_MODE=observe` during the endpoint-agent upgrade.
Switch it to `required` only after all active agents run the signing-capable
build and signed-event metrics/logs show no unsigned legacy sources.

## 3. Pre-Cutover Restore Rehearsal

Create a current encrypted backup with `scripts/backup_mongodb.sh`. Download the
encrypted archive and sidecar to a trusted operator machine and run:

```powershell
$secret = Read-Host 'Backup passphrase' -AsSecureString
.\scripts\run_backup_restore_drill.ps1 `
  -BackupPassphrase $secret `
  -ExistingEncryptedArchive C:\secure\warsoc_mongodb.archive.gz.enc `
  -ExistingHashFile C:\secure\warsoc_mongodb.archive.gz.enc.sha256
```

The drill must report `PASS`, verify SHA-256, restore `tenants` and `users`,
record all collection/index counts and delete its network-disabled temporary
MongoDB container.

## 4. Quiesce DigitalOcean Safely

Lower the `api.warsoc.tech` DNS TTL to 300 before the window. At cutover:

1. Stop old Nginx first. Agents receive connection failures and retain events in
   their bounded local spools.
2. Leave the workers, MongoDB and Redis running while existing Redis work drains.
3. Confirm the raw SIEM/FBR/PECA consumer groups have zero pending entries.
4. Confirm transactional email waiting/processing queues are empty or explicitly
   export them. Security-alert email remains disabled.
5. Stop the workers only after the queues are drained.
6. Create the final encrypted MongoDB backup and verify its SHA-256 sidecar.
7. Do not delete or reset the DigitalOcean VM.

If queues cannot drain, abort the cutover. Do not migrate a knowingly partial
evidence state.

## 5. Restore and Start Azure

Start only MongoDB and Redis on Azure, restore the final database archive into
the configured production database, then start the remaining services:

```bash
cd /opt/warsoc/Startup-backend
sudo docker compose --env-file .env.prod -f docker-compose.prod.yml up -d mongodb redis
# Decrypt and restore the verified archive using the procedure proven by the drill.
sudo docker compose --env-file .env.prod -f docker-compose.prod.yml up -d --build
```

Before public cutover, test the local API through the Nginx container and inspect
all service health and worker logs. Never publish ports 27017, 6379 or 8000.

## 6. DNS Cutover and Acceptance

Change only `api.warsoc.tech` to the Azure static public IP. Vercel remains the
owner of `warsoc.tech`; the agent installer remains in Azure Blob Storage.

After DNS resolves, run:

```bash
sudo bash deploy/azure/validate_host.sh
```

Then run the production acceptance phases from a trusted Windows machine. The
minimum gate is:

- TLS/health/CORS pass.
- Login, TOTP and RBAC pass.
- Activation, registration, signed heartbeat and signed telemetry pass.
- SIEM alert, FBR evidence and PECA evidence appear for the correct tenant.
- WebSocket updates and incident workflow pass.
- CSV/PDF and hot/cold archive retrieval pass.
- Transactional mail is tested only after the provider quota is available.
- A fresh Azure-hosted Mongo backup restores successfully in isolation.

## 7. Rollback

Keep DigitalOcean stopped but intact for at least 24 hours. Roll back if tenant
isolation fails, signed events are rejected unexpectedly, workers cannot drain,
evidence is missing, Mongo/Redis is unhealthy, or recovery validation fails.

Rollback sequence:

1. Stop Azure Nginx to prevent split writes.
2. Restore the latest post-cutover Mongo delta to DigitalOcean if any writes were
   accepted on Azure.
3. Point `api.warsoc.tech` back to the DigitalOcean IP.
4. Start the old stack and validate health before reopening ingestion.

Never run both backends writable behind the same hostname. Redis state and Mongo
state are not multi-primary replicated by this design.

## Known Limitations

- This remains a single-VM deployment, not high availability.
- Azure VM Backup is a second infrastructure recovery layer, not a replacement
  for encrypted application-consistent MongoDB backups.
- Existing endpoint agents remain lower-assurance until upgraded and production
  switches `AGENT_EVENT_SIGNATURE_MODE` from `observe` to `required`.
- A live migration needs Azure credentials, DNS control and the final production
  backup; repository changes alone cannot perform those external actions.
