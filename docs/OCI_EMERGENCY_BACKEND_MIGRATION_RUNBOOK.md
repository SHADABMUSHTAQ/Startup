# WarSOC Emergency Backend Migration To OCI

**Target:** `ubuntu@139.185.60.39`
**Release restored first:** `d92fb65`
**Data decision:** clean MongoDB/Redis start; expired pilot data is not migrated
**Azure:** existing private evidence/artifact services remain external dependencies
**Frontend:** remains on Vercel; only its existing API hostname is moved

This is a service-restoration procedure. It deliberately deploys the last
documented production-proven backend instead of the newer uncommitted candidate.
The newer work remains preserved in the local repository and is not discarded.

## 1. Required local files

These files have already been prepared locally:

```text
deploy/oci/bootstrap_warsoc_host.sh
deploy/oci/deploy_warsoc_release.sh
tmp/oci-migration/warsoc-backend-d92fb65.tar.gz
tmp/oci-migration/warsoc-backend-d92fb65.tar.gz.sha256
.env.prod
keys/private_key.pem
keys/public_key.pem
```

Never commit `.env.prod` or the private key.

## 2. Bootstrap OCI

Run in Windows PowerShell:

```powershell
cd C:\Users\Lenovo\Desktop\Startup-backend
$Key = "$env:USERPROFILE\Downloads\ssh-key-2026-08-26.key"

ssh -i $Key ubuntu@139.185.60.39
```

Verify the first host fingerprint through OCI, then exit. Copy and run the
bootstrap:

```powershell
scp -i $Key .\deploy\oci\bootstrap_warsoc_host.sh ubuntu@139.185.60.39:/home/ubuntu/
ssh -i $Key ubuntu@139.185.60.39
```

```bash
chmod 0700 /home/ubuntu/bootstrap_warsoc_host.sh
sudo bash /home/ubuntu/bootstrap_warsoc_host.sh
sudo reboot
```

Reconnect after the host returns.

## 3. Create the protected transfer directory

On OCI:

```bash
install -d -m 0700 /home/ubuntu/warsoc-migration
install -d -m 0700 /home/ubuntu/warsoc-migration/keys
```

## 4. Transfer the release and secrets

Run in Windows PowerShell:

```powershell
cd C:\Users\Lenovo\Desktop\Startup-backend
$Key = "$env:USERPROFILE\Downloads\ssh-key-2026-08-26.key"

scp -i $Key `
  .\tmp\oci-migration\warsoc-backend-d92fb65.tar.gz `
  .\tmp\oci-migration\warsoc-backend-d92fb65.tar.gz.sha256 `
  .\tmp\oci-migration\transfer.sha256 `
  .\deploy\oci\deploy_warsoc_release.sh `
  .\.env.prod `
  ubuntu@139.185.60.39:/home/ubuntu/warsoc-migration/

scp -i $Key `
  .\keys\private_key.pem `
  .\keys\public_key.pem `
  ubuntu@139.185.60.39:/home/ubuntu/warsoc-migration/keys/
```

On OCI:

```bash
chmod 0700 /home/ubuntu/warsoc-migration/deploy_warsoc_release.sh
chmod 0600 /home/ubuntu/warsoc-migration/.env.prod
chmod 0600 /home/ubuntu/warsoc-migration/keys/*.pem
cd /home/ubuntu/warsoc-migration
sha256sum --check warsoc-backend-d92fb65.tar.gz.sha256
sha256sum --check transfer.sha256
```

Both checksum checks must pass.

## 5. Build and start the private backend

On OCI:

```bash
sudo bash /home/ubuntu/warsoc-migration/deploy_warsoc_release.sh prepare
```

This stage:

1. Verifies the release archive and production configuration.
2. Extracts the release under `/opt/warsoc/releases/d92fb65`.
3. Pulls ARM64 MongoDB, Redis and Nginx images.
4. Builds the FastAPI/worker image natively on ARM64.
5. Starts MongoDB, Redis and FastAPI privately.
6. Requires the API health check to pass.
7. Starts the unified worker, compliance cron and storage archiver.
8. Leaves Nginx stopped until valid DNS and TLS exist.

Do not continue if `prepare` fails.

## 6. Change only the API DNS record

At the authoritative DNS provider, change:

```text
api.warsoc.tech  A  139.185.60.39
```

Do not change the frontend domain or Azure storage endpoints. Remove the old
DigitalOcean API address only after the new answer is visible from independent
resolvers.

Check from Windows:

```powershell
Resolve-DnsName api.warsoc.tech -Type A
```

The answer must contain `139.185.60.39`.

## 7. Issue TLS and activate the public edge

On OCI:

```bash
sudo bash /home/ubuntu/warsoc-migration/deploy_warsoc_release.sh activate
```

The script refuses activation unless DNS resolves to OCI. It obtains or reuses
the Let's Encrypt certificate, starts Nginx, and validates the HTTPS health
endpoint using the real hostname and certificate.

## 8. External acceptance

From Windows PowerShell:

```powershell
curl.exe -fsS https://api.warsoc.tech/health
curl.exe -sS -o NUL -w "%{http_code}`n" https://api.warsoc.tech/docs
Test-NetConnection 139.185.60.39 -Port 22
Test-NetConnection 139.185.60.39 -Port 80
Test-NetConnection 139.185.60.39 -Port 443
Test-NetConnection 139.185.60.39 -Port 6379
Test-NetConnection 139.185.60.39 -Port 27017
Test-NetConnection 139.185.60.39 -Port 8000
```

Required results:

```text
/health: healthy with MongoDB and Redis healthy
/docs: 404
22/80/443: reachable as intended
6379/27017/8000: not reachable
```

On OCI:

```bash
sudo bash /home/ubuntu/warsoc-migration/deploy_warsoc_release.sh status
sudo docker compose \
  --project-name warsoc-production \
  --env-file /opt/warsoc/Startup-backend/.env.prod \
  -f /opt/warsoc/Startup-backend/docker-compose.prod.yml \
  logs --since 15m warsoc-api unified-worker compliance-cron storage-archiver nginx \
  | grep -Ei 'error|failed|traceback|critical' || true
```

## 9. What this migration does not claim

- It does not migrate expired pilot MongoDB/Redis data.
- It does not promote the uncommitted backend candidate.
- It does not enable Wazuh, the network relay, archive retrieval, or other
  disabled profiles.
- It does not move or delete existing Azure blobs.
- It does not prove Azure immutability or archiver writes until a controlled
  post-start archive test is run.

After service restoration, freeze and validate the newer candidate as a
separate release rather than copying the dirty worktree onto OCI.
