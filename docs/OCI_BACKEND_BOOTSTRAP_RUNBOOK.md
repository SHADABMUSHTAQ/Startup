# WarSOC OCI Backend Host Bootstrap

**Target host:** `ubuntu@139.185.60.39`
**Operating system:** Canonical Ubuntu 22.04 Minimal
**Architecture:** ARM64 / `aarch64`
**Shape:** `VM.Standard.A1.Flex`, 4 OCPU, 24 GB RAM
**Boot volume:** 46.6 GB

This runbook prepares the OCI host. It does not deploy WarSOC, move production
data, change DNS, or expose MongoDB/Redis.

## 1. OCI network rules

Before connecting, configure the instance's OCI Network Security Group or VCN
Security List with these ingress rules:

| Protocol | Port | Source |
| --- | ---: | --- |
| TCP | 22 | Administrator public IP `/32` where possible |
| TCP | 80 | `0.0.0.0/0` |
| TCP | 443 | `0.0.0.0/0` |

Do not create ingress rules for `6379`, `27017`, `8000`, `8443`, or UDP
`5140`. OCI network rules and the host firewall are independent controls; both
must be correct.

## 2. Protect and verify the SSH key

Run in Windows PowerShell:

```powershell
$Key = "$env:USERPROFILE\Downloads\ssh-key-2026-08-26.key"
Test-Path -LiteralPath $Key
icacls $Key /inheritance:r
icacls $Key /grant:r "$($env:USERNAME):(R)"
ssh-keygen -lf $Key
```

Do not upload or paste the private key. On the first connection, compare the
server host-key fingerprint with the fingerprint shown by OCI before accepting
it.

## 3. Verify the first SSH connection

```powershell
ssh -i $Key ubuntu@139.185.60.39
```

The first connection displays the server host-key fingerprint. Verify it
through a trusted OCI console path before accepting it, then exit the session:

```bash
exit
```

## 4. Copy the bootstrap script

Run from the backend repository in Windows PowerShell:

```powershell
cd C:\Users\Lenovo\Desktop\Startup-backend
$Key = "$env:USERPROFILE\Downloads\ssh-key-2026-08-26.key"

scp -i $Key `
  .\deploy\oci\bootstrap_warsoc_host.sh `
  ubuntu@139.185.60.39:/home/ubuntu/bootstrap_warsoc_host.sh
```

## 5. Connect and bootstrap

```powershell
ssh -i $Key ubuntu@139.185.60.39
```

On the OCI host:

```bash
chmod 0700 /home/ubuntu/bootstrap_warsoc_host.sh
sudo bash /home/ubuntu/bootstrap_warsoc_host.sh
```

The script fails before making application changes if the host is not Ubuntu
22.04 ARM64, has fewer than 4 OCPU, has less than 20 GiB usable RAM, has a root
volume below 40 GiB, or has less than 15 GiB free on `/`. It then:

1. Updates and upgrades Ubuntu.
2. Installs Docker Engine, Buildx, and the Compose plugin from Docker's official
   ARM64 repository.
3. Enables Docker and containerd at boot.
4. Adds `ubuntu` to the `docker` group.
5. Enables UFW with only SSH, HTTP, and HTTPS admitted.
6. Explicitly denies public Redis and MongoDB access.
7. Installs a persistent `DOCKER-USER` guard for internal service ports because
   Docker-published traffic can bypass ordinary UFW input processing.

If the script reports that a reboot is required:

```bash
sudo reboot
```

Reconnect after the server returns. A new login is also required for Docker
group membership to take effect.

## 6. Acceptance checks

Run on the OCI host after any required reboot:

```bash
uname -m
. /etc/os-release && printf '%s %s\n' "$ID" "$VERSION_ID"
docker version --format 'Docker server: {{.Server.Version}} ({{.Server.Arch}})'
docker compose version
systemctl is-enabled docker
systemctl is-active docker
systemctl is-enabled warsoc-docker-firewall
systemctl is-active warsoc-docker-firewall
sudo ufw status verbose
sudo iptables -S DOCKER-USER
sudo ss -lntup
df -h /
free -h
```

Required result:

```text
Architecture: aarch64 / arm64
Docker: enabled and active
Docker firewall guard: enabled and active
Public listeners: SSH 22 only before WarSOC deployment
Redis 6379: no public listener
MongoDB 27017: no public listener
Free root disk: at least 15 GiB before deployment
```

After WarSOC is deployed, only Nginx may publish host ports `80` and `443`.
FastAPI remains reachable only through Nginx. Redis and MongoDB remain on the
private `warsoc-internal` Docker network with no Compose `ports` mappings.

## 7. WarSOC state boundary

The existing production stack already contains the required containers:

```text
Nginx -> FastAPI -> Redis/MongoDB
                  -> workers/archiver
```

Do not create a second simplified Compose stack. Deploy
`docker-compose.prod.yml` after the separate migration preflight is complete.

FastAPI must not use process-local dictionaries, lists, or arrays as the source
of truth for sessions, replay protection, rate limits, quotas, queues, or
correlation windows. Those states remain in Redis or MongoDB. Request-local
objects and the set of currently open WebSocket objects are transient runtime
objects, not durable session state; losing them may disconnect a live socket but
must not lose authenticated session or evidence state.

## 8. Stop point

Host bootstrap acceptance is not production migration acceptance. Do not start
WarSOC or change DNS until the following are separately available and checked:

- an exact approved backend commit;
- ARM64 image/build validation;
- a production `.env.prod` transferred without committing secrets;
- TLS certificate and renewal plan;
- MongoDB restore or clean-start decision;
- Azure evidence-storage credentials and immutability validation;
- rollback and DNS cutover commands.

The 46.6 GB boot volume is the main capacity risk. Do not keep database backup
archives, restored Azure blobs, or uncompressed evidence packages on this host.
