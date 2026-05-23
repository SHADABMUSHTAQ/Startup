# Fresh Run Checklist

Use this checklist before running end-to-end validation on the backend.

## 1) Clean the runtime
- Stop any stray local API processes.
- Stop worker terminals if they are still running.
- Confirm port `8000` is free.
- Confirm Docker is not holding an old gateway/API instance.

## 2) Start infrastructure
- Start MongoDB and Redis.
- Verify both containers are healthy.
- Make sure the backend environment points to the local Docker services.

## 3) Start the API
- Start a single local API process with `PYTHONPATH=.`.
- Confirm startup logs show Redis connected, MongoDB connected, and routers loaded.

## 4) Run the targeted pipeline test
- Run the hardcoded SIEM / PECA / FBR pipeline test first.
- Expected result: login succeeds, ingest succeeds, evidence is written and fetchable.

## 5) Run the full end-to-end suite
- Run `tests/test_compliance_evidence_gate.py`.
- Run `tests/mega_suite`.
- Run `tests/test_grand_master_e2e.py`.
- Expected result: compliance gate passes, hardening suite passes, and grand master E2E passes.

## 6) Bring up Docker gateway
- Start `api` and `nginx`.
- Ensure the TLS files exist at `nginx/ssl/server.crt` and `nginx/ssl/server.key`.
  - For Day-1 native deployment prefer systemd instead of Docker for the API:
    - Copy backend to `/opt/warsoc`, create virtualenv at `/opt/warsoc/.venv`, and install requirements.
    - Install systemd unit: `sudo cp scripts/systemd/warsoc-api.service /etc/systemd/system/` then `sudo systemctl daemon-reload && sudo systemctl enable --now warsoc-api`.
  - Ensure `nginx/ssl/server.crt` and `nginx/ssl/server.key` are present for TLS edge termination.
- If those files are missing, generate local self-signed certs for development.
- Verify the gateway responds over HTTPS.

## 7) Validate gateway health
- Smoke test the gateway with `curl.exe -k -I https://127.0.0.1/`.
- Expected result: `HTTP/1.1 200 OK`.

## 8) Memory gate guidance
- Do not disable the memory gate in production.
- If `MemoryLimitMiddleware` trips locally, first check stray processes, load generators, and Docker containers.
- Only after the runtime is clean should you decide whether the workload itself is too heavy.

## 9) Common failure signals
- `503 Service unavailable: memory pressure too high` usually means the host is already under load.
- nginx certificate errors usually mean `nginx/ssl` is empty or the cert mount is missing.
- Login or ingest `401`/`422` errors usually mean the seeded user, tenant, or payload is wrong.

## 10) Final verification
- Confirm the pipeline test passes.
- Confirm the full suite passes.
- Confirm the gateway smoke test passes.
- Record warnings separately from failures.

## Notes
- Keep the memory gate enabled in production.
- For local development, prefer cleaning the runtime over masking the root cause.
- Replace any self-signed certs with the real certificate pipeline before deploying to production.# Fresh Run Checklist

Use this checklist before running end-to-end validation on the backend.

## 1) Clean the runtime
- Stop any stray local API processes:
  - `uvicorn app.main:app`
  - any old `python.exe` workers
- Stop worker terminals if they are still running.
- Confirm port `8000` is free.
- Confirm Docker containers are not holding an old gateway/API instance.

## 2) Start infrastructure
- Start MongoDB and Redis.
- Verify both containers are healthy.
- Make sure the backend environment points to the local Docker services.

## 3) Start the API
- Start a single local API process with `PYTHONPATH=.`.
- Confirm startup logs show:
  - Redis connected
  - MongoDB connected
  - routers loaded
  - no startup exceptions

## 4) Run the targeted pipeline test
- Run the hardcoded SIEM / PECA / FBR pipeline test first.
- Expected result:
  - login succeeds
  - ingest succeeds
  - evidence is written and fetchable

## 5) Run the full end-to-end suite
- Run:
  - `tests/test_compliance_evidence_gate.py`
  - `tests/mega_suite`
  - `tests/test_grand_master_e2e.py`
- Expected result:
  - compliance gate passes
  - hardening suite passes
  - grand master E2E passes

## 6) Bring up Docker gateway
- Start `api` and `nginx`.
- Ensure the TLS files exist at:
  - `nginx/ssl/server.crt`
  - `nginx/ssl/server.key`
- If those files are missing, generate local self-signed certs for development.
- Verify the gateway responds over HTTPS.

## 7) Validate gateway health
- Smoke test the gateway:
  - `curl.exe -k -I https://127.0.0.1/`
- Expected result:
  - `HTTP/1.1 200 OK`

## 8) Memory gate guidance
- Do not treat a successful local run as permission to disable safety checks in production.
- If `MemoryLimitMiddleware` trips locally, first check:
  - stray API/worker processes
  - load generator activity
  - Docker containers consuming memory
- Only after confirming the runtime is clean should you decide whether the workload itself is too heavy.

## 9) Common failure signals
- `503 Service unavailable: memory pressure too high`
  - usually means the host is already under load
- nginx certificate errors
  - usually means `nginx/ssl` is empty or the cert mount is missing
- login or ingest 401/422 errors
  - usually means the seeded user/tenant or request payload is wrong

## 10) Final verification
- Confirm the pipeline test passes.
- Confirm the full suite passes.
- Confirm the gateway smoke test passes.
- Record any warnings separately from failures.

## 11) Production Host-Native Deployment (2GB Droplet)

To bypass Docker's heavy memory overhead on the 2GB VPS, deploy the application stack directly to the host OS using the systemd and gateway assets provided:

### 11.1) Bare-Metal Directory Preparation
1. Deploy the codebase to `/opt/warsoc` on the server.
2. Initialize virtualenv and install dependencies:
   ```bash
   cd /opt/warsoc
   python3 -m venv .venv
   source .venv/bin/activate
   pip install --upgrade pip
   pip install -r requirements.txt
   ```
3. Establish your production environment file at `/opt/warsoc/.env`.

### 11.2) Natively Daemonize API & 7 Workers
1. Navigate to the systemd setup directory:
   ```bash
   cd /opt/warsoc/scripts/systemd
   ```
2. Run the automated native installer script to deploy and register all 8 services:
   ```bash
   sudo bash install_native.sh
   ```
3. Confirm all services are active:
   ```bash
   sudo systemctl status warsoc-*
   ```

### 11.3) Configure Nginx TLS Edge & Certbot
1. Install Nginx and Certbot on the host:
   ```bash
   sudo apt update
   sudo apt install nginx certbot python3-certbot-nginx -y
   ```
2. Copy the production Nginx config to `/etc/nginx/nginx.conf`:
   ```bash
   sudo cp /opt/warsoc/nginx/nginx.prod.conf /etc/nginx/nginx.conf
   ```
3. Obtain Let's Encrypt certificates (replace yourdomain.com with your domain name):
   ```bash
   sudo certbot --nginx -d yourdomain.com
   ```
4. Verify the Certbot cron job auto-renews certificates under Let's Encrypt.
5. Reload Nginx to register the TLS configurations:
   ```bash
   sudo systemctl reload nginx
   ```

### 11.4) Implement MongoDB 90-Day TTL Indexes
1. Access the mongo shell or apply the script directly:
   ```bash
   mongosh "mongodb://user:password@127.0.0.1:27017/WarSOC_DB?authSource=admin" /opt/warsoc/scripts/apply_ttl_indexes.js
   ```
2. This script automatically coerces legacy ISO string timestamps into BSON Dates and builds background indices.

## Notes
- Keep the memory gate enabled in production.
- For local development, prefer cleaning the runtime over masking the root cause.
- Replace any self-signed certs with the real certificate pipeline before deploying to production.
