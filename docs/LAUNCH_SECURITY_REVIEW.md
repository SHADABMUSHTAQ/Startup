# WarSOC Launch Security Review

Review date: 2026-05-11

## Launch Verdict

Status: conditional go.

The backend has strong launch-ready foundations: tenant isolation, Redis-backed revocation, CSRF protection, signed agent telemetry, WebSocket tickets, SIEM workers, compliance evidence handling, exports, and audit trails are present.

Do not expose this publicly until the critical launch blockers below are closed or explicitly accepted.

## Fixes Applied During This Review

- Fixed `MemoryLimitMiddleware` so healthy requests continue to the application instead of returning no response.
- Removed `.env` from the Docker image build.
- Added Docker build exclusions for `.env`, agent private keys, PEM files, and temporary enrollment files.
- Removed a stale legacy `agent_secret` value from tracked agent policy artifacts. Current agent authentication uses provisioning tokens plus ECDSA.

Verification performed:

- `python -m compileall app`
- `python -m pytest tests\mega_suite\test_08_backend_hardening.py -q`

## Critical Launch Blockers

1. Restrict trusted proxy headers before production.
   - `app/main.py` currently trusts all proxy headers through `ProxyHeadersMiddleware(... trusted_hosts="*")`.
   - `docker-compose.yml` also starts Uvicorn with `--forwarded-allow-ips=*`.
   - `app/utils/limiter.py` trusts `X-Forwarded-For` directly.
   - Risk: if the API is directly reachable, clients can spoof source IPs, weaken rate limiting, and affect IP-based controls.
   - Required action: remove the public `8000:8000` mapping in production and only trust the Nginx/private proxy address or internal Docker subnet.

2. Do not run production from the default compose file.
   - `docker-compose.yml` exposes MongoDB on `27017:27017` and API on `8000:8000`.
   - Required action: production traffic should enter only through Nginx on 443; MongoDB, Redis, API, and workers should remain private.

3. Fix `docker-compose.prod.yml` worker target.
   - It starts one service with `python -m app.workers.threat_hunter`, but the present worker file is `app/workers/detection_worker.py`.
   - Required action: change that command or add the missing module before launch.

4. Validate writable volumes in production.
   - `docker-compose.prod.yml` uses `read_only: true`.
   - The upload route writes to `uploaded_files`, and report generation uses app data paths.
   - Required action: add explicit writable volumes for uploads/reports or disable those features in production.

5. Rotate and protect local release secrets.
   - Untracked local artifacts include `.env`, `agent/agent_private_key.pem`, `nginx/ssl/server.key`, and token helper outputs.
   - Required action: rotate any secret or key that was ever shared, copied into images, committed elsewhere, or used outside local development.

## Important Hardening Items

- Use real CA-issued TLS certificates before public launch; do not ship the local Nginx self-signed key.
- Replace static super-admin API key comparison with constant-time comparison and network restrictions.
- Add explicit password policy on signup and invite flows.
- Add MFA for admin users before onboarding external customers.
- Disable or gate legacy routes (`/auth`, `/upload`, `/firewall`) if the frontend no longer needs them.
- Pin dependency versions for release builds, then run vulnerability scanning before tagging.
- Add structured JSON application logging instead of relying on console prints for production incident response.
- Confirm `ALLOWED_ORIGINS` is set to the actual production frontend domain only.

## Feature Inventory

Core product features:

- Multi-tenant user signup, login, logout, plan upgrade, and team management.
- Role-based access for admins, analysts, managers, and auditors.
- Signed Windows agent enrollment using provisioning tokens and ECDSA public keys.
- Live endpoint ingestion through `/api/v1/ingest/pulse` into Redis Stream `raw_logs_queue`.
- Agent heartbeat and endpoint status visibility.
- Real-time tenant-scoped WebSocket alerts using short-lived one-time tickets.
- SIEM alert feed, severity/status filtering, and alert status workflow.
- Manual CSV log upload, parsing, normalization, search, report download, and deletion.
- Global search across live logs and uploaded CSV records.
- Threat mitigation: tenant-scoped IP block/revoke list and agent-side firewall enforcement.
- Compliance evidence vault for ETO/PECA and FBR-style evidence streams.
- Cryptographic evidence verification endpoint for signed forensic records.
- CSV/PDF exports for logs, alerts, compliance records, and audit reports.
- Prometheus metrics endpoint for Redis health, dead-letter queue depth, and fail-closed auth counts.
- Admin tenant provisioning and tenant listing using `SUPER_ADMIN_API_KEY`.
- Network syslog receiver for RFC 3164, RFC 5424, CEF, and plain text syslog.
- Separate SIEM, PECA, FBR, detection, and compliance cron workers.

## Current Log Coverage

Endpoint logs collected by the Windows agent:

- Windows Security log events from configured channels.
- Sysmon events when Sysmon is installed and the channel is available.
- Web server access logs from configured file paths and glob patterns.
- Agent heartbeat state.
- Local firewall block actions applied from tenant mitigation policy.
- Disk-spooled telemetry for offline resilience and retry.

Configured endpoint event IDs include:

- `4624`: successful logon.
- `4625`: failed logon.
- `4672`: special privileges assigned.
- `4720`: account created.
- `4726`: account deleted.
- `1102`: audit log cleared.
- `4663`: object/file access.
- `4660`: object deleted.
- `4657`: registry value modified.
- `4698`: scheduled task created.
- `4732`: local group member added.
- `4670`: permissions changed.
- `4616`: system time changed.
- `4697` and `7045`: service installed.
- `4719`: audit policy changed.
- `4798`: local group membership enumerated.
- `4648`: explicit credential use.
- `5156`: Windows Filtering Platform network connection.
- `80`: custom web log event.
- Sysmon `1`, `3`, `11`: process creation, network connection, and file creation coverage where Sysmon is enabled.

Network logs collected:

- UDP syslog on port `5140`.
- RFC 3164 syslog.
- RFC 5424 syslog.
- CEF security appliance events.
- Plain text syslog fallback.
- Nginx access/error logs at the gateway.
- Web access logs tailed by endpoint agent paths.
- Endpoint network telemetry via Sysmon Event 3 and Windows Event 5156.

Application/security logs produced:

- `logs`: normalized live endpoint and network telemetry.
- `security_alerts`: SIEM and detection alerts.
- `csv_uploads`: normalized manual CSV uploads.
- `analysis_results`: upload/report metadata.
- `management_audit`: audited user/admin actions.
- `system_audit`: upload deletion and system audit actions.
- `peca_forensic_logs`: signed long-retention forensic records.
- `fbr_pos_logs`: FBR-style compliance records.
- `firewall_rules`: tenant IP block/revoke state.
- `daily_forensic_ledgers`: periodic integrity ledger.
- Redis keys/streams for raw logs, replay prevention, auth blacklist, agent status, throttles, threat intel fanout, and dead-letter queue metrics.

Major current gaps:

- No first-class email security connector yet.
- No STIX/TAXII or MISP feed ingestion yet.
- No cloud audit connectors yet for Microsoft Entra, AWS CloudTrail, Google Cloud, or SaaS apps beyond Google/Microsoft guidance below.
- Sysmon coverage depends on endpoint deployment and policy validation.

## Email Integration Guidance

Recommended first release path:

1. Microsoft 365 email security.
   - Preferred: Microsoft Graph Security `alerts_v2` for alert ingestion.
   - Enterprise/high-volume option: Microsoft Defender XDR incidents or streaming through Azure Event Hubs.
   - Normalize `MailBox`, `MailMessage`, sender, recipient, subject, URL, attachment hash, source IP, severity, and service source into `raw_logs_queue`.

2. Google Workspace email security.
   - Use Google Workspace Alert Center API with a service account and domain-wide delegation.
   - Poll `/v1beta1/alerts` using `pageToken`, `filter`, and `orderBy`.
   - Normalize Gmail phishing, malware, spam, spoofing, suspicious login, and account alerts into the same log schema.

3. User-reported phishing mailbox.
   - Use IMAP or Graph mailbox read only as a fallback, not as the primary enterprise integration.
   - Extract headers, sender domain, URLs, attachments, hashes, and submitter identity.

Implementation model:

- Add an `integrations` collection keyed by `tenant_id`, provider, status, encrypted credentials, scopes, cursor, and last sync time.
- Add provider workers that poll or consume events and write normalized records to Redis Stream `raw_logs_queue`.
- Use a stable idempotency key: `provider:tenant:event_id`.
- Store raw provider JSON in `raw_data`; store analyst-friendly fields in `processed_data`.
- Add integration health metrics: last success, last error, lag seconds, events ingested, and rate-limit state.
- Keep provider network calls out of user request paths.

Suggested custom email event mapping:

- `8233`: email security/phishing event.
- `8234`: malicious attachment or file hash event.
- `8235`: suspicious sender/domain event.
- `8236`: user-reported phishing event.
- MITRE mapping should include `T1566` for phishing and related URL/file execution stages where applicable.

## Threat Intel Integration Guidance

What exists now:

- Static threat intelligence IP list in config.
- VirusTotal IP reputation lookup with in-memory rate limiting and learned IP persistence.
- AbuseIPDB reputation lookup in the detection worker with Redis caching.
- Mongo collection for learned malicious IPs and Redis pub/sub fanout into active SIEM memory.

Recommended next phase:

1. Add a provider-neutral indicator store.
   - Collection: `threat_intel_indicators`.
   - Fields: `tenant_id`, `type`, `value`, `source`, `confidence`, `tlp`, `tags`, `first_seen`, `last_seen`, `expires_at`, `provider_ref`, `revoked`, `raw_data`.
   - Unique key: `tenant_id + type + value + source`.
   - TTL on `expires_at`.

2. Add feed workers.
   - MISP: pull `/attributes/restSearch` using API key auth.
   - STIX/TAXII: pull TAXII 2.1 collections and parse STIX indicators.
   - VirusTotal: keep current IP enrichment and extend to domain/hash/URL lookups if licensed.
   - AbuseIPDB: keep cached IP scoring and optionally add reporting for high-confidence confirmed attacks.

3. Use confidence-based enforcement.
   - `>= 90`: auto-enrich and optionally auto-block if tenant policy allows it.
   - `70-89`: enrich and alert; analyst confirmation before block.
   - `< 70`: store as context only.

4. Keep detection fast.
   - Hot path should use Redis sets/hashes or in-memory snapshots.
   - Provider calls should run in background workers.
   - If a provider is down or rate limited, ingestion should continue and mark enrichment as degraded.

5. Add governance.
   - Track source, TLP, expiry, and confidence for every indicator.
   - Support allowlists for private ranges, customer-owned IPs, payment providers, and critical SaaS.
   - Audit every auto-block with indicator source and rule version.

## Release Gate Checklist

- [ ] Use production compose or equivalent private-network deployment only.
- [ ] Remove direct public exposure of API, MongoDB, and Redis.
- [ ] Restrict trusted proxy/forwarded headers.
- [ ] Fix `docker-compose.prod.yml` `app.workers.threat_hunter` command.
- [ ] Add writable production volume for uploads/reports or disable upload/report features.
- [ ] Replace self-signed TLS material.
- [ ] Rotate all release secrets and agent keys.
- [ ] Set production `ALLOWED_ORIGINS`.
- [ ] Confirm Redis password, MongoDB auth, JWT secret, encryption key, metrics token, and super-admin key are strong and stored outside git/images.
- [ ] Run full backend hardening suite and live-fire syslog/agent ingestion tests against the release container.
- [ ] Run dependency and container image vulnerability scans.
- [ ] Validate at least one live Windows endpoint with Sysmon installed.
- [ ] Validate tenant isolation with two tenants in the production-like environment.
- [ ] Validate alert WebSocket flow via one-time `/api/v1/ws/ticket`.

## References

- Microsoft Graph Security alerts API: https://learn.microsoft.com/en-us/graph/api/security-list-alerts_v2
- Microsoft Defender XDR incidents API: https://learn.microsoft.com/en-us/microsoft-365/security/defender/api-list-incidents
- Microsoft Defender streaming guidance: https://learn.microsoft.com/en-us/microsoft-365/security/defender-business/mdb-streaming-api
- Google Workspace Alert Center API overview: https://developers.google.com/workspace/admin/alertcenter/guides
- Google Workspace Alert Center `alerts.list`: https://developers.google.com/admin-sdk/alertcenter/reference/rest/v1beta1/alerts/list
- STIX 2.1 standard: https://docs.oasis-open.org/cti/stix/v2.1/
- TAXII 2.1 standard: https://docs.oasis-open.org/cti/taxii/v2.1/
- MISP automation API: https://misp.gitbooks.io/misp-book/content/automation/
- VirusTotal IP address report API: https://docs.virustotal.com/reference/ip-info
- AbuseIPDB API v2 docs: https://docs.abuseipdb.com/
