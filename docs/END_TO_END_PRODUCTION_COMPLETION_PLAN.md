# WarSOC End-to-End Production Completion Plan

> **HISTORICAL IMPLEMENTATION PLAN.** Most items in this plan were executed before the 2026-07-15 production proof. Do not use its baseline or remaining-work statements as current status. Use `WARSOC_CURRENT_STATE_ARCHITECTURE.md`, `WARSOC_END_TO_END_PRODUCT_AND_OPERATOR_GUIDE.md`, and `PRODUCTION_ACCEPTANCE_TEST.md`.

## Purpose

This document defines the remaining changes required to move WarSOC from its
current locally validated state to a controlled production pilot. It is an
implementation specification only. Creating this document does not modify
runtime behavior, deployment configuration, detection rules, or customer data.

The plan improves existing WarSOC capabilities without adding unrelated
features or weakening endpoint security.

## Non-Negotiable Security Rules

- Microsoft Defender, SmartScreen, cloud protection, real-time protection, and
  tamper protection remain enabled.
- The unsigned pilot installer is authorized only through managed, per-release
  hash allowlisting. No directory-wide antivirus exclusions are permitted.
- MongoDB and Redis remain private Docker services with no public host ports.
- Public signup and legacy payment routes remain disabled.
- FBR evidence remains encrypted at rest.
- PECA evidence remains RSA-PSS signed and tenant isolated.
- Production secrets must not be committed, logged, emailed, or pasted into
  documentation.
- A failed durability operation must retain or retry evidence rather than
  silently acknowledging it.

## Verified Baseline

The following evidence already exists and should be preserved as regression
gates:

- Backend launch validator: 28 passes, zero failures, zero warnings.
- Frontend lint and production build pass.
- Frontend dependency audit reports no high-severity production dependency
  findings.
- Authenticated browser validation covers dashboard data, profile persistence,
  alert acknowledgment and closure, compliance evidence, team RBAC, and agent
  activation.
- Fifty-agent local soak:
  - 50 of 50 agents registered.
  - The 51st agent was rejected.
  - 50 of 50 burst requests were accepted.
  - SIEM canary latency was approximately 1.93 seconds.
  - SIEM, FBR, and PECA completion was approximately 15.84 seconds.
- The latest 100 sampled PECA records passed RSA-PSS signature verification.
- The current FBR vault dry run found no plaintext sensitive fields.
- The pilot hash manifest matches the current installer, agent, NSSM binary,
  and native telemetry script.

These checks prove local routing, entitlement, cryptography, and burst
capacity. They do not replace a native Windows VM test or production
infrastructure validation.

## Priority Definitions

- `P0`: Must be completed before the first customer endpoint is onboarded.
- `P1`: Must be completed during the controlled pilot before expanding beyond
  the first few endpoints.
- `P2`: Production hardening that can safely follow the pilot.

## Timebox Rules

The timeboxes below are maximum uninterrupted engineering budgets, not
permission to bypass acceptance criteria.

- At 75 percent of a timebox, the owner records the remaining blocker and
  requests a second review.
- At 100 percent, stop expanding the solution. Choose one of:
  - Apply the smallest safe correction within the existing scope.
  - Revert the incomplete change and use the last green build.
  - Declare the item a launch blocker.
- Never weaken security, suppress a failing test, or relabel a failure as a
  warning to meet a timebox.
- P0-8 infrastructure preparation runs in parallel with P0-1 through P0-7.
- A same-day pilot assumes the VM, Azure subscription, DNS access, Vercel
  access, and DigitalOcean host are available when work begins.
- With one engineer working strictly sequentially, the full plan can exceed one
  day. The same-day target depends on parallel infrastructure preparation.

### Parallel Execution Lanes

- Code lane: P0-1 through P0-6.
- Infrastructure lane: P0-8 and the backup destination from P0-9.
- Validation lane: P0-7, P0-9 restore proof, and P0-10.
- Release lane: P0-11 after all launch gates are green.

---

## P0-1: Make Agent Spooling Durability-Aware [Timebox: 90 Minutes]

### Problem

`DiskSpooler.append()` currently catches local write failures and returns
without informing the Windows event collector. The collector can subsequently
advance its channel watermark even though the event was not persisted.

### Files

- `agent/windows_agent.py`
- `tests/test_native_detection_completion.py`
- `scripts/validate_native_windows_vm.ps1`

### Required Change

1. Make `DiskSpooler.append()` return a success result or raise a dedicated
   spool persistence exception.
2. Complete the JSON serialization and durable file write before reporting
   success.
3. Flush the file handle and use `os.fsync()` before a target event is treated
   as durably accepted.
4. Increment a `spool_write_failures` sensor counter on every failed append.
5. Mark endpoint telemetry as degraded in the signed heartbeat while spool
   writes are failing.
6. For target Windows events, advance the channel watermark only after the
   event has been durably appended.
7. For intentionally ignored event IDs, advance the watermark normally.
8. If event `N` cannot be persisted, stop processing that channel batch before
   advancing beyond `N`. Retry from that record on the next poll.
9. Preserve the deterministic `channel:event_record_id` event UID so a retry
   after a watermark-write failure is idempotent at the backend.
10. Do not delete or truncate an unprocessed spool artifact.

### Tests

- Simulate access denied, disk full, serialization failure, and partial write.
- Confirm the watermark does not advance past the failed event.
- Restore disk access and confirm the same event is forwarded exactly once
  from the backend user's perspective.
- Kill the agent between spool append and watermark persistence, restart it,
  and confirm duplicate suppression works through the stable event UID.
- Confirm heartbeat status changes to `Degraded` and later returns to `Active`.

### Acceptance

- No target event is lost when the spool directory is temporarily unwritable.
- No infinite retry loop occurs for intentionally ignored events.
- The dashboard exposes spool failure health.

---

## P0-2: Preserve FBR Correlation Through Persistence Failure [Timebox: 2 Hours]

### Problem

The FBR worker currently consumes the Redis `4663` correlation value before
the resulting `FIM-DB-MOD` document is safely persisted. If MongoDB then fails,
the original `4660` event can be retained without the recovered file path.

### Files

- `app/workers/fbr_worker.py`
- `tests/test_native_detection_completion.py`
- `tests/mega_suite/test_14_fbr_deep.py`
- `scripts/launch_readiness_validator.py`

### Required Change

Use a Redis-backed correlation claim rather than deleting all context before
MongoDB persistence:

1. Keep the existing context key:

   `warsoc:fim_correlate:{tenant_id}:{agent_id}:{handle_id}`

2. When `4660` arrives, use one Lua transaction to:
   - Return an existing claim for the same event UID when retrying.
   - Otherwise move the context value into a short-lived claim key.
   - Prevent a second worker from claiming the same handle context.

3. Claim key:

   `warsoc:fim_claim:{tenant_id}:{agent_id}:{event_uid}`

4. Give the claim enough TTL for database retry and stale-message reclaim.
5. Build the normalized `FIM-DB-MOD` document with a deterministic event UID.
6. Upsert the encrypted FBR evidence and deterministic alert first.
7. Delete the claim only after MongoDB persistence succeeds.
8. A Redis or MongoDB failure must leave the stream message pending or place
   an enriched payload containing the resolved path in the DLQ.
9. A retry must upsert the same evidence and alert rather than creating a
   duplicate.
10. Never store the internal Redis key in customer-visible evidence.

### Tests

- Cross-worker `4663` and `4660` correlation.
- Redis unavailable during context creation and claim acquisition.
- MongoDB unavailable after claim acquisition.
- Worker crash after MongoDB upsert but before Redis cleanup.
- Stale-message reclaim after each failure point.
- Duplicate `4660` events.
- Handle reuse with a different path.
- TTL expiry.
- Exactly one encrypted FIM evidence record and one alert after recovery.

### Acceptance

- No FBR filename context is lost during Redis, worker, or MongoDB failure.
- Normal database writes still create no FIM alert.
- Deletion and permission changes remain idempotent.

---

## P0-3: Strengthen Native Windows Validation Provenance [Timebox: 1 Hour]

### Problem

The native VM validator currently accepts recent evidence by event type and
time. Background Windows activity could satisfy some checks without proving
that the validation run generated the evidence.

### Files

- `scripts/validate_native_windows_vm.ps1`
- `tests/test_native_detection_completion.py`
- Compliance evidence query tests

### Required Change

1. Generate one cryptographically random run ID per validation.
2. Record the registered agent ID, tenant ID, start time, hostname, and
   baseline channel record IDs.
3. Place the run ID in native fields where Windows permits it:
   - Failed and successful logon usernames.
   - Temporary account and group member names.
   - Process command lines.
   - Scheduled task names.
   - Service names and image paths.
   - Database filenames.
   - FBR invoice IDs and event UIDs.
4. Query evidence for the exact tenant and validate the returned `agent_id`.
5. Decrypt authorized evidence fields before checking the marker.
6. For `1100` and `1102`, which cannot carry an arbitrary marker, require:
   - The exact validation agent.
   - The expected Security channel/provider.
   - A record ID newer than the recorded baseline where applicable.
   - A timestamp inside the operation/reboot window.
   - The expected operator or machine context when Windows supplies it.
7. Reject evidence created before the validation start.
8. Produce a machine-readable JSON report containing every event, observed
   latency, evidence ID, agent ID, and pass/fail result.

### Acceptance

- Background activity cannot make the validator pass.
- All 11 PECA controls are tied to the disposable VM and validation run.
- FBR deletion and permission evidence identifies the exact test database.

---

## P0-4: Keep Permitted-Connection Auditing Controlled [Timebox: 30 Minutes]

### Problem

Event `5156` is a successful permitted connection and can generate very high
event volume. Event `5157` represents a blocked connection. Enabling both
globally on every POS endpoint without measurement could overwhelm the
Security log and agent spool.

### Files

- `agent/deploy_warsoc_telemetry.ps1`
- `agent/windows_agent.py`
- `agent/tenant_policy.json`
- `installer.iss`
- `app/utils/siem_catalog.py`
- Related unit and VM tests

### Required Change

1. Keep Filtering Platform failure auditing enabled by default for `5157`.
2. Do not advertise default `5156` collection when success auditing is off.
3. Report permitted-connection coverage as `Not Configured` in heartbeat and
   dashboard coverage for the pilot.
4. Keep the option off until a separate measured pilot establishes safe event,
   spool, ingestion, and storage limits.

Adding a customer-selectable `5156` policy option is P2 work. It is explicitly
outside this 30-minute launch-alignment timebox.

### Acceptance

- Default deployments reliably collect blocked connections.
- The UI accurately describes whether permitted connections are configured.
- Optional `5156` collection cannot silently overload the endpoint.

---

## P0-5: Define the Real FBR POS Integration Contract [Timebox: 45 Minutes]

### Problem

`/POS_PATHS` configures SACL-based file integrity monitoring. It does not make
the proprietary POS application emit invoice-level modification or deletion
events. The JSONL reader uses the fixed path:

`%ProgramData%\WarSOC\pos_audit.log`

The WarSOC state directory is intentionally restricted to SYSTEM and
Administrators, so an ordinary POS process cannot automatically append there.

### Files

- `docs/FBR_PECA_15_AGENT_FRONTEND_HANDOFF.md`
- A new concise customer POS integration document
- `agent/deploy_warsoc_telemetry.ps1`
- `installer.iss`
- `app/routes/pos.py`
- POS integration and tenant-isolation tests

### Required Change

Support and document two explicit modes:

#### Mode A: Zero-Integration FIM

- Customer supplies protected local POS database directories through
  `/POS_PATHS`.
- WarSOC detects supported database-file deletion and permission changes.
- WarSOC does not claim to detect proprietary row or invoice changes.

#### Mode B: Invoice-Level Integration

- Preferred: the POS backend sends authenticated events to
  `/api/v1/fbr/pos/ingest`.
- For the initial pilot, use this authenticated API unless the POS process
  already runs under an explicitly approved service identity.
- Do not enable local JSONL writing for an ordinary POS user by weakening the
  WarSOC directory ACL.

The P0 deliverable is to select and record either Mode A or authenticated API
Mode B for the pilot and align the contract and sales language. A new
installer-managed local writer identity, append-only ACL, and writer-health
telemetry are P1 work because they require additional endpoint and rollback
testing.

### Tests

- Strict schema, unknown-field rejection, malformed-line quarantine, event UID
  retry preservation, and tenant isolation.
- Authenticated API retries remain idempotent.
- Non-authorized local users cannot modify WarSOC state.

### Acceptance

- Sales and customer documentation distinguish FIM from invoice integration.
- Invoice-level claims are made only after the POS integration passes.

---

## P0-6: Rebuild and Validate the Pilot Installer [Timebox: 45 Minutes]

### Files

- `build_agent.bat`
- `warsoc_agent.spec`
- `installer.iss`
- `scripts/generate_pilot_hash_manifest.ps1`
- `docs/PILOT_UNSIGNED_AGENT_POLICY.md`

### Required Change

After all P0 agent changes:

1. Build the Windows agent from the reviewed source.
2. Build the Inno Setup installer.
3. Generate a new pilot hash manifest.
4. Verify manifest hashes for:
   - Installer.
   - Agent.
   - NSSM.
   - Native telemetry script.
5. Confirm Authenticode status is expected to be `NotSigned` for the pilot.
6. Transfer the installer and manifest through an authenticated channel.
7. Keep Defender and all protection features enabled.

### Acceptance

- Every shipped artifact matches the current release manifest.
- The installer aborts when telemetry or supplied POS-path configuration fails.
- Uninstall restores only WarSOC audit-policy and SACL changes.

---

## P0-7: Disposable Windows VM Acceptance [Timebox: 3 Hours]

### Environment

- Fresh supported Windows VM snapshot.
- Defender fully enabled.
- Pilot hashes authorized through managed IT policy.
- Real production-style HTTPS backend.
- FBR and PECA entitlement enabled for the test tenant.

### Test Sequence

1. Install with activation code, backend URL, and local POS path.
2. Confirm service, agent identity, and signed heartbeat.
3. Confirm Security and System channels are healthy.
4. Confirm audit-policy and SACL coverage.
5. Generate all 11 PECA controls from native Windows actions.
6. Generate FBR database permission and deletion scenarios.
7. Send strict invoice JSONL or authenticated API events.
8. Reboot to exercise Event `1100`.
9. Verify evidence, alerts, email, dashboard, PDF/CSV export, and RBAC.
10. Uninstall and verify audit-policy/SACL rollback.

### Acceptance Thresholds

- All 11 PECA controls are linked to the validation agent and run.
- Normal database writes create zero FIM alerts.
- Permission and deletion scenarios create the expected encrypted FIM evidence.
- Ordinary online detection is visible within 15 seconds.
- Reboot-related evidence uses a separate bounded timeout.
- No sensitive FBR fields are plaintext.
- PECA signatures verify with the configured public key.
- Defender remains active throughout.

---

## P0-7A: Preserve Validation Artifacts [Timebox: 30 Minutes]

### Storage Location

Create a private, access-controlled release folder outside the Git repository:

`launch_artifacts/<release_id>/`

The authoritative copy must be uploaded to a private Azure container. The
folder must never be committed because it can contain hostnames, tenant IDs,
usernames, infrastructure details, and security evidence.

### Required Artifacts

- `release_identity.json`
  - Release ID.
  - Git commit.
  - Container image digests.
  - Installer and manifest hashes.
  - UTC start/end times.
  - Operators and reviewers.
- `automated_tests.txt`
  - Unit and contract test results.
- `launch_validator.json`
  - Complete backend launch-validator output.
- `fifty_agent_soak.json`
  - Agent count, rejection of agent 51, latency, and failures.
- `native_windows_vm.json`
  - Exact tenant, agent, run marker, event IDs, evidence IDs, and latency.
- `native_windows_vm_screenshot.png`
  - Supporting dashboard view showing all 11 PECA controls. The JSON report,
    not the screenshot, remains authoritative.
- `defender_status.txt`
  - Defender, SmartScreen, real-time protection, and tamper-protection state.
- `audit_policy_before.txt` and `audit_policy_after.txt`
- `pos_sacl_before.txt` and `pos_sacl_after.txt`
- `fbr_plaintext_audit.txt`
- `peca_signature_audit.txt`
- `production_compose_redacted.txt`
  - Resolved service topology with every secret value removed.
- `tls_and_cors_validation.txt`
- `backup_restore_validation.txt`
- `frontend_user_journey.json`
- `rollback_target.json`
  - Previous frontend deployment, backend commit/images, and recovery owner.
- `launch_decision.json`
  - Final `GO`, `HOLD`, or `ROLLBACK` decision with reasons.

### Integrity and Retention

1. Generate `SHA256SUMS.txt` for every artifact.
2. Upload the bundle and checksum file to private Azure storage.
3. Verify uploaded hashes by downloading a sample or using a trusted retrieval
   verification process.
4. Apply the same access logging and retention policy used for launch records.
5. Redact secrets, session cookies, activation codes, private keys, SMTP
   passwords, SAS tokens, and full database connection strings.

### Gate Placement

P0-8 infrastructure preparation may continue in parallel. The P0-7 native VM
artifacts must be complete before P0-10 begins. The full artifact bundle,
including P0-9 and P0-10 results, must be complete and checksum-verified before
P0-11 customer rollout.

---

## P0-8: Production Infrastructure Configuration [Timebox: 3 Hours, Parallel]

### Azure

Create separate security boundaries:

1. Public artifact storage for the installer only.
2. Private compliance evidence storage.
3. Separate private database backup storage.

For private evidence and backup storage:

- Disable anonymous access.
- Enable secure transfer only.
- Enable versioning and soft delete.
- Configure appropriate immutability/WORM policy.
- Restrict credentials to the minimum required container.
- Test upload, hash verification, retrieval, and retention behavior.

### DigitalOcean

- Ubuntu LTS, 8 GB RAM, 4 vCPU.
- SSH keys only.
- UFW exposes only SSH, HTTP, and HTTPS by default.
- Bind syslog to loopback unless trusted network devices require it.
- If remote syslog is required, restrict UDP access by source network or VPN.
- MongoDB and Redis remain internal-only.
- Create swap, disk monitoring, time synchronization, and unattended security
  updates.

### TLS and DNS

1. Point `api.warsoc.tech` to the Droplet.
2. Wait for DNS resolution.
3. Obtain the Let's Encrypt certificate before starting TLS Nginx.
4. Mount `/etc/letsencrypt` read-only into Nginx.
5. Confirm automatic renewal and Nginx reload behavior.

### Production Environment

Populate `.env.prod` using the exact application and Compose variable names.
At minimum, validate:

- `APP_ENV=production`
- `JWT_SECRET_KEY`
- `SUPER_ADMIN_API_KEY`
- `ENCRYPTION_KEY`
- `PRIVATE_KEY_B64`
- `PUBLIC_KEY_B64`
- `PRIVATE_KEY_PASSWORD` when used
- `MONGO_USER`
- `MONGO_PASSWORD`
- `MONGODB_DB_NAME`
- `REDIS_PASSWORD`
- `ALLOWED_ORIGINS`
- `BACKEND_PUBLIC_URL`
- `AGENT_CDN_URL`
- `AZURE_STORAGE_CONNECTION_STRING`
- `AZURE_STORAGE_CONTAINER`
- `ZOHO_SMTP_HOST`
- `ZOHO_SMTP_PORT`
- `ZOHO_SMTP_USER`
- `ZOHO_SMTP_PASS`
- `SALES_EMAIL`
- `SYSLOG_BIND`
- Metrics authentication values

### Acceptance

- Production Compose resolves without placeholders.
- API and databases start healthy.
- Nginx is the only public API entry point.
- TLS, CORS, cookies, CSRF, and authenticated WebSockets work from the actual
  Vercel domain.

---

## P0-9: Backup and Restore Proof [Timebox: 90 Minutes]

### Files

- `scripts/backup_mongodb.sh`
- `deploy/backup.env.example`
- `docs/PRODUCTION_BACKUP_RUNBOOK.md`

### Required Action

1. Create a private Azure backup container.
2. Store backup credentials in `/etc/warsoc/backup.env` as root with mode 600.
3. Run one encrypted MongoDB backup.
4. Verify its SHA-256 sidecar.
5. Restore it into a disposable MongoDB 7 container.
6. Confirm tenants, users, agents, alerts, evidence metadata, and indexes.
7. Destroy the disposable restore environment.
8. Install the daily root cron only after the manual backup succeeds.

### Acceptance

- A backup is not considered operational until a complete restore succeeds.

---

## P0-10: Frontend and Production User Journey [Timebox: 90 Minutes]

### Frontend Configuration

- `VITE_API_BASE_URL=https://api.warsoc.tech/api/v1`
- Backend CORS contains only the actual production frontend origins.
- Do not add wildcard credentialed CORS.
- WebSocket URL remains derived from the API base URL.

### Browser Acceptance

Test from the deployed Vercel site:

1. Quote request and contact request.
2. Provisioned-user login.
3. Session hydration and CSRF.
4. Dashboard data and live WebSocket alerts.
5. Agent activation and Azure installer redirect.
6. Profile persistence.
7. Alert acknowledge and close-with-notes behavior.
8. FBR and PECA evidence visibility.
9. PDF and CSV exports.
10. Admin, analyst, manager, and auditor RBAC.
11. Logout and expired-session behavior.
12. Mobile and desktop layout smoke.

### Acceptance

- No browser mixed-content, CORS, cookie, CSRF, or WebSocket errors.
- Every visible operational action persists through the backend.

---

## P0-11: Controlled Customer Rollout [Timebox: 1 Hour Initial Canary]

Do not onboard all endpoints simultaneously:

1. Run one internal/disposable canary for 30 to 60 minutes.
2. Onboard one customer endpoint.
3. Expand to three endpoints after health remains green.
4. Expand to 15 and then 50 only while latency, queues, storage, and endpoint
   health remain within limits.

Monitor:

- API and worker health.
- Redis pending counts and memory.
- MongoDB disk and query latency.
- Agent channel and spool health.
- Parsing failures and DLQ entries.
- FIM correlation misses.
- Detection latency.
- Email delivery failures.
- Azure archival failures.
- TLS expiry and backup status.

---

## Production Test-Data Handling

- Never wipe the entire production MongoDB database.
- Identify disposable tenants by the validator run ID and known test prefixes.
- Create and verify a backup first.
- Delete only disposable tenant-owned records.
- Record the purge result.
- Preserve indexes, configuration, and legitimate tenants.

If the super-admin key was exposed during deployment or troubleshooting, rotate
it and rerun the minimal admin authorization tests. Otherwise, generate the
final production key once and keep it secret rather than rotating it
unnecessarily.

---

## Rollback Plan

### Decision Authority

The release owner can call `HOLD`. The security owner can call immediate
`ROLLBACK` for any security or evidence-integrity trigger. No commercial
approval is required to stop an unsafe deployment.

### Automatic Abort and Rollback Triggers

The following conditions require an immediate rollout abort. Restore the
affected component to the recorded rollback target:

| Area | Mandatory trigger |
| --- | --- |
| Tenant isolation | Any cross-tenant data, alert, evidence, agent, or user access |
| Authentication | Any authentication bypass, public signup success, auditor privilege escalation, or CSRF bypass |
| Endpoint security | Installer disables Defender protections, creates a broad exclusion, or cannot restore WarSOC audit/SACL changes |
| Evidence confidentiality | Any newly written sensitive FBR field is plaintext |
| Evidence integrity | Any newly written PECA signature fails verification |
| Evidence loss | A target native event is acknowledged after spool, Redis, or MongoDB persistence failed |
| False FIM | A normal database write creates a `FIM-DB-MOD` alert |
| API availability | After a five-minute startup grace period, `/health` fails three consecutive 30-second checks or remains unreachable for five minutes |
| API errors | HTTP 5xx responses exceed 5 percent for five consecutive minutes with at least 20 requests |
| Core dependencies | MongoDB or Redis remains unhealthy for more than two minutes after initial startup |
| Agent onboarding | Three consecutive canary agents fail registration or fail to produce a signed heartbeat within two minutes |
| Detection | An exact ordinary canary event is not visible within 60 seconds, or a reboot-related event is not visible within the declared VM timeout |
| Queue integrity | Run-specific DLQ entries appear during acceptance, or pending entries exceed 1,000 and continue growing for five minutes |
| Storage safety | The archiver deletes a hot record before blob/hash verification and metadata persistence |
| Resource exhaustion | Disk usage reaches 90 percent, or a required container repeatedly restarts three times within ten minutes |
| TLS | Certificate validation, hostname validation, or HTTPS-to-backend routing fails |

Security, isolation, evidence-integrity, and storage-safety triggers have no
grace period.

### Hold-and-Investigate Triggers

These conditions pause expansion but do not automatically roll back an
otherwise healthy backend:

- One email delivery failure while alert storage remains correct.
- One PDF/CSV export failure.
- Frontend visual defects that do not expose data or block core operations.
- CPU or memory above 90 percent for ten minutes without data loss.
- Detection between 15 and 60 seconds during an ordinary canary.
- Azure archival retries while hot MongoDB records remain intact.
- Backup failure before customer onboarding.

The owner has 30 minutes to resolve a hold condition. If it reaches an
automatic trigger, affects security/data integrity, or remains unexplained at
the end of that window, roll back or declare `HOLD` for the launch.

### Rollback Completion Criteria

A rollback is complete only when:

- The previous health endpoint is stable for five minutes.
- Authentication, tenant isolation, and RBAC smoke tests pass.
- Redis and MongoDB are healthy.
- No new run-specific DLQ growth occurs.
- The canary agent either reports healthy on the previous build or is safely
  stopped and its telemetry configuration is restored.
- The rollback action and final state are written to the launch artifact bundle.

### Backend

- Record the deployed Git commit and image IDs.
- Keep the previous known-good images available.
- Roll back API and worker images together.
- Do not roll back MongoDB data without a verified restore decision.

### Frontend

- Preserve the previous Vercel deployment.
- Promote the previous deployment if production browser checks fail.

### Windows Agent

- Stop or uninstall the canary service.
- Run native telemetry rollback.
- Verify prior audit policy and SACL state is restored.
- Do not expand rollout until the failure is understood.

### Azure

- Never delete evidence as part of an application rollback.
- Disable the failing archiver while preserving blobs and hot records.

---

## P1 Pilot Hardening

Complete before expanding beyond the controlled pilot:

- Make Azure archival idempotent when blob upload, metadata insertion, or hot
  deletion partially fails.
- Verify archive hashes after upload before deleting hot records.
- Add an active PECA signature-verification command instead of relying on a
  legacy-labeled helper.
- Schedule recurring signature and FBR plaintext audits.
- Remove obsolete Sysmon-era operational documents so deployment staff cannot
  follow conflicting instructions.
- Remove or reclassify broad FBR mappings that do not represent POS evidence.
- If a customer requires local JSONL integration, add an installer-managed
  writer identity with append-only permission to `pos_audit.log`, explicit
  rollback, and heartbeat writer-health reporting.
- Add external alerts for unhealthy workers, DLQ growth, backup failure, disk
  pressure, and certificate renewal failure.
- Perform an Azure archive recovery exercise.

## P2 Post-Pilot Improvements

These do not block the first controlled pilot:

- Authenticode code-signing certificate and publisher reputation.
- Optional measured `5156` permitted-connection telemetry.
- VirusTotal or another external threat-intelligence provider.
- HSM or managed-key storage for forensic signing.
- Per-tenant signing-key strategy if contractually required.
- Multi-node/high-availability API, Redis, and MongoDB architecture.
- Frontend bundle splitting and performance optimization.
- Automated backup restore drills.
- Broader POS vendor adapters.

---

## Final Launch Gate

The first customer endpoint may be onboarded only when all of the following are
true:

- P0 reliability patches pass automated regression tests.
- The rebuilt installer and manifest match.
- The native disposable Windows VM report is fully green.
- The 50-agent soak remains within the 60-second burst target.
- FBR plaintext audit reports zero changes required.
- PECA signature verification reports zero failures.
- Production TLS, CORS, CSRF, cookies, and WebSockets pass.
- Azure artifact, evidence, and backup storage are correctly separated.
- One database backup has been restored successfully.
- Production browser user journeys pass.
- A rollback target is recorded.
- Monitoring is active before the customer agent is installed.
- The complete private launch artifact bundle and `SHA256SUMS.txt` have been
  uploaded and verified.
- No automatic rollback trigger is active.
- Every hold condition is resolved or explicitly recorded as launch-blocking.

This gate provides a controlled pilot launch without requiring unrelated
post-pilot features to be completed first.
