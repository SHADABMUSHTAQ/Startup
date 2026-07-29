# WarSOC End-to-End Current-State and Priority Map

**Snapshot date:** 2026-07-28
**Purpose:** Freeze the current system truth before further implementation.  
**Scope:** Commercial flow, frontend, identity, RBAC, Windows agent, ingestion, SIEM, PECA, FBR, incidents, storage, Azure, reports, email, infrastructure, security and future phases.  
**Rule:** An implemented feature is not called proven unless a current test or production artifact supports it.

## 0. High-Priority Closure Update

The 2026-07-22 high-priority implementation pass completed the following without enabling unprovisioned cloud resources:

- Deployment defaults now point to agent 4.2.6, keep endpoint signatures in explicit observation mode, disable security-alert email, and disable manual log injection unless operations opts in.
- The public quote path now records requested scope for a custom contract/manual invoice and does not generate authoritative prices from browser or hardcoded formulas. Mongo lead persistence remains successful when the email queue is unavailable.
- Team invitations retain hashed, 24-hour, single-use activation tokens and now return a non-cacheable setup URL once to the authenticated admin, removing SMTP as an onboarding dependency.
- Archive writes support fixed FBR/PECA targets and duration-aware SIEM/general Azure targets; new ledger rows record the physical container and readback follows that ledger. All overrides fall back to the existing locked container until cloud operators explicitly configure separately locked targets.
- Backend verification closes with 346 passed, 3 skipped and zero application failures. All 11 PECA controls now pass the signed ingestion-to-worker-to-vault integration test. Frontend ESLint and production build remain the previous verified baseline; no frontend source was changed by this backend closure pass.

Still external: verify the live CDN object hash, deploy matching backend/frontend commits, provision and lock FBR/PECA and duration-specific SIEM/general Azure containers before setting routing overrides, and later move backend hosting before the DigitalOcean deadline. Legal content was not modified by this engineering pass.

## 1. Executive Truth

WarSOC is currently a Windows-focused SMB security and compliance platform with three core processing outcomes:

1. SIEM evidence and actionable incidents.
2. PECA-oriented forensic evidence for an 11-event Windows catalog.
3. FBR-oriented invoice evidence and configured POS/database file-integrity evidence.

The current endpoint core is operational. Agent 4.2.6 was exercised from a real Windows machine against the production API. Authentication, active health, SIEM detection, exact PECA Event 4688 retrieval, strict FBR JSONL evidence, native FBR database deletion evidence and endpoint signature verification passed. The observed signature counters were 7,191 verified and zero rejected.

That proof does not complete the broader hybrid-SIEM roadmap. Network relay intake, network-assisted PECA correlation, externally anchored daily roots, JIT support access and external exposure monitoring remain incomplete or unimplemented.

## 2. System Ownership Map

| Layer | Current owner | Responsibility |
|---|---|---|
| Public website and application | Vercel | Marketing pages, quote/contact forms, login and authenticated React UI. |
| API edge | DigitalOcean Nginx | TLS, security headers, request routing and public 80/443 exposure. |
| Application API | FastAPI `warsoc-api` | Authentication, tenant binding, validation, orchestration, reads and operator actions. |
| Event transport | Private Redis | Streams, sessions, WebSocket tickets, FIM correlation, mitigation state, caches and queues. |
| Processing | `unified-worker` | SIEM, FBR, PECA, email and stream-retention loops. |
| Hot operational storage | Private MongoDB | Seven-day evidence windows, incidents, users, tenants and ledgers. |
| Cold evidence storage | Private Azure Blob | Immutable evidence archive and hash companions. |
| Agent artifacts | Public Azure Blob | Versioned Windows installer and customer-verifiable manifest. |
| Email | Zoho SMTP | Invitations, quote/contact messages and other configured operational mail. Security-alert email is intentionally disabled by default. |
| Endpoint runtime | Windows/NSSM | Native Windows collection, POS JSONL collection, durable spool and signed HTTPS delivery. |

## 3. Commercial and Customer Onboarding Flow

### Current flow

1. Prospect selects endpoint count and requested FBR/PECA capabilities in the frontend.
2. Frontend submits `POST /api/v1/sales/request-quote`, or the homepage submits `POST /api/v1/sales/contact`.
3. Backend stores the lead in `sales_leads` before attempting email delivery.
4. WarSOC performs the meeting, contract and manual invoicing outside the platform.
5. A WarSOC operator provisions the tenant using `POST /api/v1/admin/provision` or the local operations console.
6. Provisioning creates the tenant, customer admin, endpoint limit, entitlements, retention metadata and cache/genesis state.
7. Customer admin logs in, invites team members and generates endpoint activation codes.

### Deliberate boundaries

- No Safepay or automated checkout is part of the operating flow.
- Public self-signup is present as a route but is configured to return HTTP 403.
- Customer plan changes through `/auth/update-plan` and `/auth/upgrade` return HTTP 403.
- No automatic agent installer link is emailed to analysts.
- Tenant admins control team invitations and agent activation.

### Verified commercial mismatch

The operating description says contracts are customized, but backend pricing and frontend quote logic still contain fixed endpoint, FBR, PECA and activation prices and legacy `plan_type` fields. This is not a payment bypass, because payment remains manual, but it is a customer-facing commercial source-of-truth mismatch that must be resolved before relying on displayed totals.

## 4. Authentication, Session and RBAC Flow

### Authentication

1. Browser posts credentials to `/api/v1/auth/login`.
2. Backend issues a secure HttpOnly session cookie and a CSRF double-submit token.
3. Frontend Zustand store hydrates identity through `/api/v1/auth/me`.
4. State-changing browser requests attach `X-CSRF-Token`.
5. Optional TOTP setup, verification and disable routes are available.
6. Password policy requires at least 16 characters with uppercase, lowercase, number and symbol, capped at 72 UTF-8 bytes for bcrypt compatibility.

### Roles

| Capability | Admin | Manager | Analyst | Auditor |
|---|---:|---:|---:|---:|
| Operational dashboard/incidents | Yes | Yes | Yes | No |
| Acknowledge, assign and close incidents | Yes | Yes | No | No |
| IP/CIDR mitigation | Yes | Yes | No | No |
| Generate activation/download agent | Yes | No | No | No |
| Manage team | Yes | No | No | No |
| Compliance catalog | Yes | Yes | Yes | Yes |
| Coverage | Yes | Yes | No | Yes |
| FBR/PECA evidence and exports | Yes | No | No | Yes |

### Team invitation

1. Admin posts role and email to `/api/v1/auth/invite`.
2. Backend creates a pending user and queues a 24-hour, single-use activation link.
3. Pending users cannot log in.
4. User opens `/set-password`, supplies a compliant password and atomically consumes the token.
5. Backend role enforcement remains authoritative regardless of frontend visibility.

### Current obligation

The email provider quota has been reported exhausted. Alert emails are intentionally disabled, but invitation, quote and contact delivery still depend on SMTP capacity. A real invitation click-through remains an operational acceptance gate.

## 5. Windows Agent Lifecycle

### Enrollment and download

1. Admin requests `/api/v1/agent/generate-activation`.
2. Backend issues a one-time `WARSOC-XXXXXXXX` code, normally valid for 24 hours.
3. Admin downloads through `/api/v1/agent/download`.
4. Backend returns HTTP 307 to `AGENT_CDN_URL`; FastAPI does not stream the installer.
5. Installer validates the activation before making the service operational.
6. Agent generates an Ed25519 key pair, registers the public key and receives agent credentials.
7. Activation material is removed after enrollment.

### Runtime

- NSSM runs `WarSOC_Agent` as an automatically restarting Windows service.
- The service continues when the website or browser is closed.
- Security and System channels are collected through language-independent XML.
- Sysmon is not used.
- Optional POS paths enable SACL-backed FBR file monitoring.
- `%ProgramData%\WarSOC\pos_audit.log` is strict BOM-free JSON Lines for invoice events.

### Durability and authenticity

- Event is written to the durable spool before the Windows watermark advances.
- Retry preserves `event_uid`.
- Spool hard boundary is 500 MiB, recovery boundary is 400 MiB and free-disk reserve is 2 GiB by default.
- New events pause under disk pressure; existing unacknowledged evidence is retained.
- New 4.2.6 keys use Windows DPAPI-protected software storage.
- Each event is signed with Ed25519 and verified against the enrolled agent key before Redis admission.

### Current artifact truth

- Source agent and installer version: 4.2.6.
- Exact-machine 4.2.6 production proof passed.
- Installer is not Authenticode signed; customer IT must keep Defender enabled and use approved SHA-256 allowlisting when required.
- Local `Output` contains installers and manifests from 4.2.0 through 4.2.6. These are ignored development artifacts, not all approved releases.

### Verified configuration drift

Local `.env.prod` still points `AGENT_CDN_URL` to `warsoc_installer-4.2.4.exe`, while source and the tested artifact are 4.2.6. Because `.env.prod` is intentionally untracked and DigitalOcean is edited manually, this does not prove the live server is wrong. It does prove that the local deployment source can silently roll the download redirect backward during a later deployment.

## 6. Ingestion and Queue Flow

### Agent telemetry

`POST /api/v1/ingest/pulse` performs:

1. Agent JWT validation.
2. Tenant and agent identity binding from authenticated credentials.
3. Request-size, event-count, rate and daily-byte quota checks.
4. Ed25519 signature verification when supplied.
5. Rejection of invalid signatures.
6. Stream admission/backpressure checks.
7. Append to `raw_logs_queue` and selected priority append to `siem_hot_queue`.

### Current limits

- Maximum 50 active agents per tenant.
- Maximum request body 5 MiB.
- Daily quota floor 1 GiB per tenant.
- Daily allowance 50 MiB per active agent.
- Hard daily tenant ceiling 3 GiB.
- Raw Redis admission boundary 500,000 entries.
- Redis uses `noeviction`; backpressure is preferred over silent evidence eviction.

### Consumer ownership

| Consumer | Group | Output |
|---|---|---|
| SIEM general | `siem_group` | `siem_cold_vault`, detections and incidents. |
| SIEM priority | `siem_hot_group` | Priority SIEM processing. |
| FBR | `fbr_group` | `fbr_pos_logs` and operational FBR incidents. |
| PECA | `eto_group` | `peca_forensic_logs`. |

`eto_group` is a legacy internal name for the active PECA consumer. It is not a second ETO product.

Workers acknowledge only after required persistence succeeds. Transient failures remain pending; poison events enter a DLQ before acknowledgement. Safe stream trimming considers required consumer progress.

## 7. SIEM Pipeline

### Evidence and incidents

1. Every accepted Windows event is normalized and may be stored in `siem_cold_vault`.
2. Normal activity is evidence, not automatically a threat.
3. Stateless and contextual rules evaluate trusted source-specific fields.
4. Actionable detections persist to `security_alerts`.
5. Incident projection groups compatible detections into `security_incidents` without deleting underlying evidence.
6. `security_incident_occurrences` prevents retry duplicates.
7. WebSocket publishes compact tenant-scoped incident updates; HTTP polling reconciles missed messages.

### Current detection boundary

- Windows, web, POS and future network rules are source-isolated.
- Event 4688 supplies process-creation context.
- Event 5157 is blocked-connection evidence; 5156 is permitted-connection evidence.
- Normal 4624, 4625, 4672 and 4688 events feed evidence/correlation instead of producing one alert each.
- Repeated matching detections group by tenant, minute and material context.
- Different actor, target, endpoint, process, outcome, rule or minute remains separate.

### Current limitations

- Five rules requiring unsupported telemetry are explicitly disabled.
- Full network-flow analytics are not claimed.
- Every enabled rule has not been re-proven natively on a clean 4.2.6 snapshot after the latest changes.
- MITRE/CWE enrichment is not yet the completed Phase 9 architecture.

## 8. PECA-Oriented Evidence Pipeline

### Current 11-event catalog

`4625`, `1102`, `4624`, `4688`, `4672`, `4720`, `4726`, `4732`, `4697`, `7045`, `1100`.

### Processing

1. PECA consumer verifies tenant entitlement.
2. Only catalog events are accepted into the PECA evidence path.
3. Sensitive payload fields are encrypted.
4. Canonical evidence is sealed with RSA-PSS/SHA-256.
5. Tenant plus `event_uid` provides idempotent persistence in `peca_forensic_logs`.
6. Evidence is visible to admin/auditor roles and can exist without a SIEM incident.

### Storage contract

- Mongo hot target: 7 days.
- Logical PECA vault policy: 365 days.
- Exact-machine Event 4688 was retrieved successfully from production.

### Current limitation

Endpoint evidence does not provide firewall, VPN, DNS, DHCP/NAT or perimeter-device correlation. The current catalog supports investigation workflows but is not a claim of blanket statutory PECA compliance.

## 9. FBR-Oriented Evidence Pipeline

### Invoice truth

- Strict JSONL or authenticated `/api/v1/fbr/pos/ingest`.
- Accepted IDs: `FBR-INV-MOD` and `FBR-INV-DEL`.
- Unknown fields/IDs and malformed records are rejected or locally quarantined.
- WarSOC does not infer invoice semantics from proprietary databases.

### File-integrity truth

1. Configured local POS/database paths receive delete and permission-change SACL auditing.
2. Event 4663 stores delete intent in Redis by tenant, agent and handle for 60 seconds.
3. Event 4660 consumes matching context and creates exactly one `FIM-DB-MOD` for approved database extensions.
4. Event 4670 can create direct permission-tamper evidence.
5. Ordinary writes and unmatched 4660 records do not create FBR tamper alerts.

### Confidentiality and storage

- Sensitive FBR payload fields use Fernet field encryption.
- Mongo hot target: 7 days.
- Logical FBR vault policy: 2,190 days.
- Exact-machine BOM-free invoice JSONL and native database deletion both passed.

## 10. Dashboard and Operator Workflow

| UI area | Backend contract | Meaning |
|---|---|---|
| Omni Agent Feed | `/logs/live?source=siem&aggregate=true` | Grouped hot endpoint evidence, not incidents. |
| Live Inspection | `/incidents` | Actionable mutable incident workflow. |
| Metrics | `/incidents/summary` | Server-derived open/severity/correlation counts. |
| Incident detail | `/incidents/{id}` | Context, rationale, evidence coverage, history and assignment. |
| Agent health | `/data/status` | Active, degraded or offline/not configured. |
| Compliance | `/compliance/packs`, `/coverage`, `/evidence/{pack}` | Entitlements, sensor coverage and hot/cold evidence. |
| Team | `/auth/team`, `/auth/invite` | Admin-only membership workflow. |
| Agent activation | `/agent/generate-activation`, `/agent/download` | Admin-only deployment workflow. |

Operational incidents support assignment, acknowledgement, false-positive disposition, reopen and close. Close/false-positive actions require notes. IP mitigation distributes tenant policy to signed agent heartbeats; it is not a cloud firewall.

The frontend API paths for auth, profile, team, incidents, live logs, compliance, agent activation, uploads and mitigation match mounted backend routes. The backend repository was clean before this mapping document was added. Frontend file inspection succeeded, but its Git revision and working-tree cleanliness remain unverified because Windows blocked the sandbox ownership check.

## 11. Storage, Retention and Retrieval

### Mongo hot tier

| Data | Hot policy | Logical cold policy |
|---|---:|---:|
| General/SIEM evidence and alerts | 7 days | Contract-driven, normally 90 days. |
| PECA evidence | 7 days | 365 days. |
| FBR evidence | 7 days | 2,190 days. |
| Mutable incidents | Active-tenant operational record | Not immutable evidence. |

Mongo TTL is not allowed to delete archive-managed evidence. The archiver is the deletion authority.

### Archive transaction

1. Select eligible tenant records.
2. Serialize exact JSON bytes and calculate SHA-256.
3. Upload data and `.sha256` companion to private Azure storage.
4. Verify Azure immutability properties.
5. Write `storage_archives` ledger.
6. Delete only the exact Mongo IDs after every prior step succeeds.

Any failure retains Mongo data and causes visible hot-storage growth.

### Retrieval

The archive reader uses the tenant-scoped ledger, downloads the blob, verifies SHA-256, validates tenant identity, filters and deduplicates records, and exposes safe hot/cold provenance. Compliance reads, search, CSV and PDF can use cold data; the live dashboard intentionally reads hot Mongo only.

### Verified retention deployment gap

The deployed configuration still writes all evidence into one Azure container locked for 2,190 days. This prevents early deletion and satisfies the FBR floor, but physically over-retains PECA and shorter SIEM contracts. The code now routes contract-driven evidence to exact-duration keys such as `SIEM_90` and `GENERAL_180`, with fixed FBR/PECA targets and safe class/global fallbacks. Physical correction therefore requires operators to create and lock the matching Azure containers before setting those environment overrides. Existing six-year-locked blobs cannot be shortened or moved out of their current immutability obligation.

### Daily roots

`compliance-cron` computes daily root chains in MongoDB. The master-plan requirement for an independent daily root anchored outside MongoDB is not yet complete.

## 12. Reports and Email

### Reports

- CSV merges authorized hot and hash-verified cold data, defaulting to 5,000 and capped at 50,000 rows.
- PDF is a bounded human-readable summary over the newest matching records and previews 50 evidence rows.
- PDF is not digitally signed; underlying PECA evidence carries the forensic seal.

### Email

- Sales/contact and team-invite messages remain enabled when SMTP capacity exists.
- Alert email is disabled by default through `ENABLE_SECURITY_ALERT_EMAILS=false` behavior.
- Evidence and incidents persist even if SMTP fails.
- Queue depth, retries and DLQ state are the operational truth for delivery.

## 13. Infrastructure and Failure Boundaries

### Active production topology

- DigitalOcean: Nginx, API, worker, MongoDB, Redis, compliance cron and archiver.
- Vercel: frontend.
- Azure public account/container: agent artifact.
- Azure private account/container: immutable evidence.
- Zoho: SMTP.

MongoDB, Redis and API port 8000 are private. Only Nginx 80/443 is public. Syslog and legacy threat-hunter services are profile-gated and outside the Windows pilot.

### Resource controls

- API: 1 GiB.
- Unified worker: 1.28 GiB.
- MongoDB: 2 GiB.
- Redis: 1 GiB container, 640 MiB dataset with no eviction.
- Archiver: 768 MiB.
- Supporting services: bounded separately.
- Docker logs: 10 MiB times five files per service.

### Failure contract

| Failure | Required behavior |
|---|---|
| API unreachable | Agent keeps bounded spool and retries. |
| Redis unavailable/full | API fails admission; agent retries. |
| Mongo unavailable | Worker leaves event pending/retryable. |
| Poison event | DLQ before acknowledgement. |
| Azure/immutability failure | Mongo copy is retained. |
| Archive hash mismatch | Cold records are rejected. |
| WebSocket disconnect | HTTP polling reconciles. |
| SMTP failure | Evidence persists; notification failure is visible. |
| Channel/audit failure | Agent reports Degraded. |

## 14. Security Control Map

### Implemented

- HTTPS/WSS, HSTS, clickjacking and MIME protections.
- Private MongoDB/Redis/API ports.
- Secure HttpOnly session cookie and CSRF validation.
- Tenant identity derived from authentication, not payload fields.
- Route-level RBAC and tenant-scoped queries.
- Short-lived single-use activation and invitation tokens.
- Ed25519 agent identity and event signatures.
- DPAPI-protected software private key.
- RSA-PSS PECA evidence seal and Fernet field encryption.
- Bounded request, stream, spool, quota and export limits.
- WebSocket ticket bound to session/tenant.
- Immutable archive verification before deletion.
- Docker read-only filesystems, tmpfs and log rotation.

### Partial or missing

- `AGENT_EVENT_SIGNATURE_MODE` is absent from local `.env.prod`; Compose defaults to `observe`.
- Required signing cannot be enabled until every active agent is upgraded and unsigned traffic remains zero for the observation window.
- Installer has no trusted publisher signature.
- DPAPI software protection is lower assurance than TPM/CNG and cannot defend against full local SYSTEM compromise.
- No endpoint/relay sequence chain, previous-batch hash or complete replay-state gate from the master plan.
- Daily roots are not independently anchored outside MongoDB.
- No JIT tenant-approved support-access system.
- Production `/api/v1/logs/inject` allows admin/manager simulation writes into the general `logs` collection and is not explicitly disabled by production environment.
- The current production fallback still uses one six-year Azure lock and over-retains shorter data classes until duration-specific containers are provisioned and enabled.

## 15. Product Boundary and Unsupported Claims

WarSOC currently supports Windows endpoint monitoring. It does not currently provide:

- Linux endpoint collection.
- Production network-device syslog or authenticated relay intake.
- Firewall/VPN/DNS/DHCP/NAT hybrid correlation.
- EDR prevention, antivirus replacement or host isolation.
- Automatic proprietary POS database understanding.
- Guaranteed invoice evidence without JSONL/API integration.
- FBR file-integrity coverage without configured local paths.
- Live third-party threat-intelligence dependence.
- Authenticode-signed installer.
- Blanket FBR or PECA legal compliance certification.
- Unlimited agents, ingestion, search or retention.

## 16. Documentation and Claim Drift

The authoritative current-state document is dated 2026-07-18 and still describes 4.2.4 production, a 4.2.5 candidate and pre-deployment incident contracts. Current source and exact-machine proof are 4.2.6.

The frontend legal page currently states that data moves from DigitalOcean to Pakistan-based Nexus Cloud production, describes an EDR split and says logs archive for six years. That copy does not match the current architecture or the planned Azure backend migration and overstates uniform six-year retention. This map records the mismatch; it does not modify legal content.

## 17. Master Phase Status

| Phase | Status | Current truth |
|---|---|---|
| 0. Scope/baseline | Partial | Strong documentation exists, but release/config/claim drift prevents a frozen baseline. |
| 1. Cryptographic source identity | Partial | Endpoint Ed25519/DPAPI works; required mode, sequence/key lifecycle and relay identity remain. |
| 2. Canonical envelope/verification | Partial | Signature verification before Redis works; full chain/replay/export/archive verification contract remains. |
| 3. Customer network relay | Partial and disabled | Backend activation, signed admission, parsers, bounded spool/outbox and metrics exist behind `NETWORK_RELAY_ENABLED=false`; no installable relay service or real-device proof exists. |
| 4. PECA hybrid correlation | Narrow candidate and disabled | Endpoint catalog works. A limited relay-assisted correlation subset exists but is dormant; full network identity reconstruction and real-device proof remain. |
| 5. FBR evidence integrity | Operational for current scope | Strict invoice and native FIM paths are implemented and exact-machine tested. |
| 6. External daily anchoring | Partial | Mongo daily roots exist; independent Azure anchor does not. |
| 7. Custody/JIT/break glass | Mostly unimplemented | Basic audit/RBAC exists; JIT support architecture does not. |
| 8. Retention/archive/DR | Partial but operational | Archive/retrieval, ledger-aware multi-container readback, duration-aware routing and a disposable restore drill exist; Azure bucket provisioning and final cutover restore remain. |
| 9. SIEM detection/enrichment | Partial | Every enabled regex rule has an executable contract and source isolation passes. Complete clean-VM native proof and broader MITRE/CWE enrichment remain. |
| 10. Exposure monitoring | Not implemented | Deliberately last and isolated. |
| 11. Integrated acceptance | Partial | Backend closure is 346 passed and 3 explicit skips; exact-machine and prior soak proofs exist. Current paired production browser, final Azure segmentation and cutover restore artifacts remain. |

## 18. Prioritized Gap Register

### P0: Freeze release and prevent operational regression

1. Establish one release identity: backend commit, frontend commit, agent 4.2.6, manifest hash and deployed CDN URL.
2. Correct deployment-source drift so a future deployment cannot redirect customers to 4.2.4.
3. Update the authoritative current-state document from 4.2.4/4.2.5 candidate language to the deployed 4.2.6 truth.
4. Resolve customer-facing pricing/custom-package and legal/infrastructure claim mismatches before they are relied on in a contract or demonstration.
5. Preserve the exact-machine proof and create a clean tenant for demonstrations rather than using contaminated engineering history.

### P0: Maintain service continuity

1. DigitalOcean student hosting is expected to end on 2026-08-01. Backend continuity therefore has a fixed deadline.
2. Execute the already documented Azure backend migration separately from product feature changes.
3. Take and verify an independent encrypted Mongo backup immediately before cutover.
4. Keep the existing DigitalOcean deployment available for rollback until Azure acceptance passes.

### P1: Close current security enforcement

1. Upgrade every active endpoint to 4.2.6.
2. Measure verified, unsigned and rejected signature metrics over the agreed observation window.
3. Move from `observe` to `required` only when active unsigned agents reach zero.
4. Disable or production-gate `/logs/inject`.
5. Keep Defender enabled and use hash allowlisting until Authenticode signing is available.

### P1: Close current customer workflow acceptance

1. Restore SMTP capacity for invitations, quote and contact mail while keeping alert email disabled.
2. Complete one real invitation activation and role-specific login.
3. Exercise admin, manager, analyst and auditor permissions from the browser.
4. Exercise agent activation/download, incident assignment/acknowledgement/closure, mitigation, compliance evidence and CSV/PDF from a clean tenant.
5. Confirm hot, cold and archive-reader-error UI states.

### P1: Close evidence and lifecycle proof

1. Re-run all 11 PECA native controls on a clean snapshot-based Windows VM using agent 4.2.6.
2. Re-run FBR invoice modification/deletion, correlated database deletion, permission change and normal-write negative control.
3. Repeat the 50-agent soak against the final post-migration backend.
4. Run final Mongo backup restore and Azure archive retrieval proof after infrastructure cutover.
5. Measure 24-hour spool, Redis, Mongo, worker, Nginx buffering and disk behavior.

### P2: Correct retention architecture

1. Define contract-supported SIEM retention classes.
2. Provision and lock FBR/PECA plus duration-specific SIEM/general containers, then enable the already implemented environment routing without changing existing locked blobs.
3. Do not attempt to shorten the existing locked six-year container.
4. Add independently anchored daily evidence roots.

### P3: Expand only after current gates close

1. Complete the disabled customer-side authenticated network relay candidate: Windows service, listener, protected keys, installer lifecycle and real-device proof.
2. Add firewall/VPN/DNS/DHCP/NAT PECA correlations.
3. Add JIT support and break-glass controls.
4. Finish MITRE/CWE enrichment.
5. Add isolated external exposure monitoring last.

## 19. Execution Order

No implementation should start outside this order:

1. **Release truth freeze.** Resolve version, environment, documentation, pricing and claim drift.
2. **Infrastructure continuity.** Complete backend migration and rollback/backup proof before the hosting deadline.
3. **Current security closure.** Upgrade endpoints, observe signing metrics, require signatures and production-gate simulation paths.
4. **Current product acceptance.** Browser roles, invitations, reports, archive provenance and clean-tenant onboarding.
5. **Current evidence acceptance.** All PECA controls, all FBR positive/negative cases and 50-agent post-migration soak.
6. **Retention correction.** Physical storage classes and external daily anchors.
7. **Hybrid expansion.** Network relay and cross-source PECA correlations.
8. **Advanced operations.** JIT support, enrichment and isolated exposure monitoring.

Any failure in tenant isolation, evidence durability, signature enforcement, archive integrity, bounded resource behavior or rollback stops progression to the next step.

## 20. Immediate Decision

The next engineering task is not a new detection rule or network feature. It is the P0 release-truth freeze. Until the deployed backend commit, frontend commit, agent version, manifest, CDN URL, environment values, documentation and customer-facing claims agree, additional implementation increases uncertainty rather than product capability.
