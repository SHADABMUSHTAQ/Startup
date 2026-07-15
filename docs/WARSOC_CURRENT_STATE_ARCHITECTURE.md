# WarSOC Current-State Architecture and Operational Contract

**Document status:** Authoritative as-built map  
**Snapshot date:** 2026-07-14  
**Scope:** Windows agent, ingestion, Redis, SIEM, FBR, PECA, MongoDB hot storage, Azure cold storage, retrieval, reports, dashboard, RBAC, email, deployment, and launch proof.

This document describes what the current source code does. It is not a sales claim and it does not treat an implemented path as production-proven unless verification evidence exists.

## 1. Current Verdict

WarSOC currently has a coherent end-to-end architecture for a maximum of 50 Windows agents per tenant:

1. A tenant admin generates a one-time activation code.
2. The Windows installer validates that code, configures native Windows auditing, and installs the agent as an NSSM service.
3. The agent collects native Windows Security and System events, maintains a durable local spool, and sends authenticated telemetry over HTTPS.
4. Redis Streams buffer each accepted event for independent SIEM, FBR, and PECA consumers.
5. SIEM creates operational alerts and a short-lived operational evidence feed governed by the seven-day hot policy.
6. PECA creates signed and encrypted forensic evidence for the entitled 11-control catalog.
7. FBR creates encrypted invoice evidence and database-file tamper evidence for the entitled six-control catalog.
8. MongoDB holds seven days of operational SIEM, PECA, and FBR data.
9. The storage archiver uploads expired hot records to immutable Azure Blob storage, verifies integrity and immutability, writes a Mongo archive ledger, and only then removes the Mongo copies.
10. Compliance views, search, CSV exports, and PDF reports can merge Mongo hot records with verified Azure archive records.
11. The dashboard intentionally separates normal agent telemetry from actual security alerts and groups repeated detections into operator incidents.

The architecture is implemented. The current local release candidate adds bounded agent spooling, strict telemetry-family routing, fresh-heartbeat health, Redis ingest admission control, incident-wide workflow updates, and one-time team activation links. Public production preflight, live agent/PECA processing, and the archive-before-delete transaction were verified against the previously deployed release. Full acceptance of this release candidate remains conditional on the outstanding proof obligations in Section 22; this document does not convert unexecuted native-VM, soak, production-email, retrieval, or restore tests into production claims.

## 2. Product Boundary

### 2.1 What WarSOC currently provides

- Native Windows endpoint telemetry without Sysmon.
- Windows Security and System event collection.
- Stateless signatures and contextual/stateful SIEM detection.
- Live alert delivery through authenticated WebSockets.
- Alert acknowledgement, closure, notes, and incident occurrence tracking.
- IP/CIDR mitigation with active-agent and self-lockout guards.
- FBR invoice evidence through strict JSONL or authenticated API ingestion.
- FBR database file-integrity monitoring when POS/database paths are configured.
- PECA forensic evidence for 11 native Windows controls.
- Tenant isolation and role-based access.
- Seven-day Mongo hot storage for operational SIEM, FBR, and PECA data.
- Immutable Azure archive storage with hashes and an archive ledger.
- Hot-plus-cold compliance retrieval and CSV/PDF export.
- Email queue processing for configured operational messages and high/critical alert notifications.
- Manual B2B sales, manual payment/invoicing, and administrative tenant provisioning.

### 2.2 What WarSOC does not currently provide

- It does not automatically understand proprietary POS database schemas.
- It does not create invoice-level FBR evidence unless the POS vendor writes the required JSONL records or calls the authenticated POS API.
- It does not provide FBR file-integrity monitoring when no POS/database directory is configured.
- It does not replace endpoint antivirus or EDR.
- It does not require customers to disable Windows Defender.
- It does not use Safepay or self-service payment for the current commercial flow.
- It does not use Sysmon.
- It does not currently ingest Linux or network-device syslog. The receiver remains a disabled future profile and is outside the Windows SMB pilot contract.
- It does not guarantee that every normal Windows event becomes an alert. Normal events are evidence and correlation inputs; only dangerous or contextually suspicious activity alerts.
- It does not make a PDF cryptographically signed. The PECA source records contain the forensic signatures; the PDF is a human-readable summary.
- It does not automatically email an agent installer link to analysts. Agent activation and download are tenant-admin actions.

## 3. End-to-End Data Flow

```mermaid
flowchart TD
    A["Tenant admin generates one-time activation code"] --> B["Windows installer validates activation"]
    B --> C["Native audit policy and optional POS SACL configured"]
    C --> D["NSSM starts WarSOC agent service"]
    D --> E["Security and System XML events collected"]
    D --> F["Strict POS JSONL records collected when configured"]
    E --> G["Durable local spool"]
    F --> G
    G --> H["HTTPS agent telemetry or authenticated POS API"]
    H --> I["API authentication, validation, quotas and tenant binding"]
    I --> J["Redis raw_logs_queue"]
    I --> K["Redis siem_hot_queue for selected SIEM events"]
    J --> L["SIEM consumer group"]
    K --> L
    J --> M["FBR consumer group"]
    J --> N["PECA consumer group"]
    L --> O["siem_cold_vault"]
    L --> P["security_alerts"]
    M --> Q["fbr_pos_logs"]
    N --> R["peca_forensic_logs"]
    P --> S["WebSocket and email notification"]
    O --> T["Dashboard agent feed"]
    P --> U["Dashboard threat feed"]
    Q --> V["Compliance evidence"]
    R --> V
    O --> W["Daily storage archiver"]
    P --> W
    Q --> W
    R --> W
    W --> X["Immutable Azure Blob plus SHA-256"]
    W --> Y["storage_archives ledger"]
    X --> Z["Verified archive reader"]
    Y --> Z
    Z --> V
    Z --> AA["Search, CSV and PDF"]
```

## 4. Tenant and Commercial Flow

1. A prospect selects the desired endpoint count and compliance packs on the website.
2. The prospect submits a quote request to `POST /api/v1/sales/request-quote`.
3. WarSOC contacts the prospect, agrees the scope, and issues a manual invoice outside the product.
4. An authorized WarSOC operator provisions the tenant through the protected admin provisioning API or the local operations console.
5. Provisioning creates the tenant, admin account, endpoint limit, compliance entitlements, retention value, and required cache/genesis state.
6. Credentials are transferred to the customer through the agreed secure onboarding channel.
7. Public self-service signup is configured to fail closed for the launch model.

There are no fixed product-tier names required by the operating flow. The tenant contract is defined by its endpoint limit, selected compliance packs, and configured retention.

## 5. Identity, Session, and RBAC Flow

### 5.1 Browser authentication

- Login endpoint: `POST /api/v1/auth/login`.
- Session identity is hydrated from `GET /api/v1/auth/me`.
- The browser uses secure cookie authentication and CSRF protection for state-changing requests.
- Logout invalidates the session.
- Frontend authentication state is centralized in the Zustand auth store.

### 5.2 Role matrix

| Capability | Admin | Manager | Analyst | Auditor |
|---|---:|---:|---:|---:|
| Operational dashboard | Yes | Yes | Yes | No |
| Read operational alerts | Yes | Yes | Yes | No |
| Acknowledge/close alerts | Yes | Yes | No | No |
| Mitigate IP/CIDR | Yes | Yes | No | No |
| Generate activation code | Yes | No | No | No |
| Download agent | Yes | No | No | No |
| Manage team | Yes | No | No | No |
| Read catalog metadata | Yes | Yes | Yes | Yes |
| Read sensor coverage | Yes | Yes | No | Yes |
| View FBR/PECA evidence | Yes | No | No | Yes |
| Export compliance evidence | Yes | No | No | Yes |

The frontend exposes the Compliance workspace to admin and auditor roles. The backend permits every authenticated role to read non-evidence catalog metadata, permits admin/manager/auditor to read coverage, and restricts evidence/export to admin/auditor. The backend enforces the sensitive role checks; hiding a frontend button is not treated as authorization.

### 5.3 Team management

- Create or resend a pending team invitation: `POST /api/v1/auth/invite`, admin only.
- Activate an invitation and choose a password: `POST /api/v1/auth/activate-invite`, public one-time-token endpoint.
- List team: `GET /api/v1/auth/team`, admin only.
- Remove team member: `DELETE /api/v1/auth/team/{user_id}`, admin only.
- Roles are assigned by the tenant admin within the backend's allowed-role policy.
- The invite email contains a 24-hour single-use HTTPS activation link. It never contains a temporary password.
- Invited users remain `pending` and cannot log in until the token is atomically consumed and a policy-compliant password is stored.
- Analysts do not receive agent enrollment authority merely because they can investigate alerts.
- New and changed passwords must contain at least 16 characters, an uppercase letter, a lowercase letter, a number, and a symbol; bcrypt-compatible input is capped at 72 UTF-8 bytes.

## 6. Agent Activation and Installation

### 6.1 Activation code

- Endpoint: `POST /api/v1/agent/generate-activation`.
- Caller: authenticated tenant admin.
- Format: `WARSOC-XXXXXXXX`.
- Default validity: 86,400 seconds (24 hours).
- The backend checks tenant status, contract state, and the maximum-agent seat count.
- The code is one-time enrollment material, not a permanent agent token.
- Installer validation endpoint: `POST /api/v1/agent/validate-activation`.
- Agent registration endpoint: `POST /api/v1/agent/register`.
- Successful registration binds the generated Ed25519 public key, tenant, and agent identity and returns agent credentials.
- The activation secret is scrubbed after enrollment.

### 6.2 Installer sequence

1. The admin selects Download Agent in the dashboard.
2. The frontend requests `GET /api/v1/agent/download`.
3. The backend returns a redirect to `AGENT_CDN_URL`.
4. Azure public artifact storage serves the currently approved versioned installer. The local release candidate is `warsoc_installer-4.2.2.exe`; Azure must not be switched until its hash is approved.
5. The installer asks for the activation code, confirms `https://api.warsoc.tech`, and optionally accepts local POS directories.
6. The installer validates the activation code before making the installation operational.
7. The native telemetry script configures auditing and optional POS SACLs.
8. NSSM installs and starts `WarSOC_Agent` with automatic restart and output rotation.

Random text must not successfully enroll an agent. An installer may copy files before validation failure, but it must not register a functioning agent without a valid, unexpired, unused tenant activation code.

### 6.3 Unsigned pilot artifact

The current installer is unsigned and may be flagged by Windows Defender or SmartScreen. The supported pilot procedure is:

1. Keep Defender enabled.
2. Calculate and distribute the exact SHA-256 manifest over a trusted onboarding channel.
3. Have the customer's IT administrator verify the downloaded file hash.
4. Apply an organization-approved hash allow rule through Defender, WDAC, or Intune where required.
5. Rebuild and redistribute the manifest whenever any packaged binary or script changes.

A code-signing certificate remains the correct long-term solution.

## 7. Native Windows Telemetry

### 7.1 Data sources

- Windows Security channel.
- Windows System channel, including Event 7045.
- Language-independent XML fields rather than rendered localized message text.
- Optional strict POS JSONL file at `%ProgramData%\WarSOC\pos_audit.log`.

### 7.2 Audit policy configured by the installer

- Logon: success and failure.
- Process Creation: success, with command-line inclusion for Event 4688.
- File System: success and failure.
- Registry: success and failure.
- Other Object Access: success and failure.
- Filtering Platform Connection: failure events for blocked connections.
- User Account Management: success and failure.
- Security Group Management: success and failure.
- Special Logon: success.
- Security System Extension: success and failure.
- Audit Policy Change: success and failure.

The installer stores the pre-existing audit/SACL state and removes only WarSOC-owned changes during uninstall.

### 7.3 POS directories

- POS directories are optional for general SIEM and PECA monitoring.
- They are required for native FBR file-integrity monitoring.
- Paths must be existing local absolute directories; UNC/network paths are rejected.
- WarSOC adds inherited SACL auditing for delete, child-delete, and permission-change actions.
- Supplied-path configuration failure aborts installation rather than silently claiming FBR coverage.

### 7.4 Agent health

Signed heartbeat data reports:

- Security channel state.
- System channel state.
- Audit policy state.
- Telemetry version.
- POS SACL path count.
- POS audit-log state.
- Last-seen and sensor state.
- Local spool usage, hard limit, free-disk reserve, backpressure state, and limit-hit count.

The backend stores the state on the agent record and exposes it through `GET /api/v1/data/status`.

Dashboard health means:

- `Active`: enrolled agent is reporting and required telemetry is healthy.
- `Degraded`: the agent is reporting but a channel/audit requirement is incomplete or local spool backpressure is active. An unconfigured optional POS feed is reported separately and does not invent FBR coverage.
- `Not Configured` or offline: no healthy enrolled reporting agent is available for the requested coverage.

## 8. Durable Agent Delivery

1. Windows events are normalized into the agent's local queue.
2. The event is durably appended to disk before its Windows watermark advances.
3. If durable spool writing fails, the watermark does not advance; the source event is not treated as delivered.
4. The agent sends batches to the HTTPS ingestion endpoint.
5. Transient failures leave records in the local spool for retry.
6. Malformed POS JSONL records are quarantined locally and are not guessed, relabelled, or sent as valid evidence.
7. `event_uid` is preserved across retries for backend idempotency.
8. The spool has a 500 MiB hard boundary, a 400 MiB recovery boundary, and a 2 GiB free-disk reserve by default.
9. Reaching either disk boundary pauses new durable collection, leaves existing unacknowledged records intact, and reports the endpoint as Degraded.

This is at-least-once delivery with event-level duplicate suppression, not fire-and-forget delivery.

## 9. API Ingestion Contract

### 9.1 Agent telemetry

- Endpoint: `POST /api/v1/ingest/pulse`.
- Requires valid agent authentication.
- Tenant and agent identity are taken from the authenticated token, not trusted from client payload fields.
- Enforces request-size, event-count, rate, and tenant daily-ingest controls.
- Rejects new batches with HTTP 503 when `raw_logs_queue` reaches the configured admission boundary; the agent retains and retries them.
- Rejects banned sources according to the active mitigation state.
- Accepted events enter Redis Streams.

### 9.2 Authenticated POS evidence

- Endpoint: `POST /api/v1/fbr/pos/ingest`.
- Requires agent authentication.
- Maximum request body: 5 MB.
- Maximum event count: 500.
- Unknown fields are rejected.
- Accepted IDs: `FBR-INV-DEL` and `FBR-INV-MOD` only.
- Required contract fields include event ID, event UID, invoice ID, timezone-aware timestamp, actor, and source system.
- API clients cannot submit `FIM-DB-MOD`; only validated native Windows telemetry can generate it.

## 10. Redis Transport and Failure Semantics

### 10.1 Streams

| Stream | Purpose |
|---|---|
| `raw_logs_queue` | Durable fan-out source for SIEM, FBR, and PECA consumers. |
| `siem_hot_queue` | Priority path for selected SIEM-interest events. |

### 10.2 Consumer groups

| Consumer | Redis group | Source stream |
|---|---|---|
| SIEM general | `siem_group` | `raw_logs_queue` |
| SIEM priority | `siem_hot_group` | `siem_hot_queue` |
| FBR | `fbr_group` | `raw_logs_queue` |
| PECA | `eto_group` | `raw_logs_queue` |

`eto_group` is a legacy internal group name. It currently owns PECA consumption and must not be renamed casually because stream retention requires it.

### 10.3 Acknowledgement rules

- Each consumer group receives its own copy of a stream entry.
- A worker acknowledges only after its required persistence/action succeeds.
- Transient Mongo or Redis failures leave messages pending for reclaim/retry.
- Repeated poison messages are copied to a DLQ before acknowledgement.
- SIEM DLQ: `raw_logs_queue_dlq`.
- FBR/PECA DLQ: `warsoc:dlq:{tenant_id}`.
- Stream trimming runs only when all required consumer groups exist and their pending state permits safe progress.
- The trim boundary considers only the active required groups: `siem_group`, `fbr_group`, and `eto_group`. Historical/profile-gated groups such as `threat_hunters` cannot pin the active pipeline.
- The raw stream is never blindly trimmed to enforce memory. `RAW_STREAM_MAX_ENTRIES` applies admission backpressure while acknowledged-entry retention performs safe trimming.
- Metrics expose raw depth, cumulative safe trims, and the stream-retention worker heartbeat so retention can be proven rather than inferred.
- Production Redis uses a 640 MB `noeviction` dataset ceiling inside a 1 GB container, leaving allocator/AOF headroom while preserving fail-closed admission behavior.

### 10.4 Unified worker

The production unified worker supervises SIEM, FBR, PECA, email, and stream-retention loops concurrently. A crashed loop is restarted after a delay without terminating the other loops.

## 11. SIEM Detection Architecture

### 11.1 Evidence versus alerts

This distinction is intentional:

- `siem_cold_vault` stores normalized native events for investigation and correlation.
- `siem_cold_vault` indexes `(tenant_id,event_uid)` for idempotent writes and `(tenant_id,timestamp)` for newest-first tenant dashboard reads.
- `security_alerts` stores detections that require action.
- Normal Events 4624, 4625, 4672, and 4688 do not automatically create one alert per event.
- They feed stateful correlation and signature logic.
- Inherently dangerous events, including audit-log clearing, audit shutdown, blocked connections, dangerous service installation, and selected account changes, may alert directly.

This prevents a normal Windows endpoint from producing thousands of meaningless alerts.

### 11.2 Native event map

The current engine understands these core native IDs and custom FBR IDs:

`1100`, `1102`, `4616`, `4624`, `4625`, `4648`, `4657`, `4660`, `4663`, `4670`, `4672`, `4688`, `4697`, `4698`, `4719`, `4720`, `4726`, `4732`, `4768`, `4769`, `4776`, `4798`, `5140`, `5156`, `5157`, `7045`, `FBR-INV-DEL`, `FBR-INV-MOD`, and `FIM-DB-MOD`.

Event 5157 is treated as a blocked connection. Event 5156, when supplied by a reviewed source, is permitted-connection evidence and must never be mislabelled as a block. The default Windows SMB audit policy collects Filtering Platform failures (5157), not every permitted connection, to prevent a high-volume 5156 flood.

### 11.3 Stateless/signature coverage

Current rule families include:

- SQL injection.
- Cross-site scripting.
- Command injection.
- Path traversal.
- XXE.
- Web-shell patterns.
- PowerShell obfuscation.
- Privilege escalation.
- Lateral movement.
- Log evasion.
- Reverse shell behavior.
- Reconnaissance.
- Persistence.
- Data exfiltration and staging.
- Brute-force patterns.
- Malware execution.
- Ransomware shadow-copy deletion.
- Credential dumping.
- Defender evasion.
- LOLBin download behavior.
- Firewall blocking.

Web rules require structured HTTP log-file context. Windows keyword/EDR rules require native Security/System XML context, so ordinary Windows text cannot enter Web-WAF classification. Process command-line rules use normalized Event 4688 `process_create` input.

### 11.4 Stateful/contextual coverage

Current executable stateful categories include:

- Identity/authentication correlation: phishing chain, high-velocity brute force, low-and-slow brute force, five-user password spraying, impossible travel when trusted coordinates exist, concurrent sessions, after-hours login, account storm, privilege spike, dormant-account activation, ghost-admin behavior, SMB lateral movement, share enumeration, and registry persistence.
- File/ransomware correlation: six file-system/ransomware behavior families.
- Network/lateral correlation definitions consume structured flow fields when such telemetry is supplied. The Windows SMB pilot directly supplies blocked-connection Event 5157 plus SMB/authentication events; it does not claim full flow analytics without a reviewed flow source.
- Web-application correlation: six contextual web behavior families.

Contextual detectors reduce false positives by requiring sequences, thresholds, distinct-user counts, time windows, or event-type context. Five catalog entries are explicitly disabled for the Windows pilot because their required telemetry is not collected: new-location baseline, byte-counted exfiltration, interval-based C2 beaconing, connection duration, and rare-port baseline. They are not production capability claims.

Linux/syslog rule definitions are retained only as future design inventory. They have no enabled production intake profile and are not part of current detection coverage.

### 11.5 SIEM persistence and notification

- Normalized evidence: `siem_cold_vault`.
- Actionable detections: `security_alerts`.
- Stable alert identity: `alert_uid` within a tenant.
- Duplicate occurrences roll into the same alert/incident where the rule identity matches.
- Live notifications are published through Redis and delivered through authenticated WebSockets.
- High/critical alerts can enqueue email notifications when SMTP and tenant notification configuration are active.

## 12. PECA Pipeline

### 12.1 Entitlement and storage

- Pack ID: `peca_forensic`.
- Collection: `peca_forensic_logs`.
- Hot Mongo window: 7 days.
- Azure vault period: 365 days.
- Only entitled tenants receive PECA forensic records.

### 12.2 Current 11-control catalog

| Control | Event | Purpose |
|---|---:|---|
| PECA-101 | 4625 | Failed logon evidence. |
| PECA-102 | 1102 | Audit log cleared. |
| PECA-103 | 4624 | Successful logon evidence. |
| PECA-104 | 4688 | Process creation evidence and detection input. |
| PECA-105 | 4672 | Special privileges assigned. |
| PECA-106 | 4720 | Account created. |
| PECA-107 | 4726 | Account deleted. |
| PECA-108 | 4732 | Member added to privileged/local group. |
| PECA-109 | 4697 | Service installed through Security auditing. |
| PECA-110 | 7045 | Service installed through the System channel. |
| PECA-111 | 1100 | Windows Event Log service shut down. |

### 12.3 Evidence properties

- Canonical event representation.
- Tenant and agent identity.
- Stable event UID/idempotency.
- Sensitive field encryption.
- Forensic hash/seal.
- RSA-PSS signature using a key of at least 2048 bits.
- Duplicate isolation through tenant-plus-event UID uniqueness.

PECA evidence can exist without a corresponding actionable SIEM alert. For example, a normal 4624 login is useful forensic evidence but is not automatically a threat.

## 13. FBR Pipeline

### 13.1 Entitlement and storage

- Pack ID: `fbr_pos`.
- Collection: `fbr_pos_logs`.
- Hot Mongo window: 7 days.
- Azure vault period: 2,190 days (six years).
- Only entitled tenants receive FBR evidence.

### 13.2 Current six-control catalog

| Control | Event | Source and purpose |
|---|---|---|
| FBR-101 | `FBR-INV-DEL` | POS JSONL/API invoice deletion evidence. |
| FBR-102 | `FBR-INV-MOD` | POS JSONL/API invoice modification evidence. |
| FBR-103 | `4660` | Native Windows object-deletion evidence. |
| FBR-104 | `4663` | Delete-intent context containing path and handle. |
| FBR-105 | `4670` | Native permission-change evidence. |
| FBR-106 | `FIM-DB-MOD` | Correlated database-file tamper evidence. |

### 13.3 Two independent FBR truth sources

1. **Invoice semantic evidence:** the POS vendor writes strict JSONL or sends authenticated API events. This identifies invoice IDs, actors, source systems, and modification/deletion intent.
2. **Native file-integrity evidence:** Windows auditing monitors configured database/POS paths. This proves database-file deletion or permission tampering but does not infer invoice line items.

### 13.4 Redis FIM correlation

Event 4660 does not carry a usable path. WarSOC correlates it with Event 4663:

1. A qualifying 4663 delete-intent event stores the path under `warsoc:fim_correlate:{tenant_id}:{agent_id}:{handle_id}` with a 60-second TTL.
2. A matching 4660 reads that key.
3. The worker validates the file extension.
4. The worker persists one `FIM-DB-MOD` event.
5. The correlation key is consumed without allowing duplicate FIM creation.
6. Redis or Mongo failure leaves the stream event retryable rather than silently losing evidence.

Approved database extensions are `.mdf`, `.ndf`, `.ldf`, `.sqlite`, `.sqlite3`, `.db`, `.db3`, and `.bak`.

Normal file writes do not create FIM database-tamper alerts. Unmatched 4660 events remain SIEM evidence. Event 4670 can directly generate FIM evidence when it targets an approved database file.

### 13.5 FBR confidentiality

Sensitive FBR fields, including message, raw event, raw data, raw event data, and processed data, are encrypted with `encryption_version="fernet-v1"`. Authorized detail and export paths decrypt fields for the requesting tenant and permitted role.

## 14. MongoDB Hot Storage

### 14.1 Collection ownership

| Collection | Owner | Purpose |
|---|---|---|
| `logs` | Upload/raw normalized routes | General uploaded or normalized log records. |
| `siem_cold_vault` | SIEM worker | Seven-day operational event/evidence feed. The name is historical; it is Mongo hot storage before Azure archival. |
| `security_alerts` | SIEM/mitigation paths | Actionable incidents and status history. |
| `fbr_pos_logs` | FBR worker | Encrypted FBR evidence. |
| `peca_forensic_logs` | PECA worker | Signed/encrypted PECA evidence. |
| `storage_archives` | Storage archiver | Azure archive ledger and retrieval index. |
| `csv_uploads` | Upload workflow | Uploaded source metadata. |
| `analysis_results` | Analysis workflow | Derived analysis results. |
| `management_audit` | Administrative actions | Operator/management audit trail. |
| `system_audit` | System actions | System-level audit trail. |

### 14.2 Seven-day hot-storage policy

| Data class | Hot-policy threshold | Azure vault window |
|---|---:|---:|
| Raw/general logs | 7 days | Tenant retention, normally 90 days. |
| SIEM evidence (`siem_cold_vault`) | 7 days | Tenant retention, normally 90 days. |
| SIEM alerts (`security_alerts`) | 7 days | Tenant retention, normally 90 days. |
| FBR evidence | 7 days | 2,190 days. |
| PECA evidence | 7 days | 365 days. |
| Uploads/results | Tenant retention | Tenant retention. |

There is no end-user retention button for PECA or FBR because these values are compliance policy, not an arbitrary UI preference. SIEM archive retention follows the tenant contract. All three core live data classes use a seven-day Mongo archival threshold.

The threshold and the physical move time are not identical:

- The archiver runs once every 24 hours, so timestamp-selected FBR, PECA, and general-log records normally move on the first run after they become seven days old, approximately between day 7 and day 8.
- SIEM evidence and alerts have `_expire_at` set to day 7. The production one-day archive lead makes them eligible approximately at day 6, and the daily schedule normally moves them between day 6 and day 7.
- If the archiver or Azure is unavailable, Mongo records remain beyond these windows. This is intentional fail-safe behavior: storage use grows visibly instead of evidence being deleted without a verified archive.
- Therefore, "seven-day hot" is the operating policy, not a destructive Mongo TTL guarantee. Archiver health and Mongo disk growth must be monitored.

### 14.3 Retention markers

- `_expire_at` is the SIEM hot-expiry marker. On FBR/PECA records it also carries the long compliance-expiry metadata, while the fixed collection timestamp policy controls the seven-day move to Azure.
- `_retention_ts` is used as a stable date anchor for raw/upload collections.
- The archiver knows the valid fields for each collection and also applies the fixed seven-day collection threshold.
- Legacy records are backfilled so they remain discoverable by the archiver.
- Mongo TTL indexes are removed from archive-managed collections.

MongoDB itself is therefore not allowed to delete evidence on a timer. Only the verified archive transaction may remove hot copies.

## 15. Azure Cold Archive Transaction

### 15.1 Production scheduler

- Production service: `storage-archiver` in `docker-compose.prod.yml`.
- Default interval: 86,400 seconds (daily).
- Default batch size: 5,000 documents.
- Default archive lead: one day for explicit expiry markers.
- Azure configuration is mandatory for the production service.
- `AZURE_IMMUTABILITY_REQUIRED` defaults to true in production Compose.

### 15.2 Archive-before-delete sequence

For each tenant, collection, and batch:

1. Select eligible Mongo records using the collection's hot-retention rules.
2. Serialize the batch as JSON.
3. Calculate SHA-256 over the exact JSON bytes.
4. Upload the JSON blob with collection, hash, and vault-retention metadata.
5. Upload a companion `.sha256` blob.
6. Read Azure blob properties.
7. Verify legal hold or a locked immutability policy that lasts through the required retention date.
8. Insert a `storage_archives` ledger row with tenant, collection, blob names, hash, count, timestamps, event IDs, retention, and immutability status.
9. Delete only those exact Mongo `_id` values for the same tenant.

If upload, hash handling, immutability verification, or ledger insertion fails, the Mongo records are not deleted. The visible failure mode is hot-storage growth, not silent evidence loss.

### 15.3 Blob layout

Archive paths use tenant and collection partitions:

```text
{tenant_id}/{collection}/year=YYYY/month=MM/day=DD/archive_{collection}_{run_id}_batch_NNNN.json
{tenant_id}/{collection}/year=YYYY/month=MM/day=DD/archive_{collection}_{run_id}_batch_NNNN.sha256
```

The public agent-artifact account/container must remain separate from the private immutable evidence account/container.

## 16. Cold Archive Retrieval

### 16.1 Reader safety

The archive reader:

1. Queries `storage_archives` for the authenticated tenant and permitted collections.
2. Narrows ledger entries by date, event ID, event UID, or document ID when filters exist.
3. Downloads the referenced private Azure blob.
4. Recomputes and verifies SHA-256 before parsing.
5. Rejects invalid JSON, failed hashes, and records whose tenant does not match the authenticated tenant.
6. Applies date/event/search filters.
7. Marks records as archived and records their source collection/blob.
8. Deduplicates hot and cold identities and sorts newest first.

### 16.2 Routes that read hot plus cold

- Compliance evidence detail/list routes.
- Global data search.
- CSV export.
- PDF audit report.

The dashboard's live SIEM feed intentionally reads Mongo hot data only. It is an operational screen, not a six-year archive browser.

### 16.3 Bounded retrieval

- Default archive-ledger scan: 100 blobs.
- Hard code cap: 500 blobs.
- API result limits still apply.
- CSV default: 5,000 rows; maximum: 50,000 rows.
- PDF considers the newest 500 matching records and prints a 50-row evidence preview.

For deep historical work, users must apply date/event filters or use CSV in bounded exports. A single unfiltered browser request is not intended to materialize an entire multi-year vault.

## 17. Dashboard Data Contract

### 17.1 Operational views

| Screen/widget | Backend source | Meaning |
|---|---|---|
| Omni Agent Feed | `GET /api/v1/logs?source=siem&limit=100&aggregate=false` | Latest normal and suspicious endpoint evidence from `siem_cold_vault`. |
| Live Inspection / threats | `GET /api/v1/logs` default alert source | Actionable records from `security_alerts`, grouped by incident/occurrence. |
| Historical charts | Dashboard history/search endpoints | Tenant-scoped aggregates for selected time window. |
| Agent health badge | `GET /api/v1/data/status` | Active, degraded, or offline/not-configured telemetry state. |
| Compliance catalog | `GET /api/v1/compliance/packs` and `GET /api/v1/auth/my-packs` | Available and entitled packs. |
| Compliance coverage | `GET /api/v1/compliance/coverage` | Sensor/control coverage status. |
| PECA/FBR evidence | `GET /api/v1/compliance/evidence/{pack_id}` | Merged hot and Azure evidence for authorized roles. |

The Agent Feed and Live Inspection must not use the same dataset. If normal events appear as threats, or threats disappear because only raw events are fetched, that is a frontend binding regression.

### 17.2 Live updates

1. The browser requests a one-time WebSocket ticket from `POST /api/v1/ws/ticket`.
2. The ticket is short-lived, stored in Redis, and bound to the session/tenant.
3. The browser connects to `/ws/alerts` over WSS.
4. The backend validates and consumes the ticket.
5. The browser receives tenant-scoped alert messages.
6. Periodic HTTP refresh remains a fallback/reconciliation path.

### 17.3 Duplicate presentation

Repeated occurrences of the same stable alert identity are represented as an incident with a count and occurrence details instead of creating unrelated rows for every duplicate. Raw evidence remains individually traceable.

## 18. Alert and Mitigation Workflow

### 18.1 Alert status

- Read alerts: admin, manager, analyst.
- Acknowledge or close: admin and manager.
- Endpoint: `PATCH /api/v1/alerts/{alert_id}/status`.
- Close requires resolution notes.
- Status changes persist and are returned after refresh.
- Related/grouped alert identities are handled as one incident where applicable.

### 18.2 IP/CIDR mitigation

- Authorized roles: admin and manager.
- Validates IPv4/IPv6/CIDR syntax.
- Blocks loopback, protected/system addresses, the current administrative source, and active enrolled-agent addresses from unsafe self-lockout.
- Writes the enforcement state to Redis first.
- Persists the management record to Mongo.
- Rolls back Redis if database persistence fails.
- Signed agent heartbeats receive the current tenant ban list.

This is WarSOC policy distribution. Actual packet enforcement on an endpoint depends on the installed agent applying the returned policy.

## 19. Reports and Exports

### 19.1 CSV

- Endpoint: `GET /api/v1/export/csv`.
- Enforces tenant scope, role, and compliance entitlement.
- Merges hot Mongo and verified Azure records.
- Decrypts authorized compliance fields.
- Removes internal retention fields and private signature implementation fields from ordinary tabular output.
- Default limit 5,000; maximum 50,000.

### 19.2 PDF audit report

- Endpoint: `GET /api/v1/export/audit-report`.
- Authorized for admin and auditor compliance workflows.
- Merges hot Mongo and verified Azure evidence.
- Considers the newest 500 matching records.
- Prints a 50-record ledger preview and states that additional records were omitted from the human-readable summary.
- Includes compliance/control scorecard information.
- Is not itself digitally signed.

The source PECA evidence remains signed and verifiable even though the PDF presentation is a bounded summary.

## 20. Email Behavior

- General contact and quote requests are sent to the WarSOC backend, not Web3Forms.
- The unified worker includes the email delivery daemon.
- Production SMTP variables use the Zoho configuration expected by the backend.
- High/critical SIEM alerts can queue email notifications when tenant notification settings and SMTP are valid.
- Team invite behavior must be judged by the actual invite endpoint response and mail queue result; creating a team account and successfully delivering email are separate operations.
- Email bodies and credentials must not be logged.
- Delivery failures must be visible through queue/worker metrics or logs and retried according to the email worker policy.

## 21. Production Topology

```mermaid
flowchart LR
    B["Customer browser"] --> V["Vercel warsoc.tech"]
    V -->|"HTTPS API and WSS"| N["Nginx api.warsoc.tech"]
    A["Windows agents"] -->|"HTTPS telemetry"| N
    N --> API["FastAPI service"]
    API --> R["Private Redis"]
    API --> M["Private MongoDB"]
    R --> W["Unified worker"]
    W --> M
    W --> SMTP["Zoho SMTP"]
    M --> AR["Daily storage archiver"]
    AR --> AZ["Private immutable Azure evidence storage"]
    API --> AZ
    V -->|"Agent redirect"| PUB["Public Azure artifact storage"]
```

### 21.1 Production services

| Service | State | Purpose |
|---|---|---|
| `warsoc-api` | Required | HTTPS API behind Nginx. |
| `unified-worker` | Required | SIEM, FBR, PECA, email, stream retention. |
| `storage-archiver` | Required | Daily immutable Azure archival. |
| `compliance-cron` | Required | Scheduled compliance/report activity. |
| `mongodb` | Required/private | Hot operational data and archive ledger. |
| `redis` | Required/private | Streams, correlation, sessions/tickets, cache, mitigation. |
| `nginx` | Required/public 80/443 | TLS termination and reverse proxy. |
| `syslog-receiver` | Disabled future profile | Reserved for a separately reviewed Linux/network-device intake; not part of the Windows SMB pilot. |
| `threat-hunter` | Legacy optional profile | Legacy detector, not the primary unified SIEM path. |

### 21.2 Infrastructure controls

- MongoDB, Redis, and API port 8000 are not directly exposed to the internet.
- Nginx mounts native Let's Encrypt files read-only.
- Redis uses authentication, AOF with `everysec`, and `noeviction`.
- Persistent volumes protect Mongo and Redis across container recreation.
- Docker JSON logs rotate at 10 MB with five files per service.
- API and workers use read-only filesystems with explicit writable volumes/tmpfs.
- Production target: DigitalOcean 4 vCPU / 8 GB RAM.
- Frontend target: Vercel at `https://warsoc.tech`.
- API target: DigitalOcean at `https://api.warsoc.tech`.
- Agent artifact: separate public Azure storage.
- Evidence: separate private immutable Azure storage.

## 22. Verification State

### 22.1 Verified for the current release-candidate code

- Focused release-candidate backend checks: 122 passed across native SIEM/FBR/PECA behavior, spool durability, telemetry routing, stream retention, archive contracts, platform policy, incidents, RBAC/hardening, and secure invitation activation.
- Python compilation for the modified backend modules passed.
- Frontend lint passed.
- Frontend production build passed with 2,851 modules; only a non-blocking large-chunk warning remained.
- Local Windows agent and installer build passed for version 4.2.2.
- Local `warsoc_installer-4.2.2.exe`: 17,415,232 bytes, SHA-256 `FDF008750DD7A8BE0778106C1A2A15BECD6FB64EE7A0DA4D0CC71845B927CC1E`.
- The generated manifest also records the agent, NSSM, native telemetry script, and tenant policy hashes.

### 22.2 Verified for the previously deployed public release

- Production Compose configuration validation passed.
- Backend release `81db420` is deployed on DigitalOcean and reports healthy.
- Frontend release `fdae9ce` is deployed on Vercel and is bound to `https://api.warsoc.tech/api/v1` with no localhost API binding.
- Live frontend assets request up to 500 raw alerts; 279 raw alert records were verified as 13 grouped incidents rather than 279 duplicate rows.
- A production endpoint returned to Active after service restart, and new PECA evidence was signed and vaulted by the live worker.
- Production preflight run `136bf34e0c` passed every check on 2026-07-14:
  - `warsoc.tech` and `api.warsoc.tech` resolve to separate Vercel and DigitalOcean addresses.
  - Frontend and backend TLS, HTTPS, CORS, HSTS, clickjacking protection, MIME protection, health, and blocked public API docs passed.
  - MongoDB `27017`, Redis `6379`, and API `8000` were closed externally.
  - The live `warsoc_installer-4.2.0.exe` was 17,415,025 bytes and matched the local manifest SHA-256 `89507E72BD885D9DD61E321F2215AD55E29915C39B964048A3BE58E4831E1A9B`.

### 22.3 Verified directly in the production archive pipeline

- Private Azure evidence storage is reachable with the configured production identity.
- The evidence container reports a locked immutability policy sufficient for the required retention window.
- The production archiver is configured for container-scoped immutability verification.
- Expired records from `siem_cold_vault`, `security_alerts`, `fbr_pos_logs`, and `peca_forensic_logs` were uploaded successfully.
- JSON payloads and SHA-256 sidecars were written and verified before deletion.
- Archive-ledger entries were committed and the corresponding expired Mongo records were deleted only after successful verification.
- A controlled archiver restart produced no duplicate archive for the already committed records.
- PECA archival has now been observed in production; it is no longer only a code-path claim.
- Historical duplicate blobs created by failed pre-fix attempts remain immutable until their retention expires. They are storage-cleanup debt, not evidence loss, and the deterministic-key/ledger fix prevents new copies for the same committed batch.

### 22.4 Remaining release proof

Focused, contract-aligned checks are green. The legacy broad suite was intentionally not used as a launch claim because some fixtures encode pre-hardening behavior and must be classified before their results are used as a release gate.

| Remaining proof | Current state | Completion condition |
|---|---|---|
| Contract-aligned backend regression suite | 122 focused cases passed. | Run the production acceptance phases after deployment and explicitly quarantine/delete stale pre-hardening tests. |
| Production Platform phase | Not rerun against the latest release. | Platform acceptance exits `0`, including provisioning, auth, agent, SIEM, FBR, PECA, WebSocket, RBAC, mitigation, CSV/PDF, and SMTP metric checks. |
| Latest Windows installer | Local 4.2.2 build and manifest are complete; Azure still serves the previously approved artifact until operator upload. | Upload 4.2.2, set `AGENT_CDN_URL`, verify the CDN hash, then rerun Preflight. |
| Native Windows proof | Individual live telemetry and PECA processing are visible; the complete matrix is not captured. | Disposable Windows VM produces all 11 PECA controls plus FBR delete/permission scenarios with a passing NativeVerify JSON artifact. |
| Fifty-agent capacity | Not proven for this release. | Soak phase exits `0` within latency targets without Redis eviction, DLQ growth, or unexpected restarts. |
| Cold-only retrieval and reports | Upload, immutability, ledger, hot deletion, and direct integrity checks passed. | Records no longer in Mongo are retrieved through the authorized API and appear correctly in CSV and PDF output. |
| Email delivery | Worker path exists; final mailbox delivery is not captured for this release. | Invite and high/critical alert emails arrive in the intended inbox with no unexpected DLQ entries. |
| Independent backup recovery | Archive is working; backup is not a restore proof. | Restore a Mongo backup into an isolated environment and record the result. |

The unsigned installer remains dependent on customer IT hash allowlisting until code signing is added. Defender must remain enabled.

## 23. Failure Map

| Failure | Expected behavior | Operational signal |
|---|---|---|
| Agent cannot reach API | Keep local spool; retry; do not advance undurable watermark. | Agent/service log and stale heartbeat. |
| Spool reaches 500 MiB or disk reserve | Pause new durable collection; retain existing evidence; report Degraded. | `/data/status`, spool metrics, agent log. |
| Security/System channel fails | Continue reporting heartbeat as degraded. | `/data/status` and dashboard Degraded. |
| Malformed POS JSONL | Quarantine locally; do not invent evidence. | Agent quarantine/parse metric. |
| Redis unavailable at ingest | Reject/fail request; agent retries from spool. | API error, Redis health, ingest metrics. |
| Raw stream reaches admission limit | Return HTTP 503; never trim unacknowledged events; agent retries. | `warsoc_raw_stream_depth`, API log, endpoint spool growth. |
| Worker cannot write Mongo | Leave stream message pending for reclaim. | Worker error/pending count. |
| Poison stream event | Copy to DLQ after delivery threshold, then acknowledge. | DLQ metric and security signal. |
| FIM Redis correlation misses | No false FIM alert; keep unmatched event as SIEM evidence. | Correlation-miss metric. |
| Azure upload fails | Do not delete hot Mongo records. | Archiver error and hot-storage growth. |
| Azure immutability insufficient | Do not delete hot Mongo records. | Archiver hard failure. |
| Archive hash mismatch on read | Reject that blob's records. | Archive-reader integrity error. |
| WebSocket disconnects | HTTP refresh reconciles; reconnect with a fresh ticket. | UI reconnect state and API polling. |
| SMTP fails | Detection/evidence persists; notification retries/fails visibly. | Email worker metrics/logs. |

## 24. Operating Checks

### Daily

- API, Mongo, Redis, unified worker, archiver, and Nginx health.
- Redis stream pending and DLQ counts.
- Agent Active/Degraded/offline counts.
- Detection latency and queue age.
- Disk, Mongo volume, and Redis memory usage.
- Latest successful Azure archive ledger timestamp.
- Email queue failures.

### Weekly

- Sample Azure blob download and SHA verification.
- Sample hot-plus-cold compliance search/export.
- Backup restoration test status.
- Agent version and audit-policy coverage.
- Top noisy rules, false positives, and ignored normal-write metrics.
- Expiring TLS, encryption, signing, and admin credentials.

### Before each production release

- Backend unit/integration suite.
- Frontend lint and production build.
- Production acceptance preflight.
- Real activation, registration, heartbeat, and telemetry smoke test.
- One SIEM detection, one PECA control, one FBR invoice event, and one FBR FIM correlation.
- Alert acknowledge/close and mitigation check.
- CSV and PDF hot-plus-cold check.
- Azure archive/restore integrity check.
- SMTP delivery check.
- Installer SHA-256 manifest regeneration and artifact/CDN match.

## 25. Final Production Acceptance Gate

Do not declare the current release fully accepted until all of the following are captured in a dated launch-artifacts folder:

1. Production preflight JSON with DNS, TLS, CORS, private-port, health, and artifact-hash checks passing.
2. Tenant provisioning and browser login proof.
3. Valid activation generation and successful real Windows agent enrollment.
4. Signed heartbeat showing Security and System channels healthy.
5. SIEM alert generated from a known native test event within the target latency.
6. PECA evidence for the required native controls, including System Event 7045.
7. FBR invoice evidence from strict JSONL or authenticated API.
8. FBR file delete/permission scenario producing exactly one encrypted FIM event and no alert for ordinary writes.
9. Dashboard Agent Feed showing normal evidence and Live Inspection showing only actionable threats.
10. Alert acknowledgement, closure with notes, and safe IP mitigation.
11. Auditor access allowed for entitled evidence and denied for operations/team/agent controls.
12. Email delivery proof.
13. PDF and CSV proof.
14. Azure blob upload, immutability, SHA verification, archive-ledger entry, and successful API retrieval proof.
15. Backup restore proof distinct from the compliance archive.

## 26. Source-of-Truth Files

| Concern | Source |
|---|---|
| Compliance controls and fixed retention | `app/utils/compliance_catalog.py` |
| SIEM event/rule catalog | `app/utils/siem_catalog.py` |
| SIEM processing | `app/workers/siem_worker.py` |
| FBR processing and Redis correlation | `app/workers/fbr_worker.py` |
| PECA evidence/signing | `app/workers/peca_worker.py` |
| Unified supervision | `app/workers/unified_worker.py` |
| Stream trimming safety | `app/workers/stream_retention.py` |
| Storage archival | `app/workers/storage_archiver.py` |
| Azure retrieval | `app/utils/archive_reader.py` |
| Database indexes/TTL removal | `app/db/init_db.py` |
| Agent enrollment/download/heartbeat | `app/routes/agent_orchestration.py` |
| Agent ingest | `app/routes/ingest_pulse.py` |
| POS API | `app/routes/pos.py` |
| Compliance API | `app/routes/compliance.py` |
| Alert lifecycle | `app/routes/alerts.py` |
| Search/status | `app/routes/data.py` |
| Reports | `app/routes/export.py` |
| Roles | `app/utils/rbac.py` plus route dependencies |
| Windows agent | `agent/` |
| Native audit configuration | `agent/deploy_warsoc_telemetry.ps1` |
| Installer | `installer.iss` |
| Production services | `docker-compose.prod.yml` |
| Dashboard integration | Frontend `src/assets/Pages/Dashboard/Dashboard.jsx` |
| Compliance integration | Frontend `src/assets/Pages/Compliance/ComplianceDashboard.jsx` |

## 27. Interpretation Rules

- `siem_cold_vault` is a historical name for the Mongo SIEM evidence collection governed by the seven-day hot policy. Azure Blob is the actual cold archive.
- Empty Live Inspection does not mean the agent is broken if the Agent Feed is receiving normal events; it means no actionable detection currently matches.
- Empty compliance evidence can mean no entitled control fired, an unhealthy sensor, or an archive/API error. The UI must show API errors separately from a valid empty result.
- `Degraded` is not a cosmetic failure. It means at least one required telemetry/coverage condition needs investigation.
- A successful PDF proves report generation, not full-vault materialization. CSV and filtered archive search are the detailed evidence paths.
- FBR FIM and FBR invoice semantics are complementary but not interchangeable.
- Azure archive is evidence retention. Independent Mongo backup and restoration remain separate operational requirements.

This file should be updated whenever a queue name, consumer group, collection, retention value, API path, role permission, detector threshold, installer contract, or production service changes.
