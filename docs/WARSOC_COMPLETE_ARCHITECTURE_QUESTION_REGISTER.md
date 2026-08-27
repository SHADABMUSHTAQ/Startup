# WarSOC Complete Architecture Question Register

**Status:** Authoritative governance register
**Reviewed:** 2026-08-01
**Implementation authority:** None. A failed or open question creates a separately reviewed implementation item.
**Detailed closure companion:** `WARSOC_CURRENT_SCOPE_15_ARCHITECTURE_QUESTIONS.md`

## How To Use This Register

Every review records:

```text
Decision:
Evidence:
Owner:
Status:
Date:
```

Allowed status values are `OPEN`, `CANDIDATE-PROVEN`, `PRODUCTION-PROVEN`, `PER-CUSTOMER`, `ONGOING`, `ACCEPTED-RISK`, and `BLOCKED`.

The register has three time horizons:

- Questions 1-15 are gates before the first paying customer on the new production host.
- Questions 16-20 are answered for every customer before provisioning.
- Questions 21-25 are permanent architecture governance questions.

## A. Before The First Paying Customer

### 1. Have we frozen one candidate and later proved its deployed identity?

Before deployment, can WarSOC freeze the backend commit, frontend commit, expected image build inputs, database/index contract, sanitized configuration, agent version, installer bytes, and manifest? After acceptance, can it prove HostKey, Vercel, and Azure match that candidate using immutable image digests and production evidence?

**Current status:** `OPEN`. Historical DigitalOcean proof and local tests do not prove HostKey. Agent 4.2.6 is the approved artifact while 4.2.8 remains an unbuilt source candidate.

**Close with:** A pre-deployment candidate freeze followed by a final production release manifest containing exact commits/digests, installer and manifest SHA-256, sanitized non-secret environment fingerprint, test run IDs, backup identifier, rollback point, approvals, and timestamp.

### 2. Is the HostKey server securely configured?

Are only ports 80 and 443 public, is SSH key-only and source-restricted, and are FastAPI, MongoDB, Redis, metrics, and optional syslog inaccessible externally?

**Current status:** `OPEN` until the exact HostKey machine is scanned.

**Close with:** Provider firewall where available, UFW, Docker published-port and `DOCKER-USER`/equivalent enforcement, external IPv4 and IPv6 port scans, SSH tests, database authentication, private Docker network inspection, root-owned secret permissions, and public-docs denial. UFW alone is not evidence because Docker-published ports can bypass ordinary UFW rules.

### 3. Does TLS bootstrap and renewal work across cutover?

Can Nginx start before DNS cutover, serve the correct chain after cutover, and renew automatically on HostKey?

**Current status:** `OPEN`.

**Decided bootstrap method:** Securely transfer the current `/etc/letsencrypt` tree from DigitalOcean to the matching path on HostKey, verify an encrypted transfer manifest/hash, set root-only private-key permissions, and validate Nginx before DNS changes. Do not place certificate material in Git or ordinary backups.

**Close with:** Transferred-tree hash verification, root-only key permissions, `nginx -t`, pre-DNS `curl --resolve`, post-DNS chain/fingerprint/expiry, HTTP-to-HTTPS redirect, and `certbot renew --dry-run` after DNS points to HostKey.

### 4. Can WarSOC create the first tenant from an empty database?

Can the protected provisioning route create the tenant, administrator, endpoint limit, compliance packs, retention term, forensic genesis record, and Redis entitlement state while public signup remains disabled?

**Current status:** `CANDIDATE-PROVEN` in code; clean HostKey database proof remains open.

**Close with:** Empty-database provisioning, login, `/auth/me`, entitlement checks, agent-code generation, duplicate-provision rejection, rollback-on-write-failure proof, and public-signup denial.

### 5. Can a new Windows agent enrol and deliver trustworthy telemetry?

Can the approved installer validate a one-time code, register an Ed25519 key, protect the private key with DPAPI, send signed events and heartbeats, spool during downtime, retry without changing event identity, and report Security/System/audit health?

**Current status:** `CANDIDATE-PROVEN` on the exact test machine; final HostKey release proof remains open.

**Close with:** Approved artifact hash, enrollment, signed heartbeat/event acceptance, invalid/unsigned rejection, channel health, disconnect/reconnect, bounded-spool recovery, restart behavior, and zero silent watermark advancement.

### 6. Does SIEM create correct evidence and actionable incidents?

Can trusted Windows telemetry produce raw evidence, detection evidence, a tenant-scoped incident, authenticated live notification, and persistent workflow state while benign events remain non-alert evidence?

**Current status:** `CANDIDATE-PROVEN`; final paired HostKey/Vercel proof remains open.

**Close with:** Known malicious and benign cases, tenant/agent/actor/process/target context, rule/evidence references, detection p95, correct grouping and occurrence counts, context separation, assignment, acknowledgement, close-with-notes, and refresh persistence.

### 7. Does FBR operate according to its two real source contracts?

Can strict JSONL/authenticated API events provide invoice semantics while configured local POS paths and native Windows events independently provide database-file tamper evidence?

**Current status:** `CANDIDATE-PROVEN` using a POS-like test contract; each real customer still requires source mapping.

**Close with:** Invoice modification/deletion, database deletion correlation, permission change, malformed-line quarantine, stable event UID, ordinary-write no-alert proof, encrypted evidence, and honest `Not Configured` coverage when no valid local POS path or invoice source exists.

### 8. Do all 11 PECA catalog controls create traceable evidence?

Can an entitled tenant produce all 11 native Windows control records with source identity, event UID, timestamps, encrypted sensitive content, PECA signature, tenant isolation, and archive linkage?

**Current status:** `CANDIDATE-PROVEN` by maintained integration and exact-machine evidence; final release proof remains open.

**Close with:** Explicit 11-control matrix, unentitled denial, encryption/signature checks, export references, and wording that the PDF is a summary and WarSOC provides evidence readiness rather than government certification or guaranteed admissibility.

### 9. Do Redis and all workers fail safely?

Can independent SIEM, FBR, and PECA consumers survive Mongo/Redis loss, worker termination, duplicate delivery, poison records, and reordering without cross-tenant processing or silent evidence loss?

**Current status:** `CANDIDATE-PROVEN` by contract/chaos paths; exact final-host fault proof remains open.

**Close with:** Persist-before-ack verification, pending reclaim, idempotency, DLQ preservation, safe stream-retention boundary that never trims required pending entries, restart recovery, and final expected counts after each injected failure.

### 10. Is tenant isolation enforced across the complete workflow?

Can Tenant A read or mutate any Tenant B user, agent, evidence, incident, report, export, archive ledger, retrieval request, or configuration by changing IDs or tenant fields?

**Current status:** `CANDIDATE-PROVEN` in backend tests; final browser/API role matrix remains open.

**Close with:** Cross-tenant read/update denial, admin/manager/analyst/auditor matrix, direct API denial independent of frontend buttons, invitation replay denial, disabled-user session invalidation, entitlement-change behavior, concurrent incident version handling, cross-tenant URL denial, and management-audit records.

### 11. Is every evidence class routed to its correct locked Azure boundary?

Can WarSOC prove SIEM/general routing, including new PECA and FBR evidence, to the configured tenant-duration container without falling into an unlocked or shorter policy?

**Current status:** `OPEN`. Code supports the routes; the separated production containers and mappings remain infrastructure proof.

**Close with:** One bounded test per actual SIEM/general mapping plus PECA and FBR-on-general routing, proving tenant path, container, lock duration, hash, ledger, authorized readback, exact-ID deletion, unrelated-ID preservation, and fail-closed behavior for insufficient/missing policy. Staging and database-backup containers remain separate and are not evidence-WORM containers.

### 12. Does archive-before-delete work on HostKey under success and failure?

Can the HostKey archiver select an exact batch, serialize/hash it, upload evidence/hash, verify Azure properties and retention, commit the ledger, then delete only those Mongo IDs?

**Current status:** `CANDIDATE-PROVEN` historically and locally; HostKey proof remains open.

**Close with:** Success path plus invalid credentials, insufficient/unlocked container, conflicting existing blob/hash, ledger failure, interrupted archiver, retry idempotency, and Azure outage. Every failure before committed ledger/immutability proof must retain Mongo records.

### 13. Can WarSOC recover from complete HostKey loss?

Can operations rebuild from a blank replacement host within approved RPO/RTO while preserving secrets, tenant state, agent continuity, archive metadata, and any non-reconstructable accepted Redis state?

**Current status:** `CANDIDATE-PROVEN` for isolated Mongo restore only; complete blank-host recovery is open.

**Close with:** HostKey-generated encrypted backup, SHA-256 and key recovery, exact release install, secret restoration, Mongo restore, Redis-state classification/recovery, indexes, tenant/login, incident/configuration, agent continuity or re-enrollment policy, archive ledger/Azure access, DNS/TLS recovery, measured elapsed time, and management-approved RPO/RTO.

### 14. What workload can the selected HostKey vm.v2-mini safely sustain?

Can the selected EUR 8 plan (4 shared vCPU, 8 GB RAM, 120 GB NVMe, IPv4, and 3 TB included traffic) sustain the approved aggregate endpoint and daily-byte limits while preserving ingestion, detection, dashboard, archive, and operating-system headroom?

**Current status:** `OPEN`. Earlier 50-agent proof did not run on the final HostKey plan.

**Close with:** At least 24 hours of normal traffic, several hours at expected peak, and a controlled failure/recovery burst. Measure CPU and steal time, available RAM, swap rate, Mongo working set and p50/p95/p99, Redis memory/pending age, API p95/p99, detection p95, archive duration/backlog, disk latency/free space, temporary files, and Docker logs. Approve explicit upgrade triggers from measured results rather than assumptions.

### 15. How long can HostKey survive an Azure archival outage?

When archive upload or immutability verification fails closed and Mongo records remain, how long can local storage grow before platform safety is threatened?

**Current status:** `OPEN`.

**Close with:** Measure net hourly growth across Mongo documents/indexes, Redis, Docker/Nginx logs, temporary files, and local backups. Reserve disk for Mongo journal, Redis AOF, Docker, archive batches, OS stability, and emergency recovery. Validate warning, critical, and controlled-ingestion-backpressure thresholds. Agents must retain backpressured data in bounded local spools; MongoDB must not be abruptly stopped as a disk-control mechanism.

## B. Questions Asked For Every Customer

### 16. How many endpoints is the customer purchasing?

**Status:** `PER-CUSTOMER`.

Record the tenant contract limit separately from current platform capacity and existing aggregate usage. Do not provision seats that exceed measured remaining platform headroom; upgrade capacity first.

### 17. What telemetry and volume will the customer generate?

**Status:** `PER-CUSTOMER`.

Record endpoint roles, Windows versions, active users, expected EPS/bytes, high-volume servers, POS paths, invoice JSONL/API availability, business hours, and peaks. Web, firewall, Linux, DNS, or other unproven sources must be marked unsupported/disabled rather than silently included. Test slightly above the contracted current-scope load.

### 18. What exact service is the customer purchasing?

**Status:** `PER-CUSTOMER`.

Record endpoint count, SIEM retention term, FBR/PECA packs, support/onboarding, approved data region, authorized roles, start/end dates, exclusions, and commercial terms. Contract wording must distinguish FBR invoice evidence from file integrity and PECA evidence readiness from certification.

### 19. What availability, response, RPO, and RTO does the customer require?

**Status:** `PER-CUSTOMER`.

Do not promise high availability, staffed SOC response, after-hours escalation, or recovery targets beyond the approved single-host operating model. A stronger requirement must fund and wait for the required architecture and proof.

### 20. Does the customer require historical retrieval?

**Status:** `PER-CUSTOMER`, but currently `BLOCKED` as a commercial promise.

Clarify requester roles, collections, date range, required readiness time, monthly allowance, 10 GiB boundary, expiry, and paid exceptions. The backend retrieval path is a disabled candidate, not a production entitlement. Before selling retrieval, WarSOC must prove the restricted operator procedure, Azure rehydration/staging, tenant authorization, short-lived SAS delivery, metering, audit trail, expiry, and cleanup. Self-service UI may remain future work.

## C. Permanent Architecture Questions

### 21. Can one noisy tenant harm other tenants?

**Status:** `ONGOING`.

Continuously evaluate per-tenant and platform request, byte, burst, queue, CPU, Mongo, Redis, disk, archive, and retrieval controls using multi-tenant load rather than a single-tenant daily quota alone.

### 22. Can infrastructure change without reconfiguring customer agents?

**Status:** `ONGOING`.

Keep agents on `https://api.warsoc.tech`. Provider, IP, and internal topology changes must remain behind DNS/TLS and preserve the public agent contract, with rollback and DNS TTL planning.

### 23. What happens throughout the tenant lifecycle?

**Status:** `ONGOING`.

Define provisioning, seat changes, pack/retention changes, suspension, non-payment, termination, retrieval, credential/key revocation, and deletion of ordinary data. Locked evidence remains governed by its lawful retention and cannot be treated like deletable operational state.

### 24. Are keys and secrets manageable, recoverable, and rotatable?

**Status:** `ONGOING`.

Review agent keys, JWT, super-admin, metrics, Mongo, Redis, Azure, Fernet, PECA signing, backup encryption, and TLS material. Record ownership, storage, backup, rotation, compromise response, dead-key behavior, and whether old evidence/backups remain verifiable and decryptable.

### 25. Does every proposed feature preserve WarSOC architecture rules?

**Status:** `ONGOING`.

Every future source must identify the tenant, authenticate or accurately qualify source trust, use least privilege, enter a canonical schema, respect quotas, preserve original identity, follow Redis/custody/RBAC boundaries, and pass security, capacity, legal, and physical acceptance before being advertised. Customer funding or demand alone cannot waive these gates. Wazuh, firewall relays, Linux, cloud identity, and other integrations remain candidates until separately approved.

## Current Priority

**Latest local candidate review (2026-08-01):** `132` focused service-independent contracts passed, the modified Python tree compiled, and Bandit reported zero high-severity findings. The disabled archive-retrieval candidate was additionally restricted so managers cannot cross into FBR/PECA archives, auditors cannot cross into operational SIEM archives, and compliance access requires the current pack entitlement. These results support existing `CANDIDATE-PROVEN` labels only; they do not convert any HostKey, Azure, browser, live-service, load, or recovery gate to `PRODUCTION-PROVEN`.

1. Close Questions 1-4 to freeze and secure the HostKey release boundary.
2. Close Questions 11-13 to protect retention and recovery before load generation.
3. Close Questions 5-10 to prove the customer-facing Windows/SIEM/FBR/PECA workflow.
4. Close Questions 14-15 with exact HostKey capacity and Azure-outage measurements.
5. Seal the final release manifest and production acceptance bundle.

Questions 16-20 are mandatory onboarding records. Questions 21-25 remain in every architecture and release review. Tenant/platform limit separation remains mandatory in Questions 14, 16, and 21; exact release consistency remains mandatory in Question 1 and every later release review.
