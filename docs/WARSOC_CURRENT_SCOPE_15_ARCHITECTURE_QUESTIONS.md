# WarSOC Current-Scope Architecture: 15 Questions That Must Be Closed

**Status:** Architecture discovery backlog; no implementation is authorized by this document.
**Reviewed:** 2026-08-01
**Scope:** Existing Windows agent, signed ingestion, SIEM, FBR, PECA, Redis/Mongo processing, seven-day hot storage, Azure evidence archival, RBAC, incidents, exports, and the low-cost single-host deployment.

## Purpose

The larger gap inventory contains real risks, future product ideas, accepted limitations, and items already implemented. This document keeps only the questions that can materially affect the correctness, security, performance, evidence quality, or operability of WarSOC's current product.

The questions are ordered by dependency. A later question must not be treated as closed when an earlier dependency remains unproven.

Closure is deliberately right-sized for the selected low-cost launch: it proves the current HostKey plan and expected initial load, uses internal provisional RPO/RTO until management approves contractual targets, and does not require high availability, redundant compute, self-service retrieval, or future integrations.

## Current Facts That Must Not Be Reopened as Missing Features

- Production Compose defaults endpoint event signing to `required`.
- The Windows agent uses a bounded 500 MiB spool and advances event-channel watermarks only after durable local persistence.
- The agent reads native Windows `Security` and `System` channels without Sysmon.
- SIEM and raw-log Mongo hot retention are capped at seven days.
- Tenant and platform daily-ingestion quotas and a 50-agent deployment ceiling exist.
- Redis uses bounded stream retention and `noeviction`; workers have pending-message reclaim and DLQ paths.
- The FBR path separates invoice events from native database-file tamper evidence.
- The PECA catalog contains 11 current Windows controls.
- The archiver verifies hashes and required Azure immutability before deleting corresponding Mongo records.
- Network relay code exists but remains disabled and is not part of this current-scope review.

## Closure Labels

- **P0:** Must be answered before moving the current platform to a new production host or onboarding a paying customer.
- **P1:** Must be answered during controlled operation before expanding traffic or contractual claims.
- **Implemented:** The control exists in code.
- **Proof gap:** The control exists, but the final deployment or realistic workload has not proved it.
- **Design gap:** Existing controls do not yet fully answer the question.
- **Operating decision:** A measurable threshold or responsibility has not been approved.

---

## 1. Is the candidate release frozen and signing-compatible before deployment?

**Priority:** P0
**Gap type:** Proof gap and release-identity gap

**Verified state:** Production Compose and `.env.example` default `AGENT_EVENT_SIGNATURE_MODE` to `required`. The backend verifies Ed25519 event signatures. Agent `4.2.6-Native-Signed` has real-machine signature proof. A local unsigned `4.2.8-Native-Signed` installer and manifest were built on 2026-08-10 after adding a mandatory pywin32 build gate, but Azure upload, clean-machine installation, and production preflight remain open; therefore 4.2.8 is not yet the approved public artifact.

**Why it matters:** If enforcement is weaker than expected, forged telemetry can enter SIEM, FBR, and PECA. If the deployed backend and published agent disagree, legitimate events can be rejected.

**Question to close:** Before deployment, which exact backend commit, installer version, manifest/CDN hash, and required-signing configuration form the frozen candidate, and do they accept the approved signed agent while rejecting invalid/unsigned events?

**Required evidence:** A pre-deployment candidate manifest plus maintained acceptance output showing successful signed ingestion from the approved installer, rejection of invalid/unsigned events, and exact backend/CDN SHA-256 identity. This freezes the candidate; Question 15 later proves the deployed system matches it.

## 2. Does the agent remain durable and bounded through outages, disk pressure, malformed records, and service restarts?

**Priority:** P0
**Gap type:** Proof gap

**Verified state:** The agent has a 500 MiB spool ceiling, a lower resume boundary, disk-space checks, malformed-record quarantine, retry-preserving processing files, signed health data, and durability-aware Windows channel watermarks.

**Why it matters:** These boundaries prevent silent log loss and prevent an endpoint from filling its disk during a backend outage or recursive logging fault.

**Question to close:** Under the approved installer, what is the exact behavior at spool warning, hard limit, recovery, restart, and prolonged backend outage?

**Required evidence:** A controlled Windows test proving bounded disk use, no watermark advancement after failed spool writes, exact retry after restart, no duplicate event UID, health-state degradation, and normal recovery below the resume boundary.

## 3. Is native Windows collection producing the required evidence without collecting an unsustainable event volume?

**Priority:** P1
**Gap type:** Operating measurement gap

**Verified state:** The installer configures native auditing and command-line capture, while the agent reads `Security` and `System`. Capture-all modes are disabled by default, and heartbeat health records channel and audit-policy state.

**Why it matters:** Missing audit categories create blind spots; overly broad collection creates noise, disk pressure, and avoidable compute and archive costs.

**Question to close:** For each supported Windows/POS role, which audit subcategories and event IDs are required, and what normal events-per-minute and bytes-per-day do they generate?

**Required evidence:** A baseline from a clean workstation and a representative POS workload showing channel health, required event coverage, event volume, rejection count, parse failures, and daily bytes.

## 4. Does SIEM turn trusted telemetry into actionable incidents instead of false-positive noise?

**Priority:** P0
**Gap type:** Detection-quality proof gap

**Verified state:** SIEM now separates trusted Windows, web, and relay telemetry families. Normal events can remain evidence/correlation inputs, dangerous events can alert directly, and immutable detections project into mutable grouped incidents.

**Why it matters:** Source-family mistakes and context-free keyword matching previously produced misleading alerts. High false-positive volume makes the product operationally unusable even when the pipeline is technically running.

**Question to close:** For every enabled current-scope rule, what trusted source, required fields, threshold, suppression, title, actor, endpoint, target, process, outcome, and evidence reference must be present?

**Required evidence:** A rule matrix plus benign and malicious Windows scenarios showing expected alert/no-alert behavior, incident grouping, occurrence counts, and complete investigation context.

## 5. Are stateful detections correct under retries, reordering, concurrency, and duplicate delivery?

**Priority:** P1
**Gap type:** Correlation proof gap

**Verified state:** Redis-backed correlation and cooldown logic exists for multi-event behavior, including password spraying and FBR handle correlation. Workers use consumer groups, pending-message recovery, and idempotency fields.

**Why it matters:** Real streams are at-least-once and may be processed by different worker tasks. In-memory or non-atomic state would miss attacks or create duplicate incidents.

**Question to close:** Which current correlations require order, what time windows apply, how are duplicates suppressed, and what happens when Redis is temporarily unavailable?

**Required evidence:** Cross-worker tests with out-of-order, repeated, expired, and Redis-failure events proving one correct result or a retained retry, never silent acknowledgement.

## 6. Does FBR distinguish invoice truth from file-tamper truth without overstating either?

**Priority:** P0
**Gap type:** Product-truth and customer-integration gap

**Verified state:** Invoice semantics come only from strict `FBR-INV-MOD`/`FBR-INV-DEL` JSONL or authenticated POS API events. Native file integrity uses configured local POS/database paths and Windows `4663`/`4660`/`4670` evidence. Ordinary writes must not create `FIM-DB-MOD`.

**Why it matters:** File deletion cannot identify a changed invoice, and an application invoice event cannot independently prove database-file tampering. Confusing these sources creates false compliance claims.

**Question to close:** For each customer POS, which local paths are protected and which application component will produce the strict invoice events with stable event UIDs?

**Required evidence:** A customer-specific FBR source map and a real POS-like test proving valid modification/deletion evidence, exactly one correlated file-tamper event, permission-change evidence, malformed-line quarantine, and no alert from ordinary database writes.

## 7. Do all 11 PECA evidence controls remain complete, correctly classified, and cryptographically traceable?

**Priority:** P0
**Gap type:** Coverage and legal-evidence proof gap

**Verified state:** The catalog defines 11 Windows controls and the maintained integration test exercises all 11. Real-machine evidence has also been recorded. PECA records are evidence-readiness artifacts, not an official certification or guarantee of admissibility.

**Why it matters:** A passing catalog count is insufficient if fields, source identity, timestamps, signatures, encryption, or chain references are incomplete.

**Question to close:** Does every control preserve the original event identity, agent identity, actor/context fields available from Windows, signature verification state, encrypted sensitive content, and archive linkage?

**Required evidence:** An 11-row control matrix with one native example per control, field completeness, signature result, encryption check, tenant isolation, export reference, and Azure ledger/hash reference.

## 8. Can Redis/Mongo failures occur without losing accepted SIEM, FBR, or PECA evidence?

**Priority:** P0
**Gap type:** Failure-semantics proof gap

**Verified state:** Ingestion rejects or asks agents to retain/retry under capacity pressure. SIEM, FBR, and PECA workers have pending-entry recovery and DLQ handling; FBR correlation has retryable Redis state.

**Why it matters:** Incorrect acknowledgement ordering converts a temporary database or Redis outage into permanent evidence loss.

**Question to close:** At every worker persistence point, is stream acknowledgement performed only after the intended database/evidence action is durably committed or safely quarantined?

**Required evidence:** Fault injection for Redis loss, Mongo loss, worker termination, poison events, duplicate delivery, and restart, with final counts proving no silent loss and no uncontrolled duplicate evidence.

## 9. Can one noisy tenant or burst starve every other tenant before daily quotas react?

**Priority:** P0
**Gap type:** Design and operating-policy gap

**Verified state:** Per-tenant and platform daily byte ceilings exist, along with API pressure checks and a 50-agent deployment ceiling. Resources are nevertheless shared across Redis, Mongo, workers, and disk.

**Why it matters:** A daily quota limits total consumption but does not automatically guarantee fair short-term CPU, queue, or I/O access during a burst.

**Question to close:** What per-tenant burst, batch, request-rate, queue-depth, and concurrent-processing boundaries preserve service for other tenants?

**Required evidence:** A two-tenant load test where one tenant reaches its allowed burst while the second tenant continues to ingest, detect, query, and heartbeat within approved latency.

## 10. What workload can the selected HostKey vm.v2-mini safely sustain?

**Priority:** P0
**Gap type:** Final-host capacity proof and operating decision

**Verified state:** The selected EUR 8 `vm.v2-mini` is listed as 4 shared vCPU, 8 GB RAM, 120 GB NVMe, IPv4, and 3 TB included traffic. The current architecture caps the shared deployment at 50 agents and 3 GiB/day. A prior 50-agent simulation passed, but it did not prove this exact HostKey tier.

**Why it matters:** CPU steal, Mongo working-set pressure, Redis memory, archive backlog, Docker logs, and local disk all share one inexpensive VPS.

**Question to close:** What measured traffic level leaves sufficient CPU, RAM, swap, disk, queue, and detection-latency headroom on the exact HostKey plan?

**Required evidence:** A production-shaped soak on the exact purchased HostKey plan: at least 24 hours of normal traffic, several hours at expected peak, and one controlled failure/recovery burst. Measure CPU and CPU steal, available memory, swap-in/out, Mongo working set and p50/p95/p99 query latency, Redis memory/pending depth/oldest-pending age, API p95/p99, end-to-end detection latency, archive duration/backlog, disk write latency/free space, Nginx temporary files, and Docker logs. The result must approve measured upgrade triggers; initial values such as sustained CPU above 70%, repeated CPU steal above 10%, available memory below 20%, sustained swap, disk above 75%, Mongo p95 above 500 ms, pending age above 60 seconds, detection p95 above 60 seconds, or archive backlog beyond one cycle remain proposals until the soak validates them.

## 11. How long can the host survive when Azure archival is unavailable?

**Priority:** P0
**Gap type:** Operating safeguard gap

**Verified state:** Archival fails closed: records remain in Mongo when upload, hash, ledger, or immutability verification fails. This protects evidence but allows local storage growth.

**Why it matters:** Evidence safety and host availability conflict during a prolonged Azure or credential outage.

**Question to close:** At the measured net local-growth rate, how many hours or days remain before warning, critical, ingestion-backpressure, and emergency-reserve thresholds are reached?

**Required evidence:** An archive-outage test must measure Mongo documents and indexes, Redis, Docker/Nginx logs, temporary files, and local backups minus safe cleanup. Survival calculations must reserve capacity for Mongo journaling, Redis AOF, Docker operations, archive batches, OS stability, and emergency backup. Proposed actions are warning/investigation at 60%, critical alert plus suspension of nonessential jobs at 75%, and controlled ingestion backpressure at 85%. Evidence intake, MongoDB, Redis, and the archiver are never treated as nonessential; agents must retain rejected/backpressured data in their bounded spools rather than an operator abruptly stopping MongoDB.

## 12. Is every evidence class routed to the correct locked Azure retention boundary?

**Priority:** P0
**Gap type:** Infrastructure proof gap

**Verified state:** The archiver supports duration-aware SIEM/general containers plus fixed PECA 365-day and FBR 2,190-day classes. The existing six-year fallback avoids early deletion but over-retains shorter-lived data.

**Why it matters:** Incorrect routing can either delete evidence too early or retain personal/security data far longer than contracted.

**Question to close:** Have all required private containers been created, tested, locked for the intended duration, and mapped to every SIEM and general environment key used by routing before routing is enabled?

**Required evidence:** One bounded archive/readback test per retention class proving tenant, evidence class, physical container, locked duration, SHA-256, ledger, record count, authorized readback, deletion of only exact committed Mongo IDs, and preservation of unrelated IDs. Missing or unsupported duration mapping must use only an explicitly approved longer locked fallback or fail closed. An insufficient/unlocked container must fail archival and preserve Mongo data. Retrieval staging and database-backup containers must remain separate and must not inherit evidence-WORM settings that prevent their intended expiry.

## 13. Can WarSOC recover tenant state and operations within an approved RPO/RTO?

**Priority:** P0
**Gap type:** Disaster-recovery operating decision and final-host proof

**Verified state:** Encrypted Mongo backups and an isolated restore drill exist. Azure evidence archives are correctly treated as evidence, not as complete database backups. Final HostKey backup generation and restoration have not been proved.

**Why it matters:** Losing Mongo loses tenant accounts, users, agent registrations, incident workflow, configuration, and archive metadata even when evidence blobs remain intact.

**Question to close:** What are the business-approved backup frequency, backup retention, recovery point objective, recovery time objective, key custody, and blank-host restore procedure? A proposed `RPO 24 hours / RTO 8 hours` must not become contractual until management accepts the possible loss of one day of tenant, agent, incident, configuration, and ledger state.

**Required evidence:** Begin from a blank replacement host, install the exact approved release, restore secrets through approved custody, restore and verify a HostKey-generated encrypted Mongo backup, recreate or restore only required Redis state, start services, validate indexes, tenants, login, agent continuity/re-enrolment policy, archive ledger and Azure access, and measure elapsed recovery time. Redis keys/streams must be classified as reconstructable or backup-required; otherwise Mongo-only recovery is incomplete.

## 14. Do tenant isolation, RBAC, incidents, reports, and invitations behave correctly as one customer workflow?

**Priority:** P0
**Gap type:** Integrated authorization proof gap

**Verified state:** Backend role checks distinguish admin, manager, analyst, and auditor. Evidence routes are tenant- and entitlement-scoped; incident closure requires notes; invitation tokens are one-time and pending users cannot log in. A final deployed browser workflow is still an acceptance item.

**Why it matters:** Individually correct endpoints can still form an over-privileged or broken workflow when combined through the frontend.

**Question to close:** Can each role perform only its intended actions across hot evidence, compliance evidence, incident assignment/closure, exports, team management, agent activation, and invitation activation?

**Required evidence:** A backend-enforced role matrix against the final paired deployment. It must cover cross-tenant object reads and incident updates, tenant-ID tampering in query/body, direct auditor API calls, role-specific export restrictions, manager restrictions on activation/team management, disabled-user session reuse, revoked invitation replay, concurrent incident updates, entitlement removal during an active session, archive-metadata isolation, cross-tenant download-link rejection, persisted incident state, HTTP status, and corresponding management-audit records. Frontend button visibility is not authorization evidence.

## 15. Does the accepted production deployment exactly match the frozen candidate?

**Priority:** P0
**Gap type:** Release and migration-control gap

**Verified state:** Local tests and historical DigitalOcean/Vercel acceptance artifacts exist. The compute target is now HostKey, the backend worktree contains uncommitted changes, agent source and published artifact versions differ intentionally, and the migration runbook still requires HostKey normalization.

**Why it matters:** Passing tests on one commit does not prove that HostKey runs it, Vercel calls it, Azure serves the matching installer, or production uses the reviewed environment values.

**Question to close:** After production acceptance, what immutable release record proves that Git, HostKey, Vercel, Azure, the database/index state, and the installer match the candidate frozen by Question 1?

**Required evidence:** First freeze a candidate release, then generate the final immutable manifest only after acceptance. Record backend and frontend commits, clean-worktree state, immutable Docker image digests, database/index migration version, agent and manifest SHA-256, Nginx configuration hash, a sanitized non-secret configuration fingerprint plus required-secret-presence confirmation, Azure account/container identities and retention state, HostKey plan/IP, DNS result, TLS fingerprint/expiry, acceptance run ID, backup/restore result, rollback point, approvers, and timestamp. Never publish a raw `.env.prod` hash as a substitute for sanitized configuration evidence.

---

## Local Candidate Evidence - 2026-08-01

This evidence narrows implementation risk but does not close HostKey or production-only gates:

- `132` service-independent contract tests passed across endpoint signing, incident grouping/redaction, native Windows/FBR/PECA behavior, ingest quotas, SIEM source isolation and rule catalogs, storage archival, bounded hot search, archive-retrieval safety, production Compose contracts, and unsafe stream-trimming prevention.
- The full modified Python tree passed `compileall`.
- Bandit reported zero high-severity findings across `app`, `agent`, and `scripts`.
- A committed-secret pattern scan found placeholders and Compose interpolation only; it found no private key, cloud access key, GitHub token, or Azure account key.
- A retrieval RBAC bypass in the disabled archive-retrieval candidate was found and fixed: managers cannot retrieve FBR/PECA archives, auditors cannot retrieve operational SIEM archives, and compliance archives require the matching current entitlement.
- Direct archive bytes remain outside the API process; the hot dashboard search is exact-match, tenant-scoped, and limited to seven days.

Not counted as proof: the integration test suite could not run locally because Docker/Mongo/Redis were unavailable. The archive API workflow, active stream consumer behavior, full role matrix, final Azure containers, HostKey capacity/fairness, and blank-host recovery therefore remain open exactly as stated above.

---

## Explicitly Out of Scope for These 15 Questions

The following may be future work, but they must not distract from closing the current product:

- Enabling the customer-side firewall/network relay or advertising real-device support.
- Linux endpoint ingestion.
- Packet capture or network payload inspection.
- EDR, antivirus, memory inspection, vulnerability scanning, or patch management.
- DNS, cloud-identity, threat-intelligence, ticketing, Slack/Teams, PagerDuty, or MSSP integrations.
- External attack-surface scanning.
- Self-service payment or public signup.
- Customer self-service archive-retrieval UI while retrieval remains feature-gated. Before historical retrieval is commercially promised, a restricted and tested operator-driven retrieval procedure is mandatory.
- Independent public evidence-verification portal.
- Automatic failover, redundant compute, multi-region active-active, or scaling beyond the approved single-host ceiling. Backup, blank-host rebuild, endpoint spooling, external monitoring, and measured RPO/RTO remain mandatory compensating controls.

These are not silently dismissed. They remain future architecture items and should be reconsidered only after the current 15 questions have dated closure evidence.

## Recommended Closure Order

1. Freeze the candidate release and environment inputs: the opening portion of Questions 1 and 15.
2. Prove Azure retention boundaries and blank-host recovery: Questions 12 and 13.
3. Prove endpoint/source reliability and signed ingestion: Questions 1 through 3.
4. Prove SIEM/FBR/PECA correctness: Questions 4 through 7.
5. Prove queue behavior, tenant fairness, and workflow authorization: Questions 8, 9, and 14.
6. Prove HostKey capacity and Azure-outage survival: Questions 10 and 11.
7. Execute final full acceptance and seal the final Question 15 release manifest.

## Decision Rule

A question is not closed by code existence, a synthetic unit test, or an earlier deployment result alone. Closure requires the specified evidence from the exact release and environment being approved. Any failed result becomes a narrowly scoped implementation item; it does not authorize unrelated feature work.
