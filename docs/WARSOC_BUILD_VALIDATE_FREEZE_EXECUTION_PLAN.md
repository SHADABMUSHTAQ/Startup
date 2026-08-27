# WarSOC Build, Validate, and Freeze Execution Plan

**Status:** Approved operating sequence
**Approved:** 2026-08-12
**Scope authority:** `WARSOC_CURRENT_IMPLEMENTATION_AND_FUTURE_SCOPE.md`
**Purpose:** Finish the selected WarSOC release without confusing implemented,
lab-proven, release-candidate, and production-proven states.

## 1. Frozen Scope

The target release contains:

- tenant provisioning, authentication, RBAC, and team access;
- Windows Agent and signed ingestion;
- WarSOC-native SIEM, grouped incidents, reports, and dashboard;
- FBR invoice evidence and configured protected-path monitoring;
- PECA 11-control evidence profile;
- Mongo hot storage, Azure immutable archival, and backup/recovery;
- Wazuh two-host shadow detection, WarSOC reconciliation, and only individually
  approved rule families;
- WarSOC Relay with pfSense as the first physically accepted firewall;
- endpoint/firewall correlation into one WarSOC incident;
- sold Azure retention classes;
- historical retrieval only when included in the launch contract.

The release does not add Linux/macOS agents, full EDR, packet capture, TLS
decryption, broad vulnerability scanning, expanded whole-host FIM/SCA, new SaaS
integrations, HA/multi-region, additional firewall vendors, or unrelated modules.

## 2. Non-Negotiable Ownership Boundaries

1. WarSOC owns tenants, RBAC, evidence, incidents, severity, retention, reports,
   response, FBR, and PECA.
2. Wazuh is a replaceable private detection subsystem. It initially produces only
   shadow observations.
3. Wazuh output is interpretation, not canonical FBR or PECA evidence.
4. The Relay accepts metadata-only firewall syslog on the customer LAN and sends
   signed HTTPS batches to WarSOC. No packet payload or general PCAP is collected.
5. Both detectors may contribute observations, but the customer receives one
   normalized WarSOC incident.
6. Tenant identity always comes from authenticated WarSOC state, never from an
   endpoint, relay, Wazuh, query, or request payload assertion.

## 3. Candidate Evidence Record

Every serious validation run must identify one reproducible candidate. Record:

```text
candidate name
backend commit
frontend commit when applicable
clean/dirty worktree state
Docker image digests
sanitized configuration fingerprint
database/index migration state
agent version and SHA-256
relay version and SHA-256 when applicable
Wazuh version
Wazuh registry/ruleset SHA-256 when applicable
Azure account/container identity when applicable
test run ID and artifacts
result and unresolved findings
rollback point
reviewer and timestamp
```

Candidate names may follow:

```text
warsoc-core-rc1
warsoc-wazuh-shadow-rc1
warsoc-relay-pfsense-rc1
warsoc-fullstack-rc1
warsoc-prepentest-rc1
warsoc-v1.0.0
```

Names may change, but unidentified or dirty candidates may not advance.

## 4. Official Execution Sequence

### Step 1: Freeze Scope

**Goal:** Prevent feature drift.

**Exit gate:** Section 1 is accepted. Any new capability is deferred unless it fixes
a proven security, correctness, or operational blocker within this scope.

### Step 2: Reconcile and Split Git Work

**Goal:** Recover a reviewable repository without losing work.

Actions:

- fetch and inspect the one remote commit currently ahead;
- preserve the dirty worktree;
- separate core fixes, agent, Wazuh, relay, retrieval/storage, tests, and documents
  into reviewable commits;
- verify every deployable file is Git-tracked;
- establish a rollback branch/tag before rebasing or merging;
- run committed-secret and diff checks.

**Exit gate:** Clean worktree, reviewed history, no lost files, and an identified
baseline commit.

### Step 3: Create the Baseline Candidate

**Goal:** Give core acceptance a reproducible identity.

**Exit gate:** `warsoc-core-rc1` or equivalent record contains the fields in
Section 3 and all candidate services remain disabled unless they are under test.

### Step 4: Accept Current WarSOC Core

Prove the complete current path:

```text
tenant provisioning
-> role-specific login and invitation activation
-> agent activation and service
-> signed telemetry
-> Redis admission and independent consumers
-> SIEM evidence and grouped incident
-> PECA evidence
-> FBR invoice and configured-path evidence
-> reports
-> archive transaction
-> encrypted backup and isolated restore
```

Required tests include cross-tenant attempts, direct API RBAC, malformed/replayed
requests, duplicate delivery, Redis/Mongo interruption, worker recovery, bounded
queries, archive-before-delete, and exact-ID deletion.

**Exit gate:** Core acceptance matrix passes against one candidate. Open audit-policy
and SIEM raw-evidence privacy decisions are closed or explicitly block release.

### Step 5: Qualify the Windows Agent

Use `4.2.8-Native-Signed` only if the exact binary passes:

- build dependency gate;
- manifest and Azure object SHA-256 identity;
- Microsoft Defender scan/hash review with Defender enabled;
- clean-machine install and enrollment;
- required Ed25519 ingestion and invalid/unsigned rejection;
- native Security/System collection;
- POS JSONL and configured-path behavior;
- malformed XML rejection;
- 500 MiB spool bound, watermark safety, outage/restart/replay recovery;
- automatic service recovery and dashboard health.

If it fails, retain the accepted 4.2.6 artifact and fix 4.2.8 in another candidate.

**Exit gate:** One published agent and manifest are tied to the candidate record.

### Step 6: Prove Wazuh Two-Host Shadow Transport

**Goal:** Prove transport and trust boundaries before detection expansion.

Required path:

```text
canonical WarSOC evidence
-> minimized allowlisted projection
-> durable encrypted dispatch
-> private mTLS
-> Wazuh 4.14.7
-> canary match
-> signed candidate return
-> WarSOC dispatch/tenant/registry validation
-> shadow observation only
```

Test tamper, stale/replayed requests, unknown dispatches, wrong connector/rule/version,
oversized bodies, Wazuh outage, bridge restart, alert-file rotation/truncation,
spool saturation, receipt loss, health/loss reporting, and recovery.

**Exit gate:** Two-host canary and all failure cases pass. No customer incident is
created by Wazuh.

**Execution record - 2026-08-12:** The isolated local equivalent passed from
canonical evidence through minimized encrypted dispatch, mutual TLS, Wazuh
4.14.7 rule `100500`, signed candidate return and one shadow observation. A
forced manager outage plus bridge restart preserved the accepted dispatch and
recovered automatically. Live transport checks rejected replay, tampering,
wrong connector identity, oversized bodies and missing client certificates.
The resulting counts were one shadow observation and zero customer incidents,
security alerts, FBR records, PECA records, emails or block actions.

This exposed and fixed one real compatibility defect: current HTTPX requires an
explicit client `SSLContext` for the certificate chain used by this connector;
the previous certificate tuple did not complete mTLS. The focused Wazuh suite is
now 32 passing contracts and the selected cross-system compatibility suites are
152 passing contracts.

The formal exit gate is **not closed**. On 2026-08-13 the separate Compute-B
host was reached through Tailscale and its manager, indexer and dashboard were
confirmed at 4.14.7 with loopback-only host bindings. The private listener is
restricted to bridge IP `172.19.0.50`, rule `100500` is present, and
`wazuh-analysisd -t` exits zero. Reviewed code-only staging and short-lived
identity preparation pass, but the encrypted connector-secret transfer and the
same signed canary/failure matrix still require explicit acceptance and
execution over the physical two-host path. Local and baseline proof do not
substitute for that transport/topology proof.

### Step 7: Implement and Validate Dual-Detector Reconciliation

**Goal:** Allow both engines to contribute without duplicating incidents.

The reconciliation contract must:

- normalize WarSOC and Wazuh observations;
- resolve tenant from WarSOC dispatch/evidence state;
- preserve engine, rule, version, confidence, MITRE, and evidence provenance;
- group equivalent behavior by tenant, endpoint/device, target, and bounded time;
- create one WarSOC incident with multiple internal observations;
- keep immutable evidence event-granular;
- preserve WarSOC severity, suppression, workflow, RBAC, and retention;
- retain immediate WarSOC-native fallback.

**Exit gate:** Corpus tests prove one correct incident under duplicates, retries,
reordering, and simultaneous matches.

### Step 8: Promote Wazuh Rules One Family at a Time

For each proposed family, measure:

- required source and fields;
- malicious true positives;
- benign false positives;
- misses relative to WarSOC;
- latency and queue loss;
- analyst context and evidence linkage;
- CPU, RAM, disk, and Wazuh index growth;
- tenant separation;
- MITRE mapping quality;
- rollback behavior.

Possible decisions are `shadow`, `WarSOC-primary`, `Wazuh-primary`, `both-enrich`,
or `disabled`. A successful canary does not approve a detection family.

**Exit gate:** Registry contains only reviewed rules and every promoted family has
a signed decision/evidence record.

### Step 9: Accept the pfSense Relay

**Goal:** Make one firewall model supportable before claiming multiple vendors.

Prove:

- exact Windows Relay build and manifest;
- service installation, dedicated account/ACL, DPAPI identity, restart, upgrade,
  uninstall, Defender, and dead-key recovery;
- pfSense metadata-only syslog configuration and NTP;
- allowed source/device mapping and wrong-source rejection;
- UDP/TCP framing as offered;
- allow/block/authentication records supported by the selected pfSense logs;
- malformed messages and unknown actions fail conservatively;
- duplicate prevention and clock-skew handling;
- per-device/global EPS limits, loss reporting, evidence/control spool behavior;
- LAN/API/internet outage and FIFO recovery;
- daily bytes, disk growth, latency, and storage cost.

Fortinet, Cisco ASA, and MikroTik remain parser candidates until separately accepted.

**Exit gate:** pfSense receives an explicit supported-version matrix and rollback
procedure. `NETWORK_RELAY_ENABLED` remains false for all other tenants.

### Step 10: Prove Endpoint and Firewall Correlation

Test same-tenant/same-host scenarios with correct chronology, including repeated
network activity followed by authentication and suspicious endpoint behavior.

Verify:

- correct tenant, endpoint, firewall/device, source, target, and timestamps;
- no cross-tenant/cross-host joins;
- no duplicate customer incidents;
- original endpoint and network evidence references remain separate;
- correct severity and internal detector provenance;
- stale/out-of-order events do not create false attack chains.

**Exit gate:** One WarSOC incident accurately represents each accepted scenario.

### Step 11: Validate FBR and PECA Enrichment

Wazuh and firewall context may strengthen investigations but cannot replace evidence.

Test examples:

- PECA authentication evidence plus a validated password-spray interpretation;
- account creation, privilege change, and suspicious process sequence;
- FBR protected-path deletion plus PowerShell/privilege/audit-clearing context.

**Exit gate:** FBR/PECA records remain authoritative and independently verifiable;
the incident links context without relabeling Wazuh output as compliance evidence.

### Step 12: Provision and Prove Sold Azure Retention Classes

Create only approved private evidence containers:

```text
90-day SIEM/general
180-day SIEM/general
270-day SIEM/general
360-day SIEM/general
PECA through the matching tenant-duration general route
```

New FBR evidence uses the matching general tenant-retention class. No active
FBR-specific six-year container is required. Historical locked evidence remains
under its original Azure policy.

Test each policy unlocked, then lock it. Configure environment routing only after
every referenced container exists and has the required locked duration.

For each configured class prove event -> Mongo -> blob -> SHA-256 -> immutability
-> ledger -> exact Mongo-ID deletion -> authorized readback. An unlocked/short container must
fail closed and preserve Mongo.

**Exit gate:** Physical container behavior matches every sold retention promise.

### Step 13: Complete Historical Retrieval Only If Sold

If the launch contract promises monthly historical access, prove:

- one-job/10-GiB atomic monthly allowance and approval path;
- private staging container with three-day lifecycle cleanup;
- least-privilege managed identity/service principal;
- Azure server-side rehydration/copy without API or local-disk proxying;
- `REQUESTED/PENDING_REHYDRATION/READY/EXPIRED` lifecycle;
- short-lived read-only user-delegation SAS;
- expected SHA-256 verification;
- tenant/RBAC/download isolation;
- frontend request/status/download flow.

If not sold, leave `ARCHIVE_RETRIEVAL_ENABLED=false` and exclude self-service
retrieval from release claims.

### Step 14: Run Disposable Failure Testing

Use an isolated production-shaped environment. Deliberately interrupt Redis,
MongoDB, Wazuh, Azure access, WarSOC API, Relay connectivity, and internet access.
Exercise full spools, malformed input, duplicate/replay input, revoked identities,
wrong tenants, wrong candidates, worker kills, and service restarts.

**Exit gate:** No silent accepted-evidence loss, cross-tenant access, premature
archive deletion, uncontrolled duplicate incident, or unrecoverable queue/spool.

### Step 15: Run Exact-Topology Capacity and Soak Testing

Test 10, 25, then 50 endpoints plus accepted pfSense traffic, Wazuh shadow/approved
rules, archiver, reports, and dashboard reads. Measure Compute A and Compute B
separately; do not treat a colleague laptop as production capacity evidence.

Measure CPU/steal, memory, swap, disk latency/free space, Mongo working set and
query p95/p99, Redis memory/lag/oldest pending, API p95/p99, detection latency,
Wazuh latency/index growth, relay spool growth, archive duration/backlog, Docker
logs, and tenant fairness.

**Exit gate:** Measured operating limits and upgrade triggers are approved. The
existing 50-agent/3-GiB-day values remain ceilings, not guaranteed capacity.

### Step 16: Freeze the Pre-Pentest Candidate

Create `warsoc-prepentest-rc1` or equivalent. No feature changes are allowed after
this point. Record the complete Section 3 manifest and deployment topology.

**Exit gate:** External testers receive the exact immutable candidate and scope.

### Step 17: Pentest, Fix, Regress, and Freeze Production

1. Test tenant isolation, RBAC, sessions/invitations, signing, relay/Wazuh mTLS,
   secrets, retrieval/archive authorization, rate limits, malformed input, replay,
   network boundaries, and dependency/container posture.
2. Classify and remediate findings on a new candidate.
3. Rerun affected tests plus the complete maintained regression and acceptance suite.
4. Repeat targeted security validation where fixes changed the attack surface.
5. Create `warsoc-v1.0.0` only after all release gates pass.
6. Deploy the exact accepted artifacts and perform post-deploy parity/health checks.

**Final exit gate:** The production manifest proves Git, frontend, compute, database,
Azure, agents, relay, Wazuh, configuration, tests, rollback, and deployed behavior
all match the accepted release.

## 5. Release Completion Definition

The target release is complete only when the following selected items are green:

```text
CORE
tenant/RBAC, agent, signed ingestion, SIEM, incidents, FBR, PECA,
reports, archive, backup/restore

DETECTION
two-host Wazuh shadow, reconciliation, approved rule families,
measured detection quality, WarSOC-native fallback

NETWORK
pfSense Relay service acceptance, metadata evidence,
endpoint/firewall correlation, tenant/device isolation

COMMERCIAL STORAGE
sold retention classes, retrieval only if promised

OPERATIONS
failure recovery, exact-topology capacity, observability, rollback

SECURITY
immutable pre-pentest candidate, findings remediated, full regression,
final deployed-release parity
```

Passing source tests alone does not satisfy this definition.

## 6. Current Starting Point

As of the 2026-08-12 Step 6 local execution:

- the reconciled candidate is based on commit `f9d27fa`; only the surgical mTLS
  compatibility fix and its contract test are uncommitted;
- 184 selected current-tree contracts pass: 32 focused Wazuh contracts and 152
  cross-system backend, relay, quota, archive, security, incident, FBR and PECA
  contracts;
- production Compose renders with optional profiles;
- the Wazuh bridge Compose contract renders with example configuration;
- local Wazuh 4.14.7 is loopback-bound, `wazuh-analysisd -t` passes, and the lab
  canary rule hash matches the repository;
- Wazuh remains shadow-only with only the canary registry approved;
- the live isolated local and separate two-host Wazuh paths, outage recovery,
  tenant isolation and negative transport checks pass;
- the Relay remains disabled and pfSense is lab-proven, not customer-supported;
- archive retrieval remains disabled;
- the public 4.2.8 Azure artifact matches the local release manifest; the live
  authenticated redirect and clean-machine lifecycle remain deployment gates.

The remaining Step 6 gates are physical capacity/saturation evidence, ruleset
rollback and representative rule-family quality. Do not enable primary mode
until those records are accepted.
