# WarSOC FBR and PECA End-to-End Operating Guide

**Date:** 2026-08-24
**Scope:** The implemented Windows endpoint, POS semantic, native SIEM, PECA
evidence, FBR evidence, retention, custody and archive pipelines.
**Boundary:** This is a technical operating guide, not a legal opinion or a
claim that WarSOC is an FBR-licensed integrator.

## 1. System Boundary

WarSOC currently provides two evidence programs on top of one authenticated
ingestion platform:

```text
Windows Security/System events       Approved POS semantic events
              |                                  |
       WarSOC Agent 4.2.9                signed POS envelope
              |                                  |
              +------ authenticated ingestion ---+
                                  |
                    encrypted canonical source evidence
                                  |
                   bounded Redis fan-out and retry state
                    /             |              \
               native SIEM    PECA worker      FBR worker
                    |             |              |
             alerts/incidents  PECA vault      FBR vault
                    \             |              /
                     claims, cases, custody and holds
                                  |
                    verified immutable Azure archive
```

The source event is retained separately from the derived alert or compliance
record. A detector can therefore be retuned without silently changing the
original observation.

## 2. Shared Trust and Failure Rules

1. Agent enrollment binds an Ed25519 public key to one tenant and agent.
2. Agent `4.2.9` signs its event identity, collection time, channel, epoch and
   sequence. Required mode rejects missing, invalid and replayed signatures.
3. The API derives tenant and agent identity from the authenticated token; it
   does not trust identity fields supplied by the body.
4. A canonical encrypted source envelope is committed before its dispatch is
   considered ready.
5. Redis consumer groups isolate SIEM, PECA and FBR processing. One worker does
   not consume another worker's copy.
6. Worker retry and dead-letter behavior is bounded. Missing evidence is shown
   as missing or unverified; it is never converted to a passing result.
7. Mongo evidence is deleted only after Azure upload, byte/hash verification,
   immutability verification, archive-ledger commit and a final legal-hold
   recheck.

## 3. PECA Evidence Program

### 3.1 What it observes

The current PECA pack contains exactly 11 Windows evidence controls:

| Control | Event | Channel | Preserved observation | Important limit |
|---|---:|---|---|---|
| PECA-101 | 4625 | Security | Failed sign-in | Does not prove intent or unauthorized access by itself |
| PECA-102 | 1102 | Security | Security audit log cleared | Does not identify motive without actor/context evidence |
| PECA-103 | 4624 | Security | Successful sign-in | A successful sign-in is not automatically suspicious |
| PECA-104 | 4688 | Security | Process creation | Requires process, command, parent and actor context |
| PECA-105 | 4672 | Security | Administrative privileges assigned | Does not prove privilege abuse by itself |
| PECA-106 | 4720 | Security | User account created | Does not prove the account is rogue |
| PECA-107 | 4726 | Security | User account deleted | Does not prove malicious deletion |
| PECA-108 | 4732 | Security | Member added to local group | Does not prove successful exploitation by itself |
| PECA-109 | 4697 | Security | Service installed | Requires service path, actor and host context |
| PECA-110 | 7045 | System | Service installed | Requires service path, actor and host context |
| PECA-111 | 1100 | Security | Event Log service stopped | Does not prove compromise without supporting evidence |

These controls support endpoint-forensics and authorized investigations. They
do not, by themselves, satisfy PECA section 32 traffic-data retention, prove an
offence, prove attribution, or guarantee court admissibility.

### 3.2 Endpoint prerequisites

- The endpoint must run the accepted WarSOC agent as an automatic Windows
  service.
- The Security and System event channels must be readable by the service.
- Windows audit policy must enable the relevant event family. Event 4688 command
  lines require the Windows process-command-line audit setting.
- Account-management events require account-management auditing.
- Object/FIM events require auditing plus a SACL on the approved protected path.
- A workstation cannot produce domain-controller-only evidence. WarSOC reports
  unsupported coverage instead of inventing it.
- Host time must be synchronized. WarSOC preserves source, collection and
  server-receipt time rather than rewriting an unreliable source timestamp.

### 3.3 Processing flow

```text
Windows XML
  -> bounded XML parser and normalized fields
  -> Ed25519 signed event
  -> POST /api/v1/ingest/pulse
  -> signature, sequence, replay, size and quota checks
  -> encrypted source_envelopes_peca record
  -> raw_logs_queue / eto_group
  -> tenant entitlement and source-assurance checks
  -> canonical record encryption and RSA-PSS sealing
  -> peca_forensic_logs
  -> evidence-state and claim-state evaluation
  -> case/custody/hold/archive paths
```

The native SIEM independently evaluates the same source observation. A SIEM
alert and a PECA evidence record have different purposes and are not duplicates.

### 3.4 PECA retention

- Hot Mongo window: 7 days.
- New PECA evidence: tenant retention entitlement through the matching general archive route.
- Historical PECA records and locked blobs retain their existing recorded obligations and are not automatically migrated.
- Active legal holds override normal deletion.
- Archive failure preserves the Mongo record.
- A 365-day product policy is not a universal legal conclusion for every
  tenant; applicability remains tenant and case specific.

### 3.5 PECA acceptance test

Use an isolated test tenant and a disposable endpoint. For every control:

1. Confirm the required Windows audit policy and channel are healthy.
2. Generate one authorized, reversible test action for the event family.
3. Record the Windows event record ID and UTC time.
4. Confirm a signed source envelope exists for the same tenant, agent and event
   UID.
5. Confirm the native SIEM outcome is appropriate; ordinary activity must not
   be upgraded to an attack solely because the event exists.
6. Confirm one PECA evidence record contains the matching event UID, source
   assurance, evidence state, claim boundary and cryptographic metadata.
7. Confirm wrong-tenant and wrong-role access is denied.
8. Confirm repeated reads do not create duplicate evidence.
9. Confirm the event can be referenced by a case without copying or modifying
   the original.
10. Confirm archive-before-delete and independent package verification in the
    isolated archive drill.

Never stop the Windows Event Log service on a customer machine for a test.
Event 1100 is validated only in a disposable lab or by a controlled synthetic
signed fixture.

## 4. FBR Evidence Program

### 4.1 Current evidence sources

WarSOC currently accepts two independent source classes:

1. **POS semantic evidence:** the approved POS application writes or submits a
   structured `FBR-INV-MOD` or `FBR-INV-DEL` event containing event UID, invoice
   ID, timestamp, actor and source system. Optional reason and before/after
   SHA-256 values improve the evidence.
2. **Windows FIM evidence:** Windows reports access, deletion, permissions or
   database-file modification activity on an explicitly approved POS path.

WarSOC does not auto-discover a POS application. The customer or deployer must
identify the actual POS export/audit directory or database-file path. An empty
POS-path field means FIM coverage is not configured; Windows telemetry and PECA
can still operate.

### 4.2 Current controls

| Control | Event | Source | Preserved observation | Important limit |
|---|---|---|---|---|
| FBR-101 | FBR-INV-DEL | POS semantic | POS reported invoice deletion | Does not prove FBR acceptance or unauthorized intent |
| FBR-102 | FBR-INV-MOD | POS semantic | POS reported invoice modification and fields | Does not prove agreement with DB/FBR truth |
| FBR-103 | 4660 | Windows FIM | Protected object deleted | Does not identify invoice fields or FBR state |
| FBR-104 | 4663 | Windows FIM | Protected-object access relevant to deletion | Does not prove completed deletion by itself |
| FBR-105 | 4670 | Windows FIM | Protected-object permissions changed | Does not prove invoice content changed |
| FBR-106 | FIM-DB-MOD | WarSOC native FIM | Protected database file changed | Does not identify affected rows or FBR acceptance |

`FIM-DB-MOD` is generated only by the trusted native FIM path. The API/worker
rejects an external client trying to claim this internal event directly.

### 4.3 POS semantic flow

```text
approved POS audit output
  -> strict JSONL schema and allowlisted event ID
  -> agent signed nonce/timestamp/payload envelope
  -> POST /api/v1/fbr/pos/ingest
  -> key, signature, timestamp, nonce/replay, size and quota checks
  -> tenant identity derived from agent token
  -> encrypted source_envelopes_fbr record
  -> raw_logs_queue / fbr_group
  -> FBR evidence normalization and sealing
  -> fbr_pos_logs
```

The endpoint JSONL reader accepts only complete lines with required fields and
bounded metadata. Rejected records increment health counters; they are not
silently converted into evidence.

### 4.4 Windows FIM flow

```text
approved protected path
  -> Windows object-access/SACL events and native bounded FIM snapshot
  -> signed endpoint event
  -> authenticated common ingestion
  -> encrypted FBR source envelope
  -> FBR worker correlation/normalization
  -> FBR-103 through FBR-106 evidence
```

FIM proves that a protected file or permissions state changed. It does not know
which invoice row changed. POS semantic evidence, authoritative database audit
evidence and external FBR/integrator status are different truths and must not be
merged by assumption.

### 4.5 Not implemented or enabled

- WarSOC does not submit invoices to FBR.
- WarSOC does not issue FBR invoice/reference numbers.
- WarSOC is not an FBR-licensed integrator.
- No real customer database connector is accepted.
- No licensed-integrator connector is accepted.
- Synthetic POS/DB/external reconciliation code is disabled by default and is
  not a production compliance claim.

### 4.6 FBR retention

FBR evidence is a WarSOC security/evidence product record, not the customer's
statutory tax-record repository. New FBR evidence therefore inherits the same
normal commercial retention entitlement stored in `tenants.retention_days`.

```text
new FBR observation
  -> retention_model = TENANT_ENTITLEMENT_V1
  -> seven-day Mongo operational window
  -> GENERAL_<tenant retention days> archive route
  -> verified immutable Azure archive
```

No product-plan name is embedded in FBR records. The day count is read from the
existing tenant retention architecture and captured at ingest for auditability.
Archive selection uses the tenant's active entitlement, matching general
security evidence. Legal holds still prevent hot deletion.

Historical FBR Mongo records created under the retired tax-period/six-year
model are not rewritten and are excluded from automatic archival by the new
path. Existing Azure blobs and locked policies remain untouched. Any later
historical migration must be an explicit, separately approved operation.

### 4.7 FBR acceptance test

Use a disposable directory, never a live customer database:

1. Configure the directory as an approved POS path during agent installation or
   controlled reconfiguration.
2. Enable the required object-access audit policy and SACL.
3. Create a harmless fixture and establish the initial FIM snapshot.
4. Modify, permission-change and delete separate fixture copies.
5. Create signed `FBR-INV-MOD` and `FBR-INV-DEL` semantic fixtures with unique
   event UIDs and invoice IDs.
6. Confirm each source event is signed, tenant-bound and stored in
   `source_envelopes_fbr` before dispatch.
7. Confirm the six controls are produced only from their allowed source class.
8. Confirm POS semantic and FIM evidence remain separate in UI/report/API.
9. Confirm replay, stale timestamp, invalid signature, unknown event ID,
   external `FIM-DB-MOD`, oversize body and wrong tenant are rejected.
10. Confirm new records contain `TENANT_ENTITLEMENT_V1`, `TENANT_POLICY`, and
    the tenant retention snapshot, with no tax-period or six-year expiry fields.
11. Confirm a too-short Azure policy causes an archive error and zero Mongo
    deletions.
12. Confirm legal hold prevents deletion and produces an audit event.
13. Verify an exported evidence package with
    `scripts/verify_evidence_package.py` outside the API process.

## 5. SIEM, PECA and FBR Separation

| Output | Purpose | Can create incident? | Compliance meaning |
|---|---|---:|---|
| Native SIEM alert | Detect suspicious behavior using context and rules | Yes | Security finding, not a legal conclusion |
| PECA evidence | Preserve selected endpoint observations | Only when an alert rule separately warrants it | Investigation support |
| FBR evidence | Preserve POS semantic/FIM integrity observations | Only when an alert rule separately warrants it | Evidence readiness, not FBR acceptance |

WarSOC groups repeated equivalent alerts in a bounded time window while retaining
their count and source evidence references. A new actor, host, event family,
outcome or correlation context produces a separate incident.

## 6. Roles and Access

- **Admin:** tenant configuration, team access, agent activation, cases, holds
  and permitted evidence operations.
- **Analyst:** operational investigation and incident workflow within tenant
  scope; no platform administration.
- **Auditor:** read/verify/export evidence and custody within allowed policy;
  no destructive administration.
- **Viewer:** read-only dashboard scope; no raw evidence, hold or export powers
  unless explicitly granted by policy.

Every record query is tenant-scoped. Platform administration uses a separate
administrator key boundary and is not a tenant role.

## 7. Operational Acceptance Definition

The FBR/PECA backend is accepted only when one exact backend commit, frontend
commit and agent manifest are recorded; the signed agent is active; source,
dispatch, worker and incident/evidence outputs are correlated by IDs; RBAC and
tenant-negative tests pass; Azure archive-before-delete is proven; and backup
restoration is demonstrated.

Code tests alone prove implementation contracts. They do not prove a customer's
audit policy, POS schema, tax applicability, firewall, Azure policy or legal
interpretation. Those remain deployment/customer acceptance inputs.
