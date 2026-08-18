# WarSOC 90-Day Backend Evidence Plan Review

**Status:** reviewed target plan; not an implementation-complete claim  
**Date:** 2026-08-15  
**Applies to:** the current Windows-only WarSOC backend, agent, SIEM, FBR, PECA, Azure archive, disabled network relay, and disabled Wazuh candidate boundary

## 1. Decision

The proposed direction is valid, but it is not safe to execute as one large change.
WarSOC must preserve the current working pipeline while adding evidence controls in
small, reversible phases with explicit exit gates.

The target remains:

```text
signed source telemetry
  -> bounded authenticated ingestion
  -> canonical tenant-scoped persistence
  -> WarSOC SIEM / PECA / FBR processing
  -> seven-day hot operations
  -> verified archive-before-delete
  -> private immutable Azure evidence
  -> isolated historical retrieval
  -> independently verifiable evidence package
```

Wazuh and the network relay remain disabled candidates. They are not production
dependencies for the current Windows agent, SIEM, PECA, FBR, archive, or incident
workflows.

## 2. Scope Lock

### Current-system work allowed now

- Correct current API/report/archive contracts.
- Fix bounded, tenant-scoped operational defects.
- Improve release, security, backup, and archive verification.
- Document and test existing Windows SIEM, PECA, FBR, retention, and RBAC behavior.
- Keep feature gates closed for unaccepted candidates.

### Major work requiring a separate approval

- Tax-period-aware FBR retention and legal holds.
- Evidence cases, custody chains, and independent package verification.
- Database and licensed-integrator FBR connectors.
- Wazuh shadow deployment or rule promotion.
- Customer firewall/network-relay production rollout.
- Historical archive self-service.
- Key-vault migration or historical SIEM field-encryption migration.

### Out of scope for this plan

- Linux endpoint collection.
- Packet payload or PCAP collection.
- Wazuh agents on customer endpoints.
- Wazuh Active Response.
- Public UDP syslog into the WarSOC cloud.
- MDM, IMEI, SIM, threat-intelligence, SOAR, or POS replacement features.
- Claims that WarSOC is an FBR licensed integrator or guarantees blanket PECA/FBR compliance.

## 3. Current Truth

| Area | Current truth | Boundary |
|---|---|---|
| Windows agent | Signed native Windows telemetry and bounded local spool exist. | Installer publisher signing remains open. |
| SIEM | WarSOC's own worker/catalog is authoritative. | Detection quality still requires ongoing noise and false-positive review. |
| PECA | Eleven WarSOC evidence controls exist. | They support investigations; they are not automatic legal-compliance declarations. |
| FBR | POS semantic events plus Windows FIM exist. | FIM cannot infer invoice business fields, and no DB/integrator truth source exists yet. |
| Hot data | Core evidence is operationally targeted for seven days in MongoDB. | Failed archival retains Mongo data and may increase disk use. |
| Azure | Archive-before-delete, hash, ledger, and immutability checks exist. | Current shared 2,190-day lock over-retains shorter classes. |
| Historical reads | Metadata-only discovery and an isolated retrieval design exist. | Self-service retrieval is disabled and not production-accepted. |
| Network relay | Feature-gated code and pfSense lab evidence exist. | No customer appliance or packaged service acceptance; production remains disabled. |
| Wazuh | Minimized encrypted outbox/candidate foundation and lab evidence exist. | No customer detection authority; production remains disabled. |
| Frontend | Current report, lint, and build are useful candidate evidence. | It is not authenticated browser, RBAC, download, accessibility, or performance acceptance. |

## 4. Immediate Current-Release Closure

### 4.1 Release identity

Freeze one backend commit, one frontend commit, one installer version/hash, one
ruleset hash, and the exact production environment checksum. After deployment,
prove that the running API, worker, frontend assets, and Azure artifact match the
frozen release.

### 4.2 Database startup must fail visibly

`app/db/init_db.py` currently catches the top-level initialization failure and logs
it without re-raising. That permits the API to become healthy while required
indexes or migrations may be incomplete. This is a major current-system issue.

Required design before a code change:

1. Separate required startup indexes from optional/backfill maintenance.
2. A required-index failure prevents API readiness.
3. A long backfill reports `DEGRADED` and runs outside request startup.
4. Startup is idempotent and does not rebuild equivalent large indexes.
5. Acceptance deliberately injects an index failure and proves readiness stays closed.

### 4.3 Installer download

The correct contract is:

```text
Admin -> create one-time activation code
Admin -> authenticated GET /api/v1/agent/download
API   -> 307 redirect to versioned HTTPS Azure .exe
Azure -> installer bytes
Client verifies release manifest/hash
```

Do not proxy installer bytes through FastAPI and do not make the Azure evidence
account public. The installer artifact account is separate. The remaining proof is
an authenticated browser click against the deployed release. A UI failure must
show a generic actionable error without exposing backend configuration details.

### 4.4 Normal reports versus historical retrieval

Normal CSV/PDF and evidence-list APIs are hot-tier operations. They must not load
cold Azure blobs into the API process.

```text
Normal list / CSV / PDF -> bounded hot Mongo data + archive availability metadata
Historical request      -> request ledger -> isolated worker -> Azure staging
                        -> short-lived user-delegation SAS -> browser downloads from Azure
```

This supersedes older statements that ordinary CSV/PDF automatically merge all
multi-year Azure evidence.

## 5. Phase Sequence and Exit Gates

### Phase A - Days 1-10: freeze and prove the current release

Work:

- Generate the internal FastAPI route/RBAC/tenant/limit inventory.
- Close the required-index readiness defect.
- Prove installer redirect, login, invitations, agent enrollment, signing, hot search,
  SIEM, all 11 PECA controls, current FBR paths, reports, archive ledger, and backup restore.
- Record exact resource use and query plans.

Exit gate:

- No required startup migration can fail while health remains green.
- No cross-tenant or wrong-role read/write succeeds.
- No report or API request materializes cold blob bytes.
- Deployed identities match the frozen release.

### Phase B - Days 8-25: design FBR retention, do not guess it

The current 2,190-day policy is a conservative fallback. The target calculation is
six calendar years from the applicable tax-period boundary, plus any valid hold.
It must not be implemented from ingestion date alone.

Target fields:

```text
tax_regime
tax_period_id
tax_period_start
tax_period_end
retention_basis
base_retention_until
legal_hold
proceeding_hold
effective_retention_until
retention_state
retention_calculation_version
```

Rules:

- If the tax period cannot be established, mark `UNRESOLVED` and do not delete.
- Legal/proceeding hold extends retention and is independently audited.
- Existing immutable blobs keep their original lock.
- A Pakistan-qualified legal/tax reviewer must approve the calculation and claims.

Exit gate:

- Boundary tests cover leap years, period end, timezone, late ingestion, correction,
  unresolved period, hold application/release, and no early deletion.

### Phase C - Days 12-28: choose the Azure immutability model

Do not blindly create and lock a new `warsoc-fbr-2190` container as the final FBR
design. Evaluate container-level duration classes against version-level policies.

Version-level WORM requires blob versioning, has account/billing implications,
cannot be used with hierarchical namespace, and has irreversible migration choices.
Legal-hold audit behavior also differs from container-level policy.

Required decision record:

- Storage account type, region, versioning, soft-delete interaction, lifecycle rules.
- Container-level versus version-level policy by data class.
- Exact RBAC identities for writer, verifier, retrieval worker, and operator.
- Azure Activity/resource log retention for policy and hold changes.
- Cost model for write, version, archive, rehydration, retrieval, and egress.

Exit gate:

- Harmless test data proves upload, policy properties, hash, readback, ledger, hold,
  expired-object behavior, and fail-closed Mongo deletion before any policy is locked.

### Phase D - Days 15-35: custody and legal hold

Target collections:

```text
evidence_cases
evidence_case_items
legal_holds
evidence_custody_events
evidence_exports
```

Cases reference immutable evidence; they never move or rewrite it. Custody actions
record actor, role, reason, UTC time, request ID, previous hash, and current hash.

Exit gate:

- Cross-tenant case references fail.
- Holds prevent deletion in both Mongo/archive workflows.
- Custody tampering is detected.
- Hold release requires explicit authorized review and preserves history.

### Phase E - Days 20-40: independent evidence package and crypto/time lifecycle

Create a deterministic manifest and an offline verifier. The verifier must produce
`VERIFIED`, `ALTERED`, `MISSING`, `SIGNATURE_INVALID`, or `MANIFEST_INVALID`
without trusting the running WarSOC API.

Add key identity/version lifecycle and preserve source, collection, and server receipt
times. Clock health is evidence context; original timestamps are never rewritten to
hide drift.

Exit gate:

- A clean package verifies offline.
- One-byte, missing-file, reordered-manifest, wrong-key, and clock-drift cases fail visibly.
- Rotated keys continue to verify/decrypt retained evidence.

### Phase F - Days 25-45: PECA legal mapping cleanup

Keep the existing worker and eleven controls. Add legal reference, evidence purpose,
mapping type, applicability, required telemetry, claim boundary, and retention basis.

Exit gate:

- Each control states what was observed, what telemetry was required, and what it
  cannot prove.
- Missing telemetry produces `NOT OBSERVED` or `UNVERIFIED`, never a green claim.

### Phase G - Days 40-78: FBR truth expansion and reconciliation

This is major future work and needs separate approval.

1. Choose one real pilot database engine.
2. Add a read-only, parameterized, bounded connector with incremental watermarks.
3. Add one licensed-integrator external-status connector.
4. Preserve both exact-byte SHA-256 and normalized semantic fingerprint.
5. Reconcile POS semantic, Windows FIM, DB transaction, and external submission evidence.

Outcomes are `MATCHED`, `MISMATCH`, `REJECTED`, `PENDING`, `MISSING_LOCAL`,
`MISSING_EXTERNAL`, or `UNVERIFIED`. Missing data never becomes green.

Exit gate:

- Replay, duplicate, outage, late response, rejection, mismatch, compromised identity,
  and read-only DB permission tests all pass.
- WarSOC observes; it does not submit invoices as a licensed integrator.

### Phase H - Days 80-90: destructive backend acceptance

Run failure tests for agent disconnect/replay/impersonation/spool limit/clock rollback,
Redis/Mongo/worker failure, poison records, FBR source disagreement, tenant/RBAC/IDOR,
archive failure/hash mismatch/short policy/hold, package tampering, key mismatch, and
blank-host backup restoration.

The result may be `BACKEND_ACCEPTED` only. Product acceptance additionally requires
frontend and customer-environment acceptance.

## 6. Wazuh Candidate Plan

### Current boundary

- `WAZUH_DETECTION_MODE=disabled`.
- `WAZUH_PRIMARY_APPROVED=false`.
- Services require the explicit `wazuh-detection` Compose profile.
- Only signed Windows and relay-attested network events are eligible.
- Projection fields are allowlisted; invoice/POS payloads, raw identities, secrets,
  and arbitrary raw messages are excluded.
- Candidate output is validated and stored as `shadow_observation` only.
- Wazuh cannot create PECA/FBR evidence or directly create incidents.

### Required test plan before shadow mode

1. Pin Wazuh image/package digest, ruleset hash, decoder hash, and connector release.
2. Keep every Wazuh port private; use mTLS over a private overlay between hosts.
3. Prove one signed canary WarSOC -> outbox -> Wazuh -> alerts file -> WarSOC candidate.
4. Prove tenant-scoped HMAC correlation and cross-tenant canary rejection.
5. Prove duplicate delivery, checkpoint restart, file rotation, Wazuh restart, WarSOC
   restart, network outage, bounded outbox, event expiry, and zero Redis growth.
6. Evaluate each rule family with labeled true/false fixtures and measured precision,
   recall, latency, duplicate rate, and operator usefulness.
7. Prove PECA/FBR continue during forced Wazuh outage.

### Promotion boundary

The current code does not implement customer incident promotion from Wazuh, even if
the configuration string says `primary`. A separate reviewed promotion state machine,
rollback, canary, severity normalization, and shadow acceptance period are required.
Do not enable primary mode until that code and evidence exist.

## 7. Firewall and Network-Relay Candidate Plan

### Current boundary

- `NETWORK_RELAY_ENABLED=false`.
- Cloud UDP syslog is not exposed.
- The customer relay accepts local vendor syslog and forwards authenticated signed
  HTTPS batches.
- Collection is metadata only: addresses, ports, protocol, action, direction, size,
  interface, device/original time, and relay receipt time. No packet payload/PCAP.
- Raw vendor records are encrypted before cloud queue admission.

### Required implementation/acceptance sequence

1. Freeze supported vendor/version/parser combinations.
2. Package and sign the separate Windows relay service; do not hide it inside the
   endpoint service.
3. Prove source allowlist, per-device EPS circuit breaker, bounded evidence/control
   spools, drop-new saturation policy, and signed loss telemetry.
4. Prove pfSense again from clean install, then one real target appliance chosen from
   the actual customer estate. Lab emulation is not hardware acceptance.
5. Prove timestamp/original-time/receipt-time handling and bounded skew-aware correlation.
6. Prove outage, full spool, process kill, power loss, duplicate replay, spoofed allowed
   IP flood, disk reserve, ACL protection, upgrade drain, recovery, and uninstall.
7. Prove dashboard/API relay lifecycle only after backend physical acceptance.

No production claim exists until all gates pass on a named customer-like device.

## 8. Azure Read-Only Verification While Features Stay Disabled

The current release can be checked without changing cloud policy:

1. Read the latest `storage_archives` ledger rows by tenant and collection.
2. Resolve the recorded storage container and blob/version.
3. Read Azure properties only; record policy scope, lock/hold state, tier, size, ETag,
   content MD5 when present, and last modified time.
4. Download one bounded sample directly in the verifier, not through FastAPI.
5. Match exact bytes to the ledger SHA-256 and companion hash blob.
6. Confirm the corresponding Mongo deletion occurred only after a successful ledger.
7. Confirm archiver logs contain no upload, hash, immutability, or deletion failure.

Do not change policies, tiers, containers, lifecycle, or environment routing during
this read-only check.

## 9. Security Release Gate

Every release requires:

- Unit/integration, tenant-isolation, RBAC-negative, BOLA/IDOR, replay, signature,
  parser, size/rate, archive-cross-tenant, and crypto-version tests.
- Bandit, dependency audit, secret scan, lock verification, container scan, and SBOM.
- Exact image digests for release reproducibility after tested digest selection.
- No tracked live `.env`, private key, certificate key, activation code, or backup key.
- Public errors that reveal no file paths, secrets, stack traces, internal hostnames,
  storage names, or dependency topology.
- A publisher-signed installer before enterprise trust claims.

Current supply-chain debt: production images use mutable base/service tags and
`azure-identity` is range-pinned. Change these only with a tested release and rollback,
not as an unreviewed textual patch.

## 10. Contradictions Requiring Decision

1. **FBR retention:** current fixed 2,190-day fallback versus tax-period-aware target.
   Keep the fallback; do not call it the final legal calculation.
2. **Azure policy scope:** duration containers versus version-level WORM. Decide from
   account capabilities, audit behavior, operational complexity, and measured cost.
3. **Report scope:** hot operational reports versus full historical evidence. Historical
   access must remain an isolated asynchronous workflow.
4. **Wazuh primary mode:** configuration validation exists, but promotion authority does
   not. Keep disabled/shadow only until promotion is implemented and accepted.
5. **Network readiness:** pfSense lab proof is not equivalent to customer appliance,
   packaged service, capacity, and failure acceptance.
6. **Frontend completion:** source/build success is not authenticated role, browser,
   accessibility, performance, or download proof.
7. **PECA/FBR wording:** evidence support and retention are not blanket compliance or
   legal conclusions.

## 11. Acceptance Labels

Use only these labels:

- `CODE REVIEWED`: static contract exists.
- `TEST PROVEN`: named automated/isolated test evidence exists.
- `LAB PROVEN`: physical lab evidence exists, but not customer production.
- `DEPLOYED`: exact runtime identity matches the release.
- `PRODUCTION ACCEPTED`: authenticated, operational, resource, failure, and security
  evidence passes in the target environment.
- `DISABLED CANDIDATE`: code exists but is not a customer capability.

Never replace a missing proof with architectural confidence.

## 12. Primary References

- FBR Sales Tax Act current publication: https://download1.fbr.gov.pk/Docs/202586148252375SalesTaxActupdatedupto2025-26.pdf
- FBR STGO 01 of 2026: https://download1.fbr.gov.pk/Docs/2026331133557466STGO01of2026.pdf
- Azure immutable storage overview: https://learn.microsoft.com/en-us/azure/storage/blobs/immutable-storage-overview
- Azure version-level WORM: https://learn.microsoft.com/en-us/azure/storage/blobs/immutable-version-level-worm-policies
- Azure version-scope configuration: https://learn.microsoft.com/en-us/azure/storage/blobs/immutable-policy-configure-version-scope
- Azure archive rehydration: https://learn.microsoft.com/en-us/azure/storage/blobs/archive-rehydrate-overview
- Azure user-delegation SAS: https://learn.microsoft.com/en-us/azure/storage/blobs/storage-blob-user-delegation-sas-create-dotnet

## Final Position

The plan is suitable only when treated as gated architecture work, not as a 90-day
promise that every phase is already supported. The next engineering action is to
close current-release correctness and readiness first. Tax-period retention, custody,
DB/integrator reconciliation, Wazuh promotion, firewall production rollout, and
historical self-service are separate major approvals with their own failure tests.
