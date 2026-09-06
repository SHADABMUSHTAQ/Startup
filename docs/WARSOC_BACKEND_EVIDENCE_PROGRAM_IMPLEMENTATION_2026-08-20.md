# WarSOC Backend Evidence Program Implementation Ledger

**Date:** 2026-09-06 (updated from the 2026-08-20 implementation close)
**State:** EVIDENCE CASES / LEGAL HOLDS / SIGNED EXPORTS PRODUCTION ACCEPTED
**Scope:** Current backend evidence trust, retention, custody, privacy, export,
authorization, and synthetic FBR reconciliation contracts. The production
acceptance in this document is limited to evidence cases, custody, legal holds,
and signed evidence-package exports. It does not approve historical archive
retrieval, daily anchoring, FBR reconciliation, Wazuh promotion, network-relay
scope, or a customer compliance claim.

## 1. Governing Boundary

WarSOC remains an evidence and security-monitoring platform. It does not become
a POS system, an FBR licensed integrator, a legal authority, or a packet-content
capture product. Missing evidence is never converted into a green result.

The implemented flow is:

```text
authenticated source
    -> canonical encrypted source evidence
    -> bounded durable dispatch
    -> SIEM / PECA / FBR processing
    -> evidence and claim evaluation
    -> tenant-scoped custody/case references
    -> verified immutable archive or signed evidence package
```

## 2. Implemented Source Contracts

| Area | Implemented source behavior | Deployment state |
|---|---|---|
| Endpoint authenticity | Ed25519 event signatures, signed sequence state, signed heartbeat coverage, key ID/version metadata | Agent `4.2.9` is built and manifested; publisher signature, upload, installation and live acceptance remain |
| Source durability | Encrypted canonical source envelopes are committed before Redis dispatch becomes ready | Source implemented |
| Dispatch recovery | Leased idempotent outbox retries without storing a second plaintext payload | Source implemented |
| SIEM privacy | Raw message/data/XML and sensitive command context are field-encrypted before SIEM persistence; authorized detail/export paths decrypt | Source implemented; historical plaintext migration is separate |
| Evidence evaluation | `evidence_state` and `claim_state` are evaluated independently with explicit gaps | Source implemented |
| Authorization intent | Human-reviewed authorization policy is checked against the generated FastAPI route inventory | Source implemented |

## 3. FBR Retention

The active product does not treat WarSOC as the customer's statutory tax-record
repository. FBR POS/FIM monitoring evidence follows the tenant's existing
normal WarSOC retention entitlement.

New FBR evidence records:

```text
retention_model = TENANT_ENTITLEMENT_V1
retention_state = TENANT_POLICY
retention_basis = TENANT_RETENTION_ENTITLEMENT
tenant_retention_days_at_ingest = tenants.retention_days
```

FBR keeps its seven-day Mongo operational window and then uses the existing
duration-aware `GENERAL_<days>` Azure routing used by commercial evidence.
Explicit legal holds still prevent deletion. Historical tax-period records and
already locked Azure evidence are not rewritten, shortened, or automatically
migrated.

## 4. Holds and Archive Fences

Tenant-scoped hold records are explicit and audited. No hold is invented during
ingestion. Event-scoped holds must identify existing tenant evidence in Mongo or
the archive ledger. `ACTIVE` and `PENDING_RELEASE` both block hot deletion.

The dedicated hold worker applies and verifies Azure legal holds on both the
archive JSON object and its SHA companion. A release first becomes
`PENDING_RELEASE`; it becomes `RELEASED` only after all matching archive
bindings are reconciled and the release audit is committed. Pre-existing Azure
holds and protection required by another active WarSOC hold are never cleared.

The archiver:

1. selects a bounded retention cohort;
2. acquires evidence/archive fences;
3. uploads immutable block blobs and hash companions;
4. verifies downloaded bytes, SHA-256, and Azure immutability coverage;
5. writes the archive ledger;
6. rechecks holds and fences immediately before deletion;
7. deletes only the exact verified Mongo records.

Upload, hash, WORM, ledger, hold-race, retention, or dispatch failure preserves
Mongo evidence. Automatic creation or irreversible locking of Azure containers
is disabled; that remains an operator-controlled infrastructure action.

## 5. Cases and Custody

Cases reference original hot evidence by identity and digest. They do not copy or
move evidence. Case items, views, exports, verification, transfers, holds, and
closure are represented by hash-linked custody events.

The state machine includes recovery for:

- a case interrupted during initialization;
- a custody head committed before its event row;
- a case item interrupted between reference creation and custody commit;
- a case closure interrupted after custody commit.

The operator UI supports case creation, hot-evidence attachment, case/item
custody actions, verified closure, package requests, status polling, and
short-lived downloads. A case cannot close empty or with a broken custody chain.

Archived evidence must first use the existing isolated archive-retrieval flow.
It is not silently omitted from a package.

## 6. Daily External Commitment

An optional daily Azure anchor publishes a small deterministic root commitment,
not raw customer evidence. It verifies object bytes and an adequate locked
immutability/legal-hold boundary before recording success.

```text
EVIDENCE_DAILY_ANCHOR_ENABLED=false
```

The feature stays disabled until a private locked container, identity, key
permissions, retention decision, and live failure/retry proof exist.

## 7. Evidence Packages and Export Isolation

The deterministic `warsoc-evidence-package-v1` contains exact stored evidence,
a custody ledger, a canonical manifest, per-file hashes and evidence-record
digests, an RSA-PSS-SHA256 manifest signature, and public verification material.
Private and symmetric keys are never packaged.

`scripts/verify_evidence_package.py` validates a package outside WarSOC and
returns `VERIFIED`, `ALTERED`, `MISSING`, `SIGNATURE_INVALID`, or
`MANIFEST_INVALID`.

Package generation and Azure upload run in an isolated bounded worker with
retry-safe leases. The API creates jobs and issues short-lived read-only HTTPS
SAS links; it does not proxy archive/package bytes through the API container or
local host disk. OCI deployments can use the existing Azure storage account key
to sign a scoped SAS without exposing that key in the URL. User-delegation SAS
remains supported for Azure-managed identities.

The repository default remains `EVIDENCE_EXPORT_ENABLED=false`. The selected
production environment was prepared on 2026-09-06 with a separate private
`warsoc-evidence-exports` container, a distinct RSA-3072 package-signing key,
and `EVIDENCE_EXPORT_ENABLED=true`. Deployment and authenticated browser proof
are still required before this becomes a deployed claim.

The existing archive-retrieval workflow remains asynchronous and separate.
Cold evidence returns `REQUIRES_ARCHIVE_RETRIEVAL` before packaging.

## 8. FBR Reconciliation Boundary

The source contains a disabled contract/lab reconciliation engine for POS, DB,
and external-integrator observations. It separates exact raw SHA-256 from a
deterministic semantic fingerprint and supports:

```text
MATCHED
MISMATCH
REJECTED
PENDING
MISSING_LOCAL
MISSING_EXTERNAL
UNVERIFIED
```

Duplicate, replayed, missing, or unverified data never becomes green. This is
synthetic contract proof only:

```text
FBR_RECONCILIATION_ENABLED=false
```

No customer DB connector or licensed-integrator connector has been implemented
or accepted. Those require one real POS schema and an authorized integrator
environment before engineering proceeds.

## 9. Authorization and Route Inventory

`docs/WARSOC_AUTHORIZATION_POLICY.json` records intended authentication, roles,
tenant scope, public routes, platform administration, service identities, and
feature gates. `scripts/generate_api_security_inventory.py` derives the actual
FastAPI implementation inventory.

The two artifacts are tested against each other. The current generated
inventory contains 132 routes and zero manual-review classifications. This is a
source-level policy proof, not a substitute for production BOLA/IDOR testing.

## 10. Configuration Defaults

Repository defaults remain fail-safe. The selected production environment may
enable an accepted capability only when its required configuration is present:

```text
EVIDENCE_DAILY_ANCHOR_ENABLED=false
EVIDENCE_EXPORT_ENABLED=false  # repository default; selected production config is true
FBR_RECONCILIATION_ENABLED=false
NETWORK_RELAY_ENABLED=false
WAZUH_DETECTION_MODE=disabled
WAZUH_BRIDGE_ENABLED=false
```

Production must supply stable managed keys, private pre-created containers,
least-privilege identities, resource limits, monitoring, and rollback evidence
before any disabled capability is enabled.

## 11. Acceptance Boundaries

### Proven locally in source

- tenant-entitlement FBR retention and legacy-record isolation;
- hold extension and hold/delete race refusal;
- bounded archive cohorting and WORM verification contracts;
- SIEM sensitive-field protection and authorized readback;
- case/custody crash recovery;
- empty/tampered-case closure refusal;
- Azure legal-hold application, retry, release, and concurrent/pre-existing hold preservation;
- signed package verification and tamper detection;
- isolated export lease/recovery behavior and scoped shared-key SAS generation;
- deterministic daily anchor behavior;
- synthetic FBR reconciliation outcomes;
- route inventory and authorization-policy agreement.

### Still requires separate proof

- live Azure daily-anchor and historical-retrieval validation;
- 4.2.9 Authenticode/CDN/installation acceptance (local build and manifest are complete);
- historical SIEM privacy migration decision;
- real POS DB and licensed-integrator connectors;
- frontend support for historical retrieval states;
- destructive backup/restore and failover acceptance on the final host.

## 12. Final Local Validation

The complete maintained local backend campaign passed on 2026-08-20:

```text
Focused evidence/retention/custody/privacy/export/security: pass
Detection/security/relay/Wazuh-boundary/archive/deployment: pass
Complete maintained pytest suite: 523 passed, 1 skipped, 44 warnings (175.31s)
Python compileall: pass
Docker Compose production configuration: pass
Generated API inventory: 121 routes, 0 manual-review routes (2026-08-20 snapshot)
git diff --check: pass
Bandit high-severity scan over app/agent/scripts: 0 findings
pip check: pass
pip-audit: no known vulnerabilities
Local CI connectivity: Redis pass, Mongo pass, API health pass
```

The skipped test is the explicitly opt-in destructive grand E2E boundary in
`tests/test_grand_master_e2e.py`; it requires `E2E=1`. Warnings are FastAPI
ORJSON and test-only `datetime.utcnow()` deprecations, not failed assertions.

This result accepted the source regression boundary only. The scoped production
acceptance below does not grant whole-platform `BACKEND_ACCEPTED`; destructive
backup/recovery, disabled capabilities, and unrelated external gates remain open.

### 2026-09-06 evidence-governance delta

```text
Focused custody/hold/export/archive/deployment tests: 66 passed
Production Compose validation: pass
Private Azure export container: created and public access disabled
Package signing key: generated separately; private material not logged
Live Azure package lifecycle: upload, SHA readback, scoped SAS download,
offline signature verification, expiry, and blob deletion passed with synthetic test data
Frontend evidence contracts: 13 passed
Frontend ESLint and production build: pass
Complete maintained backend suite: 644 passed, 1 skipped, 28 warnings
Generated API inventory: 132 routes, 0 manual-review routes
Bandit high-severity findings: 0
pip-audit: no known vulnerabilities
pip check and git diff --check: pass
```

### 2026-09-06 production acceptance

Executable backend revision `9974df6` is active on OCI at
`/opt/warsoc/releases/9974df6`. The API, unified worker, archiver,
evidence-export worker, and evidence-hold worker all reported `running`, zero
restarts, and the exact revision label. Public health reported healthy MongoDB
and Redis dependencies; the API, export worker, and hold worker had no matching
critical errors in the final observation window.

Production acceptance run
`EVIDENCE-ACCEPTANCE-20260906T043509Z-c9b91a9d` passed with isolated synthetic
data. It proved authenticated admin/auditor behavior, second-tenant isolation,
case creation and attachment, custody-chain verification, closure RBAC, legal
hold apply/reconcile/release, hot-evidence retention blocking, asynchronous
export, private Azure upload, SHA-256 readback, short-lived read-only SAS
download, and offline RSA-PSS package verification. The run removed its MongoDB
and Azure test artifacts; the final residual synthetic-user count was zero.

The production defect found during acceptance was a non-root export worker that
could not write to a root-owned `/tmp` tmpfs. Revision `9974df6` assigns that
bounded tmpfs to UID/GID 1000 and adds worker exception logging. The focused
deployment contract passed after the correction, and a direct runtime write
probe plus the complete production workflow both passed.

The frontend `e7c5aa0` is live from `origin/main`; its production build points to
`https://api.warsoc.tech/api/v1`, exposes Evidence Cases and Legal Holds, and
enables evidence export. The production workflow was exercised through the
public authenticated API. A human browser click-through is useful UX evidence,
but it is not an open backend correctness gate.
