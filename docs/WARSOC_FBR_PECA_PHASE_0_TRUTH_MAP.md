# WarSOC FBR and PECA Phase 0 Truth Map

**Status:** Implemented historical baseline; source/retention and later evidence
governance sections are superseded by the P0 closure and backend evidence-program
implementation ledger; deployment acceptance remains separate
**Snapshot:** 2026-08-20
**Scope:** Legal-reference status, evidence meanings, claim boundaries, API
security inventory, and regression protection. This phase does not change
ingestion, retention, archival, Wazuh, relay, or historical evidence.

> **Current retention decision (2026-08-24):** The fixed/tax-period FBR
> retention content below is historical. New FBR evidence follows the tenant's
> normal WarSOC retention entitlement. See
> `WARSOC_FBR_PECA_END_TO_END_OPERATING_GUIDE_2026-08-24.md`.

## 1. Runtime Freeze

Phase 0 preserves these runtime contracts:

| Contract | Preserved value |
|---|---|
| PECA pack ID | `peca_forensic` |
| FBR pack ID | `fbr_pos` |
| PECA controls | 11 existing controls |
| FBR controls | 6 existing controls |
| PECA hot/vault policy at this snapshot | 7/365 days (superseded for new evidence) |
| FBR hot/current fallback policy at this snapshot | 7/2,190 days (superseded) |
| Worker and stream routing | Unchanged |
| Mongo collections and TTL/archive behavior | Unchanged |
| Azure container routing and locks | Unchanged |
| Historical evidence | No migration or rewrite |

This table records what Phase 0 deliberately preserved at the time. The later
P0 evidence-integrity closure supersedes the fixed FBR fallback: current source
marks FBR retention unresolved, removes invented expiry/hold metadata, and
requires a 2,557-day preservation floor until period-aware retention exists.
See `WARSOC_P0_EVIDENCE_INTEGRITY_CLOSURE_2026-08-20.md`.

## 2. Legal Reference Registry

`app/utils/compliance_legal_registry.py` is the source of truth for reference
identity and status. It records official URL, source version, verification date,
instrument status, regime, and scope note. It does not decide tenant
applicability and is not legal advice.

| Reference | Regime | Status | Current use |
|---|---|---|---|
| PECA 2016, current Pakistan Code text | PECA | FINAL | Contextual relevance for endpoint evidence |
| ETO 2002 sections 5 and 6 | Electronic records | FINAL | Integrity and retention qualities |
| Sales Tax Act 1990 section 24 | Sales Tax | FINAL | Future period-aware retention basis |
| Sales Tax Rules 2006 Chapter XIV | Sales Tax | FINAL | Digital-invoice and integrator context |
| STGO 01 of 2026 | Sales Tax | FINAL | Current invoice integration/amendment context |
| S.R.O. 288(I)/2026 | Income Tax | DRAFT | Architecture awareness only; never a final-law claim |

Source hashes are not yet pinned. Registry entries state
`OFFICIAL_URL_VERIFIED_HASH_NOT_PINNED` rather than claiming stronger proof.

## 3. Evidence State and Claim State

These are independent dimensions:

```text
evidence_state
  OBSERVED
  NOT_OBSERVED
  UNVERIFIED
  NOT_APPLICABLE

claim_state
  SUPPORTED
  CONDITIONALLY_SUPPORTED
  UNSUPPORTED
```

An observed Windows event can therefore be `OBSERVED` while its broader legal
claim remains `CONDITIONALLY_SUPPORTED`. The compliance evidence list now
returns both fields plus the control ID, source class, legal-reference IDs, and
claim boundary.

## 4. PECA Evidence Matrix

At this historical snapshot the product name was `WarSOC PECA Evidence Controls`.
The active catalog now uses `WarSOC PECA Evidence Pack`. The old Section 46 product
mapping is removed because current PECA Section 46 is not a forensic-logging
provision.

| Control | Telemetry | Evidence purpose | Claim boundary |
|---|---|---|---|
| PECA-101 | Security 4625 | Failed-authentication observation | Does not prove unauthorized access or actor intent |
| PECA-102 | Security 1102 | Audit-log clearing observation | Does not establish who cleared it or why without supporting context |
| PECA-103 | Security 4624 | Successful-authentication context | A successful login is not automatically suspicious |
| PECA-104 | Security 4688 | Process-creation context | Does not prove malicious execution without process/actor context |
| PECA-105 | Security 4672 | Elevated-token context | Does not by itself prove privilege abuse |
| PECA-106 | Security 4720 | Account-creation evidence | Does not prove the account was rogue |
| PECA-107 | Security 4726 | Account-deletion evidence | Does not prove malicious deletion |
| PECA-108 | Security 4732 | Local-group membership change | Does not prove successful privilege escalation by itself |
| PECA-109 | Security 4697 | Security-channel service installation | Requires service, actor, and host context |
| PECA-110 | System 7045 | System-channel service installation | Requires service, actor, and host context |
| PECA-111 | Security 1100 | Event Log service shutdown | Does not prove host compromise without supporting evidence |

All eleven are WarSOC investigation-support controls. None automatically proves
an offence, admissibility, blanket PECA compliance, or PECA Section 32
traffic-data retention.

## 5. FBR Evidence Matrix

The product name is `WarSOC FBR POS Evidence Readiness`. WarSOC is an
independent monitoring and evidence platform, not an FBR-licensed integrator.

| Control | Source class | What it can establish | What it cannot establish |
|---|---|---|---|
| FBR-101 `FBR-INV-DEL` | POS semantic | Approved POS source reported invoice deletion | FBR acceptance or whether deletion was unauthorized |
| FBR-102 `FBR-INV-MOD` | POS semantic | Approved POS source reported invoice modification and supplied fields | Agreement with DB/FBR truth without reconciliation |
| FBR-103 `4660` | Windows FIM | Object deletion on an approved protected path | Invoice fields or FBR status |
| FBR-104 `4663` | Windows FIM | Object-access context relevant to delete correlation | Completed deletion, intent, or invoice semantics by itself |
| FBR-105 `4670` | Windows FIM | Permission change on an approved protected object | Invoice modification or malicious intent |
| FBR-106 `FIM-DB-MOD` | Windows FIM | Protected database file was modified | Affected invoice fields or FBR acceptance status |

Missing source data cannot be converted into a successful compliance result.
The disabled reconciliation contract/lab engine now defines multi-source
outcomes, hashes, fingerprints, replay handling and missing-source behavior.
Real database and licensed-integrator connectors remain later major work.

## 6. API Security Inventory

Run:

```powershell
.\.venv\Scripts\python.exe scripts\generate_api_security_inventory.py
```

The committed artifact is:

```text
docs/generated/WARSOC_API_SECURITY_INVENTORY.json
```

It records method, route, source line, feature condition, authentication type,
RBAC roles, tenant scope, request/response schemas, and statically visible
size/rate controls. The Phase 0 snapshot contained 108 routes. The current
generated inventory has 121 routes with zero manual-review classifications and
is checked against the independent `WARSOC_AUTHORIZATION_POLICY.json` intent
manifest.

Static classification does not replace BOLA, IDOR, RBAC, replay, signature,
rate, and boundary tests. Those remain continuous release gates.

## 7. Phase 0 Acceptance

Phase 0 is accepted in source only when:

1. Catalog import validation passes.
2. PECA contains exactly the existing 11 event IDs.
3. FBR contains exactly the existing 6 event IDs.
4. Existing retention numbers remain unchanged.
5. Every catalog reference exists in the legal registry.
6. S.R.O. 288(I)/2026 remains `DRAFT` and `INCOME_TAX`.
7. Evidence API output separates observation from claim state.
8. Reports do not call themselves compliance certificates.
9. The generated API inventory matches source and has no unresolved route.
10. Focused and maintained regression suites pass.

## 8. Explicitly Not Completed At The Historical Phase 0 Boundary

- Tax-period/tax-year-aware retention calculation.
- Historical evidence migration.
- New Azure containers or immutability policies.
- Cases, custody ledger, legal holds, or offline verifier.
- New PECA controls.
- Database or licensed-integrator connector.
- FBR multi-source reconciliation.
- Wazuh or firewall production enablement.
- Legal opinion on applicability to a specific customer.

Those boundaries prevent terminology cleanup from silently changing evidence
physics or customer obligations.

The current source retains the tax-period resolver only for historical
interpretation and uses tenant-entitlement retention for new FBR evidence. It also implemented explicit holds,
cases/custody, signed packages/offline verification, SIEM sensitive-field
privacy, and a disabled reconciliation contract. It still has no live DB or
licensed-integrator connector, no production Azure proof for the new workflows,
and no Wazuh/firewall production enablement. See
`WARSOC_BACKEND_EVIDENCE_PROGRAM_IMPLEMENTATION_2026-08-20.md`.
