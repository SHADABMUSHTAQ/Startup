# WarSOC Release Condition Report

**Date:** 2026-08-24
**Decision:** Local candidate accepted; production promotion not yet completed.

## 1. Exact State

| Item | Identity/state | Result |
|---|---|---|
| Backend candidate | Local branch based on `6c3900f`; intentional release changes still uncommitted | **LOCAL ONLY** |
| Backend production | `d92fb65`, API/Mongo/Redis healthy at last observation | **OLDER HEALTHY RELEASE** |
| Frontend | `6ffc9e0`; lint/build/audit pass | **PUSHED, BUILD-ACCEPTED** |
| Public agent | 4.2.8 | **CURRENT ACCEPTED FALLBACK** |
| Candidate agent | 4.2.9 installer and manifest built | **NOT UPLOADED/INSTALLED** |
| Optional Wazuh | Disabled | **NOT PRODUCTION** |
| Optional network relay | Disabled | **NOT PRODUCTION** |
| Evidence export/anchor/reconciliation | Disabled | **NOT PRODUCTION** |

## 2. Verification Completed

```text
Backend pytest:       523 passed, 1 skipped, 44 warnings (175.31s)
pip check:            pass
pip-audit:            no known vulnerabilities
Bandit high severity: no findings
Python compileall:    pass
Compose config:       pass
API security inventory: 121 routes, 0 manual-review classifications
Frontend lint:        pass
Frontend build:       pass
Frontend npm audit:   0 high/critical vulnerabilities
```

The skipped test is explicitly destructive and requires an isolated stack. The
warnings are ORJSONResponse and test-only `datetime.utcnow()` deprecations, not
failed application assertions.

## 3. Proven Fixes in the Candidate

- Signed endpoint event continuity and signed heartbeat coverage for agent 4.2.9.
- Bounded/replay-safe agent behavior retained.
- Canonical encrypted source evidence before durable Redis dispatch.
- Source-class separation for SIEM, PECA and FBR evidence.
- Case-insensitive identity uniqueness with race-safe account/invitation flows.
- Production minimum secret-length gates.
- SIEM raw sensitive-field privacy controls.
- Tenant-entitlement FBR retention with no product-plan or statutory-period hardcoding.
- Explicit legal/proceeding holds and pre-delete hold race fencing.
- Bounded archive cohorts and archive-before-delete verification.
- Evidence cases, hash-linked custody and offline-verifiable packages.
- Evidence-export worker isolated and disabled by default; generic Compose no
  longer starts a permanently exited disabled worker.
- Historical FBR tax-period records and locked Azure blobs are isolated from
  the new automatic archive path rather than rewritten.
- Dependency advisories removed by supported package updates.

## 4. FBR Condition

FBR has six current evidence controls: two approved POS semantic events and four
Windows FIM-derived controls. These produce integrity/investigation evidence;
they do not submit invoices, issue FBR references or prove FBR acceptance.

New FBR source and derived evidence carry `TENANT_ENTITLEMENT_V1` and use the
tenant's existing `retention_days`. After the seven-day hot window, FBR uses the
duration-aware general archive route. Existing legacy Mongo records and locked
Azure blobs remain untouched.

**Required operator action:** provision and prove the approved general-duration
Azure routes before enabling them. No FBR-specific statutory container is
required by the active product.

## 5. PECA Condition

The PECA pack preserves 11 selected Windows endpoint observations. The worker,
catalog, encryption/signing, claim boundary and tenant isolation contracts pass.
Actual coverage depends on the endpoint's Security/System channels and audit
policy. PECA evidence supports investigation; it is not blanket statutory
certification and does not replace section 32 service-provider traffic-data
retention.

## 6. Security Condition

Completed review covered authentication, role/tenant policy inventory, signed
ingestion, replay, parser bounds, quotas, Redis admission, source durability,
worker isolation, evidence access, holds, archive deletion gates, dependency
advisories, production secret presence/length and external port exposure.

No known high-severity static or dependency finding remains in the tested
candidate. This is not a claim that no vulnerability can exist. A separate
repository-wide deep scan was canceled at the operator's request and is not
counted as evidence.

## 7. Remaining Promotion Steps

1. Review the final Git file inventory, commit one backend release and push it
   to `origin/backend` without force.
2. Deploy that exact commit with Wazuh, relay, evidence export, daily anchor and
   FBR reconciliation still disabled.
3. Verify health, container identity, startup indexes and error-free logs.
4. Run authenticated admin/analyst/auditor/viewer and cross-tenant negative
   checks against the deployed candidate.
5. Upload the 4.2.9 installer and manifest, hash the downloaded Azure object,
   then update the CDN setting.
6. Install 4.2.9 with a fresh activation code and validate service, heartbeat,
   signed ingest, SIEM, PECA and disposable FBR fixture flows on this machine.
7. Prove FBR archive-before-delete against the matching general tenant-duration
   route with an isolated test cohort.
8. Capture final backend/frontend/agent/Azure identities in the acceptance
   artifact.

## 8. Final Verdict

WarSOC is not currently broken in production; production is healthy on the
older backend. The upgraded source candidate is coherent and locally accepted,
but it is not live. Calling the upgraded platform "production accepted" before
the deployment, agent and Azure steps above would be inaccurate.
