# WarSOC Release Audit

**Date:** 2026-08-24 (updated from the 2026-08-21 audit)
**Scope:** Source, tests, production identity, endpoint agent, ingestion,
detection, PECA/FBR evidence, authorization, retention, Azure, optional Wazuh
and firewall relay, and frontend integration.
**Decision:** **LOCAL RELEASE CANDIDATE ACCEPTED - PRODUCTION ACCEPTANCE OPEN**

## 1. Executive Verdict

WarSOC has achieved most of the intended source architecture for its current
scope: signed Windows telemetry, bounded ingestion, tenant-isolated processing,
native SIEM detections, PECA/FBR evidence generation, retention fencing,
evidence custody and fail-closed archival contracts.

It has **not** yet achieved an all-to-all production acceptance. The upgraded
backend is still an uncommitted release candidate, production is serving an
older release, and the newly built `4.2.9` installer is not publisher-signed or
uploaded. FBR now follows the tenant's normal retention entitlement; historical
locked evidence remains under its existing policy.

This means:

```text
source architecture: implemented for the current scope
local regression and security gates: accepted
production release identity: not accepted
live upgraded pipeline: not accepted
customer launch claim: not accepted
```

## 2. Evidence Reviewed

- Backend branch: `codex/warsoc-release-reconcile-20260812`.
- Backend base HEAD: `6c3900f681b921aec6d760b40fc818ef74ec370e`.
- Candidate state before release commit: 51 tracked files modified plus the
  intentional new evidence, test and documentation files listed by Git.
- Backend regression: `523 passed, 1 skipped, 44 warnings` in 175.31 seconds.
- Skipped test: destructive grand-master E2E requiring an isolated stack and
  explicit `E2E=1`.
- Backend dependency audit: `pip check` clean and `pip-audit` reports no known
  vulnerabilities after updating `aiohttp` and `cryptography`.
- Frontend source: clean `origin/main` candidate at `6ffc9e0` in
  `Startup-main-release-reconcile`.
- Frontend verification: lint, production build and high-severity dependency
  audit pass; no complete automated browser E2E suite.
- Production health: API, MongoDB and Redis report healthy; public docs are
  blocked.
- Production relay status route: unauthenticated request returns `404`, which is
  consistent with the upgraded relay route not being deployed.
- Agent `4.2.9` was built locally. Installer SHA-256 is
  `960BF349C023A1FB79065F7ACC692A089ADEF583585DEB2BDFFCC3DC60003670`.
  The installer and manifest are not uploaded and Authenticode status is
  `NotSigned`.

## 3. End-to-End Status Matrix

| Component | Source | Automated proof | Physical/live proof | Verdict |
|---|---|---|---|---|
| Exact release identity | Dirty candidate | Git inspection | No matching deployed SHA | **BLOCKED** |
| Agent `4.2.9` | Implemented in source | Signing/spool contracts pass | Built and manifested; not publisher-signed, uploaded or installed | **BLOCKED** |
| Enrollment and heartbeat | Implemented | Contract tests pass | Older agent versions previously proven | Candidate not live-proven |
| Signed endpoint ingestion | Required-mode contract implemented | Signature/replay/sequence tests pass | `4.2.9` not exercised against candidate backend | Candidate not live-proven |
| Bounded spool and quota | Implemented | Boundary tests pass | Older agent spool was exercised | Candidate not live-proven |
| Durable source/outbox | Implemented | Failure/retry tests pass | No candidate outage drill | Source-proven only |
| Native SIEM | Implemented and source-isolated | Detection tests pass | Older deployed SIEM observed | Candidate not live-proven |
| Incident grouping/workflow | Implemented | Idempotency and RBAC tests pass | No final role-by-role browser run | Partial |
| PECA evidence | 11 controls | Worker/catalog tests pass | Coverage depends on endpoint audit profile | Conditional |
| FBR evidence | POS semantic plus Windows FIM | Worker/retention tests pass | No real POS/database/integrator acceptance | Partial |
| Roles and tenant isolation | Admin/analyst/auditor/viewer | Static inventory plus negative tests pass | No exhaustive 121-route runtime matrix | Strong, not exhaustive |
| Retention and legal holds | Implemented | Retention/hold/race tests pass | Final Azure containers/policies not proven | Source-proven only |
| Azure archive-before-delete | Fail-closed contract implemented | Archiver, hold-race and policy-length tests pass | New FBR uses the general tenant-duration route; existing locked evidence is unchanged | Cloud duration routes pending |
| Evidence cases/custody/export | Implemented | Package/custody/export tests pass | Not deployed; frontend incomplete | Source-proven only |
| Firewall relay | Implemented behind disabled flag | Parser/runtime/contracts pass | pfSense virtual lab only | Lab candidate |
| Wazuh integration | Shadow architecture implemented, disabled | Lab/cross-rule tests pass | One candidate family; no production promotion | Lab candidate |
| Frontend | Current dashboard works against older API | Lint/build pass | No upgraded browser acceptance | Partial |

## 4. Findings by Priority

### P0 - Release blockers

1. **The candidate is not reproducible.** The upgraded source is not committed,
   tagged or tied to one backend/frontend/agent manifest. Deployment or rollback
   cannot be proven from the current working tree.
2. **Agent `4.2.9` is not distribution-accepted.** The installer and manifest
   exist locally, but the binary is not Authenticode-signed, uploaded or tested
   after installation against the candidate backend.
3. **Duration-specific Azure routes still need operational proof.** New FBR
   evidence uses the general route matching the tenant entitlement. The
   archiver must prove the selected policy before deleting Mongo evidence.
4. **The final production pipeline is untested for this candidate.** Exact
   deployed-release reconciliation, live role flows and live Azure behavior
   remain to be run after deployment.

### P1 - Correctness and security gaps

1. **Identity uniqueness is now normalized and database-enforced.** The live
   duplicate audit returned zero conflicts, and the candidate adds normalized
   unique indexes plus race-safe signup, invite and provisioning behavior. It
   still requires production index-build observation during deployment.
2. **Production secret lengths are now enforced.** The candidate rejects short
   JWT and platform-administrator keys without logging values. Production
   inspection confirmed current values satisfy the minimum length.
3. **PECA telemetry coverage is conditional.** Event `4776`, `5140`, `4657`,
   `4768` and `4769` require audit policy, SACL or domain-controller placement
   beyond a normal workstation profile. The UI and reports must show unsupported
   or coverage-degraded states instead of compliance success.
4. **No exhaustive production runtime authorization matrix exists.** The generated
   121-route inventory and selected negative tests are useful, but each role's
   allow/deny behavior has not been exercised against a running candidate.
5. **The frontend relay/evidence UI remains a separately owned release.** Its
   integration contract is documented, but optional relay and Wazuh modes stay
   disabled in production until their own acceptance gates pass.

### P2 - Hardening and operational debt

1. FastAPI's internal docs remain enabled in the process and are blocked by
   Nginx. This is acceptable only while the API port remains private; disabling
   them in production adds defense in depth.
2. The dashboard chunk is approximately 1.46 MB minified / 447 KB gzip. The
   route-split shell is smaller, but dashboard activation remains a measured
   performance issue.
3. There is no automated browser suite covering invitation, role boundaries,
   agent activation/download, incident workflow, evidence cases, holds, archive
   requests and degraded/error states.
4. The relay executable and endpoint installer still require a trusted publisher
   signature for customer distribution. A SHA-256 manifest proves integrity,
   but it does not establish publisher reputation to Windows Defender.
5. Legal/product copy contains infrastructure, retention and evidence-admission
   statements that may not match the current deployment. Runtime code is not the
   place to resolve these; the legal owner must review them before commercial use.

## 5. Capability Boundaries

WarSOC may accurately claim that the candidate implements signed Windows
telemetry, bounded ingestion, native alerting, tenant-isolated evidence,
PECA/FBR evidence support, fail-closed archival logic and auditable custody.

WarSOC must not yet claim:

- that release `4.2.9` is deployed or customer-tested;
- complete PECA or FBR compliance;
- court admissibility of every export;
- authoritative FBR invoice acceptance or reconciliation;
- physical Fortinet, Cisco ASA or MikroTik acceptance;
- production Wazuh-backed detection;
- live proof of every Azure retention and retrieval path;
- an all-to-all production acceptance.

Starting an elevated PowerShell window is also not, by itself, proof of malicious
privilege escalation. Detection requires supporting process, logon, privilege,
actor and outcome context.

## 6. Safe Closure Order

1. Freeze the reviewed candidate in one intentional backend release commit and
   record the frontend and agent hashes.
2. Push and deploy the exact commit with optional Wazuh, relay, anchor,
   reconciliation and archive-retrieval features disabled.
3. Create and lock the adequate FBR Azure policy/container through the
   management plane; never shorten the required retention in code.
4. Publisher-sign, upload and install agent `4.2.9`; do not replace
   the last accepted artifact until its acceptance passes.
5. Run health, role/tenant matrix, enrollment, signed ingest, SIEM, PECA, FBR and
   incident workflow smoke tests against the deployed candidate.
6. In an isolated tenant, run Azure WORM, archive-before-delete, hold-race,
   export, offline verification, retrieval and backup/restore proof.
7. Run browser acceptance for all four roles against the exact deployed API.
8. Promote firewall relay and Wazuh separately only after their own production
   gates. Neither is a prerequisite for accepting the native WarSOC core.

Until these gates close, keep production on its known healthy release and do not
enable optional subsystems merely because their source tests pass.
