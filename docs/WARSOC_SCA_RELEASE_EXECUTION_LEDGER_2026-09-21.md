# WarSOC SCA Release Execution Ledger - 2026-09-21

**Purpose:** Close the remaining SCA release gates without changing WarSOC's
canonical SIEM, PECA, FBR, firewall-relay, retention, or incident ownership.

**Release rule:** Each verification is executed once after its implementation
stage. Failed checks are rerun only after the specific defect is corrected.

## Starting state (superseded by this execution)

- Backend branch: `codex/warsoc-release-reconcile-20260812`
- Backend base: `origin/backend` at `0a8caf1`
- Production Wazuh registry: `warsoc-projected-shadow-v2`
- Wazuh mode: shadow; WarSOC remains the incident authority
- SCA backend candidate: implemented locally, default disabled
- SCA production registry: not yet approved
- SCA frontend: absent from the production-aligned frontend checkout
- Local backend regression: 822 passed, 2 skipped
- Production deployment: not started by this execution

## Execution stages

| Stage | Status | Evidence |
|---|---|---|
| 1. Map source, runtime, hosts and release identities | COMPLETE | Source/runtime identities and private-host topology recorded below |
| 2. Complete dependency vulnerability audit | COMPLETE | Both Python requirement sets report no known vulnerabilities |
| 3. Define and validate a dedicated SCA shadow registry | COMPLETE | v3 registry validated; SHA-256 recorded below |
| 4. Update backend SCA contracts and focused tests | COMPLETE | Focused backend campaign: 34 passed |
| 5. Add minimal production-aligned frontend SCA surface | COMPLETE | 26 tests, lint and production build passed; npm audit clean |
| 6. Prove live two-host SCA flow and isolation | COMPLETE | Native agent `001`, scan `573050547`, 424 checks, one tenant, zero promotion/incidents |
| 7. Run final backend/frontend release verification | COMPLETE | Backend/frontend campaign recorded below |
| 8. Commit, push and deploy exact approved files | COMPLETE | Backend `3335112`; frontend `1e64b79`; aligned OCI Wazuh services |
| 9. Update architecture/current-state documents | COMPLETE | Authoritative documents record the accepted controlled scope |

## Non-negotiable boundaries

- SCA remains shadow evidence and posture only; it does not create or mutate
  canonical incidents.
- Summary rules are not individual SCA controls. Only Wazuh SCA `type=check`
  events may create posture rows.
- Tenant and agent identity come from trusted WarSOC bindings, never candidate
  payload claims.
- No public Wazuh manager, bridge, candidate API, MongoDB, or Redis listener.
- No production enablement before the live acceptance and final test stages pass.
- Existing unrelated working-tree changes are preserved and are not silently
  included in the release.

## Evidence log

### 2026-09-21 - Stage 1 opened

- Confirmed backend base and dirty working-tree state.
- Confirmed the active registry documented by the backend is
  `warsoc-projected-shadow-v2`, containing 22 shadow detection families.
- Began runtime and host identity inspection before changing SCA behavior.

### 2026-09-21 - Stages 1-4 completed

- Confirmed production is running a private OCI Wazuh manager, dispatch,
  candidate API and bridge. Wazuh manager data is not dependent on a laptop.
- Confirmed all Wazuh services are in shadow mode and WarSOC remains the only
  incident authority.
- Confirmed the official Wazuh 4.14.7 SCA check/transition rules are
  `19007` through `19015`; summary rule `19002` is deliberately excluded.
- Added and validated `warsoc-projected-shadow-v3` with 31 rules. Registry
  SHA-256: `15886c032ee2ce65c0a3af27f51814ad4bfc99656165a631097b740e32bec1a4`.
- Added a Tailscale-only native-agent listener, pre-enrollment-only operator
  workflow, server-owned tenant/agent bindings and unique binding indexes.
- Fixed native-candidate lineage so SCA cannot borrow an unrelated endpoint
  event when no Windows event identity exists.
- Added freshness/trust semantics; stale scans cannot appear compliant.
- Focused backend campaign passed: `34 passed`.
- Isolated `pip-audit` passed for `requirements.txt` and
  `requirements-wazuh-bridge.txt`: no known vulnerabilities.

### 2026-09-21 - Stage 5 frontend contract verification

- Added a minimal Configuration Assessment view without exposing Wazuh as a
  customer-facing product or detection authority.
- Frontend contract/integration campaign passed: `26 passed`.
- Frontend lint and production build passed. `npm audit --audit-level=high`
  reported zero vulnerabilities.
- The existing Dashboard chunk-size warning remains a non-blocking performance
  optimization item; no new build or runtime error was introduced.
- The production feature remains disabled until the live two-host proof and
  final release campaign are complete.

### 2026-09-21 - Stage 7 release verification

- Backend full regression completed: `827 passed`, `2 skipped`, `28 warnings`.
  One generated-inventory mismatch was caused by the Windows system Python
  shim silently skipping the generator; no runtime logic test failed.
- Regenerated the inventory with the repository Python 3.13 interpreter:
  `138 routes`, `0 manual review required`; its exact contract test passed.
- Python compileall, PowerShell AST parsing, registry validation and both Git
  diff checks passed.
- Bandit high-severity gate passed with zero high-severity findings.
- Backend dependency audits found no known vulnerabilities; `pip check` passed.
- Frontend: `26 passed`; lint, production build and npm high-severity audit
  passed with zero vulnerabilities.
- Release registry remains shadow-only: 31 rules, SHA-256
  `15886c032ee2ce65c0a3af27f51814ad4bfc99656165a631097b740e32bec1a4`.

### 2026-09-21 - Stage 6 live native-agent acceptance

- Installed and configured Wazuh agent 4.14.7 on the Windows 10 validation
  endpoint using the fail-safe operator script. `WazuhSvc` is Automatic and
  running.
- The endpoint connects only to the OCI Tailscale address
  `100.108.232.122:1514/tcp`. Public ports `1514` and `1515` remain closed.
- Manager agent `001` (`desktop-u5k0v15-sca`) is Active and bound server-side to
  tenant `WARSOC_E43CE566` and WarSOC agent
  `WARSOC_AGENT_dc3126c94cf74953bdb0a35e5c91b3ec`.
- Live scan `573050547` produced 424 accepted `type=check` observations using
  rules `19007`, `19008`, and `19009`: 120 passed, 299 failed, and 5 not
  applicable. The projected score is 28.6 and status is `AT_RISK`; this is
  endpoint posture evidence, not a product-health failure or certification.
- Rule `19002` produced zero posture rows. All 424 observations remain
  `shadow_observation`; matching incident count is zero.

### 2026-09-21 - Stages 8-9 production closure

- Backend code release `3335112` is active at
  `/opt/warsoc/releases/3335112`; public health reports MongoDB and Redis
  healthy. The authenticated SCA route is live and returns HTTP 401 without a
  user token, rather than 404/503.
- The OCI deployer now rebuilds and reconciles the Wazuh candidate API and
  dispatch worker whenever `WAZUH_DETECTION_MODE` is `shadow` or `primary`.
  Both containers identify `/opt/warsoc/releases/3335112` and are running.
- Runtime gates are `WAZUH_DETECTION_MODE=shadow`,
  `WAZUH_PRIMARY_APPROVED=false`, and `WAZUH_SCA_ENABLED=true`.
- Candidate, bridge, and native-agent listeners are reachable only through
  Tailscale (`8443`, `9443`, and `1514`). Public MongoDB, Redis, API-internal,
  and Wazuh enrollment/agent ports remain closed.
- Frontend revision `1e64b79` provides the WarSOC Configuration Assessment
  surface without exposing Wazuh as a customer-facing engine.

## Accepted scope and residual boundary

The controlled Windows 10 SCA path is production-accepted as shadow posture
evidence. WarSOC remains the only incident authority. This acceptance does not
prove Windows Server SCA policy coverage, a customer fleet, sustained capacity,
high availability, automatic remediation, or any Wazuh primary rule family.
