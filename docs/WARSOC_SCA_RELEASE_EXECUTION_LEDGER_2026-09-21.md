# WarSOC SCA Release Execution Ledger - 2026-09-21

**Purpose:** Close the remaining SCA release gates without changing WarSOC's
canonical SIEM, PECA, FBR, firewall-relay, retention, or incident ownership.

**Release rule:** Each verification is executed once after its implementation
stage. Failed checks are rerun only after the specific defect is corrected.

## Initial state

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
| 6. Prove live two-host SCA flow and isolation | PENDING | Run ID, source host, manager, tenant binding and zero incident pollution |
| 7. Run final backend/frontend release verification | COMPLETE | Backend/frontend campaign recorded below |
| 8. Commit, push and deploy exact approved files | PENDING | Git commits, image/runtime identities and health evidence |
| 9. Update architecture/current-state documents | PENDING | Source-of-truth files point to accepted runtime truth |

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
