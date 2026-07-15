# WarSOC Production Acceptance Test

Run these phases from the hardened release checkout. Do not substitute the
older `run_launch_e2e.ps1`; that script contains a pre-hardening FBR fixture.

## Current Status (2026-07-14)

| Phase | Latest status | Remaining action |
|---|---|---|
| Preflight | Passed as run `4665bcb57e` against the deployed site, API, and Azure `warsoc_installer-4.2.2.exe`. The remote artifact matched SHA-256 `FDF008750DD7A8BE0778106C1A2A15BECD6FB64EE7A0DA4D0CC71845B927CC1E`. | No public-infrastructure defect is open from this phase. Rerun after the backend reliability patch is deployed. |
| Platform | Run `c78aff40aa` completed with zero failures. Quote/contact, auth, CDN, enrollment, signed heartbeat, mitigation, SIEM, FBR, PECA, WebSocket, secure pending invite, exports, and SMTP activity passed. | Activate one real mailbox invitation and prove activated-auditor RBAC. Rerun after provisioning reliability is deployed. |
| Native Windows | Outstanding as a complete 11-control/FBR proof artifact. | Run Generate and Verify on a snapshot-based disposable Windows VM. |
| Fifty-agent soak | Run `8cc3b67a18` proved 50/50 enrollment and blocked seat 51. Only 29/50 burst requests were accepted. Live metrics then proved `raw_logs_queue=482465` against the 500000 admission ceiling. A stale profile-gated consumer group was incorrectly pinning acknowledged-entry retention. | Deploy the consumer-safe retention correction, verify the stream depth falls without DLQ growth, then rerun the instrumented soak. |

The current Windows-only launch regression completed with `247 passed`,
`3 skipped`, and zero failures in 90.68 seconds. The excluded files are the
explicitly deferred Linux/syslog suites plus obsolete mega-suite duplicates.
The three skips are one environment-gated all-rules E2E case and two Git
metadata checks that cannot run inside the API test image; they are not runtime
feature failures. A separate reliability run covering dependency-aware health,
provisioning rollback, consumer-safe stream retention, and worker metrics
completed with `8 passed` and zero failures.

The current frontend checkout also completed `npm run lint` and a production
Vite build successfully. Its production API binding remains
`https://api.warsoc.tech/api/v1`; no localhost, ngrok, or Web3Forms production
binding was found. These local results do not replace the live production
phases listed in the table above.

### Open production blockers

1. Deploy the safe-retention correction. It calculates the trim boundary from
   `siem_group`, `fbr_group`, and PECA's legacy internal `eto_group` only. An
   unrelated disabled `threat_hunters` group must not pin the active pipeline.
2. Investigate repeatable provisioning HTTP 500 responses from acceptance runs
   `60769581ec` and `532ce2f502`. Neither attempt inserted a partial tenant.
   The release candidate now exposes real Mongo/Redis health and compensates
   tenant/genesis/user writes on failure, but the DigitalOcean API traceback is
   still required to identify the deployed failure.
3. After deployment, require a recent
   `warsoc_stream_retention_worker_age_seconds`, a rising
   `warsoc_raw_stream_trimmed_total`, a falling `warsoc_raw_stream_depth`, and
   zero unexpected `warsoc_dlq_depth` before rerunning the soak.

## 1. Public Infrastructure

This phase is read-only. It checks the live Vercel build, production API
binding, DNS, TLS-backed health endpoint, security headers, CORS, blocked API
documentation, closed database ports, and the local installer manifest.

```powershell
.\scripts\run_production_acceptance.ps1 `
  -Phase Preflight `
  -ManifestPath ".\Output\pilot_hash_manifest.json" `
  -InstallerPath ".\Output\warsoc_installer-<version>.exe" `
  -ArtifactUrl "https://<artifact-account>.blob.core.windows.net/<container>/warsoc_installer-<version>.exe"
```

## 2. Platform Pipeline

This creates disposable production QA data. It validates the sales forms,
tenant provisioning, authentication, profile persistence, CDN redirect and
installer hash, agent registration, signed heartbeat, mitigation delivery,
SIEM alerting, Redis-correlated FBR deletion, authenticated POS evidence,
PECA evidence, WebSocket delivery, alert lifecycle, auditor RBAC, CSV/PDF
exports, and SMTP delivery activity.

Set secrets in the current PowerShell process so they are not committed:

```powershell
$env:SUPER_ADMIN_API_KEY = "<production admin key>"
$env:METRICS_BEARER_TOKEN = "<production metrics token>"

.\scripts\run_production_acceptance.ps1 `
  -Phase Platform `
  -ConfirmProductionDataCreation
```

The test sends sales messages whose company and subject contain a unique run
identifier. Confirm one of those messages is visible in the WarSOC sales
mailbox; the automated metric proves SMTP acceptance, while the mailbox check
proves final inbox delivery. Team invitations deliberately do not return their
one-time token through the API. Complete one invitation from the mailbox and
verify the activated auditor receives HTTP 403 from team, operational-alert,
and agent-activation APIs while entitled compliance evidence returns HTTP 200.

## 3. Native Windows VM

Create a VMware snapshot first. Generate a fresh activation code for the
disposable QA tenant and copy the installer, manifest, this coordinator and
`validate_native_windows_vm.ps1` to the VM.

From elevated PowerShell inside the VM:

```powershell
.\scripts\run_production_acceptance.ps1 `
  -Phase NativeGenerate `
  -ActivationCode "<one-time activation code>" `
  -ConfirmDisposableVm
```

Reboot the VM. Then verify using the disposable tenant administrator:

```powershell
$credential = Get-Credential
.\scripts\run_production_acceptance.ps1 `
  -Phase NativeVerify `
  -Credential $credential `
  -WaitSeconds 240
```

This is the authoritative proof for native Windows collection and all 11 PECA
controls. Synthetic API events do not replace it.

## 4. Fifty-Agent Soak

Run once during a quiet production window:

```powershell
.\scripts\run_production_acceptance.ps1 `
  -Phase Soak `
  -ConfirmProductionDataCreation `
  -SoakTimeoutSeconds 60
```

The soak output includes an HTTP response distribution and one sanitized
sample body for each failed status. Do not classify a partial burst as a
worker-latency issue until this distribution identifies whether the boundary
is API admission, gateway timeout, memory pressure, or client transport.

## Acceptance

Launch is accepted only when all four phases exit with code `0`, the native VM
JSON report says `passed: true`, the sales email is present in the mailbox,
and no unexpected email DLQ, worker restart, Redis eviction, or container
restart appears during the run.

Reports are stored under:

```text
tmp/production-acceptance/<run-id>/
```
