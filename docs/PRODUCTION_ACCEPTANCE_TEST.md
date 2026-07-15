# WarSOC Production Acceptance Test

Run these phases from the hardened release checkout. Do not substitute the
older `run_launch_e2e.ps1`; that script contains a pre-hardening FBR fixture.

## Current Status (2026-07-15)

| Phase | Latest status | Remaining action |
|---|---|---|
| Preflight | Run `a9216bdb7d` passed against the deployed Vercel site, DigitalOcean API, and Azure `warsoc_installer-4.2.2.exe`. The remote artifact matched SHA-256 `FDF008750DD7A8BE0778106C1A2A15BECD6FB64EE7A0DA4D0CC71845B927CC1E`. | No public-infrastructure defect is open from this phase. |
| Platform | Run `a9216bdb7d` / validator `6f5476d9b4` completed with zero failures. Quote/contact, auth, CDN, enrollment, signed heartbeat, mitigation, SIEM, FBR, PECA, WebSocket, secure pending invite, exports, and SMTP delivery passed. | Activate one real mailbox invitation and prove activated-auditor RBAC. Complete the separately gated DB-backed self-lockout proof. |
| Native Windows | Outstanding as a complete 11-control/FBR proof artifact. | Run Generate and Verify on a snapshot-based disposable Windows VM. |
| Fifty-agent soak | Run `2053d97832` passed: 50/50 agents registered, seat 51 returned HTTP 403, all 50 concurrent ingests returned HTTP 200, SIEM latency was 5.18s, PECA vaulted all 50 events, FBR correlation passed, and the pipeline completed in 7.22s. | No capacity defect is open at the current 50-agent product limit. Continue operational monitoring. |

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

### Open production proofs

1. Complete the native Windows snapshot-VM proof for all 11 PECA controls and
   the FBR deletion/permission scenarios.
2. Activate one real mailbox invitation and verify activated-auditor RBAC.
3. Complete the separately gated DB-backed active-agent self-lockout proof.
4. Preserve an Azure archive/readback artifact demonstrating immutable upload,
   successful authorized retrieval, and archive-before-hot-delete ordering.

### 2026-07-15 Redis recovery

The deployed stream reached Redis's 512 MB no-eviction ceiling because 78,965
SIEM entries remained pending and an unrelated stale consumer group had
previously pinned acknowledged-entry retention. Recovery preserved every
pending event: Redis received temporary headroom, SIEM-only consumers drained
the normal detection/persistence path, and consumer-safe retention reclaimed
acknowledged entries. Final production state was `raw_logs_queue=1`, all
SIEM/FBR/PECA/hot pending counts `0`, DLQ `0`, and Redis dataset memory 2.78 MB.
Two missing `siem_cold_vault` indexes were created for `(tenant_id,event_uid)`
upserts and `(tenant_id,timestamp)` dashboard reads. The release configuration
now uses a 640 MB Redis no-eviction ceiling within a 1 GB container.

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
