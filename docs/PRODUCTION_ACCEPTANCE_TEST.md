# WarSOC Production Acceptance Test

Run these phases from the hardened release checkout. Do not substitute the
older `run_launch_e2e.ps1`; that script contains a pre-hardening FBR fixture.

## Current Status (2026-07-14)

| Phase | Latest status | Remaining action |
|---|---|---|
| Preflight | Passed as run `136bf34e0c` against the deployed site, API, and Azure `warsoc_installer-4.2.0.exe`. | Upload and rerun against local release candidate `warsoc_installer-4.2.1.exe` SHA-256 `B3F861086B0DE4C02B1D11506A77781268A5C0F2BD803B252BEAE720F596B857`. |
| Platform | Outstanding for the current deployed release. | Run with disposable production QA data and verify the sales mailbox. |
| Native Windows | Outstanding as a complete 11-control/FBR proof artifact. | Run Generate and Verify on a snapshot-based disposable Windows VM. |
| Fifty-agent soak | Outstanding for the current release. | Run in a quiet window and inspect workers, Redis, DLQ, and latency. |

Pytest collection currently reports 251 backend cases. The latest archive and
incident and runtime-safety changes have 122 focused passing cases; remaining legacy tests
have not all been rerun in the current release cycle. Production acceptance
still requires the contract-aligned regression suites to pass.

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
proves final inbox delivery.

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

## Acceptance

Launch is accepted only when all four phases exit with code `0`, the native VM
JSON report says `passed: true`, the sales email is present in the mailbox,
and no unexpected email DLQ, worker restart, Redis eviction, or container
restart appears during the run.

Reports are stored under:

```text
tmp/production-acceptance/<run-id>/
```
