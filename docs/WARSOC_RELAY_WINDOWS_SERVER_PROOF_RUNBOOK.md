# WarSOC Network Relay Windows Server Service Proof Runbook

**Status:** `PENDING` — Gate 2 of the six production gates
**Purpose:** Prove the relay runs correctly as a hardened Windows Server service
through every lifecycle event: install, restart, reboot, crash recovery, and
uninstall, with DPAPI identity and DACL/SACL security intact.
**Production impact:** None (lab only)
**Required production state:** `NETWORK_RELAY_ENABLED=false` (local test backend only)

## 1. Acceptance Boundary

This runbook can approve the relay's **service-layer behavior** on one recorded
Windows Server version. It cannot approve:

- Firewall vendor parsers (see Gate 3 per-vendor proof)
- Throughput or saturation limits (see Gate 4)
- Pilot operations (see Gate 5)
- Any production tenant or activation code

## 2. Prerequisites

| Item | Requirement |
|---|---|
| Windows Server VM | 2019 or 2022, disposable, no production data |
| Relay executable | Built via `build_relay.bat`, SHA-256 recorded in manifest |
| NSSM | Downloaded from official nssm.cc, SHA-256 recorded |
| Relay config | `relay-config.json` pointing at local test backend |
| Activation code | Test-tenant only, never a production code |
| Admin session | Elevated PowerShell on the VM |

## 3. Install Proof

Run the installer:

```powershell
.\install_warsoc_relay.ps1 `
    -RelayExecutable .\warsoc_relay.exe `
    -NssmExecutable .\nssm.exe `
    -ConfigFile .\relay-config.json
```

Record the following evidence after install completes:

```powershell
# Service is running and auto-start
Get-Service WarSOC_Relay | Format-List Name, Status, StartType

# Identity file exists and is DPAPI-protected (binary, not plaintext)
Get-Item "C:\ProgramData\WarSOCRelay\identity.dpapi" | Select-Object Length, LastWriteTime

# Firewall rules are source-scoped (not any-source)
Get-NetFirewallRule -DisplayName "WarSOC Relay - *" | Format-Table DisplayName, Enabled, Action

# Verify each rule's RemoteAddress matches the config's source_addresses
Get-NetFirewallRule -DisplayName "WarSOC Relay - *" | Get-NetFirewallAddressFilter | Format-Table RemoteAddress

# Directory DACL: SYSTEM-only access
(Get-Acl "C:\ProgramData\WarSOCRelay").Access | Format-Table IdentityReference, FileSystemRights, AccessControlType

# SACL: auditing is enabled for Everyone on security-sensitive operations
(Get-Acl "C:\ProgramData\WarSOCRelay").GetAuditRules($true, $true, [System.Security.Principal.SecurityIdentifier]) | Format-Table IdentityReference, AuditFlags

# Audit policy: File System auditing is enabled
auditpol /get /subcategory:"File System"
```

**Pass criteria:**
- Service status: `Running`, StartType: `Automatic`
- Identity file exists, non-zero size
- Firewall rules exist, one per listener, RemoteAddress matches config
- DACL shows only `SYSTEM` with `FullControl`
- SACL shows `Everyone` with `Success,Failure` on sensitive operations
- `auditpol` shows File System auditing enabled for Success and Failure

## 4. Service Restart Proof

```powershell
# NSSM restart (graceful quiesce + drain)
Restart-Service WarSOC_Relay

# Wait for quiesce+drain (configured graceful_drain_seconds, default 30)
Start-Sleep -Seconds 35

Get-Service WarSOC_Relay
```

**Pass criteria:** Service returns to `Running` after restart. Check
`service-output.log` for the quiesce/drain lifecycle messages:

```powershell
Get-Content "C:\ProgramData\WarSOCRelay\service-output.log" -Tail 20
```

## 5. Reboot Proof (DPAPI Identity Persistence)

```powershell
Restart-Computer -Force
# After reboot, log back in and run:
Get-Service WarSOC_Relay
```

**Pass criteria:**
- Service auto-starts after reboot (`Running` without manual start)
- Relay connects to the backend (check service-output.log for successful
  registration or batch delivery)
- DPAPI identity survived the reboot (no re-registration required)

## 6. Crash Recovery Proof

```powershell
# Force-kill the relay process (simulates crash)
$relayPid = (Get-WmiObject Win32_Service -Filter "Name='WarSOC_Relay'").ProcessId
Stop-Process -Id $relayPid -Force

# Wait for NSSM restart delay (10s configured) + throttle
Start-Sleep -Seconds 30

Get-Service WarSOC_Relay
```

**Pass criteria:**
- NSSM restarts the process automatically (service returns to `Running`)
- No evidence is lost: relay resumes from the encrypted spool and outbox
- Check spool/outbox consistency in service-output.log

## 7. Uninstall Preservation Proof

```powershell
.\uninstall_warsoc_relay.ps1
```

**Pass criteria:**
- Service and firewall rules are removed
- Evidence spool directory is PRESERVED (not deleted) per the uninstaller's
  evidence-preservation contract
- Identity file is preserved or securely wiped per operator choice

## 8. Evidence Bundle

After all proofs pass, collect into a single directory (NOT committed to git):

| Evidence | Command to capture |
|---|---|
| Service status at each stage | `Get-Service WarSOC_Relay` output |
| DACL/SACL | `(Get-Acl "C:\ProgramData\WarSOCRelay") \| Format-List *` |
| Firewall rules | `Get-NetFirewallRule -DisplayName "WarSOC Relay - *"` |
| Audit policy | `auditpol /get /subcategory:"File System"` |
| Lifecycle logs | `service-output.log` and `service-error.log` |
| Event Viewer | Windows Application log entries for service start/stop/crash |
| VM spec | `Get-ComputerInfo \| Select-Object WindowsVersion, OsBuildNumber` |

## 9. Recording the Result

Update this runbook's status header to:

```
**Status:** `SERVER_PROVEN` on Windows Server <version> <build>, <date>
```

and record the SHA-256 of the relay executable used, matching the build manifest.
