[CmdletBinding()]
param(
    [ValidateSet("Generate", "Verify")]
    [string]$Phase = "Generate",
    [string]$InstallerPath = "",
    [string]$ActivationCode = "",
    [string]$BackendUrl = "https://api.warsoc.tech",
    [string]$PosPath = "C:\WarSOC-Validation-POS",
    [PSCredential]$Credential,
    [switch]$ConfirmDisposableVm,
    [int]$VerifyTimeoutSeconds = 180,
    [string]$ArtifactDirectory = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$StateDirectory = Join-Path $env:ProgramData "WarSOC"
$StatePath = Join-Path $StateDirectory "native-vm-validation.json"
$BackendUrl = $BackendUrl.TrimEnd("/")

function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Assert-LastExitCode {
    param([Parameter(Mandatory = $true)][string]$Operation)
    if ($LASTEXITCODE -ne 0) {
        throw "$Operation failed with exit code $LASTEXITCODE"
    }
}

function ConvertTo-UtcDate {
    param([object]$Value)
    try {
        return [DateTimeOffset]::Parse([string]$Value).UtcDateTime
    }
    catch {
        return $null
    }
}

function Get-LatestEventRecordId {
    param([Parameter(Mandatory = $true)][string]$Channel)
    $latest = Get-WinEvent -LogName $Channel -MaxEvents 1 -ErrorAction Stop
    return [int64]$latest.RecordId
}

function Initialize-ArtifactDirectory {
    param([Parameter(Mandatory = $true)][string]$Path)
    New-Item -ItemType Directory -Path $Path -Force | Out-Null
    & icacls.exe $Path /inheritance:r `
        /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" | Out-Null
    Assert-LastExitCode "Validation artifact directory ACL"
}

function Invoke-GeneratePhase {
    if (-not $ConfirmDisposableVm) {
        throw "Generate phase changes audit policy, creates temporary users/services, clears Security logs, and requires a reboot. Re-run on a snapshot VM with -ConfirmDisposableVm."
    }
    if (-not (Test-IsAdministrator)) {
        throw "Generate phase must run from an elevated PowerShell session."
    }
    if (-not $ActivationCode) {
        throw "-ActivationCode is required for Generate."
    }
    if (-not $InstallerPath) {
        $InstallerPath = Join-Path (Split-Path $PSScriptRoot -Parent) "Output\warsoc_installer.exe"
    }
    $resolvedInstaller = (Resolve-Path -LiteralPath $InstallerPath).Path

    New-Item -ItemType Directory -Path $PosPath -Force | Out-Null
    $installerArguments = @(
        "/VERYSILENT",
        "/SUPPRESSMSGBOXES",
        "/NORESTART",
        "/ACTIVATION_CODE=$ActivationCode",
        "/BACKEND_URL=$BackendUrl",
        "/POS_PATHS=$PosPath"
    )
    $install = Start-Process -FilePath $resolvedInstaller -ArgumentList $installerArguments -Wait -PassThru -WindowStyle Hidden
    if ($install.ExitCode -ne 0) {
        throw "Installer failed with exit code $($install.ExitCode)"
    }

    $service = Get-Service -Name "WarSOC_Agent" -ErrorAction Stop
    if ($service.Status -ne "Running") {
        throw "WarSOC_Agent is not running after installation."
    }

    $agentIdPath = Join-Path $StateDirectory ".agent_id"
    $agentIdDeadline = [DateTimeOffset]::UtcNow.AddSeconds(60)
    while (
        -not (Test-Path -LiteralPath $agentIdPath) -and
        [DateTimeOffset]::UtcNow -lt $agentIdDeadline
    ) {
        Start-Sleep -Seconds 2
    }
    if (-not (Test-Path -LiteralPath $agentIdPath)) {
        throw "The installed agent did not persist its assigned agent ID within 60 seconds."
    }
    $agentId = (Get-Content -Raw -LiteralPath $agentIdPath).Trim()
    if (-not $agentId) {
        throw "The installed agent ID is empty."
    }

    $runId = [Guid]::NewGuid().ToString("N").Substring(0, 10)
    $startedAt = [DateTimeOffset]::UtcNow
    $securityBaseline = Get-LatestEventRecordId -Channel "Security"
    $systemBaseline = Get-LatestEventRecordId -Channel "System"
    $resolvedArtifactDirectory = $ArtifactDirectory
    if (-not $resolvedArtifactDirectory) {
        $resolvedArtifactDirectory = Join-Path $StateDirectory "launch_artifacts\$runId"
    }
    Initialize-ArtifactDirectory -Path $resolvedArtifactDirectory

    $state = [ordered]@{
        run_id = $runId
        started_at = $startedAt.ToString("o")
        backend_url = $BackendUrl
        pos_path = $PosPath
        hostname = $env:COMPUTERNAME
        agent_id = $agentId
        artifact_directory = $resolvedArtifactDirectory
        channel_baselines = @{
            Security = $securityBaseline
            System = $systemBaseline
        }
        expected_peca_event_ids = @("4625", "1102", "4624", "4688", "4672", "4720", "4726", "4732", "4697", "7045", "1100")
        expected_fbr_event_ids = @("FBR-INV-MOD", "FBR-INV-DEL", "FIM-DB-MOD")
    }
    New-Item -ItemType Directory -Path $StateDirectory -Force | Out-Null
    $state | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $StatePath -Encoding UTF8
    Copy-Item -LiteralPath $StatePath -Destination (
        Join-Path $resolvedArtifactDirectory "native-vm-validation-state.json"
    ) -Force

    Start-Process -FilePath "$env:SystemRoot\System32\cmd.exe" -ArgumentList "/c", "echo WarSOC-$runId" -Wait -WindowStyle Hidden

    if (-not ("WarSOC.NativeLogon" -as [type])) {
        Add-Type @"
using System;
using System.Runtime.InteropServices;
namespace WarSOC {
    public static class NativeLogon {
        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool LogonUser(
            string username,
            string domain,
            string password,
            int logonType,
            int logonProvider,
            out IntPtr token);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool CloseHandle(IntPtr handle);
    }
}
"@
    }
    $failedToken = [IntPtr]::Zero
    [void][WarSOC.NativeLogon]::LogonUser(
        "WarSOC-Missing-$runId",
        $env:COMPUTERNAME,
        "Definitely-Wrong-$runId",
        2,
        0,
        [ref]$failedToken
    )

    $temporaryUser = "WSV$($runId.Substring(0, 8))"
    $temporaryPassword = "WsV-$runId-9!x"
    & net.exe user $temporaryUser $temporaryPassword /add | Out-Null
    Assert-LastExitCode "Temporary account creation"
    & net.exe localgroup Administrators $temporaryUser /add | Out-Null
    Assert-LastExitCode "Temporary administrator membership"

    $successfulToken = [IntPtr]::Zero
    $successfulLogon = [WarSOC.NativeLogon]::LogonUser(
        $temporaryUser,
        $env:COMPUTERNAME,
        $temporaryPassword,
        2,
        0,
        [ref]$successfulToken
    )
    if (-not $successfulLogon) {
        throw "Temporary administrator logon failed with Win32 error $([Runtime.InteropServices.Marshal]::GetLastWin32Error())."
    }
    if ($successfulToken -ne [IntPtr]::Zero) {
        [void][WarSOC.NativeLogon]::CloseHandle($successfulToken)
    }

    $taskName = "WarSOC-Validation-$runId"
    & schtasks.exe /Create /TN $taskName /TR "cmd.exe /c exit 0" /SC ONCE /ST 23:59 /RU SYSTEM /F | Out-Null
    Assert-LastExitCode "SYSTEM validation task creation"
    & schtasks.exe /Run /TN $taskName | Out-Null
    Assert-LastExitCode "SYSTEM validation task execution"

    $serviceName = "WarSOCValidation$($runId.Substring(0, 6))"
    & sc.exe create $serviceName binPath= "$env:SystemRoot\System32\cmd.exe /c exit 0" start= demand | Out-Null
    Assert-LastExitCode "Validation service creation"

    $databasePath = Join-Path $PosPath "warsoc-$runId.db"
    Set-Content -LiteralPath $databasePath -Value "WarSOC native FBR validation" -Encoding UTF8
    & icacls.exe $databasePath /grant "*S-1-5-32-545:R" | Out-Null
    Assert-LastExitCode "Database permission change"
    Remove-Item -LiteralPath $databasePath -Force

    $auditLogPath = Join-Path $StateDirectory "pos_audit.log"
    $invoiceBase = @{
        invoice_id = "INV-$runId"
        timestamp = [DateTimeOffset]::UtcNow.ToString("o")
        actor = "warsoc-vm-validator"
        source_system = "native-vm-validation"
    }
    $modified = $invoiceBase.Clone()
    $modified.event_id = "FBR-INV-MOD"
    $modified.event_uid = "$runId-invoice-modified"
    $modified.reason = "Disposable VM validation"
    $deleted = $invoiceBase.Clone()
    $deleted.event_id = "FBR-INV-DEL"
    $deleted.event_uid = "$runId-invoice-deleted"
    $deleted.reason = "Disposable VM validation"
    Add-Content -LiteralPath $auditLogPath -Value ($modified | ConvertTo-Json -Compress)
    Add-Content -LiteralPath $auditLogPath -Value ($deleted | ConvertTo-Json -Compress)

    Start-Sleep -Seconds 30
    & schtasks.exe /Delete /TN $taskName /F | Out-Null
    & sc.exe delete $serviceName | Out-Null
    & net.exe localgroup Administrators $temporaryUser /delete | Out-Null
    & net.exe user $temporaryUser /delete | Out-Null

    & wevtutil.exe cl Security
    Assert-LastExitCode "Security audit-log clear"
    Start-Sleep -Seconds 20

    Write-Host "[PASS] Native events generated and forwarded before log clear."
    Write-Host "[NEXT] Reboot this disposable VM normally to generate Event 1100."
    Write-Host "[NEXT] After reboot, wait 30 seconds and run this script with -Phase Verify -Credential (Get-Credential)."
}

function Get-BackendEvidence {
    param(
        [Parameter(Mandatory = $true)][Microsoft.PowerShell.Commands.WebRequestSession]$Session,
        [Parameter(Mandatory = $true)][string]$Pack,
        [Parameter(Mandatory = $true)][string]$EventId
    )
    $encodedId = [Uri]::EscapeDataString($EventId)
    $uri = "$BackendUrl/api/v1/compliance/evidence/$Pack`?event_id=$encodedId&limit=200"
    return Invoke-RestMethod -Uri $uri -Method Get -WebSession $Session -TimeoutSec 30
}

function Find-MatchingEvidence {
    param(
        [Parameter(Mandatory = $true)][object]$Response,
        [Parameter(Mandatory = $true)][DateTime]$StartedAt,
        [Parameter(Mandatory = $true)][string]$ExpectedAgentId,
        [Parameter(Mandatory = $true)][object]$ChannelBaselines,
        [string]$RunId = "",
        [string]$EventId = ""
    )
    $rows = @()
    if ($null -ne $Response.data) {
        $rows = @($Response.data)
    }
    
    $runIdEvents = @(
        "4624", "4625", "4672", "4688", "4720", "4726", "4732",
        "4697", "7045", "FBR-INV-MOD", "FBR-INV-DEL", "FIM-DB-MOD"
    )
    $nativeEventIds = @(
        "1100", "1102", "4624", "4625", "4672", "4688",
        "4720", "4726", "4732", "4697", "7045"
    )
    
    foreach ($row in $rows) {
        if ([string]$row.agent_id -ne $ExpectedAgentId) {
            continue
        }
        $candidate = $null
        if ($null -ne $row.timestamp) {
            $candidate = ConvertTo-UtcDate $row.timestamp
        }
        if (($null -eq $candidate) -and ($null -ne $row.ingested_at)) {
            $candidate = ConvertTo-UtcDate $row.ingested_at
        }
        if (($null -ne $candidate) -and ($candidate -ge $StartedAt.AddMinutes(-2))) {
            if ($nativeEventIds -contains $EventId) {
                $channel = if ($EventId -eq "7045") { "System" } else { "Security" }
                [int64]$recordId = 0
                if (
                    $null -ne $row.raw_event_data -and
                    $null -ne $row.raw_event_data.system -and
                    $null -ne $row.raw_event_data.system.event_record_id
                ) {
                    [void][int64]::TryParse(
                        [string]$row.raw_event_data.system.event_record_id,
                        [ref]$recordId
                    )
                }
                $baseline = [int64]$ChannelBaselines.$channel
                if ($recordId -le $baseline) {
                    continue
                }
            }
            if ($RunId -and ($runIdEvents -contains $EventId)) {
                $rowStr = $row | ConvertTo-Json -Depth 5 -Compress
                $shortId = $RunId.Substring(0, 6)
                if ($rowStr -match $shortId) {
                    return $row
                }
            } else {
                return $row
            }
        }
    }
    return $null
}

function Invoke-VerifyPhase {
    if (-not $Credential) {
        throw "-Credential is required for Verify. Use: -Credential (Get-Credential)"
    }
    if (-not (Test-Path -LiteralPath $StatePath)) {
        throw "Validation state not found at $StatePath"
    }
    $state = Get-Content -Raw -LiteralPath $StatePath | ConvertFrom-Json
    $startedAt = [DateTimeOffset]::Parse([string]$state.started_at).UtcDateTime
    $runId = $state.run_id
    $expectedAgentId = [string]$state.agent_id

    $plainPassword = $Credential.GetNetworkCredential().Password
    $loginBody = @{
        username = $Credential.UserName
        password = $plainPassword
    } | ConvertTo-Json
    $null = Invoke-RestMethod `
        -Uri "$BackendUrl/api/v1/auth/login" `
        -Method Post `
        -ContentType "application/json" `
        -Body $loginBody `
        -SessionVariable session `
        -TimeoutSec 30
    $plainPassword = $null
    $loginBody = $null

    $deadline = [DateTimeOffset]::UtcNow.AddSeconds($VerifyTimeoutSeconds)
    $pending = [ordered]@{}
    foreach ($eventId in @($state.expected_peca_event_ids)) {
        $pending["peca_forensic:$eventId"] = $null
    }
    foreach ($eventId in @($state.expected_fbr_event_ids)) {
        $pending["fbr_pos:$eventId"] = $null
    }

    while ([DateTimeOffset]::UtcNow -lt $deadline) {
        foreach ($key in @($pending.Keys)) {
            if ($null -ne $pending[$key]) {
                continue
            }
            $parts = $key.Split(":", 2)
            try {
                $response = Get-BackendEvidence -Session $session -Pack $parts[0] -EventId $parts[1]
                $pending[$key] = Find-MatchingEvidence `
                    -Response $response `
                    -StartedAt $startedAt `
                    -ExpectedAgentId $expectedAgentId `
                    -ChannelBaselines $state.channel_baselines `
                    -RunId $runId `
                    -EventId $parts[1]
            }
            catch {
                $pending[$key] = $null
            }
        }
        if (@($pending.Values | Where-Object { $null -eq $_ }).Count -eq 0) {
            break
        }
        Start-Sleep -Seconds 5
    }

    $failures = @(
        $pending.GetEnumerator() |
            Where-Object { $null -eq $_.Value } |
            ForEach-Object { $_.Key }
    )
    $latencyFailures = @()
    $results = @()
    foreach ($key in $pending.Keys) {
        $row = $pending[$key]
        $label = if ($null -ne $row) { "PASS" } else { "FAIL" }
        Write-Host "[$label] $key"
        if ($null -eq $row) {
            $results += [ordered]@{ check = $key; status = "fail" }
            continue
        }

        $eventId = $key.Split(":", 2)[1]
        $eventTime = ConvertTo-UtcDate $row.timestamp
        $ingestedTime = ConvertTo-UtcDate $row.ingested_at
        $latencySeconds = $null
        if ($null -ne $eventTime -and $null -ne $ingestedTime) {
            $latencySeconds = [Math]::Max(
                0,
                [Math]::Round(($ingestedTime - $eventTime).TotalSeconds, 3)
            )
            $limit = if ($eventId -eq "1100") { 120 } else { 15 }
            if ($latencySeconds -gt $limit) {
                $latencyFailures += "$key ($latencySeconds seconds)"
            }
        }
        $results += [ordered]@{
            check = $key
            status = "pass"
            evidence_id = $row.id
            event_uid = $row.event_uid
            agent_id = $row.agent_id
            timestamp = $row.timestamp
            ingested_at = $row.ingested_at
            detection_latency_seconds = $latencySeconds
        }
    }

    $coverage = Invoke-RestMethod `
        -Uri "$BackendUrl/api/v1/compliance/coverage" `
        -Method Get `
        -WebSession $session `
        -TimeoutSec 30
    $agentStatus = Invoke-RestMethod `
        -Uri "$BackendUrl/api/v1/data/status" `
        -Method Get `
        -WebSession $session `
        -TimeoutSec 30
    $coverageFailures = @(
        $coverage.coverage |
            Where-Object {
                $_.pack_id -in @("peca_forensic", "fbr_pos") -and
                $_.status -ne "active"
            } |
            ForEach-Object { "$($_.pack_id):$($_.status)" }
    )
    $matchingAgent = @(
        $agentStatus.data | Where-Object { $_.agent_id -eq $expectedAgentId }
    ) | Select-Object -First 1
    $matchingAgentHealth = if ($null -eq $matchingAgent) {
        "missing"
    } else {
        [string]$matchingAgent.health
    }
    if ($matchingAgentHealth -ne "active") {
        $coverageFailures += "agent_health:$matchingAgentHealth"
    }

    $artifactDirectory = [string]$state.artifact_directory
    Initialize-ArtifactDirectory -Path $artifactDirectory
    $report = [ordered]@{
        run_id = $runId
        verified_at = [DateTimeOffset]::UtcNow.ToString("o")
        agent_id = $expectedAgentId
        hostname = $state.hostname
        evidence_results = $results
        evidence_failures = $failures
        latency_failures = $latencyFailures
        coverage_failures = $coverageFailures
        coverage = $coverage.coverage
        agent_health = $matchingAgent
        passed = (
            $failures.Count -eq 0 -and
            $latencyFailures.Count -eq 0 -and
            $coverageFailures.Count -eq 0
        )
    }
    $reportPath = Join-Path $artifactDirectory "native-vm-validation-result.json"
    $report | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $reportPath -Encoding UTF8

    if ($failures.Count -gt 0 -or $latencyFailures.Count -gt 0 -or $coverageFailures.Count -gt 0) {
        Write-Error (
            "Native VM validation failed. Evidence: $($failures -join ', '); " +
            "latency: $($latencyFailures -join ', '); coverage: $($coverageFailures -join ', '). " +
            "Report: $reportPath"
        )
        exit 1
    }
    Write-Host "[PASS] All native controls, FBR evidence, latency, and coverage checks passed."
    Write-Host "[ARTIFACT] $reportPath"
}

if ($Phase -eq "Generate") {
    Invoke-GeneratePhase
}
else {
    Invoke-VerifyPhase
}
