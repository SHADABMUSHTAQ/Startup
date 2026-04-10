[CmdletBinding()]
param(
    [Alias("Uninstall")][switch]$Rollback,
    [string]$SysmonUri = "https://live.sysinternals.com/Sysmon64.exe",
    [string]$ConfigPath = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if ([string]::IsNullOrWhiteSpace($ConfigPath)) {
    $scriptDirectory = Split-Path -Parent $MyInvocation.MyCommand.Path
    $ConfigPath = Join-Path $scriptDirectory "sysmon-config.xml"
}

$ScriptVersion = "2.0.0"
$EventLogName = "Application"
$EventSource = "WarSOC-TelemetryDeploy"
$AuditRegPath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
$AuditRegName = "ProcessCreationIncludeCmdLine_Enabled"
$SysmonExePath = Join-Path $env:TEMP "Sysmon64.exe"
$PrimaryArtifactDir = Join-Path $env:ProgramData "WarSOC"
$FallbackArtifactDir = Join-Path $env:TEMP "WarSOC"

$EventIds = @{
    InstallSuccess = 7001
    InstallFailure = 7002
    UpdateSuccess = 7003
    RollbackSuccess = 7004
    RollbackFailure = 7005
    IntegrityFailure = 7006
    AdminGateFailure = 7007
}

$script:ArtifactDir = $null
$script:ArtifactPath = $null
$script:StatePath = $null
$script:PendingEventPath = $null
$script:TelemetryContext = [ordered]@{
    sysmon_config_sha256 = ""
    sysmon_config_version = ""
    sysmon_binary_sha256 = ""
    signer_subject = ""
    signer_thumbprint = ""
}

function Test-IsAdmin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-Operator {
    try {
        return [Security.Principal.WindowsIdentity]::GetCurrent().Name
    } catch {
        return $env:USERNAME
    }
}

function Get-ConfigVersion {
    param([string]$Path)

    if (-not (Test-Path $Path)) {
        return "missing"
    }

    $firstLines = Get-Content -Path $Path -TotalCount 20
    foreach ($line in $firstLines) {
        if ($line -match "WarSOC-Config-Version:\s*([0-9A-Za-z._-]+)") {
            return $Matches[1]
        }
    }

    return "unversioned"
}

function Get-FileSha256 {
    param([string]$Path)

    if (-not (Test-Path $Path)) {
        return ""
    }

    return (Get-FileHash -Path $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Get-ArtifactDirectory {
    foreach ($candidate in @($PrimaryArtifactDir, $FallbackArtifactDir)) {
        try {
            if (-not (Test-Path $candidate)) {
                New-Item -ItemType Directory -Path $candidate -Force | Out-Null
            }
            return $candidate
        } catch {
            continue
        }
    }

    throw "Unable to create artifact directory in ProgramData or TEMP."
}

function Initialize-EvidencePaths {
    $script:ArtifactDir = Get-ArtifactDirectory
    $script:ArtifactPath = Join-Path $script:ArtifactDir "telemetry-deploy.json"
    $script:StatePath = Join-Path $script:ArtifactDir "telemetry-state.json"
    $script:PendingEventPath = Join-Path $script:ArtifactDir "telemetry-eventlog-pending.json"
}

function Write-PendingEventArtifact {
    param(
        [int]$EventId,
        [string]$EntryType,
        [string]$Message,
        [hashtable]$Record,
        [string]$Reason
    )

    $pendingRecord = [ordered]@{
        timestamp_utc = (Get-Date).ToUniversalTime().ToString("o")
        event_id = $EventId
        entry_type = $EntryType
        source = $EventSource
        log_name = $EventLogName
        reason = $Reason
        message = $Message
        payload = $Record
    }

    $pendingJson = $pendingRecord | ConvertTo-Json -Compress -Depth 8
    Add-Content -Path $script:PendingEventPath -Value $pendingJson -Encoding UTF8
}

function Flush-PendingEventArtifacts {
    if (-not (Test-Path $script:PendingEventPath)) {
        return
    }

    if (-not (Ensure-EventSource)) {
        return
    }

    $failedLines = @()
    $pendingLines = Get-Content -Path $script:PendingEventPath
    foreach ($line in $pendingLines) {
        if ([string]::IsNullOrWhiteSpace($line)) {
            continue
        }

        try {
            $pending = $line | ConvertFrom-Json
            Write-EventLog -LogName $EventLogName -Source $EventSource -EventId ([int]$pending.event_id) -EntryType ([string]$pending.entry_type) -Category 0 -Message ([string]$pending.message)
        } catch {
            $failedLines += $line
        }
    }

    if ($failedLines.Count -eq 0) {
        Remove-Item -Path $script:PendingEventPath -ErrorAction SilentlyContinue
        return
    }

    Set-Content -Path $script:PendingEventPath -Value $failedLines -Encoding UTF8
}

function Ensure-EventSource {
    try {
        if (-not [System.Diagnostics.EventLog]::SourceExists($EventSource)) {
            New-EventLog -LogName $EventLogName -Source $EventSource
        }
        return $true
    } catch {
        return $false
    }
}

function Write-LocalArtifact {
    param(
        [hashtable]$Record
    )

    $json = $Record | ConvertTo-Json -Compress -Depth 8
    Add-Content -Path $script:ArtifactPath -Value $json -Encoding UTF8
}

function Write-EventArtifact {
    param(
        [int]$EventId,
        [ValidateSet("Information", "Warning", "Error")][string]$EntryType,
        [string]$Operation,
        [string]$Status,
        [int]$ExitCode,
        [string]$Detail,
        [hashtable]$Record
    )

    $recordJson = $Record | ConvertTo-Json -Compress -Depth 8
    $message = "operation=$Operation status=$Status exit_code=$ExitCode script_version=$ScriptVersion config_version=$($script:TelemetryContext.sysmon_config_version) host=$($Record.hostname)"
    if ($Detail) {
        $message = "$message`nmessage=$Detail"
    }
    $message = "$message`njson=$recordJson"

    if (-not (Ensure-EventSource)) {
        Write-PendingEventArtifact -EventId $EventId -EntryType $EntryType -Message $message -Record $Record -Reason "event_source_unavailable_or_permission_denied"
        return
    }

    try {
        Write-EventLog -LogName $EventLogName -Source $EventSource -EventId $EventId -EntryType $EntryType -Category 0 -Message $message
    } catch {
        Write-PendingEventArtifact -EventId $EventId -EntryType $EntryType -Message $message -Record $Record -Reason "write_eventlog_failed"
        Write-Warning "Failed to write deployment event log evidence: $($_.Exception.Message)"
    }
}

function Publish-Evidence {
    param(
        [string]$Operation,
        [string]$Status,
        [int]$ExitCode,
        [int]$EventId,
        [ValidateSet("Information", "Warning", "Error")][string]$EntryType,
        [string]$Detail = ""
    )

    $record = [ordered]@{
        operation = $Operation
        status = $Status
        timestamp_utc = (Get-Date).ToUniversalTime().ToString("o")
        script_version = $ScriptVersion
        sysmon_config_sha256 = $script:TelemetryContext.sysmon_config_sha256
        sysmon_config_version = $script:TelemetryContext.sysmon_config_version
        sysmon_binary_sha256 = $script:TelemetryContext.sysmon_binary_sha256
        signer_subject = $script:TelemetryContext.signer_subject
        signer_thumbprint = $script:TelemetryContext.signer_thumbprint
        hostname = $env:COMPUTERNAME
        operator = (Get-Operator)
        rollback_marker = [bool]$Rollback
        exit_code = $ExitCode
        artifact_path = $script:ArtifactPath
    }

    if ($Detail) {
        $record.error_detail = $Detail
    }

    Write-LocalArtifact -Record $record
    Write-EventArtifact -EventId $EventId -EntryType $EntryType -Operation $Operation -Status $Status -ExitCode $ExitCode -Detail $Detail -Record $record
}

function Exit-WithEvidence {
    param(
        [string]$Operation,
        [string]$Status,
        [int]$ExitCode,
        [int]$EventId,
        [ValidateSet("Information", "Warning", "Error")][string]$EntryType,
        [string]$Detail = ""
    )

    Publish-Evidence -Operation $Operation -Status $Status -ExitCode $ExitCode -EventId $EventId -EntryType $EntryType -Detail $Detail
    exit $ExitCode
}

function Get-ProcessCreationAuditSetting {
    $output = (& auditpol /get /subcategory:"Process Creation") 2>&1
    foreach ($line in $output) {
        if ($line -match "Process Creation\s+(No Auditing|Success and Failure|Success|Failure)") {
            return $Matches[1]
        }
    }
    return "Unknown"
}

function Set-ProcessCreationAuditSetting {
    param([string]$Setting)

    switch ($Setting) {
        "Success and Failure" {
            & auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable | Out-Null
        }
        "Success" {
            & auditpol /set /subcategory:"Process Creation" /success:enable /failure:disable | Out-Null
        }
        "Failure" {
            & auditpol /set /subcategory:"Process Creation" /success:disable /failure:enable | Out-Null
        }
        default {
            & auditpol /set /subcategory:"Process Creation" /success:disable /failure:disable | Out-Null
        }
    }

    if ($LASTEXITCODE -ne 0) {
        throw "Failed to set Process Creation audit policy to '$Setting'."
    }
}

function Save-PreDeploymentState {
    $previousAuditSetting = Get-ProcessCreationAuditSetting

    $state = [ordered]@{
        timestamp_utc = (Get-Date).ToUniversalTime().ToString("o")
        previous_audit_setting = $previousAuditSetting
        registry_value_present = $false
        registry_value = $null
    }

    $existing = Get-ItemProperty -Path $AuditRegPath -Name $AuditRegName -ErrorAction SilentlyContinue
    if ($null -ne $existing) {
        $state.registry_value_present = $true
        $state.registry_value = [int]$existing.$AuditRegName
    }

    $state | ConvertTo-Json -Depth 4 | Set-Content -Path $script:StatePath -Encoding UTF8
}

function Enable-AuditControls {
    Save-PreDeploymentState
    Set-ProcessCreationAuditSetting -Setting "Success and Failure"

    if (-not (Test-Path $AuditRegPath)) {
        New-Item -Path $AuditRegPath -Force | Out-Null
    }

    New-ItemProperty -Path $AuditRegPath -Name $AuditRegName -Value 1 -PropertyType DWord -Force | Out-Null
}

function Restore-AuditControls {
    $targetSetting = "No Auditing"
    $restoreRegistryValue = $null
    $restoreRegistryPresence = $false

    if (Test-Path $script:StatePath) {
        $savedState = Get-Content -Path $script:StatePath -Raw | ConvertFrom-Json
        if ($savedState.previous_audit_setting) {
            $targetSetting = [string]$savedState.previous_audit_setting
        }
        $restoreRegistryPresence = [bool]$savedState.registry_value_present
        $restoreRegistryValue = $savedState.registry_value
    }

    Set-ProcessCreationAuditSetting -Setting $targetSetting

    if ($restoreRegistryPresence) {
        New-ItemProperty -Path $AuditRegPath -Name $AuditRegName -Value ([int]$restoreRegistryValue) -PropertyType DWord -Force | Out-Null
    } else {
        Remove-ItemProperty -Path $AuditRegPath -Name $AuditRegName -ErrorAction SilentlyContinue
    }

    Remove-Item -Path $script:StatePath -ErrorAction SilentlyContinue
}

function Download-AndValidateSysmonBinary {
    param([string]$OperationForEvidence)

    Invoke-WebRequest -Uri $SysmonUri -OutFile $SysmonExePath
    $script:TelemetryContext.sysmon_binary_sha256 = Get-FileSha256 -Path $SysmonExePath

    $signature = Get-AuthenticodeSignature -FilePath $SysmonExePath
    if ($signature.Status -ne "Valid") {
        Exit-WithEvidence -Operation $OperationForEvidence -Status "failed" -ExitCode 20 -EventId $EventIds.IntegrityFailure -EntryType Error -Detail "Authenticode validation failed: $($signature.Status)"
    }

    if ($null -eq $signature.SignerCertificate) {
        Exit-WithEvidence -Operation $OperationForEvidence -Status "failed" -ExitCode 21 -EventId $EventIds.IntegrityFailure -EntryType Error -Detail "Signer certificate missing on downloaded Sysmon binary."
    }

    $subject = [string]$signature.SignerCertificate.Subject
    if ($subject -notmatch "Microsoft Corporation") {
        Exit-WithEvidence -Operation $OperationForEvidence -Status "failed" -ExitCode 22 -EventId $EventIds.IntegrityFailure -EntryType Error -Detail "Unexpected signer subject: $subject"
    }

    $script:TelemetryContext.signer_subject = $subject
    $script:TelemetryContext.signer_thumbprint = [string]$signature.SignerCertificate.Thumbprint
}

function Get-SysmonService {
    return Get-Service -Name "Sysmon64", "Sysmon" -ErrorAction SilentlyContinue | Select-Object -First 1
}

function Invoke-SysmonInstallOrUpdate {
    if (-not (Test-Path $ConfigPath)) {
        Exit-WithEvidence -Operation "install" -Status "failed" -ExitCode 10 -EventId $EventIds.InstallFailure -EntryType Error -Detail "sysmon-config.xml not found at: $ConfigPath"
    }

    $script:TelemetryContext.sysmon_config_sha256 = Get-FileSha256 -Path $ConfigPath
    $script:TelemetryContext.sysmon_config_version = Get-ConfigVersion -Path $ConfigPath

    Enable-AuditControls

    $existingService = Get-SysmonService
    $operation = if ($null -ne $existingService) { "update" } else { "install" }

    Download-AndValidateSysmonBinary -OperationForEvidence $operation

    if ($operation -eq "install") {
        Write-Host "[*] Installing Sysmon with WarSOC configuration..."
        & $SysmonExePath -accepteula -i $ConfigPath
        if ($LASTEXITCODE -ne 0) {
            Exit-WithEvidence -Operation "install" -Status "failed" -ExitCode 30 -EventId $EventIds.InstallFailure -EntryType Error -Detail "Sysmon install command failed with exit code $LASTEXITCODE"
        }
        Exit-WithEvidence -Operation "install" -Status "success" -ExitCode 0 -EventId $EventIds.InstallSuccess -EntryType Information
    }

    Write-Host "[*] Updating existing Sysmon configuration..."
    & $SysmonExePath -c $ConfigPath
    if ($LASTEXITCODE -ne 0) {
        Exit-WithEvidence -Operation "update" -Status "failed" -ExitCode 31 -EventId $EventIds.InstallFailure -EntryType Error -Detail "Sysmon config update failed with exit code $LASTEXITCODE"
    }

    Exit-WithEvidence -Operation "update" -Status "success" -ExitCode 0 -EventId $EventIds.UpdateSuccess -EntryType Information
}

function Invoke-Rollback {
    $script:TelemetryContext.sysmon_config_sha256 = Get-FileSha256 -Path $ConfigPath
    $script:TelemetryContext.sysmon_config_version = Get-ConfigVersion -Path $ConfigPath

    $sysmonService = Get-SysmonService
    if ($null -ne $sysmonService) {
        Download-AndValidateSysmonBinary -OperationForEvidence "rollback"
        Write-Host "[*] Uninstalling Sysmon..."
        & $SysmonExePath -u force
        if ($LASTEXITCODE -ne 0) {
            Exit-WithEvidence -Operation "rollback" -Status "failed" -ExitCode 40 -EventId $EventIds.RollbackFailure -EntryType Error -Detail "Sysmon uninstall failed with exit code $LASTEXITCODE"
        }
    }

    Restore-AuditControls
    Exit-WithEvidence -Operation "rollback" -Status "success" -ExitCode 0 -EventId $EventIds.RollbackSuccess -EntryType Information
}

Write-Host "========== WARSOC TELEMETRY DEPLOYMENT V2 ==========" -ForegroundColor Cyan
Initialize-EvidencePaths

if (-not (Test-IsAdmin)) {
    Exit-WithEvidence -Operation "admin_gate" -Status "failed" -ExitCode 5 -EventId $EventIds.AdminGateFailure -EntryType Error -Detail "Please run this script as Administrator."
}

Flush-PendingEventArtifacts

try {
    if ($Rollback) {
        Invoke-Rollback
    } else {
        Invoke-SysmonInstallOrUpdate
    }
} catch {
    $errorText = $_.Exception.Message
    if ($Rollback) {
        Exit-WithEvidence -Operation "rollback" -Status "failed" -ExitCode 50 -EventId $EventIds.RollbackFailure -EntryType Error -Detail $errorText
    }

    Exit-WithEvidence -Operation "install" -Status "failed" -ExitCode 51 -EventId $EventIds.InstallFailure -EntryType Error -Detail $errorText
}
