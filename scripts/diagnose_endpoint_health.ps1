[CmdletBinding()]
param(
    [string]$SpoolPath = "$env:ProgramData\WarSOC\spool",
    [string]$InstallPath = "${env:ProgramFiles(x86)}\WarSOC",
    [string]$BackendUrl = "https://api.warsoc.tech"
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$Identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$Principal = New-Object Security.Principal.WindowsPrincipal($Identity)
if (-not $Principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Open PowerShell as Administrator and run this read-only diagnostic again.'
}
$Backend = [uri]$BackendUrl
if ($Backend.Scheme -ne 'https' -or $Backend.UserInfo -or $Backend.Query -or $Backend.Fragment) {
    throw 'Use the configured HTTPS backend origin without credentials, query or fragment.'
}

Get-Service -Name WarSOC_Agent | Select-Object Name, Status, StartType | Format-Table
try {
    $Health = Invoke-RestMethod -Uri ($BackendUrl.TrimEnd('/') + '/health') -TimeoutSec 10
    Write-Host "Backend health: $($Health.status)"
} catch {
    Write-Warning 'Backend health could not be reached. Check DNS, HTTPS and the endpoint network.'
}

if (-not (Test-Path -LiteralPath $SpoolPath -PathType Container)) {
    throw "Spool directory was not found: $SpoolPath"
}
$Files = @(Get-ChildItem -LiteralPath $SpoolPath -Filter '*.jsonl' -File)
$TotalBytes = [int64](($Files | Measure-Object -Property Length -Sum).Sum)
$Rejected = @($Files | Where-Object Name -eq 'rejected_logs.jsonl')
$RejectedBytes = [int64](($Rejected | Measure-Object -Property Length -Sum).Sum)
$AcknowledgedBytes = [int64]0
$InvalidCursors = 0
foreach ($File in @($Files | Where-Object Name -like 'processing_*.jsonl')) {
    $OffsetFile = $File.FullName + '.offset'
    if (Test-Path -LiteralPath $OffsetFile -PathType Leaf) {
        $Offset = [int64]0
        $Text = (Get-Content -LiteralPath $OffsetFile -Raw).Trim()
        if ([int64]::TryParse($Text, [ref]$Offset) -and $Offset -ge 0 -and $Offset -le $File.Length) {
            $AcknowledgedBytes += $Offset
        } else {
            $InvalidCursors += 1
        }
    }
}
[pscustomobject]@{
    SpoolFiles = $Files.Count
    PhysicalSpoolBytes = $TotalBytes
    RejectedEvidenceBytes = $RejectedBytes
    AcknowledgedPrefixBytes = $AcknowledgedBytes
    PendingDeliveryBytes = [Math]::Max(0, $TotalBytes - $RejectedBytes - $AcknowledgedBytes)
    InvalidCursors = $InvalidCursors
} | Format-List
$Files | Select-Object Name, Length, LastWriteTimeUtc | Format-Table -AutoSize

$Executable = Join-Path $InstallPath 'warsoc_agent.exe'
if (Test-Path -LiteralPath $Executable -PathType Leaf) {
    Get-FileHash -LiteralPath $Executable -Algorithm SHA256 | Select-Object Algorithm, Hash | Format-List
}
$Log = Join-Path $InstallPath 'logs\warsoc_agent.out.log'
if (Test-Path -LiteralPath $Log -PathType Leaf) {
    # Report known delivery categories only; never emit event bodies or credentials.
    $Signals = @(Get-Content -LiteralPath $Log -Tail 400 | ForEach-Object {
        if ($_ -match 'Backend rejected payload\s+(\d{3})') { "HTTP_$($Matches[1])" }
        elseif ($_ -match 'Bulk Sender Crash') { 'SENDER_ERROR' }
        elseif ($_ -match 'Connection Error|Backend Unavailable') { 'DELIVERY_UNAVAILABLE' }
        elseif ($_ -match 'rate limited') { 'RATE_LIMITED' }
        elseif ($_ -match 'spool hard limit') { 'SPOOL_LIMIT' }
    })
    $Signals | Group-Object | Select-Object Name, Count | Format-Table
}
Write-Host 'No evidence, enrollment, audit policy or firewall configuration was modified.'
Write-Host 'If blocked: repair delivery/rejections, then use the approved current agent and verify drain below the reported resume boundary.'
Write-Host 'Do not delete spool files, reset event cursors, uninstall the agent, or use an unlimited spool.'
