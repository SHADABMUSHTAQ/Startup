[CmdletBinding()]
param(
    [string]$InstallDirectory = "C:\Program Files\WarSOC Relay"
)

$ErrorActionPreference = "Stop"
$serviceName = "WarSOC_Relay"
$nssm = Join-Path $InstallDirectory "nssm.exe"

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run this uninstaller from an elevated PowerShell session."
}

$service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
if ($service) {
    Stop-Service -Name $serviceName -Force -ErrorAction SilentlyContinue
    if (Test-Path -LiteralPath $nssm) {
        & $nssm remove $serviceName confirm | Out-Null
    }
    else {
        & sc.exe delete $serviceName | Out-Null
    }
}
Get-NetFirewallRule -DisplayName "WarSOC Relay - *" -ErrorAction SilentlyContinue | `
    Remove-NetFirewallRule -ErrorAction Stop

Write-Host "WarSOC Relay service and firewall rules removed." -ForegroundColor Green
Write-Host "Relay binaries and C:\ProgramData\WarSOCRelay evidence were preserved intentionally."
