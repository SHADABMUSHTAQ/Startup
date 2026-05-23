<#
.SYNOPSIS
    WarSOC Enterprise Agent - Automated Installer
.DESCRIPTION
    Installs the WarSOC telemetry agent, provisions the cryptographic environment,
    and registers the background Windows Service using NSSM (Non-Sucking Service Manager).
    Must be run as Administrator.
#>

param (
    [Parameter(Mandatory=$true)][string]$TenantID,
    [Parameter(Mandatory=$true)][string]$AgentToken,
    [string]$BackendIP = "127.0.0.1" # Defaulting for local testing
)

# 1. Enforce Administrator Privileges
if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Warning "CRITICAL: WarSOC Installer must be run as Administrator."
    exit
}

$InstallDir = "C:\Program Files\WarSOC Agent"
$LogDir = "$InstallDir\logs"
$EnvPath = "$InstallDir\.env"
$ExePath = "$InstallDir\warsoc_agent.exe" 

Write-Host "[*] Initializing WarSOC Deployment for Tenant: $TenantID" -ForegroundColor Cyan

# 2. Build the Directory Structure
if (!(Test-Path -Path $InstallDir)) {
    New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
    New-Item -ItemType Directory -Force -Path $LogDir | Out-Null
    Write-Host "[+] Created secure directories at $InstallDir" -ForegroundColor Green
}

# 3. Provision the Cryptographic Environment (.env)
Write-Host "[*] Provisioning Agent Vault..." -ForegroundColor Cyan
$EnvContent = @"
TENANT_ID=$TenantID
AGENT_MASTER_SECRET=$AgentToken
BACKEND_URL=http://$BackendIP:8000
ENVIRONMENT=production
"@
Set-Content -Path $EnvPath -Value $EnvContent
# Secure the .env file (SYSTEM and Admin access only)
icacls $EnvPath /inheritance:r /grant "Administrators:F" /grant "SYSTEM:F" | Out-Null
Write-Host "[+] Environment locked." -ForegroundColor Green

# 4. Copy the Agent Binary 
$SourceExe = Join-Path $PSScriptRoot "warsoc_agent.exe"
if (Test-Path $SourceExe) {
    Copy-Item -Path $SourceExe -Destination $ExePath -Force
    Write-Host "[+] Agent binary deployed." -ForegroundColor Green
} else {
    Write-Error "CRITICAL: warsoc_agent.exe not found in deployment folder. Please place the PyInstaller executable next to this script."
    exit
}

$SourcePolicy = Join-Path $PSScriptRoot "tenant_policy.json"
if (Test-Path $SourcePolicy) {
    Copy-Item -Path $SourcePolicy -Destination (Join-Path $InstallDir "tenant_policy.json") -Force
    Write-Host "[+] Tenant policy deployed." -ForegroundColor Green
} else {
    Write-Warning "tenant_policy.json not found in deployment folder. The agent may exit if no runtime policy is available."
}

# 5. Register and Start via Scheduled Task (Native Windows, No SCM Timeout)
Write-Host "[*] Registering WarSOC Telemetry as a Background Task..." -ForegroundColor Cyan
$TaskName = "WarSOC_Agent"

# Remove existing task if updating
Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue

# Create the Scheduled Task Action and Trigger
$Action = New-ScheduledTaskAction -Execute $ExePath -WorkingDirectory $InstallDir
$Trigger = New-ScheduledTaskTrigger -AtStartup
$Settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Days 0) -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)

# Register as SYSTEM
Register-ScheduledTask -TaskName $TaskName -Action $Action -Trigger $Trigger -Settings $Settings -User "NT AUTHORITY\SYSTEM" -RunLevel Highest -Force | Out-Null

# Start the engine immediately
Start-ScheduledTask -TaskName $TaskName
Write-Host "[SUCCESS] WarSOC Agent is now running and streaming telemetry." -ForegroundColor Green
