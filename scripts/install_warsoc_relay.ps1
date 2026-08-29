[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$RelayExecutable,

    [Parameter(Mandatory = $true)]
    [string]$NssmExecutable,

    [Parameter(Mandatory = $true)]
    [string]$ConfigFile,

    [string]$InstallDirectory = "C:\Program Files\WarSOC Relay",
    [string]$DataDirectory = "C:\ProgramData\WarSOCRelay",
    [switch]$AllowWorkstation,
    [switch]$AllowEndpointColocation
)

$ErrorActionPreference = "Stop"
$serviceName = "WarSOC_Relay"
$firewallPrefix = "WarSOC Relay - "

function Assert-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "Run this installer from an elevated PowerShell session."
    }
}

function Set-RelayDirectorySecurity([string]$Path) {
    & auditpol.exe /set /subcategory:"File System" /success:enable /failure:enable | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "Unable to enable native File System auditing for the relay spool."
    }

    $system = [Security.Principal.SecurityIdentifier]::new("S-1-5-18")
    $everyone = [Security.Principal.SecurityIdentifier]::new("S-1-1-0")
    $inheritance = [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor `
        [Security.AccessControl.InheritanceFlags]::ObjectInherit
    $propagation = [Security.AccessControl.PropagationFlags]::None

    $acl = [Security.AccessControl.DirectorySecurity]::new()
    $acl.SetAccessRuleProtection($true, $false)
    $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
        $system,
        [Security.AccessControl.FileSystemRights]::FullControl,
        $inheritance,
        $propagation,
        [Security.AccessControl.AccessControlType]::Allow
    ))
    $auditRights = [Security.AccessControl.FileSystemRights]::Delete -bor `
        [Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor `
        [Security.AccessControl.FileSystemRights]::ChangePermissions -bor `
        [Security.AccessControl.FileSystemRights]::TakeOwnership -bor `
        [Security.AccessControl.FileSystemRights]::WriteData
    $acl.AddAuditRule([Security.AccessControl.FileSystemAuditRule]::new(
        $everyone,
        $auditRights,
        $inheritance,
        $propagation,
        [Security.AccessControl.AuditFlags]::Success -bor [Security.AccessControl.AuditFlags]::Failure
    ))
    Set-Acl -LiteralPath $Path -AclObject $acl
}

Assert-Administrator
$RelayExecutable = (Resolve-Path -LiteralPath $RelayExecutable).Path
$NssmExecutable = (Resolve-Path -LiteralPath $NssmExecutable).Path
$ConfigFile = (Resolve-Path -LiteralPath $ConfigFile).Path
$config = Get-Content -LiteralPath $ConfigFile -Raw | ConvertFrom-Json

$os = Get-CimInstance Win32_OperatingSystem
if ($os.ProductType -eq 1 -and -not $AllowWorkstation) {
    throw "Relay installation requires Windows Server. Use -AllowWorkstation only for an approved back-office pilot host."
}
$endpointService = Get-Service -Name "WarSOC_Agent" -ErrorAction SilentlyContinue
if ($endpointService -and -not $AllowEndpointColocation) {
    throw "WarSOC Endpoint is installed. Relay co-location requires the explicit -AllowEndpointColocation override."
}
if ($config.backend_url -notmatch '^https://') {
    throw "Relay backend_url must use HTTPS."
}
if ([IO.Path]::GetFullPath($config.data_directory) -ne [IO.Path]::GetFullPath($DataDirectory)) {
    throw "Config data_directory must match -DataDirectory."
}

$drive = Get-PSDrive -Name ([IO.Path]::GetPathRoot($DataDirectory).Substring(0, 1))
$required = [int64]$config.evidence_spool_bytes + [int64]$config.control_spool_bytes + `
    [int64]$config.minimum_free_disk_bytes
if ($drive.Free -lt $required) {
    throw "Insufficient free disk for the configured relay spool and reserve."
}

New-Item -ItemType Directory -Force -Path $InstallDirectory, $DataDirectory | Out-Null
Copy-Item -LiteralPath $RelayExecutable -Destination (Join-Path $InstallDirectory "warsoc_relay.exe") -Force
Copy-Item -LiteralPath $NssmExecutable -Destination (Join-Path $InstallDirectory "nssm.exe") -Force
Copy-Item -LiteralPath $ConfigFile -Destination (Join-Path $DataDirectory "relay-config.json") -Force

$identityPath = Join-Path $DataDirectory $config.identity_file
if (-not (Test-Path -LiteralPath $identityPath)) {
    $secureCode = Read-Host "Paste the tenant-issued WarSOC Relay activation or recovery code" -AsSecureString
    $pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureCode)
    try {
        $code = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer)
        if ([string]::IsNullOrWhiteSpace($code) -or $code.Length -lt 16) {
            throw "Relay activation code is invalid."
        }
        [IO.File]::WriteAllText((Join-Path $DataDirectory $config.activation_file), $code)
    }
    finally {
        if ($pointer -ne [IntPtr]::Zero) {
            [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer)
        }
        $code = $null
    }
}

Get-NetFirewallRule -DisplayName "$firewallPrefix*" -ErrorAction SilentlyContinue | `
    Remove-NetFirewallRule -ErrorAction Stop
foreach ($listener in $config.listeners) {
    $sources = @($config.devices | Where-Object transport -eq $listener.transport | `
        ForEach-Object { $_.source_addresses } | Select-Object -Unique)
    if ($sources.Count -eq 0) {
        throw "Listener $($listener.transport) has no registered source contract."
    }
    $protocol = if ($listener.transport -eq "udp") { "UDP" } else { "TCP" }
    New-NetFirewallRule `
        -DisplayName "$firewallPrefix$($listener.transport)-$($listener.port)" `
        -Direction Inbound `
        -Action Allow `
        -Protocol $protocol `
        -LocalAddress $listener.bind_host `
        -LocalPort $listener.port `
        -RemoteAddress $sources `
        -Profile Domain,Private | Out-Null
}

$nssm = Join-Path $InstallDirectory "nssm.exe"
$relay = Join-Path $InstallDirectory "warsoc_relay.exe"
$service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
if ($service) {
    Stop-Service -Name $serviceName -Force -ErrorAction SilentlyContinue
    & $nssm remove $serviceName confirm | Out-Null
}
& $nssm install $serviceName $relay "--config" (Join-Path $DataDirectory "relay-config.json") | Out-Null
if ($LASTEXITCODE -ne 0) { throw "NSSM could not install the WarSOC Relay service." }
& $nssm set $serviceName ObjectName LocalSystem | Out-Null
& $nssm set $serviceName Start SERVICE_AUTO_START | Out-Null
& $nssm set $serviceName AppExit Default Restart | Out-Null
& $nssm set $serviceName AppThrottle 10000 | Out-Null
& $nssm set $serviceName AppRestartDelay 10000 | Out-Null
& $nssm set $serviceName AppStdout (Join-Path $DataDirectory "service-output.log") | Out-Null
& $nssm set $serviceName AppStderr (Join-Path $DataDirectory "service-error.log") | Out-Null
& $nssm set $serviceName AppRotateFiles 1 | Out-Null
& $nssm set $serviceName AppRotateOnline 1 | Out-Null
& $nssm set $serviceName AppRotateBytes 10485760 | Out-Null
& sc.exe failure $serviceName reset= 86400 actions= restart/10000/restart/30000/restart/60000 | Out-Null

Set-RelayDirectorySecurity -Path $DataDirectory
Start-Service -Name $serviceName
Start-Sleep -Seconds 8
$service = Get-Service -Name $serviceName
if ($service.Status -ne "Running") {
    throw "WarSOC Relay did not remain running. Review the protected service-error.log as SYSTEM."
}
Write-Host "WarSOC Relay installed and running." -ForegroundColor Green
$installedVersion = $config.relay_version
Write-Host "Installed relay version: $installedVersion" -ForegroundColor Cyan
try {
    $contract = Invoke-RestMethod -Uri "$($config.backend_url)/api/v1/network-relay/contract" -Method Get -TimeoutSec 10
    Write-Host "Backend minimum relay version: $($contract.minimum_version)" -ForegroundColor Cyan
    try {
        if ([version]$installedVersion -lt [version]$contract.minimum_version) {
            Write-Host "WARNING: installed relay $installedVersion is BELOW the backend minimum $($contract.minimum_version). Evidence ingest will be rejected with 403 until the relay is upgraded." -ForegroundColor Red
        } else {
            Write-Host "Relay version satisfies the backend contract." -ForegroundColor Green
        }
    } catch {
        Write-Host "Compare the installed version against the backend minimum above before leaving site." -ForegroundColor Yellow
    }
} catch {
    Write-Host "Backend minimum relay version: unavailable (backend unreachable). Confirm it in the WarSOC dashboard relay status." -ForegroundColor Yellow
}
Write-Host "If the relay version is below the backend minimum, evidence ingest is rejected" -ForegroundColor Yellow
Write-Host "with a 403 status; health and control records remain accepted so the relay stays visible." -ForegroundColor Yellow
