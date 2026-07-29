[CmdletBinding()]
param(
    [ValidatePattern('^\d+\.\d+\.\d+$')]
    [string]$Version = "4.2.7",
    [string]$AgentPath = "",
    [string]$InstallerPath = "",
    [string]$NssmPath = "",
    [string]$TelemetryScriptPath = "",
    [string]$TenantPolicyPath = "",
    [string]$OutputPath = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$repositoryRoot = Split-Path $PSScriptRoot -Parent
if (-not $AgentPath) {
    $AgentPath = Join-Path $repositoryRoot "agent\dist\warsoc_agent.exe"
}
if (-not $InstallerPath) {
    $InstallerPath = Join-Path $repositoryRoot "Output\warsoc_installer-$Version.exe"
}
if (-not $NssmPath) {
    $NssmPath = Join-Path $repositoryRoot "tools\nssm\nssm.exe"
}
if (-not $TelemetryScriptPath) {
    $TelemetryScriptPath = Join-Path $repositoryRoot "agent\deploy_warsoc_telemetry.ps1"
}
if (-not $TenantPolicyPath) {
    $TenantPolicyPath = Join-Path $repositoryRoot "agent\tenant_policy.json"
}
if (-not $OutputPath) {
    $OutputPath = Join-Path $repositoryRoot "Output\pilot_hash_manifest-$Version.json"
}

$resolvedAgent = (Resolve-Path -LiteralPath $AgentPath).Path
$resolvedInstaller = (Resolve-Path -LiteralPath $InstallerPath).Path
$resolvedNssm = (Resolve-Path -LiteralPath $NssmPath).Path
$resolvedTelemetryScript = (Resolve-Path -LiteralPath $TelemetryScriptPath).Path
$resolvedTenantPolicy = (Resolve-Path -LiteralPath $TenantPolicyPath).Path
$outputDirectory = Split-Path $OutputPath -Parent
if ($outputDirectory) {
    New-Item -ItemType Directory -Path $outputDirectory -Force | Out-Null
}

function Get-ArtifactRecord {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Role
    )

    $item = Get-Item -LiteralPath $Path
    $hash = Get-FileHash -LiteralPath $Path -Algorithm SHA256
    $signature = Get-AuthenticodeSignature -LiteralPath $Path
    return [ordered]@{
        role = $Role
        file_name = $item.Name
        size_bytes = $item.Length
        sha256 = $hash.Hash
        authenticode_status = [string]$signature.Status
        file_version = [string]$item.VersionInfo.FileVersion
        product_version = [string]$item.VersionInfo.ProductVersion
    }
}

$manifest = [ordered]@{
    generated_at = [DateTimeOffset]::UtcNow.ToString("o")
    hash_algorithm = "SHA-256"
    release_policy = "pilot-managed-allowlisting"
    warning = "Rebuilds change file hashes. Generate and approve a new policy for every release."
    artifacts = @(
        (Get-ArtifactRecord -Path $resolvedInstaller -Role "windows-installer"),
        (Get-ArtifactRecord -Path $resolvedAgent -Role "windows-agent"),
        (Get-ArtifactRecord -Path $resolvedNssm -Role "windows-service-manager"),
        (Get-ArtifactRecord -Path $resolvedTelemetryScript -Role "native-telemetry-configuration"),
        (Get-ArtifactRecord -Path $resolvedTenantPolicy -Role "tenant-monitoring-policy")
    )
}

$json = $manifest | ConvertTo-Json -Depth 5
[IO.File]::WriteAllText(
    $OutputPath,
    $json + [Environment]::NewLine,
    [Text.UTF8Encoding]::new($false)
)

Write-Host "Pilot hash manifest written to $OutputPath"
foreach ($artifact in $manifest.artifacts) {
    Write-Host "$($artifact.file_name): $($artifact.sha256) [$($artifact.authenticode_status)]"
}
