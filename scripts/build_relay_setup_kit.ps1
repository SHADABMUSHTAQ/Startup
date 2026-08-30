[CmdletBinding()]
param(
    [string]$RelayVersion = "1.0.0",
    [string]$RelayExecutable = "relay\dist\warsoc_relay.exe",
    [string]$RelayBuildManifest = "relay\dist\build-manifest.json",
    [string]$NssmExecutable = "tools\nssm\nssm-2.24\win64\nssm.exe",
    [string]$OutputDirectory = "Output",
    [switch]$AllowUnsigned
)

$ErrorActionPreference = "Stop"
$Root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path

function Resolve-RepositoryPath([string]$Path) {
    if ([IO.Path]::IsPathRooted($Path)) {
        return (Resolve-Path -LiteralPath $Path).Path
    }
    return (Resolve-Path -LiteralPath (Join-Path $Root $Path)).Path
}

if ($RelayVersion -notmatch '^\d+\.\d+\.\d+([.-][A-Za-z0-9.-]+)?$') {
    throw "RelayVersion must be a versioned release identifier such as 1.0.0."
}

$RelayExecutable = Resolve-RepositoryPath $RelayExecutable
$RelayBuildManifest = Resolve-RepositoryPath $RelayBuildManifest
$NssmExecutable = Resolve-RepositoryPath $NssmExecutable
$InstallerScript = Resolve-RepositoryPath "scripts\install_warsoc_relay.ps1"
$UninstallerScript = Resolve-RepositoryPath "scripts\uninstall_warsoc_relay.ps1"
$Readme = Resolve-RepositoryPath "deploy\relay\README.txt"
$ThirdPartyNotices = Resolve-RepositoryPath "deploy\relay\THIRD_PARTY_NOTICES.txt"

$Build = Get-Content -LiteralPath $RelayBuildManifest -Raw | ConvertFrom-Json
$RelayHash = (Get-FileHash -LiteralPath $RelayExecutable -Algorithm SHA256).Hash.ToLowerInvariant()
if ($RelayHash -ne [string]$Build.sha256) {
    throw "Relay executable does not match relay/dist/build-manifest.json. Rebuild and approve the artifact first."
}

$RelaySignature = Get-AuthenticodeSignature -LiteralPath $RelayExecutable
$NssmSignature = Get-AuthenticodeSignature -LiteralPath $NssmExecutable
if (-not $AllowUnsigned -and ($RelaySignature.Status -ne "Valid" -or $NssmSignature.Status -ne "Valid")) {
    throw "The relay kit contains an unsigned or invalid executable. Sign both executables or use -AllowUnsigned only for an approved lab build."
}

$OutputPath = if ([IO.Path]::IsPathRooted($OutputDirectory)) {
    $OutputDirectory
} else {
    Join-Path $Root $OutputDirectory
}
New-Item -ItemType Directory -Force -Path $OutputPath | Out-Null

$Stage = Join-Path ([IO.Path]::GetTempPath()) ("warsoc-relay-kit-" + [guid]::NewGuid().ToString("N"))
$ZipPath = Join-Path $OutputPath "warsoc_relay_setup-$RelayVersion.zip"

try {
    New-Item -ItemType Directory -Force -Path $Stage | Out-Null
    Copy-Item -LiteralPath $RelayExecutable -Destination (Join-Path $Stage "warsoc_relay.exe")
    Copy-Item -LiteralPath $NssmExecutable -Destination (Join-Path $Stage "nssm.exe")
    Copy-Item -LiteralPath $InstallerScript -Destination (Join-Path $Stage "install_warsoc_relay.ps1")
    Copy-Item -LiteralPath $UninstallerScript -Destination (Join-Path $Stage "uninstall_warsoc_relay.ps1")
    Copy-Item -LiteralPath $Readme -Destination (Join-Path $Stage "README.txt")
    Copy-Item -LiteralPath $ThirdPartyNotices -Destination (Join-Path $Stage "THIRD_PARTY_NOTICES.txt")

    $Files = Get-ChildItem -LiteralPath $Stage -File | Sort-Object Name | ForEach-Object {
        [ordered]@{
            name = $_.Name
            size_bytes = $_.Length
            sha256 = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        }
    }
    $Manifest = [ordered]@{
        schema_version = "warsoc-relay-kit-v1"
        relay_version = $RelayVersion
        created_at_utc = [DateTime]::UtcNow.ToString("o")
        relay_build_sha256 = $RelayHash
        signing = [ordered]@{
            relay = [string]$RelaySignature.Status
            nssm = [string]$NssmSignature.Status
            lab_override_used = [bool]$AllowUnsigned
        }
        contains_activation_secret = $false
        contains_customer_configuration = $false
        files = @($Files)
    }
    $ManifestJson = ($Manifest | ConvertTo-Json -Depth 8) + "`n"
    $Utf8NoBom = [Text.UTF8Encoding]::new($false)
    [IO.File]::WriteAllText(
        (Join-Path $Stage "relay-kit-manifest.json"),
        $ManifestJson,
        $Utf8NoBom
    )

    Remove-Item -LiteralPath $ZipPath -Force -ErrorAction SilentlyContinue
    Compress-Archive -Path (Join-Path $Stage "*") -DestinationPath $ZipPath -CompressionLevel Optimal

    $Zip = Get-Item -LiteralPath $ZipPath
    [ordered]@{
        path = $Zip.FullName
        size_bytes = $Zip.Length
        sha256 = (Get-FileHash -LiteralPath $Zip.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        relay_signature = [string]$RelaySignature.Status
        nssm_signature = [string]$NssmSignature.Status
    } | ConvertTo-Json -Depth 4
}
finally {
    if (Test-Path -LiteralPath $Stage) {
        Remove-Item -LiteralPath $Stage -Recurse -Force
    }
}
