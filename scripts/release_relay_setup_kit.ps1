[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[A-Fa-f0-9]{40}$')]
    [string]$CertificateThumbprint,

    [Parameter(Mandatory = $true)]
    [uri]$ArtifactUploadSasUrl,

    [Parameter(Mandatory = $true)]
    [switch]$AcknowledgeThirdPartySigning,

    [string]$RelayVersion = "1.0.0",
    [string]$TimestampServer = "http://timestamp.digicert.com",
    [string]$RelayExecutable = "relay\dist\warsoc_relay.exe",
    [string]$RelayBuildManifest = "relay\dist\build-manifest.json",
    [string]$NssmExecutable = "tools\nssm\nssm-2.24\win64\nssm.exe",
    [string]$OutputDirectory = "Output"
)

$ErrorActionPreference = "Stop"
$Root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path

function Resolve-RepositoryPath([string]$Path) {
    if ([IO.Path]::IsPathRooted($Path)) {
        return (Resolve-Path -LiteralPath $Path).Path
    }
    return (Resolve-Path -LiteralPath (Join-Path $Root $Path)).Path
}

function Find-CodeSigningCertificate([string]$Thumbprint) {
    $normalized = $Thumbprint.Replace(" ", "").ToUpperInvariant()
    foreach ($store in @("Cert:\CurrentUser\My", "Cert:\LocalMachine\My")) {
        $certificate = Get-ChildItem -LiteralPath $store -ErrorAction SilentlyContinue |
            Where-Object Thumbprint -eq $normalized |
            Select-Object -First 1
        if ($certificate) {
            return $certificate
        }
    }
    throw "The requested code-signing certificate is not installed in CurrentUser/My or LocalMachine/My."
}

if (-not $AcknowledgeThirdPartySigning) {
    throw "AcknowledgeThirdPartySigning is required because the WarSOC release signs the bundled NSSM copy."
}
if ($ArtifactUploadSasUrl.Scheme -ne "https") {
    throw "ArtifactUploadSasUrl must use HTTPS."
}
if ([string]::IsNullOrWhiteSpace($ArtifactUploadSasUrl.Query)) {
    throw "ArtifactUploadSasUrl must be an exact, write-capable blob SAS URL."
}

$expectedFileName = "warsoc_relay_setup-$RelayVersion.zip"
if ([IO.Path]::GetFileName($ArtifactUploadSasUrl.AbsolutePath) -cne $expectedFileName) {
    throw "ArtifactUploadSasUrl must target the versioned blob $expectedFileName."
}

$certificate = Find-CodeSigningCertificate $CertificateThumbprint
if (-not $certificate.HasPrivateKey) {
    throw "The code-signing certificate does not expose its private key to this user."
}
$now = Get-Date
if ($certificate.NotBefore -gt $now -or $certificate.NotAfter -le $now) {
    throw "The code-signing certificate is not currently valid."
}
if (-not ($certificate.EnhancedKeyUsageList.ObjectId.Value -contains "1.3.6.1.5.5.7.3.3")) {
    throw "The selected certificate is not valid for code signing."
}

$relay = Resolve-RepositoryPath $RelayExecutable
$manifestPath = Resolve-RepositoryPath $RelayBuildManifest
$nssm = Resolve-RepositoryPath $NssmExecutable
$builder = Resolve-RepositoryPath "scripts\build_relay_setup_kit.ps1"
$stage = Join-Path ([IO.Path]::GetTempPath()) ("warsoc-relay-release-" + [guid]::NewGuid().ToString("N"))
$verificationDownload = Join-Path $stage $expectedFileName

try {
    New-Item -ItemType Directory -Force -Path $stage | Out-Null
    $signedRelay = Join-Path $stage "warsoc_relay.exe"
    $signedNssm = Join-Path $stage "nssm.exe"
    $signedManifest = Join-Path $stage "build-manifest.json"
    Copy-Item -LiteralPath $relay -Destination $signedRelay
    Copy-Item -LiteralPath $nssm -Destination $signedNssm
    Copy-Item -LiteralPath $manifestPath -Destination $signedManifest

    foreach ($file in @($signedRelay, $signedNssm)) {
        $signature = Set-AuthenticodeSignature `
            -LiteralPath $file `
            -Certificate $certificate `
            -HashAlgorithm SHA256 `
            -TimestampServer $TimestampServer
        if ($signature.Status -ne "Valid") {
            throw "Authenticode signing did not produce a valid signature for $([IO.Path]::GetFileName($file))."
        }
    }

    # Authenticode changes the PE hash. Pin the exact signed copy without changing
    # the source-build toolchain evidence in the original manifest.
    $manifest = Get-Content -LiteralPath $signedManifest -Raw | ConvertFrom-Json
    $manifest.sha256 = (Get-FileHash -LiteralPath $signedRelay -Algorithm SHA256).Hash.ToLowerInvariant()
    $manifest.size_bytes = (Get-Item -LiteralPath $signedRelay).Length
    $manifest | Add-Member -NotePropertyName signed_at_utc -NotePropertyValue ([DateTime]::UtcNow.ToString("o")) -Force
    $manifest | Add-Member -NotePropertyName signing_certificate_thumbprint -NotePropertyValue $certificate.Thumbprint -Force
    $manifestJson = ($manifest | ConvertTo-Json -Depth 8) + "`n"
    [IO.File]::WriteAllText($signedManifest, $manifestJson, [Text.UTF8Encoding]::new($false))

    $buildJson = & $builder `
        -RelayVersion $RelayVersion `
        -RelayExecutable $signedRelay `
        -RelayBuildManifest $signedManifest `
        -NssmExecutable $signedNssm `
        -OutputDirectory $OutputDirectory
    $build = $buildJson | ConvertFrom-Json
    if ($build.relay_signature -ne "Valid" -or $build.nssm_signature -ne "Valid") {
        throw "The package builder did not preserve both valid Authenticode signatures."
    }

    $zipPath = (Resolve-Path -LiteralPath $build.path).Path
    $zipHash = (Get-FileHash -LiteralPath $zipPath -Algorithm SHA256).Hash.ToLowerInvariant()
    try {
        $upload = Invoke-WebRequest `
            -Uri $ArtifactUploadSasUrl `
            -Method Put `
            -InFile $zipPath `
            -UseBasicParsing `
            -Headers @{
                "x-ms-blob-type" = "BlockBlob"
                "x-ms-version" = "2023-11-03"
                "Content-Type" = "application/zip"
                "If-None-Match" = "*"
            }
        if ($upload.StatusCode -notin @(200, 201)) {
            throw "Unexpected Azure status."
        }
    }
    catch {
        throw "Azure artifact upload failed. Confirm the exact blob does not exist and the SAS grants create/write permission."
    }

    $publicBuilder = [UriBuilder]::new($ArtifactUploadSasUrl)
    $publicBuilder.Query = ""
    $publicBuilder.Fragment = ""
    $publicUrl = $publicBuilder.Uri.AbsoluteUri
    try {
        Invoke-WebRequest -Uri $publicUrl -OutFile $verificationDownload -UseBasicParsing | Out-Null
    }
    catch {
        throw "The uploaded artifact is not publicly downloadable from its query-free versioned URL."
    }
    $remoteHash = (Get-FileHash -LiteralPath $verificationDownload -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($remoteHash -ne $zipHash) {
        throw "The downloaded Azure artifact hash does not match the signed release package."
    }

    [ordered]@{
        relay_version = $RelayVersion
        installer_url = $publicUrl
        size_bytes = (Get-Item -LiteralPath $zipPath).Length
        sha256 = $zipHash
        relay_signature = "Valid"
        nssm_signature = "Valid"
        lab_override_used = $false
        oci_environment = "NETWORK_RELAY_INSTALLER_URL=$publicUrl"
    } | ConvertTo-Json -Depth 4
}
finally {
    if (Test-Path -LiteralPath $stage) {
        Remove-Item -LiteralPath $stage -Recurse -Force
    }
}
