[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [uri]$ArtifactUploadSasUrl,

    [string]$RelayVersion = "1.0.0",
    [string]$PackagePath = "Output\warsoc_relay_setup-1.0.0.zip"
)

$ErrorActionPreference = "Stop"
$Root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$expectedFileName = "warsoc_relay_setup-$RelayVersion.zip"

if ($ArtifactUploadSasUrl.Scheme -ne "https") {
    throw "ArtifactUploadSasUrl must use HTTPS."
}
if ([string]::IsNullOrWhiteSpace($ArtifactUploadSasUrl.Query)) {
    throw "ArtifactUploadSasUrl must be an exact, write-capable blob SAS URL."
}
if ([IO.Path]::GetFileName($ArtifactUploadSasUrl.AbsolutePath) -cne $expectedFileName) {
    throw "ArtifactUploadSasUrl must target the versioned blob $expectedFileName."
}

$zipPath = if ([IO.Path]::IsPathRooted($PackagePath)) {
    (Resolve-Path -LiteralPath $PackagePath).Path
} else {
    (Resolve-Path -LiteralPath (Join-Path $Root $PackagePath)).Path
}
if ([IO.Path]::GetFileName($zipPath) -cne $expectedFileName) {
    throw "PackagePath must identify $expectedFileName."
}

Add-Type -AssemblyName System.IO.Compression.FileSystem
$archive = [IO.Compression.ZipFile]::OpenRead($zipPath)
try {
    $names = @($archive.Entries | ForEach-Object FullName)
    if ($names -contains "relay-config.json" -or $names -match "activation") {
        throw "The pilot kit must not contain customer configuration or activation material."
    }
    $manifestEntry = $archive.GetEntry("relay-kit-manifest.json")
    if (-not $manifestEntry) {
        throw "The pilot kit does not contain relay-kit-manifest.json."
    }
    $reader = [IO.StreamReader]::new($manifestEntry.Open())
    try {
        $manifest = $reader.ReadToEnd() | ConvertFrom-Json
    }
    finally {
        $reader.Dispose()
    }
    if ($manifest.relay_version -ne $RelayVersion) {
        throw "The pilot manifest version does not match RelayVersion."
    }
    if ($manifest.contains_activation_secret -ne $false -or
        $manifest.contains_customer_configuration -ne $false) {
        throw "The pilot manifest does not declare a secret-free generic package."
    }
    if ($manifest.signing.lab_override_used -ne $true) {
        throw "The package is not an explicitly marked unsigned lab/pilot build."
    }
}
finally {
    $archive.Dispose()
}

$zipHash = (Get-FileHash -LiteralPath $zipPath -Algorithm SHA256).Hash.ToLowerInvariant()
$verificationDownload = Join-Path ([IO.Path]::GetTempPath()) (
    "warsoc-relay-pilot-verify-" + [guid]::NewGuid().ToString("N") + ".zip"
)
try {
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
        throw "Azure artifact upload failed. Confirm the blob does not exist and the SAS grants create/write permission."
    }

    $publicBuilder = [UriBuilder]::new($ArtifactUploadSasUrl)
    $publicBuilder.Query = ""
    $publicBuilder.Fragment = ""
    $publicUrl = $publicBuilder.Uri.AbsoluteUri
    try {
        Invoke-WebRequest -Uri $publicUrl -OutFile $verificationDownload -UseBasicParsing | Out-Null
    }
    catch {
        throw "The uploaded pilot package is not publicly downloadable from its query-free URL."
    }
    $remoteHash = (Get-FileHash -LiteralPath $verificationDownload -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($remoteHash -ne $zipHash) {
        throw "The downloaded Azure pilot artifact hash does not match the local package."
    }

    [ordered]@{
        relay_version = $RelayVersion
        installer_url = $publicUrl
        size_bytes = (Get-Item -LiteralPath $zipPath).Length
        sha256 = $zipHash
        publisher_trust = "hash_allowlisted_pilot"
        windows_warning_expected = $true
        oci_environment = @(
            "NETWORK_RELAY_INSTALLER_URL=$publicUrl"
            "NETWORK_RELAY_INSTALLER_SHA256=$zipHash"
        )
    } | ConvertTo-Json -Depth 4
}
finally {
    Remove-Item -LiteralPath $verificationDownload -Force -ErrorAction SilentlyContinue
}
