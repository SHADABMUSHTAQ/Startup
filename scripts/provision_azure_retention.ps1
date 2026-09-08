[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory)]
    [ValidatePattern('^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')]
    [string]$SubscriptionId,

    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$ResourceGroup,

    [Parameter(Mandatory)]
    [ValidatePattern('^[a-z0-9]{3,24}$')]
    [string]$StorageAccount,

    [ValidateSet("Inspect", "Prepare", "Verify", "Lock")]
    [string]$Mode = "Inspect",

    [ValidateRange(1, 36500)]
    [int]$RetentionDays = 90,

    [switch]$AcknowledgeValidationBlobRetention,

    [string]$LockConfirmation,

    [string]$OutputDirectory = "tmp/azure-retention"
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$approvedRetentionDays = @(90, 180, 270, 365)
$approvedContainers = @(
    "warsoc-siem-$RetentionDays",
    "warsoc-general-$RetentionDays"
)
$legacyContainer = "warsoc-cold-storage"
$requiredLockConfirmation = "LOCK-WARSOC-$RetentionDays-DAY-RETENTION"
$runId = (Get-Date).ToUniversalTime().ToString("yyyyMMddTHHmmssZ") + "-" +
    ([guid]::NewGuid().ToString("N").Substring(0, 8))
$script:AzureCliPath = $null

if ($RetentionDays -notin $approvedRetentionDays) {
    throw "RetentionDays must be one of: $($approvedRetentionDays -join ', '). Refusing RetentionDays=$RetentionDays."
}
if ($approvedContainers -contains $legacyContainer) {
    throw "Safety invariant failed: the legacy container is in the mutation allowlist."
}
if ($Mode -eq "Prepare" -and -not $AcknowledgeValidationBlobRetention) {
    throw "Prepare creates harmless validation blobs retained for $RetentionDays days. Re-run with -AcknowledgeValidationBlobRetention."
}
if ($Mode -eq "Lock" -and $LockConfirmation -cne $requiredLockConfirmation) {
    throw "Lock requires -LockConfirmation '$requiredLockConfirmation'."
}

function Invoke-AzRaw {
    param(
        [Parameter(Mandatory)][string[]]$Arguments,
        [switch]$AllowNotFound
    )

    $commandArguments = @($Arguments) + @(
        "--subscription", $SubscriptionId,
        "--only-show-errors",
        "--output", "json"
    )
    $previousErrorActionPreference = $ErrorActionPreference
    $nativePreference = Get-Variable -Name PSNativeCommandUseErrorActionPreference `
        -ErrorAction SilentlyContinue
    $previousNativePreference = $(if ($nativePreference) { $nativePreference.Value } else { $null })
    try {
        # Windows PowerShell surfaces native stderr as ErrorRecord objects. Keep
        # those records in the captured output so expected 404s can be classified.
        $ErrorActionPreference = "Continue"
        if ($nativePreference) {
            Set-Variable -Name PSNativeCommandUseErrorActionPreference -Value $false
        }
        $output = @(& $script:AzureCliPath @commandArguments 2>&1)
        $exitCode = $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $previousErrorActionPreference
        if ($nativePreference) {
            Set-Variable -Name PSNativeCommandUseErrorActionPreference `
                -Value $previousNativePreference
        }
    }
    $text = ($output | ForEach-Object { "$_" }) -join "`n"

    if ($exitCode -ne 0) {
        if ($AllowNotFound -and $text -match '(?i)(notfound|not found|does not exist|resource.*not.*found|immutability.*missing)') {
            return [pscustomobject]@{ Found = $false; Text = $text }
        }
        throw "Azure CLI failed (exit $exitCode): az $($Arguments -join ' ')`n$text"
    }

    return [pscustomobject]@{ Found = $true; Text = $text }
}

function Invoke-AzJson {
    param(
        [Parameter(Mandatory)][string[]]$Arguments,
        [switch]$AllowNotFound
    )

    $raw = Invoke-AzRaw -Arguments $Arguments -AllowNotFound:$AllowNotFound
    if (-not $raw.Found) { return $null }
    if ([string]::IsNullOrWhiteSpace($raw.Text)) { return $null }

    try {
        $convertFromJson = Get-Command ConvertFrom-Json
        if ($convertFromJson.Parameters.ContainsKey("DateKind")) {
            # Azure blob version IDs are ISO timestamps but must remain opaque
            # strings. PowerShell 7.5 otherwise converts them to DateTime.
            return $raw.Text | ConvertFrom-Json -DateKind String
        }
        return $raw.Text | ConvertFrom-Json
    }
    catch {
        throw "Azure CLI returned invalid JSON for 'az $($Arguments -join ' ')': $($raw.Text)"
    }
}

function Invoke-AzMutation {
    param([Parameter(Mandatory)][string[]]$Arguments)
    [void](Invoke-AzRaw -Arguments $Arguments)
}

function Get-OptionalProperty {
    param(
        $Object,
        [Parameter(Mandatory)][string]$Name
    )
    if ($null -eq $Object) { return $null }
    $property = $Object.PSObject.Properties[$Name]
    if ($null -eq $property) { return $null }
    return $property.Value
}

function Get-ContainerResource {
    param([Parameter(Mandatory)][string]$ContainerName)
    return Invoke-AzJson -Arguments @(
        "storage", "container-rm", "show",
        "--resource-group", $ResourceGroup,
        "--storage-account", $StorageAccount,
        "--name", $ContainerName
    ) -AllowNotFound
}

function Get-ImmutabilityPolicy {
    param([Parameter(Mandatory)][string]$ContainerName)
    return Invoke-AzJson -Arguments @(
        "storage", "container", "immutability-policy", "show",
        "--resource-group", $ResourceGroup,
        "--account-name", $StorageAccount,
        "--container-name", $ContainerName
    ) -AllowNotFound
}

function Wait-ForContainerResource {
    param([Parameter(Mandatory)][string]$ContainerName)
    for ($attempt = 0; $attempt -lt 12; $attempt++) {
        $container = Get-ContainerResource -ContainerName $ContainerName
        if ($null -ne $container -and (Test-VersionWormEnabled -Container $container)) {
            return $container
        }
        Start-Sleep -Seconds 5
    }
    throw "Container '$ContainerName' did not expose version-level WORM within 60 seconds."
}

function Wait-ForImmutabilityPolicy {
    param([Parameter(Mandatory)][string]$ContainerName)
    for ($attempt = 0; $attempt -lt 12; $attempt++) {
        $policy = Get-ImmutabilityPolicy -ContainerName $ContainerName
        if ($null -ne $policy) { return $policy }
        Start-Sleep -Seconds 5
    }
    throw "Container '$ContainerName' did not expose its immutability policy within 60 seconds."
}

function Wait-ForBlobResource {
    param(
        [Parameter(Mandatory)][string]$ContainerName,
        [Parameter(Mandatory)][string]$BlobName
    )
    for ($attempt = 0; $attempt -lt 12; $attempt++) {
        $blob = Invoke-AzJson -Arguments @(
            "storage", "blob", "show",
            "--account-name", $StorageAccount,
            "--container-name", $ContainerName,
            "--name", $BlobName,
            "--auth-mode", "login"
        ) -AllowNotFound
        if ($null -ne $blob) { return $blob }
        Start-Sleep -Seconds 5
    }
    throw "Validation blob '$ContainerName/$BlobName' was not readable within 60 seconds."
}

function Test-ContainerIsPrivate {
    param([Parameter(Mandatory)]$Container)
    $publicAccess = [string](Get-OptionalProperty -Object $Container -Name "publicAccess")
    return [string]::IsNullOrWhiteSpace($publicAccess) -or
        $publicAccess -in @("None", "Off")
}

function Test-VersionWormEnabled {
    param([Parameter(Mandatory)]$Container)
    $worm = Get-OptionalProperty -Object $Container -Name "immutableStorageWithVersioning"
    return [bool](Get-OptionalProperty -Object $worm -Name "enabled")
}

function Get-LatestValidationBlob {
    param([Parameter(Mandatory)][string]$ContainerName)

    $items = @(Invoke-AzJson -Arguments @(
        "storage", "blob", "list",
        "--account-name", $StorageAccount,
        "--container-name", $ContainerName,
        "--prefix", "policy-validation/",
        "--include", "v",
        "--auth-mode", "login"
    ))
    $versioned = @($items | Where-Object {
        -not [string]::IsNullOrWhiteSpace([string]$_.name) -and
        -not [string]::IsNullOrWhiteSpace([string]$_.versionId)
    })
    if ($versioned.Count -eq 0) { return $null }

    return $versioned | Sort-Object {
        $properties = Get-OptionalProperty -Object $_ -Name "properties"
        $lastModified = Get-OptionalProperty -Object $properties -Name "lastModified"
        if ($lastModified) { [datetime]$lastModified } else { [datetime]::MinValue }
    } -Descending | Select-Object -First 1
}

function Get-RetentionSnapshot {
    param([switch]$IncludeValidationBlobs)

    $blobService = Invoke-AzJson -Arguments @(
        "storage", "account", "blob-service-properties", "show",
        "--resource-group", $ResourceGroup,
        "--account-name", $StorageAccount
    )
    $containerRows = @()

    foreach ($containerName in $approvedContainers) {
        $container = Get-ContainerResource -ContainerName $containerName
        $policy = $null
        $validationBlob = $null
        if ($null -ne $container) {
            $policy = Get-ImmutabilityPolicy -ContainerName $containerName
            if ($IncludeValidationBlobs) {
                $validationBlob = Get-LatestValidationBlob -ContainerName $containerName
            }
        }

        $worm = Get-OptionalProperty -Object $container -Name "immutableStorageWithVersioning"
        $validationProperties = Get-OptionalProperty -Object $validationBlob -Name "properties"
        $containerRows += [ordered]@{
            name = $containerName
            exists = ($null -ne $container)
            private = $(if ($null -ne $container) { Test-ContainerIsPrivate -Container $container } else { $null })
            version_level_worm = $(if ($null -ne $container) { Test-VersionWormEnabled -Container $container } else { $null })
            migration_state = $(if ($null -ne $worm) { Get-OptionalProperty -Object $worm -Name "migrationState" } else { $null })
            policy_state = $(if ($null -ne $policy) { [string]$policy.state } else { $null })
            policy_days = $(if ($null -ne $policy) { [int]$policy.immutabilityPeriodSinceCreationInDays } else { $null })
            policy_etag = $(if ($null -ne $policy) { [string]$policy.etag } else { $null })
            validation_blob = $(if ($null -ne $validationBlob) { [string]$validationBlob.name } else { $null })
            validation_version_id = $(if ($null -ne $validationBlob) { [string]$validationBlob.versionId } else { $null })
            validation_tier = $(if ($null -ne $validationProperties) { [string](Get-OptionalProperty -Object $validationProperties -Name "blobTier") } else { $null })
        }
    }

    return [ordered]@{
        blob_versioning = [bool]$blobService.isVersioningEnabled
        containers = $containerRows
    }
}

function Assert-AccountBoundary {
    param([Parameter(Mandatory)]$Account)

    if ([string](Get-OptionalProperty -Object $Account -Name "name") -cne $StorageAccount) {
        throw "Storage account identity mismatch."
    }
    if ([string](Get-OptionalProperty -Object $Account -Name "resourceGroup") -ne $ResourceGroup) {
        throw "Storage account '$StorageAccount' is not in resource group '$ResourceGroup'."
    }
    $publicAccessAllowed = Get-OptionalProperty -Object $Account -Name "allowBlobPublicAccess"
    if ($null -eq $publicAccessAllowed) {
        throw "The evidence account public-access boundary could not be verified."
    }
    if ([bool]$publicAccessAllowed) {
        throw "The evidence account permits blob public access. Harden it and re-run; the script will not change account-wide policy."
    }
    if (-not [bool](Get-OptionalProperty -Object $Account -Name "enableHttpsTrafficOnly")) {
        throw "The evidence account does not require HTTPS. Harden it and re-run."
    }
    if ([string](Get-OptionalProperty -Object $Account -Name "minimumTlsVersion") -ne "TLS1_2") {
        throw "The evidence account minimum TLS version must be TLS1_2."
    }
    if ([string](Get-OptionalProperty -Object $Account -Name "kind") -ne "StorageV2") {
        throw "The evidence account must be StorageV2."
    }
}

function Assert-ExistingTargetIsSafe {
    param(
        [Parameter(Mandatory)][string]$ContainerName,
        [Parameter(Mandatory)]$Container,
        $Policy,
        [switch]$RejectLockedPolicy
    )

    if (-not (Test-ContainerIsPrivate -Container $Container)) {
        throw "Container '$ContainerName' is not private. No changes were made to it."
    }
    if (-not (Test-VersionWormEnabled -Container $Container)) {
        throw "Container '$ContainerName' was not created with version-level WORM. The script will not run preview migration on an existing container."
    }
    if ($null -ne $Policy) {
        $days = [int]$Policy.immutabilityPeriodSinceCreationInDays
        $state = [string]$Policy.state
        if ($days -ne $RetentionDays) {
            throw "Container '$ContainerName' has a $days-day policy, not $RetentionDays days."
        }
        if ($state -notin @("Unlocked", "Locked")) {
            throw "Container '$ContainerName' has unsupported policy state '$state'."
        }
        if ($RejectLockedPolicy -and $state -eq "Locked") {
            throw "Container '$ContainerName' is already locked. Use -Mode Verify; Prepare will not add another canary."
        }
    }
}

function Assert-SnapshotReady {
    param(
        [Parameter(Mandatory)]$Snapshot,
        [ValidateSet("Either", "Unlocked", "Locked")]
        [string]$RequiredPolicyState = "Either",
        [switch]$RequireValidationBlob
    )

    if (-not [bool]$Snapshot.blob_versioning) {
        throw "Blob versioning is not enabled on '$StorageAccount'."
    }
    foreach ($row in $Snapshot.containers) {
        if (-not $row.exists) { throw "Required container '$($row.name)' does not exist." }
        if (-not $row.private) { throw "Required container '$($row.name)' is not private." }
        if (-not $row.version_level_worm) { throw "Required container '$($row.name)' lacks version-level WORM." }
        if ([int]$row.policy_days -ne $RetentionDays) {
            throw "Container '$($row.name)' does not have the exact $RetentionDays-day policy."
        }
        if ($RequiredPolicyState -eq "Either" -and $row.policy_state -notin @("Unlocked", "Locked")) {
            throw "Container '$($row.name)' policy is neither Unlocked nor Locked."
        }
        if ($RequiredPolicyState -ne "Either" -and $row.policy_state -ne $RequiredPolicyState) {
            throw "Container '$($row.name)' policy must be $RequiredPolicyState, found '$($row.policy_state)'."
        }
        if ($RequireValidationBlob) {
            if ([string]::IsNullOrWhiteSpace([string]$row.validation_blob)) {
                throw "Container '$($row.name)' has no retained policy-validation blob."
            }
            if ([string]::IsNullOrWhiteSpace([string]$row.validation_version_id)) {
                throw "Container '$($row.name)' validation blob has no version ID."
            }
            if ([string]$row.validation_tier -ne "Cold") {
                throw "Container '$($row.name)' validation blob tier is '$($row.validation_tier)', not Cold."
            }
        }
    }
}

function Write-ResultReport {
    param(
        [Parameter(Mandatory)][string]$Status,
        [Parameter(Mandatory)]$Account,
        [Parameter(Mandatory)]$Snapshot,
        [array]$ValidationResults = @()
    )

    $projectRoot = Split-Path -Parent $PSScriptRoot
    $outputPath = [IO.Path]::GetFullPath((Join-Path $projectRoot $OutputDirectory))
    New-Item -ItemType Directory -Force -Path $outputPath | Out-Null
    $reportPath = Join-Path $outputPath "$runId-$($Mode.ToLowerInvariant()).json"
    $activationEnvironment = [ordered]@{}
    foreach ($retentionClass in @("SIEM", "GENERAL")) {
        $containerName = "warsoc-$($retentionClass.ToLowerInvariant())-$RetentionDays"
        $activationEnvironment["AZURE_STORAGE_CONTAINER_${retentionClass}_$RetentionDays"] = $containerName
        $activationEnvironment["AZURE_STORAGE_TIER_${retentionClass}_$RetentionDays"] = "Cold"
        $activationEnvironment["AZURE_IMMUTABILITY_SCOPE_${retentionClass}_$RetentionDays"] = "blob"
        $activationEnvironment["AZURE_CONTAINER_IMMUTABILITY_LOCKED_${retentionClass}_$RetentionDays"] = "true"
        $activationEnvironment["AZURE_CONTAINER_IMMUTABILITY_DAYS_${retentionClass}_$RetentionDays"] = "$RetentionDays"
    }

    $report = [ordered]@{
        status = $Status
        mode = $Mode
        run_id = $runId
        completed_at_utc = (Get-Date).ToUniversalTime().ToString("o")
        subscription_id = $SubscriptionId
        resource_group = $ResourceGroup
        storage_account = $StorageAccount
        account = [ordered]@{
            kind = [string](Get-OptionalProperty -Object $Account -Name "kind")
            https_only = [bool](Get-OptionalProperty -Object $Account -Name "enableHttpsTrafficOnly")
            minimum_tls = [string](Get-OptionalProperty -Object $Account -Name "minimumTlsVersion")
            public_blob_access_allowed = [bool](Get-OptionalProperty -Object $Account -Name "allowBlobPublicAccess")
        }
        target = [ordered]@{
            retention_days = $RetentionDays
            access_tier = "Cold"
            containers = $approvedContainers
            legacy_container_mutated = $false
        }
        snapshot = $Snapshot
        validation_results = $ValidationResults
        activation_environment = $activationEnvironment
    }
    $report | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $reportPath -Encoding UTF8
    Write-Host "Report: $reportPath" -ForegroundColor Cyan
    return $reportPath
}

$az = Get-Command az -ErrorAction SilentlyContinue
$azureCliFallback = "C:\Program Files\Microsoft SDKs\Azure\CLI2\wbin\az.cmd"
if ($az) {
    $script:AzureCliPath = $az.Source
}
elseif (Test-Path -LiteralPath $azureCliFallback) {
    $script:AzureCliPath = $azureCliFallback
}
else {
    throw "Azure CLI is not installed. Install it, run 'az login', and retry."
}

$versionOutput = @(& $script:AzureCliPath version --only-show-errors --output json 2>&1)
if ($LASTEXITCODE -ne 0) {
    throw "Unable to read the Azure CLI version: $($versionOutput -join "`n")"
}
$convertFromJson = Get-Command ConvertFrom-Json
$versionInfo = $(
    if ($convertFromJson.Parameters.ContainsKey("DateKind")) {
        ($versionOutput -join "`n") | ConvertFrom-Json -DateKind String
    }
    else {
        ($versionOutput -join "`n") | ConvertFrom-Json
    }
)
$azureCliVersionText = [string](Get-OptionalProperty -Object $versionInfo -Name "azure-cli")
$azureCliVersion = $null
if (-not [version]::TryParse($azureCliVersionText, [ref]$azureCliVersion) -or
    $azureCliVersion -lt [version]"2.27.0") {
    throw "Azure CLI 2.27.0 or later is required for version-level immutability. Found '$azureCliVersionText'."
}
Write-Host "Azure CLI version: $azureCliVersionText"

$activeAccount = Invoke-AzJson -Arguments @("account", "show")
if ([string]$activeAccount.state -ne "Enabled") {
    throw "Azure subscription '$SubscriptionId' is not enabled."
}
if ([string]$activeAccount.id -ne $SubscriptionId) {
    throw "Azure CLI could not select subscription '$SubscriptionId'."
}

$storageAccountResource = Invoke-AzJson -Arguments @(
    "storage", "account", "show",
    "--resource-group", $ResourceGroup,
    "--name", $StorageAccount
)
Assert-AccountBoundary -Account $storageAccountResource

$legacyResource = Get-ContainerResource -ContainerName $legacyContainer
$legacyExists = ($null -ne $legacyResource)
Write-Host "Legacy container '$legacyContainer' present: $legacyExists (read-only; never mutated)."

if ($Mode -eq "Inspect") {
    $snapshot = Get-RetentionSnapshot
    [void](Write-ResultReport -Status "INSPECTED" -Account $storageAccountResource -Snapshot $snapshot)
    $snapshot | ConvertTo-Json -Depth 10
    return
}

if ($Mode -eq "Prepare") {
    foreach ($containerName in $approvedContainers) {
        $existing = Get-ContainerResource -ContainerName $containerName
        if ($null -ne $existing) {
            $existingPolicy = Get-ImmutabilityPolicy -ContainerName $containerName
            Assert-ExistingTargetIsSafe -ContainerName $containerName -Container $existing `
                -Policy $existingPolicy -RejectLockedPolicy
        }
    }

    if ($WhatIfPreference) {
        foreach ($operation in @(
            "Enable account blob versioning if disabled",
            "Create private version-WORM container warsoc-siem-$RetentionDays if absent",
            "Create private version-WORM container warsoc-general-$RetentionDays if absent",
            "Create unlocked $RetentionDays-day policies if absent",
            "Upload and hash-readback one retained Cold canary per container"
        )) {
            [void]$PSCmdlet.ShouldProcess($StorageAccount, $operation)
        }
        $snapshot = Get-RetentionSnapshot
        [void](Write-ResultReport -Status "WHATIF" -Account $storageAccountResource -Snapshot $snapshot)
        return
    }

    $blobService = Invoke-AzJson -Arguments @(
        "storage", "account", "blob-service-properties", "show",
        "--resource-group", $ResourceGroup,
        "--account-name", $StorageAccount
    )
    if (-not [bool]$blobService.isVersioningEnabled) {
        if ($PSCmdlet.ShouldProcess($StorageAccount, "Enable blob versioning")) {
            Invoke-AzMutation -Arguments @(
                "storage", "account", "blob-service-properties", "update",
                "--resource-group", $ResourceGroup,
                "--account-name", $StorageAccount,
                "--enable-versioning", "true"
            )
        }
    }

    foreach ($containerName in $approvedContainers) {
        $container = Get-ContainerResource -ContainerName $containerName
        if ($null -eq $container) {
            if ($PSCmdlet.ShouldProcess($containerName, "Create private version-level WORM container")) {
                Invoke-AzMutation -Arguments @(
                    "storage", "container-rm", "create",
                    "--resource-group", $ResourceGroup,
                    "--storage-account", $StorageAccount,
                    "--name", $containerName,
                    "--enable-vlw", "true",
                    "--public-access", "off",
                    "--fail-on-exist"
                )
            }
            $container = Wait-ForContainerResource -ContainerName $containerName
        }
        Assert-ExistingTargetIsSafe -ContainerName $containerName -Container $container `
            -Policy (Get-ImmutabilityPolicy -ContainerName $containerName) -RejectLockedPolicy

        $policy = Get-ImmutabilityPolicy -ContainerName $containerName
        if ($null -eq $policy) {
            if ($PSCmdlet.ShouldProcess($containerName, "Create unlocked $RetentionDays-day immutability policy")) {
                Invoke-AzMutation -Arguments @(
                    "storage", "container", "immutability-policy", "create",
                    "--resource-group", $ResourceGroup,
                    "--account-name", $StorageAccount,
                    "--container-name", $containerName,
                    "--period", "$RetentionDays",
                    "--allow-protected-append-writes", "false"
                )
            }
            $policy = Wait-ForImmutabilityPolicy -ContainerName $containerName
        }
        Assert-ExistingTargetIsSafe -ContainerName $containerName -Container $container `
            -Policy $policy -RejectLockedPolicy
    }

    $validationResults = @()
    foreach ($containerName in $approvedContainers) {
        $sourcePath = Join-Path ([IO.Path]::GetTempPath()) "$runId-$containerName-source.txt"
        $readbackPath = Join-Path ([IO.Path]::GetTempPath()) "$runId-$containerName-readback.txt"
        $blobName = "policy-validation/$runId.txt"
        try {
            "WarSOC $RetentionDays-day retention validation $runId $containerName" |
                Set-Content -LiteralPath $sourcePath -Encoding UTF8
            $sourceHash = (Get-FileHash -LiteralPath $sourcePath -Algorithm SHA256).Hash

            if ($PSCmdlet.ShouldProcess("$containerName/$blobName", "Upload retained Cold validation blob")) {
                Invoke-AzMutation -Arguments @(
                    "storage", "blob", "upload",
                    "--account-name", $StorageAccount,
                    "--container-name", $containerName,
                    "--name", $blobName,
                    "--file", $sourcePath,
                    "--tier", "Cold",
                    "--auth-mode", "login",
                    "--overwrite", "false",
                    "--metadata", "purpose=warsoc-retention-validation", "run_id=$runId",
                    "--no-progress"
                )
            }

            $blob = Wait-ForBlobResource -ContainerName $containerName -BlobName $blobName
            $blobVersionId = [string](Get-OptionalProperty -Object $blob -Name "versionId")
            $blobProperties = Get-OptionalProperty -Object $blob -Name "properties"
            $blobTier = [string](Get-OptionalProperty -Object $blobProperties -Name "blobTier")
            if ([string]::IsNullOrWhiteSpace($blobVersionId)) {
                throw "Validation blob '$containerName/$blobName' has no Azure version ID."
            }
            if ($blobTier -ne "Cold") {
                throw "Validation blob '$containerName/$blobName' is not in Cold tier."
            }

            Invoke-AzMutation -Arguments @(
                "storage", "blob", "download",
                "--account-name", $StorageAccount,
                "--container-name", $containerName,
                "--name", $blobName,
                "--version-id", $blobVersionId,
                "--file", $readbackPath,
                "--auth-mode", "login",
                "--no-progress"
            )
            $readbackHash = (Get-FileHash -LiteralPath $readbackPath -Algorithm SHA256).Hash
            if ($sourceHash -ne $readbackHash) {
                throw "Validation blob '$containerName/$blobName' failed SHA-256 readback."
            }

            $validationResults += [ordered]@{
                container = $containerName
                blob = $blobName
                version_id = $blobVersionId
                etag = [string](Get-OptionalProperty -Object $blobProperties -Name "etag")
                tier = $blobTier
                sha256 = $sourceHash
                readback_verified = $true
            }
        }
        finally {
            Remove-Item -LiteralPath $sourcePath, $readbackPath -Force -ErrorAction SilentlyContinue
        }
    }

    $snapshot = Get-RetentionSnapshot -IncludeValidationBlobs
    Assert-SnapshotReady -Snapshot $snapshot -RequiredPolicyState "Unlocked" -RequireValidationBlob
    [void](Write-ResultReport -Status "PREPARED_UNLOCKED" -Account $storageAccountResource `
        -Snapshot $snapshot -ValidationResults $validationResults)
    Write-Host "Preparation passed. Policies remain UNLOCKED." -ForegroundColor Green
    return
}

if ($Mode -eq "Verify") {
    $snapshot = Get-RetentionSnapshot -IncludeValidationBlobs
    Assert-SnapshotReady -Snapshot $snapshot -RequiredPolicyState "Either" -RequireValidationBlob
    [void](Write-ResultReport -Status "VERIFIED" -Account $storageAccountResource -Snapshot $snapshot)
    Write-Host "Both $RetentionDays-day retention routes passed read-only verification." -ForegroundColor Green
    return
}

if ($Mode -eq "Lock") {
    $snapshot = Get-RetentionSnapshot -IncludeValidationBlobs
    Assert-SnapshotReady -Snapshot $snapshot -RequiredPolicyState "Either" -RequireValidationBlob

    if ($WhatIfPreference) {
        foreach ($row in $snapshot.containers | Where-Object { $_.policy_state -eq "Unlocked" }) {
            [void]$PSCmdlet.ShouldProcess($row.name, "Irreversibly lock exact $RetentionDays-day immutability policy")
        }
        [void](Write-ResultReport -Status "WHATIF" -Account $storageAccountResource -Snapshot $snapshot)
        return
    }

    foreach ($row in $snapshot.containers) {
        if ($row.policy_state -eq "Locked") {
            Write-Host "Policy already locked: $($row.name)"
            continue
        }
        if ([string]::IsNullOrWhiteSpace([string]$row.policy_etag)) {
            throw "Policy ETag is missing for '$($row.name)'."
        }
        if ($PSCmdlet.ShouldProcess($row.name, "Irreversibly lock exact $RetentionDays-day immutability policy")) {
            Invoke-AzMutation -Arguments @(
                "storage", "container", "immutability-policy", "lock",
                "--resource-group", $ResourceGroup,
                "--account-name", $StorageAccount,
                "--container-name", [string]$row.name,
                "--if-match", [string]$row.policy_etag
            )
        }
    }

    $lockedSnapshot = Get-RetentionSnapshot -IncludeValidationBlobs
    Assert-SnapshotReady -Snapshot $lockedSnapshot -RequiredPolicyState "Locked" -RequireValidationBlob
    [void](Write-ResultReport -Status "LOCKED_AND_VERIFIED" -Account $storageAccountResource -Snapshot $lockedSnapshot)
    Write-Host "Both exact $RetentionDays-day policies are LOCKED and verified." -ForegroundColor Green
}
