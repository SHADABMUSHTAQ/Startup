[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$SubscriptionId,

    [Parameter(Mandatory = $true)]
    [string]$ResourceGroup,

    [Parameter(Mandatory = $true)]
    [string]$StorageAccount,

    [string]$StagingContainer = "warsoc-retrieval-staging",
    [string]$ServicePrincipalName = "warsoc-oci-archive-retrieval",
    [string]$CredentialOutputPath = ".\tmp\archive-retrieval-oci.env",
    [switch]$RotateCredential,
    [switch]$UseServiceSasFallback
)

$ErrorActionPreference = "Stop"

function Invoke-AzureCli {
    param([Parameter(Mandatory = $true)][string[]]$Arguments)

    $output = @(& az @Arguments 2>&1)
    if ($LASTEXITCODE -ne 0) {
        throw "Azure CLI failed: az $($Arguments -join ' ')`n$($output -join [Environment]::NewLine)"
    }
    return $output
}

function Add-RoleAssignmentIfMissing {
    param(
        [Parameter(Mandatory = $true)][string]$AppId,
        [Parameter(Mandatory = $true)][string]$ObjectId,
        [Parameter(Mandatory = $true)][string]$Role,
        [Parameter(Mandatory = $true)][string]$Scope
    )

    $existing = Invoke-AzureCli @(
        "role", "assignment", "list",
        "--assignee", $AppId,
        "--role", $Role,
        "--scope", $Scope,
        "--query", "length(@)",
        "--output", "tsv"
    )
    if ([int]($existing | Select-Object -Last 1) -gt 0) {
        return
    }
    Invoke-AzureCli @(
        "role", "assignment", "create",
        "--assignee-object-id", $ObjectId,
        "--assignee-principal-type", "ServicePrincipal",
        "--role", $Role,
        "--scope", $Scope,
        "--output", "none"
    ) | Out-Null
}

Invoke-AzureCli @("account", "set", "--subscription", $SubscriptionId) | Out-Null

$account = ((
    Invoke-AzureCli @(
        "storage", "account", "show",
        "--resource-group", $ResourceGroup,
        "--name", $StorageAccount,
        "--output", "json"
    )
) -join "`n") | ConvertFrom-Json

if ($account.allowBlobPublicAccess -eq $true) {
    throw "Evidence storage account permits public blob access. Stop and correct that boundary first."
}

Invoke-AzureCli @(
    "storage", "container", "create",
    "--account-name", $StorageAccount,
    "--name", $StagingContainer,
    "--auth-mode", "login",
    "--public-access", "off",
    "--output", "none"
) | Out-Null

$existingPolicyOutput = @(
    & az storage account management-policy show `
        --resource-group $ResourceGroup `
        --account-name $StorageAccount `
        --output json 2>$null
)
$existingPolicyExit = $LASTEXITCODE
$rules = @()
if ($existingPolicyExit -eq 0 -and $existingPolicyOutput.Count -gt 0) {
    $existingPolicy = ($existingPolicyOutput -join "`n") | ConvertFrom-Json
    if ($null -ne $existingPolicy.policy -and $null -ne $existingPolicy.policy.rules) {
        $rules = @($existingPolicy.policy.rules)
    } elseif ($null -ne $existingPolicy.rules) {
        $rules = @($existingPolicy.rules)
    }
}

$lifecycleRuleName = "delete-warsoc-retrieval-staging-after-3-days"
$rules = @($rules | Where-Object { $_.name -ne $lifecycleRuleName })
$rules += [ordered]@{
    enabled = $true
    name = $lifecycleRuleName
    type = "Lifecycle"
    definition = [ordered]@{
        actions = [ordered]@{
            baseBlob = [ordered]@{
                delete = [ordered]@{ daysAfterModificationGreaterThan = 3 }
            }
        }
        filters = [ordered]@{
            blobTypes = @("blockBlob")
            prefixMatch = @("$StagingContainer/")
        }
    }
}

$temporaryPolicy = Join-Path ([IO.Path]::GetTempPath()) "warsoc-retrieval-lifecycle-$([guid]::NewGuid().ToString('N')).json"
try {
    $policyJson = @{ rules = $rules } | ConvertTo-Json -Depth 20
    [IO.File]::WriteAllText($temporaryPolicy, $policyJson, [Text.UTF8Encoding]::new($false))
    Invoke-AzureCli @(
        "storage", "account", "management-policy", "create",
        "--resource-group", $ResourceGroup,
        "--account-name", $StorageAccount,
        "--policy", "@$temporaryPolicy",
        "--output", "none"
    ) | Out-Null
} finally {
    Remove-Item -LiteralPath $temporaryPolicy -Force -ErrorAction SilentlyContinue
}

if ($UseServiceSasFallback -and $RotateCredential) {
    throw "-RotateCredential cannot be combined with -UseServiceSasFallback."
}

$credential = $null
$sasMode = "service_sas"
if (-not $UseServiceSasFallback) {
    $servicePrincipals = @(
        ((Invoke-AzureCli @(
            "ad", "sp", "list",
            "--display-name", $ServicePrincipalName,
            "--output", "json"
        )) -join "`n") | ConvertFrom-Json
    )

    if ($servicePrincipals.Count -gt 1) {
        throw "More than one service principal uses the requested display name. Resolve the ambiguity first."
    }
    if ($servicePrincipals.Count -eq 1 -and -not $RotateCredential) {
        throw "The service principal already exists. Re-run with -RotateCredential only when credential rotation is intended."
    }

    if ($servicePrincipals.Count -eq 1) {
        $credential = ((
            Invoke-AzureCli @(
                "ad", "sp", "credential", "reset",
                "--id", $servicePrincipals[0].appId,
                "--years", "1",
                "--output", "json"
            )
        ) -join "`n") | ConvertFrom-Json
    } else {
        $credential = ((
            Invoke-AzureCli @(
                "ad", "sp", "create-for-rbac",
                "--name", $ServicePrincipalName,
                "--skip-assignment",
                "--years", "1",
                "--output", "json"
            )
        ) -join "`n") | ConvertFrom-Json
    }

    $objectId = (
        Invoke-AzureCli @(
            "ad", "sp", "show",
            "--id", $credential.appId,
            "--query", "id",
            "--output", "tsv"
        ) | Select-Object -Last 1
    ).Trim()
    $accountScope = [string]$account.id
    $sourceContainers = @(
        "warsoc-siem-90", "warsoc-siem-180", "warsoc-siem-270", "warsoc-siem-365",
        "warsoc-general-90", "warsoc-general-180", "warsoc-general-270", "warsoc-general-365"
    )
    foreach ($container in $sourceContainers) {
        Add-RoleAssignmentIfMissing `
            -AppId $credential.appId `
            -ObjectId $objectId `
            -Role "Storage Blob Data Reader" `
            -Scope "$accountScope/blobServices/default/containers/$container"
    }
    Add-RoleAssignmentIfMissing `
        -AppId $credential.appId `
        -ObjectId $objectId `
        -Role "Storage Blob Data Contributor" `
        -Scope "$accountScope/blobServices/default/containers/$StagingContainer"
    Add-RoleAssignmentIfMissing `
        -AppId $credential.appId `
        -ObjectId $objectId `
        -Role "Storage Blob Delegator" `
        -Scope $accountScope
    $sasMode = "user_delegation"
}

$credentialDirectory = Split-Path -Parent ([IO.Path]::GetFullPath($CredentialOutputPath))
New-Item -ItemType Directory -Path $credentialDirectory -Force | Out-Null
$environmentLines = @(
    "ARCHIVE_RETRIEVAL_ENABLED=true",
    "AZURE_RETRIEVAL_STAGING_CONTAINER=$StagingContainer",
    "AZURE_RETRIEVAL_SAS_MODE=$sasMode",
    "AZURE_STORAGE_ACCOUNT_URL=https://$StorageAccount.blob.core.windows.net"
)
if ($null -ne $credential) {
    $environmentLines += @(
        "AZURE_TENANT_ID=$($credential.tenant)",
        "AZURE_CLIENT_ID=$($credential.appId)",
        "AZURE_CLIENT_SECRET=$($credential.password)"
    )
}
$environmentText = $environmentLines -join "`n"
$resolvedCredentialPath = [IO.Path]::GetFullPath($CredentialOutputPath)
[IO.File]::WriteAllText(
    $resolvedCredentialPath,
    $environmentText.Trim() + "`n",
    [Text.UTF8Encoding]::new($false)
)

if ($env:USERNAME) {
    & icacls.exe $resolvedCredentialPath /inheritance:r /grant:r "$($env:USERNAME):F" | Out-Null
}

Write-Output "Storage account: $StorageAccount"
Write-Output "Private staging container: $StagingContainer"
Write-Output "Lifecycle: staged blobs deleted after 3 days"
Write-Output "SAS mode: $sasMode"
if ($null -ne $credential) {
    Write-Output "Service principal app ID: $($credential.appId)"
}
Write-Output "Root-only OCI environment source: $resolvedCredentialPath"
if ($null -ne $credential) {
    Write-Output "Secret value was written to the file and was not printed."
} else {
    Write-Output "No new secret was generated; OCI will use the existing storage connection credential."
}
