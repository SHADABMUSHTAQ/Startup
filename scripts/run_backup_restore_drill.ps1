[CmdletBinding()]
param(
    [string]$ComposeFile = "docker-compose.yml",
    [string]$EnvFile = ".env",
    [string]$OutputDirectory = "tmp/backup-restore-drill",
    [SecureString]$BackupPassphrase,
    [string]$ExistingEncryptedArchive,
    [string]$ExistingHashFile,
    [switch]$KeepEncryptedBackup
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

function Invoke-Docker {
    param([Parameter(Mandatory)][string[]]$Arguments)
    & docker @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "Docker command failed with exit code $LASTEXITCODE."
    }
}

function Read-EnvValue {
    param([string]$Path, [string]$Name)
    $line = Get-Content -LiteralPath $Path | Where-Object {
        $_ -match "^\s*$([regex]::Escape($Name))\s*="
    } | Select-Object -Last 1
    if (-not $line) { return $null }
    return (($line -split "=", 2)[1]).Trim().Trim('"').Trim("'")
}

$projectRoot = Split-Path -Parent $PSScriptRoot
$composePath = [IO.Path]::GetFullPath((Join-Path $projectRoot $ComposeFile))
$envPath = [IO.Path]::GetFullPath((Join-Path $projectRoot $EnvFile))
$outputPath = [IO.Path]::GetFullPath((Join-Path $projectRoot $OutputDirectory))

if (-not (Test-Path -LiteralPath $composePath)) { throw "Compose file not found: $composePath" }
if (-not (Test-Path -LiteralPath $envPath)) { throw "Environment file not found: $envPath" }

$databaseName = Read-EnvValue -Path $envPath -Name "MONGODB_DB_NAME"
if ([string]::IsNullOrWhiteSpace($databaseName)) { throw "MONGODB_DB_NAME is missing from $envPath" }
if ($databaseName -notmatch '^[A-Za-z0-9_-]{1,64}$') { throw "MONGODB_DB_NAME contains unsupported characters." }

if (-not $BackupPassphrase) {
    $BackupPassphrase = Read-Host "Enter the backup encryption passphrase" -AsSecureString
}
$passphrase = [Net.NetworkCredential]::new("", $BackupPassphrase).Password
if ($passphrase.Length -lt 32) { throw "Backup passphrase must contain at least 32 characters." }

New-Item -ItemType Directory -Force -Path $outputPath | Out-Null
$runId = (Get-Date).ToUniversalTime().ToString("yyyyMMddTHHmmssZ") + "-" + ([guid]::NewGuid().ToString("N").Substring(0, 8))
$rawName = "warsoc-$runId.archive.gz"
$encryptedName = "$rawName.enc"
$hashName = "$encryptedName.sha256"
$usingExistingArchive = -not [string]::IsNullOrWhiteSpace($ExistingEncryptedArchive)
if ($usingExistingArchive -xor (-not [string]::IsNullOrWhiteSpace($ExistingHashFile))) {
    throw "ExistingEncryptedArchive and ExistingHashFile must be supplied together."
}
if ($usingExistingArchive) {
    $encryptedPath = [IO.Path]::GetFullPath($ExistingEncryptedArchive)
    $hashPath = [IO.Path]::GetFullPath($ExistingHashFile)
    if (-not (Test-Path -LiteralPath $encryptedPath)) { throw "Encrypted archive not found: $encryptedPath" }
    if (-not (Test-Path -LiteralPath $hashPath)) { throw "SHA-256 sidecar not found: $hashPath" }
    $encryptedName = Split-Path -Leaf $encryptedPath
    $hashName = Split-Path -Leaf $hashPath
} else {
    $encryptedPath = Join-Path $outputPath $encryptedName
    $hashPath = Join-Path $outputPath $hashName
}
$reportPath = Join-Path $outputPath "restore-drill-$runId.json"
$restoreContainer = "warsoc-restore-drill-$($runId.ToLowerInvariant())"
$restoreVolume = "warsoc-restore-drill-data-$($runId.ToLowerInvariant())"
$restoreDatabase = "WarSOC_Restore_Drill"
$sourceContainer = $null
$plainArchivePath = "/tmp/$rawName"

try {
    if (-not $usingExistingArchive) {
        $sourceContainer = (& docker compose --env-file $envPath -f $composePath ps -q mongodb).Trim()
        if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($sourceContainer)) {
            throw "The source MongoDB Compose service is not running."
        }

        Write-Host "Creating compressed source backup..."
        Invoke-Docker @(
            "exec", $sourceContainer, "sh", "-eu", "-c",
            'mongodump --host 127.0.0.1 --port 27017 --username "$MONGO_INITDB_ROOT_USERNAME" --password "$MONGO_INITDB_ROOT_PASSWORD" --authenticationDatabase admin --db "$1" --archive="$2" --gzip',
            "sh", $databaseName, $plainArchivePath
        )

        Write-Host "Encrypting backup and producing SHA-256 proof..."
        Invoke-Docker @(
            "exec", "-e", "BACKUP_ENCRYPTION_PASSPHRASE=$passphrase", $sourceContainer,
            "openssl", "enc", "-aes-256-cbc", "-salt", "-pbkdf2", "-iter", "200000",
            "-pass", "env:BACKUP_ENCRYPTION_PASSPHRASE",
            "-in", $plainArchivePath, "-out", "/tmp/$encryptedName"
        )
        Invoke-Docker @(
            "exec", $sourceContainer, "sh", "-eu", "-c",
            'cd /tmp && sha256sum "$1" > "$2"', "sh", $encryptedName, $hashName
        )
        Invoke-Docker @("cp", "${sourceContainer}:/tmp/$encryptedName", $encryptedPath)
        Invoke-Docker @("cp", "${sourceContainer}:/tmp/$hashName", $hashPath)
    }

    $expectedHash = ((Get-Content -LiteralPath $hashPath -Raw).Trim() -split '\s+')[0].ToUpperInvariant()
    $actualHash = (Get-FileHash -LiteralPath $encryptedPath -Algorithm SHA256).Hash.ToUpperInvariant()
    if ($expectedHash -ne $actualHash) { throw "Encrypted backup checksum verification failed." }

    Write-Host "Starting isolated MongoDB restore target..."
    $containerId = (& docker run -d --name $restoreContainer --network none --mount "type=volume,source=$restoreVolume,target=/data/db" mongo:7 --bind_ip_all).Trim()
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($containerId)) {
        throw "Could not start the isolated restore container."
    }

    $ready = $false
    for ($attempt = 0; $attempt -lt 30; $attempt++) {
        Start-Sleep -Seconds 1
        & docker exec $restoreContainer mongosh --quiet --eval "quit(db.adminCommand({ ping: 1 }).ok ? 0 : 2)" 2>$null
        if ($LASTEXITCODE -eq 0) { $ready = $true; break }
    }
    if (-not $ready) { throw "The isolated restore MongoDB did not become ready." }

    Invoke-Docker @("cp", $encryptedPath, "${restoreContainer}:/tmp/$encryptedName")
    Invoke-Docker @(
        "exec", "-e", "BACKUP_ENCRYPTION_PASSPHRASE=$passphrase", $restoreContainer,
        "openssl", "enc", "-d", "-aes-256-cbc", "-pbkdf2", "-iter", "200000",
        "-pass", "env:BACKUP_ENCRYPTION_PASSPHRASE",
        "-in", "/tmp/$encryptedName", "-out", $plainArchivePath
    )
    Invoke-Docker @(
        "exec", $restoreContainer, "mongorestore", "--archive=$plainArchivePath", "--gzip",
        "--nsFrom=$databaseName.*", "--nsTo=$restoreDatabase.*"
    )

    $summaryScript = @"
const target = db.getSiblingDB('$restoreDatabase');
const collections = target.getCollectionNames().sort().map((name) => ({
  name,
  documents: target.getCollection(name).countDocuments({}),
  indexes: target.getCollection(name).getIndexes().length
}));
print(JSON.stringify({ database: '$restoreDatabase', collections }));
"@
    $summaryJson = (& docker exec $restoreContainer mongosh --quiet --eval $summaryScript | Select-Object -Last 1)
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($summaryJson)) {
        throw "Could not inspect the restored database."
    }
    $summary = $summaryJson | ConvertFrom-Json
    $collectionNames = @($summary.collections | ForEach-Object { $_.name })
    foreach ($requiredCollection in @("tenants", "users")) {
        if ($requiredCollection -notin $collectionNames) {
            throw "Restore is missing required collection: $requiredCollection"
        }
    }

    $report = [ordered]@{
        status = "PASS"
        run_id = $runId
        completed_at_utc = (Get-Date).ToUniversalTime().ToString("o")
        source_database = $databaseName
        archive_source = $(if ($usingExistingArchive) { "existing_encrypted_backup" } else { "live_compose_dump" })
        restored_database = $restoreDatabase
        encrypted_archive_bytes = (Get-Item -LiteralPath $encryptedPath).Length
        encrypted_archive_sha256 = $actualHash
        isolated_network = "none"
        restore_storage = "temporary_docker_volume"
        required_collections = @("tenants", "users")
        collections = $summary.collections
    }
    $report | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $reportPath -Encoding UTF8
    Write-Host "Backup/restore drill passed: $reportPath" -ForegroundColor Green
}
finally {
    $passphrase = $null
    if ($sourceContainer) {
        & docker exec $sourceContainer rm -f $plainArchivePath "/tmp/$encryptedName" "/tmp/$hashName" 2>$null | Out-Null
    }
    & docker rm -f $restoreContainer 2>$null | Out-Null
    & docker volume rm -f $restoreVolume 2>$null | Out-Null
    if (-not $usingExistingArchive -and -not $KeepEncryptedBackup) {
        Remove-Item -LiteralPath $encryptedPath, $hashPath -Force -ErrorAction SilentlyContinue
    }
}
