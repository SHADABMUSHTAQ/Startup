[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$LabRoot,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^(?:\d{1,3}\.){3}\d{1,3}$')]
    [string]$BridgeContainerIp,

    [string]$ComposeProjectName = "warsoc-wazuh-4147",

    [switch]$Apply
)

$ErrorActionPreference = "Stop"

if (-not $Apply) {
    throw "No changes made. Re-run with -Apply after reviewing LabRoot and BridgeContainerIp."
}

$RepoRoot = Split-Path -Parent $PSScriptRoot
$RuleSource = Join-Path $RepoRoot "deploy\wazuh\rules\warsoc_canary_rules.xml"
$HostManagerConfig = Join-Path $LabRoot "config\wazuh_cluster\wazuh_manager.conf"
if (-not (Test-Path -LiteralPath $RuleSource)) {
    throw "WarSOC canary rule file was not found: $RuleSource"
}
if (-not (Test-Path -LiteralPath (Join-Path $LabRoot "docker-compose.yml"))) {
    throw "Wazuh docker-compose.yml was not found in $LabRoot"
}
if (-not (Test-Path -LiteralPath $HostManagerConfig)) {
    throw "The host-mounted Wazuh manager config was not found: $HostManagerConfig"
}

Push-Location $LabRoot
try {
    $env:COMPOSE_PROJECT_NAME = $ComposeProjectName
    $Manager = (docker compose ps -q wazuh.manager).Trim()
    if (-not $Manager) {
        throw "The Wazuh manager container is not running."
    }

    $EvidenceRoot = Join-Path $LabRoot ("warsoc-integration-backup-" + (Get-Date -Format "yyyyMMddHHmmss"))
    New-Item -ItemType Directory -Path $EvidenceRoot | Out-Null
    docker cp "${Manager}:/var/ossec/etc/ossec.conf" (Join-Path $EvidenceRoot "ossec.conf.before")
    Copy-Item -LiteralPath $HostManagerConfig `
        -Destination (Join-Path $EvidenceRoot "wazuh_manager.conf.host.before")
    docker cp "${Manager}:/var/ossec/etc/rules/local_rules.xml" (Join-Path $EvidenceRoot "local_rules.xml.before")

    docker exec $Manager sh -lc "test -f /var/ossec/etc/rules/warsoc_canary_rules.xml"
    $HadCanaryRule = $LASTEXITCODE -eq 0
    if ($HadCanaryRule) {
        docker cp "${Manager}:/var/ossec/etc/rules/warsoc_canary_rules.xml" `
            (Join-Path $EvidenceRoot "warsoc_canary_rules.xml.before")
    }

    $ManagerChanged = $false

    try {

    $WorkingConfig = Join-Path $EvidenceRoot "ossec.conf.working"
    Copy-Item -LiteralPath $HostManagerConfig -Destination $WorkingConfig
    $ConfigText = Get-Content -LiteralPath $WorkingConfig -Raw
    $Marker = "WarSOC private JSON listener"
    if ($ConfigText -notmatch [regex]::Escape($Marker)) {
        $RemoteBlock = @"

  <!-- $Marker -->
  <remote>
    <connection>syslog</connection>
    <port>15140</port>
    <protocol>tcp</protocol>
    <allowed-ips>$BridgeContainerIp</allowed-ips>
    <local_ip>0.0.0.0</local_ip>
  </remote>
"@
        $ClosingTag = $ConfigText.IndexOf("</ossec_config>", [System.StringComparison]::Ordinal)
        if ($ClosingTag -lt 0) {
            throw "No closing ossec_config tag was found. The manager config was not modified."
        }
        $ConfigText = $ConfigText.Insert($ClosingTag, $RemoteBlock)
        $Utf8NoBom = New-Object System.Text.UTF8Encoding($false)
        [System.IO.File]::WriteAllText($WorkingConfig, $ConfigText, $Utf8NoBom)
        Copy-Item -LiteralPath $WorkingConfig -Destination $HostManagerConfig -Force
        docker cp $WorkingConfig "${Manager}:/var/ossec/etc/ossec.conf"
        $ManagerChanged = $true
    }

    docker cp $RuleSource "${Manager}:/var/ossec/etc/rules/warsoc_canary_rules.xml"
    $ManagerChanged = $true
    docker exec $Manager /var/ossec/bin/wazuh-analysisd -t
    if ($LASTEXITCODE -ne 0) {
        throw "Wazuh configuration validation failed."
    }

    $Sample = '{"warsoc_schema":"warsoc.wazuh-local-input/v1","warsoc_dispatch_uid":"WZD_0123456789ABCDEF0123456789ABCDEF","warsoc_event_uid":"event-canary-0001","warsoc_event_id":"4688","warsoc_source_family":"windows_endpoint","warsoc_dispatch_mode":"live","warsoc_original_event_time":"2026-08-11T12:00:00+00:00","warsoc_field_new_process_name":"C:\\Windows\\System32\\whoami.exe"}'
    $LogTestOutput = @($Sample | docker exec -i $Manager /var/ossec/bin/wazuh-logtest -q -U 100500:3:json 2>&1)
    $LogTestExitCode = $LASTEXITCODE
    $LogTestOutput | Write-Output
    $LogTestText = $LogTestOutput -join "`n"
    if ($LogTestExitCode -ne 0 -or $LogTestText -match '(?i)\berror\b|\bfailed\b') {
        throw "Wazuh canary rule validation failed."
    }

    docker compose up -d --no-deps --force-recreate wazuh.manager
    Start-Sleep -Seconds 30
    docker compose ps wazuh.manager
    $Manager = (docker compose ps -q wazuh.manager).Trim()
    if (-not $Manager) {
        throw "The recreated Wazuh manager is not running."
    }
    $ManagerStatus = @(docker exec $Manager /var/ossec/bin/wazuh-control status)
    if (-not ($ManagerStatus -match '^wazuh-analysisd is running')) {
        throw "The recreated Wazuh manager is not detection-ready."
    }
    docker exec $Manager sh -lc "grep -n 'WarSOC private JSON listener' /var/ossec/etc/ossec.conf"
    docker exec $Manager sh -lc "grep -n '100500' /var/ossec/etc/rules/warsoc_canary_rules.xml"

    Get-FileHash -LiteralPath (Join-Path $EvidenceRoot "ossec.conf.before") -Algorithm SHA256
    Get-FileHash -LiteralPath $RuleSource -Algorithm SHA256
    Write-Host "Wazuh lab listener and canary rule validated. Backup: $EvidenceRoot" -ForegroundColor Green
    }
    catch {
        if ($ManagerChanged) {
            Write-Warning "Validation failed. Restoring the pre-change Wazuh manager files."
            Copy-Item -LiteralPath (Join-Path $EvidenceRoot "wazuh_manager.conf.host.before") `
                -Destination $HostManagerConfig -Force
            docker cp (Join-Path $EvidenceRoot "ossec.conf.before") `
                "${Manager}:/var/ossec/etc/ossec.conf"
            if ($HadCanaryRule) {
                docker cp (Join-Path $EvidenceRoot "warsoc_canary_rules.xml.before") `
                    "${Manager}:/var/ossec/etc/rules/warsoc_canary_rules.xml"
            }
            else {
                docker exec $Manager sh -lc "rm -f /var/ossec/etc/rules/warsoc_canary_rules.xml"
            }
            docker compose restart wazuh.manager
        }
        throw
    }
}
finally {
    Pop-Location
}
