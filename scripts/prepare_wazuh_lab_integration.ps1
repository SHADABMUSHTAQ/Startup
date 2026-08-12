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
if (-not (Test-Path -LiteralPath $RuleSource)) {
    throw "WarSOC canary rule file was not found: $RuleSource"
}
if (-not (Test-Path -LiteralPath (Join-Path $LabRoot "docker-compose.yml"))) {
    throw "Wazuh docker-compose.yml was not found in $LabRoot"
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
    docker cp "${Manager}:/var/ossec/etc/rules/local_rules.xml" (Join-Path $EvidenceRoot "local_rules.xml.before")

    $WorkingConfig = Join-Path $EvidenceRoot "ossec.conf.working"
    Copy-Item -LiteralPath (Join-Path $EvidenceRoot "ossec.conf.before") -Destination $WorkingConfig
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
        docker cp $WorkingConfig "${Manager}:/var/ossec/etc/ossec.conf"
    }

    docker cp $RuleSource "${Manager}:/var/ossec/etc/rules/warsoc_canary_rules.xml"
    docker exec $Manager /var/ossec/bin/wazuh-analysisd -t

    $Sample = '{"warsoc_schema":"warsoc.wazuh-local-input/v1","warsoc_dispatch_uid":"WZD_0123456789ABCDEF0123456789ABCDEF","warsoc_event_uid":"event-canary-0001","warsoc_event_id":"4688","warsoc_source_family":"windows_endpoint","warsoc_dispatch_mode":"live","warsoc_original_event_time":"2026-08-11T12:00:00+00:00","warsoc_field_new_process_name":"C:\\Windows\\System32\\whoami.exe"}'
    $Sample | docker exec -i $Manager /var/ossec/bin/wazuh-logtest -q -U 100500:3:json

    docker compose restart wazuh.manager
    Start-Sleep -Seconds 20
    docker compose ps wazuh.manager
    docker exec $Manager sh -lc "grep -n 'WarSOC private JSON listener' /var/ossec/etc/ossec.conf"
    docker exec $Manager sh -lc "grep -n '100500' /var/ossec/etc/rules/warsoc_canary_rules.xml"

    Get-FileHash -LiteralPath (Join-Path $EvidenceRoot "ossec.conf.before") -Algorithm SHA256
    Get-FileHash -LiteralPath $RuleSource -Algorithm SHA256
    Write-Host "Wazuh lab listener and canary rule validated. Backup: $EvidenceRoot" -ForegroundColor Green
}
finally {
    Pop-Location
}
