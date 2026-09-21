[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^(?:\d{1,3}\.){3}\d{1,3}$')]
    [string]$ManagerAddress,

    [Parameter(Mandatory = $true)]
    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })]
    [string]$EnrollmentKeyPath,

    [string]$AgentRoot = 'C:\Program Files (x86)\ossec-agent'
)

$ErrorActionPreference = 'Stop'

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this script from an elevated PowerShell window.'
}

$configPath = Join-Path $AgentRoot 'ossec.conf'
$keyPath = Join-Path $AgentRoot 'client.keys'
$manageAgentsPath = Join-Path $AgentRoot 'manage_agents.exe'
$scaPath = Join-Path $AgentRoot 'ruleset\sca'
$serviceName = 'WazuhSvc'
$timestamp = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ')
$configBackup = "$configPath.warsoc-$timestamp.bak"
$keyBackup = "$keyPath.warsoc-$timestamp.bak"
$enrollmentKey = (Get-Content -LiteralPath $EnrollmentKeyPath -Raw).Trim()

if ($enrollmentKey -notmatch '^[A-Za-z0-9+/=]{40,4096}$') {
    throw 'The enrollment-key file does not contain one valid Wazuh agent key.'
}

foreach ($requiredPath in @($configPath, $keyPath, $manageAgentsPath, $scaPath)) {
    if (-not (Test-Path -LiteralPath $requiredPath)) {
        throw "Required Wazuh agent path is missing: $requiredPath"
    }
}
if (-not (Get-ChildItem -LiteralPath $scaPath -Filter '*.yml' -File -ErrorAction SilentlyContinue)) {
    throw 'No local Wazuh SCA policy files are installed.'
}

Copy-Item -LiteralPath $configPath -Destination $configBackup
Copy-Item -LiteralPath $keyPath -Destination $keyBackup

try {
    Stop-Service -Name $serviceName -Force

    $xml = [xml]::new()
    $xml.PreserveWhitespace = $true
    $xml.Load($configPath)
    $root = $xml.SelectSingleNode('/ossec_config')
    if ($null -eq $root) {
        throw 'The Wazuh agent configuration has no ossec_config root.'
    }

    $client = $root.SelectSingleNode('client')
    if ($null -eq $client) {
        $client = $xml.CreateElement('client')
        [void]$root.PrependChild($client)
    }
    $servers = @($client.SelectNodes('server'))
    if ($servers.Count -eq 0) {
        $server = $xml.CreateElement('server')
        [void]$client.AppendChild($server)
    }
    else {
        $server = $servers[0]
        foreach ($extraServer in $servers | Select-Object -Skip 1) {
            [void]$client.RemoveChild($extraServer)
        }
    }

    foreach ($setting in ([ordered]@{
        address = $ManagerAddress
        port = '1514'
        protocol = 'tcp'
    }).GetEnumerator()) {
        $node = $server.SelectSingleNode($setting.Key)
        if ($null -eq $node) {
            $node = $xml.CreateElement($setting.Key)
            [void]$server.AppendChild($node)
        }
        $node.InnerText = $setting.Value
    }

    $sca = $root.SelectSingleNode('sca')
    if ($null -eq $sca) {
        $sca = $xml.CreateElement('sca')
        [void]$root.AppendChild($sca)
    }
    foreach ($setting in ([ordered]@{
        enabled = 'yes'
        scan_on_start = 'yes'
        interval = '12h'
        skip_nfs = 'yes'
    }).GetEnumerator()) {
        $node = $sca.SelectSingleNode($setting.Key)
        if ($null -eq $node) {
            $node = $xml.CreateElement($setting.Key)
            [void]$sca.AppendChild($node)
        }
        $node.InnerText = $setting.Value
    }

    $utf8NoBom = [Text.UTF8Encoding]::new($false)
    $writerSettings = [Xml.XmlWriterSettings]::new()
    $writerSettings.Encoding = $utf8NoBom
    $writerSettings.Indent = $false
    $writer = [Xml.XmlWriter]::Create($configPath, $writerSettings)
    try { $xml.Save($writer) } finally { $writer.Dispose() }

    $startInfo = [Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $manageAgentsPath
    $startInfo.Arguments = "-i $enrollmentKey"
    $startInfo.UseShellExecute = $false
    $startInfo.RedirectStandardInput = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    $startInfo.CreateNoWindow = $true
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $startInfo
    [void]$process.Start()
    $process.StandardInput.WriteLine('y')
    $process.StandardInput.Close()
    $process.WaitForExit()
    if ($process.ExitCode -ne 0) {
        $errorText = $process.StandardError.ReadToEnd().Trim()
        throw "Wazuh enrollment-key import failed (exit $($process.ExitCode)): $errorText"
    }
    Remove-Item -LiteralPath $EnrollmentKeyPath -Force
    $enrollmentKey = $null

    Start-Service -Name $serviceName
    Start-Sleep -Seconds 10
    $service = Get-Service -Name $serviceName
    if ($service.Status -ne 'Running') {
        throw 'WazuhSvc did not return to the Running state.'
    }

    $connection = Test-NetConnection -ComputerName $ManagerAddress -Port 1514 -WarningAction SilentlyContinue
    if (-not $connection.TcpTestSucceeded) {
        throw "The private Wazuh manager channel $ManagerAddress`:1514 is unreachable."
    }

    [pscustomobject]@{
        status = 'CONFIGURED'
        manager = $ManagerAddress
        port = 1514
        service = $service.Status
        sca_enabled = $true
        scan_on_start = $true
        config_backup = $configBackup
        key_backup = $keyBackup
    } | ConvertTo-Json
}
catch {
    $enrollmentKey = $null
    Copy-Item -LiteralPath $configBackup -Destination $configPath -Force
    Copy-Item -LiteralPath $keyBackup -Destination $keyPath -Force
    Start-Service -Name $serviceName -ErrorAction SilentlyContinue
    throw
}
