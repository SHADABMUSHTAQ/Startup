[CmdletBinding()]
param(
    [ValidateSet("Preflight", "Platform", "NativeGenerate", "NativeVerify", "Soak")]
    [string]$Phase = "Preflight",
    [string]$FrontendUrl = "https://warsoc.tech",
    [string]$BackendUrl = "https://api.warsoc.tech",
    [string]$AdminKey = $env:SUPER_ADMIN_API_KEY,
    [string]$MetricsToken = $env:METRICS_BEARER_TOKEN,
    [string]$EmailDomain = "warsoc.tech",
    [string]$ManifestPath = "",
    [string]$InstallerPath = "",
    [string]$ArtifactUrl = $env:AGENT_CDN_URL,
    [string]$ActivationCode = "",
    [PSCredential]$Credential,
    [int]$WaitSeconds = 180,
    [int]$SoakTimeoutSeconds = 60,
    [switch]$ConfirmProductionDataCreation,
    [switch]$ConfirmDisposableVm,
    [switch]$SkipEmailDeliveryCheck
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$Root = Split-Path $PSScriptRoot -Parent
if (-not $ManifestPath) {
    $ManifestPath = Join-Path $Root "Output\pilot_hash_manifest.json"
}
if (-not $InstallerPath) {
    $InstallerPath = Join-Path $Root "Output\warsoc_installer.exe"
}

$RunId = [Guid]::NewGuid().ToString("N").Substring(0, 10)
$ArtifactDirectory = Join-Path $Root "tmp\production-acceptance\$RunId"
New-Item -ItemType Directory -Path $ArtifactDirectory -Force | Out-Null
$Results = [System.Collections.Generic.List[object]]::new()

function Add-AcceptanceResult {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)]
        [ValidateSet("PASS", "FAIL", "WARN")]
        [string]$Status,
        [string]$Detail = ""
    )
    $Results.Add([ordered]@{
        name = $Name
        status = $Status
        detail = $Detail
    })
    $color = if ($Status -eq "PASS") {
        "Green"
    } elseif ($Status -eq "FAIL") {
        "Red"
    } else {
        "Yellow"
    }
    Write-Host "[$Status] $Name`: $Detail" -ForegroundColor $color
}

function Get-HttpStatus {
    param(
        [Parameter(Mandatory = $true)][string]$Uri,
        [hashtable]$Headers = @{},
        [string]$Method = "GET"
    )
    try {
        $response = Invoke-WebRequest `
            -Uri $Uri `
            -Method $Method `
            -Headers $Headers `
            -UseBasicParsing `
            -TimeoutSec 30
        return [ordered]@{
            status = [int]$response.StatusCode
            headers = $response.Headers
            content = [string]$response.Content
        }
    }
    catch {
        $status = 0
        try {
            $status = [int]$_.Exception.Response.StatusCode
        }
        catch {}
        return [ordered]@{
            status = $status
            headers = if ($_.Exception.Response) { $_.Exception.Response.Headers } else { @{} }
            content = $_.Exception.Message
        }
    }
}

function Test-TcpPort {
    param(
        [Parameter(Mandatory = $true)][string]$HostName,
        [Parameter(Mandatory = $true)][int]$Port,
        [int]$TimeoutMilliseconds = 2000
    )
    $client = [System.Net.Sockets.TcpClient]::new()
    try {
        $pending = $client.BeginConnect($HostName, $Port, $null, $null)
        if (-not $pending.AsyncWaitHandle.WaitOne($TimeoutMilliseconds)) {
            return $false
        }
        $client.EndConnect($pending)
        return $true
    }
    catch {
        return $false
    }
    finally {
        $client.Dispose()
    }
}

function Get-TlsCertificateInfo {
    param(
        [Parameter(Mandatory = $true)][string]$HostName,
        [int]$Port = 443,
        [int]$TimeoutMilliseconds = 10000
    )
    $client = [System.Net.Sockets.TcpClient]::new()
    $stream = $null
    try {
        $pending = $client.BeginConnect($HostName, $Port, $null, $null)
        if (-not $pending.AsyncWaitHandle.WaitOne($TimeoutMilliseconds)) {
            throw "TLS connection to $HostName`:$Port timed out after $TimeoutMilliseconds ms"
        }
        $client.EndConnect($pending)
        $client.ReceiveTimeout = $TimeoutMilliseconds
        $client.SendTimeout = $TimeoutMilliseconds
        $stream = [System.Net.Security.SslStream]::new(
            $client.GetStream(),
            $false,
            { param($sender, $certificate, $chain, $errors) $errors -eq [System.Net.Security.SslPolicyErrors]::None }
        )
        $stream.ReadTimeout = $TimeoutMilliseconds
        $stream.WriteTimeout = $TimeoutMilliseconds
        $stream.AuthenticateAsClient($HostName)
        $certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new(
            $stream.RemoteCertificate
        )
        return [ordered]@{
            subject = $certificate.Subject
            issuer = $certificate.Issuer
            expires = $certificate.NotAfter.ToUniversalTime()
            days_remaining = [Math]::Floor(
                ($certificate.NotAfter.ToUniversalTime() - [DateTime]::UtcNow).TotalDays
            )
            protocol = [string]$stream.SslProtocol
        }
    }
    finally {
        if ($null -ne $stream) {
            $stream.Dispose()
        }
        $client.Dispose()
    }
}

function Save-Report {
    param([bool]$Passed)
    $report = [ordered]@{
        run_id = $RunId
        phase = $Phase
        frontend_url = $FrontendUrl
        backend_url = $BackendUrl
        completed_at = [DateTimeOffset]::UtcNow.ToString("o")
        passed = $Passed
        results = $Results
    }
    $path = Join-Path $ArtifactDirectory "$($Phase.ToLowerInvariant())-result.json"
    $report | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $path -Encoding UTF8
    Write-Host "[ARTIFACT] $path" -ForegroundColor Cyan
}

function Invoke-Preflight {
    $frontend = [Uri]$FrontendUrl
    $backend = [Uri]$BackendUrl
    if ($frontend.Scheme -ne "https" -or $backend.Scheme -ne "https") {
        Add-AcceptanceResult "HTTPS URLs" "FAIL" "Frontend and backend must both use HTTPS."
        return
    }
    Add-AcceptanceResult "HTTPS URLs" "PASS" "$FrontendUrl -> $BackendUrl"

    $resolvedAddresses = @{}
    foreach ($uri in @($frontend, $backend)) {
        try {
            $addresses = @([System.Net.Dns]::GetHostAddresses($uri.DnsSafeHost))
            $resolvedAddresses[$uri.DnsSafeHost] = @(
                $addresses | ForEach-Object { $_.IPAddressToString } | Sort-Object -Unique
            )
            $addressText = ($addresses | ForEach-Object { $_.IPAddressToString }) -join ","
            Add-AcceptanceResult "DNS $($uri.DnsSafeHost)" "PASS" $addressText
        }
        catch {
            Add-AcceptanceResult "DNS $($uri.DnsSafeHost)" "FAIL" $_.Exception.Message
        }
    }

    if (
        $frontend.DnsSafeHost -ne $backend.DnsSafeHost -and
        $resolvedAddresses.ContainsKey($frontend.DnsSafeHost) -and
        $resolvedAddresses.ContainsKey($backend.DnsSafeHost)
    ) {
        $sharedAddresses = @(
            $resolvedAddresses[$frontend.DnsSafeHost] |
                Where-Object { $resolvedAddresses[$backend.DnsSafeHost] -contains $_ }
        )
        $dnsIsolated = $sharedAddresses.Count -eq 0
        Add-AcceptanceResult `
            "Frontend/backend DNS isolation" `
            $(if ($dnsIsolated) { "PASS" } else { "FAIL" }) `
            $(if ($dnsIsolated) { "no shared addresses" } else { "shared=$($sharedAddresses -join ','); remove the API/DigitalOcean address from the frontend apex record" })
    }

    try {
        $tls = Get-TlsCertificateInfo -HostName $frontend.DnsSafeHost
        $tlsOk = $tls.days_remaining -ge 14
        Add-AcceptanceResult "Frontend TLS certificate" $(if ($tlsOk) { "PASS" } else { "FAIL" }) "protocol=$($tls.protocol); expires=$($tls.expires.ToString('o')); days=$($tls.days_remaining)"
    }
    catch {
        Add-AcceptanceResult "Frontend TLS certificate" "FAIL" $_.Exception.Message
    }

    try {
        $tls = Get-TlsCertificateInfo -HostName $backend.DnsSafeHost
        $tlsOk = $tls.days_remaining -ge 14
        Add-AcceptanceResult "Backend TLS certificate" $(if ($tlsOk) { "PASS" } else { "FAIL" }) "protocol=$($tls.protocol); expires=$($tls.expires.ToString('o')); days=$($tls.days_remaining)"
    }
    catch {
        Add-AcceptanceResult "Backend TLS certificate" "FAIL" $_.Exception.Message
    }

    $frontendResponse = Get-HttpStatus -Uri $FrontendUrl
    $frontendOk = (
        $frontendResponse.status -eq 200 -and
        $frontendResponse.content -match "<html"
    )
    Add-AcceptanceResult "Vercel frontend" $(if ($frontendOk) { "PASS" } else { "FAIL" }) "HTTP $($frontendResponse.status)"

    $assetMatches = [regex]::Matches(
        $frontendResponse.content,
        '(?:src|href)=["'']([^"'']+\.(?:js|css)(?:\?[^"'']*)?)["'']'
    )
    $assetFailures = 0
    $javascript = [System.Text.StringBuilder]::new()
    foreach ($match in $assetMatches) {
        $assetUri = [Uri]::new($frontend, $match.Groups[1].Value).AbsoluteUri
        $asset = Get-HttpStatus -Uri $assetUri
        if ($asset.status -ne 200) {
            $assetFailures += 1
        }
        elseif ($assetUri -match "\.js(?:\?|$)") {
            [void]$javascript.Append($asset.content)
        }
    }
    $assetsOk = $assetMatches.Count -gt 0 -and $assetFailures -eq 0
    Add-AcceptanceResult "Frontend assets" $(if ($assetsOk) { "PASS" } else { "FAIL" }) "found=$($assetMatches.Count); failed=$assetFailures"

    $expectedApi = $BackendUrl.TrimEnd("/") + "/api/v1"
    $javascriptText = $javascript.ToString()
    $apiLiterals = @(
        [regex]::Matches($javascriptText, 'https?://[^"'']+/api/v1') |
            ForEach-Object { $_.Value } |
            Sort-Object -Unique
    )
    $directBinding = $javascriptText.Contains($expectedApi)
    $sameOriginBinding = $javascriptText.Contains("/api/v1")
    $bindingOk = $directBinding -or $sameOriginBinding
    $bindingMode = if ($directBinding) { "direct" } elseif ($sameOriginBinding) { "same-origin-proxy" } else { "missing" }
    Add-AcceptanceResult "Frontend production API binding" $(if ($bindingOk) { "PASS" } else { "FAIL" }) "mode=$bindingMode; backend=$expectedApi; observed=$($apiLiterals -join ',')"

    $developmentApiAbsent = -not $javascriptText.Contains("http://localhost:8000/api/v1")
    Add-AcceptanceResult "Frontend no development API" $(if ($developmentApiAbsent) { "PASS" } else { "FAIL" }) $(if ($developmentApiAbsent) { "no localhost API binding" } else { "deployed bundle contains http://localhost:8000/api/v1" })

    $web3FormsAbsent = -not $javascriptText.Contains("https://api.web3forms.com/submit")
    Add-AcceptanceResult "Frontend contact uses WarSOC backend" $(if ($web3FormsAbsent) { "PASS" } else { "FAIL" }) $(if ($web3FormsAbsent) { "no Web3Forms dependency" } else { "deployed bundle still contains Web3Forms" })

    $proxyProbe = Get-HttpStatus -Uri ($FrontendUrl.TrimEnd("/") + "/api/v1/auth/me")
    $proxyOk = $proxyProbe.status -eq 401
    Add-AcceptanceResult "Frontend API proxy" $(if ($proxyOk) { "PASS" } else { "FAIL" }) "HTTP $($proxyProbe.status); expected unauthenticated HTTP 401"

    $healthResponse = Get-HttpStatus -Uri ($BackendUrl.TrimEnd("/") + "/health")
    $healthOk = $healthResponse.status -eq 200 -and $healthResponse.content -match '"status"\s*:\s*"healthy"'
    Add-AcceptanceResult "Backend health" $(if ($healthOk) { "PASS" } else { "FAIL" }) "HTTP $($healthResponse.status); $($healthResponse.content)"

    foreach ($headerName in @("Strict-Transport-Security", "X-Frame-Options", "X-Content-Type-Options")) {
        $value = [string]$healthResponse.headers[$headerName]
        Add-AcceptanceResult "Security header $headerName" $(if ($value) { "PASS" } else { "FAIL" }) $value
    }

    $origin = "$($frontend.Scheme)://$($frontend.Authority)"
    $cors = Get-HttpStatus `
        -Uri ($BackendUrl.TrimEnd("/") + "/api/v1/auth/me") `
        -Method "OPTIONS" `
        -Headers @{
            Origin = $origin
            "Access-Control-Request-Method" = "GET"
            "Access-Control-Request-Headers" = "content-type,x-csrf-token"
        }
    $allowOrigin = [string]$cors.headers["Access-Control-Allow-Origin"]
    $allowCredentials = [string]$cors.headers["Access-Control-Allow-Credentials"]
    $corsOk = $cors.status -in @(200, 204) -and $allowOrigin -eq $origin -and $allowCredentials -eq "true"
    Add-AcceptanceResult "Frontend/backend CORS" $(if ($corsOk) { "PASS" } else { "FAIL" }) "HTTP $($cors.status); origin=$allowOrigin; credentials=$allowCredentials"

    $docs = Get-HttpStatus -Uri ($BackendUrl.TrimEnd("/") + "/docs")
    Add-AcceptanceResult "Public API docs blocked" $(if ($docs.status -eq 404) { "PASS" } else { "FAIL" }) "HTTP $($docs.status)"

    foreach ($port in @(27017, 6379, 8000)) {
        $open = Test-TcpPort -HostName $backend.DnsSafeHost -Port $port
        Add-AcceptanceResult "Private port $port" $(if (-not $open) { "PASS" } else { "FAIL" }) $(if ($open) { "publicly reachable" } else { "closed externally" })
    }

    $expectedInstallerHash = $null
    $expectedInstallerSize = $null
    try {
        $manifest = Get-Content -Raw -LiteralPath $ManifestPath | ConvertFrom-Json
        $installer = @($manifest.artifacts | Where-Object { $_.role -eq "windows-installer" }) | Select-Object -First 1
        $actualHash = (Get-FileHash -LiteralPath $InstallerPath -Algorithm SHA256).Hash
        $expectedInstallerHash = [string]$installer.sha256
        $expectedInstallerSize = [int64]$installer.size_bytes
        $manifestOk = (
            $null -ne $installer -and
            $actualHash -eq $expectedInstallerHash -and
            (Get-Item -LiteralPath $InstallerPath).Length -eq $expectedInstallerSize
        )
        Add-AcceptanceResult "Local installer manifest" $(if ($manifestOk) { "PASS" } else { "FAIL" }) "sha256=$actualHash"
    }
    catch {
        Add-AcceptanceResult "Local installer manifest" "FAIL" $_.Exception.Message
    }

    if ($ArtifactUrl) {
        $artifactFile = Join-Path $ArtifactDirectory "azure-installer.exe"
        try {
            $artifactUri = [Uri]$ArtifactUrl
            $safeArtifactUrl = "$($artifactUri.Scheme)://$($artifactUri.Authority)$($artifactUri.AbsolutePath)"
            if (
                $artifactUri.Scheme -ne "https" -or
                -not $artifactUri.AbsolutePath.ToLowerInvariant().EndsWith(".exe")
            ) {
                throw "Artifact URL must be HTTPS and point directly to an .exe file."
            }
            if (-not $expectedInstallerHash -or -not $expectedInstallerSize) {
                throw "Local installer manifest must be valid before checking Azure."
            }
            Invoke-WebRequest `
                -Uri $ArtifactUrl `
                -OutFile $artifactFile `
                -UseBasicParsing `
                -TimeoutSec 180
            $artifactItem = Get-Item -LiteralPath $artifactFile
            $artifactHash = (Get-FileHash -LiteralPath $artifactFile -Algorithm SHA256).Hash
            $artifactOk = (
                $artifactItem.Length -eq $expectedInstallerSize -and
                $artifactHash -eq $expectedInstallerHash
            )
            Add-AcceptanceResult "Azure installer artifact" $(if ($artifactOk) { "PASS" } else { "FAIL" }) "url=$safeArtifactUrl; bytes=$($artifactItem.Length); sha256=$artifactHash"
        }
        catch {
            Add-AcceptanceResult "Azure installer artifact" "FAIL" $_.Exception.Message
        }
        finally {
            Remove-Item -LiteralPath $artifactFile -Force -ErrorAction SilentlyContinue
        }
    }
    else {
        Add-AcceptanceResult "Azure installer artifact" "WARN" "Pass -ArtifactUrl or set AGENT_CDN_URL to verify the deployed binary."
    }
}

function Get-PythonCommand {
    $launcher = Get-Command py -ErrorAction SilentlyContinue
    if ($launcher) {
        return [ordered]@{ executable = $launcher.Source; prefix = @("-3.13") }
    }
    $python = Get-Command python -ErrorAction SilentlyContinue
    if ($python) {
        return [ordered]@{ executable = $python.Source; prefix = @() }
    }
    throw "Python 3.13+ was not found."
}

function Invoke-Platform {
    if (-not $ConfirmProductionDataCreation) {
        throw "Platform phase creates a disposable tenant, users, agents, alerts, leads and evidence. Re-run with -ConfirmProductionDataCreation."
    }
    if (-not $AdminKey) {
        throw "Set SUPER_ADMIN_API_KEY or pass -AdminKey."
    }
    if (-not $MetricsToken -and -not $SkipEmailDeliveryCheck) {
        throw "Set METRICS_BEARER_TOKEN, or explicitly pass -SkipEmailDeliveryCheck."
    }

    Invoke-Preflight
    $preflightFailures = @($Results | Where-Object { $_.status -eq "FAIL" }).Count
    if ($preflightFailures -gt 0) {
        throw "Public infrastructure preflight failed; production data was not created."
    }

    $python = Get-PythonCommand
    $reportPath = Join-Path $ArtifactDirectory "platform-result.json"
    $logPath = Join-Path $ArtifactDirectory "platform-output.log"
    $arguments = @(
        $python.prefix
        (Join-Path $PSScriptRoot "launch_readiness_validator.py")
        "--base-url", $BackendUrl
        "--email-domain", $EmailDomain
        "--wait-seconds", [string]$WaitSeconds
        "--provision-timeout", [string]$WaitSeconds
        "--manifest-path", $ManifestPath
        "--report-path", $reportPath
    )

    $previousAdminKey = $env:SUPER_ADMIN_API_KEY
    $previousMetricsToken = $env:METRICS_BEARER_TOKEN
    try {
        $env:SUPER_ADMIN_API_KEY = $AdminKey
        if ($MetricsToken) {
            $env:METRICS_BEARER_TOKEN = $MetricsToken
        }
        else {
            Remove-Item Env:METRICS_BEARER_TOKEN -ErrorAction SilentlyContinue
        }
        & $python.executable @arguments 2>&1 | Tee-Object -LiteralPath $logPath
        if ($LASTEXITCODE -ne 0) {
            throw "Platform acceptance failed. Review $reportPath and $logPath."
        }
    }
    finally {
        if ($null -eq $previousAdminKey) {
            Remove-Item Env:SUPER_ADMIN_API_KEY -ErrorAction SilentlyContinue
        }
        else {
            $env:SUPER_ADMIN_API_KEY = $previousAdminKey
        }
        if ($null -eq $previousMetricsToken) {
            Remove-Item Env:METRICS_BEARER_TOKEN -ErrorAction SilentlyContinue
        }
        else {
            $env:METRICS_BEARER_TOKEN = $previousMetricsToken
        }
    }
    Write-Host "[PASS] Platform acceptance" -ForegroundColor Green
    Write-Host "[ARTIFACT] $reportPath" -ForegroundColor Cyan
}

function Invoke-NativeGenerate {
    if (-not $ConfirmDisposableVm) {
        throw "NativeGenerate is destructive and must run only on a snapshot VM with -ConfirmDisposableVm."
    }
    if (-not $ActivationCode) {
        throw "Pass a disposable tenant activation code with -ActivationCode."
    }
    & (Join-Path $PSScriptRoot "validate_native_windows_vm.ps1") `
        -Phase Generate `
        -InstallerPath $InstallerPath `
        -ActivationCode $ActivationCode `
        -BackendUrl $BackendUrl `
        -ConfirmDisposableVm `
        -ArtifactDirectory $ArtifactDirectory
    if ($LASTEXITCODE -ne 0) {
        throw "Native Windows event generation failed."
    }
}

function Invoke-NativeVerify {
    if (-not $Credential) {
        throw "Pass the disposable tenant administrator credential with -Credential (Get-Credential)."
    }
    & (Join-Path $PSScriptRoot "validate_native_windows_vm.ps1") `
        -Phase Verify `
        -BackendUrl $BackendUrl `
        -Credential $Credential `
        -VerifyTimeoutSeconds $WaitSeconds `
        -ArtifactDirectory $ArtifactDirectory
    if ($LASTEXITCODE -ne 0) {
        throw "Native Windows verification failed."
    }
}

function Invoke-Soak {
    if (-not $ConfirmProductionDataCreation) {
        throw "Soak creates one tenant and 50 registered agents. Re-run with -ConfirmProductionDataCreation."
    }
    if (-not $AdminKey) {
        throw "Set SUPER_ADMIN_API_KEY or pass -AdminKey."
    }
    $python = Get-PythonCommand
    $logPath = Join-Path $ArtifactDirectory "soak-output.log"
    $arguments = @(
        $python.prefix
        (Join-Path $PSScriptRoot "native_50_agent_soak.py")
        "--base-url", $BackendUrl
        "--email-domain", $EmailDomain
        "--timeout", [string]$SoakTimeoutSeconds
    )
    $previousAdminKey = $env:SUPER_ADMIN_API_KEY
    try {
        $env:SUPER_ADMIN_API_KEY = $AdminKey
        & $python.executable @arguments 2>&1 | Tee-Object -LiteralPath $logPath
        if ($LASTEXITCODE -ne 0) {
            throw "50-agent soak failed. Review $logPath."
        }
    }
    finally {
        if ($null -eq $previousAdminKey) {
            Remove-Item Env:SUPER_ADMIN_API_KEY -ErrorAction SilentlyContinue
        }
        else {
            $env:SUPER_ADMIN_API_KEY = $previousAdminKey
        }
    }
    Write-Host "[PASS] 50-agent soak" -ForegroundColor Green
    Write-Host "[ARTIFACT] $logPath" -ForegroundColor Cyan
}

Write-Host "WarSOC production acceptance - $Phase" -ForegroundColor Cyan
Write-Host "Run ID: $RunId" -ForegroundColor Cyan

try {
    switch ($Phase) {
        "Preflight" {
            Invoke-Preflight
            $failed = @($Results | Where-Object { $_.status -eq "FAIL" }).Count
            Save-Report -Passed ($failed -eq 0)
            if ($failed -gt 0) {
                exit 1
            }
        }
        "Platform" { Invoke-Platform }
        "NativeGenerate" { Invoke-NativeGenerate }
        "NativeVerify" { Invoke-NativeVerify }
        "Soak" { Invoke-Soak }
    }
}
catch {
    Add-AcceptanceResult "$Phase execution" "FAIL" $_.Exception.Message
    Save-Report -Passed $false
    exit 1
}

exit 0
