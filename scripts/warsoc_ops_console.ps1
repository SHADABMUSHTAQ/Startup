param(
    [string]$DefaultApiBase = "https://api.warsoc.tech/api/v1"
)

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

[System.Windows.Forms.Application]::EnableVisualStyles()

$ErrorActionPreference = "Stop"

function Normalize-ApiBase {
    param([string]$Value)
    $base = ($Value -replace "\s", "").TrimEnd("/")
    if (-not $base) {
        return "https://api.warsoc.tech/api/v1"
    }
    if ($base -notmatch "/api/v1$") {
        $base = "$base/api/v1"
    }
    return $base
}

function New-StrongPassword {
    $lower = "abcdefghijkmnopqrstuvwxyz"
    $upper = "ABCDEFGHJKLMNPQRSTUVWXYZ"
    $digits = "23456789"
    $symbols = "!@#$%^&*()-_=+[]{}"
    $all = ($lower + $upper + $digits + $symbols).ToCharArray()
    $required = @(
        $lower[(Get-Random -Maximum $lower.Length)],
        $upper[(Get-Random -Maximum $upper.Length)],
        $digits[(Get-Random -Maximum $digits.Length)],
        $symbols[(Get-Random -Maximum $symbols.Length)]
    )
    $chars = New-Object System.Collections.Generic.List[char]
    foreach ($c in $required) { [void]$chars.Add([char]$c) }
    while ($chars.Count -lt 20) {
        [void]$chars.Add($all[(Get-Random -Maximum $all.Length)])
    }
    -join ($chars | Sort-Object { Get-Random })
}

function Test-StrongPassword {
    param([string]$Password)
    if ($Password.Length -lt 16) { return "Password must be at least 16 characters." }
    if ($Password -notmatch "[a-z]") { return "Password must include a lowercase letter." }
    if ($Password -notmatch "[A-Z]") { return "Password must include an uppercase letter." }
    if ($Password -notmatch "\d") { return "Password must include a number." }
    if ($Password -notmatch "[^a-zA-Z0-9\s]") { return "Password must include a symbol." }
    return $null
}

function Get-ErrorMessage {
    param($ErrorRecord)
    try {
        if ($ErrorRecord.ErrorDetails -and $ErrorRecord.ErrorDetails.Message) {
            return $ErrorRecord.ErrorDetails.Message
        }
        $response = $ErrorRecord.Exception.Response
        if ($response) {
            $stream = $response.GetResponseStream()
            if ($stream) {
                $reader = New-Object System.IO.StreamReader($stream)
                return $reader.ReadToEnd()
            }
        }
    } catch {
    }
    return $ErrorRecord.Exception.Message
}

$form = New-Object System.Windows.Forms.Form
$form.Text = "WarSOC Ops Provisioning"
$form.Size = New-Object System.Drawing.Size(760, 680)
$form.StartPosition = "CenterScreen"
$form.MinimumSize = New-Object System.Drawing.Size(760, 680)

$font = New-Object System.Drawing.Font("Segoe UI", 9)
$form.Font = $font

$y = 18
function Add-Label {
    param([string]$Text, [int]$Top)
    $label = New-Object System.Windows.Forms.Label
    $label.Text = $Text
    $label.Location = New-Object System.Drawing.Point(18, $Top)
    $label.Size = New-Object System.Drawing.Size(170, 24)
    $form.Controls.Add($label)
    return $label
}

function Add-TextBox {
    param([int]$Top, [string]$Text = "", [bool]$Masked = $false)
    $box = New-Object System.Windows.Forms.TextBox
    $box.Location = New-Object System.Drawing.Point(195, $Top)
    $box.Size = New-Object System.Drawing.Size(520, 24)
    $box.Text = $Text
    if ($Masked) { $box.UseSystemPasswordChar = $true }
    $form.Controls.Add($box)
    return $box
}

Add-Label "API base URL" $y | Out-Null
$apiBaseBox = Add-TextBox $y $DefaultApiBase
$y += 34

Add-Label "Super admin key" $y | Out-Null
$adminKeyBox = Add-TextBox $y "" $true
$y += 34

Add-Label "Company name" $y | Out-Null
$companyBox = Add-TextBox $y "Customer Company"
$y += 34

Add-Label "Plan type" $y | Out-Null
$planBox = New-Object System.Windows.Forms.ComboBox
$planBox.Location = New-Object System.Drawing.Point(195, $y)
$planBox.Size = New-Object System.Drawing.Size(220, 24)
$planBox.DropDownStyle = "DropDownList"
[void]$planBox.Items.AddRange(@("Enterprise", "Professional", "Customized", "15_AGENT_FBR_PECA"))
$planBox.SelectedIndex = 0
$form.Controls.Add($planBox)
$y += 34

Add-Label "Compliance packs" $y | Out-Null
$fbrCheck = New-Object System.Windows.Forms.CheckBox
$fbrCheck.Text = "FBR POS"
$fbrCheck.Checked = $true
$fbrCheck.Location = New-Object System.Drawing.Point(195, $y)
$fbrCheck.Size = New-Object System.Drawing.Size(100, 24)
$form.Controls.Add($fbrCheck)
$pecaCheck = New-Object System.Windows.Forms.CheckBox
$pecaCheck.Text = "PECA Forensic"
$pecaCheck.Checked = $true
$pecaCheck.Location = New-Object System.Drawing.Point(315, $y)
$pecaCheck.Size = New-Object System.Drawing.Size(130, 24)
$form.Controls.Add($pecaCheck)
$y += 34

Add-Label "Max agents" $y | Out-Null
$agentsBox = New-Object System.Windows.Forms.NumericUpDown
$agentsBox.Location = New-Object System.Drawing.Point(195, $y)
$agentsBox.Size = New-Object System.Drawing.Size(100, 24)
$agentsBox.Minimum = 1
$agentsBox.Maximum = 50
$agentsBox.Value = 15
$form.Controls.Add($agentsBox)
$y += 34

Add-Label "Retention days" $y | Out-Null
$retentionBox = New-Object System.Windows.Forms.NumericUpDown
$retentionBox.Location = New-Object System.Drawing.Point(195, $y)
$retentionBox.Size = New-Object System.Drawing.Size(100, 24)
$retentionBox.Minimum = 1
$retentionBox.Maximum = 2190
$retentionBox.Value = 90
$form.Controls.Add($retentionBox)
$retentionHint = New-Object System.Windows.Forms.Label
$retentionHint.Text = "FBR vault evidence is retained by compliance policy; this is tenant default/archive setting."
$retentionHint.Location = New-Object System.Drawing.Point(310, $y + 2)
$retentionHint.Size = New-Object System.Drawing.Size(420, 24)
$form.Controls.Add($retentionHint)
$y += 34

Add-Label "Daily quota GiB" $y | Out-Null
$quotaBox = New-Object System.Windows.Forms.NumericUpDown
$quotaBox.Location = New-Object System.Drawing.Point(195, $y)
$quotaBox.Size = New-Object System.Drawing.Size(100, 24)
$quotaBox.Minimum = 0
$quotaBox.Maximum = 500
$quotaBox.Value = 0
$form.Controls.Add($quotaBox)
$quotaHint = New-Object System.Windows.Forms.Label
$quotaHint.Text = "0 = backend default. Use a number only for a specific contract."
$quotaHint.Location = New-Object System.Drawing.Point(310, $y + 2)
$quotaHint.Size = New-Object System.Drawing.Size(360, 24)
$form.Controls.Add($quotaHint)
$y += 34

Add-Label "Admin email" $y | Out-Null
$emailBox = Add-TextBox $y "admin@customer.com"
$y += 34

Add-Label "Admin name" $y | Out-Null
$nameBox = Add-TextBox $y "Customer Admin"
$y += 34

Add-Label "Admin password" $y | Out-Null
$passwordBox = Add-TextBox $y "" $true
$generateButton = New-Object System.Windows.Forms.Button
$generateButton.Text = "Generate"
$generateButton.Location = New-Object System.Drawing.Point(610, $y - 1)
$generateButton.Size = New-Object System.Drawing.Size(105, 27)
$form.Controls.Add($generateButton)
$y += 44

$provisionButton = New-Object System.Windows.Forms.Button
$provisionButton.Text = "Provision Tenant"
$provisionButton.Location = New-Object System.Drawing.Point(195, $y)
$provisionButton.Size = New-Object System.Drawing.Size(140, 32)
$form.Controls.Add($provisionButton)

$listButton = New-Object System.Windows.Forms.Button
$listButton.Text = "List Tenants"
$listButton.Location = New-Object System.Drawing.Point(345, $y)
$listButton.Size = New-Object System.Drawing.Size(110, 32)
$form.Controls.Add($listButton)

$clearButton = New-Object System.Windows.Forms.Button
$clearButton.Text = "Clear"
$clearButton.Location = New-Object System.Drawing.Point(465, $y)
$clearButton.Size = New-Object System.Drawing.Size(85, 32)
$form.Controls.Add($clearButton)
$y += 44

$outputBox = New-Object System.Windows.Forms.TextBox
$outputBox.Location = New-Object System.Drawing.Point(18, $y)
$outputBox.Size = New-Object System.Drawing.Size(700, 210)
$outputBox.Multiline = $true
$outputBox.ScrollBars = "Vertical"
$outputBox.ReadOnly = $true
$outputBox.Font = New-Object System.Drawing.Font("Consolas", 9)
$form.Controls.Add($outputBox)

function Write-OutputBox {
    param([string]$Message)
    $outputBox.AppendText("[$(Get-Date -Format 'HH:mm:ss')] $Message`r`n")
}

$generateButton.Add_Click({
    $passwordBox.Text = New-StrongPassword
    Write-OutputBox "Generated a strong temporary admin password. Copy it before closing this tool."
})

$clearButton.Add_Click({
    $outputBox.Clear()
})

$listButton.Add_Click({
    try {
        $apiBase = Normalize-ApiBase $apiBaseBox.Text
        $adminKey = $adminKeyBox.Text.Trim()
        if (-not $adminKey) { throw "Super admin key is required." }
        $headers = @{ "X-Admin-Key" = $adminKey }
        $result = Invoke-RestMethod -Uri "$apiBase/admin/tenants" -Method Get -Headers $headers -TimeoutSec 30
        Write-OutputBox "Tenants:"
        foreach ($tenant in $result.tenants) {
            Write-OutputBox (" - {0} | {1} | plan={2} | agents={3} | packs={4}" -f `
                $tenant.tenant_id, $tenant.company_name, $tenant.plan_type, $tenant.max_agents, `
                (($tenant.compliance_packs | ForEach-Object { $_ }) -join ","))
        }
    } catch {
        Write-OutputBox ("ERROR: " + (Get-ErrorMessage $_))
    }
})

$provisionButton.Add_Click({
    try {
        $apiBase = Normalize-ApiBase $apiBaseBox.Text
        $adminKey = $adminKeyBox.Text.Trim()
        $password = $passwordBox.Text
        if (-not $adminKey) { throw "Super admin key is required." }
        $passwordError = Test-StrongPassword $password
        if ($passwordError) { throw $passwordError }

        $packs = New-Object System.Collections.Generic.List[string]
        if ($fbrCheck.Checked) { [void]$packs.Add("fbr_pos") }
        if ($pecaCheck.Checked) { [void]$packs.Add("peca_forensic") }

        $body = @{
            company_name = $companyBox.Text.Trim()
            plan_type = $planBox.SelectedItem.ToString()
            compliance_packs = @($packs)
            max_agents = [int]$agentsBox.Value
            retention_days = [int]$retentionBox.Value
            admin_email = $emailBox.Text.Trim()
            admin_name = $nameBox.Text.Trim()
            admin_password = $password
        }

        if ([int]$quotaBox.Value -gt 0) {
            $body.daily_ingest_quota_bytes = [int64]$quotaBox.Value * 1024 * 1024 * 1024
        }

        if (-not $body.company_name) { throw "Company name is required." }
        if (-not $body.admin_email) { throw "Admin email is required." }
        if (-not $body.admin_name) { throw "Admin name is required." }
        if ($packs.Count -eq 0) { throw "Select at least one compliance pack." }

        $headers = @{ "X-Admin-Key" = $adminKey }
        $json = $body | ConvertTo-Json -Depth 6
        $result = Invoke-RestMethod -Uri "$apiBase/admin/provision" -Method Post -Headers $headers -ContentType "application/json" -Body $json -TimeoutSec 60

        Write-OutputBox "PROVISIONED"
        Write-OutputBox ("Tenant ID:    " + $result.tenant_id)
        Write-OutputBox ("Company:      " + $result.company_name)
        Write-OutputBox ("Plan:         " + $result.plan_type)
        Write-OutputBox ("Admin email:  " + $result.admin_email)
        Write-OutputBox "Login URL:    https://warsoc.tech"
        Write-OutputBox "Hand over the admin email and password through your agreed secure channel."
    } catch {
        Write-OutputBox ("ERROR: " + (Get-ErrorMessage $_))
    }
})

[void]$form.ShowDialog()
