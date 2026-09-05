[CmdletBinding()]
param(
    [Alias("Uninstall")][switch]$Rollback,
    [string]$PosPaths = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$ScriptVersion = "3.0.0-native"
$StateDirectory = Join-Path $env:ProgramData "WarSOC"
$StatePath = Join-Path $StateDirectory "native-telemetry-state.json"
$EvidencePath = Join-Path $StateDirectory "telemetry-deploy.json"
$PosAuditPath = Join-Path $StateDirectory "pos_audit.log"
$AuditRegistryPath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
$AuditRegistryName = "ProcessCreationIncludeCmdLine_Enabled"
$InstallHadExistingState = $false

$AuditControls = @(
    @{ Name = "Logon"; Id = "{0CCE9215-69AE-11D9-BED3-505054503030}"; Success = $true; Failure = $true },
    @{ Name = "Process Creation"; Id = "{0CCE922B-69AE-11D9-BED3-505054503030}"; Success = $true; Failure = $false },
    @{ Name = "File System"; Id = "{0CCE921D-69AE-11D9-BED3-505054503030}"; Success = $true; Failure = $true },
    @{ Name = "Registry"; Id = "{0CCE921E-69AE-11D9-BED3-505054503030}"; Success = $true; Failure = $true },
    @{ Name = "Other Object Access Events"; Id = "{0CCE9227-69AE-11D9-BED3-505054503030}"; Success = $true; Failure = $true },
    @{ Name = "Filtering Platform Connection"; Id = "{0CCE9226-69AE-11D9-BED3-505054503030}"; Success = $false; Failure = $true },
    @{ Name = "User Account Management"; Id = "{0CCE9235-69AE-11D9-BED3-505054503030}"; Success = $true; Failure = $true },
    @{ Name = "Security Group Management"; Id = "{0CCE9237-69AE-11D9-BED3-505054503030}"; Success = $true; Failure = $true },
    @{ Name = "Special Logon"; Id = "{0CCE921B-69AE-11D9-BED3-505054503030}"; Success = $true; Failure = $false },
    @{ Name = "Security System Extension"; Id = "{0CCE9211-69AE-11D9-BED3-505054503030}"; Success = $true; Failure = $true },
    @{ Name = "Audit Policy Change"; Id = "{0CCE922F-69AE-11D9-BED3-505054503030}"; Success = $true; Failure = $true }
)

$IsWindowsServer = $false
try {
    $IsWindowsServer = ([int](Get-CimInstance Win32_OperatingSystem).ProductType -ne 1)
} catch {
    throw "Unable to determine whether this host is Windows Server; refusing to configure auditing."
}
$GeneralServerExcludedAuditIds = @(
    "{0CCE921D-69AE-11D9-BED3-505054503030}", # File System
    "{0CCE921E-69AE-11D9-BED3-505054503030}"  # Registry
)

Add-Type -TypeDefinition @"
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
public static class WarSocAuditPolicy {
    private const uint TOKEN_ADJUST_PRIVILEGES = 0x0020;
    private const uint TOKEN_QUERY = 0x0008;
    private const uint SE_PRIVILEGE_ENABLED = 0x0002;
    private const int ERROR_NOT_ALL_ASSIGNED = 1300;
    [StructLayout(LayoutKind.Sequential)]
    private struct LUID {
        public uint LowPart;
        public int HighPart;
    }
    [StructLayout(LayoutKind.Sequential)]
    private struct LUID_AND_ATTRIBUTES {
        public LUID Luid;
        public uint Attributes;
    }
    [StructLayout(LayoutKind.Sequential)]
    private struct TOKEN_PRIVILEGES {
        public uint PrivilegeCount;
        public LUID_AND_ATTRIBUTES Privileges;
    }
    [StructLayout(LayoutKind.Sequential)]
    private struct AUDIT_POLICY_INFORMATION {
        public Guid AuditSubCategoryGuid;
        public uint AuditingInformation;
        public Guid AuditCategoryGuid;
    }
    [DllImport("advapi32.dll", SetLastError=true)]
    private static extern bool AuditQuerySystemPolicy(
        [In] Guid[] pSubCategoryGuids, uint dwPolicyCount, out IntPtr ppAuditPolicy);
    [DllImport("advapi32.dll")]
    private static extern void AuditFree(IntPtr buffer);
    [DllImport("kernel32.dll")]
    private static extern IntPtr GetCurrentProcess();
    [DllImport("kernel32.dll")]
    private static extern bool CloseHandle(IntPtr handle);
    [DllImport("kernel32.dll")]
    private static extern void SetLastError(uint errorCode);
    [DllImport("advapi32.dll", SetLastError=true)]
    private static extern bool OpenProcessToken(
        IntPtr process, uint desiredAccess, out IntPtr token);
    [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    private static extern bool LookupPrivilegeValue(
        string systemName, string name, out LUID luid);
    [DllImport("advapi32.dll", SetLastError=true)]
    private static extern bool AdjustTokenPrivileges(
        IntPtr token, bool disableAll, ref TOKEN_PRIVILEGES newState,
        uint bufferLength, out TOKEN_PRIVILEGES previousState, out uint returnLength);
    [DllImport("advapi32.dll", EntryPoint="AdjustTokenPrivileges", SetLastError=true)]
    private static extern bool RestoreTokenPrivileges(
        IntPtr token, bool disableAll, ref TOKEN_PRIVILEGES newState,
        uint bufferLength, IntPtr previousState, IntPtr returnLength);
    public static uint Query(string subcategory) {
        IntPtr token;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, out token))
            throw new Win32Exception(Marshal.GetLastWin32Error());
        try {
            LUID luid;
            if (!LookupPrivilegeValue(null, "SeSecurityPrivilege", out luid))
                throw new Win32Exception(Marshal.GetLastWin32Error());
            TOKEN_PRIVILEGES desired = new TOKEN_PRIVILEGES {
                PrivilegeCount = 1,
                Privileges = new LUID_AND_ATTRIBUTES {
                    Luid = luid, Attributes = SE_PRIVILEGE_ENABLED
                }
            };
            TOKEN_PRIVILEGES previous;
            uint returned;
            SetLastError(0);
            if (!AdjustTokenPrivileges(token, false, ref desired,
                    (uint)Marshal.SizeOf(typeof(TOKEN_PRIVILEGES)), out previous, out returned))
                throw new Win32Exception(Marshal.GetLastWin32Error());
            int privilegeError = Marshal.GetLastWin32Error();
            if (privilegeError == ERROR_NOT_ALL_ASSIGNED)
                throw new Win32Exception(privilegeError);
            try {
                IntPtr buffer;
                if (!AuditQuerySystemPolicy(new [] { new Guid(subcategory) }, 1, out buffer))
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                try {
                    return ((AUDIT_POLICY_INFORMATION)Marshal.PtrToStructure(
                        buffer, typeof(AUDIT_POLICY_INFORMATION))).AuditingInformation;
                } finally {
                    AuditFree(buffer);
                }
            } finally {
                RestoreTokenPrivileges(token, false, ref previous, 0, IntPtr.Zero, IntPtr.Zero);
            }
        } finally {
            CloseHandle(token);
        }
    }
}
"@

function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Ensure-StateDirectory {
    if (-not (Test-Path -LiteralPath $StateDirectory)) {
        New-Item -ItemType Directory -Path $StateDirectory -Force | Out-Null
    }
    if (-not (Test-Path -LiteralPath $PosAuditPath)) {
        New-Item -ItemType File -Path $PosAuditPath -Force | Out-Null
    }

    & icacls.exe $StateDirectory /inheritance:r `
        /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to secure $StateDirectory"
    }
}

function Get-AuditControlState {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$Id
    )

    $flags = [WarSocAuditPolicy]::Query($Id)

    return [ordered]@{
        name = $Name
        id = $Id
        success = [bool]($flags -band 1)
        failure = [bool]($flags -band 2)
        raw = ("0x{0:X8}" -f $flags)
    }
}

function Set-AuditControlState {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$Id,
        [Parameter(Mandatory = $true)][bool]$Success,
        [Parameter(Mandatory = $true)][bool]$Failure
    )

    $successValue = if ($Success) { "enable" } else { "disable" }
    $failureValue = if ($Failure) { "enable" } else { "disable" }
    $output = (& auditpol.exe /set "/subcategory:$Id" "/success:$successValue" "/failure:$failureValue" 2>&1 | Out-String)
    if ($LASTEXITCODE -ne 0) {
        throw "Unable to configure audit policy '$Name': $output"
    }
}

function Get-NormalizedPosPaths {
    param([string]$RawPaths)

    if ([string]::IsNullOrWhiteSpace($RawPaths)) {
        return @()
    }

    $normalized = @()
    foreach ($candidate in ($RawPaths -split "[,;]")) {
        $candidate = $candidate.Trim().Trim('"')
        if ([string]::IsNullOrWhiteSpace($candidate)) {
            continue
        }
        if ($candidate.StartsWith("\\")) {
            throw "POS path must be local, not UNC: $candidate"
        }
        if (-not [IO.Path]::IsPathRooted($candidate)) {
            throw "POS path must be absolute: $candidate"
        }
        if (-not (Test-Path -LiteralPath $candidate -PathType Container)) {
            throw "POS directory does not exist: $candidate"
        }
        $normalized += (Resolve-Path -LiteralPath $candidate).Path.TrimEnd("\")
    }
    return @($normalized | Sort-Object -Unique)
}

function Get-MissingWarSocAuditRights {
    param([Parameter(Mandatory = $true)][string]$Path)

    $requiredRights = [Security.AccessControl.FileSystemRights]::Delete `
        -bor [Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles `
        -bor [Security.AccessControl.FileSystemRights]::ChangePermissions
    $requiredInheritance = [Security.AccessControl.InheritanceFlags]::ContainerInherit `
        -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit
    $requiredAuditFlags = [Security.AccessControl.AuditFlags]::Success `
        -bor [Security.AccessControl.AuditFlags]::Failure
    $coveredRights = [Security.AccessControl.FileSystemRights]0

    $acl = Get-Acl -LiteralPath $Path -Audit
    foreach ($entry in $acl.Audit) {
        try {
            $sid = $entry.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
        } catch {
            continue
        }
        if (
            $sid -eq "S-1-1-0" -and
            ($entry.InheritanceFlags -band $requiredInheritance) -eq $requiredInheritance -and
            ($entry.AuditFlags -band $requiredAuditFlags) -eq $requiredAuditFlags
        ) {
            $coveredRights = $coveredRights -bor ($entry.FileSystemRights -band $requiredRights)
        }
    }

    return [Security.AccessControl.FileSystemRights](
        ([int64]$requiredRights) -band (-bnot [int64]$coveredRights)
    )
}

function New-WarSocAuditRule {
    param([Parameter(Mandatory = $true)][Security.AccessControl.FileSystemRights]$Rights)

    return [Security.AccessControl.FileSystemAuditRule]::new(
        [Security.Principal.SecurityIdentifier]::new("S-1-1-0"),
        $Rights,
        (
            [Security.AccessControl.InheritanceFlags]::ContainerInherit `
            -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit
        ),
        [Security.AccessControl.PropagationFlags]::None,
        (
            [Security.AccessControl.AuditFlags]::Success `
            -bor [Security.AccessControl.AuditFlags]::Failure
        )
    )
}

function Add-WarSocAuditRule {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][Security.AccessControl.FileSystemRights]$Rights
    )

    if ([int64]$Rights -eq 0) {
        return
    }
    $rule = New-WarSocAuditRule -Rights $Rights
    $acl = Get-Acl -LiteralPath $Path -Audit
    $acl.AddAuditRule($rule)
    Set-Acl -LiteralPath $Path -AclObject $acl

    $remaining = Get-MissingWarSocAuditRights -Path $Path
    if ([int64]$remaining -ne 0) {
        throw "SACL verification failed for $Path"
    }
}

function Remove-WarSocAuditRule {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][Security.AccessControl.FileSystemRights]$Rights
    )

    if ([int64]$Rights -eq 0) {
        return
    }
    $rule = New-WarSocAuditRule -Rights $Rights
    $acl = Get-Acl -LiteralPath $Path -Audit
    [void]$acl.RemoveAuditRule($rule)
    Set-Acl -LiteralPath $Path -AclObject $acl
}

function Test-AuditStateMatches {
    param(
        [Parameter(Mandatory = $true)]$State,
        [Parameter(Mandatory = $true)][bool]$Success,
        [Parameter(Mandatory = $true)][bool]$Failure
    )

    return (
        ([bool]$State.success -eq $Success) -and
        ([bool]$State.failure -eq $Failure)
    )
}

function Write-Evidence {
    param(
        [string]$Status,
        [array]$Paths,
        [string]$Detail = ""
    )

    $record = [ordered]@{
        timestamp_utc = (Get-Date).ToUniversalTime().ToString("o")
        script_version = $ScriptVersion
        telemetry_config_version = "native-windows-v1"
        status = $Status
        pos_path_count = @($Paths).Count
        detail = $Detail
    }
    $record | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $EvidencePath -Encoding UTF8
}

function Install-NativeTelemetry {
    Ensure-StateDirectory
    if ($IsWindowsServer -and -not [string]::IsNullOrWhiteSpace($PosPaths)) {
        throw "POS paths require the separately qualified POS/database-host profile and cannot be enabled on General Server V1."
    }
    $paths = Get-NormalizedPosPaths -RawPaths $PosPaths

    $existingState = $null
    $existingStateJson = $null
    if (Test-Path -LiteralPath $StatePath) {
        try {
            $existingStateJson = Get-Content -LiteralPath $StatePath -Raw
            $existingState = $existingStateJson | ConvertFrom-Json
        } catch {
            throw "Existing WarSOC telemetry state is unreadable; refusing to overwrite the rollback baseline."
        }
    }
    $script:InstallHadExistingState = ($null -ne $existingState)
    # Preserve an existing installation exactly. Fresh server installations do
    # not enable File System/Registry categories that belong to later profiles.
    $auditControlsForInstall = @($AuditControls)
    if ($IsWindowsServer -and $null -eq $existingState) {
        $auditControlsForInstall = @(
            $AuditControls | Where-Object { $GeneralServerExcludedAuditIds -notcontains [string]$_.Id }
        )
    }

    $previousRegistry = Get-ItemProperty -Path $AuditRegistryPath -Name $AuditRegistryName -ErrorAction SilentlyContinue
    $runAuditStates = @()
    if ($null -ne $existingState) {
        $processBaseline = [ordered]@{
            existed = [bool]$existingState.process_command_line.existed
            value = $existingState.process_command_line.value
        }
        if ($null -eq $previousRegistry -or [int]$previousRegistry.$AuditRegistryName -ne 1) {
            $processBaseline = [ordered]@{
                existed = ($null -ne $previousRegistry)
                value = if ($null -ne $previousRegistry) { [int]$previousRegistry.$AuditRegistryName } else { $null }
            }
        }
    } else {
        $processBaseline = [ordered]@{
            existed = ($null -ne $previousRegistry)
            value = if ($null -ne $previousRegistry) { [int]$previousRegistry.$AuditRegistryName } else { $null }
        }
    }
    $state = [ordered]@{
        script_version = $ScriptVersion
        created_at = if ($null -ne $existingState) {
            [string]$existingState.created_at
        } else {
            (Get-Date).ToUniversalTime().ToString("o")
        }
        audit_controls = @()
        process_command_line = $processBaseline
        pos_paths = @()
    }

    foreach ($control in $auditControlsForInstall) {
        $currentControl = Get-AuditControlState -Name $control.Name -Id $control.Id
        $runAuditStates += $currentControl
        $savedControl = $null
        if ($null -ne $existingState) {
            $savedControl = $existingState.audit_controls |
                Where-Object { [string]$_.name -eq [string]$control.Name } |
                Select-Object -First 1
        }
        if ($null -eq $savedControl) {
            $savedControl = $currentControl
        }
        $baselineSuccess = [bool]$savedControl.success
        $baselineFailure = [bool]$savedControl.failure
        if (
            $null -ne $savedControl.PSObject.Properties["configured_success"] -and
            ([bool]$currentControl.success -ne [bool]$savedControl.configured_success)
        ) {
            $baselineSuccess = [bool]$currentControl.success
        }
        if (
            $null -ne $savedControl.PSObject.Properties["configured_failure"] -and
            ([bool]$currentControl.failure -ne [bool]$savedControl.configured_failure)
        ) {
            $baselineFailure = [bool]$currentControl.failure
        }
        $state.audit_controls += [ordered]@{
            name = [string]$control.Name
            id = [string]$control.Id
            success = $baselineSuccess
            failure = $baselineFailure
            raw = [string]$savedControl.raw
            configured_success = ([bool]$currentControl.success -or [bool]$control.Success)
            configured_failure = ([bool]$currentControl.failure -or [bool]$control.Failure)
        }
    }

    if ($null -ne $existingState) {
        foreach ($savedPath in @($existingState.pos_paths)) {
            if (-not [string]::IsNullOrWhiteSpace([string]$savedPath.path)) {
                $savedAddedRights = 0
                if ($null -ne $savedPath.PSObject.Properties["added_rights"]) {
                    $savedAddedRights = [int64]$savedPath.added_rights
                }
                $state.pos_paths += [ordered]@{
                    path = [string]$savedPath.path
                    added_rights = $savedAddedRights
                }
            }
        }
    }

    $rulesToAdd = @()
    foreach ($path in $paths) {
        $missingRights = [int64](Get-MissingWarSocAuditRights -Path $path)
        $savedPath = $state.pos_paths |
            Where-Object { [string]$_.path -ieq [string]$path } |
            Select-Object -First 1
        if ($null -eq $savedPath) {
            $savedPath = [ordered]@{
                path = $path
                added_rights = $missingRights
            }
            $state.pos_paths += $savedPath
        } else {
            $savedPath["added_rights"] = ([int64]$savedPath.added_rights) -bor $missingRights
        }
        $rulesToAdd += [ordered]@{
            path = $path
            rights = $missingRights
        }
    }

    $state | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $StatePath -Encoding UTF8

    try {
        foreach ($control in $state.audit_controls) {
            Set-AuditControlState `
                -Name ([string]$control.name) `
                -Id ([string]$control.id) `
                -Success ([bool]$control.configured_success) `
                -Failure ([bool]$control.configured_failure)
            $verified = Get-AuditControlState -Name ([string]$control.name) -Id ([string]$control.id)
            if ([bool]$control.configured_success -and -not $verified.success) {
                throw "Success auditing verification failed for '$($control.name)'"
            }
            if ([bool]$control.configured_failure -and -not $verified.failure) {
                throw "Failure auditing verification failed for '$($control.name)'"
            }
        }

        if (-not (Test-Path -LiteralPath $AuditRegistryPath)) {
            New-Item -Path $AuditRegistryPath -Force | Out-Null
        }
        New-ItemProperty -Path $AuditRegistryPath -Name $AuditRegistryName -Value 1 -PropertyType DWord -Force | Out-Null
        $verifiedRegistry = Get-ItemPropertyValue -Path $AuditRegistryPath -Name $AuditRegistryName
        if ([int]$verifiedRegistry -ne 1) {
            throw "Process command-line auditing registry verification failed."
        }

        foreach ($entry in $rulesToAdd) {
            Add-WarSocAuditRule `
                -Path ([string]$entry.path) `
                -Rights ([Security.AccessControl.FileSystemRights][int64]$entry.rights)
        }

        Write-Evidence -Status "configured" -Paths $paths
    } catch {
        if ($null -ne $existingState) {
            foreach ($entry in $rulesToAdd) {
                try {
                    Remove-WarSocAuditRule `
                        -Path ([string]$entry.path) `
                        -Rights ([Security.AccessControl.FileSystemRights][int64]$entry.rights)
                } catch {
                }
            }
            foreach ($before in $runAuditStates) {
                try {
                    $target = $state.audit_controls |
                        Where-Object { [string]$_.id -eq [string]$before.id } |
                        Select-Object -First 1
                    $current = Get-AuditControlState -Name ([string]$before.name) -Id ([string]$before.id)
                    if (
                        $null -ne $target -and
                        (Test-AuditStateMatches `
                            -State $current `
                            -Success ([bool]$target.configured_success) `
                            -Failure ([bool]$target.configured_failure))
                    ) {
                        Set-AuditControlState `
                            -Name ([string]$before.name) `
                            -Id ([string]$before.id) `
                            -Success ([bool]$before.success) `
                            -Failure ([bool]$before.failure)
                    }
                } catch {
                }
            }
            try {
                $currentRegistry = Get-ItemProperty -Path $AuditRegistryPath -Name $AuditRegistryName -ErrorAction SilentlyContinue
                if ($null -ne $currentRegistry -and [int]$currentRegistry.$AuditRegistryName -eq 1) {
                    if ($null -ne $previousRegistry) {
                        New-ItemProperty -Path $AuditRegistryPath -Name $AuditRegistryName `
                            -Value ([int]$previousRegistry.$AuditRegistryName) -PropertyType DWord -Force | Out-Null
                    } else {
                        Remove-ItemProperty -Path $AuditRegistryPath -Name $AuditRegistryName -ErrorAction SilentlyContinue
                    }
                }
            } catch {
            }
            $existingStateJson | Set-Content -LiteralPath $StatePath -Encoding UTF8
        }
        throw
    }
}

function Restore-NativeTelemetry {
    Ensure-StateDirectory
    if (-not (Test-Path -LiteralPath $StatePath)) {
        Write-Evidence -Status "rollback_skipped" -Paths @() -Detail "No saved state was found."
        return
    }

    $state = Get-Content -LiteralPath $StatePath -Raw | ConvertFrom-Json
    foreach ($control in $state.audit_controls) {
        if (
            $null -eq $control.PSObject.Properties["id"] -or
            $null -eq $control.PSObject.Properties["configured_success"] -or
            $null -eq $control.PSObject.Properties["configured_failure"]
        ) {
            continue
        }

        $current = Get-AuditControlState -Name ([string]$control.name) -Id ([string]$control.id)
        if (Test-AuditStateMatches `
            -State $current `
            -Success ([bool]$control.configured_success) `
            -Failure ([bool]$control.configured_failure)
        ) {
            Set-AuditControlState `
                -Name ([string]$control.name) `
                -Id ([string]$control.id) `
                -Success ([bool]$control.success) `
                -Failure ([bool]$control.failure)
        }
    }

    $currentRegistry = Get-ItemProperty -Path $AuditRegistryPath -Name $AuditRegistryName -ErrorAction SilentlyContinue
    if ($null -ne $currentRegistry -and [int]$currentRegistry.$AuditRegistryName -eq 1) {
        if ([bool]$state.process_command_line.existed) {
            New-ItemProperty -Path $AuditRegistryPath -Name $AuditRegistryName `
                -Value ([int]$state.process_command_line.value) -PropertyType DWord -Force | Out-Null
        } else {
            Remove-ItemProperty -Path $AuditRegistryPath -Name $AuditRegistryName -ErrorAction SilentlyContinue
        }
    }

    foreach ($entry in $state.pos_paths) {
        if (
            (Test-Path -LiteralPath ([string]$entry.path)) -and
            ($null -ne $entry.PSObject.Properties["added_rights"])
        ) {
            Remove-WarSocAuditRule `
                -Path ([string]$entry.path) `
                -Rights ([Security.AccessControl.FileSystemRights][int64]$entry.added_rights)
        }
    }

    Write-Evidence -Status "rolled_back" -Paths @($state.pos_paths)
    Remove-Item -LiteralPath $StatePath -Force
}

if (-not (Test-IsAdministrator)) {
    Write-Error "WarSOC native telemetry configuration requires Administrator privileges."
    exit 10
}

try {
    if ($Rollback) {
        Restore-NativeTelemetry
    } else {
        Install-NativeTelemetry
    }
    exit 0
} catch {
    $originalError = $_.Exception.Message
    if (
        -not $Rollback -and
        -not $InstallHadExistingState -and
        (Test-Path -LiteralPath $StatePath)
    ) {
        try {
            Restore-NativeTelemetry
        } catch {
        }
    }
    try {
        Ensure-StateDirectory
        Write-Evidence -Status "failed" -Paths @() -Detail $originalError
    } catch {
    }
    Write-Error $originalError
    exit 20
}
