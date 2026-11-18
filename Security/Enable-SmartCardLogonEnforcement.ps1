#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Enables smart card logon enforcement on Windows devices.

.DESCRIPTION
    This script enables smart card logon enforcement by modifying registry keys that control
    smart card authentication behavior. It sets registry values to require smart card for
    interactive logon and enables automatic lock on smart card removal. The script also enables
    the Smart Card Policy Service.

    WARNING: "Interactive logon: Require smart card" (scforceoption = 1) blocks password logon
    for EVERY account on the device, including the local administrator. A device that has no
    smart card reader, no card or no certificate-based logon set up can be locked out for good.

    To prevent that, the script runs a preflight check before it writes anything. It refuses to
    continue (exit 1, nothing changed) unless the Smart Card Policy Service exists and at least one
    smart card reader is present and healthy. The check cannot prove that a user has a card or a
    logon certificate, so confirm that separately. Use -Force only for a deliberate, supervised run
    where you accept the lockout risk.

    Every registry write uses -ErrorAction Stop and is read back after it is written. If any write
    or read-back fails the script exits 1. The log file is always kept.

    Recovery if a device is locked out: boot to Windows Recovery, load the device's
    SOFTWARE hive in regedit and set
    HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\scforceoption to 0, or push
    Disable-SmartCardLogonEnforcement.ps1 through Intune to a device that can still check in.

.PARAMETER KeepLogs
    Retained so existing callers keep working. It has no effect: the log file is always kept now,
    because this script changes a security setting and should leave an audit trail.

.PARAMETER Force
    Skips the smart card reader preflight check. Lockout risk applies.

.EXAMPLE
    .\Enable-SmartCardLogonEnforcement.ps1

.EXAMPLE
    .\Enable-SmartCardLogonEnforcement.ps1 -WhatIf

.EXAMPLE
    .\Enable-SmartCardLogonEnforcement.ps1 -Force

.NOTES
    Requires: Administrator privileges
    Modifies: HKLM registry keys, SCPolicySvc startup type
    Log: %ProgramData%\Microsoft\IntuneManagementExtension\Logs\win32-Enable_SmartCardLogon_Enforcement.log
    Exit Codes:
    - 0: All changes applied and verified, or a -WhatIf run
    - 1: Preflight refused, a change failed, or verification failed
#>

[CmdletBinding(SupportsShouldProcess=$true)]
param(
    [Parameter(Mandatory=$false)]
    [switch]$KeepLogs,

    [Parameter(Mandatory=$false)]
    [switch]$Force
)

# Build the argument list used to relaunch this script in 64-bit PowerShell.
# Every switch that was passed (-WhatIf, -Verbose, -KeepLogs, -Force) is forwarded, so the child
# does what the caller asked. Dropping -WhatIf here would make the 64-bit child change the machine.
function Get-RelaunchArgumentList {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$ScriptPath,

        [Parameter(Mandatory=$false)]
        [hashtable]$BoundParameters = @{}
    )

    $arguments = @('-ExecutionPolicy', 'Bypass', '-NoProfile', '-File', $ScriptPath)
    foreach ($key in $BoundParameters.Keys) {
        $value = $BoundParameters[$key]
        if ($value -is [System.Management.Automation.SwitchParameter]) {
            if ($value.IsPresent) { $arguments += "-$key" }
        }
    }
    return $arguments
}

# Architecture check: if running as a 32-bit process on a 64-bit system, relaunch as 64-bit
# so registry writes go to the 64-bit hive. PROCESSOR_ARCHITEW6432 is set for 32-bit processes on 64-bit Windows.
if ($env:PROCESSOR_ARCHITEW6432 -and $env:PROCESSOR_ARCHITEW6432 -ne "ARM64")
{
    # SysNative lets a 32-bit process reach the 64-bit system files
    $sysNativePowerShell = "$($env:WINDIR)\SysNative\WindowsPowerShell\v1.0\powershell.exe"
    if (Test-Path $sysNativePowerShell)
    {
        $relaunchArguments = Get-RelaunchArgumentList -ScriptPath $PSCommandPath -BoundParameters $PSBoundParameters
        & $sysNativePowerShell @relaunchArguments
        exit $LASTEXITCODE
    }
}

# Logging Preparation Section
$AppName = "Enable_SmartCardLogon_Enforcement"
$Log_FileName = "win32-$AppName.log"
$Log_Path = Join-Path $env:ProgramData "Microsoft\IntuneManagementExtension\Logs"
$TestPath = Join-Path $Log_Path $Log_FileName
$SectionLine = "* * " * 10

# Write a timestamped message to the log file and to the console.
# Under -WhatIf nothing is written to disk, so a dry run leaves no files behind.
function Write-ScriptLog {
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$Message
    )
    $timestamp = Get-Date -Format "dddd MM/dd/yyyy HH:mm:ss"
    if ($WhatIfPreference) {
        Write-Host "[log] $Message"
        return
    }
    try {
        if (-not (Test-Path -Path $Log_Path)) {
            New-Item -Path $Log_Path -ItemType Directory -Force -ErrorAction Stop | Out-Null
        }
        Add-Content -Path $TestPath -Value "$timestamp : $Message" -ErrorAction Stop
    }
    catch {
        Write-Warning "Could not write to log file ${TestPath}: $($_.Exception.Message)"
    }
}

# Set one DWORD registry value and read it back. Throws if the write or the read-back fails.
# Creates the key only when it is missing, and only when the change is confirmed (-WhatIf creates nothing).
function Set-RegistryDwordVerified {
    [CmdletBinding(SupportsShouldProcess=$true)]
    param(
        [Parameter(Mandatory=$true)]
        [string]$Path,

        [Parameter(Mandatory=$true)]
        [string]$Name,

        [Parameter(Mandatory=$true)]
        [int]$Value,

        [Parameter(Mandatory=$true)]
        [string]$Description
    )

    if (-not $PSCmdlet.ShouldProcess("$Path\$Name", $Description)) {
        return
    }

    if (-not (Test-Path -LiteralPath $Path)) {
        Write-ScriptLog "Reg path $Path not found, creating it"
        New-Item -Path $Path -Force -ErrorAction Stop | Out-Null
    }

    Write-ScriptLog "Setting $Path\$Name to $Value"
    New-ItemProperty -LiteralPath $Path -Name $Name -Value $Value -PropertyType DWord -Force -ErrorAction Stop | Out-Null

    $actual = (Get-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction Stop).$Name
    if ($actual -ne $Value) {
        throw "Verification failed for $Path\$Name. Expected $Value, read back '$actual'."
    }
    Write-ScriptLog "Verified $Path\$Name = $actual"
}

# Preflight for the Enable script: is there any chance a user can still log on after enforcement?
# Returns an object with Ready and a list of Reasons it is not. It cannot see cards or logon
# certificates, only that the platform pieces exist.
function Test-SmartCardLogonReady {
    [CmdletBinding()]
    param()

    $reasons = @()

    if (-not (Test-Path -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Services\SCPolicySvc')) {
        $reasons += "The Smart Card Policy Service (SCPolicySvc) is not installed."
    }

    $readers = @()
    try {
        $readers = @(Get-CimInstance -ClassName Win32_PnPEntity -Filter "PNPClass='SmartCardReader'" -ErrorAction Stop |
            Where-Object { $_.Status -eq 'OK' })
    }
    catch {
        $reasons += "Could not enumerate smart card readers: $($_.Exception.Message)"
    }
    if ($readers.Count -eq 0) {
        $reasons += "No working smart card reader was found."
    }

    [PSCustomObject]@{
        Ready   = ($reasons.Count -eq 0)
        Reasons = $reasons
        Readers = @($readers | ForEach-Object { $_.Name })
    }
}

# Start logging
Write-ScriptLog "Begin..."
Write-ScriptLog $SectionLine
if ($KeepLogs) {
    Write-ScriptLog "-KeepLogs was given. It has no effect: the log file is always kept."
}

$failures = @()

# Preflight: refuse before any change if the device could be locked out
$preflight = Test-SmartCardLogonReady
if ($preflight.Ready) {
    Write-ScriptLog "Preflight passed. Smart card reader(s): $($preflight.Readers -join ', ')"
}
elseif ($Force) {
    Write-ScriptLog "Preflight failed but -Force was given, continuing: $($preflight.Reasons -join ' ')"
    Write-Warning "Preflight failed but -Force was given. Lockout risk applies: $($preflight.Reasons -join ' ')"
}
else {
    $why = $preflight.Reasons -join ' '
    Write-ScriptLog "Preflight refused. $why No changes were made."
    if ($WhatIfPreference) {
        Write-Host "WhatIf: a real run would refuse and exit 1. $why"
        exit 0
    }
    Write-Error "Refusing to require smart card logon: $why Enforcing it on a device with no working reader can lock every user out, including the local administrator. Fix the above or use -Force on a supervised run."
    exit 1
}

# Step 1: lock the workstation when the smart card is removed
try {
    # 0 = do nothing, 1 = lock workstation
    Set-RegistryDwordVerified -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name 'ScRemoveOption' -Value 1 -Description 'Set value to 1 (lock workstation on smart card removal)'
}
catch {
    $failures += "ScRemoveOption: $($_.Exception.Message)"
    Write-ScriptLog "Error: ScRemoveOption: $($_.Exception.Message)"
}

# Step 2: Smart Card Policy Service startup type
try {
    $serviceKey = 'HKLM:\SYSTEM\CurrentControlSet\Services\SCPolicySvc'
    if (-not (Test-Path -LiteralPath $serviceKey)) {
        # Do not create a bare service key: that leaves a phantom service entry with only a Start value.
        throw "Service key $serviceKey does not exist, so SCPolicySvc cannot be enabled. Nothing was created."
    }

    # Service startup types: 0=Boot, 1=System, 2=Auto, 3=Manual, 4=Disabled
    Set-RegistryDwordVerified -Path $serviceKey -Name 'Start' -Value 2 -Description 'Set Start value to 2 (Automatic) for SCPolicySvc'

    if ($PSCmdlet.ShouldProcess('SCPolicySvc', 'Set service startup type to Automatic')) {
        Set-Service -Name 'SCPolicySvc' -StartupType Automatic -ErrorAction Stop
        $startType = (Get-Service -Name 'SCPolicySvc' -ErrorAction Stop).StartType
        if ("$startType" -ne 'Automatic') {
            throw "SCPolicySvc startup type reads '$startType' after Set-Service, expected Automatic."
        }
        Write-ScriptLog "Service startup type set to Automatic and verified"
    }
}
catch {
    $failures += "SCPolicySvc: $($_.Exception.Message)"
    Write-ScriptLog "Error: SCPolicySvc: $($_.Exception.Message)"
}

# Step 3, LAST: require a smart card for interactive logon.
# This is the setting that blocks password logon, so it is written only after every other step succeeded.
# If any earlier step failed it is not written at all. If its own write or read-back fails, the value that was
# there before is put back, so a half-applied run never leaves the device requiring a card.
if ($failures.Count -gt 0) {
    Write-ScriptLog "Not enforcing smart card logon because an earlier step failed: $($failures -join ' | ')"
}
else {
    $enforceKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    $previousEnforce = $null
    if (-not $WhatIfPreference) {
        $existing = Get-ItemProperty -LiteralPath $enforceKey -Name 'scforceoption' -ErrorAction SilentlyContinue
        if ($existing -and $existing.PSObject.Properties['scforceoption']) { $previousEnforce = $existing.scforceoption }
    }
    try {
        # 0 = allow password logon, 1 = require smart card
        Set-RegistryDwordVerified -Path $enforceKey -Name 'scforceoption' -Value 1 -Description 'Set value to 1 (require smart card for interactive logon)'
    }
    catch {
        $failures += "scforceoption: $($_.Exception.Message)"
        Write-ScriptLog "Error: scforceoption: $($_.Exception.Message)"
        # Roll back to the previous value, or to 0 (the Windows default, password logon allowed) if there was none
        $restore = if ($null -ne $previousEnforce) { [int]$previousEnforce } else { 0 }
        try {
            New-ItemProperty -LiteralPath $enforceKey -Name 'scforceoption' -Value $restore -PropertyType DWord -Force -ErrorAction Stop | Out-Null
            Write-ScriptLog "Rolled scforceoption back to $restore"
        }
        catch {
            $failures += "scforceoption rollback: $($_.Exception.Message)"
            Write-ScriptLog "ERROR: could not roll scforceoption back to $restore : $($_.Exception.Message)"
        }
    }
}

# The log file is kept on purpose: it is the audit trail for a security setting change.
if ($WhatIfPreference) {
    Write-Host "WhatIf: no changes were made."
    exit 0
}

if ($failures.Count -gt 0) {
    Write-ScriptLog "Script finished with $($failures.Count) failure(s): $($failures -join ' | ')"
    Write-Error "Smart card enforcement was NOT fully applied: $($failures -join ' | ')"
    exit 1
}

Write-ScriptLog "Script completed successfully. All changes were applied and verified."
exit 0
