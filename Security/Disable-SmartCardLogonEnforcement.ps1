#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Disables smart card logon enforcement on Windows devices.

.DESCRIPTION
    This script disables smart card logon enforcement by modifying registry keys that control
    smart card authentication behavior. It sets registry values to allow password-based logon
    and disables automatic lock on smart card removal. The script also disables the Smart Card
    Policy Service.

    This is also the way back from Enable-SmartCardLogonEnforcement.ps1 on a device that can
    still check in to Intune.

    Every registry write uses -ErrorAction Stop and is read back after it is written. If any write
    or read-back fails the script exits 1. The log file is always kept.

.PARAMETER KeepLogs
    Retained so existing callers keep working. It has no effect: the log file is always kept now,
    because this script changes a security setting and should leave an audit trail.

.EXAMPLE
    .\Disable-SmartCardLogonEnforcement.ps1

.EXAMPLE
    .\Disable-SmartCardLogonEnforcement.ps1 -WhatIf

.NOTES
    Requires: Administrator privileges
    Modifies: HKLM registry keys, SCPolicySvc startup type
    Log: %ProgramData%\Microsoft\IntuneManagementExtension\Logs\win32-Disable_SmartCardLogon_Enforcement.log
    Exit Codes:
    - 0: All changes applied and verified, or a -WhatIf run
    - 1: A change failed or verification failed
#>

[CmdletBinding(SupportsShouldProcess=$true)]
param(
    [Parameter(Mandatory=$false)]
    [switch]$KeepLogs
)

# Build the argument list used to relaunch this script in 64-bit PowerShell.
# Every switch that was passed (-WhatIf, -Verbose, -KeepLogs) is forwarded, so the child
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
$AppName = "Disable_SmartCardLogon_Enforcement"
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

# Start logging
Write-ScriptLog "Begin..."
Write-ScriptLog $SectionLine
if ($KeepLogs) {
    Write-ScriptLog "-KeepLogs was given. It has no effect: the log file is always kept."
}

$failures = @()

# Section 1: allow password logon
try {
    # 0 = allow password logon, 1 = require smart card
    Set-RegistryDwordVerified -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'scforceoption' -Value 0 -Description 'Set value to 0 (allow password logon)'
}
catch {
    $failures += "scforceoption: $($_.Exception.Message)"
    Write-ScriptLog "Error: scforceoption: $($_.Exception.Message)"
}

# Section 2: do not lock the workstation when the smart card is removed
try {
    # 0 = do nothing, 1 = lock workstation
    Set-RegistryDwordVerified -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name 'ScRemoveOption' -Value 0 -Description 'Set value to 0 (do not lock on smart card removal)'
}
catch {
    $failures += "ScRemoveOption: $($_.Exception.Message)"
    Write-ScriptLog "Error: ScRemoveOption: $($_.Exception.Message)"
}

# Section 3: Smart Card Policy Service startup type
try {
    $serviceKey = 'HKLM:\SYSTEM\CurrentControlSet\Services\SCPolicySvc'
    if (-not (Test-Path -LiteralPath $serviceKey)) {
        # Nothing to disable. Do not create a bare service key: that leaves a phantom service entry.
        Write-ScriptLog "Service key $serviceKey does not exist, so there is no service to disable. Skipped."
    }
    else {
        # Service startup types: 0=Boot, 1=System, 2=Auto, 3=Manual, 4=Disabled
        Set-RegistryDwordVerified -Path $serviceKey -Name 'Start' -Value 4 -Description 'Set Start value to 4 (Disabled) for SCPolicySvc'

        if ($PSCmdlet.ShouldProcess('SCPolicySvc', 'Set service startup type to Disabled')) {
            Set-Service -Name 'SCPolicySvc' -StartupType Disabled -ErrorAction Stop
            $startType = (Get-Service -Name 'SCPolicySvc' -ErrorAction Stop).StartType
            if ("$startType" -ne 'Disabled') {
                throw "SCPolicySvc startup type reads '$startType' after Set-Service, expected Disabled."
            }
            Write-ScriptLog "Service startup type set to Disabled and verified"
        }
    }
}
catch {
    $failures += "SCPolicySvc: $($_.Exception.Message)"
    Write-ScriptLog "Error: SCPolicySvc: $($_.Exception.Message)"
}

# The log file is kept on purpose: it is the audit trail for a security setting change.
if ($WhatIfPreference) {
    Write-Host "WhatIf: no changes were made."
    exit 0
}

if ($failures.Count -gt 0) {
    Write-ScriptLog "Script finished with $($failures.Count) failure(s): $($failures -join ' | ')"
    Write-Error "Smart card enforcement was NOT fully removed: $($failures -join ' | ')"
    exit 1
}

Write-ScriptLog "Script completed successfully. All changes were applied and verified."
exit 0
