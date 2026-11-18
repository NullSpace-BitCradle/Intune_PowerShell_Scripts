#Requires -Version 5.1
#Requires -PSEdition Desktop

<#
.SYNOPSIS
    Starts an MDM sync session using Windows Management APIs.

.DESCRIPTION
    This script creates an MDM (Mobile Device Management) sync session and waits for it to complete.
    It uses the Windows.Management.MdmSessionManager API to trigger a sync between the device
    and the MDM service (e.g., Microsoft Intune). The script waits up to the specified timeout
    for the sync to complete and provides status updates during the process.

    The WinRT type this script uses can only be loaded by Windows PowerShell 5.1. PowerShell 7 cannot
    load it, so the script requires the Desktop edition and says so, instead of failing on the type load.

    A session that reaches Completed with an extended error code is reported as a failure.
    The session's own ExtendedError is read; the states are NotStarted, Starting, Connecting,
    Communicating, AlertStatusAvailable, Retrying and Completed.

.PARAMETER TimeoutSeconds
    Optional. Maximum time in seconds to wait for sync to complete. Default is 60 seconds.

.PARAMETER CheckIntervalSeconds
    Optional. Interval in seconds between status checks. Default is 5 seconds.

.EXAMPLE
    .\Start-MDMSync.ps1

.EXAMPLE
    .\Start-MDMSync.ps1 -TimeoutSeconds 120 -CheckIntervalSeconds 10

.NOTES
    Requires: Windows PowerShell 5.1 (Desktop edition), Windows 10/11 with MDM enrollment
    Exit Codes:
    - 0: Sync completed with no error
    - 1: Sync failed (session could not be created, or it completed with an error) or an error occurred
    - 2: Sync timeout (didn't complete within timeout period)
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [ValidateRange(1, 3600)]
    [int]$TimeoutSeconds = 60,

    [Parameter(Mandatory=$false)]
    [ValidateRange(1, 300)]
    [int]$CheckIntervalSeconds = 5
)

# Create the WinRT MDM session. Kept in a function so a test can replace it.
function New-MdmSession {
    [CmdletBinding()]
    param()

    # Loads the Windows.Management.MdmSessionManager type from the Windows Runtime
    [Windows.Management.MdmSessionManager, Windows.Management, ContentType = WindowsRuntime] | Out-Null
    return [Windows.Management.MdmSessionManager]::TryCreateSession()
}

# Return the session's extended error as text (for example 0x80190190), or $null when there is none.
# ExtendedError is an HRESULT projected as an Exception; S_OK (0) means no error.
function Get-MdmSessionError {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        $Session
    )

    $extended = $Session.ExtendedError
    if ($null -eq $extended) { return $null }

    $hresult = if ($extended -is [System.Exception]) { [int]$extended.HResult } else { [int]$extended }
    if ($hresult -eq 0) { return $null }
    return ('0x{0:X8}' -f $hresult)
}

# Poll the session until it is Completed or the timeout is reached. No early exit on an unchanged
# state: a sync that sits in Connecting is slow, not failed, and the timeout covers it.
# Returns the final state, the extended error text (or $null) and whether the timeout was reached.
function Wait-MdmSession {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        $Session,

        [Parameter(Mandatory=$true)]
        [int]$TimeoutSeconds,

        [Parameter(Mandatory=$true)]
        [int]$CheckIntervalSeconds
    )

    $maxIterations = [math]::Ceiling($TimeoutSeconds / $CheckIntervalSeconds)
    $iteration = 0

    do {
        Start-Sleep -Seconds $CheckIntervalSeconds
        $iteration++
        Write-Host "Waiting for sync to complete... ($($iteration * $CheckIntervalSeconds)/$TimeoutSeconds seconds) - State: $($Session.State)" -ForegroundColor Cyan
    } while (("$($Session.State)" -ne "Completed") -and ($iteration -lt $maxIterations))

    [PSCustomObject]@{
        State    = "$($Session.State)"
        Error    = Get-MdmSessionError -Session $Session
        TimedOut = ("$($Session.State)" -ne "Completed")
    }
}

# Map a wait result to the documented exit code: 0 success, 1 failure, 2 timeout.
function Get-MdmSyncExitCode {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        $Result
    )

    if ($Result.TimedOut) { return 2 }
    if ($Result.Error) { return 1 }
    return 0
}

# Main script execution wrapped in try-catch for error handling
try {
    Write-Host "Attempting to create MDM sync session..." -ForegroundColor Yellow
    $MDMSession = New-MdmSession

    # TryCreateSession returns null when the device is not enrolled or MDM is not configured
    if ($null -eq $MDMSession) {
        Write-Error "Failed to create MDM session. Device may not be enrolled in MDM."
        exit 1
    }

    # StartAsync() initiates the sync but doesn't wait for completion
    Write-Host "MDM session created. Starting sync..." -ForegroundColor Yellow
    $MDMSession.StartAsync() | Out-Null

    $result = Wait-MdmSession -Session $MDMSession -TimeoutSeconds $TimeoutSeconds -CheckIntervalSeconds $CheckIntervalSeconds
    $exitCode = Get-MdmSyncExitCode -Result $result

    switch ($exitCode) {
        0 { Write-Host "MDM sync completed successfully." -ForegroundColor Green }
        1 { Write-Error "MDM sync completed with error $($result.Error) (state: $($result.State))." }
        2 { Write-Warning "MDM sync did not complete within $TimeoutSeconds seconds. Current state: $($result.State)$(if ($result.Error) { ", extended error $($result.Error)" })" }
    }
    exit $exitCode
}
# Error handling block - catches exceptions during session creation or sync process
catch {
    Write-Error "Start-MDMSync: Failed to start MDM sync - $($_.Exception.Message)"
    if ($PSBoundParameters.ContainsKey('Verbose')) {
        Write-Verbose "Stack Trace: $($_.ScriptStackTrace)"
        if ($_.Exception.InnerException) {
            Write-Verbose "Inner Exception: $($_.Exception.InnerException.Message)"
        }
    }
    exit 1
}
