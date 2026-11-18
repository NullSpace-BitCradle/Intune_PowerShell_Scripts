<#
.SYNOPSIS
    Detection script for Office update channel and version verification.

.DESCRIPTION
    This script verifies if Microsoft Office is using the Semi-Annual update channel
    and is on the latest version. It reads the local Office configuration from the registry
    and compares it with the latest available version from Microsoft's cloud service.

    It is the detection half of an Intune Remediation (proactive remediation) and follows that
    contract: exit 0 means no remediation is needed, exit 1 means the remediation script should run.
    Four outcomes are kept apart:
    - Compliant: Semi-Annual channel and latest version. Exit 0.
    - Not applicable: Office Click-to-Run is not installed. Exit 0, so the device is not
      sent to a remediation that cannot succeed.
    - Cannot determine: the registry or Microsoft's release service could not be read. Exit 0
      with a message, so a missing network does not trigger remediation on every cycle.
    - Non-compliant: wrong channel or an older build. Exit 1.

    Run the script in 64-bit PowerShell. If it is started in a 32-bit host on a 64-bit system it
    relaunches itself in 64-bit PowerShell.

.EXAMPLE
    .\Detect-OfficeUpdateChannel.ps1

.NOTES
    Intune Remediations contract: set "Run script in 64-bit PowerShell" to Yes.
    Exit Codes:
    - 0: Compliant, not applicable, or cannot determine (see the message)
    - 1: Office is not on the Semi-Annual channel or not on the latest version
#>

[CmdletBinding()]
param()

# Build the argument list used to relaunch this script in 64-bit PowerShell.
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

# Function to invoke Office API with retry logic
# Handles transient failures (429, 503, etc.) with exponential backoff
function Invoke-OfficeApiWithRetry {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$Uri,

        [Parameter(Mandatory=$false)]
        [int]$MaxRetries = 3,

        [Parameter(Mandatory=$false)]
        [int]$InitialDelaySeconds = 2
    )

    $retryCount = 0
    $delaySeconds = $InitialDelaySeconds

    while ($retryCount -le $MaxRetries) {
        try {
            $response = Invoke-RestMethod -Uri $Uri -ErrorAction Stop
            return $response
        }
        catch {
            $statusCode = $null
            if ($_.Exception.Response) { $statusCode = [int]$_.Exception.Response.StatusCode }

            # Retryable: 429 Too Many Requests, 502 Bad Gateway, 503 Service Unavailable, 504 Gateway Timeout
            if ($statusCode -in @(429, 502, 503, 504) -and $retryCount -lt $MaxRetries) {
                $retryCount++
                Write-Verbose "Office API call failed with status $statusCode. Retrying in $delaySeconds seconds (attempt $retryCount of $MaxRetries)..."
                Start-Sleep -Seconds $delaySeconds
                $delaySeconds = $delaySeconds * 2
            }
            else {
                throw
            }
        }
    }
}

# Architecture check: if running as a 32-bit process on a 64-bit system, relaunch as 64-bit.
# Intune Remediations run in 32-bit PowerShell unless told otherwise, and a 32-bit host can be
# redirected to WOW6432Node when it reads HKLM\SOFTWARE.
if ($env:PROCESSOR_ARCHITEW6432 -and $env:PROCESSOR_ARCHITEW6432 -ne "ARM64")
{
    $sysNativePowerShell = "$($env:WINDIR)\SysNative\WindowsPowerShell\v1.0\powershell.exe"
    if (Test-Path $sysNativePowerShell)
    {
        $relaunchArguments = Get-RelaunchArgumentList -ScriptPath $PSCommandPath -BoundParameters $PSBoundParameters
        & $sysNativePowerShell @relaunchArguments
        exit $LASTEXITCODE
    }
}

$officeConfigPath = "HKLM:\SOFTWARE\Microsoft\Office\ClickToRun\Configuration"

# Main script execution wrapped in try-catch for error handling
try
{
    # No Click-to-Run means there is no channel to check. Not applicable, so do not trigger remediation.
    if (-not (Test-Path -Path $officeConfigPath)) {
        Write-Output "Not applicable: Office Click-to-Run is not installed."
        exit 0
    }

    # Read the currently installed Office version and the CDN base URL (which identifies the channel)
    $ReportedVersion = Get-ItemPropertyValue -Path $officeConfigPath -Name "VersionToReport" -ErrorAction Stop
    $Channel = Get-ItemPropertyValue -Path $officeConfigPath -Name "CDNBaseUrl" -ErrorAction Stop | Select-Object -Last 1

    # Query Microsoft's Office release information service to get the latest available versions
    $CloudVersionInfo = Invoke-OfficeApiWithRetry -Uri 'https://clients.config.office.net/releases/v1.0/OfficeReleases'

    # Find the channel that matches the local CDN URL
    $UsedChannel = @($CloudVersionInfo | Where-Object { $_.OfficeVersions.cdnBaseUrl -contains $Channel }) | Select-Object -First 1

    if ($null -eq $UsedChannel) {
        # The local CDN URL is not one Microsoft lists, which is itself a wrong configuration for this policy
        Write-Output "Non-compliant: the configured update channel ($Channel) is not a Microsoft-listed channel."
        exit 1
    }

    $onSemiAnnual = ($UsedChannel.channelId -eq "SemiAnnual")
    $onLatest = ($UsedChannel.latestversion -eq $ReportedVersion)

    if ($onSemiAnnual -and $onLatest) {
        Write-Output "Compliant: using the latest version of Office in the $($UsedChannel.channelId) Channel: $ReportedVersion"
        exit 0
    }
    elseif (-not $onSemiAnnual) {
        Write-Output "Non-compliant: not using the Semi-Annual channel. Detected channel is the $($UsedChannel.channelId) Channel."
        exit 1
    }
    else {
        Write-Output "Non-compliant: on the Semi-Annual channel but behind. Installed $ReportedVersion, latest $($UsedChannel.latestversion)."
        exit 1
    }
}
# Error handling block - catches exceptions during registry reads or API calls
catch
{
    # The state could not be read. That is not evidence of non-compliance, and exiting 1 would send
    # every device without network access to a remediation that also needs the network.
    $errMsg = $_.Exception.Message
    Write-Output "Cannot determine: $errMsg"
    if ($PSBoundParameters.ContainsKey('Verbose')) {
        Write-Verbose "Stack Trace: $($_.ScriptStackTrace)"
        if ($_.Exception.InnerException) {
            Write-Verbose "Inner Exception: $($_.Exception.InnerException.Message)"
        }
    }
    exit 0
}
