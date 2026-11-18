#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Remediation script for Office update channel configuration.

.DESCRIPTION
    This script configures Microsoft Office to use the Semi-Annual update channel
    and updates it to the latest version. This is the remediation script that pairs
    with Detect-OfficeUpdateChannel.ps1. It should be run when Office is not on
    the Semi-Annual channel or not on the latest version.

    If Office Click-to-Run is not installed, the device is not applicable: the script
    says so and exits 0. Run the script in 64-bit PowerShell. If it is started in a
    32-bit host on a 64-bit system it relaunches itself in 64-bit PowerShell and
    forwards its switches (-WhatIf, -Verbose).

.EXAMPLE
    .\Set-OfficeUpdateChannel.ps1

.EXAMPLE
    .\Set-OfficeUpdateChannel.ps1 -WhatIf

.NOTES
    Requires: Administrator privileges
    Requires: Office Click-to-Run installation (not applicable otherwise)
    Intune Remediations contract: set "Run script in 64-bit PowerShell" to Yes.
    Exit Codes:
    - 0: Remediation successful, already compliant, not applicable (no Click-to-Run), or -WhatIf run
    - 1: Remediation failed or error occurred
#>

[CmdletBinding(SupportsShouldProcess=$true)]
# Define script parameters
param()

# Build the argument list used to relaunch this script in 64-bit PowerShell.
# Switches that were passed (-WhatIf, -Verbose) are forwarded so the 64-bit child behaves the same.
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

# Reduce the Office release data for one channel to a single CDN base URL and a latest version.
# officeVersions is a list and every entry repeats the CDN URL, so member enumeration returns an array.
# Writing that array to the registry is what broke this script before, so insist on exactly one URL.
function Get-ChannelInfo {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        $CloudVersionInfo,

        [Parameter(Mandatory=$true)]
        [string]$ChannelId
    )

    $channel = @($CloudVersionInfo | Where-Object { $_.channelId -eq $ChannelId }) | Select-Object -First 1
    if ($null -eq $channel) {
        throw "Could not find $ChannelId channel information from Microsoft."
    }

    $cdnUrls = @($channel.officeVersions | ForEach-Object { $_.cdnBaseUrl } | Where-Object { $_ } | Sort-Object -Unique)
    if ($cdnUrls.Count -ne 1) {
        throw "Expected exactly one CDN base URL for the $ChannelId channel but found $($cdnUrls.Count)."
    }

    [PSCustomObject]@{
        ChannelId     = $ChannelId
        CdnBaseUrl    = [string]$cdnUrls[0]
        LatestVersion = [string]$channel.latestversion
    }
}

# Find the Click-to-Run updater. OfficeC2RClient.exe lives under Common Files, not under Office16.
function Get-OfficeUpdaterPath {
    [CmdletBinding()]
    param()

    $roots = @($env:CommonProgramW6432, $env:CommonProgramFiles, ${env:CommonProgramFiles(x86)}) | Where-Object { $_ } | Select-Object -Unique
    foreach ($root in $roots) {
        $candidate = Join-Path $root 'Microsoft Shared\ClickToRun\OfficeC2RClient.exe'
        if (Test-Path -Path $candidate) { return $candidate }
    }
    return $null
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

# Main script execution wrapped in try-catch for error handling
try
{
    # Check if running as administrator
    # Office configuration changes require administrator privileges
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) {
        Write-Error "This script requires administrator privileges. Please run as administrator."
        exit 1
    }

    # Check if Office Click-to-Run is installed
    # No Click-to-Run means there is no channel to set, so the device is not applicable
    $officeConfigPath = "HKLM:\SOFTWARE\Microsoft\Office\ClickToRun\Configuration"
    if (-not (Test-Path -Path $officeConfigPath)) {
        Write-Host "Office Click-to-Run is not installed. Not applicable, nothing to remediate."
        exit 0
    }

    Write-Host "Starting Office update channel remediation..." -ForegroundColor Yellow

    # Query Microsoft's Office release information service to get the latest available versions
    Write-Host "Querying Microsoft Office release information..." -ForegroundColor Yellow
    $CloudVersionInfo = Invoke-OfficeApiWithRetry -Uri 'https://clients.config.office.net/releases/v1.0/OfficeReleases'

    # Reduce the Semi-Annual channel data to one CDN URL and one latest version
    $semiAnnual = Get-ChannelInfo -CloudVersionInfo $CloudVersionInfo -ChannelId 'SemiAnnual'
    $semiAnnualCDN = $semiAnnual.CdnBaseUrl
    $latestVersion = $semiAnnual.LatestVersion

    Write-Host "Semi-Annual channel latest version: $latestVersion" -ForegroundColor Cyan
    Write-Host "Semi-Annual channel CDN: $semiAnnualCDN" -ForegroundColor Cyan

    # Read the current Office configuration from the registry
    $currentChannel = Get-ItemPropertyValue -Path $officeConfigPath -Name "CDNBaseUrl" -ErrorAction SilentlyContinue | Select-Object -Last 1

    if ($currentChannel -eq $semiAnnualCDN) {
        Write-Host "Office is already configured for Semi-Annual channel." -ForegroundColor Green

        $currentVersion = Get-ItemPropertyValue -Path $officeConfigPath -Name "VersionToReport" -ErrorAction SilentlyContinue
        if ($currentVersion -eq $latestVersion) {
            Write-Host "Office is already on the latest version ($latestVersion)." -ForegroundColor Green
            exit 0
        }
        Write-Host "Office is on version $currentVersion but latest is $latestVersion. Updating..." -ForegroundColor Yellow
    }
    else {
        Write-Host "Current channel: $currentChannel" -ForegroundColor Yellow

        if ($PSCmdlet.ShouldProcess("Office CDNBaseUrl registry value", "Configure Office to use Semi-Annual channel ($semiAnnualCDN)")) {
            Write-Host "Configuring Office to use Semi-Annual channel..." -ForegroundColor Yellow
            Set-ItemProperty -Path $officeConfigPath -Name "CDNBaseUrl" -Value $semiAnnualCDN -Type String -Force -ErrorAction Stop
            Write-Host "Office update channel set to Semi-Annual." -ForegroundColor Green
        }
    }

    # Trigger Office update to get the latest version
    if ($PSCmdlet.ShouldProcess("Office installation", "Trigger update to latest version ($latestVersion)")) {
        Write-Host "Triggering Office update to latest version..." -ForegroundColor Yellow

        $officeUpdatePath = Get-OfficeUpdaterPath
        if (-not $officeUpdatePath) {
            # The channel value is written but nothing will pull the update, so this is a failure
            Write-Error "OfficeC2RClient.exe was not found under Common Files\Microsoft Shared\ClickToRun. The update was not triggered."
            exit 1
        }

        Write-Host "Starting Office update process..." -ForegroundColor Yellow
        $updateProcess = Start-Process -FilePath $officeUpdatePath -ArgumentList "/update", "user", "displaylevel=false" -NoNewWindow -Wait -PassThru -ErrorAction Stop
        if ($null -ne $updateProcess -and $updateProcess.ExitCode -ne 0) {
            Write-Error "Office updater exited with code $($updateProcess.ExitCode)."
            exit 1
        }
        Write-Host "Office update process completed." -ForegroundColor Green
    }

    # -WhatIf changes nothing, so there is nothing to verify. Report success.
    if ($WhatIfPreference) {
        Write-Host "WhatIf: no changes were made."
        exit 0
    }

    # Verify the remediation was successful
    Start-Sleep -Seconds 5

    $finalChannel = Get-ItemPropertyValue -Path $officeConfigPath -Name "CDNBaseUrl" -ErrorAction SilentlyContinue | Select-Object -Last 1
    $finalVersion = Get-ItemPropertyValue -Path $officeConfigPath -Name "VersionToReport" -ErrorAction SilentlyContinue

    if ($finalChannel -eq $semiAnnualCDN) {
        Write-Host "Office is now configured for Semi-Annual channel." -ForegroundColor Green
        Write-Host "Current version: $finalVersion" -ForegroundColor Cyan
        Write-Host "Latest version: $latestVersion" -ForegroundColor Cyan

        # The version may not update immediately, but the channel is configured correctly
        if ($finalVersion -eq $latestVersion) {
            Write-Host "Office is on the latest version." -ForegroundColor Green
        }
        else {
            Write-Host "Office update is in progress. Version will update to $latestVersion when complete." -ForegroundColor Yellow
        }

        exit 0
    }
    else {
        Write-Error "Remediation failed. Office channel is still set to: $finalChannel"
        exit 1
    }
}
# Error handling block - catches exceptions during registry modifications or API calls
catch
{
    $errMsg = $_.Exception.Message
    Write-Error "Set-OfficeUpdateChannel: Failed to set Office update channel - $errMsg"
    if ($PSBoundParameters.ContainsKey('Verbose')) {
        Write-Verbose "Stack Trace: $($_.ScriptStackTrace)"
        if ($_.Exception.InnerException) {
            Write-Verbose "Inner Exception: $($_.Exception.InnerException.Message)"
        }
    }
    exit 1
}
