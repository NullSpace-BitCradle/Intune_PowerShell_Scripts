<#
.SYNOPSIS
    Retrieves detailed information about Win32 app deployments.

.DESCRIPTION
    This script connects to Microsoft Graph API and retrieves detailed information about
    Win32 app deployments in Intune: the app, its install and uninstall commands, and its
    assignments. It can query a specific app or all apps. Every query is read through all result pages.

    When -DeviceId is given, each app also gets the install state Intune reports for that device
    (beta endpoint mobileApps/{id}/deviceStatuses, matched on the device ID). The states are Graph's own:
    installed, failed, notInstalled, uninstallFailed, pendingInstall, unknown, notApplicable.
    "NotReported" means Intune has no status row for that app on that device, which is the case for
    an app that is not targeted at it. Installed software inventory (detectedApps) is not used,
    because its display names rarely equal the Intune app name.
    This is one extra request (more for large result sets) per app.

    If an app's assignments or its device status cannot be read (for example a missing permission or
    a 429 after retries), the app gets an AssignmentError or DeviceStatusError value instead of an
    empty result, the report says it is incomplete and the script exits 1.

.PARAMETER AppId
    The Application (Client) ID of your Entra ID registered app. Can also be provided via
    INTUNE_APP_ID environment variable.

.PARAMETER TenantId
    Your Azure AD Tenant ID. Can also be provided via INTUNE_TENANT_ID environment variable.

.PARAMETER ClientSecret
    The Client Secret of your Entra ID registered app, as plain text. A secret on the command line
    ends up in shell history and process listings; prefer -ClientSecretSecure or the
    INTUNE_CLIENT_SECRET environment variable.

.PARAMETER ClientSecretSecure
    The Client Secret as a SecureString, for example from Read-Host -AsSecureString or a vault.

.PARAMETER IntuneAppId
    Optional. The Intune app ID to query. If not specified, retrieves all Win32 apps.

.PARAMETER DeviceId
    Optional. The device ID to query app installation status for. If specified, shows
    the reported install state of each app on that device.

.PARAMETER ExportPath
    Optional. Path to export results to CSV file. If not specified, results are displayed only.

.EXAMPLE
    .\Get-IntuneWin32AppDetails.ps1 -AppId 'your-app-id' -TenantId 'your-tenant-id' -ClientSecretSecure (Read-Host -AsSecureString 'Client secret')

.EXAMPLE
    .\Get-IntuneWin32AppDetails.ps1 -IntuneAppId 'app-guid' -DeviceId 'device-guid' -ExportPath 'C:\Temp\AppDetails.csv'

.NOTES
    Requires: Entra ID App Registration with the DeviceManagementApps.Read.All APPLICATION permission
    (admin consent granted).
    Exit Codes:
    - 0: Report complete
    - 1: A failure, or at least one app's assignments or device status could not be retrieved
#>

[CmdletBinding()]
# Define script parameters for credential input and query options
param(
    [Parameter(Mandatory=$false)]
    [string]$AppId,

    [Parameter(Mandatory=$false)]
    [string]$TenantId,

    [Parameter(Mandatory=$false)]
    [string]$ClientSecret,

    [Parameter(Mandatory=$false)]
    [securestring]$ClientSecretSecure,

    [Parameter(Mandatory=$false)]
    [string]$IntuneAppId,

    [Parameter(Mandatory=$false)]
    [string]$DeviceId,

    [Parameter(Mandatory=$false)]
    [string]$ExportPath
)

# Shared Graph helpers: token request, retry, paging, CSV safety
try {
    Import-Module (Join-Path $PSScriptRoot '..\Common\IntuneCommon.psd1') -ErrorAction Stop
}
catch {
    Write-Error "Failed to import the IntuneCommon module: $($_.Exception.Message)"
    exit 1
}

# Credential handling: parameters first, then environment variables. Placeholders are rejected.
try {
    $credential = Get-IntuneCredential -AppId $AppId -TenantId $TenantId -ClientSecret $ClientSecret -ClientSecretSecure $ClientSecretSecure
}
catch {
    Write-Error $_.Exception.Message
    exit 1
}

# Validate DeviceId and IntuneAppId format if provided
if ($DeviceId -and -not (Test-GuidFormat -Guid $DeviceId)) {
    Write-Error "DeviceId must be a valid GUID format."
    exit 1
}
if ($IntuneAppId -and -not (Test-GuidFormat -Guid $IntuneAppId)) {
    Write-Error "IntuneAppId must be a valid GUID format."
    exit 1
}

# Build the report row for one Win32 app, reading its assignments.
# A failure is recorded on the row (AssignmentError) and counted; it is never turned into "0 assignments".
function Get-AppDetailRow {
    param([Parameter(Mandatory=$true)] $App)

    $assignmentCount = $null
    $assignmentText = $null
    $assignmentError = $null

    try {
        $url = "https://graph.microsoft.com/v1.0/deviceAppManagement/mobileApps('$($App.id)')/assignments"
        $assignments = @(Get-GraphApiAllPages -Uri $url -Headers $script:headers)
        $assignmentCount = $assignments.Count
        $assignmentText = ($assignments | ForEach-Object { $_.target.'@odata.type' }) -join '; '
    }
    catch {
        $assignmentError = "Could not read assignments: $($_.Exception.Message)"
        $script:errorCount++
        Write-Verbose "$assignmentError (app $($App.id))"
    }

    [PSCustomObject][ordered]@{
        AppId                           = $App.id
        AppName                         = $App.displayName
        AppDescription                  = $App.description
        AppVersion                      = if ($App.displayVersion) { $App.displayVersion } else { $App.version }
        AppType                         = "Win32"
        Publisher                       = $App.publisher
        InstallCommandLine              = $App.installCommandLine
        UninstallCommandLine            = $App.uninstallCommandLine
        MinimumSupportedOperatingSystem = $App.minimumSupportedOperatingSystem
        AssignmentCount                 = $assignmentCount
        Assignments                     = $assignmentText
        AssignmentError                 = $assignmentError
    }
}

# Add the install state Intune reports for one device to a report row.
function Add-DeviceInstallState {
    param(
        [Parameter(Mandatory=$true)] $Row,
        [Parameter(Mandatory=$true)] [string]$ManagedDeviceId
    )

    $state = "NotReported"
    $version = $null
    $deviceError = $null

    try {
        # deviceStatuses is documented in the Graph beta endpoint only, so this one call uses beta. The rest of the script uses v1.0.
        $url = "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps('$($Row.AppId)')/deviceStatuses"
        $statuses = @(Get-GraphApiAllPages -Uri $url -Headers $script:headers)
        $mine = $statuses | Where-Object { $_.deviceId -eq $ManagedDeviceId } | Select-Object -First 1
        if ($mine) {
            $state = if ($mine.installState) { $mine.installState } else { "unknown" }
            $version = $mine.displayVersion
        }
    }
    catch {
        $state = "Unknown"
        $deviceError = "Could not read device status: $($_.Exception.Message)"
        $script:errorCount++
        Write-Verbose "$deviceError (app $($Row.AppId))"
    }

    $Row | Add-Member -MemberType NoteProperty -Name "DeviceInstallStatus" -Value $state -Force
    $Row | Add-Member -MemberType NoteProperty -Name "DeviceInstallVersion" -Value $version -Force
    $Row | Add-Member -MemberType NoteProperty -Name "DeviceStatusError" -Value $deviceError -Force
}

# Main script execution wrapped in try-catch for error handling
try
{
    Write-Host "Connecting to Microsoft Graph API..." -ForegroundColor Yellow
    $script:headers = Get-IntuneGraphHeaders -AppRegistration $credential
    Write-Host "Successfully connected to Microsoft Graph API." -ForegroundColor Green

    $script:errorCount = 0
    $appDetails = @()

    if ($IntuneAppId) {
        Write-Host "Querying details for app: $IntuneAppId" -ForegroundColor Yellow

        # A failed fetch is a failure of the whole run (caught below, exit 1), not a "completed successfully"
        $app = Invoke-GraphApiWithRetry -Uri "https://graph.microsoft.com/v1.0/deviceAppManagement/mobileApps('$IntuneAppId')" -Headers $script:headers -Method Get
        if ($null -eq $app) {
            Write-Error "App not found or API returned null response for app ID: $IntuneAppId"
            exit 1
        }

        if ($app.'@odata.type' -eq '#microsoft.graph.win32LobApp') {
            $appDetails += Get-AppDetailRow -App $app
        }
        else {
            Write-Warning "App $IntuneAppId is not a Win32 app. Type: $($app.'@odata.type')"
        }
    }
    else {
        Write-Host "Querying details for all Win32 apps..." -ForegroundColor Yellow

        $appsUrl = "https://graph.microsoft.com/v1.0/deviceAppManagement/mobileApps?`$filter=$([uri]::EscapeDataString("isof('microsoft.graph.win32LobApp')"))"
        $allApps = @(Get-GraphApiAllPages -Uri $appsUrl -Headers $script:headers)
        Write-Host "Found $($allApps.Count) Win32 app(s). Processing..." -ForegroundColor Cyan

        $appCount = 0
        foreach ($app in $allApps) {
            $appCount++
            Write-Progress -Activity "Processing Win32 apps" -Status "Processing app $appCount of $($allApps.Count): $($app.displayName)" -PercentComplete (($appCount / $allApps.Count) * 100)
            Write-Host "Processing app $appCount of $($allApps.Count): $($app.displayName)" -ForegroundColor Cyan
            $appDetails += Get-AppDetailRow -App $app
        }
        Write-Progress -Activity "Processing Win32 apps" -Completed
    }

    # If DeviceId is specified, add the reported install state of each app on that device
    if ($DeviceId) {
        Write-Host "`nQuerying app installation status for device: $DeviceId" -ForegroundColor Yellow
        foreach ($row in $appDetails) { Add-DeviceInstallState -Row $row -ManagedDeviceId $DeviceId }
    }

    # Display results
    Write-Host "`nWin32 App Details:" -ForegroundColor Cyan
    Write-Host "==================" -ForegroundColor Cyan

    if ($appDetails.Count -eq 0) {
        Write-Host "No Win32 apps found matching the specified criteria." -ForegroundColor Yellow
    }
    else {
        foreach ($detail in $appDetails) {
            Write-Host "`nApp: $($detail.AppName)" -ForegroundColor Green
            Write-Host "  App ID: $($detail.AppId)" -ForegroundColor White
            Write-Host "  Publisher: $($detail.Publisher)" -ForegroundColor White
            Write-Host "  Version: $($detail.AppVersion)" -ForegroundColor White
            Write-Host "  Install Command: $($detail.InstallCommandLine)" -ForegroundColor White
            if ($detail.AssignmentError) { Write-Host "  ERROR: $($detail.AssignmentError)" -ForegroundColor Red }
            else { Write-Host "  Assignment Count: $($detail.AssignmentCount)" -ForegroundColor White }
            if ($detail.DeviceInstallStatus) {
                Write-Host "  Device Install Status: $($detail.DeviceInstallStatus)" -ForegroundColor $(if ($detail.DeviceInstallStatus -eq 'installed') { 'Green' } else { 'Yellow' })
                if ($detail.DeviceInstallVersion) { Write-Host "  Device Install Version: $($detail.DeviceInstallVersion)" -ForegroundColor White }
                if ($detail.DeviceStatusError) { Write-Host "  ERROR: $($detail.DeviceStatusError)" -ForegroundColor Red }
            }
        }

        # Export to CSV if path is specified
        if ($ExportPath) {
            $exportDirectory = Split-Path -Path $ExportPath -Parent
            if ($exportDirectory -and -not (Test-Path -Path $exportDirectory)) {
                New-Item -Path $exportDirectory -ItemType Directory -Force | Out-Null
            }

            $appDetails | ConvertTo-SafeCsvRecord | Export-Csv -Path $ExportPath -NoTypeInformation -Encoding UTF8
            Write-Host "`nResults exported to: $ExportPath" -ForegroundColor Green

            if (-not (Test-Path -Path $ExportPath)) {
                Write-Error "Export file was not created successfully at: $ExportPath"
                exit 1
            }
        }
    }

    if ($script:errorCount -gt 0) {
        Write-Error "The report is incomplete: $($script:errorCount) request(s) failed. Affected rows have an AssignmentError or DeviceStatusError value."
        exit 1
    }

    Write-Host "`nQuery completed successfully. Found $($appDetails.Count) Win32 app(s)." -ForegroundColor Green
}
# Error handling block - catches exceptions during Graph API calls
catch
{
    $errMsg = $_.Exception.Message
    Write-Error "Get-IntuneWin32AppDetails: Failed to retrieve Win32 app details - $errMsg"

    if ($_.Exception.Response) {
        $statusCode = $_.Exception.Response.StatusCode.value__
        Write-Verbose "HTTP Status Code: $statusCode"
    }

    if ($_.Exception.InnerException) {
        Write-Verbose "Inner Exception: $($_.Exception.InnerException.Message)"
    }

    if ($PSBoundParameters.ContainsKey('Verbose')) {
        Write-Verbose "Stack Trace: $($_.ScriptStackTrace)"
    }

    exit 1
}
