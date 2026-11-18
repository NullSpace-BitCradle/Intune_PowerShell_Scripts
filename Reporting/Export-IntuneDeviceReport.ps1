<#
.SYNOPSIS
    Exports comprehensive device information to CSV/JSON.

.DESCRIPTION
    This script connects to Microsoft Graph API and collects comprehensive device information
    including device details, the device's compliance policy states and its configuration
    profile states. The collected data is exported to CSV or JSON format. Every query is read
    through all result pages.

    If a device's compliance or configuration states cannot be read (for example a missing
    permission or a 429 after retries), that device gets a CollectionErrors value instead of
    blank columns, the report says it is incomplete and the script exits 1. The report file is
    still written so the rest of the data is not lost.

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

.PARAMETER DeviceId
    Optional. The device ID to generate report for. If not specified, generates report for all devices.

.PARAMETER OutputPath
    Optional. Path to export report file. If not specified, exports to $env:TEMP\IntuneDeviceReport_<timestamp>.csv (or .json).

.PARAMETER Format
    Optional. Export format: "CSV" or "JSON". Default is "CSV".

.EXAMPLE
    .\Export-IntuneDeviceReport.ps1 -AppId 'your-app-id' -TenantId 'your-tenant-id' -ClientSecretSecure (Read-Host -AsSecureString 'Client secret')

.EXAMPLE
    .\Export-IntuneDeviceReport.ps1 -DeviceId 'device-guid' -Format 'JSON' -OutputPath 'C:\Reports\DeviceReport.json'

.NOTES
    Requires: Entra ID App Registration with the DeviceManagementManagedDevices.Read.All and
    DeviceManagementConfiguration.Read.All APPLICATION permissions (admin consent granted).
    No apps endpoint is called, so DeviceManagementApps.Read.All is not needed.
    Exit Codes:
    - 0: Report complete
    - 1: A failure, or at least one device's compliance or configuration states could not be retrieved
#>

[CmdletBinding()]
# Define script parameters for credential input and export options
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
    [string]$DeviceId,

    [Parameter(Mandatory=$false)]
    [string]$OutputPath,

    [Parameter(Mandatory=$false)]
    [ValidateSet("CSV", "JSON")]
    [string]$Format = "CSV"
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

# Validate DeviceId format if provided
if ($DeviceId -and -not (Test-GuidFormat -Guid $DeviceId)) {
    Write-Error "DeviceId must be a valid GUID format."
    exit 1
}

# Determine output path if not specified
# If not specified, create a timestamped file in $env:TEMP
if (-not $OutputPath) {
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $extension = if ($Format -eq "JSON") { "json" } else { "csv" }
    $OutputPath = Join-Path $env:TEMP "IntuneDeviceReport_$timestamp.$extension"
}

# Create output directory if it doesn't exist
$exportDirectory = Split-Path -Path $OutputPath -Parent
if ($exportDirectory -and -not (Test-Path -Path $exportDirectory)) {
    New-Item -Path $exportDirectory -ItemType Directory -Force | Out-Null
}

# Read one per-device state collection. Returns the display names, or records the failure.
# A failure is never turned into an empty list: it is counted and returned as an error text.
function Get-DeviceStateName {
    param(
        [Parameter(Mandatory=$true)] [string]$ManagedDeviceId,
        [Parameter(Mandatory=$true)] [string]$Collection,
        [Parameter(Mandatory=$true)] [string]$Label
    )

    try {
        $url = "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices('$ManagedDeviceId')/$Collection"
        $states = @(Get-GraphApiAllPages -Uri $url -Headers $script:headers)
        return [PSCustomObject]@{ Names = (($states | ForEach-Object { $_.displayName }) -join '; '); Error = $null }
    }
    catch {
        $script:collectionErrorCount++
        Write-Verbose "Could not retrieve $Label for device ${ManagedDeviceId}: $($_.Exception.Message)"
        return [PSCustomObject]@{ Names = $null; Error = "$Label`: $($_.Exception.Message)" }
    }
}

# Main script execution wrapped in try-catch for error handling
try
{
    Write-Host "Connecting to Microsoft Graph API..." -ForegroundColor Yellow
    $script:headers = Get-IntuneGraphHeaders -Credential $credential
    Write-Host "Successfully connected to Microsoft Graph API." -ForegroundColor Green

    $script:collectionErrorCount = 0
    $deviceReports = @()

    if ($DeviceId) {
        Write-Host "Generating report for device: $DeviceId" -ForegroundColor Yellow

        $device = Invoke-GraphApiWithRetry -Uri "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices('$DeviceId')" -Headers $script:headers -Method Get
        if ($null -eq $device) {
            Write-Error "Device not found or API returned null response for device ID: $DeviceId"
            exit 1
        }
        $devices = @($device)
    }
    else {
        Write-Host "Generating report for all devices..." -ForegroundColor Yellow
        $devices = @(Get-GraphApiAllPages -Uri "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices" -Headers $script:headers)
    }

    Write-Host "Found $($devices.Count) device(s). Collecting information..." -ForegroundColor Cyan

    $deviceCount = 0
    foreach ($device in $devices) {
        $deviceCount++
        Write-Host "Processing device $deviceCount of $($devices.Count): $($device.deviceName)" -ForegroundColor Cyan

        $compliance = Get-DeviceStateName -ManagedDeviceId $device.id -Collection 'deviceCompliancePolicyStates' -Label 'compliance policy states'
        $configuration = Get-DeviceStateName -ManagedDeviceId $device.id -Collection 'deviceConfigurationStates' -Label 'configuration profile states'
        $errors = @($compliance.Error, $configuration.Error) | Where-Object { $_ }

        $deviceReports += [PSCustomObject][ordered]@{
            DeviceId                  = $device.id
            DeviceName                = $device.deviceName
            UserPrincipalName         = $device.userPrincipalName
            UserDisplayName           = $device.userDisplayName
            EnrollmentDateTime        = $device.enrolledDateTime
            LastSyncDateTime          = $device.lastSyncDateTime
            ComplianceState           = $device.complianceState
            ManagementAgent           = $device.managementAgent
            OperatingSystem           = $device.operatingSystem
            OSVersion                 = $device.osVersion
            Manufacturer              = $device.manufacturer
            Model                     = $device.model
            SerialNumber              = $device.serialNumber
            TotalStorageSpaceInBytes  = $device.totalStorageSpaceInBytes
            FreeStorageSpaceInBytes   = $device.freeStorageSpaceInBytes
            ManagedDeviceName         = $device.managedDeviceName
            DeviceEnrollmentType      = $device.deviceEnrollmentType
            IsSupervised              = $device.isSupervised
            IsEncrypted               = $device.isEncrypted
            JailBroken                = $device.jailBroken
            PhoneNumber               = $device.phoneNumber
            IMEI                      = $device.imei
            EASDeviceId               = $device.easDeviceId
            ExchangeAccessState       = $device.exchangeAccessState
            ExchangeAccessStateReason = $device.exchangeAccessStateReason
            CompliancePolicies        = $compliance.Names
            ConfigurationProfiles     = $configuration.Names
            CollectionErrors          = ($errors -join ' | ')
            ReportGeneratedDate       = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        }
    }

    # Export report based on specified format
    Write-Host "`nExporting report to $Format format..." -ForegroundColor Yellow

    if ($Format -eq "JSON") {
        $deviceReports | ConvertTo-Json -Depth 10 | Out-File -FilePath $OutputPath -Encoding UTF8
    }
    else {
        $deviceReports | ConvertTo-SafeCsvRecord | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
    }
    Write-Host "Report exported to: $OutputPath" -ForegroundColor Green

    # Verify the export file was created successfully
    if (-not (Test-Path -Path $OutputPath)) {
        Write-Error "Export file was not created successfully at: $OutputPath"
        exit 1
    }

    $fileInfo = Get-Item -Path $OutputPath
    if ($fileInfo.Length -eq 0) {
        Write-Warning "Export file was created but appears to be empty."
    }

    # Display summary
    Write-Host "`nReport Summary:" -ForegroundColor Cyan
    Write-Host "===============" -ForegroundColor Cyan
    Write-Host "Devices included: $($deviceReports.Count)" -ForegroundColor White
    Write-Host "Output format: $Format" -ForegroundColor White
    Write-Host "Output path: $OutputPath" -ForegroundColor White

    if ($script:collectionErrorCount -gt 0) {
        Write-Error "The report is incomplete: $($script:collectionErrorCount) state request(s) failed. Affected devices have a CollectionErrors value."
        exit 1
    }

    Write-Host "`nReport generation completed successfully." -ForegroundColor Green
    exit 0
}
# Error handling block - catches exceptions during Graph API calls or export
catch
{
    $errMsg = $_.Exception.Message
    Write-Error "Export-IntuneDeviceReport: Failed to export device report - $errMsg"

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
