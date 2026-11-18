<#
.SYNOPSIS
    Retrieves detailed information about Intune-managed devices.

.DESCRIPTION
    This script connects to Microsoft Graph API and retrieves comprehensive information
    about Intune-managed devices including enrollment details, last sync time, management
    state, hardware information, and device configuration. It can query a specific device
    by ID, search devices by name, or retrieve all devices. Every query is read through all
    result pages.

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
    Optional. The device ID to query. If not specified, retrieves all devices.

.PARAMETER DeviceName
    Optional. The device name to search for. This is a substring match (Graph contains()), so
    'LAPTOP-01' finds every device whose name includes it. Wildcard characters (* and %) are
    removed, not expanded.

.PARAMETER ExportPath
    Optional. Path to export results to CSV file. If not specified, results are displayed only.

.EXAMPLE
    .\Get-IntuneDeviceDetails.ps1 -AppId 'your-app-id' -TenantId 'your-tenant-id' -ClientSecretSecure (Read-Host -AsSecureString 'Client secret')

.EXAMPLE
    .\Get-IntuneDeviceDetails.ps1 -DeviceId 'device-guid' -ExportPath 'C:\Temp\DeviceDetails.csv'

.EXAMPLE
    .\Get-IntuneDeviceDetails.ps1 -DeviceName 'LAPTOP-01' -ExportPath 'C:\Temp\DeviceDetails.csv'

.NOTES
    Requires: Entra ID App Registration with the DeviceManagementManagedDevices.Read.All APPLICATION
    permission (admin consent granted).
    Exit Codes:
    - 0: Query completed
    - 1: A failure occurred
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
    [string]$DeviceId,

    [Parameter(Mandatory=$false)]
    [string]$DeviceName,

    [Parameter(Mandatory=$false)]
    [string]$ExportPath,

    [Parameter(Mandatory=$false)]
    [ValidateRange(1, 10)]
    [int]$MaxRetries = 3,

    [Parameter(Mandatory=$false)]
    [ValidateRange(1, 60)]
    [int]$InitialDelaySeconds = 2
)

# Shared Graph helpers: token request, retry, paging, OData escaping, CSV safety
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

# Escape DeviceName for an OData query: wildcard characters are removed, single quotes are doubled
$escapedDeviceName = $null
if ($DeviceName) {
    try {
        $escapedDeviceName = Test-ODataFilterInput -InputString $DeviceName
    }
    catch {
        Write-Error "DeviceName cannot be empty after sanitization."
        exit 1
    }
}

# Validate ExportPath if provided
if ($ExportPath) {
    $exportDirectory = Split-Path -Path $ExportPath -Parent
    if ($exportDirectory -and -not (Test-Path -Path $exportDirectory)) {
        try {
            New-Item -Path $exportDirectory -ItemType Directory -Force -ErrorAction Stop | Out-Null
            Write-Verbose "Created export directory: $exportDirectory"
        }
        catch {
            Write-Error "Cannot create export directory: $exportDirectory. Error: $($_.Exception.Message)"
            exit 1
        }
    }

    # Check the file is writable if it already exists
    if (Test-Path -Path $ExportPath) {
        try {
            $testFile = [System.IO.File]::OpenWrite($ExportPath)
            $testFile.Close()
        }
        catch {
            Write-Error "Export path is not writable: $ExportPath. Error: $($_.Exception.Message)"
            exit 1
        }
    }
}

# Turn one managedDevice into a report row
function ConvertTo-DeviceDetail {
    param([Parameter(Mandatory=$true)] $Device)

    [PSCustomObject][ordered]@{
        DeviceId                  = $Device.id
        DeviceName                = $Device.deviceName
        UserPrincipalName         = $Device.userPrincipalName
        UserDisplayName           = $Device.userDisplayName
        EnrollmentDateTime        = $Device.enrolledDateTime
        LastSyncDateTime          = $Device.lastSyncDateTime
        ComplianceState           = $Device.complianceState
        ManagementAgent           = $Device.managementAgent
        OperatingSystem           = $Device.operatingSystem
        OSVersion                 = $Device.osVersion
        Manufacturer              = $Device.manufacturer
        Model                     = $Device.model
        SerialNumber              = $Device.serialNumber
        TotalStorageSpaceInBytes  = $Device.totalStorageSpaceInBytes
        FreeStorageSpaceInBytes   = $Device.freeStorageSpaceInBytes
        ManagedDeviceName         = $Device.managedDeviceName
        DeviceEnrollmentType      = $Device.deviceEnrollmentType
        IsSupervised              = $Device.isSupervised
        IsEncrypted               = $Device.isEncrypted
        JailBroken                = $Device.jailBroken
        PhoneNumber               = $Device.phoneNumber
        IMEI                      = $Device.imei
        EASDeviceId               = $Device.easDeviceId
        ExchangeAccessState       = $Device.exchangeAccessState
        ExchangeAccessStateReason = $Device.exchangeAccessStateReason
    }
}

# Main script execution wrapped in try-catch for error handling
try
{
    Write-Host "Connecting to Microsoft Graph API..." -ForegroundColor Yellow
    $headers = Get-IntuneGraphHeaders -AppRegistration $credential
    Write-Host "Successfully connected to Microsoft Graph API." -ForegroundColor Green

    if ($DeviceId) {
        Write-Host "Querying details for device: $DeviceId" -ForegroundColor Yellow

        $device = Invoke-GraphApiWithRetry -Uri "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices('$DeviceId')" -Headers $headers -Method Get -MaxRetries $MaxRetries -InitialDelaySeconds $InitialDelaySeconds
        if ($null -eq $device) {
            Write-Error "Device not found or API returned null response for device ID: $DeviceId"
            exit 1
        }
        $devices = @($device)
    }
    elseif ($DeviceName) {
        Write-Host "Searching for devices whose name contains: $DeviceName" -ForegroundColor Yellow

        # Substring match. The whole filter is URL-encoded and every result page is read.
        $filter = "contains(deviceName,'$escapedDeviceName')"
        $devicesUrl = "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices?`$filter=$([uri]::EscapeDataString($filter))"
        $devices = @(Get-GraphApiAllPages -Uri $devicesUrl -Headers $headers -MaxRetries $MaxRetries -InitialDelaySeconds $InitialDelaySeconds)
        if ($devices.Count -eq 0) { Write-Warning "No devices found matching name: $DeviceName" }
    }
    else {
        Write-Host "Querying details for all devices..." -ForegroundColor Yellow
        $devices = @(Get-GraphApiAllPages -Uri "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices" -Headers $headers -MaxRetries $MaxRetries -InitialDelaySeconds $InitialDelaySeconds)
    }

    $deviceDetails = @($devices | ForEach-Object { ConvertTo-DeviceDetail -Device $_ })

    # Display results
    Write-Host "`nDevice Details:" -ForegroundColor Cyan
    Write-Host "===============" -ForegroundColor Cyan

    if ($deviceDetails.Count -eq 0) {
        Write-Host "No devices found matching the specified criteria." -ForegroundColor Yellow
    }
    else {
        foreach ($detail in $deviceDetails) {
            Write-Host "`nDevice: $($detail.DeviceName)" -ForegroundColor Green
            Write-Host "  Device ID: $($detail.DeviceId)" -ForegroundColor White
            Write-Host "  User: $($detail.UserPrincipalName) ($($detail.UserDisplayName))" -ForegroundColor White
            Write-Host "  Operating System: $($detail.OperatingSystem) $($detail.OSVersion)" -ForegroundColor White
            Write-Host "  Manufacturer: $($detail.Manufacturer)" -ForegroundColor White
            Write-Host "  Model: $($detail.Model)" -ForegroundColor White
            Write-Host "  Serial Number: $($detail.SerialNumber)" -ForegroundColor White
            Write-Host "  Enrollment Date: $($detail.EnrollmentDateTime)" -ForegroundColor White
            Write-Host "  Last Sync: $($detail.LastSyncDateTime)" -ForegroundColor White
            Write-Host "  Compliance State: $($detail.ComplianceState)" -ForegroundColor $(if ($detail.ComplianceState -eq 'compliant') { 'Green' } else { 'Red' })
            Write-Host "  Management Agent: $($detail.ManagementAgent)" -ForegroundColor White
            Write-Host "  Enrollment Type: $($detail.DeviceEnrollmentType)" -ForegroundColor White
            Write-Host "  Supervised: $($detail.IsSupervised)" -ForegroundColor White
            Write-Host "  Encrypted: $($detail.IsEncrypted)" -ForegroundColor White
            if ($detail.TotalStorageSpaceInBytes) {
                $totalGB = [math]::Round($detail.TotalStorageSpaceInBytes / 1GB, 2)
                $freeGB = [math]::Round($detail.FreeStorageSpaceInBytes / 1GB, 2)
                Write-Host "  Storage: $freeGB GB free of $totalGB GB total" -ForegroundColor White
            }
        }

        # Export to CSV if path is specified
        if ($ExportPath) {
            $deviceDetails | ConvertTo-SafeCsvRecord | Export-Csv -Path $ExportPath -NoTypeInformation -Encoding UTF8
            Write-Host "`nResults exported to: $ExportPath" -ForegroundColor Green

            if (-not (Test-Path -Path $ExportPath)) {
                Write-Error "Export file was not created successfully at: $ExportPath"
                exit 1
            }
        }
    }

    Write-Host "`nQuery completed successfully. Found $($deviceDetails.Count) device(s)." -ForegroundColor Green
}
# Error handling block - catches exceptions during Graph API calls
catch
{
    $errMsg = $_.Exception.Message
    Write-Error "Get-IntuneDeviceDetails: Failed to retrieve device details - $errMsg"

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
