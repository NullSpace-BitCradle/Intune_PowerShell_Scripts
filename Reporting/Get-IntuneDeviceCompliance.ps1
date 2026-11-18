<#
.SYNOPSIS
    Retrieves compliance status for Intune-managed devices.

.DESCRIPTION
    This script connects to Microsoft Graph API and retrieves compliance status information
    for Intune-managed devices. It can query compliance for a specific device, all devices,
    or devices for a specific user.

    For each device it reads the device's own compliance policy states
    (managedDevices/{id}/deviceCompliancePolicyStates). CompliancePolicies lists every policy that
    applies to that device with its state, for example "Baseline (compliant); BitLocker (nonCompliant)",
    and NonCompliantPolicies lists the ones in the nonCompliant, error or conflict state. Per-setting
    non-compliance reasons are not retrieved.

    That is one extra request per device. Use -SkipPolicyStates on a large tenant to skip it; the
    policy columns are then blank.

    If a device's policy states cannot be read (for example a missing permission or a 429 after
    retries) the device gets a CollectionError value, the report says it is incomplete and the
    script exits 1. A blank policy column is never used to mean "failed".

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
    Optional. The device ID to query compliance for. If not specified, retrieves all devices.

.PARAMETER UserPrincipalName
    Optional. The user principal name to query devices for. If specified, retrieves compliance
    for all devices owned by this user.

.PARAMETER ExportPath
    Optional. Path to export results to CSV file. If not specified, results are displayed only.

.PARAMETER SkipPolicyStates
    Optional switch. Do not read each device's policy states (saves one request per device).

.EXAMPLE
    .\Get-IntuneDeviceCompliance.ps1 -AppId 'your-app-id' -TenantId 'your-tenant-id' -ClientSecretSecure (Read-Host -AsSecureString 'Client secret')

.EXAMPLE
    .\Get-IntuneDeviceCompliance.ps1 -DeviceId 'device-guid' -ExportPath 'C:\Temp\ComplianceReport.csv'

.EXAMPLE
    .\Get-IntuneDeviceCompliance.ps1 -UserPrincipalName 'user@domain.com' -ExportPath 'C:\Temp\ComplianceReport.csv'

.NOTES
    Requires: Entra ID App Registration with the DeviceManagementManagedDevices.Read.All and
    DeviceManagementConfiguration.Read.All APPLICATION permissions (admin consent granted).
    Exit Codes:
    - 0: Report complete
    - 1: A failure, or at least one device's policy states could not be retrieved
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
    [string]$UserPrincipalName,

    [Parameter(Mandatory=$false)]
    [string]$ExportPath,

    [Parameter(Mandatory=$false)]
    [switch]$SkipPolicyStates,

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

# Validate UserPrincipalName format if provided
if ($UserPrincipalName -and -not (Test-EmailFormat -Email $UserPrincipalName)) {
    Write-Error "UserPrincipalName must be a valid email address format."
    exit 1
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

# Build one report row for a device, reading the device's own compliance policy states.
# Errors are recorded on the row and counted; they are never turned into an empty policy list.
function Get-ComplianceRow {
    param([Parameter(Mandatory=$true)] $Device)

    $policyText = $null
    $nonCompliantText = $null
    $collectionError = $null

    if (-not $SkipPolicyStates) {
        try {
            $url = "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices('$($Device.id)')/deviceCompliancePolicyStates"
            $states = @(Get-GraphApiAllPages -Uri $url -Headers $script:headers -MaxRetries $MaxRetries -InitialDelaySeconds $InitialDelaySeconds)
            $policyText = ($states | ForEach-Object { "$($_.displayName) ($($_.state))" }) -join '; '
            $nonCompliantText = ($states | Where-Object { $_.state -in @('nonCompliant', 'error', 'conflict') } | ForEach-Object { $_.displayName }) -join '; '
        }
        catch {
            $collectionError = "Could not read policy states: $($_.Exception.Message)"
            $script:collectionErrorCount++
            Write-Verbose "$collectionError (device $($Device.id))"
        }
    }

    [PSCustomObject][ordered]@{
        DeviceId             = $Device.id
        DeviceName           = $Device.deviceName
        UserPrincipalName    = $Device.userPrincipalName
        ComplianceState      = $Device.complianceState
        LastSyncDateTime     = $Device.lastSyncDateTime
        OSVersion            = $Device.osVersion
        ManagementAgent      = $Device.managementAgent
        CompliancePolicies   = $policyText
        NonCompliantPolicies = $nonCompliantText
        CollectionError      = $collectionError
    }
}

# Main script execution wrapped in try-catch for error handling
try
{
    Write-Host "Connecting to Microsoft Graph API..." -ForegroundColor Yellow
    $script:headers = Get-IntuneGraphHeaders -AppRegistration $credential
    Write-Host "Successfully connected to Microsoft Graph API." -ForegroundColor Green

    $script:collectionErrorCount = 0
    $complianceResults = @()

    if ($DeviceId) {
        Write-Host "Querying compliance for device: $DeviceId" -ForegroundColor Yellow

        $device = Invoke-GraphApiWithRetry -Uri "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices('$DeviceId')" -Headers $script:headers -Method Get -MaxRetries $MaxRetries -InitialDelaySeconds $InitialDelaySeconds
        if ($null -eq $device) {
            Write-Error "Device not found or API returned null response for device ID: $DeviceId"
            exit 1
        }
        $devices = @($device)
    }
    elseif ($UserPrincipalName) {
        Write-Host "Querying compliance for devices owned by: $UserPrincipalName" -ForegroundColor Yellow

        # The quote is doubled (OData's escape) and the whole filter is URL-encoded, so a + in the UPN survives
        $filter = "userPrincipalName eq $(ConvertTo-ODataStringLiteral -Value $UserPrincipalName)"
        $devicesUrl = "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices?`$filter=$([uri]::EscapeDataString($filter))"
        $devices = @(Get-GraphApiAllPages -Uri $devicesUrl -Headers $script:headers -MaxRetries $MaxRetries -InitialDelaySeconds $InitialDelaySeconds)
        if ($devices.Count -eq 0) { Write-Warning "No devices found for user: $UserPrincipalName" }
    }
    else {
        Write-Host "Querying compliance for all devices..." -ForegroundColor Yellow
        $devices = @(Get-GraphApiAllPages -Uri "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices" -Headers $script:headers -MaxRetries $MaxRetries -InitialDelaySeconds $InitialDelaySeconds)
    }

    $deviceCount = 0
    foreach ($device in $devices) {
        $deviceCount++
        Write-Progress -Activity "Reading compliance policy states" -Status "Device $deviceCount of $($devices.Count): $($device.deviceName)" -PercentComplete (($deviceCount / $devices.Count) * 100)
        $complianceResults += Get-ComplianceRow -Device $device
    }
    Write-Progress -Activity "Reading compliance policy states" -Completed

    # Display results
    Write-Host "`nCompliance Results:" -ForegroundColor Cyan
    Write-Host "===================" -ForegroundColor Cyan

    if ($complianceResults.Count -eq 0) {
        Write-Host "No devices found matching the specified criteria." -ForegroundColor Yellow
    }
    else {
        foreach ($result in $complianceResults) {
            Write-Host "`nDevice: $($result.DeviceName)" -ForegroundColor Green
            Write-Host "  Device ID: $($result.DeviceId)" -ForegroundColor White
            Write-Host "  User: $($result.UserPrincipalName)" -ForegroundColor White
            Write-Host "  Compliance State: $($result.ComplianceState)" -ForegroundColor $(if ($result.ComplianceState -eq 'compliant') { 'Green' } else { 'Red' })
            Write-Host "  Last Sync: $($result.LastSyncDateTime)" -ForegroundColor White
            Write-Host "  OS Version: $($result.OSVersion)" -ForegroundColor White
            Write-Host "  Management Agent: $($result.ManagementAgent)" -ForegroundColor White
            if ($result.CompliancePolicies) { Write-Host "  Policies: $($result.CompliancePolicies)" -ForegroundColor White }
            if ($result.NonCompliantPolicies) { Write-Host "  Not compliant with: $($result.NonCompliantPolicies)" -ForegroundColor Red }
            if ($result.CollectionError) { Write-Host "  ERROR: $($result.CollectionError)" -ForegroundColor Red }
        }

        # Export to CSV if path is specified
        if ($ExportPath) {
            try {
                $complianceResults | ConvertTo-SafeCsvRecord | Export-Csv -Path $ExportPath -NoTypeInformation -Encoding UTF8
                Write-Host "`nResults exported to: $ExportPath" -ForegroundColor Green

                if (-not (Test-Path -Path $ExportPath)) {
                    Write-Error "Export file was not created successfully at: $ExportPath"
                    exit 1
                }
            }
            catch {
                Write-Error "Get-IntuneDeviceCompliance: Failed to export results to CSV - $($_.Exception.Message)"
                exit 1
            }
        }
    }

    if ($script:collectionErrorCount -gt 0) {
        Write-Error "The report is incomplete: policy states could not be read for $($script:collectionErrorCount) device(s). They have a CollectionError value."
        exit 1
    }

    Write-Host "`nQuery completed successfully." -ForegroundColor Green
}
# Error handling block - catches exceptions during Graph API calls
catch
{
    $errMsg = $_.Exception.Message
    Write-Error "Get-IntuneDeviceCompliance: Failed to retrieve device compliance information - $errMsg"

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
