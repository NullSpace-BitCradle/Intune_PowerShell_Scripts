<#
.SYNOPSIS
    Comprehensive device health check.

.DESCRIPTION
    This script performs a health check on Intune-managed devices covering enrollment, sync
    freshness, compliance state, management agent, operating system and storage. It can check a
    specific device or all devices. Every query is read through all result pages.

    Each device starts at 100 and loses points for each problem. The weights are fixed values in
    this script (see $HealthWeights in Get-DeviceHealthAssessment) and are a rule of thumb, not a
    Microsoft measure:

    - Not enrolled -30, never synced -25, last sync over 24 hours -20, over 8 hours -10
    - Compliance not "compliant" -15, compliance unknown -5
    - Management agent "unknown" -10, missing -5, operating system not Windows/iOS/Android/macOS -5
    - Storage over 90 percent full -15, over 80 percent -5

    Overall health is Healthy at 90 or more, Fair at 70 or more, Warning at 50 or more, Critical below.

    The management agent list follows the Graph managementAgentType values (eas, mdm, easMdm,
    intuneClient, easIntuneClient, configurationManagerClient and its co-management variants, jamf,
    googleCloudDevicePolicyController, microsoft365ManagedMdm, msSense, intuneAosp). Only "unknown"
    or a missing value is penalised. A device is not penalised for being enrolled for a long time.

    Graph returns 0001-01-01T00:00:00Z as the last sync of a device that has never synced. That value
    is treated as "Never Synced".

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
    Optional. The device ID to check health for. If not specified, checks all devices.

.PARAMETER ExportPath
    Optional. Path to export results to CSV file. If not specified, results are displayed only.

.EXAMPLE
    .\Get-IntuneDeviceHealth.ps1 -AppId 'your-app-id' -TenantId 'your-tenant-id' -ClientSecretSecure (Read-Host -AsSecureString 'Client secret')

.EXAMPLE
    .\Get-IntuneDeviceHealth.ps1 -DeviceId 'device-guid' -ExportPath 'C:\Temp\DeviceHealth.csv'

.NOTES
    Requires: Entra ID App Registration with the DeviceManagementManagedDevices.Read.All APPLICATION
    permission (admin consent granted).
    Exit Codes:
    - 0: Health check completed
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

# Validate DeviceId format if provided
if ($DeviceId -and -not (Test-GuidFormat -Guid $DeviceId)) {
    Write-Error "DeviceId must be a valid GUID format."
    exit 1
}

# Score one device. Pure function: the clock is a parameter so the result can be tested.
function Get-DeviceHealthAssessment {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        $Device,

        [Parameter(Mandatory=$false)]
        [datetime]$Now = (Get-Date)
    )

    # Points lost per problem. A rule of thumb, kept in one place.
    $HealthWeights = @{
        NotEnrolled = 30; NeverSynced = 25; SyncStale = 20; SyncWarning = 10
        NotCompliant = 15; ComplianceUnknown = 5
        AgentUnknown = 10; AgentMissing = 5; OsUnsupported = 5
        StorageCritical = 15; StorageWarning = 5
    }

    # managementAgentType values from Microsoft Graph, other than "unknown"
    $knownAgents = @('eas', 'mdm', 'easMdm', 'intuneClient', 'easIntuneClient', 'configurationManagerClient',
                     'configurationManagerClientMdm', 'configurationManagerClientMdmEas', 'jamf',
                     'googleCloudDevicePolicyController', 'microsoft365ManagedMdm', 'msSense', 'intuneAosp')

    $healthScore = 100
    $healthIssues = @()

    # Check 1: Enrollment status
    $enrollmentStatus = "Healthy"
    if (-not $Device.enrolledDateTime) {
        $enrollmentStatus = "Not Enrolled"
        $healthScore -= $HealthWeights.NotEnrolled
        $healthIssues += "Device not enrolled"
    }

    # Check 2: Sync status. A device that never synced has no date or Graph's 0001-01-01 placeholder.
    $syncStatus = "Healthy"
    $lastSync = $null
    if ($Device.lastSyncDateTime) {
        $lastSync = [datetime]$Device.lastSyncDateTime
        if ($lastSync.Year -le 1) { $lastSync = $null }
    }
    if ($null -ne $lastSync) {
        $hoursSinceSync = ($Now - $lastSync).TotalHours
        if ($hoursSinceSync -gt 24) {
            $syncStatus = "Stale"
            $healthScore -= $HealthWeights.SyncStale
            $healthIssues += "Last sync was over 24 hours ago"
        }
        elseif ($hoursSinceSync -gt 8) {
            $syncStatus = "Warning"
            $healthScore -= $HealthWeights.SyncWarning
            $healthIssues += "Last sync was over 8 hours ago"
        }
    }
    else {
        $syncStatus = "Never Synced"
        $healthScore -= $HealthWeights.NeverSynced
        $healthIssues += "Device has never synced"
    }

    # Check 3: Compliance state
    $complianceStatus = "Healthy"
    if ($Device.complianceState) {
        if ($Device.complianceState -ne "compliant") {
            $complianceStatus = $Device.complianceState
            $healthScore -= $HealthWeights.NotCompliant
            $healthIssues += "Device is not compliant: $($Device.complianceState)"
        }
    }
    else {
        $complianceStatus = "Unknown"
        $healthScore -= $HealthWeights.ComplianceUnknown
        $healthIssues += "Compliance state unknown"
    }

    # Check 4: Management agent
    $managementStatus = "Healthy"
    if ($Device.managementAgent) {
        if ($Device.managementAgent -notin $knownAgents) {
            $managementStatus = "Unknown"
            $healthScore -= $HealthWeights.AgentUnknown
            $healthIssues += "Management agent is not a recognised value: $($Device.managementAgent)"
        }
    }
    else {
        $managementStatus = "Unknown"
        $healthScore -= $HealthWeights.AgentMissing
        $healthIssues += "Management agent missing"
    }

    # Check 5: Operating system
    $osStatus = "Healthy"
    if ($Device.operatingSystem) {
        if ($Device.operatingSystem -notin @("Windows", "iOS", "Android", "macOS")) {
            $osStatus = "Unsupported"
            $healthScore -= $HealthWeights.OsUnsupported
            $healthIssues += "Unsupported operating system: $($Device.operatingSystem)"
        }
    }

    # Check 6: Storage space (if available)
    $storageStatus = "Healthy"
    if ($Device.totalStorageSpaceInBytes -and $Device.freeStorageSpaceInBytes) {
        $usedPercent = (($Device.totalStorageSpaceInBytes - $Device.freeStorageSpaceInBytes) / $Device.totalStorageSpaceInBytes) * 100
        if ($usedPercent -gt 90) {
            $storageStatus = "Critical"
            $healthScore -= $HealthWeights.StorageCritical
            $healthIssues += "Storage is over 90% full"
        }
        elseif ($usedPercent -gt 80) {
            $storageStatus = "Warning"
            $healthScore -= $HealthWeights.StorageWarning
            $healthIssues += "Storage is over 80% full"
        }
    }

    $overallHealth = "Healthy"
    if ($healthScore -lt 50) { $overallHealth = "Critical" }
    elseif ($healthScore -lt 70) { $overallHealth = "Warning" }
    elseif ($healthScore -lt 90) { $overallHealth = "Fair" }

    [PSCustomObject][ordered]@{
        DeviceId          = $Device.id
        DeviceName        = $Device.deviceName
        UserPrincipalName = $Device.userPrincipalName
        OverallHealth     = $overallHealth
        HealthScore       = $healthScore
        EnrollmentStatus  = $enrollmentStatus
        EnrollmentDate    = $Device.enrolledDateTime
        SyncStatus        = $syncStatus
        LastSyncDateTime  = $Device.lastSyncDateTime
        ComplianceStatus  = $complianceStatus
        ComplianceState   = $Device.complianceState
        ManagementStatus  = $managementStatus
        ManagementAgent   = $Device.managementAgent
        OSStatus          = $osStatus
        OperatingSystem   = $Device.operatingSystem
        OSVersion         = $Device.osVersion
        StorageStatus     = $storageStatus
        TotalStorageGB    = if ($Device.totalStorageSpaceInBytes) { [math]::Round($Device.totalStorageSpaceInBytes / 1GB, 2) } else { $null }
        FreeStorageGB     = if ($Device.freeStorageSpaceInBytes) { [math]::Round($Device.freeStorageSpaceInBytes / 1GB, 2) } else { $null }
        HealthIssues      = ($healthIssues -join '; ')
        HealthIssueCount  = $healthIssues.Count
    }
}

# Main script execution wrapped in try-catch for error handling
try
{
    Write-Host "Connecting to Microsoft Graph API..." -ForegroundColor Yellow
    $headers = Get-IntuneGraphHeaders -AppRegistration $credential
    Write-Host "Successfully connected to Microsoft Graph API." -ForegroundColor Green

    if ($DeviceId) {
        Write-Host "Checking health for device: $DeviceId" -ForegroundColor Yellow

        $device = Invoke-GraphApiWithRetry -Uri "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices('$DeviceId')" -Headers $headers -Method Get
        if ($null -eq $device) {
            Write-Error "Device not found or API returned null response for device ID: $DeviceId"
            exit 1
        }
        $devices = @($device)
    }
    else {
        Write-Host "Checking health for all devices..." -ForegroundColor Yellow
        $devices = @(Get-GraphApiAllPages -Uri "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices" -Headers $headers)
    }

    Write-Host "Found $($devices.Count) device(s). Checking health..." -ForegroundColor Cyan

    $now = Get-Date
    $deviceHealthResults = @($devices | ForEach-Object { Get-DeviceHealthAssessment -Device $_ -Now $now })

    # Display results
    Write-Host "`nDevice Health Results:" -ForegroundColor Cyan
    Write-Host "=====================" -ForegroundColor Cyan

    if ($deviceHealthResults.Count -eq 0) {
        Write-Host "No devices found matching the specified criteria." -ForegroundColor Yellow
    }
    else {
        $healthyDevices = @($deviceHealthResults | Where-Object { $_.OverallHealth -eq "Healthy" })
        $fairDevices = @($deviceHealthResults | Where-Object { $_.OverallHealth -eq "Fair" })
        $warningDevices = @($deviceHealthResults | Where-Object { $_.OverallHealth -eq "Warning" })
        $criticalDevices = @($deviceHealthResults | Where-Object { $_.OverallHealth -eq "Critical" })

        Write-Host "`nHealth Summary:" -ForegroundColor Cyan
        Write-Host "  Healthy: $($healthyDevices.Count)" -ForegroundColor Green
        Write-Host "  Fair: $($fairDevices.Count)" -ForegroundColor Yellow
        Write-Host "  Warning: $($warningDevices.Count)" -ForegroundColor $(if ($warningDevices.Count -gt 0) { 'Yellow' } else { 'White' })
        Write-Host "  Critical: $($criticalDevices.Count)" -ForegroundColor $(if ($criticalDevices.Count -gt 0) { 'Red' } else { 'White' })

        foreach ($health in $deviceHealthResults) {
            $healthColor = switch ($health.OverallHealth) {
                "Healthy" { "Green" }
                "Fair" { "Yellow" }
                "Warning" { "Yellow" }
                "Critical" { "Red" }
                default { "White" }
            }

            Write-Host "`nDevice: $($health.DeviceName)" -ForegroundColor $healthColor
            Write-Host "  Overall Health: $($health.OverallHealth) (Score: $($health.HealthScore))" -ForegroundColor $healthColor
            Write-Host "  User: $($health.UserPrincipalName)" -ForegroundColor White
            Write-Host "  Enrollment: $($health.EnrollmentStatus)" -ForegroundColor White
            Write-Host "  Sync: $($health.SyncStatus) (Last: $($health.LastSyncDateTime))" -ForegroundColor White
            Write-Host "  Compliance: $($health.ComplianceStatus)" -ForegroundColor White
            Write-Host "  Management: $($health.ManagementStatus) ($($health.ManagementAgent))" -ForegroundColor White
            if ($health.HealthIssueCount -gt 0) {
                Write-Host "  Issues: $($health.HealthIssueCount)" -ForegroundColor Red
                foreach ($issue in ($health.HealthIssues -split '; ')) {
                    Write-Host "    - $issue" -ForegroundColor Red
                }
            }
        }

        # Export to CSV if path is specified
        if ($ExportPath) {
            $exportDirectory = Split-Path -Path $ExportPath -Parent
            if ($exportDirectory -and -not (Test-Path -Path $exportDirectory)) {
                New-Item -Path $exportDirectory -ItemType Directory -Force | Out-Null
            }

            $deviceHealthResults | ConvertTo-SafeCsvRecord | Export-Csv -Path $ExportPath -NoTypeInformation -Encoding UTF8
            Write-Host "`nResults exported to: $ExportPath" -ForegroundColor Green

            if (-not (Test-Path -Path $ExportPath)) {
                Write-Error "Export file was not created successfully at: $ExportPath"
                exit 1
            }
        }
    }

    Write-Host "`nHealth check completed successfully. Checked $($deviceHealthResults.Count) device(s)." -ForegroundColor Green
}
# Error handling block - catches exceptions during Graph API calls
catch
{
    $errMsg = $_.Exception.Message
    Write-Error "Get-IntuneDeviceHealth: Failed to check device health - $errMsg"

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
