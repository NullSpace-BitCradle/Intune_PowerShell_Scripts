<#
.SYNOPSIS
    Retrieves all applications published in Microsoft Intune and exports their assignment details.

.DESCRIPTION
    This script retrieves all applications published in Microsoft Intune and exports their
    assignment details to a CSV file. It connects to Microsoft Graph API using app registration
    credentials and retrieves information about each app including its type, version, assignments,
    and target groups. It uses plain REST calls and the shared IntuneCommon module; it does not need
    the Microsoft.Graph PowerShell SDK.

    Each assignment becomes one row. TargetType says what the assignment targets:
    "All Users", "All Devices", "Group", or "Excluded group". An excluded group is a group the app is
    NOT deployed to, and is never shown as a targeted group. Apps with no assignments get one row with
    Group "Not Assigned".

    The query uses the Graph beta endpoint with $expand=Assignments,Category,Version, as the original
    script did, and reads every result page.

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

.PARAMETER ExportCSVpath
    Optional. Where to write the CSV file. Default is $env:TEMP\Get-IntuneAllAppsAssignmentDetails.csv.

.EXAMPLE
    .\Get-IntuneAllAppsAssignmentDetails.ps1 -AppId 'your-app-id' -TenantId 'your-tenant-id' -ClientSecretSecure (Read-Host -AsSecureString 'Client secret')

.EXAMPLE
    .\Get-IntuneAllAppsAssignmentDetails.ps1 -ExportCSVpath 'C:\Reports\AppAssignments.csv'

.NOTES
    Requires: Entra ID App Registration with the DeviceManagementApps.Read.All and Group.Read.All
    APPLICATION permissions (admin consent granted).
    Exit Codes:
    - 0: Export written (or no apps found)
    - 1: A failure occurred
#>

[CmdletBinding()]
# Define script parameters for credential input and the export location
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
    [string]$ExportCSVpath = (Join-Path $env:TEMP "Get-IntuneAllAppsAssignmentDetails.csv")
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

# Create the export directory if it does not exist
$exportDirectory = Split-Path -Path $ExportCSVpath -Parent
if ($exportDirectory -and -not (Test-Path -Path $exportDirectory)) {
    try {
        New-Item -Path $exportDirectory -ItemType Directory -Force -ErrorAction Stop | Out-Null
        Write-Host "Created export directory: $exportDirectory" -ForegroundColor Green
    }
    catch {
        Write-Error "Failed to create export directory: $($_.Exception.Message)"
        exit 1
    }
}

# Convert the OData type identifier to a human-readable app type name
function Get-AppTypeName {
    param([string]$ODataType)

    switch ($ODataType) {
        "#microsoft.graph.androidLobApp" { 'Android LOB' }
        "#microsoft.graph.androidStoreApp" { 'Google Play' }
        "#microsoft.graph.androidManagedStoreWebApp" { 'Android Managed Store Web App' }
        "#microsoft.graph.managedAndroidLobApp" { 'Managed Android LOB' }
        "#microsoft.graph.managedAndroidStoreApp" { 'Managed Google Play' }
        "#microsoft.graph.androidForWorkApp" { 'Android for Work' }
        "#microsoft.graph.iosLobApp" { 'iOS LOB' }
        "#microsoft.graph.iosStoreApp" { 'iOS Store' }
        "#microsoft.graph.managedIOSLobApp" { 'Managed iOS LOB' }
        "#microsoft.graph.managedIOSStoreApp" { 'Managed iOS Store' }
        "#microsoft.graph.iosVppApp" { 'iOS VPP' }
        "#microsoft.graph.iosVppEBook" { 'iOS VPP Ebook' }
        "#microsoft.graph.iosiPadOSWebClip" { 'iOS Weblink' }
        "#microsoft.graph.webApp" { 'Web Link' }
        "#microsoft.graph.microsoftStoreForBusiness" { 'Microsoft Store' }
        "#microsoft.graph.winGetApp" { 'New Microsoft Store' }
        "#microsoft.graph.windowsStoreApp" { 'Windows Store App' }
        "#microsoft.graph.windowsPhoneXAP" { 'Windows Phone XAP' }
        "#microsoft.graph.win32LobApp" { 'Win32' }
        "#microsoft.graph.windowsAppX" { 'Windows AppX' }
        "#microsoft.graph.windowsMicrosoftEdgeApp" { 'Intune Windows Built-in Edge App' }
        "#microsoft.graph.windowsMobileMSI" { 'Windows MSI' }
        "#microsoft.graph.windowsUniversalAppX" { 'Windows Universal AppX' }
        "#microsoft.graph.windowsUniversalAppXContainedApp" { 'Windows Universal AppX Contained App' }
        "#microsoft.graph.windowsWebApp" { 'Windows Web App' }
        "#microsoft.graph.officeSuiteApp" { 'Intune Windows Built-in M365 App for Enterprise' }
        "#microsoft.graph.macOSDmgApp" { 'MacOS DMG' }
        "#microsoft.graph.macOSLobApp" { 'MacOS LOB' }
        "#microsoft.graph.macOSMdatpApp" { 'MacOS MDATP' }
        "#microsoft.graph.macOSMicrosoftDefenderApp" { 'MacOS Defender' }
        "#microsoft.graph.macOSMicrosoftEdgeApp" { 'MacOS Edge' }
        "#microsoft.graph.macOSOfficeSuiteApp" { 'Intune MacOS Built-in M365 App for Enterprise' }
        "#microsoft.graph.macOSPkgApp" { 'MacOS PKG' }
        "#microsoft.graph.macOsVppApp" { 'MacOS VPP' }
        default { 'Unknown' }
    }
}

# Map an assignment target type to the label shown in the TargetType column.
# exclusionGroupAssignmentTarget is a group the app is NOT deployed to.
function Get-TargetTypeName {
    param([string]$ODataType)

    if ($ODataType -like "*allLicensedUsersAssignmentTarget") { return 'All Users' }
    if ($ODataType -like "*allDevicesAssignmentTarget") { return 'All Devices' }
    if ($ODataType -like "*exclusionGroupAssignmentTarget") { return 'Excluded group' }
    if ($ODataType -like "*groupAssignmentTarget") { return 'Group' }
    return "$ODataType"
}

# Resolve a group ID to its display name. Cached so each group is looked up once.
$script:groupNameCache = @{}
function Resolve-GroupName {
    param([string]$GroupId)

    if ($script:groupNameCache.ContainsKey($GroupId)) { return $script:groupNameCache[$GroupId] }

    $name = $GroupId
    try {
        $group = Invoke-GraphApiWithRetry -Uri "https://graph.microsoft.com/v1.0/groups/$GroupId" -Headers $script:headers -Method Get
        if ($null -ne $group -and $null -ne $group.displayName) { $name = $group.displayName }
        else { Write-Warning "Could not retrieve group name for Group ID: $GroupId" }
    }
    catch {
        Write-Verbose "Failed to retrieve group name for Group ID: $GroupId - $($_.Exception.Message)"
    }
    $script:groupNameCache[$GroupId] = $name
    return $name
}

# Build the output rows for one app: one per assignment, or one "Not Assigned" row
function Get-AppRow {
    param([Parameter(Mandatory=$true)] $App)

    $appType = Get-AppTypeName -ODataType $App.'@odata.type'
    $appVer = $App.displayVersion
    $name = "$($App.displayName)"
    $assignments = @($App.assignments)

    if ($assignments.Count -eq 0) {
        Write-Host "No assignments for this app"
        [PSCustomObject][ordered]@{ Name = $name; Platform = $appType; Version = "$appVer"; Assignment = ""; Group = "Not Assigned"; TargetType = "None" }
        return
    }

    foreach ($assignment in $assignments) {
        Write-Host "Assignment intent: $($assignment.intent)"
        $targetType = Get-TargetTypeName -ODataType $assignment.target.'@odata.type'

        if ($targetType -in @('All Users', 'All Devices')) {
            $groupName = $targetType
        }
        elseif ($assignment.target.groupId) {
            $groupName = Resolve-GroupName -GroupId $assignment.target.groupId
        }
        else {
            $groupName = $targetType
        }
        Write-Host "Target: $targetType, Group Name: $groupName"

        [PSCustomObject][ordered]@{ Name = $name; Platform = $appType; Version = "$appVer"; Assignment = "$($assignment.intent)"; Group = $groupName; TargetType = $targetType }
    }
}

try {
    Write-Host "Connecting to Microsoft Graph API..." -ForegroundColor Yellow
    $script:headers = Get-IntuneGraphHeaders -AppRegistration $credential

    # Beta is used for the Assignments/Category/Version expand, as before. Every page is read: $expand
    # makes Graph return small pages, so a single request silently truncated the report on a large tenant.
    $uri = "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps?`$expand=Assignments,Category,Version"
    $Apps = @(Get-GraphApiAllPages -Uri $uri -Headers $script:headers)
}
catch {
    $ex = $_.Exception
    if ($ex.Response) {
        Write-Error "Get-IntuneAllAppsAssignmentDetails: Request failed with HTTP Status $($ex.Response.StatusCode.value__) - $($ex.Message)"
    }
    else {
        Write-Error "Get-IntuneAllAppsAssignmentDetails: Request failed - $($ex.Message)"
    }
    exit 1
}

if ($Apps.Count -gt 0) {
    Write-Host "Number of Apps found is: $($Apps.Count)" -ForegroundColor Cyan
}
else {
    Write-Host "No apps found." -ForegroundColor Yellow
    exit 0
}

$Output = New-Object System.Collections.ArrayList
$appCount = 0
foreach ($App in $Apps) {
    $appCount++
    Write-Progress -Activity "Processing Intune Apps" -Status "Processing app $appCount of $($Apps.Count): $($App.displayName)" -PercentComplete (($appCount / $Apps.Count) * 100)
    Write-Host "App Name: $($App.displayName)" -ForegroundColor Yellow

    foreach ($row in @(Get-AppRow -App $App)) { [void]$Output.Add($row) }
}
Write-Progress -Activity "Processing Intune Apps" -Completed

# Export the collected data to CSV file, formula-safe
try {
    $Output | ConvertTo-SafeCsvRecord | Export-Csv -Path $ExportCSVpath -Encoding UTF8 -NoTypeInformation -ErrorAction Stop
    Write-Host "Exported $($Output.Count) row(s) to: $ExportCSVpath" -ForegroundColor Green
}
catch {
    Write-Error "Get-IntuneAllAppsAssignmentDetails: Failed to write $ExportCSVpath - $($_.Exception.Message)"
    exit 1
}
exit 0
