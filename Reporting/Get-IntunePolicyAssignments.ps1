<#
.SYNOPSIS
    Retrieves all Intune policy assignments (configuration profiles, compliance policies).

.DESCRIPTION
    This script connects to Microsoft Graph API and retrieves all Intune policy assignments
    including configuration profiles and compliance policies. It shows which policies are
    assigned to which groups or users and the assignment intent.

    A policy with no assignments gets one row with TargetType "None" and TargetName
    "No assignments", so unassigned policies show up in the report. A policy whose assignments
    could not be read gets one row with TargetType "Error". If any policy has an error row the
    script exits 1 at the end, so an incomplete report is not mistaken for a complete one.

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

.PARAMETER PolicyType
    Optional. Filter by policy type: "Configuration" or "Compliance". If not specified, retrieves both.

.PARAMETER ExportPath
    Optional. Path to export results to CSV file. If not specified, results are displayed only.

.EXAMPLE
    .\Get-IntunePolicyAssignments.ps1 -AppId 'your-app-id' -TenantId 'your-tenant-id' -ClientSecretSecure (Read-Host -AsSecureString 'Client secret')

.EXAMPLE
    $env:INTUNE_APP_ID = 'your-app-id'; $env:INTUNE_TENANT_ID = 'your-tenant-id'; $env:INTUNE_CLIENT_SECRET = '<from your vault>'
    .\Get-IntunePolicyAssignments.ps1 -PolicyType "Configuration" -ExportPath 'C:\Temp\PolicyAssignments.csv'

.NOTES
    Requires: Entra ID App Registration with the DeviceManagementConfiguration.Read.All APPLICATION
    permission (admin consent granted) and Group.Read.All to resolve group names.
    Exit Codes:
    - 0: Report complete
    - 1: A failure, or at least one policy's assignments could not be retrieved
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
    [ValidateSet("Configuration", "Compliance", "All")]
    [string]$PolicyType = "All",

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

# Resolve a group ID to its display name. Cached so each group is looked up once.
# A failed lookup falls back to the group ID; the assignment itself is still reported.
$script:groupNameCache = @{}
function Resolve-GroupName {
    param([string]$GroupId)

    if ($script:groupNameCache.ContainsKey($GroupId)) { return $script:groupNameCache[$GroupId] }

    $name = $GroupId
    try {
        $group = Invoke-GraphApiWithRetry -Uri "https://graph.microsoft.com/v1.0/groups/$GroupId" -Headers $script:headers -Method Get
        if ($null -ne $group -and $null -ne $group.displayName) { $name = $group.displayName }
    }
    catch {
        Write-Verbose "Failed to retrieve group name for Group ID: $GroupId - $($_.Exception.Message)"
    }
    $script:groupNameCache[$GroupId] = $name
    return $name
}

# Build the report rows for one policy. Always returns at least one row:
# the assignments, a "No assignments" row, or an "Error" row.
function Get-PolicyAssignmentRow {
    param(
        [Parameter(Mandatory=$true)] [string]$Type,
        [Parameter(Mandatory=$true)] $Policy,
        [Parameter(Mandatory=$true)] [string]$AssignmentsUrl
    )

    # Column order is fixed here so the CSV always has the same columns in the same order
    function New-Row($AssignmentId, $TargetType, $TargetId, $TargetName, $Intent, $Source) {
        [PSCustomObject][ordered]@{
            PolicyType        = $Type
            PolicyId          = $Policy.id
            PolicyName        = $Policy.displayName
            PolicyDescription = $Policy.description
            AssignmentId      = $AssignmentId
            TargetType        = $TargetType
            TargetId          = $TargetId
            TargetName        = $TargetName
            Intent            = $Intent
            Source            = $Source
        }
    }

    try {
        # Count the list, not $null: an empty list parses as an empty array, never as $null
        $assignments = @(Get-GraphApiAllPages -Uri $AssignmentsUrl -Headers $script:headers)
    }
    catch {
        Write-Verbose "Failed to retrieve assignments for $Type policy '$($Policy.displayName)': $($_.Exception.Message)"
        $script:assignmentErrorCount++
        return (New-Row $null "Error" $null "Error retrieving assignments: $($_.Exception.Message)" $null $null)
    }

    if ($assignments.Count -eq 0) {
        return (New-Row $null "None" $null "No assignments" $null $null)
    }

    foreach ($assignment in $assignments) {
        $targetGroupId = $assignment.target.groupId
        $targetName = $assignment.target.'@odata.type'
        if ($targetGroupId) { $targetName = Resolve-GroupName -GroupId $targetGroupId }

        New-Row $assignment.id $assignment.target.'@odata.type' $targetGroupId $targetName $assignment.intent $assignment.source
    }
}

# Main script execution wrapped in try-catch for error handling
try
{
    Write-Host "Connecting to Microsoft Graph API..." -ForegroundColor Yellow
    $script:headers = Get-IntuneGraphHeaders -Credential $credential
    Write-Host "Successfully connected to Microsoft Graph API." -ForegroundColor Green

    $script:assignmentErrorCount = 0
    $policyAssignments = @()

    # Configuration profiles define device settings and restrictions
    if ($PolicyType -eq "All" -or $PolicyType -eq "Configuration") {
        Write-Host "`nQuerying configuration profiles..." -ForegroundColor Yellow
        $allConfigProfiles = @(Get-GraphApiAllPages -Uri "https://graph.microsoft.com/v1.0/deviceManagement/deviceConfigurations" -Headers $script:headers)

        $profileCount = 0
        foreach ($configProfile in $allConfigProfiles) {
            $profileCount++
            Write-Progress -Activity "Processing configuration profiles" -Status "Processing profile $profileCount of $($allConfigProfiles.Count): $($configProfile.displayName)" -PercentComplete (($profileCount / $allConfigProfiles.Count) * 100)
            Write-Host "  Processing configuration profile: $($configProfile.displayName)" -ForegroundColor Cyan

            $url = "https://graph.microsoft.com/v1.0/deviceManagement/deviceConfigurations('$($configProfile.id)')/assignments"
            $policyAssignments += @(Get-PolicyAssignmentRow -Type "Configuration" -Policy $configProfile -AssignmentsUrl $url)
        }
        Write-Progress -Activity "Processing configuration profiles" -Completed
    }

    # Compliance policies define requirements devices must meet
    if ($PolicyType -eq "All" -or $PolicyType -eq "Compliance") {
        Write-Host "`nQuerying compliance policies..." -ForegroundColor Yellow
        $allCompliancePolicies = @(Get-GraphApiAllPages -Uri "https://graph.microsoft.com/v1.0/deviceManagement/deviceCompliancePolicies" -Headers $script:headers)

        $policyCount = 0
        foreach ($policy in $allCompliancePolicies) {
            $policyCount++
            Write-Progress -Activity "Processing compliance policies" -Status "Processing policy $policyCount of $($allCompliancePolicies.Count): $($policy.displayName)" -PercentComplete (($policyCount / $allCompliancePolicies.Count) * 100)
            Write-Host "  Processing compliance policy: $($policy.displayName)" -ForegroundColor Cyan

            $url = "https://graph.microsoft.com/v1.0/deviceManagement/deviceCompliancePolicies('$($policy.id)')/assignments"
            $policyAssignments += @(Get-PolicyAssignmentRow -Type "Compliance" -Policy $policy -AssignmentsUrl $url)
        }
        Write-Progress -Activity "Processing compliance policies" -Completed
    }

    # Display results
    Write-Host "`nPolicy Assignments:" -ForegroundColor Cyan
    Write-Host "===================" -ForegroundColor Cyan

    if ($policyAssignments.Count -eq 0) {
        Write-Host "No policies found." -ForegroundColor Yellow
    }
    else {
        foreach ($type in @("Configuration", "Compliance")) {
            $rows = @($policyAssignments | Where-Object { $_.PolicyType -eq $type })
            if ($rows.Count -eq 0) { continue }

            $assigned = @($rows | Where-Object { $_.TargetType -notin @("None", "Error") })
            $unassigned = @($rows | Where-Object { $_.TargetType -eq "None" })
            $failed = @($rows | Where-Object { $_.TargetType -eq "Error" })

            Write-Host "${type}: $($assigned.Count) assignment(s), $($unassigned.Count) policy(ies) with no assignment, $($failed.Count) policy(ies) with an error" -ForegroundColor Green
            foreach ($row in $assigned) {
                Write-Host "  Policy: $($row.PolicyName)" -ForegroundColor White
                Write-Host "    Target: $($row.TargetName) ($($row.TargetType))" -ForegroundColor Gray
                Write-Host "    Intent: $($row.Intent)" -ForegroundColor Gray
            }
            foreach ($row in $unassigned) { Write-Host "  Not assigned: $($row.PolicyName)" -ForegroundColor Yellow }
            foreach ($row in $failed) { Write-Host "  Error: $($row.PolicyName) - $($row.TargetName)" -ForegroundColor Red }
        }

        # Export to CSV if path is specified
        if ($ExportPath) {
            $exportDirectory = Split-Path -Path $ExportPath -Parent
            if ($exportDirectory -and -not (Test-Path -Path $exportDirectory)) {
                New-Item -Path $exportDirectory -ItemType Directory -Force | Out-Null
            }

            $policyAssignments | ConvertTo-SafeCsvRecord | Export-Csv -Path $ExportPath -NoTypeInformation -Encoding UTF8
            Write-Host "`nResults exported to: $ExportPath" -ForegroundColor Green

            if (-not (Test-Path -Path $ExportPath)) {
                Write-Error "Export file was not created successfully at: $ExportPath"
                exit 1
            }
        }
    }

    if ($script:assignmentErrorCount -gt 0) {
        Write-Error "The report is incomplete: assignments could not be retrieved for $($script:assignmentErrorCount) policy(ies). They are marked TargetType 'Error'."
        exit 1
    }

    Write-Host "`nQuery completed successfully. Found $($policyAssignments.Count) policy assignment row(s)." -ForegroundColor Green
}
# Error handling block - catches exceptions during Graph API calls
catch
{
    $errMsg = $_.Exception.Message
    Write-Error "Get-IntunePolicyAssignments: Failed to retrieve policy assignments - $errMsg"

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
