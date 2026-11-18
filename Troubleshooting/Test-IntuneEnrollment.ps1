<#
.SYNOPSIS
    Tests if device is properly enrolled in Intune.

.DESCRIPTION
    This script checks the local device to verify if it is properly enrolled in Microsoft Intune.
    It reads the MDM enrollment records under HKLM:\SOFTWARE\Microsoft\Enrollments, picks the ones
    whose ProviderID is "MS DM Server" (the Intune MDM provider), and checks that the enrollment
    state says enrolled. It also reports the enrolling user, the Intune device ID and first sync
    time when they exist, and the state of the Intune Management Extension service.
    The script can be run locally on the device to verify enrollment status.

    The Enrollments key always holds subkeys that are not enrollments (Context, Status,
    ValidNodePaths and others). The script skips them instead of failing on them.

.EXAMPLE
    .\Test-IntuneEnrollment.ps1

.NOTES
    Exit Codes:
    - 0: Device is enrolled in Intune (an enrollment with ProviderID "MS DM Server" and EnrollmentState 1)
    - 1: Device is not enrolled, enrollment state is not "enrolled", or an error occurred
#>

[CmdletBinding()]
param()

# Read one registry value without throwing when the value does not exist.
# Get-ItemPropertyValue throws a terminating error for a missing value and -ErrorAction
# SilentlyContinue does not stop that, so read the whole key and look for the property instead.
function Get-RegistryValueOrNull {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$Path,

        [Parameter(Mandatory=$true)]
        [string]$Name
    )

    $properties = Get-ItemProperty -Path $Path -ErrorAction SilentlyContinue
    if ($null -eq $properties) { return $null }
    $property = $properties.PSObject.Properties[$Name]
    if ($null -eq $property) { return $null }
    return $property.Value
}

# Collect the MDM enrollment records that belong to Intune.
# Intune's MDM provider ID is "MS DM Server". Subkeys without a ProviderID are not enrollments.
function Get-IntuneEnrollmentRecord {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [string]$EnrollmentsPath = "HKLM:\SOFTWARE\Microsoft\Enrollments"
    )

    $records = @()
    if (-not (Test-Path -Path $EnrollmentsPath)) { return $records }

    foreach ($key in @(Get-ChildItem -Path $EnrollmentsPath -ErrorAction SilentlyContinue)) {
        $providerId = Get-RegistryValueOrNull -Path $key.PSPath -Name "ProviderID"
        if (-not $providerId) { continue }

        $dmClientPath = Join-Path $key.PSPath "DMClient\MS DM Server"
        $records += [PSCustomObject]@{
            KeyName         = $key.PSChildName
            ProviderID      = $providerId
            IsIntune        = ($providerId -eq 'MS DM Server')
            EnrollmentState = Get-RegistryValueOrNull -Path $key.PSPath -Name "EnrollmentState"
            EnrollmentType  = Get-RegistryValueOrNull -Path $key.PSPath -Name "EnrollmentType"
            UPN             = Get-RegistryValueOrNull -Path $key.PSPath -Name "UPN"
            FirstSyncTime   = Get-RegistryValueOrNull -Path $key.PSPath -Name "FirstSyncTime"
            IntuneDeviceId  = Get-RegistryValueOrNull -Path $dmClientPath -Name "EntDMID"
        }
    }
    return $records
}

# Main script execution wrapped in try-catch for error handling
try
{
    Write-Host "Testing Intune enrollment status..." -ForegroundColor Yellow
    Write-Host "====================================" -ForegroundColor Yellow

    $enrollmentIssues = @()

    # Check 1: MDM enrollment records
    Write-Host "`n[1/3] Checking MDM enrollment registry..." -ForegroundColor Cyan
    $mdmEnrollmentPath = "HKLM:\SOFTWARE\Microsoft\Enrollments"
    if (-not (Test-Path -Path $mdmEnrollmentPath)) {
        $enrollmentIssues += "MDM enrollment registry path not found"
        Write-Host "  MDM enrollment registry path not found." -ForegroundColor Red
    }

    $records = @(Get-IntuneEnrollmentRecord -EnrollmentsPath $mdmEnrollmentPath)
    $intuneRecords = @($records | Where-Object { $_.IsIntune })

    if ($records.Count -gt 0) {
        Write-Host "  Found $($records.Count) enrollment record(s), $($intuneRecords.Count) with the Intune provider (MS DM Server)." -ForegroundColor Green
    }
    else {
        $enrollmentIssues += "No enrollment records with a ProviderID found in registry"
        Write-Host "  No enrollment records found." -ForegroundColor Red
    }
    foreach ($record in $records) {
        Write-Host "  $($record.KeyName): ProviderID=$($record.ProviderID) EnrollmentState=$($record.EnrollmentState) EnrollmentType=$($record.EnrollmentType)" -ForegroundColor White
    }

    # Check 2: enrollment state. EnrollmentState 1 means enrolled.
    Write-Host "`n[2/3] Checking enrollment state..." -ForegroundColor Cyan
    $enrolledRecord = $intuneRecords | Where-Object { "$($_.EnrollmentState)" -eq '1' } | Select-Object -First 1
    $isEnrolled = ($null -ne $enrolledRecord)

    if ($isEnrolled) {
        Write-Host "  Enrolled. User: $($enrolledRecord.UPN)" -ForegroundColor Green
        if ($enrolledRecord.IntuneDeviceId) { Write-Host "  Intune device ID: $($enrolledRecord.IntuneDeviceId)" -ForegroundColor White }
        if ($enrolledRecord.FirstSyncTime) { Write-Host "  First sync: $($enrolledRecord.FirstSyncTime)" -ForegroundColor White }
    }
    elseif ($intuneRecords.Count -gt 0) {
        $states = ($intuneRecords | ForEach-Object { $_.EnrollmentState }) -join ', '
        $enrollmentIssues += "Intune enrollment record found but EnrollmentState is not 1 (found: $states)"
        Write-Host "  Intune enrollment record found, but its state is not 'enrolled' (EnrollmentState: $states)." -ForegroundColor Red
    }
    else {
        $enrollmentIssues += "No enrollment with ProviderID 'MS DM Server' found"
        Write-Host "  No Intune (MS DM Server) enrollment found." -ForegroundColor Red
    }

    # Check 3: Intune Management Extension service
    Write-Host "`n[3/3] Checking Intune Management Extension..." -ForegroundColor Cyan
    $imeService = Get-Service -Name "IntuneManagementExtension" -ErrorAction SilentlyContinue
    if ($imeService) {
        Write-Host "  Intune Management Extension service found." -ForegroundColor Green
        Write-Host "  Service Status: $($imeService.Status)" -ForegroundColor $(if ($imeService.Status -eq 'Running') { 'Green' } else { 'Yellow' })
        if ($imeService.Status -ne 'Running') {
            $enrollmentIssues += "Intune Management Extension service is not running"
        }
    }
    else {
        Write-Host "  Intune Management Extension service not found (installed only once a Win32 app or script is assigned)." -ForegroundColor Yellow
    }

    # Summary
    Write-Host "`n====================================" -ForegroundColor Yellow
    Write-Host "Enrollment Test Summary" -ForegroundColor Cyan
    Write-Host "====================================" -ForegroundColor Yellow

    if ($isEnrolled) {
        Write-Host "`nResult: Device is enrolled in Intune." -ForegroundColor Green
        if ($enrollmentIssues.Count -gt 0) {
            Write-Host "`nIssues Found:" -ForegroundColor Yellow
            foreach ($issue in $enrollmentIssues) {
                Write-Host "  - $issue" -ForegroundColor Yellow
            }
        }
        exit 0
    }
    else {
        Write-Host "`nResult: Device does not appear to be enrolled in Intune." -ForegroundColor Red
        if ($enrollmentIssues.Count -gt 0) {
            Write-Host "`nIssues Found:" -ForegroundColor Red
            foreach ($issue in $enrollmentIssues) {
                Write-Host "  - $issue" -ForegroundColor Red
            }
        }
        exit 1
    }
}
# Error handling block - catches exceptions during enrollment checks
catch
{
    $errMsg = $_.Exception.Message
    Write-Error "Test-IntuneEnrollment: Failed to test Intune enrollment - $errMsg"
    if ($PSBoundParameters.ContainsKey('Verbose')) {
        Write-Verbose "Stack Trace: $($_.ScriptStackTrace)"
        if ($_.Exception.InnerException) {
            Write-Verbose "Inner Exception: $($_.Exception.InnerException.Message)"
        }
    }
    exit 1
}
