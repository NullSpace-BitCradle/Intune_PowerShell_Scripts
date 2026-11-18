# Intune PowerShell Scripts

PowerShell scripts for managing, troubleshooting and reporting on Microsoft Intune deployments: detection and remediation scripts for Intune Remediations, Graph API reports, device troubleshooting and a few security settings.

These scripts are tested with Pester against mocks. Nothing here has been run against a live tenant by the test suite. Read a script before you deploy it, run it with `-WhatIf` where it has one, and try it on a pilot device first.

## Table of Contents

- [Overview](#overview)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Project Structure](#project-structure)
- [Quick Start](#quick-start)
- [How Intune runs the detection and remediation scripts](#how-intune-runs-the-detection-and-remediation-scripts)
- [Script Categories](#script-categories)
  - [Detection & Remediation](#detection--remediation)
  - [Device Management](#device-management)
  - [Reporting & Analysis](#reporting--analysis)
  - [Service Management](#service-management)
  - [Connectivity & Testing](#connectivity--testing)
- [Common Module](#common-module)
- [Usage Examples](#usage-examples)
- [Exit Codes](#exit-codes)
- [Error Handling](#error-handling)
- [Security Considerations](#security-considerations)
- [Testing](#testing)
- [Contributing](#contributing)
- [Script Index](#script-index)

## Overview

The scripts are grouped by purpose and follow these rules:

- Error handling that ends in an exit code you can rely on. A script that could not finish does not exit 0.
- `-WhatIf` on every script that changes the machine. A `-WhatIf` run changes nothing and exits 0.
- Input validation on IDs, user names and paths.
- Reports that fail loudly. When a Graph request fails, the report row says so and the script exits 1. A blank value never stands for "the request failed".

## Prerequisites

### General Requirements

- **Windows 10/11** or **Windows Server 2016+**
- **Windows PowerShell 5.1** is the supported shell. The Graph reports and most troubleshooting scripts also run in PowerShell 7. `Start-MDMSync.ps1` needs Windows PowerShell 5.1 (Desktop edition): its Windows Runtime type does not load in PowerShell 7, and the script says so.
- **Administrator privileges** for scripts that change the machine or read protected logs (marked in the [Script Index](#script-index))

### For Graph API Scripts

The Graph scripts use plain REST calls with a client secret and the shared `IntuneCommon` module. They do not need the Microsoft.Graph PowerShell SDK and they do not install it.

You need an **Entra ID app registration** with these **Application** permissions (not Delegated), with **admin consent granted**. The scripts use the client credentials flow and the `.default` scope, so the permissions the app has consented are the permissions you get.

| Script | Application permissions it needs |
|---|---|
| `Get-IntuneDeviceDetails.ps1`, `Get-IntuneDeviceHealth.ps1` | `DeviceManagementManagedDevices.Read.All` |
| `Get-IntuneDeviceCompliance.ps1`, `Export-IntuneDeviceReport.ps1` | `DeviceManagementManagedDevices.Read.All`, `DeviceManagementConfiguration.Read.All` |
| `Get-IntunePolicyAssignments.ps1` | `DeviceManagementConfiguration.Read.All`, `Group.Read.All` (group names) |
| `Get-IntuneWin32AppDetails.ps1` | `DeviceManagementApps.Read.All` |
| `Get-IntuneAllAppsAssignmentDetails.ps1` | `DeviceManagementApps.Read.All`, `Group.Read.All` (group names) |

### App Registration Setup

1. Go to [Azure Portal](https://portal.azure.com), then **Entra ID**, then **App registrations**
2. Create a new app registration or use an existing one
3. Create a **Client Secret** and note the value (it is shown once)
4. Add the **Application** permissions from the table above and grant admin consent
5. Note the **Application (client) ID** and **Directory (tenant) ID**

## Installation

1. Clone or download this repository:

   ```powershell
   git clone https://github.com/NullSpace-BitCradle/Intune_PowerShell_Scripts.git
   cd Intune_PowerShell_Scripts
   ```

2. The Graph scripts import `Common\IntuneCommon.psd1` themselves. You only import it by hand to use its functions in your own scripts:

   ```powershell
   Import-Module .\Common\IntuneCommon.psd1
   ```

3. Give the Graph scripts their credentials. Environment variables are the simplest and keep the secret off the command line:

   ```powershell
   $env:INTUNE_APP_ID = "your-app-id"
   $env:INTUNE_TENANT_ID = "your-tenant-id"
   $env:INTUNE_CLIENT_SECRET = "your-client-secret"
   ```

   Or pass them as parameters. `-ClientSecret` takes plain text and lands in shell history and process listings, so prefer `-ClientSecretSecure` with a `SecureString`:

   ```powershell
   $secret = Read-Host -AsSecureString "Client secret"
   .\Reporting\Get-IntuneDeviceDetails.ps1 -AppId "your-app-id" -TenantId "your-tenant-id" -ClientSecretSecure $secret
   ```

## Project Structure

```
Intune_PowerShell_Scripts/
|-- Common/
|   |-- IntuneCommon.psd1                        # Module manifest
|   `-- IntuneCommon.psm1                        # Shared functions module
|-- Detection/
|   |-- Detect-MultipleIntuneMDMCert.ps1          # Detect duplicate MDM certificates
|   `-- Detect-OfficeUpdateChannel.ps1            # Detect Office update channel
|-- Remediation/
|   |-- Repair-MultipleIntuneMDMCert.ps1          # Remove duplicate MDM certificates
|   `-- Set-OfficeUpdateChannel.ps1               # Set Office to Semi-Annual channel
|-- Reporting/
|   |-- Export-IntuneDeviceReport.ps1             # Export comprehensive device reports
|   |-- Get-IntuneAllAppsAssignmentDetails.ps1    # Retrieve app assignment details
|   |-- Get-IntuneDeviceCompliance.ps1            # Retrieve device compliance status
|   |-- Get-IntuneDeviceDetails.ps1               # Retrieve device details
|   |-- Get-IntuneDeviceHealth.ps1                # Perform device health checks
|   |-- Get-IntunePolicyAssignments.ps1           # Retrieve policy assignments
|   `-- Get-IntuneWin32AppDetails.ps1             # Retrieve Win32 app details
|-- Security/
|   |-- Disable-PrintSpoolerService.ps1           # Disable Print Spooler service
|   |-- Disable-SmartCardLogonEnforcement.ps1     # Disable smart card logon enforcement
|   |-- Enable-PrintSpoolerService.ps1            # Enable Print Spooler service
|   `-- Enable-SmartCardLogonEnforcement.ps1      # Enable smart card logon enforcement
|-- Troubleshooting/
|   |-- Get-IntuneDeviceLogs.ps1                  # Collect Intune-related logs
|   |-- Start-MDMSync.ps1                         # Initiate MDM sync session
|   |-- Test-IntuneConnectivity.ps1               # Test connectivity to Intune endpoints
|   `-- Test-IntuneEnrollment.ps1                 # Test device enrollment status
|-- Tests/                                        # Pester tests (see Testing)
`-- .github/workflows/ci.yml                      # PSScriptAnalyzer and Pester
```

## Quick Start

### Example: Get Device Details

```powershell
# INTUNE_APP_ID, INTUNE_TENANT_ID and INTUNE_CLIENT_SECRET are set
.\Reporting\Get-IntuneDeviceDetails.ps1 -ExportPath "C:\Reports\Devices.csv"
```

### Example: Test Device Enrollment

```powershell
.\Troubleshooting\Test-IntuneEnrollment.ps1
```

### Example: Check Device Health

```powershell
.\Reporting\Get-IntuneDeviceHealth.ps1 -ExportPath "C:\Reports\HealthReport.csv"
```

## How Intune runs the detection and remediation scripts

The `Detect-*` and `Repair-*` / `Set-*` scripts follow the contract of **Intune Remediations** (also called proactive remediations):

- The **detection** script exits `0` when the device is fine and `1` when the remediation should run.
- The **remediation** script exits `0` on success and anything else on failure.
- In the Remediations script package, set **Run script in 64-bit PowerShell** to **Yes**. Intune runs scripts in 32-bit PowerShell by default. The Office scripts and the smart card scripts relaunch themselves in 64-bit PowerShell when they find they are in a 32-bit host, and forward `-WhatIf` and `-Verbose`, but the setting is the clean fix.

These scripts are not for **custom compliance** policies. Custom compliance needs a script that prints JSON and a rules file, and these scripts print text and use exit codes.

A device where the thing does not apply (no Office Click-to-Run) or cannot be checked (no network to Microsoft's release service) makes the Office detection script exit `0` with a message, so it does not go to remediation on every cycle. The message in the script output says which case it was.

## Script Categories

### Detection & Remediation

Detection scripts live in `Detection\`; remediation scripts live in `Remediation\`.

#### `Detect-MultipleIntuneMDMCert.ps1` (Detection)

Detects multiple Intune MDM Device CA certificates in the Local Machine certificate store. Use it as the detection script of a Remediation.

```powershell
.\Detection\Detect-MultipleIntuneMDMCert.ps1
```

**Exit Codes:**

- `0`: No remediation needed (0 or 1 certificate found)
- `1`: Remediation needed (more than 1 certificate found) or error occurred

---

#### `Repair-MultipleIntuneMDMCert.ps1` (Remediation)

Removes duplicate Intune MDM Device CA certificates, keeping the one with the newest `NotBefore` date.

```powershell
.\Remediation\Repair-MultipleIntuneMDMCert.ps1 [-WhatIf]
```

**Exit Codes:**

- `0`: Success (duplicates removed, none found, or a `-WhatIf` run)
- `1`: Error occurred

**Requirements:** Administrator privileges

**Note:** The older certificates are deleted without a backup, and the script does not check which certificate the enrollment currently references. It assumes the newest is the one in use. Run `-WhatIf` first and export the certificates you want to keep a copy of.

---

#### `Detect-OfficeUpdateChannel.ps1` (Detection)

Checks that Microsoft Office is on the Semi-Annual update channel and on the latest version of it.

```powershell
.\Detection\Detect-OfficeUpdateChannel.ps1
```

**Exit Codes:**

- `0`: Compliant, or not applicable (no Click-to-Run), or cannot determine (registry or Microsoft's release service not readable). The output says which.
- `1`: Not on the Semi-Annual channel, or on it but behind the latest version. The output says which.

**Requirements:** None to run. Applies to Office Click-to-Run installations.

---

#### `Set-OfficeUpdateChannel.ps1` (Remediation)

Sets Office to the Semi-Annual channel and starts an update through `OfficeC2RClient.exe` in `Common Files\Microsoft Shared\ClickToRun`.

```powershell
.\Remediation\Set-OfficeUpdateChannel.ps1 [-WhatIf]
```

**Exit Codes:**

- `0`: Success, already compliant, not applicable (no Click-to-Run), or a `-WhatIf` run
- `1`: Error occurred, including a missing updater

**Requirements:** Administrator privileges, Office Click-to-Run installation

---

### Device Management

#### `Get-IntuneDeviceDetails.ps1` (Reporting)

Retrieves information about Intune-managed devices: enrollment details, hardware, compliance state and management agent. All result pages are read.

```powershell
# Get all devices
.\Reporting\Get-IntuneDeviceDetails.ps1

# Get specific device
.\Reporting\Get-IntuneDeviceDetails.ps1 -DeviceId 'device-guid'

# Search by device name (substring match)
.\Reporting\Get-IntuneDeviceDetails.ps1 -DeviceName 'LAPTOP-01' -ExportPath 'C:\Reports\Devices.csv'
```

**Parameters:**

- `-DeviceId`: Specific device ID to query
- `-DeviceName`: Substring of the device name. Graph `contains()` does not expand wildcards, so `*` and `%` are removed from the value, not expanded.
- `-ExportPath`: Path to export CSV file
- `-AppId`, `-TenantId`, `-ClientSecretSecure` (or `-ClientSecret`): credentials, or use the environment variables

---

#### `Get-IntuneDeviceCompliance.ps1` (Reporting)

Retrieves compliance status for devices. For each device it reads that device's own compliance policy states, so `CompliancePolicies` reads like `Baseline (compliant); BitLocker (nonCompliant)` and `NonCompliantPolicies` lists the ones that are not compliant. Per-setting non-compliance reasons are not retrieved.

```powershell
.\Reporting\Get-IntuneDeviceCompliance.ps1
.\Reporting\Get-IntuneDeviceCompliance.ps1 -DeviceId 'device-guid' -ExportPath 'C:\Reports\Compliance.csv'
.\Reporting\Get-IntuneDeviceCompliance.ps1 -UserPrincipalName 'user@domain.com' -ExportPath 'C:\Reports\UserCompliance.csv'
```

**Parameters:**

- `-DeviceId`, `-UserPrincipalName`: limit the report to one device or one user's devices
- `-SkipPolicyStates`: skip the per-device policy request. That is one request per device; skip it on a large tenant.
- `-ExportPath`: Path to export CSV file
- Credentials as above

A device whose policy states cannot be read gets a `CollectionError` value and the script exits `1`.

---

#### `Get-IntuneDeviceHealth.ps1` (Reporting)

Scores each device out of 100 from enrollment, last sync, compliance state, management agent, operating system and storage. The weights are fixed values documented in the script header and are a rule of thumb, not a Microsoft measure.

```powershell
.\Reporting\Get-IntuneDeviceHealth.ps1
.\Reporting\Get-IntuneDeviceHealth.ps1 -DeviceId 'device-guid' -ExportPath 'C:\Reports\HealthReport.csv'
```

**Health check factors:**

- Enrolled or not
- Last sync time (a device that has never synced is reported as "Never Synced")
- Compliance state
- Management agent (any Graph `managementAgentType` value is fine; only `unknown` or missing is flagged)
- Operating system
- Storage space (if available)

---

#### `Test-IntuneEnrollment.ps1` (Troubleshooting)

Checks whether the device is enrolled in Intune. It reads the enrollment records under `HKLM:\SOFTWARE\Microsoft\Enrollments`, looks for one with ProviderID `MS DM Server` and EnrollmentState `1`, and reports the user, the Intune device ID, the first sync time and the state of the Intune Management Extension service.

```powershell
.\Troubleshooting\Test-IntuneEnrollment.ps1
```

**Exit Codes:**

- `0`: Enrolled in Intune
- `1`: Not enrolled, enrollment state is not "enrolled", or an error occurred

The script was checked against a device with no Intune enrollment and against mocked enrollments. It has not been run on an enrolled device.

---

#### `Start-MDMSync.ps1` (Troubleshooting)

Starts an MDM sync session between the device and Intune with the Windows Management API and waits for it to finish.

```powershell
# Default timeout (60 seconds)
.\Troubleshooting\Start-MDMSync.ps1

# Custom timeout and check interval
.\Troubleshooting\Start-MDMSync.ps1 -TimeoutSeconds 120 -CheckIntervalSeconds 10
```

**Exit Codes:**

- `0`: Sync completed with no error
- `1`: Session could not be created, or it completed with an extended error code, or an error occurred
- `2`: Sync did not complete within the timeout

**Parameters:**

- `-TimeoutSeconds`: Maximum time in seconds to wait for sync (default: 60)
- `-CheckIntervalSeconds`: Interval in seconds between status checks (default: 5)

**Requirements:** Windows PowerShell 5.1 (Desktop edition), Windows 10/11 with MDM enrollment. PowerShell 7 is refused with a clear message.

---

### Reporting & Analysis

#### `Get-IntuneAllAppsAssignmentDetails.ps1` (Reporting)

Retrieves all applications published in Intune and exports their assignment details to a CSV file. Each assignment is a row with the intent (`Assignment`), the group (`Group`) and what it targets (`TargetType`: `All Users`, `All Devices`, `Group` or `Excluded group`). An excluded group is a group the app is not deployed to. Apps with no assignment get one `Not Assigned` row.

```powershell
.\Reporting\Get-IntuneAllAppsAssignmentDetails.ps1 -ExportCSVpath 'C:\Reports\AppAssignments.csv'
```

**Parameters:**

- `-ExportCSVpath`: Path to export CSV file (default: `$env:TEMP\Get-IntuneAllAppsAssignmentDetails.csv`)
- Credentials as above

The query uses the Graph beta endpoint (`$expand=Assignments,Category,Version`) and reads every page.

---

#### `Get-IntunePolicyAssignments.ps1` (Reporting)

Retrieves configuration profile and compliance policy assignments with their targets. A policy with no assignments appears as a row with `TargetType` `None`. A policy whose assignments could not be read appears as `TargetType` `Error` and the script exits `1`.

```powershell
.\Reporting\Get-IntunePolicyAssignments.ps1
.\Reporting\Get-IntunePolicyAssignments.ps1 -PolicyType "Configuration" -ExportPath 'C:\Reports\ConfigProfiles.csv'
.\Reporting\Get-IntunePolicyAssignments.ps1 -PolicyType "Compliance" -ExportPath 'C:\Reports\CompliancePolicies.csv'
```

**Parameters:**

- `-PolicyType`: `All`, `Configuration` or `Compliance` (default: `All`)
- `-ExportPath`: Path to export CSV file
- Credentials as above

---

#### `Get-IntuneWin32AppDetails.ps1` (Reporting)

Retrieves Win32 app details and assignments. With `-DeviceId` it adds the install state Intune reports for that device (`mobileApps/{id}/deviceStatuses`): `installed`, `failed`, `notInstalled`, `pendingInstall` and so on, or `NotReported` when Intune has no row for that app on that device. That is one extra request per app.

```powershell
.\Reporting\Get-IntuneWin32AppDetails.ps1
.\Reporting\Get-IntuneWin32AppDetails.ps1 -IntuneAppId 'app-guid' -ExportPath 'C:\Reports\AppDetails.csv'
.\Reporting\Get-IntuneWin32AppDetails.ps1 -IntuneAppId 'app-guid' -DeviceId 'device-guid' -ExportPath 'C:\Reports\AppStatus.csv'
```

**Parameters:**

- `-IntuneAppId`: Specific Win32 app ID to query
- `-DeviceId`: Device ID to read install status for
- `-ExportPath`: Path to export CSV file
- Credentials as above

An app whose assignments or device status could not be read gets an `AssignmentError` or `DeviceStatusError` value, and the script exits `1`. Device status has been exercised only with mocks.

---

#### `Export-IntuneDeviceReport.ps1` (Reporting)

Exports device information to CSV or JSON, with each device's compliance policy states and configuration profile states.

```powershell
# Export all devices to CSV
.\Reporting\Export-IntuneDeviceReport.ps1

# Export a specific device to JSON
.\Reporting\Export-IntuneDeviceReport.ps1 -DeviceId 'device-guid' -Format 'JSON' -OutputPath 'C:\Reports\DeviceReport.json'
```

**Parameters:**

- `-DeviceId`: Specific device ID to export
- `-Format`: `CSV` or `JSON` (default: `CSV`)
- `-OutputPath`: Path to export file (default: a timestamped file in `$env:TEMP`)
- Credentials as above

A device whose states could not be read gets a `CollectionErrors` value; the file is still written and the script exits `1`.

---

#### `Get-IntuneDeviceLogs.ps1` (Troubleshooting)

Collects Intune Management Extension logs, MDM logs, the Enrollments registry export and, on request, Windows event logs.

```powershell
.\Troubleshooting\Get-IntuneDeviceLogs.ps1
.\Troubleshooting\Get-IntuneDeviceLogs.ps1 -OutputPath 'C:\Logs\Intune' -IncludeEventLogs
```

**Parameters:**

- `-OutputPath`: Path to save collected logs (default: timestamped folder in `$env:TEMP\IntuneLogs`)
- `-IncludeEventLogs`: Include the DeviceManagement and User Device Registration event logs

**Exit Codes:**

- `0`: Every collection that was attempted succeeded
- `1`: Any collection failed, nothing was collected, or an error occurred

**Requirements:** Administrator privileges

**Note:** The logs and the registry export contain device and user identifiers. When the script creates the output folder it limits access to SYSTEM and Administrators. A folder that already exists keeps its permissions.

---

### Service Management

These scripts live in `Security\`.

#### `Disable-PrintSpoolerService.ps1` (Security)

Stops the Print Spooler service and sets it to Disabled, to mitigate PrintNightmare-class vulnerabilities.

```powershell
.\Security\Disable-PrintSpoolerService.ps1 [-WhatIf]
```

**Exit Codes:** `0` service disabled or `-WhatIf` run, `1` error

**Requirements:** Administrator privileges

**Note:** Printing stops working. The script does not use `-Force`, so if a running service depends on the spooler, the stop fails and the script exits `1` with a message that names it.

---

#### `Enable-PrintSpoolerService.ps1` (Security)

Sets the Print Spooler service to Automatic and starts it.

```powershell
.\Security\Enable-PrintSpoolerService.ps1 [-WhatIf]
```

**Exit Codes:** `0` service enabled or `-WhatIf` run, `1` error

**Requirements:** Administrator privileges

---

#### `Disable-SmartCardLogonEnforcement.ps1` (Security)

Sets `scforceoption` and `ScRemoveOption` to 0 and sets the Smart Card Policy Service (`SCPolicySvc`) to Disabled. Password logon works again and the workstation no longer locks when a card is removed. This is also the way back from the Enable script on a device that can still reach Intune.

```powershell
.\Security\Disable-SmartCardLogonEnforcement.ps1 [-WhatIf] [-KeepLogs]
```

**Exit Codes:** `0` all values written and read back, or `-WhatIf` run; `1` a write or its read-back failed

**Requirements:** Administrator privileges

**Log:** `%ProgramData%\Microsoft\IntuneManagementExtension\Logs\win32-Disable_SmartCardLogon_Enforcement.log`. The log is always kept. `-KeepLogs` is accepted for old callers and does nothing.

---

#### `Enable-SmartCardLogonEnforcement.ps1` (Security)

> **Lockout warning.** This sets "Interactive logon: Require smart card". Password logon stops working for every account on the device, **including the local administrator**. A device with no smart card reader, no card or no certificate-based logon set up can be locked out for good.

Sets `scforceoption` and `ScRemoveOption` to 1 and sets `SCPolicySvc` to Automatic.

```powershell
.\Security\Enable-SmartCardLogonEnforcement.ps1 [-WhatIf] [-Force]
```

**Safeguard:** before it writes anything the script checks that `SCPolicySvc` exists and that at least one smart card reader is present and healthy. If not, it exits `1` and changes nothing. The check cannot see cards or logon certificates, so confirm those yourself. Intune cannot pass parameters to a remediation or platform script, so on managed devices this check is the safeguard. `-Force` skips it and is for a supervised run only.

**Recovery from a lockout:** boot to Windows Recovery, load the device's `SOFTWARE` hive in `regedit` and set `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\scforceoption` to `0`. Or run `Disable-SmartCardLogonEnforcement.ps1` through Intune on a device that can still check in.

**Exit Codes:** `0` all values written and read back, or `-WhatIf` run; `1` preflight refused, a write failed or a read-back did not match

**Requirements:** Administrator privileges

**Log:** `%ProgramData%\Microsoft\IntuneManagementExtension\Logs\win32-Enable_SmartCardLogon_Enforcement.log`, always kept.

---

### Connectivity & Testing

#### `Test-IntuneConnectivity.ps1` (Troubleshooting)

Tests connectivity to the mandatory Microsoft Intune (MEM) and Microsoft 365 Common endpoints, shows the network configuration and exports the results as **JSON**.

```powershell
.\Troubleshooting\Test-IntuneConnectivity.ps1
.\Troubleshooting\Test-IntuneConnectivity.ps1 -ExportPath 'C:\Reports\Connectivity.json'
```

**Parameters:**

- `-ExportPath`: Path to export the results as a JSON file
- `-IncludeUnlistedEndpoints`: Also test endpoint sets that are not in the script's built-in category tables. By default they are listed as not tested.

**How it decides:**

- A host that answers with any HTTP status counts as reachable. A timeout, DNS failure or refused connection counts as a failure.
- A host that publishes ports 80 and 443 is tried on https, then http.
- Wildcard-only entries (for example `*.microsoftonline.com`) and UDP-only entries (NTP) cannot be tested over HTTP and are reported as skipped.
- If either endpoint list cannot be retrieved, the test fails.

**Exit Codes:** `0` all tested mandatory endpoints reachable, `1` otherwise

**Known quirk:** a few hosts in Microsoft's published list have no address record or do not complete TLS (at the last live run: `activity.windows.com`, `adl.windows.com` and `windowsphone.com`). They show as failed.

---

## Common Module

### `IntuneCommon.psd1` / `IntuneCommon.psm1` (Common)

A PowerShell module with the helpers the Graph scripts share:

- **`Get-IntuneCredential`**: resolves app ID, tenant ID and secret from parameters or the `INTUNE_*` environment variables, rejects placeholders, returns the secret as a `SecureString`
- **`Get-GraphAccessToken`**: requests an OAuth2 token (secret as `SecureString` or plain string)
- **`Get-IntuneGraphHeaders`**: token plus ready-to-use request headers
- **`Invoke-GraphApiWithRetry`**: Graph request with retry and exponential backoff, honouring `Retry-After` on a 429
- **`Get-GraphApiAllPages`**: follows `@odata.nextLink` and returns every item
- **`ConvertTo-ODataStringLiteral`**: quotes a value for a `$filter` and doubles single quotes. Pass the finished filter through `[uri]::EscapeDataString`.
- **`Remove-ODataInjectionChars`**, **`Test-ODataFilterInput`**: escape a value by doubling quotes (they used to delete quotes)
- **`Protect-CsvValue`**, **`ConvertTo-SafeCsvRecord`**: prefix a leading `=`, `+`, `-`, `@`, tab or carriage return with an apostrophe so a spreadsheet does not run a device name as a formula. A string that starts with `-` gets the apostrophe too.
- **`Test-GuidFormat`**, **`Test-EmailFormat`**: format checks
- **`ConvertTo-Array`**, **`Get-IntuneLogPath`**, **`Write-StandardError`**: small utilities

```powershell
Import-Module .\Common\IntuneCommon.psd1
```

---

## Usage Examples

### Example 1: Generate Comprehensive Device Report

```powershell
.\Reporting\Export-IntuneDeviceReport.ps1 `
    -OutputPath "C:\Reports\AllDevices_$(Get-Date -Format 'yyyyMMdd').csv"
```

### Example 2: Check Compliance for Specific User

```powershell
.\Reporting\Get-IntuneDeviceCompliance.ps1 `
    -UserPrincipalName "john.doe@contoso.com" `
    -ExportPath "C:\Reports\JohnDoe_Compliance.csv"
```

### Example 3: Monitor Device Health

```powershell
.\Reporting\Get-IntuneDeviceHealth.ps1 `
    -ExportPath "C:\Reports\DeviceHealth_$(Get-Date -Format 'yyyyMMdd').csv"
```

### Example 4: Remediate Office Update Channel

```powershell
# First, detect the issue
.\Detection\Detect-OfficeUpdateChannel.ps1

# If detection returns exit code 1, run remediation
if ($LASTEXITCODE -eq 1) {
    .\Remediation\Set-OfficeUpdateChannel.ps1
}
```

### Example 5: Collect Logs for Troubleshooting

```powershell
.\Troubleshooting\Get-IntuneDeviceLogs.ps1 `
    -OutputPath "C:\Logs\Intune_$(Get-Date -Format 'yyyyMMdd_HHmmss')" `
    -IncludeEventLogs
```

(The Graph examples assume the `INTUNE_*` environment variables are set.)

---

## Exit Codes

| Exit Code | Meaning |
|-----------|---------|
| `0` | Success, nothing to do, or a `-WhatIf` run |
| `1` | Failure, action needed (detection scripts), or an incomplete report |
| `2` | Timeout (`Start-MDMSync.ps1`) |

### Exit Code Usage

- **Detection scripts**: `0` = compliant, not applicable or cannot determine; `1` = run the remediation
- **Remediation scripts**: `0` = success, `1` = failure
- **Reporting scripts**: `0` = complete report, `1` = error or incomplete report (rows marked with an error value)
- **Troubleshooting and security scripts**: `0` = success, `1` = failure; `Start-MDMSync.ps1` also uses `2` for a timeout

---

## Error Handling

- **Try-catch blocks** around the work, with a non-zero exit code on failure
- **Error messages** with the script name as a prefix
- **Verbose output** for debugging (use `-Verbose`)
- **Report rows that carry the error** for Graph reports, not blank values
- **Input validation** for GUIDs, user names and paths

```text
ScriptName: Failed to perform action - Error details
```

---

## Security Considerations

### Credentials

- Never hardcode credentials in scripts
- Use the **environment variables** or `-ClientSecretSecure`. `-ClientSecret` with a literal value is visible in shell history, process listings and transcripts.
- Use a vault such as Azure Key Vault to hold the secret and read it into the environment variable at run time
- Rotate client secrets regularly

### Permissions

- The Graph scripts use **Application** permissions with admin consent. Grant only the ones in the [permissions table](#for-graph-api-scripts).
- Scripts that change the machine need administrator privileges

### Registry and service changes

- Some scripts change registry keys or services. Review them, use `-WhatIf` and test on a pilot device first.
- `Enable-SmartCardLogonEnforcement.ps1` can lock every user out of a device. Read its section.
- `Repair-MultipleIntuneMDMCert.ps1` deletes certificates without a backup.

### Network Security

- The scripts talk to Microsoft Graph and the Microsoft sign-in service over HTTPS
- Use `Test-IntuneConnectivity.ps1` to verify the network path

### Spreadsheets

- CSV output is formula-safe: a leading `=`, `+`, `-` or `@` is prefixed with an apostrophe

---

## Testing

Tests are Pester 5 files in `Tests\`. They mock the registry, services, certificate store, files and every network call, so they never contact a tenant and never change the machine. The tests that run an elevated script need an elevated shell and skip themselves otherwise.

```powershell
Install-Module Pester -RequiredVersion 5.9.1 -Scope CurrentUser
Invoke-Pester -Path .\Tests
```

The GitHub Actions workflow in `.github\workflows\ci.yml` runs PSScriptAnalyzer (settings in `PSScriptAnalyzerSettings.psd1`) and Pester on every push and pull request.

---

## Contributing

When contributing to this repository:

1. **Follow PowerShell best practices**: approved verbs, verb-noun names, help in the script header.
2. **Make exit codes truthful**: a script that did not finish must not exit 0. No `-ErrorAction SilentlyContinue` on a write you depend on.
3. **Give every change a real `-WhatIf`**: nothing is created, written or deleted, and the exit code is 0.
4. **Add a Pester test** for each bug you fix, in the style of the existing tests (mock every state-changing cmdlet).
5. **Run PSScriptAnalyzer** with the repository settings and keep it clean.
6. **Update this README** and `CHANGELOG.md`.
7. **Use `IntuneCommon.psd1`** for shared Graph functionality.

---

## Script Index

| Script Name | Directory | Category | Requires Admin | Requires Graph API | Description |
|------------|-----------|----------|----------------|---------------------|-------------|
| `Detect-MultipleIntuneMDMCert.ps1` | `Detection\` | Detection | No | No | Detects multiple Intune MDM certificates |
| `Repair-MultipleIntuneMDMCert.ps1` | `Remediation\` | Remediation | Yes | No | Removes duplicate Intune MDM certificates |
| `Detect-OfficeUpdateChannel.ps1` | `Detection\` | Detection | No | No | Detects Office update channel |
| `Set-OfficeUpdateChannel.ps1` | `Remediation\` | Remediation | Yes | No | Sets Office to Semi-Annual channel |
| `Get-IntuneDeviceDetails.ps1` | `Reporting\` | Reporting | No | Yes | Retrieves device details |
| `Get-IntuneDeviceCompliance.ps1` | `Reporting\` | Reporting | No | Yes | Retrieves device compliance status |
| `Get-IntuneDeviceHealth.ps1` | `Reporting\` | Reporting | No | Yes | Performs device health checks |
| `Test-IntuneEnrollment.ps1` | `Troubleshooting\` | Testing | No | No | Tests device enrollment status |
| `Start-MDMSync.ps1` | `Troubleshooting\` | Management | No | No | Initiates MDM sync session (Windows PowerShell 5.1) |
| `Get-IntuneAllAppsAssignmentDetails.ps1` | `Reporting\` | Reporting | No | Yes | Retrieves app assignment details |
| `Get-IntunePolicyAssignments.ps1` | `Reporting\` | Reporting | No | Yes | Retrieves policy assignments |
| `Get-IntuneWin32AppDetails.ps1` | `Reporting\` | Reporting | No | Yes | Retrieves Win32 app details |
| `Export-IntuneDeviceReport.ps1` | `Reporting\` | Reporting | No | Yes | Exports device reports |
| `Get-IntuneDeviceLogs.ps1` | `Troubleshooting\` | Troubleshooting | Yes | No | Collects Intune-related logs |
| `Disable-PrintSpoolerService.ps1` | `Security\` | Service Management | Yes | No | Disables Print Spooler service |
| `Enable-PrintSpoolerService.ps1` | `Security\` | Service Management | Yes | No | Enables Print Spooler service |
| `Disable-SmartCardLogonEnforcement.ps1` | `Security\` | Service Management | Yes | No | Disables smart card logon enforcement |
| `Enable-SmartCardLogonEnforcement.ps1` | `Security\` | Service Management | Yes | No | Enables smart card logon enforcement (lockout risk) |
| `Test-IntuneConnectivity.ps1` | `Troubleshooting\` | Testing | No | No | Tests connectivity to Intune endpoints |
| `IntuneCommon.psd1` / `.psm1` | `Common\` | Module | No | No | Common functions module |

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Support

For issues or questions:

1. Review script header documentation for usage examples
2. Check script exit codes and error messages
3. Verify prerequisites and permissions
4. Review logs for detailed error information
5. Use `-Verbose` parameter for detailed output
