# Changelog

## Unreleased (fix/audit-2026-11-18)

Fixes from the 2026-11-18 audit. See the commit messages for the reasoning behind each change.

### Fixed

- `Set-OfficeUpdateChannel.ps1`: wrote an array of 15 URLs to `CDNBaseUrl` and always exited 1. It now writes one URL, uses the real Click-to-Run updater and fails if the updater is missing.
- `Enable-` and `Disable-SmartCardLogonEnforcement.ps1`: report real success or failure, verify each write, keep the log, forward `-WhatIf` on the 64-bit relaunch. Enable refuses to run without a working smart card reader unless `-Force` is given.
- `Test-IntuneEnrollment.ps1`: no longer crashes on registry subkeys without a ProviderID.
- `Test-IntuneConnectivity.ps1`: the Intune endpoints are tested; failure to retrieve an endpoint list fails the run.
- `Start-MDMSync.ps1`: requires Windows PowerShell 5.1, reads `ExtendedError`, and returns the documented timeout code.
- Reporting scripts: unassigned policies are listed, failed requests show as errors and exit 1, results are paged, device compliance is per device, exclusions are labelled, and the scripts no longer install the Microsoft.Graph module.
- `Repair-MultipleIntuneMDMCert.ps1` and `Set-OfficeUpdateChannel.ps1`: `-WhatIf` exits 0.
- `Detect-OfficeUpdateChannel.ps1`: separates compliant, not applicable, cannot determine and non-compliant.
- `Get-IntuneDeviceLogs.ps1`: exit code reflects failures.
- `Get-IntuneDeviceHealth.ps1`: no false "unsupported" management agents.

### Added

- `-ClientSecretSecure` on the Graph scripts, `Get-IntuneCredential` and related helpers in `IntuneCommon`, and `IntuneCommon.psd1` (version 1.1.0).
- Formula-safe CSV output.
- Pester tests in `Tests\` and a GitHub Actions workflow (PSScriptAnalyzer and Pester, actions pinned to commit SHAs).
- `Get-IntuneAllAppsAssignmentDetails.ps1`: `-ExportCSVpath` and a `TargetType` column.
- `Test-IntuneConnectivity.ps1`: `-IncludeUnlistedEndpoints`.

### Changed

- `Remove-ODataInjectionChars` and `Test-ODataFilterInput` double single quotes instead of deleting them.
- `Get-IntuneGraphHeaders` takes `-AppRegistration`.
