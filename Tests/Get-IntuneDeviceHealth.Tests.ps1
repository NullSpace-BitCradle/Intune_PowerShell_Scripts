#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

# Tests for Reporting/Get-IntuneDeviceHealth.ps1 (audit findings M10, M6, M8).

. (Join-Path $PSScriptRoot 'TestHelpers.ps1')

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    $script:ScriptPath = Get-RepoPath 'Reporting\Get-IntuneDeviceHealth.ps1'
    Import-Module (Get-ModuleManifestPath) -Force
    . ([scriptblock]::Create((Import-ScriptFunction -Path $script:ScriptPath -Name 'Get-DeviceHealthAssessment')))

    $script:Now = [datetime]'2025-06-01T12:00:00Z'
    # A device with nothing wrong
    function New-HealthyDevice {
        [PSCustomObject]@{
            id = 'd1'; deviceName = 'PC-ONE'; userPrincipalName = 'u@example.test'
            enrolledDateTime = '2023-01-01T00:00:00Z'; lastSyncDateTime = '2025-06-01T11:00:00Z'
            complianceState = 'compliant'; managementAgent = 'mdm'; operatingSystem = 'Windows'; osVersion = '10.0'
            totalStorageSpaceInBytes = 500GB; freeStorageSpaceInBytes = 300GB
        }
    }
}

Describe 'Get-DeviceHealthAssessment (M10)' {
    It 'scores a healthy device 100 with no issues' {
        $r = Get-DeviceHealthAssessment -Device (New-HealthyDevice) -Now $script:Now
        $r.HealthScore | Should -Be 100
        $r.OverallHealth | Should -Be 'Healthy'
        $r.HealthIssueCount | Should -Be 0
    }

    It 'does NOT flag Graph management agent <Agent> as unsupported' -ForEach @(
        @{ Agent = 'mdm' }, @{ Agent = 'eas' }, @{ Agent = 'easMdm' }, @{ Agent = 'intuneClient' },
        @{ Agent = 'configurationManagerClientMdm' }, @{ Agent = 'microsoft365ManagedMdm' }, @{ Agent = 'msSense' }
    ) {
        $d = New-HealthyDevice; $d.managementAgent = $Agent
        $r = Get-DeviceHealthAssessment -Device $d -Now $script:Now
        $r.ManagementStatus | Should -Be 'Healthy'
        $r.HealthScore | Should -Be 100
    }

    It 'flags an agent of "unknown" and a missing agent' {
        $d = New-HealthyDevice; $d.managementAgent = 'unknown'
        (Get-DeviceHealthAssessment -Device $d -Now $script:Now).ManagementStatus | Should -Be 'Unknown'
        $d.managementAgent = $null
        (Get-DeviceHealthAssessment -Device $d -Now $script:Now).HealthIssues | Should -Match 'Management agent missing'
    }

    It 'does not penalise a device for being enrolled over a year' {
        $d = New-HealthyDevice; $d.enrolledDateTime = '2018-01-01T00:00:00Z'
        (Get-DeviceHealthAssessment -Device $d -Now $script:Now).HealthScore | Should -Be 100
    }

    It 'treats Graph''s 0001-01-01 placeholder as Never Synced, not Stale' {
        $d = New-HealthyDevice; $d.lastSyncDateTime = '0001-01-01T00:00:00Z'
        $r = Get-DeviceHealthAssessment -Device $d -Now $script:Now
        $r.SyncStatus | Should -Be 'Never Synced'
        $r.HealthIssues | Should -Match 'never synced'
        $r.HealthScore | Should -Be 75
    }

    It 'treats a null last sync as Never Synced' {
        $d = New-HealthyDevice; $d.lastSyncDateTime = $null
        (Get-DeviceHealthAssessment -Device $d -Now $script:Now).SyncStatus | Should -Be 'Never Synced'
    }

    It 'marks a sync of <Hours> hours ago as <Status>' -ForEach @(
        @{ Hours = 2; Status = 'Healthy' }, @{ Hours = 10; Status = 'Warning' }, @{ Hours = 30; Status = 'Stale' }
    ) {
        $d = New-HealthyDevice; $d.lastSyncDateTime = $script:Now.AddHours(-$Hours).ToString('o')
        (Get-DeviceHealthAssessment -Device $d -Now $script:Now).SyncStatus | Should -Be $Status
    }

    It 'subtracts the documented weights for compliance and storage' {
        $d = New-HealthyDevice; $d.complianceState = 'nonCompliant'; $d.freeStorageSpaceInBytes = 20GB
        $r = Get-DeviceHealthAssessment -Device $d -Now $script:Now
        $r.HealthScore | Should -Be (100 - 15 - 15)
        $r.OverallHealth | Should -Be 'Fair'
    }
}

Describe 'Get-IntuneDeviceHealth.ps1' {
    BeforeEach {
        $global:IntuneTestState = New-GraphTestState
        Mock Invoke-RestMethod -ModuleName IntuneCommon -MockWith $script:GraphMockBody
        Mock Start-Sleep -ModuleName IntuneCommon { }
        Mock Install-Module { throw 'Install-Module must never be called' }
        $script:csv = Join-Path $TestDrive 'out.csv'
        if (Test-Path $script:csv) { Remove-Item $script:csv }
        $script:creds = @{ AppId = 'app-id'; TenantId = 'tenant-id'; ClientSecret = 'plain-secret' }
        Remove-Item Env:\INTUNE_APP_ID, Env:\INTUNE_TENANT_ID, Env:\INTUNE_CLIENT_SECRET -ErrorAction SilentlyContinue
    }
    AfterEach { Remove-Variable -Name IntuneTestState -Scope Global -ErrorAction SilentlyContinue }

    It 'reads every page and exports one row per device (M8)' {
        $recent = (Get-Date).AddMinutes(-5).ToString('o')
        $mk = { param($id, $name) [PSCustomObject]@{ id = $id; deviceName = $name; enrolledDateTime = '2023-01-01T00:00:00Z'; lastSyncDateTime = $recent; complianceState = 'compliant'; managementAgent = 'configurationManagerClientMdm'; operatingSystem = 'Windows' } }
        Add-GraphRoute -First -Like '*$skiptoken=2*' -Body (New-GraphPage @((& $mk 'd2' 'PC-TWO')))
        Add-GraphRoute -Like '*/managedDevices' -Body (New-GraphPage @((& $mk 'd1' 'PC-ONE')) -NextLink 'https://graph.microsoft.com/v1.0/deviceManagement/managedDevices?$skiptoken=2')
        $r = Invoke-ScriptUnderTest -Path $script:ScriptPath -Arguments ($script:creds + @{ ExportPath = $script:csv })
        $r.ExitCode | Should -Be 0
        $rows = Import-Csv $script:csv
        $rows.DeviceName | Should -Be @('PC-ONE', 'PC-TWO')
        $rows.OverallHealth | Should -Be @('Healthy', 'Healthy')
    }

    It 'never installs Microsoft.Graph (M6)' {
        Add-GraphRoute -Like '*/managedDevices' -Body (New-GraphPage @())
        (Invoke-ScriptUnderTest -Path $script:ScriptPath -Arguments $script:creds).ExitCode | Should -Be 0
        Should -Invoke Install-Module -Times 0 -Exactly
        (Get-Content $script:ScriptPath -Raw) | Should -Not -Match 'Install-Module'
    }
}
