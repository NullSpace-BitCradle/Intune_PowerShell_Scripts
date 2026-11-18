#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

# Tests for Reporting/Export-IntuneDeviceReport.ps1 (audit findings H5, M6, M7, M8, L3).

. (Join-Path $PSScriptRoot 'TestHelpers.ps1')

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    $script:ScriptPath = Get-RepoPath 'Reporting\Export-IntuneDeviceReport.ps1'
    Import-Module (Get-ModuleManifestPath) -Force
    $script:Dev = { param($Id, $Name) [PSCustomObject]@{ id = $Id; deviceName = $Name; userPrincipalName = 'u@example.test'; complianceState = 'compliant' } }
}

Describe 'Export-IntuneDeviceReport.ps1' {
    BeforeEach {
        $global:IntuneTestState = New-GraphTestState
        Mock Invoke-RestMethod -ModuleName IntuneCommon -MockWith $script:GraphMockBody
        Mock Start-Sleep -ModuleName IntuneCommon { }
        Mock Install-Module { throw 'Install-Module must never be called' }
        $script:out = Join-Path $TestDrive 'report.csv'
        if (Test-Path $script:out) { Remove-Item $script:out }
        $script:creds = @{ AppId = 'app-id'; TenantId = 'tenant-id'; ClientSecret = 'plain-secret' }
        Remove-Item Env:\INTUNE_APP_ID, Env:\INTUNE_TENANT_ID, Env:\INTUNE_CLIENT_SECRET -ErrorAction SilentlyContinue
    }
    AfterEach { Remove-Variable -Name IntuneTestState -Scope Global -ErrorAction SilentlyContinue }

    It 'lists per-device compliance and configuration states and exits 0 (happy path)' {
        Add-GraphRoute -Like '*/managedDevices' -Body (New-GraphPage @((& $script:Dev 'd1' 'PC-ONE')))
        Add-GraphRoute -Like "*managedDevices('d1')/deviceCompliancePolicyStates" -Body (New-GraphPage @([PSCustomObject]@{ displayName = 'Baseline' }, [PSCustomObject]@{ displayName = 'BitLocker' }))
        Add-GraphRoute -Like "*managedDevices('d1')/deviceConfigurationStates" -Body (New-GraphPage @([PSCustomObject]@{ displayName = 'Wi-Fi' }))
        $r = Invoke-ScriptUnderTest -Path $script:ScriptPath -Arguments ($script:creds + @{ OutputPath = $script:out })
        $r.ExitCode | Should -Be 0
        $row = Import-Csv $script:out
        $row.CompliancePolicies | Should -Be 'Baseline; BitLocker'
        $row.ConfigurationProfiles | Should -Be 'Wi-Fi'
        $row.CollectionErrors | Should -BeNullOrEmpty
    }

    It 'records a CollectionErrors value instead of silent blanks when a state call fails, and exits 1 (H5)' {
        Add-GraphRoute -Like '*/managedDevices' -Body (New-GraphPage @((& $script:Dev 'd1' 'PC-ONE')))
        Add-GraphRoute -Like "*managedDevices('d1')/deviceCompliancePolicyStates" -Throw (New-HttpException -StatusCode 403 -Message 'Forbidden')
        Add-GraphRoute -Like "*managedDevices('d1')/deviceConfigurationStates" -Body (New-GraphPage @([PSCustomObject]@{ displayName = 'Wi-Fi' }))
        $r = Invoke-ScriptUnderTest -Path $script:ScriptPath -Arguments ($script:creds + @{ OutputPath = $script:out })
        $r.ExitCode | Should -Be 1
        $r.Output | Should -Match 'incomplete'
        Test-Path $script:out | Should -BeTrue
        $row = Import-Csv $script:out
        $row.CollectionErrors | Should -Match 'compliance policy states: Forbidden'
        $row.ConfigurationProfiles | Should -Be 'Wi-Fi'
    }

    It 'treats an exhausted 429 as an error too, not as a blank (H5)' {
        Add-GraphRoute -Like '*/managedDevices' -Body (New-GraphPage @((& $script:Dev 'd1' 'PC-ONE')))
        Add-GraphRoute -Like '*deviceCompliancePolicyStates' -Body (New-GraphPage @())
        Add-GraphRoute -Like '*deviceConfigurationStates' -Throw (New-HttpException -StatusCode 429 -Message 'Too Many Requests')
        $r = Invoke-ScriptUnderTest -Path $script:ScriptPath -Arguments ($script:creds + @{ OutputPath = $script:out })
        $r.ExitCode | Should -Be 1
        (Import-Csv $script:out).CollectionErrors | Should -Match 'Too Many Requests'
    }

    It 'pages through the device list (M8)' {
        Add-GraphRoute -First -Like '*managedDevices?$skiptoken=2*' -Body (New-GraphPage @((& $script:Dev 'd2' 'PC-TWO')))
        Add-GraphRoute -Like '*/managedDevices' -Body (New-GraphPage @((& $script:Dev 'd1' 'PC-ONE')) -NextLink 'https://graph.microsoft.com/v1.0/deviceManagement/managedDevices?$skiptoken=2')
        Add-GraphRoute -Like '*States' -Body (New-GraphPage @())
        $r = Invoke-ScriptUnderTest -Path $script:ScriptPath -Arguments ($script:creds + @{ OutputPath = $script:out })
        $r.ExitCode | Should -Be 0
        (Import-Csv $script:out).DeviceName | Should -Be @('PC-ONE', 'PC-TWO')
    }

    It 'writes JSON with -Format JSON' {
        $json = Join-Path $TestDrive 'report.json'
        Add-GraphRoute -Like '*/managedDevices' -Body (New-GraphPage @((& $script:Dev 'd1' 'PC-ONE')))
        Add-GraphRoute -Like '*States' -Body (New-GraphPage @())
        $r = Invoke-ScriptUnderTest -Path $script:ScriptPath -Arguments ($script:creds + @{ OutputPath = $json; Format = 'JSON' })
        $r.ExitCode | Should -Be 0
        (Get-Content $json -Raw | ConvertFrom-Json).DeviceName | Should -Be 'PC-ONE'
    }

    It 'neutralises a device name that starts with = in the CSV (L3)' {
        Add-GraphRoute -Like '*/managedDevices' -Body (New-GraphPage @((& $script:Dev 'd1' '=cmd()')))
        Add-GraphRoute -Like '*States' -Body (New-GraphPage @())
        Invoke-ScriptUnderTest -Path $script:ScriptPath -Arguments ($script:creds + @{ OutputPath = $script:out }) | Out-Null
        (Import-Csv $script:out).DeviceName | Should -Be "'=cmd()"
    }

    It 'does not claim the Apps.Read.All permission it never uses (M7)' {
        $text = Get-Content $script:ScriptPath -Raw
        $text | Should -Not -Match 'DeviceManagementApps\.Read\.All and'
        $text | Should -Match 'APPLICATION permissions'
        $text | Should -Not -Match 'Install-Module'
    }
}
