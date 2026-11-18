#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

# Tests for Reporting/Get-IntuneWin32AppDetails.ps1 (audit findings H5, M9, M6, M8, L3).

. (Join-Path $PSScriptRoot 'TestHelpers.ps1')

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    $script:ScriptPath = Get-RepoPath 'Reporting\Get-IntuneWin32AppDetails.ps1'
    Import-Module (Get-ModuleManifestPath) -Force
    $script:App = { param($Id, $Name) [PSCustomObject]@{ id = $Id; displayName = $Name; '@odata.type' = '#microsoft.graph.win32LobApp'; displayVersion = '1.2.3'; publisher = 'Contoso' } }
    $script:Dev = '11111111-2222-3333-4444-555555555555'
}

Describe 'Get-IntuneWin32AppDetails.ps1' {
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

    It 'shows an assignments failure as an error, NOT as 0 assignments, and exits 1 (H5)' {
        Add-GraphRoute -Like '*mobileApps?$filter=*' -Body (New-GraphPage @((& $script:App 'a1' 'App One'), (& $script:App 'a2' 'App Two')))
        Add-GraphRoute -Like "*mobileApps('a1')/assignments" -Throw (New-HttpException -StatusCode 403 -Message 'Forbidden')
        Add-GraphRoute -Like "*mobileApps('a2')/assignments" -Body (New-GraphPage @([PSCustomObject]@{ id = 'x'; target = [PSCustomObject]@{ '@odata.type' = '#microsoft.graph.allDevicesAssignmentTarget' } }))
        $r = Invoke-ScriptUnderTest -Path $script:ScriptPath -Arguments ($script:creds + @{ ExportPath = $script:csv })
        $r.ExitCode | Should -Be 1
        $r.Output | Should -Match 'incomplete'
        $rows = Import-Csv $script:csv
        $one = $rows | Where-Object AppName -eq 'App One'
        $one.AssignmentError | Should -Match 'Forbidden'
        $one.AssignmentCount | Should -BeNullOrEmpty
        ($rows | Where-Object AppName -eq 'App Two').AssignmentCount | Should -Be '1'
    }

    It 'a real zero-assignment app reports 0 with no error' {
        Add-GraphRoute -Like '*mobileApps?$filter=*' -Body (New-GraphPage @((& $script:App 'a1' 'App One')))
        Add-GraphRoute -Like "*mobileApps('a1')/assignments" -Body ([PSCustomObject]@{ value = @() })
        $r = Invoke-ScriptUnderTest -Path $script:ScriptPath -Arguments ($script:creds + @{ ExportPath = $script:csv })
        $r.ExitCode | Should -Be 0
        $row = Import-Csv $script:csv
        $row.AssignmentCount | Should -Be '0'
        $row.AssignmentError | Should -BeNullOrEmpty
    }

    It 'reports the install state Intune holds for the device, matched on deviceId (M9)' {
        Add-GraphRoute -Like '*mobileApps?$filter=*' -Body (New-GraphPage @((& $script:App 'a1' '7-Zip'), (& $script:App 'a2' 'Other App'), (& $script:App 'a3' 'Broken App')))
        Add-GraphRoute -Like '*/assignments' -Body (New-GraphPage @())
        Add-GraphRoute -Like "*mobileApps('a1')/deviceStatuses" -Body (New-GraphPage @(
            [PSCustomObject]@{ deviceId = 'someone-else'; installState = 'failed' },
            [PSCustomObject]@{ deviceId = $script:Dev; installState = 'installed'; displayVersion = '24.08' }))
        Add-GraphRoute -Like "*mobileApps('a2')/deviceStatuses" -Body (New-GraphPage @([PSCustomObject]@{ deviceId = 'someone-else'; installState = 'installed' }))
        Add-GraphRoute -Like "*mobileApps('a3')/deviceStatuses" -Body (New-GraphPage @([PSCustomObject]@{ deviceId = $script:Dev; installState = 'failed' }))
        $r = Invoke-ScriptUnderTest -Path $script:ScriptPath -Arguments ($script:creds + @{ DeviceId = $script:Dev; ExportPath = $script:csv })
        $r.ExitCode | Should -Be 0
        $rows = Import-Csv $script:csv
        ($rows | Where-Object AppName -eq '7-Zip').DeviceInstallStatus | Should -Be 'installed'
        ($rows | Where-Object AppName -eq '7-Zip').DeviceInstallVersion | Should -Be '24.08'
        ($rows | Where-Object AppName -eq 'Other App').DeviceInstallStatus | Should -Be 'NotReported'
        ($rows | Where-Object AppName -eq 'Broken App').DeviceInstallStatus | Should -Be 'failed'
        # The old name match against software inventory must be gone
        ($global:IntuneTestState.Calls | Where-Object { $_.Uri -like '*detectedApps*' }).Count | Should -Be 0
    }

    It 'marks the device state Unknown with an error and exits 1 when the status call fails' {
        Add-GraphRoute -Like '*mobileApps?$filter=*' -Body (New-GraphPage @((& $script:App 'a1' 'App One')))
        Add-GraphRoute -Like '*/assignments' -Body (New-GraphPage @())
        Add-GraphRoute -Like '*deviceStatuses' -Throw (New-HttpException -StatusCode 403 -Message 'Forbidden')
        $r = Invoke-ScriptUnderTest -Path $script:ScriptPath -Arguments ($script:creds + @{ DeviceId = $script:Dev; ExportPath = $script:csv })
        $r.ExitCode | Should -Be 1
        $row = Import-Csv $script:csv
        $row.DeviceInstallStatus | Should -Be 'Unknown'
        $row.DeviceStatusError | Should -Match 'Forbidden'
    }

    It 'exits 1, not "completed successfully", when the single-app fetch fails (M9)' {
        Add-GraphRoute -Like "*mobileApps('11111111-aaaa-bbbb-cccc-111111111111')" -Throw (New-HttpException -StatusCode 404 -Message 'Not Found')
        $r = Invoke-ScriptUnderTest -Path $script:ScriptPath -Arguments ($script:creds + @{ IntuneAppId = '11111111-aaaa-bbbb-cccc-111111111111' })
        $r.ExitCode | Should -Be 1
        $r.Output | Should -Not -Match 'completed successfully'
    }

    It 'warns and exits 0 for an app that is not a Win32 app' {
        Add-GraphRoute -Like "*mobileApps('11111111-aaaa-bbbb-cccc-111111111111')" -Body ([PSCustomObject]@{ id = 'x'; displayName = 'Web'; '@odata.type' = '#microsoft.graph.webApp' })
        $r = Invoke-ScriptUnderTest -Path $script:ScriptPath -Arguments ($script:creds + @{ IntuneAppId = '11111111-aaaa-bbbb-cccc-111111111111' })
        $r.ExitCode | Should -Be 0
        $r.Output | Should -Match 'not a Win32 app'
    }

    It 'pages through the app list (M8)' {
        Add-GraphRoute -First -Like '*$skiptoken=2*' -Body (New-GraphPage @((& $script:App 'a2' 'App Two')))
        Add-GraphRoute -Like '*mobileApps?$filter=*' -Body (New-GraphPage @((& $script:App 'a1' 'App One')) -NextLink 'https://graph.microsoft.com/v1.0/deviceAppManagement/mobileApps?$filter=x&$skiptoken=2')
        Add-GraphRoute -Like '*/assignments' -Body (New-GraphPage @())
        $r = Invoke-ScriptUnderTest -Path $script:ScriptPath -Arguments ($script:creds + @{ ExportPath = $script:csv })
        $r.ExitCode | Should -Be 0
        (Import-Csv $script:csv).AppName | Should -Be @('App One', 'App Two')
    }

    It 'neutralises an app name that starts with = (L3)' {
        Add-GraphRoute -Like '*mobileApps?$filter=*' -Body (New-GraphPage @((& $script:App 'a1' '=cmd()')))
        Add-GraphRoute -Like '*/assignments' -Body (New-GraphPage @())
        Invoke-ScriptUnderTest -Path $script:ScriptPath -Arguments ($script:creds + @{ ExportPath = $script:csv }) | Out-Null
        (Import-Csv $script:csv).AppName | Should -Be "'=cmd()"
    }

    It 'never installs Microsoft.Graph (M6)' {
        Add-GraphRoute -Like '*mobileApps?$filter=*' -Body (New-GraphPage @())
        (Invoke-ScriptUnderTest -Path $script:ScriptPath -Arguments $script:creds).ExitCode | Should -Be 0
        Should -Invoke Install-Module -Times 0 -Exactly
        (Get-Content $script:ScriptPath -Raw) | Should -Not -Match 'Install-Module'
    }
}
