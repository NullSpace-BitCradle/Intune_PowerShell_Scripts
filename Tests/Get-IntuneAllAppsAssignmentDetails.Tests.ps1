#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

# Tests for Reporting/Get-IntuneAllAppsAssignmentDetails.ps1 (audit findings H6, M6, M7, M8, L3).

. (Join-Path $PSScriptRoot 'TestHelpers.ps1')

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    $script:ScriptPath = Get-RepoPath 'Reporting\Get-IntuneAllAppsAssignmentDetails.ps1'
    Import-Module (Get-ModuleManifestPath) -Force
    $script:Target = { param($Type, $GroupId) $t = [ordered]@{ '@odata.type' = $Type }; if ($GroupId) { $t.groupId = $GroupId }; [PSCustomObject]$t }
    $script:Assign = { param($Intent, $Target) [PSCustomObject]@{ id = [guid]::NewGuid().ToString(); intent = $Intent; target = $Target } }
    $script:App = { param($Name, $Assignments) [PSCustomObject]@{ id = $Name; displayName = $Name; '@odata.type' = '#microsoft.graph.win32LobApp'; displayVersion = '1.0'; assignments = @($Assignments) } }
}

Describe 'Get-IntuneAllAppsAssignmentDetails.ps1' {
    BeforeEach {
        $global:IntuneTestState = New-GraphTestState
        Mock Invoke-RestMethod -ModuleName IntuneCommon -MockWith $script:GraphMockBody
        Mock Start-Sleep -ModuleName IntuneCommon { }
        Mock Install-Module { throw 'Install-Module must never be called' }
        $script:csv = Join-Path $TestDrive 'apps.csv'
        if (Test-Path $script:csv) { Remove-Item $script:csv }
        $script:creds = @{ AppId = 'app-id'; TenantId = 'tenant-id'; ClientSecret = 'plain-secret' }
        Remove-Item Env:\INTUNE_APP_ID, Env:\INTUNE_TENANT_ID, Env:\INTUNE_CLIENT_SECRET -ErrorAction SilentlyContinue
    }
    AfterEach { Remove-Variable -Name IntuneTestState -Scope Global -ErrorAction SilentlyContinue }

    It 'has the -ExportCSVpath parameter the README documents (H6)' {
        (Get-Command $script:ScriptPath).Parameters.Keys | Should -Contain 'ExportCSVpath'
    }

    It 'writes to the path given in -ExportCSVpath (H6)' {
        Add-GraphRoute -Like '*mobileApps?*' -Body (New-GraphPage @((& $script:App 'App One' @())))
        $r = Invoke-ScriptUnderTest -Path $script:ScriptPath -Arguments ($script:creds + @{ ExportCSVpath = $script:csv })
        $r.ExitCode | Should -Be 0
        Test-Path $script:csv | Should -BeTrue
    }

    It 'labels exclusions as Excluded group, not as a targeted group (H6)' {
        $assignments = @(
            (& $script:Assign 'required' (& $script:Target '#microsoft.graph.groupAssignmentTarget' 'g-in')),
            (& $script:Assign 'required' (& $script:Target '#microsoft.graph.exclusionGroupAssignmentTarget' 'g-out')),
            (& $script:Assign 'available' (& $script:Target '#microsoft.graph.allLicensedUsersAssignmentTarget')),
            (& $script:Assign 'required' (& $script:Target '#microsoft.graph.allDevicesAssignmentTarget'))
        )
        Add-GraphRoute -Like '*mobileApps?*' -Body (New-GraphPage @((& $script:App 'App One' $assignments)))
        Add-GraphRoute -Like '*/groups/g-in' -Body ([PSCustomObject]@{ displayName = 'Pilot' })
        Add-GraphRoute -Like '*/groups/g-out' -Body ([PSCustomObject]@{ displayName = 'Kiosks' })
        $r = Invoke-ScriptUnderTest -Path $script:ScriptPath -Arguments ($script:creds + @{ ExportCSVpath = $script:csv })
        $r.ExitCode | Should -Be 0
        $rows = Import-Csv $script:csv
        $rows.Count | Should -Be 4
        $in = $rows | Where-Object Group -eq 'Pilot'
        $in.TargetType | Should -Be 'Group'
        $out = $rows | Where-Object Group -eq 'Kiosks'
        $out.TargetType | Should -Be 'Excluded group'
        ($rows | Where-Object TargetType -eq 'All Users').Group | Should -Be 'All Users'
        ($rows | Where-Object TargetType -eq 'All Devices').Group | Should -Be 'All Devices'
    }

    It 'gives an unassigned app one Not Assigned row' {
        Add-GraphRoute -Like '*mobileApps?*' -Body (New-GraphPage @((& $script:App 'Lonely' @())))
        Invoke-ScriptUnderTest -Path $script:ScriptPath -Arguments ($script:creds + @{ ExportCSVpath = $script:csv }) | Out-Null
        $row = Import-Csv $script:csv
        $row.Group | Should -Be 'Not Assigned'
        $row.TargetType | Should -Be 'None'
    }

    It 'reads every page of apps instead of only the first (H6)' {
        Add-GraphRoute -First -Like '*$skiptoken=2*' -Body (New-GraphPage @((& $script:App 'App Two' @())))
        Add-GraphRoute -Like '*mobileApps?*' -Body (New-GraphPage @((& $script:App 'App One' @())) -NextLink 'https://graph.microsoft.com/beta/deviceAppManagement/mobileApps?$expand=Assignments&$skiptoken=2')
        $r = Invoke-ScriptUnderTest -Path $script:ScriptPath -Arguments ($script:creds + @{ ExportCSVpath = $script:csv })
        $r.ExitCode | Should -Be 0
        (Import-Csv $script:csv).Name | Should -Be @('App One', 'App Two')
    }

    It 'resolves each group once, even when many assignments use it' {
        $a = @(1..3 | ForEach-Object { & $script:Assign 'required' (& $script:Target '#microsoft.graph.groupAssignmentTarget' 'g1') })
        Add-GraphRoute -Like '*mobileApps?*' -Body (New-GraphPage @((& $script:App 'A' $a), (& $script:App 'B' $a)))
        Add-GraphRoute -Like '*/groups/g1' -Body ([PSCustomObject]@{ displayName = 'G One' })
        Invoke-ScriptUnderTest -Path $script:ScriptPath -Arguments ($script:creds + @{ ExportCSVpath = $script:csv }) | Out-Null
        ($global:IntuneTestState.Calls | Where-Object { $_.Uri -like '*/groups/g1' }).Count | Should -Be 1
    }

    It 'falls back to the group ID when the group lookup fails, and still exits 0' {
        Add-GraphRoute -Like '*mobileApps?*' -Body (New-GraphPage @((& $script:App 'A' @((& $script:Assign 'required' (& $script:Target '#microsoft.graph.groupAssignmentTarget' 'gx'))))))
        Add-GraphRoute -Like '*/groups/gx' -Throw (New-HttpException -StatusCode 404)
        $r = Invoke-ScriptUnderTest -Path $script:ScriptPath -Arguments ($script:creds + @{ ExportCSVpath = $script:csv })
        $r.ExitCode | Should -Be 0
        (Import-Csv $script:csv).Group | Should -Be 'gx'
    }

    It 'exits 1 when the app list request fails' {
        Add-GraphRoute -Like '*mobileApps?*' -Throw (New-HttpException -StatusCode 403 -Message 'Forbidden')
        $r = Invoke-ScriptUnderTest -Path $script:ScriptPath -Arguments ($script:creds + @{ ExportCSVpath = $script:csv })
        $r.ExitCode | Should -Be 1
    }

    It 'neutralises an app name that starts with = (L3)' {
        Add-GraphRoute -Like '*mobileApps?*' -Body (New-GraphPage @((& $script:App '=cmd()' @())))
        Invoke-ScriptUnderTest -Path $script:ScriptPath -Arguments ($script:creds + @{ ExportCSVpath = $script:csv }) | Out-Null
        (Import-Csv $script:csv).Name | Should -Be "'=cmd()"
    }

    It 'uses no Microsoft.Graph SDK cmdlet and no plain-text-to-SecureString conversion (M6)' {
        $text = Get-Content $script:ScriptPath -Raw
        $text | Should -Not -Match 'Install-Module|Connect-MgGraph|Invoke-MgGraphRequest|Get-MgGroup|Disconnect-MgGraph'
        $text | Should -Not -Match 'ConvertTo-SecureString'
    }
}
