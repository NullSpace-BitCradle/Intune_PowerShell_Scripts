#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

# Tests for Reporting/Get-IntunePolicyAssignments.ps1 (audit findings H5, M6, M7, M8, L3).
# Every Graph and token call goes through a mocked Invoke-RestMethod inside the IntuneCommon module.
# Nothing contacts a tenant. A URI with no route throws.

. (Join-Path $PSScriptRoot 'TestHelpers.ps1')

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    $script:ScriptPath = Get-RepoPath 'Reporting\Get-IntunePolicyAssignments.ps1'
    Import-Module (Get-ModuleManifestPath) -Force
    $script:Base = 'https://graph.microsoft.com/v1.0'
}

Describe 'Get-IntunePolicyAssignments.ps1' {
    BeforeEach {
        $global:IntuneTestState = New-GraphTestState
        Mock Invoke-RestMethod -ModuleName IntuneCommon -MockWith $script:GraphMockBody
        Mock Start-Sleep -ModuleName IntuneCommon { }
        Mock Install-Module { throw 'Install-Module must never be called' }
        Mock Import-Module -ParameterFilter { "$Name" -like '*Microsoft.Graph*' } { throw 'Microsoft.Graph must not be imported' }
        $script:csv = Join-Path $TestDrive 'out.csv'
        if (Test-Path $script:csv) { Remove-Item $script:csv }
        $script:creds = @{ AppId = 'app-id'; TenantId = 'tenant-id'; ClientSecret = 'plain-secret' }
        Remove-Item Env:\INTUNE_APP_ID, Env:\INTUNE_TENANT_ID, Env:\INTUNE_CLIENT_SECRET -ErrorAction SilentlyContinue
    }
    AfterEach { Remove-Variable -Name IntuneTestState -Scope Global -ErrorAction SilentlyContinue }

    It 'lists a policy that has no assignments instead of dropping it (H5)' {
        Add-GraphRoute -Like '*deviceConfigurations' -Body (New-GraphPage @([PSCustomObject]@{ id = 'c1'; displayName = 'Assigned profile' }, [PSCustomObject]@{ id = 'c2'; displayName = 'Orphan profile' }))
        Add-GraphRoute -Like "*deviceConfigurations('c1')/assignments" -Body (New-GraphPage @([PSCustomObject]@{ id = 'a1'; intent = 'apply'; target = [PSCustomObject]@{ '@odata.type' = '#microsoft.graph.groupAssignmentTarget'; groupId = 'g1' } }))
        Add-GraphRoute -Like "*deviceConfigurations('c2')/assignments" -Body ([PSCustomObject]@{ value = @() })
        Add-GraphRoute -Like '*/groups/g1' -Body ([PSCustomObject]@{ displayName = 'Pilot group' })

        $r = Invoke-ScriptUnderTest -Path $script:ScriptPath -Arguments ($script:creds + @{ PolicyType = 'Configuration'; ExportPath = $script:csv })
        $r.ExitCode | Should -Be 0
        $rows = Import-Csv $script:csv
        $rows.Count | Should -Be 2
        ($rows | Where-Object PolicyName -eq 'Orphan profile').TargetName | Should -Be 'No assignments'
        ($rows | Where-Object PolicyName -eq 'Orphan profile').TargetType | Should -Be 'None'
        ($rows | Where-Object PolicyName -eq 'Assigned profile').TargetName | Should -Be 'Pilot group'
    }

    It 'lists an unassigned COMPLIANCE policy too (the same pattern was in the compliance half)' {
        Add-GraphRoute -Like '*deviceCompliancePolicies' -Body (New-GraphPage @([PSCustomObject]@{ id = 'p1'; displayName = 'Orphan compliance' }))
        Add-GraphRoute -Like "*deviceCompliancePolicies('p1')/assignments" -Body ([PSCustomObject]@{ value = @() })
        $r = Invoke-ScriptUnderTest -Path $script:ScriptPath -Arguments ($script:creds + @{ PolicyType = 'Compliance'; ExportPath = $script:csv })
        $r.ExitCode | Should -Be 0
        (Import-Csv $script:csv).TargetName | Should -Be 'No assignments'
    }

    It 'marks a policy whose assignments call failed as an Error row and exits 1' {
        Add-GraphRoute -Like '*deviceConfigurations' -Body (New-GraphPage @([PSCustomObject]@{ id = 'c1'; displayName = 'Denied profile' }))
        Add-GraphRoute -Like "*deviceConfigurations('c1')/assignments" -Throw (New-HttpException -StatusCode 403 -Message 'Forbidden')
        $r = Invoke-ScriptUnderTest -Path $script:ScriptPath -Arguments ($script:creds + @{ PolicyType = 'Configuration'; ExportPath = $script:csv })
        $r.ExitCode | Should -Be 1
        $r.Output | Should -Match 'incomplete'
        $row = Import-Csv $script:csv
        $row.TargetType | Should -Be 'Error'
        $row.TargetName | Should -Match 'Forbidden'
    }

    It 'follows @odata.nextLink for the policy list and for the assignments (M8)' {
        Add-GraphRoute -First -Like '*deviceConfigurations?$skiptoken=2*' -Body (New-GraphPage @([PSCustomObject]@{ id = 'c2'; displayName = 'Page two' }))
        Add-GraphRoute -Like '*deviceConfigurations' -Body (New-GraphPage @([PSCustomObject]@{ id = 'c1'; displayName = 'Page one' }) -NextLink "$($script:Base)/deviceManagement/deviceConfigurations?`$skiptoken=2")
        Add-GraphRoute -First -Like "*deviceConfigurations('c1')/assignments?`$skiptoken=a2*" -Body (New-GraphPage @([PSCustomObject]@{ id = 'a2'; intent = 'apply'; target = [PSCustomObject]@{ '@odata.type' = '#microsoft.graph.allDevicesAssignmentTarget' } }))
        Add-GraphRoute -Like "*deviceConfigurations('c1')/assignments" -Body (New-GraphPage @([PSCustomObject]@{ id = 'a1'; intent = 'apply'; target = [PSCustomObject]@{ '@odata.type' = '#microsoft.graph.allLicensedUsersAssignmentTarget' } }) -NextLink "$($script:Base)/deviceManagement/deviceConfigurations('c1')/assignments?`$skiptoken=a2")
        Add-GraphRoute -Like "*deviceConfigurations('c2')/assignments" -Body ([PSCustomObject]@{ value = @() })

        $r = Invoke-ScriptUnderTest -Path $script:ScriptPath -Arguments ($script:creds + @{ PolicyType = 'Configuration'; ExportPath = $script:csv })
        $r.ExitCode | Should -Be 0
        $rows = Import-Csv $script:csv
        ($rows | Where-Object PolicyName -eq 'Page two').TargetName | Should -Be 'No assignments'
        @($rows | Where-Object PolicyName -eq 'Page one').Count | Should -Be 2
    }

    It 'keeps exclusion targets visible as their own target type' {
        Add-GraphRoute -Like '*deviceConfigurations' -Body (New-GraphPage @([PSCustomObject]@{ id = 'c1'; displayName = 'P' }))
        Add-GraphRoute -Like "*deviceConfigurations('c1')/assignments" -Body (New-GraphPage @([PSCustomObject]@{ id = 'a1'; target = [PSCustomObject]@{ '@odata.type' = '#microsoft.graph.exclusionGroupAssignmentTarget'; groupId = 'g9' } }))
        Add-GraphRoute -Like '*/groups/g9' -Body ([PSCustomObject]@{ displayName = 'Excluded group' })
        Invoke-ScriptUnderTest -Path $script:ScriptPath -Arguments ($script:creds + @{ PolicyType = 'Configuration'; ExportPath = $script:csv }) | Out-Null
        (Import-Csv $script:csv).TargetType | Should -Be '#microsoft.graph.exclusionGroupAssignmentTarget'
    }

    It 'neutralises a policy name that starts with = so a spreadsheet will not run it (L3)' {
        Add-GraphRoute -Like '*deviceConfigurations' -Body (New-GraphPage @([PSCustomObject]@{ id = 'c1'; displayName = '=HYPERLINK("http://example.invalid","x")' }))
        Add-GraphRoute -Like "*deviceConfigurations('c1')/assignments" -Body ([PSCustomObject]@{ value = @() })
        Invoke-ScriptUnderTest -Path $script:ScriptPath -Arguments ($script:creds + @{ PolicyType = 'Configuration'; ExportPath = $script:csv }) | Out-Null
        (Import-Csv $script:csv).PolicyName | Should -BeLike "'=HYPERLINK*"
    }

    It 'never installs or imports the Microsoft.Graph meta-module (M6)' {
        Add-GraphRoute -Like '*deviceConfigurations' -Body (New-GraphPage @())
        Add-GraphRoute -Like '*deviceCompliancePolicies' -Body (New-GraphPage @())
        $r = Invoke-ScriptUnderTest -Path $script:ScriptPath -Arguments $script:creds
        $r.ExitCode | Should -Be 0
        Should -Invoke Install-Module -Times 0 -Exactly
        (Get-Content $script:ScriptPath -Raw) | Should -Not -Match 'Install-Module'
    }

    It 'accepts the secret as a SecureString and sends the plain value only to the token endpoint (M7)' {
        Add-GraphRoute -Like '*deviceConfigurations' -Body (New-GraphPage @())
        $secure = ConvertTo-SecureString 'secure-secret-value' -AsPlainText -Force
        $r = Invoke-ScriptUnderTest -Path $script:ScriptPath -Arguments @{ AppId = 'app-id'; TenantId = 'tenant-id'; ClientSecretSecure = $secure; PolicyType = 'Configuration' }
        $r.ExitCode | Should -Be 0
        $token = $global:IntuneTestState.Calls | Where-Object { $_.Uri -like '*oauth2/v2.0/token' }
        @($token).Count | Should -Be 1
        $token.Body.client_secret | Should -Be 'secure-secret-value'
        $r.Output | Should -Not -Match 'secure-secret-value'
    }

    It 'reads credentials from INTUNE_* environment variables (M7)' {
        $env:INTUNE_APP_ID = 'env-app'; $env:INTUNE_TENANT_ID = 'env-tenant'; $env:INTUNE_CLIENT_SECRET = 'env-secret'
        try {
            Add-GraphRoute -Like '*deviceConfigurations' -Body (New-GraphPage @())
            (Invoke-ScriptUnderTest -Path $script:ScriptPath -Arguments @{ PolicyType = 'Configuration' }).ExitCode | Should -Be 0
            ($global:IntuneTestState.Calls | Where-Object { $_.Uri -like '*env-tenant*' }) | Should -Not -BeNullOrEmpty
        }
        finally { Remove-Item Env:\INTUNE_APP_ID, Env:\INTUNE_TENANT_ID, Env:\INTUNE_CLIENT_SECRET -ErrorAction SilentlyContinue }
    }

    It 'exits 1 without any HTTP call when credentials are missing or placeholders' {
        $r = Invoke-ScriptUnderTest -Path $script:ScriptPath -Arguments @{ AppId = '<Your Entra Registered App ID here>'; TenantId = 't'; ClientSecret = 's' }
        $r.ExitCode | Should -Be 1
        $global:IntuneTestState.Calls.Count | Should -Be 0
    }
}
