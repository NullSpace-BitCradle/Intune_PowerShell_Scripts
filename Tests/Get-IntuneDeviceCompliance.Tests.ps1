#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

# Tests for Reporting/Get-IntuneDeviceCompliance.ps1 (audit findings H5, M6, M8, L3, L4).
# Every Graph call goes through a mocked Invoke-RestMethod inside the IntuneCommon module.

. (Join-Path $PSScriptRoot 'TestHelpers.ps1')

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    $script:ScriptPath = Get-RepoPath 'Reporting\Get-IntuneDeviceCompliance.ps1'
    Import-Module (Get-ModuleManifestPath) -Force
    $script:Dev = {
        param($Id, $Name, $Upn = 'u@example.test')
        [PSCustomObject]@{ id = $Id; deviceName = $Name; userPrincipalName = $Upn; complianceState = 'compliant'; osVersion = '10.0'; managementAgent = 'mdm'; lastSyncDateTime = '2025-01-01T00:00:00Z' }
    }
}

Describe 'Get-IntuneDeviceCompliance.ps1' {
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

    It 'gives each device ITS OWN policy states, not the tenant-wide policy list (H5)' {
        Add-GraphRoute -Like '*/managedDevices' -Body (New-GraphPage @((& $script:Dev 'd1' 'PC-ONE'), (& $script:Dev 'd2' 'PC-TWO')))
        Add-GraphRoute -Like "*managedDevices('d1')/deviceCompliancePolicyStates" -Body (New-GraphPage @([PSCustomObject]@{ displayName = 'Baseline'; state = 'compliant' }, [PSCustomObject]@{ displayName = 'BitLocker'; state = 'nonCompliant' }))
        Add-GraphRoute -Like "*managedDevices('d2')/deviceCompliancePolicyStates" -Body (New-GraphPage @([PSCustomObject]@{ displayName = 'Baseline'; state = 'compliant' }))
        # The tenant-wide list must not be what fills the column. A request for it would throw (no route).

        $r = Invoke-ScriptUnderTest -Path $script:ScriptPath -Arguments ($script:creds + @{ ExportPath = $script:csv })
        $r.ExitCode | Should -Be 0
        $rows = Import-Csv $script:csv
        ($rows | Where-Object DeviceName -eq 'PC-ONE').CompliancePolicies | Should -Be 'Baseline (compliant); BitLocker (nonCompliant)'
        ($rows | Where-Object DeviceName -eq 'PC-ONE').NonCompliantPolicies | Should -Be 'BitLocker'
        ($rows | Where-Object DeviceName -eq 'PC-TWO').CompliancePolicies | Should -Be 'Baseline (compliant)'
        ($rows | Where-Object DeviceName -eq 'PC-TWO').NonCompliantPolicies | Should -BeNullOrEmpty
        $global:IntuneTestState.Calls.Uri | Should -Not -Contain 'https://graph.microsoft.com/v1.0/deviceManagement/deviceCompliancePolicies'
    }

    It 'records a CollectionError, says the report is incomplete and exits 1 when a device state call fails (H5)' {
        Add-GraphRoute -Like '*/managedDevices' -Body (New-GraphPage @((& $script:Dev 'd1' 'PC-ONE'), (& $script:Dev 'd2' 'PC-TWO')))
        Add-GraphRoute -Like "*managedDevices('d1')/deviceCompliancePolicyStates" -Throw (New-HttpException -StatusCode 403 -Message 'Forbidden')
        Add-GraphRoute -Like "*managedDevices('d2')/deviceCompliancePolicyStates" -Body (New-GraphPage @([PSCustomObject]@{ displayName = 'Baseline'; state = 'compliant' }))
        $r = Invoke-ScriptUnderTest -Path $script:ScriptPath -Arguments ($script:creds + @{ ExportPath = $script:csv })
        $r.ExitCode | Should -Be 1
        $r.Output | Should -Match 'incomplete'
        $rows = Import-Csv $script:csv
        ($rows | Where-Object DeviceName -eq 'PC-ONE').CollectionError | Should -Match 'Forbidden'
        ($rows | Where-Object DeviceName -eq 'PC-TWO').CollectionError | Should -BeNullOrEmpty
    }

    It 'pages through the device list (M8)' {
        Add-GraphRoute -First -Like '*managedDevices?$skiptoken=2*' -Body (New-GraphPage @((& $script:Dev 'd2' 'PC-TWO')))
        Add-GraphRoute -Like '*/managedDevices' -Body (New-GraphPage @((& $script:Dev 'd1' 'PC-ONE')) -NextLink 'https://graph.microsoft.com/v1.0/deviceManagement/managedDevices?$skiptoken=2')
        Add-GraphRoute -Like '*deviceCompliancePolicyStates' -Body (New-GraphPage @())
        $r = Invoke-ScriptUnderTest -Path $script:ScriptPath -Arguments ($script:creds + @{ ExportPath = $script:csv })
        $r.ExitCode | Should -Be 0
        (Import-Csv $script:csv).DeviceName | Should -Be @('PC-ONE', 'PC-TWO')
    }

    It 'reads one device with -DeviceId' {
        Add-GraphRoute -Like "*managedDevices('11111111-2222-3333-4444-555555555555')" -Body (& $script:Dev '11111111-2222-3333-4444-555555555555' 'PC-ONE')
        Add-GraphRoute -Like '*deviceCompliancePolicyStates' -Body (New-GraphPage @())
        $r = Invoke-ScriptUnderTest -Path $script:ScriptPath -Arguments ($script:creds + @{ DeviceId = '11111111-2222-3333-4444-555555555555'; ExportPath = $script:csv })
        $r.ExitCode | Should -Be 0
        @(Import-Csv $script:csv).Count | Should -Be 1
    }

    It 'rejects a DeviceId that is not a GUID without calling Graph' {
        $r = Invoke-ScriptUnderTest -Path $script:ScriptPath -Arguments ($script:creds + @{ DeviceId = "x' or 1 eq 1" })
        $r.ExitCode | Should -Be 1
        $global:IntuneTestState.Calls.Count | Should -Be 0
    }

    It 'URL-encodes the UPN filter so a + survives, and keeps the quotes balanced (L4)' {
        Add-GraphRoute -Like '*managedDevices?$filter=*' -Body (New-GraphPage @())
        $r = Invoke-ScriptUnderTest -Path $script:ScriptPath -Arguments ($script:creds + @{ UserPrincipalName = 'first+last@example.com' })
        $r.ExitCode | Should -Be 0
        $uri = ($global:IntuneTestState.Calls | Where-Object { $_.Uri -like '*filter=*' }).Uri
        # [uri]::ToString() differs between Windows PowerShell 5.1 and 7 in how much it decodes, so accept both forms
        $uri | Should -Match "userPrincipalName( |%20)eq( |%20)(%27|')first(%2B|\+)last(%40|@)example\.com(%27|')$"
    }

    It '-SkipPolicyStates makes no per-device call' {
        Add-GraphRoute -Like '*/managedDevices' -Body (New-GraphPage @((& $script:Dev 'd1' 'PC-ONE')))
        $r = Invoke-ScriptUnderTest -Path $script:ScriptPath -Arguments ($script:creds + @{ SkipPolicyStates = $true; ExportPath = $script:csv })
        $r.ExitCode | Should -Be 0
        ($global:IntuneTestState.Calls | Where-Object { $_.Uri -like '*deviceCompliancePolicyStates*' }).Count | Should -Be 0
    }

    It 'neutralises a device name that starts with = (L3)' {
        Add-GraphRoute -Like '*/managedDevices' -Body (New-GraphPage @((& $script:Dev 'd1' '=cmd|calc')))
        Add-GraphRoute -Like '*deviceCompliancePolicyStates' -Body (New-GraphPage @())
        Invoke-ScriptUnderTest -Path $script:ScriptPath -Arguments ($script:creds + @{ ExportPath = $script:csv }) | Out-Null
        (Import-Csv $script:csv).DeviceName | Should -Be "'=cmd|calc"
    }

    It 'never installs Microsoft.Graph (M6)' {
        Add-GraphRoute -Like '*/managedDevices' -Body (New-GraphPage @())
        (Invoke-ScriptUnderTest -Path $script:ScriptPath -Arguments $script:creds).ExitCode | Should -Be 0
        Should -Invoke Install-Module -Times 0 -Exactly
        (Get-Content $script:ScriptPath -Raw) | Should -Not -Match 'Install-Module'
    }
}
