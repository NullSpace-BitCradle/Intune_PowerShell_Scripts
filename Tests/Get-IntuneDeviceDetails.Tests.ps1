#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

# Tests for Reporting/Get-IntuneDeviceDetails.ps1 (audit findings M6, M7, M8, L3, L4).

. (Join-Path $PSScriptRoot 'TestHelpers.ps1')

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    $script:ScriptPath = Get-RepoPath 'Reporting\Get-IntuneDeviceDetails.ps1'
    Import-Module (Get-ModuleManifestPath) -Force
    $script:Dev = { param($Id, $Name) [PSCustomObject]@{ id = $Id; deviceName = $Name; userPrincipalName = 'u@example.test'; complianceState = 'compliant'; osVersion = '10.0' } }
}

Describe 'Get-IntuneDeviceDetails.ps1' {
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

    It 'reads every page of a device-name search (M8)' {
        Add-GraphRoute -First -Like '*$skiptoken=2*' -Body (New-GraphPage @((& $script:Dev 'd2' 'LAPTOP-02')))
        Add-GraphRoute -Like '*managedDevices?$filter=*' -Body (New-GraphPage @((& $script:Dev 'd1' 'LAPTOP-01')) -NextLink 'https://graph.microsoft.com/v1.0/deviceManagement/managedDevices?$filter=x&$skiptoken=2')
        $r = Invoke-ScriptUnderTest -Path $script:ScriptPath -Arguments ($script:creds + @{ DeviceName = 'LAPTOP'; ExportPath = $script:csv })
        $r.ExitCode | Should -Be 0
        (Import-Csv $script:csv).DeviceName | Should -Be @('LAPTOP-01', 'LAPTOP-02')
    }

    It 'doubles an apostrophe in a device name instead of deleting it, and URL-encodes the filter (L1)' {
        Add-GraphRoute -Like '*managedDevices?$filter=*' -Body (New-GraphPage @())
        $r = Invoke-ScriptUnderTest -Path $script:ScriptPath -Arguments ($script:creds + @{ DeviceName = "O'Brien-PC" })
        $r.ExitCode | Should -Be 0
        $uri = ($global:IntuneTestState.Calls | Where-Object { $_.Uri -like '*filter=*' }).Uri
        # contains(deviceName,'O''Brien-PC') URL-encoded: ' is %27, so the doubled quote is %27%27
        $uri | Should -Match "O(%27|')(%27|')Brien-PC"
    }

    It 'treats * in a device name as a plain character that is removed, not as a wildcard' {
        Add-GraphRoute -Like '*managedDevices?$filter=*' -Body (New-GraphPage @())
        Invoke-ScriptUnderTest -Path $script:ScriptPath -Arguments ($script:creds + @{ DeviceName = 'LAPTOP-*' }) | Out-Null
        $uri = ($global:IntuneTestState.Calls | Where-Object { $_.Uri -like '*filter=*' }).Uri
        $uri | Should -Not -Match '%2A'
        $uri | Should -Match "LAPTOP-(%27|')"
    }

    It 'rejects a DeviceName that is only wildcards without calling Graph' {
        $r = Invoke-ScriptUnderTest -Path $script:ScriptPath -Arguments ($script:creds + @{ DeviceName = '***' })
        $r.ExitCode | Should -Be 1
        $global:IntuneTestState.Calls.Count | Should -Be 0
    }

    It 'neutralises a device name that starts with = (L3)' {
        Add-GraphRoute -Like '*/managedDevices' -Body (New-GraphPage @((& $script:Dev 'd1' '=1+1')))
        Invoke-ScriptUnderTest -Path $script:ScriptPath -Arguments ($script:creds + @{ ExportPath = $script:csv }) | Out-Null
        (Import-Csv $script:csv).DeviceName | Should -Be "'=1+1"
    }

    It 'never installs Microsoft.Graph (M6)' {
        Add-GraphRoute -Like '*/managedDevices' -Body (New-GraphPage @())
        (Invoke-ScriptUnderTest -Path $script:ScriptPath -Arguments $script:creds).ExitCode | Should -Be 0
        Should -Invoke Install-Module -Times 0 -Exactly
        (Get-Content $script:ScriptPath -Raw) | Should -Not -Match 'Install-Module'
    }

    It 'exits 1 when Graph returns 403' {
        Add-GraphRoute -Like '*/managedDevices' -Throw (New-HttpException -StatusCode 403)
        (Invoke-ScriptUnderTest -Path $script:ScriptPath -Arguments $script:creds).ExitCode | Should -Be 1
    }
}
