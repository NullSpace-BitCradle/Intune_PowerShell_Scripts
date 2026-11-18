#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

# Tests for Common/IntuneCommon.psm1 and its manifest (audit findings L1, L3, L4, M7, M8).

. (Join-Path $PSScriptRoot 'TestHelpers.ps1')

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Import-Module (Get-ModuleManifestPath) -Force
}

Describe 'IntuneCommon manifest (L1)' {
    It 'is a valid manifest that exports every function the module defines' {
        $manifest = Test-ModuleManifest -Path (Get-ModuleManifestPath)
        $manifest.Version.ToString() | Should -Be '1.1.0'
        $manifest.Author | Should -Be 'NullSpace-BitCradle'
        $defined = (Get-Module IntuneCommon).ExportedFunctions.Keys | Sort-Object
        $manifest.ExportedFunctions.Keys | Sort-Object | Should -Be $defined
    }
}

Describe 'Get-IntuneCredential (M7)' {
    BeforeEach { Remove-Item Env:\INTUNE_APP_ID, Env:\INTUNE_TENANT_ID, Env:\INTUNE_CLIENT_SECRET -ErrorAction SilentlyContinue }
    AfterEach { Remove-Item Env:\INTUNE_APP_ID, Env:\INTUNE_TENANT_ID, Env:\INTUNE_CLIENT_SECRET -ErrorAction SilentlyContinue }

    It 'returns the secret as a SecureString' {
        $c = Get-IntuneCredential -AppId 'a' -TenantId 't' -ClientSecret 's'
        $c.ClientSecret | Should -BeOfType [securestring]
        [System.Net.NetworkCredential]::new('', $c.ClientSecret).Password | Should -Be 's'
    }
    It 'prefers a SecureString secret over a plain one' {
        $c = Get-IntuneCredential -AppId 'a' -TenantId 't' -ClientSecret 'plain' -ClientSecretSecure (ConvertTo-SecureString 'secure' -AsPlainText -Force)
        [System.Net.NetworkCredential]::new('', $c.ClientSecret).Password | Should -Be 'secure'
    }
    It 'falls back to the INTUNE_* environment variables' {
        $env:INTUNE_APP_ID = 'ea'; $env:INTUNE_TENANT_ID = 'et'; $env:INTUNE_CLIENT_SECRET = 'es'
        $c = Get-IntuneCredential
        $c.AppId | Should -Be 'ea'
        $c.TenantId | Should -Be 'et'
    }
    It 'prefers parameters over environment variables' {
        $env:INTUNE_APP_ID = 'ea'; $env:INTUNE_TENANT_ID = 'et'; $env:INTUNE_CLIENT_SECRET = 'es'
        (Get-IntuneCredential -AppId 'pa' -TenantId 'pt' -ClientSecret 'ps').AppId | Should -Be 'pa'
    }
    It 'rejects <Name>' -ForEach @(
        @{ Name = 'a missing tenant'; Params = @{ AppId = 'a'; ClientSecret = 's' } },
        @{ Name = 'a missing secret'; Params = @{ AppId = 'a'; TenantId = 't' } },
        @{ Name = 'a placeholder app id'; Params = @{ AppId = '<Your Entra Registered App ID here>'; TenantId = 't'; ClientSecret = 's' } },
        @{ Name = 'a placeholder secret'; Params = @{ AppId = 'a'; TenantId = 't'; ClientSecret = '<Your Client Secret here>' } }
    ) {
        { Get-IntuneCredential @Params } | Should -Throw '*valid credentials*'
    }
}

Describe 'OData escaping (L1, L4)' {
    It 'doubles an apostrophe instead of deleting it' {
        ConvertTo-ODataStringLiteral -Value "O'Brien-PC" | Should -Be "'O''Brien-PC'"
        Remove-ODataInjectionChars -InputString "O'Brien" | Should -Be "O''Brien"
    }
    It 'keeps a semicolon, which is not special inside a quoted literal' {
        ConvertTo-ODataStringLiteral -Value 'a;b' | Should -Be "'a;b'"
    }
    It 'cannot be broken out of with a quote' {
        ConvertTo-ODataStringLiteral -Value "x' or 1 eq 1 or name eq 'y" | Should -Be "'x'' or 1 eq 1 or name eq ''y'"
    }
    It 'Test-ODataFilterInput strips wildcard characters unless allowed, and escapes quotes' {
        Test-ODataFilterInput -InputString "LAP*'TOP" | Should -Be "LAP''TOP"
        Test-ODataFilterInput -InputString "LAP*TOP" -AllowWildcards | Should -Be 'LAP*TOP'
        { Test-ODataFilterInput -InputString '***' } | Should -Throw '*empty*'
    }
    It 'a UPN with + survives once the filter is URL-encoded (L4)' {
        $filter = "userPrincipalName eq $(ConvertTo-ODataStringLiteral -Value 'first+last@example.com')"
        [uri]::EscapeDataString($filter) | Should -Match 'first%2Blast%40example\.com'
    }
}

Describe 'CSV formula safety (L3)' {
    It 'prefixes a value that starts with <Value>' -ForEach @(
        @{ Value = '=SUM(A1)' }, @{ Value = '+1' }, @{ Value = '-1+1' }, @{ Value = '@cmd' }
    ) {
        Protect-CsvValue -Value $Value | Should -Be ("'" + $Value)
    }
    It 'leaves ordinary values, empty strings and nulls alone' {
        Protect-CsvValue -Value 'LAPTOP-01' | Should -Be 'LAPTOP-01'
        Protect-CsvValue -Value '' | Should -Be ''
        Protect-CsvValue -Value $null | Should -BeNullOrEmpty
    }
    It 'ConvertTo-SafeCsvRecord keeps column order and non-string values' {
        $row = [PSCustomObject][ordered]@{ Name = '=evil()'; Count = 5; When = [datetime]'2025-01-02'; Empty = $null }
        $out = $row | ConvertTo-SafeCsvRecord
        $out.PSObject.Properties.Name | Should -Be @('Name', 'Count', 'When', 'Empty')
        $out.Name | Should -Be "'=evil()"
        $out.Count | Should -Be 5
        $out.When | Should -BeOfType [datetime]
    }
}

Describe 'Get-GraphAccessToken (M7)' {
    BeforeEach {
        $global:IntuneTestState = New-GraphTestState
        Mock Invoke-RestMethod -ModuleName IntuneCommon -MockWith $script:GraphMockBody
    }
    AfterEach { Remove-Variable -Name IntuneTestState -Scope Global -ErrorAction SilentlyContinue }

    It 'sends a SecureString secret as client_secret' {
        $t = Get-GraphAccessToken -AppId 'a' -TenantId 't' -ClientSecretSecure (ConvertTo-SecureString 'hidden' -AsPlainText -Force)
        $t | Should -Be 'test-token'
        $global:IntuneTestState.Calls[0].Body.client_secret | Should -Be 'hidden'
        $global:IntuneTestState.Calls[0].Uri | Should -Match '/t/oauth2/v2\.0/token$'
    }
    It 'still accepts a plain-string secret' {
        Get-GraphAccessToken -AppId 'a' -TenantId 't' -ClientSecret 'plain' | Should -Be 'test-token'
    }
}

Describe 'Invoke-GraphApiWithRetry and Get-GraphApiAllPages (M8)' {
    BeforeEach {
        $global:IntuneTestState = New-GraphTestState
        $global:IntuneTestState.Sleeps = @()
        Mock Invoke-RestMethod -ModuleName IntuneCommon -MockWith $script:GraphMockBody
        Mock Start-Sleep -ModuleName IntuneCommon { $global:IntuneTestState.Sleeps += $Seconds }
    }
    AfterEach { Remove-Variable -Name IntuneTestState -Scope Global -ErrorAction SilentlyContinue }

    It 'retries a 429 using Retry-After, then returns the result' {
        $ex = New-HttpException -StatusCode 429
        $ex.Response.Headers = @{ 'Retry-After' = '7' }
        $global:IntuneTestState.Attempts = 0
        Mock Invoke-RestMethod -ModuleName IntuneCommon {
            $global:IntuneTestState.Attempts++
            if ($global:IntuneTestState.Attempts -eq 1) { throw $global:IntuneTestState.Ex }
            [PSCustomObject]@{ ok = $true }
        }
        $global:IntuneTestState.Ex = $ex
        $r = Invoke-GraphApiWithRetry -Uri 'https://graph.microsoft.com/v1.0/x' -Headers @{}
        $r.ok | Should -BeTrue
        $global:IntuneTestState.Sleeps | Should -Be @(7)
    }

    It 'does not retry a 403' {
        Add-GraphRoute -Like '*/x' -Throw (New-HttpException -StatusCode 403)
        { Invoke-GraphApiWithRetry -Uri 'https://graph.microsoft.com/v1.0/x' -Headers @{} } | Should -Throw
        ($global:IntuneTestState.Calls | Where-Object { $_.Uri -like '*/x' }).Count | Should -Be 1
    }

    It 'Get-GraphApiAllPages follows every nextLink and returns every item' {
        Add-GraphRoute -First -Like '*/list?page=3' -Body (New-GraphPage @(5))
        Add-GraphRoute -First -Like '*/list?page=2' -Body (New-GraphPage @(3, 4) -NextLink 'https://graph.microsoft.com/v1.0/list?page=3')
        Add-GraphRoute -Like '*/list' -Body (New-GraphPage @(1, 2) -NextLink 'https://graph.microsoft.com/v1.0/list?page=2')
        @(Get-GraphApiAllPages -Uri 'https://graph.microsoft.com/v1.0/list' -Headers @{}) | Should -Be @(1, 2, 3, 4, 5)
    }

    It 'Get-GraphApiAllPages returns an empty list for an empty value array' {
        Add-GraphRoute -Like '*/empty' -Body ([PSCustomObject]@{ value = @() })
        @(Get-GraphApiAllPages -Uri 'https://graph.microsoft.com/v1.0/empty' -Headers @{}).Count | Should -Be 0
    }
}

Describe 'The H5 premise: an empty Graph list is not $null' {
    It 'parses {"value":[]} to an empty array, so a $null test never sees it' {
        $r = '{"value":[]}' | ConvertFrom-Json
        ($null -eq $r.value) | Should -BeFalse
        @($r.value).Count | Should -Be 0
    }
}
