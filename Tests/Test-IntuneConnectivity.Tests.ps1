#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

# Tests for Troubleshooting/Test-IntuneConnectivity.ps1 (audit findings H2 and M12).
# The script's functions are extracted from the file by AST. Network calls are mocked.

. (Join-Path $PSScriptRoot 'TestHelpers.ps1')

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    $script:ScriptPath = Get-RepoPath 'Troubleshooting\Test-IntuneConnectivity.ps1'
    $names = 'Invoke-EndpointApiWithRetry', 'ConvertFrom-NetshProxyOutput', 'Get-ProxySettings', 'Get-EndpointList',
             'Get-M365CommonEndpointList', 'Get-IntuneEndpointList', 'Get-EndpointRegionNote', 'Test-EndpointReachable',
             'Test-EndpointSet', 'Test-DeviceIntuneConnectivity'
    . ([scriptblock]::Create((Import-ScriptFunction -Path $script:ScriptPath -Name $names)))

    function New-HttpFailure {
        param([int]$StatusCode)
        $ex = [System.Exception]::new("HTTP $StatusCode")
        $ex | Add-Member -NotePropertyName Response -NotePropertyValue ([PSCustomObject]@{ StatusCode = $StatusCode })
        $ex
    }
}

Describe 'ConvertFrom-NetshProxyOutput (M12)' {
    It 'keeps the whole host name. The old TrimStart() ate leading characters of the proxy name' {
        ConvertFrom-NetshProxyOutput -Lines @('Current WinHTTP proxy settings:', '', '    Proxy Server(s) :  server1.contoso.com:8080', '    Bypass List     :  (none)') |
            Should -Be 'http://server1.contoso.com:8080'
    }
    It 'keeps a proxy name that starts with a character from the old trim set' {
        ConvertFrom-NetshProxyOutput -Lines @('    Proxy Server(s) :  sysproxy:3128') | Should -Be 'http://sysproxy:3128'
    }
    It 'returns NoProxy for direct access' {
        ConvertFrom-NetshProxyOutput -Lines @('Current WinHTTP proxy settings:', '', '    Direct access (no proxy server).') | Should -Be 'NoProxy'
    }
    It 'picks the https entry of a per-protocol list' {
        ConvertFrom-NetshProxyOutput -Lines @('    Proxy Server(s) :  http=a.test:80;https=b.test:443') | Should -Be 'http://b.test:443'
    }
    It 'does not double the scheme' {
        ConvertFrom-NetshProxyOutput -Lines @('    Proxy Server(s) :  http://p.test:8080') | Should -Be 'http://p.test:8080'
    }
    It 'returns a string, never an array' {
        (ConvertFrom-NetshProxyOutput -Lines @('x', '    Proxy Server(s) :  p.test:1', '    Proxy Server(s) :  q.test:2')) | Should -BeOfType [string]
    }
}

Describe 'Get-EndpointRegionNote' {
    It 'maps <Url> to <Region>' -ForEach @(
        @{ Url = 'intunemaape1.eus.attest.azure.net'; Region = 'North America' },
        @{ Url = 'intunemaape10.weu.attest.azure.net'; Region = 'Europe' },
        @{ Url = 'intunemaape13.jpe.attest.azure.net'; Region = 'Asia & Pacific' },
        @{ Url = 'naprodimedata.blob.core.windows.net'; Region = 'North America' },
        @{ Url = 'manage.microsoft.com'; Region = '' }
    ) {
        Get-EndpointRegionNote -Url $Url | Should -Be $Region
    }
}

Describe 'Intune endpoint retrieval (H2)' {
    BeforeEach {
        $global:IntuneTestState = @{ MemFails = $false; CommonFails = $false; WebFails = @{}; WebCalls = @() }
        Mock Start-Sleep { }
        Mock Invoke-RestMethod {
            $uri = "$Uri"
            if ($uri -like '*ServiceAreas=MEM*') {
                if ($global:IntuneTestState.MemFails) { throw 'MEM service down' }
                return @(
                    [PSCustomObject]@{ id = 163; ServiceArea = 'MEM'; urls = @('*.manage.microsoft.com', 'manage.microsoft.com'); tcpPorts = '443'; required = $true },
                    [PSCustomObject]@{ id = 165; ServiceArea = 'MEM'; urls = @('time.windows.com'); udpPorts = '123'; required = $true },
                    [PSCustomObject]@{ id = 9999; ServiceArea = 'MEM'; urls = @('newservice.example.test'); tcpPorts = '443'; required = $true },
                    [PSCustomObject]@{ id = 178; ServiceArea = 'MEM'; urls = @('apple.example.test'); tcpPorts = '443'; required = $false }
                )
            }
            if ($uri -like '*ServiceAreas=Common*') {
                if ($global:IntuneTestState.CommonFails) { throw 'Common service down' }
                return @(
                    [PSCustomObject]@{ id = 56; ServiceArea = 'Common'; urls = @('*.office.com', 'www.office.com'); tcpPorts = '80,443'; required = $true },
                    [PSCustomObject]@{ id = 59; ServiceArea = 'Common'; urls = @('*.microsoftonline.com'); tcpPorts = '443'; required = $true }
                )
            }
            throw "unexpected uri $uri"
        }
        Mock Invoke-WebRequest {
            $global:IntuneTestState.WebCalls += "$Uri"
            foreach ($k in $global:IntuneTestState.WebFails.Keys) {
                if ("$Uri" -like "*$k*") { throw $global:IntuneTestState.WebFails[$k] }
            }
            [PSCustomObject]@{ StatusCode = 200 }
        }
        Mock Get-ProxySettings { 'NoProxy' }
    }
    AfterEach { Remove-Variable -Name IntuneTestState -Scope Global -ErrorAction SilentlyContinue }

    It 'Get-IntuneEndpointList reaches Invoke-EndpointApiWithRetry and returns items (the old call was out of scope)' {
        $list = @(Get-IntuneEndpointList)
        $list.Count | Should -Be 4
        ($list | Where-Object id -eq 163).category | Should -Be 'Global'
        ($list | Where-Object id -eq 163).urls | Should -Be @('manage.microsoft.com')
        ($list | Where-Object id -eq 163).mandatory | Should -BeTrue
    }

    It 'keeps endpoint IDs that are not in the category table, flagged as not known (M12)' {
        $unknown = @(Get-IntuneEndpointList) | Where-Object id -eq 9999
        $unknown.category | Should -Be 'Other (id 9999)'
        $unknown.known | Should -BeFalse
        $unknown.mandatory | Should -BeTrue
    }

    It 'keeps wildcard-only entries out of the URLs to test' {
        $e = @(Get-M365CommonEndpointList) | Where-Object id -eq 59
        @($e.urls).Count | Should -Be 0
        $e.wildcardUrls | Should -Be @('*.microsoftonline.com')
    }

    It 'throws when the service fails instead of returning an empty list' {
        $global:IntuneTestState.MemFails = $true
        { Get-IntuneEndpointList } | Should -Throw '*MEM service down*'
    }

    It 'passes when every mandatory endpoint answers' {
        $ErrorActionPreference = 'Continue'
        Test-DeviceIntuneConnectivity | Should -BeTrue
        $global:IntuneTestState.WebCalls | Should -Contain 'https://manage.microsoft.com/'
        $global:IntuneTestState.WebCalls | Should -Not -Contain 'https://apple.example.test/'
        # not in the built-in tables, so listed as NOT TESTED rather than tested or hidden
        $global:IntuneTestState.WebCalls | Should -Not -Contain 'https://newservice.example.test/'
    }

    It 'tests endpoint IDs outside the built-in tables with -IncludeUnlisted, using their required flag' {
        $ErrorActionPreference = 'Continue'
        Test-DeviceIntuneConnectivity -IncludeUnlisted | Should -BeTrue
        $global:IntuneTestState.WebCalls | Should -Contain 'https://newservice.example.test/'
        $global:IntuneTestState.WebCalls | Should -Not -Contain 'https://apple.example.test/'
    }

    It 'fails on an unlisted endpoint that is down when -IncludeUnlisted is used' {
        $ErrorActionPreference = 'Continue'
        $global:IntuneTestState.WebFails['newservice.example.test'] = [System.Exception]::new('timed out')
        Test-DeviceIntuneConnectivity -IncludeUnlisted | Should -BeFalse
        Test-DeviceIntuneConnectivity | Should -BeTrue
    }

    It 'never requests a wildcard-only domain such as microsoftonline.com (it has no address record)' {
        $ErrorActionPreference = 'Continue'
        Test-DeviceIntuneConnectivity | Should -BeTrue
        ($global:IntuneTestState.WebCalls | Where-Object { $_ -like '*microsoftonline*' }) | Should -BeNullOrEmpty
        ($global:IntuneTestState.WebCalls | Where-Object { $_ -like '*`**' }) | Should -BeNullOrEmpty
    }

    It 'FAILS when the Intune list cannot be retrieved even though the M365 list works (H2)' {
        $ErrorActionPreference = 'Continue'
        $global:IntuneTestState.MemFails = $true
        Test-DeviceIntuneConnectivity 2>$null | Should -BeFalse
        # and nothing was reported as success for Intune
        $global:IntuneTestState.WebCalls | Should -Not -Contain 'https://manage.microsoft.com/'
    }

    It 'FAILS when the M365 list cannot be retrieved' {
        $ErrorActionPreference = 'Continue'
        $global:IntuneTestState.CommonFails = $true
        Test-DeviceIntuneConnectivity 2>$null | Should -BeFalse
    }

    It 'FAILS when the Intune list comes back empty' {
        $ErrorActionPreference = 'Continue'
        Mock Get-IntuneEndpointList { @() }
        Test-DeviceIntuneConnectivity 2>$null | Should -BeFalse
    }

    It 'counts an endpoint that answers 403 as reachable (M12)' {
        $ErrorActionPreference = 'Continue'
        $global:IntuneTestState.WebFails['manage.microsoft.com'] = (New-HttpFailure -StatusCode 403)
        Test-DeviceIntuneConnectivity | Should -BeTrue
    }

    It 'counts a timeout or DNS failure (no HTTP response) as failed' {
        $ErrorActionPreference = 'Continue'
        $global:IntuneTestState.WebFails['manage.microsoft.com'] = [System.Exception]::new('The operation timed out')
        Test-DeviceIntuneConnectivity | Should -BeFalse
    }

    It 'falls back to http when https gets no answer, as for CRL/OCSP hosts that serve port 80 only' {
        $ErrorActionPreference = 'Continue'
        $global:IntuneTestState.WebFails['https://www.office.com'] = [System.Exception]::new('The SSL connection could not be established')
        Test-DeviceIntuneConnectivity | Should -BeTrue
        $global:IntuneTestState.WebCalls | Should -Contain 'http://www.office.com/'
    }

    It 'fails when both https and http get no answer' {
        $ErrorActionPreference = 'Continue'
        $global:IntuneTestState.WebFails['www.office.com'] = [System.Exception]::new('No such host is known')
        Test-DeviceIntuneConnectivity | Should -BeFalse
    }

    It 'skips a UDP-only endpoint (NTP) instead of failing it over HTTP' {
        $ErrorActionPreference = 'Continue'
        Test-DeviceIntuneConnectivity | Should -BeTrue
        $global:IntuneTestState.WebCalls | Should -Not -Contain 'https://time.windows.com/'
        $global:IntuneTestState.WebCalls | Should -Not -Contain 'http://time.windows.com/'
    }
}
