#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

# Tests for Remediation/Set-OfficeUpdateChannel.ps1 (audit finding C1, M1, M2, M4).
# Every cmdlet that can change the machine is mocked. Registry reads and writes go to an
# in-memory table, so the write, verify and exit-code path runs without touching HKLM.

. (Join-Path $PSScriptRoot 'TestHelpers.ps1')
$script:Elevated = Test-IsElevated

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    $script:ScriptPath = Get-RepoPath 'Remediation\Set-OfficeUpdateChannel.ps1'

    $script:CurrentCdn    = 'http://officecdn.microsoft.com/pr/492350f6-3a01-4f97-b9c0-c7c6ddf67d60'
    $script:SemiAnnualCdn = 'http://officecdn.microsoft.com/pr/7ffbc6bf-bc32-4f92-8982-f9dd17fd3114'
    $script:C2RKey        = 'HKLM:\SOFTWARE\Microsoft\Office\ClickToRun\Configuration'
    $script:UpdaterSuffix = 'Microsoft Shared\ClickToRun\OfficeC2RClient.exe'

    # Shape of the real OfficeReleases payload: officeVersions is a list and every entry repeats the CDN URL
    function New-ReleasePayload {
        param([string[]]$SemiAnnualCdns = @($script:SemiAnnualCdn))
        $versions = 1..15 | ForEach-Object { [PSCustomObject]@{ legacyVersion = "16.0.$_"; cdnBaseUrl = $SemiAnnualCdns[($_ - 1) % $SemiAnnualCdns.Count] } }
        @(
            [PSCustomObject]@{ channelId = 'Current'; latestversion = '16.0.99999.1'; officeVersions = @([PSCustomObject]@{ cdnBaseUrl = $script:CurrentCdn }) },
            [PSCustomObject]@{ channelId = 'SemiAnnual'; latestversion = '16.0.17928.20700'; officeVersions = $versions }
        )
    }
    function Invoke-Under { param([hashtable]$Arguments = @{}) Invoke-ScriptUnderTest -Path $script:ScriptPath -Arguments $Arguments }
}

Describe 'Set-OfficeUpdateChannel.ps1' -Skip:(-not $script:Elevated) {
    BeforeEach {
        if ($env:PROCESSOR_ARCHITEW6432) { throw 'This test must not run in a 32-bit host: the relaunch branch would start a real child process.' }

        # Unfiltered default mocks that throw for everything that can change the machine
        foreach ($c in $script:StateChangingCommands) { Mock -CommandName $c -MockWith ([scriptblock]::Create("throw 'UNMOCKED state-changing call: $c'")) }

        # In-memory registry and switches. Mock bodies do not see $script: variables, so the state
        # lives in one global table that AfterEach removes.
        $global:IntuneTestState = @{
            Reg           = @{ CDNBaseUrl = $script:CurrentCdn; VersionToReport = '16.0.1.1' }
            C2RInstalled  = $true
            UpdaterExists = $true
            Payload       = (New-ReleasePayload)
            C2RKey        = $script:C2RKey
            UpdaterSuffix = $script:UpdaterSuffix
        }

        Mock Test-Path {
            $p = "$Path"
            if ($p -eq $global:IntuneTestState.C2RKey) { return $global:IntuneTestState.C2RInstalled }
            if ($p -like "*$($global:IntuneTestState.UpdaterSuffix)") { return $global:IntuneTestState.UpdaterExists }
            return $false
        }
        Mock Get-ItemPropertyValue { $global:IntuneTestState.Reg[$Name] }
        Mock Set-ItemProperty { $global:IntuneTestState.Reg[$Name] = $Value }
        Mock Invoke-RestMethod { $global:IntuneTestState.Payload }
        Mock Start-Process { [PSCustomObject]@{ ExitCode = 0 } }
        Mock Start-Sleep { }
    }

    AfterEach {
        Remove-Variable -Name IntuneTestState -Scope Global -ErrorAction SilentlyContinue
    }

    It 'has its safety net active (an unmocked state change throws)' {
        { New-Item -Path (Join-Path $TestDrive 'x') -ItemType Directory } | Should -Throw '*UNMOCKED*'
    }

    It 'writes ONE string, not an array, to CDNBaseUrl and exits 0 (C1)' {
        $r = Invoke-Under
        $r.ExitCode | Should -Be 0
        $global:IntuneTestState.Reg['CDNBaseUrl'] | Should -BeOfType [string]
        $global:IntuneTestState.Reg['CDNBaseUrl'] | Should -Be $script:SemiAnnualCdn
        Should -Invoke Set-ItemProperty -Times 1 -Exactly
    }

    It 'launches the Click-to-Run updater from Common Files (C1)' {
        $r = Invoke-Under
        $r.ExitCode | Should -Be 0
        Should -Invoke Start-Process -Times 1 -Exactly -ParameterFilter { $FilePath -like '*Microsoft Shared\ClickToRun\OfficeC2RClient.exe' }
    }

    It 'exits 1 when the updater is missing, instead of warning and carrying on (C1)' {
        $global:IntuneTestState.UpdaterExists = $false
        $r = Invoke-Under
        $r.ExitCode | Should -Be 1
        Should -Invoke Start-Process -Times 0 -Exactly
    }

    It 'exits 1 when the updater returns a non-zero code' {
        Mock Start-Process { [PSCustomObject]@{ ExitCode = 5 } }
        (Invoke-Under).ExitCode | Should -Be 1
    }

    It 'exits 1 and writes nothing when the channel has more than one distinct CDN URL' {
        $global:IntuneTestState.Payload = New-ReleasePayload -SemiAnnualCdns @($script:SemiAnnualCdn, 'http://officecdn.microsoft.com/pr/other')
        $r = Invoke-Under
        $r.ExitCode | Should -Be 1
        Should -Invoke Set-ItemProperty -Times 0 -Exactly
    }

    It 'exits 1 when the releases API fails' {
        Mock Invoke-RestMethod { throw 'boom' }
        (Invoke-Under).ExitCode | Should -Be 1
    }

    It 'exits 0 and writes nothing when already on Semi-Annual and the latest version' {
        $global:IntuneTestState.Reg['CDNBaseUrl'] = $script:SemiAnnualCdn
        $global:IntuneTestState.Reg['VersionToReport'] = '16.0.17928.20700'
        $r = Invoke-Under
        $r.ExitCode | Should -Be 0
        Should -Invoke Set-ItemProperty -Times 0 -Exactly
        Should -Invoke Start-Process -Times 0 -Exactly
    }

    It 'exits 0 as not applicable when Click-to-Run is not installed, without calling the API (M4)' {
        $global:IntuneTestState.C2RInstalled = $false
        $r = Invoke-Under
        $r.ExitCode | Should -Be 0
        $r.Output | Should -Match 'Not applicable'
        Should -Invoke Invoke-RestMethod -Times 0 -Exactly
    }

    It '-WhatIf makes no changes and exits 0 instead of failing verification (M1)' {
        $r = Invoke-Under -Arguments @{ WhatIf = $true }
        $r.ExitCode | Should -Be 0
        Should -Invoke Set-ItemProperty -Times 0 -Exactly
        Should -Invoke Start-Process -Times 0 -Exactly
        $global:IntuneTestState.Reg['CDNBaseUrl'] | Should -Be $script:CurrentCdn
    }
}

Describe 'Set-OfficeUpdateChannel.ps1 helper functions' {
    BeforeAll {
        . ([scriptblock]::Create((Import-ScriptFunction -Path $script:ScriptPath -Name 'Get-RelaunchArgumentList', 'Get-ChannelInfo')))
    }

    It 'forwards -WhatIf and -Verbose to the 64-bit relaunch (M2/M3 pattern)' {
        $a = Get-RelaunchArgumentList -ScriptPath 'C:\x\s.ps1' -BoundParameters @{ WhatIf = [switch]$true; Verbose = [switch]$true }
        $a | Should -Contain '-WhatIf'
        $a | Should -Contain '-Verbose'
        $a | Should -Contain 'C:\x\s.ps1'
    }

    It 'does not forward a switch that was not present' {
        $a = Get-RelaunchArgumentList -ScriptPath 'C:\x\s.ps1' -BoundParameters @{ WhatIf = [switch]$false }
        $a | Should -Not -Contain '-WhatIf'
    }

    It 'collapses the 15 repeated CDN entries to a single string' {
        $info = Get-ChannelInfo -CloudVersionInfo (New-ReleasePayload) -ChannelId 'SemiAnnual'
        $info.CdnBaseUrl | Should -BeOfType [string]
        $info.CdnBaseUrl | Should -Be $script:SemiAnnualCdn
        $info.LatestVersion | Should -Be '16.0.17928.20700'
    }

    It 'throws when the channel is missing' {
        { Get-ChannelInfo -CloudVersionInfo (New-ReleasePayload) -ChannelId 'Nope' } | Should -Throw '*Could not find*'
    }
}
