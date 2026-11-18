#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

# Tests for Detection/Detect-OfficeUpdateChannel.ps1 (audit finding M2, M4).
# Intune Remediations contract: exit 0 = no remediation needed, exit 1 = run the remediation.

. (Join-Path $PSScriptRoot 'TestHelpers.ps1')

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    $script:ScriptPath = Get-RepoPath 'Detection\Detect-OfficeUpdateChannel.ps1'
    $script:CurrentCdn    = 'http://officecdn.microsoft.com/pr/492350f6-3a01-4f97-b9c0-c7c6ddf67d60'
    $script:SemiAnnualCdn = 'http://officecdn.microsoft.com/pr/7ffbc6bf-bc32-4f92-8982-f9dd17fd3114'
    function New-ReleasePayload {
        @(
            [PSCustomObject]@{ channelId = 'Current'; latestversion = '16.0.99999.1'; officeVersions = @([PSCustomObject]@{ cdnBaseUrl = $script:CurrentCdn }) },
            [PSCustomObject]@{ channelId = 'SemiAnnual'; latestversion = '16.0.17928.20700'; officeVersions = @(1..15 | ForEach-Object { [PSCustomObject]@{ cdnBaseUrl = $script:SemiAnnualCdn } }) }
        )
    }
    function Invoke-Under { Invoke-ScriptUnderTest -Path $script:ScriptPath }
}

Describe 'Detect-OfficeUpdateChannel.ps1' {
    BeforeEach {
        if ($env:PROCESSOR_ARCHITEW6432) { throw 'This test must not run in a 32-bit host.' }
        foreach ($c in $script:StateChangingCommands) { Mock -CommandName $c -MockWith ([scriptblock]::Create("throw 'UNMOCKED state-changing call: $c'")) }

        $global:IntuneTestState = @{
            Reg          = @{ CDNBaseUrl = $script:SemiAnnualCdn; VersionToReport = '16.0.17928.20700' }
            C2RInstalled = $true
            Payload      = (New-ReleasePayload)
            ApiFails     = $false
        }
        Mock Test-Path { $global:IntuneTestState.C2RInstalled }
        Mock Get-ItemPropertyValue { $global:IntuneTestState.Reg[$Name] }
        Mock Invoke-RestMethod { if ($global:IntuneTestState.ApiFails) { throw 'network down' } $global:IntuneTestState.Payload }
        Mock Start-Sleep { }
    }
    AfterEach { Remove-Variable -Name IntuneTestState -Scope Global -ErrorAction SilentlyContinue }

    It 'exits 0 when on Semi-Annual and the latest version' {
        $r = Invoke-Under
        $r.ExitCode | Should -Be 0
        $r.Output | Should -Match 'Compliant'
    }

    It 'exits 1 and names the channel when not on Semi-Annual' {
        $global:IntuneTestState.Reg['CDNBaseUrl'] = $script:CurrentCdn
        $r = Invoke-Under
        $r.ExitCode | Should -Be 1
        $r.Output | Should -Match 'not using the Semi-Annual channel'
        $r.Output | Should -Match 'Current Channel'
    }

    It 'exits 1 and says it is BEHIND, not on the wrong channel, when Semi-Annual but old (M4)' {
        $global:IntuneTestState.Reg['VersionToReport'] = '16.0.1.1'
        $r = Invoke-Under
        $r.ExitCode | Should -Be 1
        $r.Output | Should -Match 'behind'
        $r.Output | Should -Not -Match 'not using the Semi-Annual channel'
    }

    It 'exits 0 as not applicable when Click-to-Run is not installed (M4)' {
        $global:IntuneTestState.C2RInstalled = $false
        $r = Invoke-Under
        $r.ExitCode | Should -Be 0
        $r.Output | Should -Match 'Not applicable'
        Should -Invoke Invoke-RestMethod -Times 0 -Exactly
    }

    It 'exits 0 with "Cannot determine" when the releases service is unreachable (M4)' {
        $global:IntuneTestState.ApiFails = $true
        $r = Invoke-Under
        $r.ExitCode | Should -Be 0
        $r.Output | Should -Match 'Cannot determine'
    }

    It 'exits 1 when the local CDN URL is not a Microsoft-listed channel' {
        $global:IntuneTestState.Reg['CDNBaseUrl'] = 'http://example.invalid/custom'
        (Invoke-Under).ExitCode | Should -Be 1
    }
}

Describe 'Detect-OfficeUpdateChannel.ps1 relaunch arguments (M2)' {
    BeforeAll {
        . ([scriptblock]::Create((Import-ScriptFunction -Path $script:ScriptPath -Name 'Get-RelaunchArgumentList')))
    }
    It 'forwards -Verbose to the 64-bit child' {
        Get-RelaunchArgumentList -ScriptPath 'C:\x\d.ps1' -BoundParameters @{ Verbose = [switch]$true } | Should -Contain '-Verbose'
    }
}
