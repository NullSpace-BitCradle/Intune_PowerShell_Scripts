#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

# Tests for Troubleshooting/Test-IntuneEnrollment.ps1 (audit finding H1).
# The Enrollments key always holds subkeys with no ProviderID. Get-ItemPropertyValue threw on them and
# the script crashed with exit 1 before it judged anything. The registry here is an in-memory table.

. (Join-Path $PSScriptRoot 'TestHelpers.ps1')

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    $script:ScriptPath = Get-RepoPath 'Troubleshooting\Test-IntuneEnrollment.ps1'
    $script:Root = 'HKLM:\SOFTWARE\Microsoft\Enrollments'
}

Describe 'Test-IntuneEnrollment.ps1' {
    BeforeEach {
        foreach ($c in $script:StateChangingCommands) { Mock -CommandName $c -MockWith ([scriptblock]::Create("throw 'UNMOCKED state-changing call: $c'")) }

        # Subkeys as they exist on a real device: some have no ProviderID at all
        $global:IntuneTestState = @{
            Root = $script:Root
            Keys = @{
                "$($script:Root)\Context"           = @{}
                "$($script:Root)\Status"            = @{}
                "$($script:Root)\ValidNodePaths"    = @{}
                "$($script:Root)\18DCFFD4-AAAA"     = @{}
                "$($script:Root)\11111111-2222"     = @{ ProviderID = 'MS DM Server'; EnrollmentState = 1; EnrollmentType = 6; UPN = 'user@example.test'; FirstSyncTime = 1700000000 }
                "$($script:Root)\11111111-2222\DMClient\MS DM Server" = @{ EntDMID = 'abcd-1234' }
            }
            Service = $null
        }

        Mock Test-Path { $global:IntuneTestState.Keys.ContainsKey("$Path") -or "$Path" -eq $global:IntuneTestState.Root }
        Mock Get-ChildItem {
            $prefix = $global:IntuneTestState.Root + '\'
            $global:IntuneTestState.Keys.Keys | Where-Object { $_.StartsWith($prefix) -and ($_.Substring($prefix.Length) -notlike '*\*') } | ForEach-Object {
                [PSCustomObject]@{ PSPath = $_; PSChildName = $_.Substring($prefix.Length) }
            }
        }
        Mock Get-ItemProperty {
            $k = "$Path"
            if (-not $global:IntuneTestState.Keys.ContainsKey($k)) { return $null }
            $o = [PSCustomObject]@{}
            foreach ($name in $global:IntuneTestState.Keys[$k].Keys) { $o | Add-Member -NotePropertyName $name -NotePropertyValue $global:IntuneTestState.Keys[$k][$name] }
            $o
        }
        Mock Get-ItemPropertyValue { throw 'Get-ItemPropertyValue must not be used: it throws on a missing value' }
        Mock Get-Service { $global:IntuneTestState.Service }
    }
    AfterEach { Remove-Variable -Name IntuneTestState -Scope Global -ErrorAction SilentlyContinue }

    It 'does not crash on subkeys without ProviderID and exits 0 for an enrolled device (H1)' {
        $r = Invoke-ScriptUnderTest -Path $script:ScriptPath
        $r.ExitCode | Should -Be 0
        $r.Output | Should -Match 'Device is enrolled in Intune'
        $r.Output | Should -Match 'abcd-1234'
        Should -Invoke Get-ItemPropertyValue -Times 0 -Exactly
    }

    It 'exits 1 and says not enrolled when only the non-enrollment subkeys exist (no crash)' {
        $global:IntuneTestState.Keys.Remove("$($script:Root)\11111111-2222")
        $global:IntuneTestState.Keys.Remove("$($script:Root)\11111111-2222\DMClient\MS DM Server")
        $r = Invoke-ScriptUnderTest -Path $script:ScriptPath
        $r.ExitCode | Should -Be 1
        $r.Output | Should -Match 'does not appear to be enrolled'
        $r.Output | Should -Not -Match 'Failed to test Intune enrollment'
    }

    It 'exits 1 when the Intune record exists but EnrollmentState is not 1' {
        $global:IntuneTestState.Keys["$($script:Root)\11111111-2222"].EnrollmentState = 0
        $r = Invoke-ScriptUnderTest -Path $script:ScriptPath
        $r.ExitCode | Should -Be 1
        $r.Output | Should -Match 'EnrollmentState is not 1'
    }

    It 'does not count a non-Intune MDM provider as Intune (the old *Microsoft* wildcard would)' {
        $global:IntuneTestState.Keys["$($script:Root)\11111111-2222"].ProviderID = 'Microsoft Something Else'
        (Invoke-ScriptUnderTest -Path $script:ScriptPath).ExitCode | Should -Be 1
    }

    It 'exits 1 when the Enrollments key does not exist' {
        $global:IntuneTestState.Keys.Clear()
        Mock Test-Path { $false }
        $r = Invoke-ScriptUnderTest -Path $script:ScriptPath
        $r.ExitCode | Should -Be 1
        $r.Output | Should -Match 'registry path not found'
    }
}
