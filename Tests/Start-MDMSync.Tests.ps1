#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

# Tests for Troubleshooting/Start-MDMSync.ps1 (audit finding H7).
# The script itself needs Windows PowerShell 5.1 and a real MDM session, so the tests extract its
# functions and feed them fake session objects. No sync is ever started.

. (Join-Path $PSScriptRoot 'TestHelpers.ps1')

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    $script:ScriptPath = Get-RepoPath 'Troubleshooting\Start-MDMSync.ps1'
    . ([scriptblock]::Create((Import-ScriptFunction -Path $script:ScriptPath -Name 'Get-MdmSessionError', 'Wait-MdmSession', 'Get-MdmSyncExitCode')))

    # A fake session whose State advances one step per Start-Sleep call
    function New-FakeSession {
        param([string[]]$States, $ExtendedError = $null)
        $global:IntuneTestState = @{ Index = 0; States = $States }
        $s = [PSCustomObject]@{ State = $States[0]; ExtendedError = $ExtendedError }
        $global:IntuneTestState.Session = $s
        $s
    }
}

Describe 'Start-MDMSync.ps1' {
    BeforeEach {
        Mock Start-Sleep {
            $st = $global:IntuneTestState
            if ($st.Index -lt ($st.States.Count - 1)) { $st.Index++ }
            $st.Session.State = $st.States[$st.Index]
        }
    }
    AfterEach { Remove-Variable -Name IntuneTestState -Scope Global -ErrorAction SilentlyContinue }

    It 'declares Windows PowerShell 5.1 Desktop so PowerShell 7 gets a clear error, not a type-load failure' {
        $text = Get-Content -Path $script:ScriptPath -Raw
        $text | Should -Match '(?m)^#Requires -PSEdition Desktop'
        $text | Should -Match '(?m)^#Requires -Version 5\.1'
    }

    It 'returns exit 0 when the session reaches Completed with no error' {
        $s = New-FakeSession -States 'Starting', 'Connecting', 'Communicating', 'Completed'
        $r = Wait-MdmSession -Session $s -TimeoutSeconds 60 -CheckIntervalSeconds 5
        $r.State | Should -Be 'Completed'
        $r.TimedOut | Should -BeFalse
        Get-MdmSyncExitCode -Result $r | Should -Be 0
    }

    It 'returns exit 1 when the session Completed but ExtendedError is set (H7)' {
        # COMException sets HResult through its constructor; Exception.HResult has no public setter in Windows PowerShell 5.1
        $err = [System.Runtime.InteropServices.COMException]::new('http error', [int]0x80190190)
        $s = New-FakeSession -States 'Starting', 'Completed' -ExtendedError $err
        $r = Wait-MdmSession -Session $s -TimeoutSeconds 60 -CheckIntervalSeconds 5
        $r.Error | Should -Be '0x80190190'
        Get-MdmSyncExitCode -Result $r | Should -Be 1
    }

    It 'treats ExtendedError with HResult 0 as no error' {
        $ok = [System.Runtime.InteropServices.COMException]::new('ok', 0)
        Get-MdmSessionError -Session ([PSCustomObject]@{ ExtendedError = $ok }) | Should -BeNullOrEmpty
        Get-MdmSessionError -Session ([PSCustomObject]@{ ExtendedError = $null }) | Should -BeNullOrEmpty
    }

    It 'returns exit 2 on timeout, even after many identical states (the old code exited 1 after 6)' {
        $s = New-FakeSession -States 'Connecting'
        $r = Wait-MdmSession -Session $s -TimeoutSeconds 60 -CheckIntervalSeconds 5
        $r.TimedOut | Should -BeTrue
        Get-MdmSyncExitCode -Result $r | Should -Be 2
        Should -Invoke Start-Sleep -Times 12 -Exactly
    }

    It 'does not treat Retrying or AlertStatusAvailable as an end state' {
        $s = New-FakeSession -States 'Starting', 'Retrying', 'AlertStatusAvailable', 'Completed'
        $r = Wait-MdmSession -Session $s -TimeoutSeconds 60 -CheckIntervalSeconds 5
        $r.State | Should -Be 'Completed'
        Get-MdmSyncExitCode -Result $r | Should -Be 0
    }
}
