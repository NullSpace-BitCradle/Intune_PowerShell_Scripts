#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

# Tests for Troubleshooting/Get-IntuneDeviceLogs.ps1 (audit finding M11).
# File copies, reg.exe, wevtutil.exe and icacls.exe are mocked, so nothing is exported or changed.

. (Join-Path $PSScriptRoot 'TestHelpers.ps1')
$script:Elevated = Test-IsElevated

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    $script:ScriptPath = Get-RepoPath 'Troubleshooting\Get-IntuneDeviceLogs.ps1'
}

Describe 'Get-IntuneDeviceLogs.ps1' -Skip:(-not $script:Elevated) {
    BeforeEach {
        foreach ($c in ($script:StateChangingCommands + @('reg', 'wevtutil', 'icacls'))) { Mock -CommandName $c -MockWith ([scriptblock]::Create("throw 'UNMOCKED state-changing call: $c'")) }

        $global:IntuneTestState = @{
            OutputPath = (Join-Path $TestDrive 'out')
            HasIme     = $true
            HasMdm     = $true
            RegExit    = 0
            EvtExit    = 0
            Present    = @('Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin')
            Asked      = @()
        }

        Mock Test-Path {
            $p = "$Path"
            if ($p -eq $global:IntuneTestState.OutputPath) { return $false }
            if ($p -like '*IntuneManagementExtension*') { return $global:IntuneTestState.HasIme }
            if ($p -like '*DeviceManagement*Logs*') { return $global:IntuneTestState.HasMdm }
            return $true
        }
        Mock New-Item { [PSCustomObject]@{ FullName = "$Path" } }
        Mock Get-ChildItem { @() }
        Mock Copy-Item { }
        Mock Out-File { }
        Mock Get-CimInstance { [PSCustomObject]@{ Version = '10.0.1'; BuildNumber = '1' } }
        Mock icacls { $global:LASTEXITCODE = 0 }
        Mock reg { $global:LASTEXITCODE = $global:IntuneTestState.RegExit }
        Mock wevtutil { $global:LASTEXITCODE = $global:IntuneTestState.EvtExit }
        Mock Get-WinEvent {
            $global:IntuneTestState.Asked += "$ListLog"
            if ($global:IntuneTestState.Present -contains "$ListLog") { [PSCustomObject]@{ LogName = "$ListLog" } }
        }
    }
    AfterEach { Remove-Variable -Name IntuneTestState -Scope Global -ErrorAction SilentlyContinue }

    It 'exits 0 when everything collected, and restricts the new output folder to SYSTEM and Administrators' {
        $r = Invoke-ScriptUnderTest -Path $script:ScriptPath -Arguments @{ OutputPath = $global:IntuneTestState.OutputPath }
        $r.ExitCode | Should -Be 0
        Should -Invoke icacls -Times 1 -Exactly
        Should -Invoke Copy-Item -Times 2 -Exactly
    }

    It 'exits 1 when the registry export fails, instead of "completed successfully" (M11)' {
        $global:IntuneTestState.RegExit = 1
        $r = Invoke-ScriptUnderTest -Path $script:ScriptPath -Arguments @{ OutputPath = $global:IntuneTestState.OutputPath }
        $r.ExitCode | Should -Be 1
        $r.Output | Should -Not -Match 'completed successfully'
    }

    It 'exits 1 when a copy fails (M11)' {
        Mock Copy-Item { throw 'sharing violation' }
        (Invoke-ScriptUnderTest -Path $script:ScriptPath -Arguments @{ OutputPath = $global:IntuneTestState.OutputPath }).ExitCode | Should -Be 1
    }

    It 'exits 1 when there is nothing to collect (M11)' {
        $global:IntuneTestState.HasIme = $false
        $global:IntuneTestState.HasMdm = $false
        Mock Test-Path { $p = "$Path"; if ($p -like '*Enrollments*' -or $p -eq $global:IntuneTestState.OutputPath -or $p -like '*Logs' -or $p -like '*Logs*') { return $false }; $true }
        (Invoke-ScriptUnderTest -Path $script:ScriptPath -Arguments @{ OutputPath = $global:IntuneTestState.OutputPath }).ExitCode | Should -Be 1
    }

    It 'asks only for real event log names, never the bare provider name (M11)' {
        $r = Invoke-ScriptUnderTest -Path $script:ScriptPath -Arguments @{ OutputPath = $global:IntuneTestState.OutputPath; IncludeEventLogs = $true }
        $r.ExitCode | Should -Be 0
        $global:IntuneTestState.Asked | Should -Not -Contain 'Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider'
        $global:IntuneTestState.Asked | Should -Contain 'Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin'
        Should -Invoke wevtutil -Times 1 -Exactly
    }

    It 'does not claim event logs were collected when none exist (M11)' {
        $global:IntuneTestState.Present = @()
        $r = Invoke-ScriptUnderTest -Path $script:ScriptPath -Arguments @{ OutputPath = $global:IntuneTestState.OutputPath; IncludeEventLogs = $true }
        $r.Output | Should -Not -Match 'Collected: .*Windows Event Logs'
        $r.Output | Should -Match 'No Windows Event Logs were exported'
        Should -Invoke wevtutil -Times 0 -Exactly
    }

    It 'exits 1 when wevtutil fails on a log that exists (M11)' {
        $global:IntuneTestState.EvtExit = 5
        $r = Invoke-ScriptUnderTest -Path $script:ScriptPath -Arguments @{ OutputPath = $global:IntuneTestState.OutputPath; IncludeEventLogs = $true }
        $r.ExitCode | Should -Be 1
    }
}
