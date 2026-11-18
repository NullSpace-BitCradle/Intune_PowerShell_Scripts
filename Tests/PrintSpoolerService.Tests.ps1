#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

# Tests for Security/Enable-PrintSpoolerService.ps1 and Disable-PrintSpoolerService.ps1 (audit finding L6).
# The service control cmdlets are mocked. Nothing touches the real Print Spooler.

. (Join-Path $PSScriptRoot 'TestHelpers.ps1')
$script:Elevated = Test-IsElevated

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    $script:Enable  = Get-RepoPath 'Security\Enable-PrintSpoolerService.ps1'
    $script:Disable = Get-RepoPath 'Security\Disable-PrintSpoolerService.ps1'
}

Describe 'Print Spooler scripts' -Skip:(-not $script:Elevated) {
    BeforeEach {
        foreach ($c in $script:StateChangingCommands) { Mock -CommandName $c -MockWith ([scriptblock]::Create("throw 'UNMOCKED state-changing call: $c'")) }
        $global:IntuneTestState = @{ Status = 'Stopped'; StartType = 'Disabled'; Dependents = @(); Calls = @() }
        Mock Get-Service {
            [PSCustomObject]@{ Name = 'Spooler'; Status = $global:IntuneTestState.Status; StartType = $global:IntuneTestState.StartType; DependentServices = $global:IntuneTestState.Dependents }
        }
        Mock Set-Service { $global:IntuneTestState.Calls += "Set-Service $StartupType" }
        Mock Start-Service { $global:IntuneTestState.Calls += 'Start-Service' }
        Mock Stop-Service { $global:IntuneTestState.Calls += "Stop-Service force=$([bool]$Force)" }
        Mock Start-Sleep { $global:IntuneTestState.Calls += "Start-Sleep $Seconds" }
    }
    AfterEach { Remove-Variable -Name IntuneTestState -Scope Global -ErrorAction SilentlyContinue }

    It 'Enable sets Automatic and starts the service without a 10 second wait (L6)' {
        $r = Invoke-ScriptUnderTest -Path $script:Enable
        $r.ExitCode | Should -Be 0
        $global:IntuneTestState.Calls | Should -Be @('Set-Service Automatic', 'Start-Service')
        Should -Invoke Start-Sleep -Times 0 -Exactly
    }

    It 'Enable -WhatIf changes nothing' {
        $r = Invoke-ScriptUnderTest -Path $script:Enable -Arguments @{ WhatIf = $true }
        $r.ExitCode | Should -Be 0
        $global:IntuneTestState.Calls.Count | Should -Be 0
    }

    It 'Disable stops WITHOUT -Force so dependent services are not stopped (L6)' {
        $global:IntuneTestState.Status = 'Running'; $global:IntuneTestState.StartType = 'Automatic'
        $r = Invoke-ScriptUnderTest -Path $script:Disable
        $r.ExitCode | Should -Be 0
        $global:IntuneTestState.Calls | Should -Contain 'Stop-Service force=False'
        $global:IntuneTestState.Calls | Should -Contain 'Set-Service Disabled'
    }

    It 'Disable warns about running dependent services' {
        $global:IntuneTestState.Status = 'Running'
        $global:IntuneTestState.Dependents = @([PSCustomObject]@{ Name = 'FaxService'; Status = 'Running' })
        $r = Invoke-ScriptUnderTest -Path $script:Disable
        $r.Output | Should -Match 'FaxService'
    }

    It 'Disable exits 1 when Stop-Service fails because of a running dependent' {
        $global:IntuneTestState.Status = 'Running'
        Mock Stop-Service { throw 'Cannot stop service because it has running dependent services.' }
        (Invoke-ScriptUnderTest -Path $script:Disable).ExitCode | Should -Be 1
    }

    It 'Disable -WhatIf changes nothing' {
        $global:IntuneTestState.Status = 'Running'
        (Invoke-ScriptUnderTest -Path $script:Disable -Arguments @{ WhatIf = $true }).ExitCode | Should -Be 0
        $global:IntuneTestState.Calls.Count | Should -Be 0
    }

    It 'neither script file has a BOM or a non-ASCII character' {
        foreach ($p in @($script:Enable, $script:Disable)) {
            $bytes = [System.IO.File]::ReadAllBytes($p)
            ($bytes | Where-Object { $_ -gt 127 }).Count | Should -Be 0
        }
    }
}
