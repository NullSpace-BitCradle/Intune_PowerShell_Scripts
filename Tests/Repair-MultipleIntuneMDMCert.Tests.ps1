#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

# Tests for Remediation/Repair-MultipleIntuneMDMCert.ps1 (audit finding M1).
# The certificate store is an in-memory list; nothing touches Cert:\LocalMachine\My.

. (Join-Path $PSScriptRoot 'TestHelpers.ps1')
$script:Elevated = Test-IsElevated

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    $script:ScriptPath = Get-RepoPath 'Remediation\Repair-MultipleIntuneMDMCert.ps1'
    function New-FakeCert {
        param([string]$Thumbprint, [datetime]$NotBefore, [string]$Issuer = 'CN=Microsoft Intune MDM Device CA')
        [PSCustomObject]@{ Thumbprint = $Thumbprint; NotBefore = $NotBefore; Issuer = $Issuer; PSPath = "fake::$Thumbprint" }
    }
}

Describe 'Repair-MultipleIntuneMDMCert.ps1' -Skip:(-not $script:Elevated) {
    BeforeEach {
        foreach ($c in $script:StateChangingCommands) { Mock -CommandName $c -MockWith ([scriptblock]::Create("throw 'UNMOCKED state-changing call: $c'")) }
        $global:IntuneTestState = @{
            Store = [System.Collections.ArrayList]@(
                (New-FakeCert 'OLD' ([datetime]'2024-01-01')),
                (New-FakeCert 'NEW' ([datetime]'2025-06-01')),
                (New-FakeCert 'OTHER' ([datetime]'2020-01-01') 'CN=Something Else')
            )
        }
        Mock Test-Path { $true }
        Mock Get-ChildItem { , @($global:IntuneTestState.Store) | ForEach-Object { $_ } }
        Mock Remove-Item { $t = $global:IntuneTestState.Store | Where-Object { $_.PSPath -eq $Path } | Select-Object -First 1; if ($t) { $global:IntuneTestState.Store.Remove($t) } }
    }
    AfterEach { Remove-Variable -Name IntuneTestState -Scope Global -ErrorAction SilentlyContinue }

    It 'removes the older certificate, keeps the newest, exits 0' {
        $r = Invoke-ScriptUnderTest -Path $script:ScriptPath
        $r.ExitCode | Should -Be 0
        Should -Invoke Remove-Item -Times 1 -Exactly -ParameterFilter { $Path -eq 'fake::OLD' }
        ($global:IntuneTestState.Store.Thumbprint -contains 'NEW') | Should -BeTrue
        ($global:IntuneTestState.Store.Thumbprint -contains 'OTHER') | Should -BeTrue
    }

    It '-WhatIf removes nothing and exits 0 instead of failing verification (M1)' {
        $r = Invoke-ScriptUnderTest -Path $script:ScriptPath -Arguments @{ WhatIf = $true }
        $r.ExitCode | Should -Be 0
        Should -Invoke Remove-Item -Times 0 -Exactly
        $global:IntuneTestState.Store.Count | Should -Be 3
    }

    It 'exits 0 and removes nothing when there is a single Intune certificate' {
        $global:IntuneTestState.Store.RemoveAt(0)
        $r = Invoke-ScriptUnderTest -Path $script:ScriptPath
        $r.ExitCode | Should -Be 0
        Should -Invoke Remove-Item -Times 0 -Exactly
    }

    It 'exits 1 when a removal fails' {
        Mock Remove-Item { throw 'access denied' }
        (Invoke-ScriptUnderTest -Path $script:ScriptPath).ExitCode | Should -Be 1
    }
}
