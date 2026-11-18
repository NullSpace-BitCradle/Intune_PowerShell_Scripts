#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

# Tests for Security/Enable-SmartCardLogonEnforcement.ps1 and Disable-SmartCardLogonEnforcement.ps1
# (audit findings H3 lockout guard, H4 false success and deleted log, M3 dropped -WhatIf, L2 phantom key).
# The registry, services, log file and hardware list are in-memory. No real registry write can happen:
# every state-changing cmdlet has an unfiltered default mock that throws.

. (Join-Path $PSScriptRoot 'TestHelpers.ps1')
$script:Elevated = Test-IsElevated

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    $script:Enable  = Get-RepoPath 'Security\Enable-SmartCardLogonEnforcement.ps1'
    $script:Disable = Get-RepoPath 'Security\Disable-SmartCardLogonEnforcement.ps1'
    $script:SysKey  = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    $script:WinKey  = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
    $script:SvcKey  = 'HKLM:\SYSTEM\CurrentControlSet\Services\SCPolicySvc'
}

Describe 'Smart card logon scripts' -Skip:(-not $script:Elevated) {
    BeforeEach {
        if ($env:PROCESSOR_ARCHITEW6432) { throw 'This test must not run in a 32-bit host: the relaunch branch would start a real child process.' }
        foreach ($c in $script:StateChangingCommands) { Mock -CommandName $c -MockWith ([scriptblock]::Create("throw 'UNMOCKED state-changing call: $c'")) }

        $global:IntuneTestState = @{
            Keys       = [System.Collections.ArrayList]@($script:SysKey, $script:WinKey, $script:SvcKey)
            Values     = @{}
            Readers    = @([PSCustomObject]@{ Name = 'Fake Reader'; Status = 'OK' })
            StartType  = 'Manual'
            ServiceSet = @()
            Log        = [System.Collections.ArrayList]@()
            WriteFails = $false
            WriteFailsFor = $null   # when set, only a write to this value name fails
            ServiceFails = $false
            ReadBackName = $null    # when set, ReadBack applies only to this value name
            ReadBack   = $null   # when set, Get-ItemProperty returns this instead of the stored value
        }

        Mock Test-Path { $p = "$Path$LiteralPath"; if ($p -like '*IntuneManagementExtension*') { return $true }; $global:IntuneTestState.Keys -contains $p }
        Mock New-Item { [void]$global:IntuneTestState.Keys.Add("$Path") }
        Mock New-ItemProperty {
            if ($global:IntuneTestState.WriteFails -or ($global:IntuneTestState.WriteFailsFor -and $Name -eq $global:IntuneTestState.WriteFailsFor)) { throw 'Requested registry access is not allowed.' }
            $global:IntuneTestState.Values["$LiteralPath|$Name"] = $Value
        }
        Mock Get-ItemProperty {
            $n = @($Name)[0]
            $v = $global:IntuneTestState.Values["$LiteralPath|$n"]
            if ($null -ne $global:IntuneTestState.ReadBack -and (-not $global:IntuneTestState.ReadBackName -or $n -eq $global:IntuneTestState.ReadBackName)) { $v = $global:IntuneTestState.ReadBack }
            $o = [PSCustomObject]@{}
            $o | Add-Member -NotePropertyName $n -NotePropertyValue $v
            $o
        }
        Mock Get-CimInstance { $global:IntuneTestState.Readers }
        Mock Set-Service { if ($global:IntuneTestState.ServiceFails) { throw 'Access is denied' }; $global:IntuneTestState.ServiceSet += "$Name=$StartupType"; $global:IntuneTestState.StartType = "$StartupType" }
        Mock Get-Service { [PSCustomObject]@{ Name = 'SCPolicySvc'; StartType = $global:IntuneTestState.StartType } }
        Mock Add-Content { [void]$global:IntuneTestState.Log.Add("$Value") }
        Mock Start-Sleep { }
    }
    AfterEach { Remove-Variable -Name IntuneTestState -Scope Global -ErrorAction SilentlyContinue }

    Context 'Enable-SmartCardLogonEnforcement.ps1' {
        It 'writes the three DWORDs, sets the service, verifies, exits 0 and keeps its log (H4)' {
            $r = Invoke-ScriptUnderTest -Path $script:Enable
            $r.ExitCode | Should -Be 0
            $v = $global:IntuneTestState.Values
            $v["$($script:SysKey)|scforceoption"] | Should -Be 1
            $v["$($script:WinKey)|ScRemoveOption"] | Should -Be 1
            $v["$($script:SvcKey)|Start"] | Should -Be 2
            $global:IntuneTestState.ServiceSet | Should -Contain 'SCPolicySvc=Automatic'
            Should -Invoke Remove-Item -Times 0 -Exactly
            ($global:IntuneTestState.Log -join "`n") | Should -Match 'completed successfully'
        }

        It 'writes DWORD values, not strings' {
            Invoke-ScriptUnderTest -Path $script:Enable | Out-Null
            Should -Invoke New-ItemProperty -Times 3 -Exactly -ParameterFilter { $PropertyType -eq 'DWord' }
        }

        It 'REFUSES with exit 1 and changes nothing when there is no smart card reader (H3)' {
            $global:IntuneTestState.Readers = @()
            $r = Invoke-ScriptUnderTest -Path $script:Enable
            $r.ExitCode | Should -Be 1
            $r.Output | Should -Match 'lock every user out'
            Should -Invoke New-ItemProperty -Times 0 -Exactly
            Should -Invoke New-Item -Times 0 -Exactly
            Should -Invoke Set-Service -Times 0 -Exactly
        }

        It 'ignores a reader that is not in a healthy state (H3)' {
            $global:IntuneTestState.Readers = @([PSCustomObject]@{ Name = 'Broken Reader'; Status = 'Error' })
            (Invoke-ScriptUnderTest -Path $script:Enable).ExitCode | Should -Be 1
            Should -Invoke New-ItemProperty -Times 0 -Exactly
        }

        It 'proceeds past the guard with -Force when there is no reader' {
            $global:IntuneTestState.Readers = @()
            $r = Invoke-ScriptUnderTest -Path $script:Enable -Arguments @{ Force = $true }
            $r.ExitCode | Should -Be 0
            $global:IntuneTestState.Values["$($script:SysKey)|scforceoption"] | Should -Be 1
        }

        It 'exits 1 when a registry write fails instead of reporting success (H4)' {
            $global:IntuneTestState.WriteFails = $true
            $r = Invoke-ScriptUnderTest -Path $script:Enable
            $r.ExitCode | Should -Be 1
            $r.Output | Should -Match 'NOT fully applied'
        }

        It 'does NOT require a smart card when the service step fails: scforceoption is never written (review blocker)' {
            $global:IntuneTestState.ServiceFails = $true
            $r = Invoke-ScriptUnderTest -Path $script:Enable
            $r.ExitCode | Should -Be 1
            $global:IntuneTestState.Values.ContainsKey("$($script:SysKey)|scforceoption") | Should -BeFalse
            $r.Output | Should -Match 'Not enforcing|NOT fully applied'
        }

        It 'does not write scforceoption when ScRemoveOption failed' {
            $global:IntuneTestState.WriteFailsFor = 'ScRemoveOption'
            $r = Invoke-ScriptUnderTest -Path $script:Enable
            $r.ExitCode | Should -Be 1
            $global:IntuneTestState.Values.ContainsKey("$($script:SysKey)|scforceoption") | Should -BeFalse
        }

        It 'writes scforceoption last, after the removal option and the service' {
            $global:IntuneTestState.Order = @()
            Mock New-ItemProperty { $global:IntuneTestState.Order += "$Name"; $global:IntuneTestState.Values["$LiteralPath|$Name"] = $Value }
            Invoke-ScriptUnderTest -Path $script:Enable | Out-Null
            $global:IntuneTestState.Order[-1] | Should -Be 'scforceoption'
            $global:IntuneTestState.Order | Should -Contain 'ScRemoveOption'
        }

        It 'rolls scforceoption back to its previous value when its own read-back fails' {
            $global:IntuneTestState.Values["$($script:SysKey)|scforceoption"] = 0
            $global:IntuneTestState.ReadBack = 0
            $global:IntuneTestState.ReadBackName = 'scforceoption'
            $r = Invoke-ScriptUnderTest -Path $script:Enable
            $r.ExitCode | Should -Be 1
            $global:IntuneTestState.Values["$($script:SysKey)|scforceoption"] | Should -Be 0
            ($global:IntuneTestState.Log -join "`n") | Should -Match 'Rolled scforceoption back to 0'
        }

        It 'rolls back to 0 when there was no previous scforceoption value and its write fails' {
            $global:IntuneTestState.WriteFailsFor = 'scforceoption'
            $r = Invoke-ScriptUnderTest -Path $script:Enable
            $r.ExitCode | Should -Be 1
            # the rollback write also fails in this setup, which must be reported, not hidden
            $r.Output | Should -Match 'rollback'
        }

        It 'exits 1 when the read-back does not match what was written (H4)' {
            $global:IntuneTestState.ReadBack = 0
            (Invoke-ScriptUnderTest -Path $script:Enable).ExitCode | Should -Be 1
        }

        It 'does not create a phantom SCPolicySvc key, and fails, when the service key is missing (L2)' {
            # The reader preflight also needs the key, so use -Force to reach the service section
            [void]$global:IntuneTestState.Keys.Remove($script:SvcKey)
            $r = Invoke-ScriptUnderTest -Path $script:Enable -Arguments @{ Force = $true }
            $r.ExitCode | Should -Be 1
            Should -Invoke New-Item -Times 0 -Exactly -ParameterFilter { "$Path" -like '*SCPolicySvc*' }
        }

        It 'refuses without -Force when the service key is missing (H3)' {
            [void]$global:IntuneTestState.Keys.Remove($script:SvcKey)
            $r = Invoke-ScriptUnderTest -Path $script:Enable
            $r.ExitCode | Should -Be 1
            Should -Invoke New-ItemProperty -Times 0 -Exactly
        }

        It '-WhatIf changes nothing at all, writes no log, and exits 0 (M3)' {
            $r = Invoke-ScriptUnderTest -Path $script:Enable -Arguments @{ WhatIf = $true }
            $r.ExitCode | Should -Be 0
            Should -Invoke New-ItemProperty -Times 0 -Exactly
            Should -Invoke New-Item -Times 0 -Exactly
            Should -Invoke Set-Service -Times 0 -Exactly
            Should -Invoke Add-Content -Times 0 -Exactly
            Should -Invoke Remove-Item -Times 0 -Exactly
        }

        It '-WhatIf with no reader reports the refusal but still changes nothing and exits 0' {
            $global:IntuneTestState.Readers = @()
            $r = Invoke-ScriptUnderTest -Path $script:Enable -Arguments @{ WhatIf = $true }
            $r.ExitCode | Should -Be 0
            $r.Output | Should -Match 'would refuse'
            Should -Invoke New-ItemProperty -Times 0 -Exactly
        }
    }

    Context 'Disable-SmartCardLogonEnforcement.ps1' {
        It 'writes the three DWORDs (0, 0, Start 4), disables the service, verifies, exits 0, keeps its log (H4)' {
            $r = Invoke-ScriptUnderTest -Path $script:Disable
            $r.ExitCode | Should -Be 0
            $v = $global:IntuneTestState.Values
            $v["$($script:SysKey)|scforceoption"] | Should -Be 0
            $v["$($script:WinKey)|ScRemoveOption"] | Should -Be 0
            $v["$($script:SvcKey)|Start"] | Should -Be 4
            $global:IntuneTestState.ServiceSet | Should -Contain 'SCPolicySvc=Disabled'
            Should -Invoke Remove-Item -Times 0 -Exactly
        }

        It 'is not blocked by the reader guard (it only loosens enforcement)' {
            $global:IntuneTestState.Readers = @()
            (Invoke-ScriptUnderTest -Path $script:Disable).ExitCode | Should -Be 0
        }

        It 'exits 1 when a registry write fails (H4)' {
            $global:IntuneTestState.WriteFails = $true
            (Invoke-ScriptUnderTest -Path $script:Disable).ExitCode | Should -Be 1
        }

        It 'skips the service and creates no phantom key when SCPolicySvc does not exist (L2)' {
            [void]$global:IntuneTestState.Keys.Remove($script:SvcKey)
            $r = Invoke-ScriptUnderTest -Path $script:Disable
            $r.ExitCode | Should -Be 0
            Should -Invoke New-Item -Times 0 -Exactly -ParameterFilter { "$Path" -like '*SCPolicySvc*' }
            Should -Invoke Set-Service -Times 0 -Exactly
        }

        It '-WhatIf changes nothing at all and exits 0 (M3)' {
            $r = Invoke-ScriptUnderTest -Path $script:Disable -Arguments @{ WhatIf = $true }
            $r.ExitCode | Should -Be 0
            Should -Invoke New-ItemProperty -Times 0 -Exactly
            Should -Invoke New-Item -Times 0 -Exactly
            Should -Invoke Set-Service -Times 0 -Exactly
            Should -Invoke Add-Content -Times 0 -Exactly
        }
    }
}

Describe 'Smart card scripts: 64-bit relaunch argument forwarding (M3)' {
    It 'forwards <Switch> to the 64-bit child in <File>' -ForEach @(
        @{ File = 'Enable-SmartCardLogonEnforcement.ps1'; Switch = 'WhatIf' },
        @{ File = 'Enable-SmartCardLogonEnforcement.ps1'; Switch = 'Force' },
        @{ File = 'Enable-SmartCardLogonEnforcement.ps1'; Switch = 'KeepLogs' },
        @{ File = 'Disable-SmartCardLogonEnforcement.ps1'; Switch = 'WhatIf' },
        @{ File = 'Disable-SmartCardLogonEnforcement.ps1'; Switch = 'KeepLogs' }
    ) {
        . ([scriptblock]::Create((Import-ScriptFunction -Path (Get-RepoPath "Security\$File") -Name 'Get-RelaunchArgumentList')))
        $bound = @{}
        $bound[$Switch] = [switch]$true
        $a = Get-RelaunchArgumentList -ScriptPath 'C:\x\s.ps1' -BoundParameters $bound
        $a | Should -Contain "-$Switch"
        $a | Should -Contain '-File'
    }
}
