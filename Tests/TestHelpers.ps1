# Shared helpers for the Pester tests. Dot-source this file from a test's BeforeAll block.
# Pester 5 syntax. Works in Windows PowerShell 5.1 and PowerShell 7.

$script:RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path

function Get-RepoPath {
    param([Parameter(Mandatory)][string]$RelativePath)
    Join-Path $script:RepoRoot $RelativePath
}

# Parse a script and return the source text of the named top-level or nested functions,
# so a test can define them without running the script body.
function Import-ScriptFunction {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string[]]$Name
    )
    $tokens = $null; $errors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$tokens, [ref]$errors)
    if ($errors -and $errors.Count -gt 0) { throw "Parse errors in ${Path}: $($errors[0].Message)" }
    $found = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $Name -contains $n.Name }, $true)
    $missing = $Name | Where-Object { $_ -notin $found.Name }
    if ($missing) { throw "Function(s) not found in ${Path}: $($missing -join ', ')" }
    ($found | ForEach-Object { $_.Extent.Text }) -join "`n`n"
}

function Test-IsElevated {
    if ($env:OS -ne 'Windows_NT') { return $false }
    ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Run a script file in the current session and return its exit code and combined output.
# A script's `exit N` ends only that script, so the code lands in $LASTEXITCODE.
# ErrorActionPreference is reset to Continue because Pester sets it to Stop inside tests,
# and the scripts under test rely on Write-Error not being terminating.
function Invoke-ScriptUnderTest {
    param(
        [Parameter(Mandatory)][string]$Path,
        [hashtable]$Arguments = @{}
    )
    $ErrorActionPreference = 'Continue'
    $global:LASTEXITCODE = $null
    $output = & $Path @Arguments *>&1 | ForEach-Object { "$_" }
    # A script that ends without `exit` returns 0 to its caller, so report that as 0
    $code = if ($null -eq $global:LASTEXITCODE) { 0 } else { [int]$global:LASTEXITCODE }
    [PSCustomObject]@{ ExitCode = $code; Output = ($output -join "`n") }
}

# Safety net for tests that run scripts in an elevated shell. Every cmdlet that can change the machine
# gets an UNFILTERED default mock that throws, so a path the test forgot to mock fails loudly instead
# of touching the real registry, services or files. Tests then re-mock the few cmdlets they need.
# Call this from BeforeAll or BeforeEach in the test file itself.
$script:StateChangingCommands = @(
    'New-Item', 'New-ItemProperty', 'Set-ItemProperty', 'Remove-Item', 'Remove-ItemProperty',
    'Rename-Item', 'Copy-Item', 'Move-Item', 'Set-Service', 'Start-Service', 'Stop-Service',
    'Restart-Service', 'Start-Process', 'Stop-Process', 'Add-Content', 'Set-Content', 'Out-File',
    'Invoke-WebRequest', 'Invoke-RestMethod', 'Invoke-Expression', 'Import-Certificate'
)

# Build an HTTP failure the way Invoke-RestMethod surfaces one: an exception with a Response whose
# StatusCode has a value__ member (the shape the retry code reads).
function New-HttpException {
    param([int]$StatusCode, [string]$Message = "HTTP $StatusCode")
    $ex = [System.Exception]::new($Message)
    $ex | Add-Member -NotePropertyName Response -NotePropertyValue ([PSCustomObject]@{
        StatusCode = ([PSCustomObject]@{ value__ = $StatusCode })
        Headers    = @{}
    })
    $ex
}

# Path to the shared module manifest
function Get-ModuleManifestPath { Get-RepoPath 'Common\IntuneCommon.psd1' }

# Mock body for Invoke-RestMethod inside the IntuneCommon module. Routes live in $global:IntuneTestState.Routes
# as @{ Like = '*pattern*'; Body = <object> } or @{ Like = ...; Throw = <exception> }. The first route whose
# Like matches the URI wins. An unmatched URI throws, so a script cannot reach a real endpoint by accident.
# Every call is recorded in $global:IntuneTestState.Calls.
$script:GraphMockBody = {
    $global:IntuneTestState.Calls += [PSCustomObject]@{ Uri = "$Uri"; Method = "$Method"; Body = $Body }
    foreach ($route in $global:IntuneTestState.Routes) {
        if ("$Uri" -like $route.Like) {
            if ($route.Throw) { throw $route.Throw }
            return $route.Body
        }
    }
    throw "UNEXPECTED URI in test: $Uri"
}

# Fresh state for a Graph-backed script test. Token route is added first.
function New-GraphTestState {
    @{
        Calls  = @()
        Routes = [System.Collections.ArrayList]@(
            @{ Like = '*login.microsoftonline.com*/oauth2/v2.0/token'; Body = [PSCustomObject]@{ access_token = 'test-token' } }
        )
    }
}

function Add-GraphRoute {
    param([string]$Like, $Body, $Throw, [switch]$First)
    $r = @{ Like = $Like; Body = $Body; Throw = $Throw }
    if ($First) { $global:IntuneTestState.Routes.Insert(0, $r) } else { [void]$global:IntuneTestState.Routes.Add($r) }
}

# Wrap a list the way Graph does
function New-GraphPage { param($Items, [string]$NextLink) $o = [ordered]@{ value = @($Items) }; if ($NextLink) { $o['@odata.nextLink'] = $NextLink }; [PSCustomObject]$o }
