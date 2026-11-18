@{
    RootModule            = 'IntuneCommon.psm1'
    ModuleVersion         = '1.1.0'
    GUID                  = '6e874e85-9805-4993-9a39-f0a5ec6151d8'
    Author                = 'NullSpace-BitCradle'
    CompanyName           = 'NullSpace-BitCradle'
    Copyright             = '(c) NullSpace-BitCradle. MIT License.'
    Description           = 'Shared helpers for the Intune PowerShell scripts: Microsoft Graph token request, retry and paging, credential handling, OData escaping and CSV formula safety.'
    PowerShellVersion     = '5.1'
    FunctionsToExport     = @(
        'ConvertTo-Array',
        'ConvertTo-ODataStringLiteral',
        'ConvertTo-SafeCsvRecord',
        'Get-GraphAccessToken',
        'Get-GraphApiAllPages',
        'Get-IntuneCredential',
        'Get-IntuneGraphHeaders',
        'Get-IntuneLogPath',
        'Invoke-GraphApiWithRetry',
        'Protect-CsvValue',
        'Remove-ODataInjectionChars',
        'Test-EmailFormat',
        'Test-GuidFormat',
        'Test-ODataFilterInput',
        'Write-StandardError'
    )
    CmdletsToExport       = @()
    VariablesToExport     = @()
    AliasesToExport       = @()
    PrivateData           = @{
        PSData = @{
            Tags         = @('Intune', 'Graph', 'Endpoint')
            LicenseUri   = 'https://github.com/NullSpace-BitCradle/Intune_PowerShell_Scripts/blob/main/LICENSE'
            ProjectUri   = 'https://github.com/NullSpace-BitCradle/Intune_PowerShell_Scripts'
        }
    }
}
