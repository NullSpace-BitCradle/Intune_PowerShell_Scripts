<#
.SYNOPSIS
    Common functions module for Intune PowerShell scripts.

.DESCRIPTION
    This module provides shared functions used across multiple Intune PowerShell scripts,
    including Graph API authentication, retry logic, and common utilities.

.NOTES
    Version: 1.1.0
    Author: NullSpace-BitCradle
#>

# Function to invoke Graph API with retry logic
# Handles transient failures (429, 503, etc.) with exponential backoff
function Invoke-GraphApiWithRetry {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$Uri,
        
        [Parameter(Mandatory=$true)]
        [hashtable]$Headers,
        
        [Parameter(Mandatory=$false)]
        [string]$Method = "Get",
        
        [Parameter(Mandatory=$false)]
        [int]$MaxRetries = 3,
        
        [Parameter(Mandatory=$false)]
        [int]$InitialDelaySeconds = 2
    )
    
    $retryCount = 0
    $delaySeconds = $InitialDelaySeconds
    
    while ($retryCount -le $MaxRetries) {
        try {
            $response = Invoke-RestMethod -Uri $Uri -Headers $Headers -Method $Method -ErrorAction Stop
            return $response
        }
        catch {
            $statusCode = $_.Exception.Response.StatusCode.value__
            
            # Check if this is a retryable error (429 Too Many Requests, 503 Service Unavailable, 502 Bad Gateway, 504 Gateway Timeout)
            if ($statusCode -in @(429, 502, 503, 504) -and $retryCount -lt $MaxRetries) {
                $retryCount++
                
                # Check for Retry-After header (429 Too Many Requests)
                if ($statusCode -eq 429 -and $_.Exception.Response.Headers['Retry-After']) {
                    $retryAfter = $_.Exception.Response.Headers['Retry-After']
                    if ($retryAfter -match '^\d+$') {
                        $delaySeconds = [int]$retryAfter
                        Write-Verbose "Graph API call rate limited. Using Retry-After header value: $delaySeconds seconds (attempt $retryCount of $MaxRetries)..."
                    }
                    else {
                        Write-Verbose "Graph API call failed with status $statusCode. Retrying in $delaySeconds seconds (attempt $retryCount of $MaxRetries)..."
                    }
                }
                else {
                    Write-Verbose "Graph API call failed with status $statusCode. Retrying in $delaySeconds seconds (attempt $retryCount of $MaxRetries)..."
                }
                
                Start-Sleep -Seconds $delaySeconds
                # Exponential backoff: double the delay for next retry (unless Retry-After was used)
                if ($statusCode -ne 429 -or -not $_.Exception.Response.Headers['Retry-After']) {
                    $delaySeconds = $delaySeconds * 2
                }
            }
            else {
                # Not a retryable error or max retries reached
                throw
            }
        }
    }
}

# Function to get all pages from a paginated Graph API response
function Get-GraphApiAllPages {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$Uri,
        
        [Parameter(Mandatory=$true)]
        [hashtable]$Headers,
        
        [Parameter(Mandatory=$false)]
        [int]$MaxRetries = 3,
        
        [Parameter(Mandatory=$false)]
        [int]$InitialDelaySeconds = 2
    )
    
    $allItems = @()
    $currentUri = $Uri
    $pageCount = 1
    
    do {
        Write-Progress -Activity "Retrieving paginated results" -Status "Fetching page $pageCount" -PercentComplete -1
        
        $response = Invoke-GraphApiWithRetry -Uri $currentUri -Headers $Headers -Method Get -MaxRetries $MaxRetries -InitialDelaySeconds $InitialDelaySeconds
        
        if ($null -ne $response -and $null -ne $response.value) {
            $allItems += $response.value
        }
        
        if ($response.'@odata.nextLink') {
            $currentUri = $response.'@odata.nextLink'
            $pageCount++
        }
        else {
            $currentUri = $null
        }
    } while ($null -ne $currentUri)
    
    Write-Progress -Activity "Retrieving paginated results" -Completed
    
    return $allItems
}

# Function to convert single object or array to array
function ConvertTo-Array {
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline=$true, Mandatory=$true)]
        $InputObject
    )
    
    process {
        if ($null -eq $InputObject) {
            return @()
        }
        if ($InputObject -is [Array]) {
            return $InputObject
        }
        return @($InputObject)
    }
}

# Function to get Graph API access token
# Accepts the client secret as a SecureString (preferred) or as a plain string (kept for compatibility).
function Get-GraphAccessToken {
    [CmdletBinding(DefaultParameterSetName='Plain')]
    param(
        [Parameter(Mandatory=$true)]
        [string]$AppId,

        [Parameter(Mandatory=$true)]
        [string]$TenantId,

        [Parameter(Mandatory=$true, ParameterSetName='Plain')]
        [string]$ClientSecret,

        [Parameter(Mandatory=$true, ParameterSetName='Secure')]
        [securestring]$ClientSecretSecure
    )

    try {
        $plainSecret = if ($PSCmdlet.ParameterSetName -eq 'Secure') {
            [System.Net.NetworkCredential]::new('', $ClientSecretSecure).Password
        }
        else {
            $ClientSecret
        }

        $body = @{
            grant_type    = "client_credentials"
            scope         = "https://graph.microsoft.com/.default"
            client_id     = $AppId
            client_secret = $plainSecret
        }

        $tokenResponse = Invoke-RestMethod -Uri "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token" -Method Post -Body $body -ErrorAction Stop
        return $tokenResponse.access_token
    }
    catch {
        Write-Error "Failed to obtain access token: $($_.Exception.Message)"
        throw
    }
}

# Function to resolve the app registration credentials the reporting scripts use.
# Order: parameter, then environment variable (INTUNE_APP_ID, INTUNE_TENANT_ID, INTUNE_CLIENT_SECRET).
# A SecureString secret wins over a plain-string secret. Placeholder values like <Your Tenant ID here> are rejected.
# Returns AppId, TenantId and the secret as a SecureString. Throws with a message that names what is missing.
function Get-IntuneCredential {
    # The secret reaches this function as a plain string when a caller passes -ClientSecret or sets
    # INTUNE_CLIENT_SECRET. Converting it to a SecureString here is the point: it is held as a SecureString from now on.
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingConvertToSecureStringWithPlainText', '', Justification='The input is already plain text (parameter or environment variable); this wraps it immediately.')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [string]$AppId,

        [Parameter(Mandatory=$false)]
        [string]$TenantId,

        [Parameter(Mandatory=$false)]
        [string]$ClientSecret,

        [Parameter(Mandatory=$false)]
        [securestring]$ClientSecretSecure
    )

    $resolvedAppId = if ($AppId) { $AppId } elseif ($env:INTUNE_APP_ID) { $env:INTUNE_APP_ID } else { $null }
    $resolvedTenantId = if ($TenantId) { $TenantId } elseif ($env:INTUNE_TENANT_ID) { $env:INTUNE_TENANT_ID } else { $null }

    $secret = $null
    if ($ClientSecretSecure) { $secret = $ClientSecretSecure }
    elseif ($ClientSecret) { $secret = ConvertTo-SecureString -String $ClientSecret -AsPlainText -Force }
    elseif ($env:INTUNE_CLIENT_SECRET) { $secret = ConvertTo-SecureString -String $env:INTUNE_CLIENT_SECRET -AsPlainText -Force }

    $plainForCheck = if ($secret) { [System.Net.NetworkCredential]::new('', $secret).Password } else { $null }

    if (-not $resolvedAppId -or -not $resolvedTenantId -or -not $secret -or
        $resolvedAppId -match '^<.*>$' -or $resolvedTenantId -match '^<.*>$' -or $plainForCheck -match '^<.*>$') {
        throw "Please provide valid credentials via parameters or environment variables (INTUNE_APP_ID, INTUNE_TENANT_ID, INTUNE_CLIENT_SECRET)."
    }

    [PSCustomObject]@{
        AppId        = $resolvedAppId
        TenantId     = $resolvedTenantId
        ClientSecret = $secret
    }
}

# Function to get the request headers for Graph calls: requests a token and builds the Authorization header.
function Get-IntuneGraphHeaders {
    [CmdletBinding()]
    param(
        # The object Get-IntuneCredential returns: AppId, TenantId and the secret as a SecureString
        [Parameter(Mandatory=$true)]
        $AppRegistration
    )

    $token = Get-GraphAccessToken -AppId $AppRegistration.AppId -TenantId $AppRegistration.TenantId -ClientSecretSecure $AppRegistration.ClientSecret
    if (-not $token) { throw "The token endpoint returned no access token." }

    return @{
        "Authorization" = "Bearer $token"
        "Content-Type"  = "application/json"
    }
}

# Function to validate GUID format
function Test-GuidFormat {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$Guid
    )
    
    return $Guid -match '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
}

# Function to validate email format
function Test-EmailFormat {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$Email
    )
    
    return $Email -match '^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
}

# Function to turn a value into an OData string literal: wrapped in single quotes, with each
# single quote doubled. Doubling is OData's escape. Deleting the quote (the old behaviour of
# Remove-ODataInjectionChars) changed the value, so a name with an apostrophe never matched.
# Build the filter with this, then URL-encode the whole filter with [uri]::EscapeDataString.
function ConvertTo-ODataStringLiteral {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$Value
    )

    return "'" + ($Value -replace "'", "''") + "'"
}

# Function to escape input for OData queries. Returns the value with single quotes doubled
# (no surrounding quotes). See ConvertTo-ODataStringLiteral.
function Remove-ODataInjectionChars {
    # Despite the verb, this only returns an escaped copy of a string. It changes no system state.
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification='Pure string function.')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$InputString
    )

    return ($InputString -replace "'", "''")
}

# Function to validate and escape OData filter input
function Test-ODataFilterInput {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$InputString,

        [Parameter(Mandatory=$false)]
        [switch]$AllowWildcards
    )

    $sanitized = $InputString

    # contains() and eq are literal matches in Graph, so a wildcard character is never a wildcard
    if (-not $AllowWildcards) {
        $sanitized = $sanitized -replace "[*%]", ""
    }

    if ([string]::IsNullOrWhiteSpace($sanitized)) {
        throw "Input string cannot be empty after sanitization."
    }

    return ($sanitized -replace "'", "''")
}

# Function to neutralise spreadsheet formulas in one CSV value. A cell that starts with = + - @ or a
# tab or carriage return is run as a formula by Excel; a leading apostrophe makes it plain text.
function Protect-CsvValue {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$Value
    )

    if ($Value -and $Value -match '^[=+\-@\t\r]') { return "'" + $Value }
    return $Value
}

# Function to apply Protect-CsvValue to every string property of the objects passed in.
# Use it just before Export-Csv: $rows | ConvertTo-SafeCsvRecord | Export-Csv ...
function ConvertTo-SafeCsvRecord {
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline=$true, Mandatory=$true)]
        $InputObject
    )

    process {
        $record = [ordered]@{}
        foreach ($property in $InputObject.PSObject.Properties) {
            $value = $property.Value
            if ($value -is [string]) { $value = Protect-CsvValue -Value $value }
            $record[$property.Name] = $value
        }
        [PSCustomObject]$record
    }
}

# Function to get Intune log path
function Get-IntuneLogPath {
    [CmdletBinding()]
    param()
    
    $logPath = Join-Path $env:ProgramData "Microsoft\IntuneManagementExtension\Logs"
    
    if (-not (Test-Path -Path $logPath)) {
        try {
            New-Item -Path $logPath -ItemType Directory -Force | Out-Null
        }
        catch {
            Write-Warning "Could not create log directory: $logPath"
        }
    }
    
    return $logPath
}

# Function to write standardized error message
function Write-StandardError {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$ScriptName,
        
        [Parameter(Mandatory=$true)]
        [string]$Operation,
        
        [Parameter(Mandatory=$false)]
        [string]$ObjectName = "",
        
        [Parameter(Mandatory=$false)]
        [Exception]$Exception
    )
    
    $errorMessage = "$ScriptName`: $Operation"
    if ($ObjectName) {
        $errorMessage += " on object '$ObjectName'"
    }
    
    if ($Exception) {
        $errorMessage += " - $($Exception.Message)"
    }
    
    Write-Error $errorMessage
    
    if ($Exception -and $PSBoundParameters.ContainsKey('Verbose')) {
        Write-Verbose "Stack Trace: $($Exception.ScriptStackTrace)"
        if ($Exception.InnerException) {
            Write-Verbose "Inner Exception: $($Exception.InnerException.Message)"
        }
    }
}

# Export module members
Export-ModuleMember -Function Invoke-GraphApiWithRetry, Get-GraphAccessToken, Get-IntuneCredential, Get-IntuneGraphHeaders, Test-GuidFormat, Test-EmailFormat, ConvertTo-ODataStringLiteral, Remove-ODataInjectionChars, Get-GraphApiAllPages, ConvertTo-Array, Test-ODataFilterInput, Protect-CsvValue, ConvertTo-SafeCsvRecord, Get-IntuneLogPath, Write-StandardError

