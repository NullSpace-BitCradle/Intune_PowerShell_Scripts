<#
.SYNOPSIS
    Tests connectivity to Microsoft Intune and Microsoft 365 endpoints required for Intune management.

.DESCRIPTION
    This script tests connectivity to all mandatory Intune and Microsoft 365 Common endpoints
    required for Intune device management functionality. It queries Microsoft's Office 365 IP
    Address and URL web service to obtain the latest endpoint URLs for Service Area "MEM"
    (Microsoft Endpoint Manager) and "M365 Common", then tests connectivity to those endpoints
    from the client device. The script handles proxy configurations and provides detailed
    output about which endpoints are accessible.

    An endpoint counts as reachable when it answers over HTTP(S) with any status code. A 403 or 404
    from the service still proves the network path works. A timeout, DNS failure or refused
    connection counts as a failure. Endpoints that only publish a UDP port (NTP, for example)
    cannot be tested over HTTP and are reported as skipped. So are wildcard-only entries such as
    "*.microsoftonline.com": the bare domain has no address record, so there is no host to test, and
    the old script reported every one of them as a failure.

    Endpoint IDs that are not in the built-in category tables are listed as NOT TESTED, not skipped
    silently. Add -IncludeUnlistedEndpoints to test them too, using the service's own "required"
    flag to decide whether each is mandatory.

    If either endpoint list cannot be retrieved, the test fails. It never reports success after
    skipping the Intune endpoints.

.PARAMETER IncludeUnlistedEndpoints
    Also test endpoint sets whose ID is not in the built-in category tables (new Microsoft
    endpoints), treating the service's "required" flag as the mandatory flag.

.PARAMETER ExportPath
    Optional path to export test results to a JSON file.
    If specified, test results including network configuration and endpoint status will be saved.

.EXAMPLE
    .\Test-IntuneConnectivity.ps1

.EXAMPLE
    .\Test-IntuneConnectivity.ps1 -ExportPath "C:\Temp\ConnectivityTest.json"

.NOTES
    Prerequisites:
    - PowerShell 3.0 or later
    - PS script execution policy: Bypass (or appropriate policy to allow script execution)
    - Does not require elevation (runs with current user permissions)
    - Internet connectivity to reach Microsoft endpoints

    The script:
    - Queries Microsoft's endpoint web service for the latest endpoint URLs
    - Tests connectivity to mandatory Intune and M365 Common endpoints
    - Handles proxy configurations automatically
    - Displays network configuration information for troubleshooting
    - Exports results as JSON when -ExportPath is given

    Exit Codes:
    - 0: All mandatory endpoints are reachable
    - 1: A mandatory endpoint is unreachable, or an endpoint list could not be retrieved
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$ExportPath,

    [Parameter(Mandatory=$false)]
    [switch]$IncludeUnlistedEndpoints
)

# Function to invoke endpoint API with retry logic
# Handles transient failures (429, 503, etc.) with exponential backoff.
# Defined at script scope so every endpoint function can reach it.
function Invoke-EndpointApiWithRetry {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$Uri,

        [Parameter(Mandatory=$false)]
        [int]$MaxRetries = 3,

        [Parameter(Mandatory=$false)]
        [int]$InitialDelaySeconds = 2
    )

    $retryCount = 0
    $delaySeconds = $InitialDelaySeconds

    while ($retryCount -le $MaxRetries) {
        try {
            $response = Invoke-RestMethod -Uri $Uri -ErrorAction Stop
            return $response
        }
        catch {
            $statusCode = $null
            if ($_.Exception.Response) { $statusCode = [int]$_.Exception.Response.StatusCode }

            # Retryable: 429 Too Many Requests, 502 Bad Gateway, 503 Service Unavailable, 504 Gateway Timeout
            if ($statusCode -in @(429, 502, 503, 504) -and $retryCount -lt $MaxRetries) {
                $retryCount++
                Write-Verbose "Endpoint API call failed with status $statusCode. Retrying in $delaySeconds seconds (attempt $retryCount of $MaxRetries)..."
                Start-Sleep -Seconds $delaySeconds
                $delaySeconds = $delaySeconds * 2
            }
            else {
                throw
            }
        }
    }
}

Function ConvertFrom-NetshProxyOutput {
    <#
    .SYNOPSIS
        Turns the text of "netsh winhttp show proxy" into a proxy URL or "NoProxy".

    .DESCRIPTION
        Takes the value after "Proxy Server(s) :" as is. TrimStart() with a string trims a set of
        characters, not a prefix, and turned "server1.contoso.com:8080" into "1.contoso.com:8080".
        A per-protocol list such as "http=a:80;https=b:443" yields the https entry.

    .OUTPUTS
        String: a proxy URL with an http:// prefix, or "NoProxy"
    #>
    param(
        [Parameter(Mandatory=$false)]
        [string[]]$Lines
    )

    $text = @($Lines) -join "`n"
    if ($text -match 'Direct access') { return "NoProxy" }

    if ($text -match '(?m)Proxy Server\(s\)\s*:\s*(\S.*?)\s*$') {
        $value = $Matches[1]

        if ($value -match '=') {
            $entries = @{}
            foreach ($part in ($value -split ';')) {
                if ($part -match '^\s*(\w+)=(.+?)\s*$') { $entries[$Matches[1].ToLower()] = $Matches[2] }
            }
            $value = if ($entries.ContainsKey('https')) { $entries['https'] } elseif ($entries.ContainsKey('http')) { $entries['http'] } else { $null }
            if (-not $value) { return "NoProxy" }
        }
        elseif ($value -match ';') {
            $value = ($value -split ';')[0].Trim()
        }

        if ($value -notmatch '^https?://') { $value = "http://" + $value }
        return $value
    }

    return "NoProxy"
}

Function Get-ProxySettings {
    <#
    .SYNOPSIS
        Retrieves the current Windows HTTP proxy configuration.

    .DESCRIPTION
        This function checks the system's winHTTP proxy settings using netsh command.
        It determines if the system is using a proxy server or has direct internet access.
        Returns the proxy server address or "NoProxy" if direct access is configured.

    .OUTPUTS
        String: Proxy server address (with http:// prefix) or "NoProxy"
    #>

    Write-Host "Checking winHTTP proxy settings..." -ForegroundColor Yellow

    $ProxyServer = ConvertFrom-NetshProxyOutput -Lines (netsh winhttp show proxy)

    if ($ProxyServer -eq "NoProxy") {
        Write-Host "Access Type : DIRECT"
    }
    else {
        Write-Host "Access Type : PROXY"
        Write-Host "Proxy Server List :" $ProxyServer
    }

    return $ProxyServer
}

Function Get-EndpointList {
    <#
    .SYNOPSIS
        Retrieves the endpoint list for one service area from Microsoft's endpoint web service.

    .DESCRIPTION
        Queries https://endpoints.office.com for one service area ("Common" or "MEM"), attaches a
        category and a mandatory flag from the built-in table, strips wildcard prefixes and removes
        duplicate URLs. Wildcard-only entries are kept apart in wildcardUrls because there is no host
        to test. IDs that are not in the table are kept: their category is "Other (id N)", known is
        $false, and the service's own "required" flag is the mandatory flag.
        A failure to retrieve the list throws. It is never turned into an empty list.

    .OUTPUTS
        Array: objects with id, category, urls, wildcardUrls, known, tcpPorts, udpPorts and mandatory
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [ValidateSet('Common', 'MEM')]
        [string]$ServiceArea,

        [Parameter(Mandatory=$true)]
        [object[]]$CategoryTable
    )

    $uri = "https://endpoints.office.com/endpoints/WorldWide?ServiceAreas=$ServiceArea&clientrequestid=" + ([GUID]::NewGuid()).Guid
    $endpointList = @(Invoke-EndpointApiWithRetry -Uri $uri | Where-Object { $_.ServiceArea -eq $ServiceArea -and $_.urls })

    $result = @()
    foreach ($endpoint in $endpointList) {
        $known = $CategoryTable | Where-Object { $_.id -eq $endpoint.id } | Select-Object -First 1

        # A URL with a * in it is a wildcard. "*.example.com" is also published as plain "example.com" when
        # that host exists, so keep only the concrete names to test and list the wildcards separately.
        $urls = @($endpoint.urls | Where-Object { $_ -notlike '*`**' } | Sort-Object -Unique)
        $wildcardUrls = @($endpoint.urls | Where-Object { $_ -like '*`**' } | Sort-Object -Unique)

        $result += [PSCustomObject]@{
            id        = $endpoint.id
            category  = if ($known) { $known.category } else { "Other (id $($endpoint.id))" }
            urls      = $urls
            wildcardUrls = $wildcardUrls
            known     = [bool]$known
            tcpPorts  = "$($endpoint.tcpPorts)"
            udpPorts  = "$($endpoint.udpPorts)"
            mandatory = if ($known) { [bool]$known.mandatory } else { [bool]$endpoint.required }
        }
    }
    return $result
}

Function Get-M365CommonEndpointList {
    <#
    .SYNOPSIS
        Retrieves the list of Microsoft 365 Common endpoints required for Intune connectivity.

    .OUTPUTS
        Array: Processed endpoint list with category and URL information
    #>

    # mandatory = $true indicates these endpoints are required for Intune to function
    [PsObject[]]$categories = @()
    $categories += [PsObject]@{id = 56; category = 'M365 Common'; mandatory = $true }
    $categories += [PsObject]@{id = 59; category = 'M365 Common'; mandatory = $true }
    $categories += [PsObject]@{id = 78; category = 'M365 Common'; mandatory = $true }
    $categories += [PsObject]@{id = 83; category = 'M365 Common'; mandatory = $true }
    $categories += [PsObject]@{id = 84; category = 'M365 Common'; mandatory = $true }
    $categories += [PsObject]@{id = 125; category = 'M365 Common'; mandatory = $true }
    $categories += [PsObject]@{id = 156; category = 'M365 Common'; mandatory = $true }

    return Get-EndpointList -ServiceArea 'Common' -CategoryTable $categories
}

Function Get-IntuneEndpointList {
    <#
    .SYNOPSIS
        Retrieves the list of Microsoft Endpoint Manager (Intune) endpoints required for connectivity.

    .OUTPUTS
        Array: Processed endpoint list with category and URL information
    #>

    # mandatory = $true: Endpoints required for basic Intune functionality
    # mandatory = $false: Optional endpoints (e.g., platform-specific or feature-specific)
    [PsObject[]]$categories = @()
    $categories += [PsObject]@{id = 163; category = 'Global'; mandatory = $true }
    $categories += [PsObject]@{id = 164; category = 'Delivery Optimization'; mandatory = $true }
    $categories += [PsObject]@{id = 165; category = 'NTP Sync'; mandatory = $true }
    $categories += [PsObject]@{id = 169; category = 'Windows Notifications & Store'; mandatory = $true }
    $categories += [PsObject]@{id = 170; category = 'Scripts & Win32 Apps'; mandatory = $true }
    $categories += [PsObject]@{id = 171; category = 'Push Notifications'; mandatory = $true }
    $categories += [PsObject]@{id = 172; category = 'Delivery Optimization'; mandatory = $true }
    $categories += [PsObject]@{id = 173; category = 'Autopilot Self-deploy'; mandatory = $true }
    $categories += [PsObject]@{id = 178; category = 'Apple Device Management'; mandatory = $false }
    $categories += [PsObject]@{id = 179; category = 'Android (AOSP) Device Management'; mandatory = $false }
    $categories += [PsObject]@{id = 181; category = 'Remote Help'; mandatory = $false }
    $categories += [PsObject]@{id = 182; category = 'Collect Diagnostics'; mandatory = $true }
    $categories += [PsObject]@{id = 186; category = 'Microsoft Azure attestation - Windows 11 only'; mandatory = $true }
    $categories += [PsObject]@{id = 187; category = 'Android Remote Help'; mandatory = $false }
    $categories += [PsObject]@{id = 188; category = 'Remote Help GCC Dependency'; mandatory = $false }
    $categories += [PsObject]@{id = 189; category = 'Feature Flighting'; mandatory = $false }

    return Get-EndpointList -ServiceArea 'MEM' -CategoryTable $categories
}

Function Get-EndpointRegionNote {
    <#
    .SYNOPSIS
        Returns the tenant-region note for Intune's regional scale-unit hosts, or an empty string.
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$Url
    )

    if ($Url -match '^approdimedata') { return 'Asia & Pacific' }
    if ($Url -match '^euprodimedata') { return 'Europe' }
    if ($Url -match '^naprodimedata') { return 'North America' }
    if ($Url -match '^intunemaape(\d+)\.') {
        $n = [int]$Matches[1]
        if ($n -ge 1 -and $n -le 6) { return 'North America' }
        if ($n -ge 7 -and $n -le 12) { return 'Europe' }
        if ($n -in @(13, 17, 18, 19)) { return 'Asia & Pacific' }
    }
    return ''
}

Function Test-EndpointReachable {
    <#
    .SYNOPSIS
        Tests one endpoint over HTTP(S). Any HTTP answer, including 3xx/4xx/5xx, means reachable.

    .OUTPUTS
        Object: Reachable (bool), StatusCode (int or $null), Error (string or $null)
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$Url,

        [Parameter(Mandatory=$true)]
        [ValidateSet('https', 'http')]
        [string]$Scheme,

        [Parameter(Mandatory=$false)]
        [string]$ProxyServer = "NoProxy"
    )

    $uri = "${Scheme}://$Url"
    $parameters = @{ Uri = $uri; UseBasicParsing = $true; TimeoutSec = 10; ErrorAction = 'Stop' }
    if ($ProxyServer -ne "NoProxy") { $parameters['Proxy'] = $ProxyServer }

    try {
        $response = Invoke-WebRequest @parameters
        return [PSCustomObject]@{ Reachable = $true; StatusCode = [int]$response.StatusCode; Error = $null }
    }
    catch {
        # An HTTP error status still means the host answered
        if ($_.Exception.Response) {
            return [PSCustomObject]@{ Reachable = $true; StatusCode = [int]$_.Exception.Response.StatusCode; Error = $null }
        }
        return [PSCustomObject]@{ Reachable = $false; StatusCode = $null; Error = $_.Exception.Message }
    }
}

Function Test-EndpointSet {
    <#
    .SYNOPSIS
        Tests every URL of every mandatory endpoint in a list and records the results.

    .OUTPUTS
        Boolean: $true if every tested mandatory URL was reachable
    #>
    param(
        [Parameter(Mandatory=$true)]
        [object[]]$EndpointList,

        [Parameter(Mandatory=$false)]
        [string]$ProxyServer = "NoProxy"
    )

    $allPassed = $true

    foreach ($endpoint in $EndpointList) {
        # Only test mandatory endpoints (skip optional ones)
        if ($endpoint.mandatory -ne $true) { continue }

        Write-Host "Checking Category: ..." $endpoint.category -ForegroundColor Yellow

        foreach ($wildcard in @($endpoint.wildcardUrls)) {
            if (-not $wildcard) { continue }
            if (-not $script:skippedEndpointList.ContainsKey($endpoint.category)) { $script:skippedEndpointList[$endpoint.category] = @() }
            $script:skippedEndpointList[$endpoint.category] += $wildcard
        }

        # Pick the schemes from the published TCP ports. UDP only (NTP) or no TCP 80/443 cannot be tested over HTTP.
        # No ports published at all: try https, then http.
        $ports = @("$($endpoint.tcpPorts)" -split ',' | ForEach-Object { $_.Trim() })
        # Hosts that publish "80,443" often answer on only one of them (CRL and OCSP hosts answer on 80 only),
        # so try https first and then http. A host is reachable if either answers.
        $schemes = @()
        if ($ports -contains '443') { $schemes += 'https' }
        if ($ports -contains '80') { $schemes += 'http' }
        if ($schemes.Count -eq 0 -and -not $endpoint.tcpPorts -and -not $endpoint.udpPorts) { $schemes = @('https', 'http') }

        foreach ($url in $endpoint.urls) {
            if ($schemes.Count -eq 0) {
                if (-not $script:skippedEndpointList.ContainsKey($endpoint.category)) { $script:skippedEndpointList[$endpoint.category] = @() }
                $script:skippedEndpointList[$endpoint.category] += $url
                Write-Host "Connection to " $url ".............. Skipped (no TCP 80/443 published, cannot be tested over HTTP)." -ForegroundColor Yellow
                continue
            }

            $test = $null
            foreach ($scheme in $schemes) {
                $test = Test-EndpointReachable -Url $url -Scheme $scheme -ProxyServer $ProxyServer
                if ($test.Reachable) { break }
            }
            $region = Get-EndpointRegionNote -Url $url
            $regionText = if ($region) { " (needed for $region tenants only)" } else { "" }

            if ($test.Reachable) {
                if (-not $script:passedEndpointList.ContainsKey($endpoint.category)) { $script:passedEndpointList[$endpoint.category] = @() }
                $script:passedEndpointList[$endpoint.category] += $url
                Write-Host "Connection to " $url ".............. Succeeded$regionText." -ForegroundColor Green
            }
            else {
                $allPassed = $false
                if (-not $script:failedEndpointList.ContainsKey($endpoint.category)) { $script:failedEndpointList[$endpoint.category] = @() }
                $script:failedEndpointList[$endpoint.category] += $url
                Write-Host "Connection to " $url ".............. Failed$regionText." -ForegroundColor Red
            }
        }
    }

    return $allPassed
}

Function Test-DeviceIntuneConnectivity {
    <#
    .SYNOPSIS
        Tests connectivity to all required Intune and Microsoft 365 endpoints.

    .DESCRIPTION
        Retrieves the M365 Common and Intune (MEM) endpoint lists and tests the mandatory ones.
        If either list cannot be retrieved or comes back empty, the test fails. The retrieval
        errors are shown, not hidden.

    .OUTPUTS
        Boolean: $true if all mandatory endpoints are accessible, $false otherwise
    #>
    param(
        [Parameter(Mandatory=$false)]
        [switch]$IncludeUnlisted
    )

    $script:failedEndpointList = @{}   # failed endpoints by category (script-level for export)
    $script:passedEndpointList = @{}   # passed endpoints by category (script-level for export)
    $script:skippedEndpointList = @{}  # endpoints that could not be tested over HTTP, and wildcard entries
    $script:notTestedEndpointIds = @() # endpoint IDs outside the built-in tables, when -IncludeUnlistedEndpoints is off

    $ProxyServer = Get-ProxySettings

    $endpointListM365Common = @()
    $endpointListIntune = @()
    $retrievalFailed = $false

    try { $endpointListM365Common = @(Get-M365CommonEndpointList) }
    catch {
        Write-Error "Get-M365CommonEndpointList: Failed to retrieve M365 Common endpoints - $($_.Exception.Message)"
        $retrievalFailed = $true
    }
    try { $endpointListIntune = @(Get-IntuneEndpointList) }
    catch {
        Write-Error "Get-IntuneEndpointList: Failed to retrieve Intune endpoints - $($_.Exception.Message)"
        $retrievalFailed = $true
    }

    if ($endpointListM365Common.Count -eq 0 -and -not $retrievalFailed) {
        Write-Error "The M365 Common endpoint list is empty."
        $retrievalFailed = $true
    }
    if ($endpointListIntune.Count -eq 0 -and -not $retrievalFailed) {
        Write-Error "The Intune (MEM) endpoint list is empty."
        $retrievalFailed = $true
    }
    if ($retrievalFailed) {
        Write-Host "Connectivity test could not run: an endpoint list was not retrieved. Intune endpoints must not be skipped." -ForegroundColor Red
        return $false
    }

    $unknown = @(($endpointListM365Common + $endpointListIntune) | Where-Object { -not $_.known })
    if ($unknown.Count -gt 0) {
        $ids = ($unknown | ForEach-Object { $_.id }) -join ', '
        if ($IncludeUnlisted) {
            Write-Host "Note: $($unknown.Count) endpoint set(s) are not in the built-in category tables and are tested using the service's own 'required' flag: $ids" -ForegroundColor Yellow
        }
        else {
            Write-Host "Note: $($unknown.Count) endpoint set(s) are not in the built-in category tables and were NOT TESTED: $ids. Use -IncludeUnlistedEndpoints to test them." -ForegroundColor Yellow
            $script:notTestedEndpointIds = @($unknown | ForEach-Object { $_.id })
            $endpointListM365Common = @($endpointListM365Common | Where-Object { $_.known })
            $endpointListIntune = @($endpointListIntune | Where-Object { $_.known })
        }
    }

    Write-Host "Starting Connectivity Check..." -ForegroundColor Yellow

    $m365Passed = Test-EndpointSet -EndpointList $endpointListM365Common -ProxyServer $ProxyServer
    $intunePassed = Test-EndpointSet -EndpointList $endpointListIntune -ProxyServer $ProxyServer
    $TestFailed = -not ($m365Passed -and $intunePassed)

    if ($TestFailed) {
        Write-Host "Test failed. Please check the following URLs:" -ForegroundColor Red
        foreach ($failedEndpoint in $script:failedEndpointList.Keys) {
            Write-Host $failedEndpoint -ForegroundColor Red
            foreach ($failedUrl in $script:failedEndpointList[$failedEndpoint]) {
                Write-Host $failedUrl -ForegroundColor Red
            }
        }
        Write-Host "Test-DeviceIntuneConnectivity completed with failures." -ForegroundColor Yellow -BackgroundColor Black
        return $false
    }

    Write-Host "Test-DeviceIntuneConnectivity completed successfully." -ForegroundColor Green -BackgroundColor Black
    return $true
}

### Main Execution Section ###

# Execute the connectivity test function
# This tests all mandatory Intune and M365 Common endpoints
$connectivityResult = Test-DeviceIntuneConnectivity -IncludeUnlisted:$IncludeUnlistedEndpoints

# Display network configuration information
# This helps troubleshoot connectivity issues by showing the device's network setup
$NetworkConfiguration = @()

# Get network configuration for all network interfaces
Get-NetIPConfiguration | ForEach-Object {
    # Handle null values gracefully to prevent errors
    $NetworkConfiguration += New-Object PSObject -Property @{
        InterfaceAlias = $_.InterfaceAlias  # Network adapter name
        ProfileName = if($null -ne $_.NetProfile.Name){$_.NetProfile.Name}else{""}  # Network profile (Domain/Private/Public)
        IPv4Address = if($null -ne $_.IPv4Address){$_.IPv4Address}else{""}  # IPv4 address
        IPv6Address = if($null -ne $_.IPv6Address){$_.IPv6Address}else{""}  # IPv6 address
        IPv4DefaultGateway = if($null -ne $_.IPv4DefaultGateway){$_.IPv4DefaultGateway.NextHop}else{""}  # IPv4 gateway
        IPv6DefaultGateway = if($null -ne $_.IPv6DefaultGateway){$_.IPv6DefaultGateway.NextHop}else{""}  # IPv6 gateway
        DNSServer = if($null -ne $_.DNSServer){$_.DNSServer.ServerAddresses}else{""}  # DNS server addresses
    }
}

# Display the network configuration in a formatted table
$NetworkConfiguration | Format-Table -AutoSize

# Export results to file if path is specified
if ($ExportPath) {
    try {
        # Create directory if it doesn't exist
        $exportDirectory = Split-Path -Path $ExportPath -Parent
        if ($exportDirectory -and -not (Test-Path -Path $exportDirectory)) {
            New-Item -Path $exportDirectory -ItemType Directory -Force | Out-Null
        }

        # Create export object with test results
        $exportData = @{
            TestDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            TestResult = if ($connectivityResult) { "Passed" } else { "Failed" }
            NetworkConfiguration = $NetworkConfiguration
        }

        # Add endpoint test results if available
        if ($script:passedEndpointList -and $script:passedEndpointList.Count -gt 0) {
            $exportData["PassedEndpoints"] = $script:passedEndpointList
        }
        if ($script:failedEndpointList -and $script:failedEndpointList.Count -gt 0) {
            $exportData["FailedEndpoints"] = $script:failedEndpointList
        }
        if ($script:notTestedEndpointIds -and $script:notTestedEndpointIds.Count -gt 0) {
            $exportData["NotTestedEndpointIds"] = $script:notTestedEndpointIds
        }
        if ($script:skippedEndpointList -and $script:skippedEndpointList.Count -gt 0) {
            $exportData["SkippedEndpoints"] = $script:skippedEndpointList
        }

        # Export to JSON format
        $exportData | ConvertTo-Json -Depth 10 | Out-File -FilePath $ExportPath -Encoding UTF8
        Write-Host "`nTest results exported to: $ExportPath" -ForegroundColor Green

        # Verify the export file was created successfully
        if (-not (Test-Path -Path $ExportPath)) {
            Write-Warning "Export file was not created successfully at: $ExportPath"
        }
    }
    catch {
        Write-Warning "Failed to export test results: $($_.Exception.Message)"
    }
}

# Exit with appropriate exit code based on connectivity test results
# Exit code 0 = All mandatory endpoints accessible
# Exit code 1 = One or more mandatory endpoints failed, or an endpoint list could not be retrieved
if ($connectivityResult) {
    exit 0
} else {
    exit 1
}
