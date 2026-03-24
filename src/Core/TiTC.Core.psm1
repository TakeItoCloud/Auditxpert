#Requires -Version 5.1
<#
.SYNOPSIS
    TakeItToCloud.Assess — Core infrastructure module.

.DESCRIPTION
    Provides authentication (Microsoft Graph, Exchange Online, Azure AD),
    structured logging, configuration management, and shared utilities
    used by all collectors, analyzers, and output generators.

.NOTES
    Module:     TiTC.Core
    Author:     TakeItToCloud
    Version:    1.0.0
#>

# ============================================================================
# MODULE DEPENDENCIES
# ============================================================================

$ModelsPath = Join-Path $PSScriptRoot 'Models\TiTC.Models.psm1'
if (Test-Path $ModelsPath) {
    Import-Module $ModelsPath -ErrorAction Stop
}

# ============================================================================
# MODULE STATE
# ============================================================================

$script:TiTCState = @{
    IsConnected       = $false
    TenantId          = $null
    TenantName        = $null
    TenantDomain      = $null
    AccessToken       = $null
    TokenExpiry       = $null
    AuthMethod        = $null          # 'Interactive', 'ClientSecret', 'Certificate', 'ManagedIdentity'
    ConnectedServices = @()            # 'Graph', 'ExchangeOnline', 'AzureAD'
    GraphBaseUrl      = 'https://graph.microsoft.com/v1.0'
    GraphBetaUrl      = 'https://graph.microsoft.com/beta'
    LogLevel          = 'Info'         # 'Debug', 'Info', 'Warning', 'Error'
    LogPath           = $null
    LogEntries        = [System.Collections.ArrayList]::new()
    ApiCallCount      = 0
    ApiCallLog        = [System.Collections.ArrayList]::new()   # Per-call timing data
    ErrorLog          = [System.Collections.ArrayList]::new()   # Warnings + errors for summary
    RunStartTime      = $null                                    # Set by Initialize-TiTCLogging
    Config            = @{}
}

# Persistent global log — written on every Write-TiTCLog call
$script:GlobalLogPath = Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) 'logs\auditxpert.log'

# ============================================================================
# LOGGING
# ============================================================================

function Write-TiTCLog {
    <#
    .SYNOPSIS
        Writes a structured log entry with timestamp, level, and optional context.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)]
        [string]$Message,

        [ValidateSet('Debug', 'Info', 'Warning', 'Error', 'Success')]
        [string]$Level = 'Info',

        [string]$Component,
        [hashtable]$Data
    )

    $levelOrder = @{ Debug = 0; Info = 1; Warning = 2; Error = 3; Success = 1 }
    $configLevel = $levelOrder[$script:TiTCState.LogLevel]
    $msgLevel = $levelOrder[$Level]

    if ($msgLevel -lt $configLevel) { return }

    $entry = [ordered]@{
        Timestamp = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff')
        Level     = $Level
        Component = if ($Component) { $Component } else { 'Core' }
        Message   = $Message
    }

    if ($Data) { $entry.Data = $Data }

    $null = $script:TiTCState.LogEntries.Add($entry)

    # Console output with color
    $prefix = '[{0}] [{1,-7}]' -f $entry.Timestamp, $Level.ToUpper()
    $componentTag = if ($Component) { " [$Component]" } else { '' }

    $color = switch ($Level) {
        'Debug'   { 'DarkGray' }
        'Info'    { 'Cyan' }
        'Warning' { 'Yellow' }
        'Error'   { 'Red' }
        'Success' { 'Green' }
    }

    Write-Host "$prefix$componentTag $Message" -ForegroundColor $color

    # Per-run file log
    if ($script:TiTCState.LogPath) {
        $logLine = "$prefix$componentTag $Message"
        Add-Content -Path $script:TiTCState.LogPath -Value $logLine -ErrorAction SilentlyContinue
    }

    # Persistent global log
    try {
        $globalDir = Split-Path $script:GlobalLogPath -Parent
        if (-not (Test-Path $globalDir)) {
            New-Item -ItemType Directory -Path $globalDir -Force | Out-Null
        }
        Add-Content -Path $script:GlobalLogPath -Value "$prefix$componentTag $Message" -ErrorAction SilentlyContinue
    }
    catch { }

    # Capture warnings and errors for end-of-run summary
    if ($Level -in @('Warning', 'Error')) {
        $null = $script:TiTCState.ErrorLog.Add($entry)
    }
}

function Initialize-TiTCLogging {
    <#
    .SYNOPSIS
        Configures logging output path and verbosity level.
    #>
    [CmdletBinding()]
    param(
        [string]$LogPath,

        [ValidateSet('Debug', 'Info', 'Warning', 'Error')]
        [string]$LogLevel = 'Info'
    )

    $script:TiTCState.LogLevel = $LogLevel

    $script:TiTCState.RunStartTime = [System.Diagnostics.Stopwatch]::StartNew()

    if ($LogPath) {
        $logDir = Split-Path $LogPath -Parent
        if (-not (Test-Path $logDir)) {
            New-Item -ItemType Directory -Path $logDir -Force | Out-Null
        }
        $script:TiTCState.LogPath = $LogPath
        Write-TiTCLog "Logging initialized: $LogPath (Level: $LogLevel)" -Level Info -Component 'Logging'
    }
}

# ============================================================================
# AUTHENTICATION
# ============================================================================

function Connect-TiTCGraph {
    <#
    .SYNOPSIS
        Authenticates to Microsoft Graph API using various methods.

    .DESCRIPTION
        Supports interactive login, client secret, certificate, and managed identity
        authentication. Validates required permissions and stores token for session reuse.

    .PARAMETER TenantId
        Azure AD tenant ID (GUID).

    .PARAMETER ClientId
        Application (client) ID for app-based auth.

    .PARAMETER ClientSecret
        Client secret for app-based auth. Use SecureString in production.

    .PARAMETER CertificateThumbprint
        Certificate thumbprint for certificate-based auth.

    .PARAMETER Interactive
        Use interactive browser-based authentication.

    .PARAMETER Scopes
        Additional Graph API scopes to request. Default scopes cover read operations
        needed by all collectors.
    #>
    [CmdletBinding(DefaultParameterSetName = 'Interactive')]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$TenantId,

        [Parameter(Mandatory, ParameterSetName = 'ClientSecret')]
        [Parameter(Mandatory, ParameterSetName = 'Certificate')]
        [ValidateNotNullOrEmpty()]
        [string]$ClientId,

        [Parameter(Mandatory, ParameterSetName = 'ClientSecret')]
        [ValidateNotNullOrEmpty()]
        [string]$ClientSecret,

        [Parameter(Mandatory, ParameterSetName = 'Certificate')]
        [ValidateNotNullOrEmpty()]
        [string]$CertificateThumbprint,

        [Parameter(ParameterSetName = 'Interactive')]
        [switch]$Interactive,

        [string[]]$Scopes = @(
            'https://graph.microsoft.com/.default'
        ),

        [string[]]$RequiredModules = @(
            'Microsoft.Graph.Authentication'
        )
    )

    begin {
        Write-TiTCLog "Connecting to Microsoft Graph..." -Level Info -Component 'Auth'
        Write-TiTCLog "Tenant: $TenantId | Method: $($PSCmdlet.ParameterSetName)" -Level Debug -Component 'Auth'
    }

    process {
        try {
            if ([string]::IsNullOrWhiteSpace($TenantId)) {
                throw "TenantId is required."
            }

            switch ($PSCmdlet.ParameterSetName) {
                'ClientSecret' {
                    if ([string]::IsNullOrWhiteSpace($ClientId)) {
                        throw "Client secret authentication requires ClientId."
                    }
                    if ([string]::IsNullOrWhiteSpace($ClientSecret)) {
                        throw "Client secret authentication requires ClientSecret."
                    }
                }
                'Certificate' {
                    if ([string]::IsNullOrWhiteSpace($ClientId)) {
                        throw "Certificate authentication requires ClientId."
                    }
                    if ([string]::IsNullOrWhiteSpace($CertificateThumbprint)) {
                        throw "Certificate authentication requires CertificateThumbprint."
                    }
                }
            }

            # ── Validate prerequisites ──────────────────────────────────
            foreach ($mod in $RequiredModules) {
                if (-not (Get-Module -ListAvailable -Name $mod)) {
                    Write-TiTCLog "Required module '$mod' not installed. Run: Install-Module $mod -Scope CurrentUser" -Level Error -Component 'Auth'
                    throw "Missing required module: $mod"
                }
            }

            # ── Build connection parameters ─────────────────────────────
            $connectParams = @{
                TenantId = $TenantId
                NoWelcome = $true
            }

            switch ($PSCmdlet.ParameterSetName) {
                'Interactive' {
                    $connectParams.Scopes = @(
                        'Directory.Read.All',
                        'Policy.Read.All',
                        'SecurityEvents.Read.All',
                        'DeviceManagementConfiguration.Read.All',
                        'DeviceManagementManagedDevices.Read.All',
                        'MailboxSettings.Read',
                        'Mail.Read',
                        'Organization.Read.All',
                        'Reports.Read.All',
                        'RoleManagement.Read.Directory',
                        'User.Read.All',
                        'Group.Read.All',
                        'Application.Read.All',
                        'AuditLog.Read.All',
                        'IdentityRiskEvent.Read.All',
                        'IdentityRiskyUser.Read.All',
                        'SecurityAlert.Read.All',
                        'SecurityIncident.Read.All'
                    )
                    $script:TiTCState.AuthMethod = 'Interactive'
                    Write-TiTCLog "Using interactive browser authentication" -Level Info -Component 'Auth'
                }

                'ClientSecret' {
                    $secureSecret = ConvertTo-SecureString $ClientSecret -AsPlainText -Force
                    $credential = [PSCredential]::new($ClientId, $secureSecret)
                    $connectParams.ClientSecretCredential = $credential
                    $script:TiTCState.AuthMethod = 'ClientSecret'
                    Write-TiTCLog "Using client secret authentication (App: $ClientId)" -Level Info -Component 'Auth'
                }

                'Certificate' {
                    $connectParams.ClientId = $ClientId
                    $connectParams.CertificateThumbprint = $CertificateThumbprint
                    $script:TiTCState.AuthMethod = 'Certificate'
                    Write-TiTCLog "Using certificate authentication (Thumbprint: $($CertificateThumbprint.Substring(0,8))...)" -Level Info -Component 'Auth'
                }
            }

            # ── Connect ─────────────────────────────────────────────────
            Connect-MgGraph @connectParams -ErrorAction Stop

            # ── Validate connection and retrieve tenant info ────────────
            $context = Get-MgContext
            if (-not $context) {
                throw "Graph connection established but no context returned."
            }

            $script:TiTCState.TenantId = $context.TenantId
            $script:TiTCState.IsConnected = $true
            $script:TiTCState.ConnectedServices += 'Graph'

            # Retrieve tenant details
            try {
                $org = Invoke-TiTCGraphRequest -Endpoint '/organization' -Select 'id,displayName,verifiedDomains'
                if ($org.value) {
                    $script:TiTCState.TenantName = $org.value[0].displayName
                    $primaryDomain = ($org.value[0].verifiedDomains | Where-Object { $_.isDefault }).name
                    $script:TiTCState.TenantDomain = $primaryDomain
                }
            }
            catch {
                Write-TiTCLog "Could not retrieve tenant details: $_" -Level Warning -Component 'Auth'
            }

            Write-TiTCLog "Connected to Graph API successfully" -Level Success -Component 'Auth' -Data @{
                TenantId   = $script:TiTCState.TenantId
                TenantName = $script:TiTCState.TenantName
                Domain     = $script:TiTCState.TenantDomain
                AuthMethod = $script:TiTCState.AuthMethod
                Scopes     = ($context.Scopes -join ', ')
            }

            return @{
                Connected  = $true
                TenantId   = $script:TiTCState.TenantId
                TenantName = $script:TiTCState.TenantName
                Domain     = $script:TiTCState.TenantDomain
                AuthMethod = $script:TiTCState.AuthMethod
            }
        }
        catch {
            $script:TiTCState.IsConnected = $false
            Write-TiTCLog "Failed to connect to Graph API: $($_.Exception.Message)" -Level Error -Component 'Auth'
            throw
        }
    }
}

function Disconnect-TiTCGraph {
    <#
    .SYNOPSIS
        Disconnects from Microsoft Graph and clears session state.
    #>
    [CmdletBinding()]
    param()

    try {
        if ($script:TiTCState.ConnectedServices -contains 'Graph') {
            Disconnect-MgGraph -ErrorAction SilentlyContinue
        }

        $script:TiTCState.IsConnected = $false
        $script:TiTCState.TenantId = $null
        $script:TiTCState.TenantName = $null
        $script:TiTCState.AccessToken = $null
        $script:TiTCState.ConnectedServices = @()

        Write-TiTCLog "Disconnected from all services" -Level Info -Component 'Auth'
    }
    catch {
        Write-TiTCLog "Error during disconnect: $($_.Exception.Message)" -Level Warning -Component 'Auth'
    }
}

function Test-TiTCConnection {
    <#
    .SYNOPSIS
        Validates current Graph connection is active and token is valid.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    if (-not $script:TiTCState.IsConnected) {
        Write-TiTCLog "Not connected to Graph API" -Level Warning -Component 'Auth'
        return $false
    }

    try {
        $context = Get-MgContext
        if ($context -and $context.TenantId) {
            return $true
        }
        Write-TiTCLog "Graph context invalid or expired" -Level Warning -Component 'Auth'
        $script:TiTCState.IsConnected = $false
        return $false
    }
    catch {
        Write-TiTCLog "Connection test failed: $($_.Exception.Message)" -Level Error -Component 'Auth'
        $script:TiTCState.IsConnected = $false
        return $false
    }
}

# ============================================================================
# GRAPH API WRAPPER
# ============================================================================

function Get-TiTCGraphErrorDetails {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $ErrorRecord,

        [string]$RequestUri,
        [string]$Endpoint,
        [string]$Method = 'GET'
    )

    $statusCode = $null
    $statusText = $null
    $responseMessage = $null
    $graphCode = $null
    $innerCode = $null

    if ($ErrorRecord.Exception.Response) {
        $statusCode = $ErrorRecord.Exception.Response.StatusCode.value__
        $statusText = $ErrorRecord.Exception.Response.StatusCode.ToString()
    }

    $errorBody = $null
    if ($ErrorRecord.ErrorDetails -and $ErrorRecord.ErrorDetails.Message) {
        $errorBody = $ErrorRecord.ErrorDetails.Message
    }

    if (-not $errorBody) {
        $exceptionMessage = $ErrorRecord.Exception.Message
        if ($exceptionMessage -and $exceptionMessage.TrimStart().StartsWith('{')) {
            $errorBody = $exceptionMessage
        }
    }

    if ($errorBody) {
        try {
            $parsedBody = $errorBody | ConvertFrom-Json -ErrorAction Stop
            if ($parsedBody.error) {
                $responseMessage = $parsedBody.error.message
                $graphCode = $parsedBody.error.code
                if ($parsedBody.error.innerError -and $parsedBody.error.innerError.code) {
                    $innerCode = $parsedBody.error.innerError.code
                }
            }
        }
        catch {
            $responseMessage = $errorBody
        }
    }

    if (-not $responseMessage) {
        $responseMessage = $ErrorRecord.Exception.Message
    }

    return [ordered]@{
        Method          = $Method
        Endpoint        = $Endpoint
        RequestUri      = $RequestUri
        StatusCode      = $statusCode
        StatusText      = $statusText
        GraphCode       = $graphCode
        InnerCode       = $innerCode
        ResponseMessage = $responseMessage
    }
}

function Get-TiTCGraphErrorCategory {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$ErrorDetails
    )

    $message = [string]$ErrorDetails.ResponseMessage
    $statusCode = $ErrorDetails.StatusCode

    if ($statusCode -eq 405) {
        return 'MethodNotAllowed'
    }

    if ($statusCode -eq 403) {
        if ($message -match 'delegated|application permissions|app-only|not supported for delegated|only available to application') {
            return 'UnsupportedEndpointDelegated'
        }

        return 'InsufficientPermissions'
    }

    if ($statusCode -eq 400) {
        if ($message -match "top query" -or ($message -match "limit of '.+' for Top query")) {
            return 'InvalidTop'
        }

        if ($message -match '\$filter| filter ' -or $message -match 'Unsupported or invalid query filter clause') {
            return 'UnsupportedFilter'
        }

        if ($message -match 'not supported in delegated|only available to application permissions|unsupported segment|resource not found for the segment') {
            return 'UnsupportedEndpointDelegated'
        }

        return 'BadRequest'
    }

    return 'GraphRequestFailed'
}

function Format-TiTCGraphRequestTarget {
    [CmdletBinding()]
    param(
        [string]$RequestUri,
        [string]$Endpoint
    )

    if ($RequestUri) {
        try {
            $uri = [System.Uri]$RequestUri
            return '{0}{1}' -f $uri.AbsolutePath, $uri.Query
        }
        catch {
            return $RequestUri
        }
    }

    return $Endpoint
}

function Initialize-TiTCCollectorCheckCatalog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $Result,

        [hashtable]$CheckSupportMap = @{}
    )

    if (-not $Result.PSObject.Properties['Metadata']) {
        Add-Member -InputObject $Result -MemberType NoteProperty -Name Metadata -Value @{} -Force
    }
    elseif (-not $Result.Metadata) {
        $Result.Metadata = @{}
    }

    if (-not $Result.Metadata['CheckResults']) {
        $Result.Metadata['CheckResults'] = @{}
    }

    foreach ($checkName in $CheckSupportMap.Keys) {
        if (-not $Result.Metadata['CheckResults'].ContainsKey($checkName)) {
            $Result.Metadata['CheckResults'][$checkName] = [ordered]@{
                Name    = $checkName
                Support = $CheckSupportMap[$checkName]
                Status  = 'Pending'
                Reason  = $null
            }
        }
    }
}

function Set-TiTCCollectorCheckOutcome {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $Result,

        [Parameter(Mandatory)]
        [string]$CheckName,

        [Parameter(Mandatory)]
        [ValidateSet('Pending', 'Passed', 'FindingDetected', 'SkippedInsufficientPermissions', 'SkippedUnsupportedMode', 'SkippedFeatureUnavailable', 'Failed')]
        [string]$Status,

        [string]$Reason,
        [string]$Support
    )

    Initialize-TiTCCollectorCheckCatalog -Result $Result

    $existing = if ($Result.Metadata['CheckResults'].ContainsKey($CheckName)) {
        $Result.Metadata['CheckResults'][$CheckName]
    }
    else {
        @{}
    }

    $Result.Metadata['CheckResults'][$CheckName] = [ordered]@{
        Name    = $CheckName
        Support = if ($Support) { $Support } elseif ($existing.Support) { $existing.Support } else { 'FullySupported' }
        Status  = $Status
        Reason  = $Reason
    }
}

function Complete-TiTCCollectorCheckOutcome {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $Result,

        [Parameter(Mandatory)]
        [string]$CheckName,

        [int]$FindingsBefore = 0
    )

    Initialize-TiTCCollectorCheckCatalog -Result $Result
    $existing = $Result.Metadata['CheckResults'][$CheckName]
    if ($existing -and $existing.Status -and $existing.Status -notin @('Pending', 'Passed', 'FindingDetected')) {
        return
    }

    $status = if (@($Result.Findings).Count -gt $FindingsBefore) { 'FindingDetected' } else { 'Passed' }
    Set-TiTCCollectorCheckOutcome -Result $Result -CheckName $CheckName -Status $status -Support $existing.Support -Reason $existing.Reason
}

function Finalize-TiTCCollectorOutcome {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $Result
    )

    $checkResults = @()
    if ($Result.Metadata -and $Result.Metadata['CheckResults']) {
        $checkResults = @($Result.Metadata['CheckResults'].Values)
    }

    if ($checkResults.Count -eq 0) {
        return
    }

    $failedCount = @($checkResults | Where-Object { $_.Status -eq 'Failed' }).Count
    $nonSkippedCount = @($checkResults | Where-Object { $_.Status -notlike 'Skipped*' }).Count

    if ($failedCount -gt 0 -and $Result.Status -eq 'Success') {
        $Result.Status = 'PartialSuccess'
    }
    elseif ($nonSkippedCount -eq 0) {
        $Result.Status = 'Skipped'
    }
}

function Invoke-TiTCGraphRequest {
    <#
    .SYNOPSIS
        Wraps Graph API calls with retry logic, pagination, throttling,
        error handling, and telemetry.

    .DESCRIPTION
        All collectors use this instead of calling Invoke-MgGraphRequest directly.
        Handles 429 throttling with exponential backoff, automatic pagination
        via @odata.nextLink, and structured error logging.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Endpoint,

        [ValidateSet('GET', 'POST', 'PATCH', 'DELETE')]
        [string]$Method = 'GET',

        [hashtable]$Body,

        [string]$Select,
        [string]$Filter,
        [string]$Expand,
        [int]$Top = 0,      # 0 = don't add $top (use for singleton endpoints)
        [switch]$NoTop,     # kept for backward compat; $Top=0 default already suppresses $top

        [switch]$Beta,
        [switch]$AllPages,
        [int]$MaxRetries = 3,
        [int]$RetryDelaySeconds = 5,
        [string]$Component = 'GraphAPI'
    )

    begin {
        if (-not (Test-TiTCConnection)) {
            throw "Not connected to Microsoft Graph. Run Connect-TiTCGraph first."
        }
    }

    process {
        $baseUrl = if ($Beta) { $script:TiTCState.GraphBetaUrl } else { $script:TiTCState.GraphBaseUrl }

        # ── Build URI with query parameters ─────────────────────────
        $queryParams = @()
        if ($Select) { $queryParams += "`$select=$Select" }
        if ($Filter) { $queryParams += "`$filter=$Filter" }
        if ($Expand) { $queryParams += "`$expand=$Expand" }
        # Add $top only when explicitly requested or when paginating (-AllPages)
        if ($Method -eq 'GET') {
            $effectiveTop = if ($Top -gt 0) { $Top } elseif ($AllPages) { 999 } else { 0 }
            if ($effectiveTop -gt 0) { $queryParams += "`$top=$effectiveTop" }
        }

        $uri = "$baseUrl$Endpoint"
        if ($queryParams.Count -gt 0) {
            $uri += '?' + ($queryParams -join '&')
        }

        $allResults = [System.Collections.ArrayList]::new()
        $singleObjectResponse = $null
        $currentUri = $uri
        $pageCount = 0
        $callStopwatch = [System.Diagnostics.Stopwatch]::StartNew()

        do {
            $retryCount = 0
            $success = $false

            while (-not $success -and $retryCount -le $MaxRetries) {
                try {
                    $script:TiTCState.ApiCallCount++

                    $requestParams = @{
                        Uri    = $currentUri
                        Method = $Method
                    }

                    if ($Body) {
                        $requestParams.Body = ($Body | ConvertTo-Json -Depth 10)
                        $requestParams.ContentType = 'application/json'
                    }

                    Write-TiTCLog "API $Method $Endpoint (Page $($pageCount + 1))" -Level Debug -Component $Component

                    $response = Invoke-MgGraphRequest @requestParams -ErrorAction Stop
                    $success = $true
                    $pageCount++

                    # Collect results
                    if ($null -ne $response.PSObject.Properties['value']) {
                        $null = $allResults.AddRange($response.value)
                    }
                    elseif ($null -ne $response) {
                        # Single object response
                        $null = $allResults.Add($response)
                        if (-not $singleObjectResponse) {
                            $singleObjectResponse = $response
                        }
                    }

                    # Handle pagination
                    if ($AllPages -and $response.'@odata.nextLink') {
                        $currentUri = $response.'@odata.nextLink'
                    }
                    else {
                        $currentUri = $null
                    }
                }
                catch {
                    $errorDetails = Get-TiTCGraphErrorDetails `
                        -ErrorRecord $_ `
                        -RequestUri $currentUri `
                        -Endpoint $Endpoint `
                        -Method $Method
                    $statusCode = $errorDetails.StatusCode
                    $requestTarget = Format-TiTCGraphRequestTarget -RequestUri $currentUri -Endpoint $Endpoint
                    $errorCategory = Get-TiTCGraphErrorCategory -ErrorDetails $errorDetails

                    if ($statusCode -eq 429) {
                        # Throttled — respect Retry-After header
                        $retryAfter = $_.Exception.Response.Headers['Retry-After']
                        $waitSeconds = if ($retryAfter) { [int]$retryAfter } else { $RetryDelaySeconds * [Math]::Pow(2, $retryCount) }

                        Write-TiTCLog "Throttled (429). Waiting ${waitSeconds}s before retry $($retryCount + 1)/$MaxRetries" -Level Warning -Component $Component
                        Start-Sleep -Seconds $waitSeconds
                        $retryCount++
                    }
                    elseif ($statusCode -in @(500, 502, 503, 504) -and $retryCount -lt $MaxRetries) {
                        $waitSeconds = $RetryDelaySeconds * [Math]::Pow(2, $retryCount)
                        Write-TiTCLog "Server error ($statusCode). Retry $($retryCount + 1)/$MaxRetries in ${waitSeconds}s" -Level Warning -Component $Component
                        Start-Sleep -Seconds $waitSeconds
                        $retryCount++
                    }
                    elseif ($statusCode -eq 403) {
                        $graphErrorMessage = if ($errorDetails.ResponseMessage) { $errorDetails.ResponseMessage } else { 'The request was forbidden by Microsoft Graph.' }
                        $logMessage = "Graph request failed [$errorCategory] $Method $requestTarget -> 403 Forbidden. $graphErrorMessage"
                        Write-TiTCLog $logMessage -Level Error -Component $Component
                        throw "Insufficient permissions for $Endpoint. $graphErrorMessage"
                    }
                    elseif ($statusCode -eq 404) {
                        Write-TiTCLog "Not found (404): $Method $requestTarget" -Level Warning -Component $Component
                        return @{ value = @() }
                    }
                    else {
                        $graphErrorMessage = if ($errorDetails.ResponseMessage) { $errorDetails.ResponseMessage } else { $_.Exception.Message }
                        $codeSuffix = if ($errorDetails.GraphCode) { " [Code: $($errorDetails.GraphCode)]" } else { '' }
                        $statusLabel = if ($errorDetails.StatusCode) {
                            '{0} {1}' -f $errorDetails.StatusCode, $errorDetails.StatusText
                        }
                        else {
                            'UnknownStatus'
                        }
                        $logMessage = "Graph request failed [$errorCategory] $Method $requestTarget -> $statusLabel. $graphErrorMessage$codeSuffix"
                        Write-TiTCLog $logMessage -Level Error -Component $Component
                        throw "Graph request failed [$errorCategory] for $Endpoint. $graphErrorMessage"
                    }
                }
            }

            if (-not $success) {
                Write-TiTCLog "Max retries exceeded for $Endpoint" -Level Error -Component $Component
                throw "Graph API request failed after $MaxRetries retries: $Endpoint"
            }

        } while ($currentUri)

        $callStopwatch.Stop()
        $null = $script:TiTCState.ApiCallLog.Add([ordered]@{
            Timestamp   = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
            Endpoint    = $Endpoint
            Method      = $Method
            DurationMs  = $callStopwatch.ElapsedMilliseconds
            ResultCount = $allResults.Count
            Pages       = $pageCount
            Component   = $Component
        })

        Write-TiTCLog "Completed: $Endpoint ($($allResults.Count) results, $pageCount pages, $($callStopwatch.ElapsedMilliseconds)ms)" -Level Debug -Component $Component

        $result = [ordered]@{
            value     = $allResults.ToArray()
            count     = $allResults.Count
            pages     = $pageCount
            endpoint  = $Endpoint
        }

        if ($singleObjectResponse) {
            foreach ($prop in $singleObjectResponse.PSObject.Properties) {
                if (-not $result.Contains($prop.Name)) {
                    $result[$prop.Name] = $prop.Value
                }
            }
        }

        return $result
    }
}

# ============================================================================
# CONFIGURATION ENGINE
# ============================================================================

function Get-TiTCConfig {
    <#
    .SYNOPSIS
        Loads assessment configuration from a JSON profile file.

    .DESCRIPTION
        Configuration profiles control which checks run, severity thresholds,
        compliance framework mappings, and output preferences. Supports merging
        a base profile with overrides.
    #>
    [CmdletBinding()]
    param(
        [string]$ProfilePath,

        [ValidateSet('Full', 'Quick', 'MSPAudit', 'LicenseOnly', 'ComplianceOnly')]
        [string]$ProfileName = 'Full',

        [hashtable]$Overrides = @{}
    )

    # Default configuration
    $defaultConfig = @{
        Profile           = $ProfileName
        Version           = '1.0.0'

        # Which domains to assess
        Domains           = @{
            EntraID   = $true
            Exchange  = $true
            Intune    = $true
            Defender  = $true
            Licensing = $true
        }

        # Severity thresholds
        Thresholds        = @{
            StaleAccountDays           = 90
            PasswordAgeDays            = 365
            MFAEnforcementTarget       = 100      # Percentage
            GuestAccountMaxAge         = 180
            AdminAccountMaxCount       = 5
            UnusedLicenseThreshold     = 10        # Percentage unused = warning
            ConditionalAccessMinPolicies = 3
            DeviceComplianceTarget     = 95        # Percentage
        }

        # Scoring weights per domain
        Weights           = @{
            EntraID   = 30
            Exchange  = 20
            Intune    = 20
            Defender  = 20
            Licensing = 10
        }

        # Output configuration
        Output            = @{
            Format              = 'PDF'            # PDF, JSON, HTML
            IncludeEvidence     = $true
            IncludeRemediation  = $true
            IncludeAIExplainer  = $false
            BrandingLogo        = $null
            BrandingCompanyName = 'TakeItToCloud'
            BrandingColors      = @{
                Primary   = '#0F172A'              # Deep navy
                Accent    = '#10B981'              # Security green
                Warning   = '#F59E0B'
                Danger    = '#EF4444'
            }
        }

        # Compliance frameworks to map
        ComplianceFrameworks = @('ISO27001', 'CyberInsurance')

        # License pricing (EUR/user/month) — used for waste calculation
        LicensePricing    = @{
            'Microsoft 365 E5'                      = 54.75
            'Microsoft 365 E3'                      = 33.00
            'Microsoft 365 E1'                      = 7.50
            'Microsoft 365 Business Premium'        = 20.60
            'Microsoft 365 Business Standard'       = 11.70
            'Microsoft 365 Business Basic'          = 5.60
            'Microsoft Defender for Endpoint P2'    = 4.70
            'Microsoft Defender for Endpoint P1'    = 2.50
            'Microsoft Defender for Office 365 P2'  = 4.70
            'Microsoft Defender for Office 365 P1'  = 1.90
            'Azure AD Premium P2'                   = 8.40
            'Azure AD Premium P1'                   = 5.40
            'Exchange Online Plan 2'                = 7.50
            'Exchange Online Plan 1'                = 3.80
            'Intune Plan 1'                         = 7.40
            'Microsoft Teams Phone Standard'        = 7.00
            'Power BI Pro'                          = 9.40
        }
    }

    # Quick profile — reduced scope for faster assessments
    if ($ProfileName -eq 'Quick') {
        $defaultConfig.Domains.Intune = $false
        $defaultConfig.Output.IncludeEvidence = $false
    }

    # MSP Audit profile — white-label ready
    if ($ProfileName -eq 'MSPAudit') {
        $defaultConfig.Output.BrandingCompanyName = $null   # MSP provides their own
        $defaultConfig.Output.IncludeEvidence = $true
        $defaultConfig.ComplianceFrameworks = @('ISO27001', 'SOC2Lite', 'CyberInsurance')
    }

    # Load from file if provided
    if ($ProfilePath -and (Test-Path $ProfilePath)) {
        try {
            $fileConfig = Get-Content $ProfilePath -Raw | ConvertFrom-Json -AsHashtable
            Write-TiTCLog "Loaded profile from: $ProfilePath" -Level Info -Component 'Config'

            # Deep merge file config into defaults
            $defaultConfig = Merge-TiTCHashtable -Base $defaultConfig -Override $fileConfig
        }
        catch {
            Write-TiTCLog "Failed to load profile '$ProfilePath': $_" -Level Error -Component 'Config'
        }
    }

    # Apply runtime overrides
    if ($Overrides.Count -gt 0) {
        $defaultConfig = Merge-TiTCHashtable -Base $defaultConfig -Override $Overrides
    }

    $script:TiTCState.Config = $defaultConfig
    Write-TiTCLog "Configuration loaded: Profile=$ProfileName" -Level Info -Component 'Config'

    return $defaultConfig
}

function Merge-TiTCHashtable {
    <#
    .SYNOPSIS
        Deep-merges two hashtables. Override values replace base values.
        Nested hashtables are merged recursively.
    #>
    [CmdletBinding()]
    param(
        [hashtable]$Base,
        [hashtable]$Override
    )

    $merged = $Base.Clone()

    foreach ($key in $Override.Keys) {
        if ($merged.ContainsKey($key) -and
            $merged[$key] -is [hashtable] -and
            $Override[$key] -is [hashtable]) {
            $merged[$key] = Merge-TiTCHashtable -Base $merged[$key] -Override $Override[$key]
        }
        else {
            $merged[$key] = $Override[$key]
        }
    }

    return $merged
}

# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

function Get-TiTCState {
    <#
    .SYNOPSIS
        Returns the current session state (connection, config, telemetry).
    #>
    [CmdletBinding()]
    param()

    return [ordered]@{
        IsConnected       = $script:TiTCState.IsConnected
        TenantId          = $script:TiTCState.TenantId
        TenantName        = $script:TiTCState.TenantName
        TenantDomain      = $script:TiTCState.TenantDomain
        AuthMethod        = $script:TiTCState.AuthMethod
        ConnectedServices = $script:TiTCState.ConnectedServices
        ApiCallCount      = $script:TiTCState.ApiCallCount
        LogEntries        = $script:TiTCState.LogEntries.Count
        ConfigProfile     = $script:TiTCState.Config.Profile
    }
}

function Get-TiTCTenantInfo {
    <#
    .SYNOPSIS
        Returns current tenant information from cached state.
    #>
    [CmdletBinding()]
    param()

    return @{
        TenantId   = $script:TiTCState.TenantId
        TenantName = $script:TiTCState.TenantName
        Domain     = $script:TiTCState.TenantDomain
    }
}

function Export-TiTCLog {
    <#
    .SYNOPSIS
        Exports all log entries to a JSON file for audit trail.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    $script:TiTCState.LogEntries | ConvertTo-Json -Depth 5 | Set-Content -Path $Path -Force
    Write-TiTCLog "Exported $($script:TiTCState.LogEntries.Count) log entries to $Path" -Level Info -Component 'Logging'
}

# ============================================================================
# PERFORMANCE & TELEMETRY
# ============================================================================

function Measure-TiTCOperation {
    <#
    .SYNOPSIS
        Times a script block and logs its duration. Returns the block's output.

    .EXAMPLE
        $users = Measure-TiTCOperation -Name 'Fetch all users' { Invoke-TiTCGraphRequest -Endpoint '/users' -AllPages }
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Name,

        [Parameter(Mandatory)]
        [scriptblock]$ScriptBlock,

        [string]$Component = 'Performance'
    )

    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $result = & $ScriptBlock
    $sw.Stop()

    Write-TiTCLog "$Name completed in $($sw.Elapsed.TotalSeconds.ToString('F2'))s" `
        -Level Info -Component $Component `
        -Data @{ Operation = $Name; DurationMs = $sw.ElapsedMilliseconds }

    return $result
}

function Get-TiTCApiCallSummary {
    <#
    .SYNOPSIS
        Returns a summary of all Graph API calls made in this session:
        total count, average response time, and slowest endpoints.
    #>
    [CmdletBinding()]
    param()

    $calls = $script:TiTCState.ApiCallLog
    if ($calls.Count -eq 0) { return $null }

    $totalMs   = ($calls | Measure-Object -Property DurationMs -Sum).Sum
    $avgMs     = ($calls | Measure-Object -Property DurationMs -Average).Average
    $slowest   = $calls | Sort-Object DurationMs -Descending | Select-Object -First 1

    return [ordered]@{
        TotalCalls         = $calls.Count
        TotalDurationMs    = $totalMs
        AverageDurationMs  = [int]$avgMs
        SlowestEndpoint    = $slowest.Endpoint
        SlowestDurationMs  = $slowest.DurationMs
        CallsByComponent   = @($calls | Group-Object Component | Select-Object Name, Count)
    }
}

function Invoke-TiTCLogRotation {
    <#
    .SYNOPSIS
        Keeps the last N days in the global log. Entries older than RetentionDays
        are moved to logs\archive\auditxpert-[date].log.
    #>
    [CmdletBinding()]
    param(
        [int]$RetentionDays = 30
    )

    if (-not (Test-Path $script:GlobalLogPath)) { return }

    $archiveDir  = Join-Path (Split-Path $script:GlobalLogPath -Parent) 'archive'
    $cutoffDate  = (Get-Date).AddDays(-$RetentionDays)

    $lines   = Get-Content $script:GlobalLogPath -ErrorAction SilentlyContinue
    $keep    = [System.Collections.ArrayList]::new()
    $archive = [System.Collections.ArrayList]::new()

    foreach ($line in $lines) {
        if ($line -match '^\[(\d{4}-\d{2}-\d{2})') {
            if ([datetime]$Matches[1] -lt $cutoffDate) {
                $null = $archive.Add($line)
            } else {
                $null = $keep.Add($line)
            }
        } else {
            $null = $keep.Add($line)   # unparseable lines are kept
        }
    }

    if ($archive.Count -gt 0) {
        if (-not (Test-Path $archiveDir)) {
            New-Item -ItemType Directory -Path $archiveDir -Force | Out-Null
        }
        $archivePath = Join-Path $archiveDir "auditxpert-$(Get-Date -Format 'yyyyMMdd').log"
        $archive | Set-Content -Path $archivePath -Encoding UTF8 -Force
        $keep    | Set-Content -Path $script:GlobalLogPath -Encoding UTF8 -Force
        Write-TiTCLog "Log rotation: archived $($archive.Count) entries (older than $RetentionDays days) → $archivePath" `
            -Level Info -Component 'Logging'
    }
}

function Write-TiTCAssessmentSummary {
    <#
    .SYNOPSIS
        Prints a formatted assessment summary to the console and writes it to the log.
    #>
    [CmdletBinding()]
    param(
        [object]$Report,           # TiTCAssessmentReport or hashtable

        [object]$CollectorResults,  # TiTCCollectorResult[] or @{ Domain = TiTCCollectorResult }

        [hashtable]$Outputs = @{}, # @{ Report = path; Evidence = path; AIReport = path; Data = path; Log = path }

        [string]$Profile = 'Full'
    )

    $separator = '═' * 63

    # Duration
    $duration = if ($script:TiTCState.RunStartTime) {
        $script:TiTCState.RunStartTime.Stop()
        $e = $script:TiTCState.RunStartTime.Elapsed
        if ($e.TotalMinutes -ge 1) { "$([int]$e.TotalMinutes)m $($e.Seconds)s" }
        else { "$($e.Seconds)s" }
    } else { 'unknown' }

    # API call summary
    $apiSummary = Get-TiTCApiCallSummary
    $apiLine = if ($apiSummary) {
        "$($apiSummary.TotalCalls) (avg $($apiSummary.AverageDurationMs)ms, slowest: $($apiSummary.SlowestEndpoint) $($apiSummary.SlowestDurationMs)ms)"
    } else { "$($script:TiTCState.ApiCallCount)" }

    # Collector stats
    $collectorLines = ''
    $collectorList = @()
    if ($CollectorResults -is [System.Collections.IDictionary]) {
        $collectorList = @($CollectorResults.Values)
    }
    elseif ($CollectorResults) {
        $collectorList = @($CollectorResults)
    }

    if ($collectorList.Count -gt 0) {
        $ran = $collectorList.Count
        $succeeded = @($collectorList | Where-Object { $_.Status -in @('Success', 'Skipped') }).Count
        $failed    = @($collectorList | Where-Object { $_.Status -eq 'Failed' }).Count
        $partial   = @($collectorList | Where-Object { $_.Status -eq 'PartialSuccess' }).Count
        $collectorLines += "  Collectors:    $ran ran, $succeeded complete, $partial partial, $failed failed`n"
        foreach ($r in $collectorList) {
            $domain = $r.Domain.ToString()
            $fCount   = if ($r.Findings) { $r.Findings.Count } else { 0 }
            $critical = if ($r.Findings) { ($r.Findings | Where-Object { $_.Severity -eq 'Critical' }).Count } else { 0 }
            $high     = if ($r.Findings) { ($r.Findings | Where-Object { $_.Severity -eq 'High' }).Count } else { 0 }
            $checks   = if ($r.ObjectsScanned -gt 0) { $r.ObjectsScanned } else { '?' }
            $checkResults = if ($r.Metadata -and $r.Metadata['CheckResults']) { @($r.Metadata['CheckResults'].Values) } else { @() }
            $passedChecks = @($checkResults | Where-Object { $_.Status -eq 'Passed' }).Count
            $findingChecks = @($checkResults | Where-Object { $_.Status -eq 'FindingDetected' }).Count
            $permSkipped = @($checkResults | Where-Object { $_.Status -eq 'SkippedInsufficientPermissions' }).Count
            $modeSkipped = @($checkResults | Where-Object { $_.Status -eq 'SkippedUnsupportedMode' }).Count
            $featureSkipped = @($checkResults | Where-Object { $_.Status -eq 'SkippedFeatureUnavailable' }).Count
            $failedChecks = @($checkResults | Where-Object { $_.Status -eq 'Failed' }).Count
            $collectorLines += "    $($domain.PadRight(12)) [$($r.Status)] $checks checks → $fCount findings ($critical critical, $high high)`n"
            if ($checkResults.Count -gt 0) {
                $collectorLines += "                  checks: $passedChecks passed, $findingChecks findings, $permSkipped permission-skipped, $modeSkipped mode-skipped, $featureSkipped feature-skipped, $failedChecks failed`n"
            }
        }
    }

    # Finding totals from report
    $scoreStr   = ''
    $findingStr = ''
    $wasteStr   = ''
    if ($Report) {
        $score = try { [math]::Round($Report.RiskScore.Score, 1) } catch { '?' }
        $grade = try { $Report.RiskScore.Grade } catch { '' }
        $scoreStr = " Risk Score:    $score/100 ($grade)"

        $all      = if ($Report.AllFindings) { @($Report.AllFindings) } else { @() }
        $crit     = ($all | Where-Object { $_.Severity -eq 'Critical' }).Count
        $high     = ($all | Where-Object { $_.Severity -eq 'High'     }).Count
        $med      = ($all | Where-Object { $_.Severity -eq 'Medium'   }).Count
        $low      = ($all | Where-Object { $_.Severity -eq 'Low'      }).Count
        $findingStr = " Total Findings: $($all.Count) ($crit critical, $high high, $med medium, $low low)"

        if ($Report.EstimatedWaste -and $Report.EstimatedWaste -gt 0) {
            $annualWaste = [math]::Round($Report.EstimatedWaste * 12, 0)
            $wasteStr = " License Waste: €$($Report.EstimatedWaste)/month (€${annualWaste}/year)"
        }
    }

    # Outputs section
    $outputLines = ''
    foreach ($key in $Outputs.Keys) {
        if ($Outputs[$key]) {
            $outputLines += "   $($key.PadRight(10)) $($Outputs[$key])`n"
        }
    }

    $tenantDisplay = if ($script:TiTCState.TenantName -and $script:TiTCState.TenantDomain) {
        "$($script:TiTCState.TenantName) ($($script:TiTCState.TenantDomain))"
    } elseif ($script:TiTCState.TenantId) {
        $script:TiTCState.TenantId
    } else { 'Unknown' }

    $summary = @"

 $separator
 ASSESSMENT SUMMARY
 $separator
 Tenant:        $tenantDisplay
 Profile:       $Profile
 Duration:      $duration
 API Calls:     $apiLine

$($collectorLines)
$scoreStr
$findingStr
$wasteStr

 Outputs:
$outputLines $separator
"@

    Write-Host $summary -ForegroundColor Cyan
    Write-TiTCLog "Assessment summary written" -Level Info -Component 'Summary' -Data @{
        Duration  = $duration
        ApiCalls  = $script:TiTCState.ApiCallCount
    }
}

function Get-TiTCErrorSummary {
    <#
    .SYNOPSIS
        Returns all warnings and errors captured during the run, grouped by component.
        Also prints a formatted summary to the console.
    #>
    [CmdletBinding()]
    param(
        [switch]$Print   # Print to console in addition to returning
    )

    $errors   = @($script:TiTCState.ErrorLog | Where-Object { $_.Level -eq 'Error'   })
    $warnings = @($script:TiTCState.ErrorLog | Where-Object { $_.Level -eq 'Warning' })

    $result = [ordered]@{
        ErrorCount          = $errors.Count
        WarningCount        = $warnings.Count
        Errors              = $errors
        Warnings            = $warnings
        ErrorsByComponent   = @($errors   | Group-Object Component | Select-Object Name, Count)
        WarningsByComponent = @($warnings | Group-Object Component | Select-Object Name, Count)
    }

    if ($Print -or ($errors.Count + $warnings.Count -gt 0)) {
        if ($warnings.Count -gt 0) {
            Write-Host ""
            Write-Host "  WARNINGS ($($warnings.Count)):" -ForegroundColor Yellow
            foreach ($w in $warnings) {
                Write-Host "    [$($w.Component)] $($w.Message)" -ForegroundColor DarkYellow
            }
        }
        if ($errors.Count -gt 0) {
            Write-Host ""
            Write-Host "  ERRORS ($($errors.Count)):" -ForegroundColor Red
            foreach ($e in $errors) {
                Write-Host "    [$($e.Component)] $($e.Message)" -ForegroundColor Red
            }
        } elseif ($warnings.Count -gt 0) {
            Write-Host ""
            Write-Host "  ERRORS (0): None" -ForegroundColor Green
        }
    }

    return $result
}

# ============================================================================
# PREREQUISITES
# ============================================================================

function Test-TiTCPrerequisites {
    <#
    .SYNOPSIS
        Checks that all required PowerShell modules, optional tools, and AI API
        keys are available. Optionally installs missing required modules.

    .PARAMETER AutoInstall
        Silently install all missing required modules without prompting.

    .PARAMETER CheckOnly
        Report the status of each component without installing anything.

    .OUTPUTS
        Hashtable with AllRequiredMet ($true/$false) and per-component status.
    #>
    [CmdletBinding()]
    param(
        [switch]$AutoInstall,
        [switch]$CheckOnly
    )

    $result = [ordered]@{
        AllRequiredMet = $true
        Components     = [ordered]@{}
    }

    $requiredModules = @(
        @{ Name = 'Microsoft.Graph.Authentication'; MinVersion = '2.0.0'; Required = $true;
           Description = 'Graph API authentication — required for all assessments' }
    )

    $optionalModules = @(
        @{ Name = 'ExchangeOnlineManagement'; MinVersion = '3.0.0'; Required = $false;
           Description = 'Deep Exchange checks (transport rules, connectors, DMARC)' },
        @{ Name = 'Pester'; MinVersion = '5.0.0'; Required = $false;
           Description = 'Unit test runner (only needed when running tests)' }
    )

    $installAll = $AutoInstall.IsPresent

    # ── Required modules ─────────────────────────────────────────────────────
    foreach ($mod in $requiredModules) {
        $installed = Get-Module -ListAvailable -Name $mod.Name |
            Where-Object { $_.Version -ge [version]$mod.MinVersion } |
            Select-Object -First 1

        if ($installed) {
            $result.Components[$mod.Name] = @{
                Installed = $true; Version = $installed.Version.ToString()
                Required = $true
            }
            Write-TiTCLog "  OK  $($mod.Name) v$($installed.Version)" -Level Info -Component 'Prerequisites'
            continue
        }

        $result.AllRequiredMet = $false

        if ($CheckOnly) {
            $result.Components[$mod.Name] = @{ Installed = $false; Required = $true }
            Write-TiTCLog "  MISSING  $($mod.Name) (required)" -Level Warning -Component 'Prerequisites'
            continue
        }

        $answer = 'N'
        if (-not $installAll) {
            Write-Host ""
            Write-Host "  $($mod.Name) is required but not installed." -ForegroundColor Yellow
            Write-Host "  $($mod.Description)" -ForegroundColor DarkGray
            $answer = Read-Host "  Install $($mod.Name)? (Y)es / (N)o / (A)ll"
            if ($answer -match '^[Aa]') { $installAll = $true }
        }

        if ($installAll -or $answer -match '^[Yy]') {
            try {
                Write-Host "  Installing $($mod.Name)..." -NoNewline -ForegroundColor Cyan
                Install-Module -Name $mod.Name -Scope CurrentUser `
                    -MinimumVersion $mod.MinVersion -Force -AllowClobber -Repository PSGallery
                $newVer = (Get-Module -ListAvailable -Name $mod.Name |
                    Sort-Object Version -Descending | Select-Object -First 1).Version
                Write-Host " OK (v$newVer)" -ForegroundColor Green
                $result.Components[$mod.Name] = @{
                    Installed = $true; Version = $newVer.ToString()
                    Required = $true; JustInstalled = $true
                }
                $result.AllRequiredMet = $true
            }
            catch {
                Write-Host " FAILED" -ForegroundColor Red
                Write-TiTCLog "Failed to install $($mod.Name): $_" -Level Error -Component 'Prerequisites'
                $result.Components[$mod.Name] = @{
                    Installed = $false; Required = $true; Error = $_.ToString()
                }
            }
        }
        else {
            Write-Host "  Skipped $($mod.Name) — assessments will fail without it." -ForegroundColor DarkYellow
            $result.Components[$mod.Name] = @{ Installed = $false; Required = $true; Skipped = $true }
        }
    }

    # ── Optional modules ──────────────────────────────────────────────────────
    foreach ($mod in $optionalModules) {
        $installed = Get-Module -ListAvailable -Name $mod.Name |
            Where-Object { $_.Version -ge [version]$mod.MinVersion } |
            Select-Object -First 1

        if ($installed) {
            $result.Components[$mod.Name] = @{
                Installed = $true; Version = $installed.Version.ToString(); Required = $false
            }
            continue
        }

        if ($AutoInstall -and -not $CheckOnly) {
            try {
                Install-Module -Name $mod.Name -Scope CurrentUser -Force -AllowClobber -Repository PSGallery
                $newVer = (Get-Module -ListAvailable -Name $mod.Name |
                    Sort-Object Version -Descending | Select-Object -First 1).Version
                $result.Components[$mod.Name] = @{
                    Installed = $true; Version = $newVer.ToString(); Required = $false; JustInstalled = $true
                }
            }
            catch {
                $result.Components[$mod.Name] = @{ Installed = $false; Required = $false; Error = $_.ToString() }
            }
        }
        else {
            $result.Components[$mod.Name] = @{ Installed = $false; Required = $false }
        }
    }

    # ── Optional tools ────────────────────────────────────────────────────────
    $wkhtmltopdf = Get-Command 'wkhtmltopdf' -ErrorAction SilentlyContinue
    $result.Components['wkhtmltopdf'] = @{
        Found    = ($null -ne $wkhtmltopdf)
        Path     = if ($wkhtmltopdf) { $wkhtmltopdf.Source } else { '' }
        Required = $false
    }

    # ── AI API keys ───────────────────────────────────────────────────────────
    $result.Components['ANTHROPIC_API_KEY'] = @{
        Set      = ($null -ne $env:ANTHROPIC_API_KEY -and $env:ANTHROPIC_API_KEY -ne '')
        Required = $false
    }
    $result.Components['OPENAI_API_KEY'] = @{
        Set      = ($null -ne $env:OPENAI_API_KEY -and $env:OPENAI_API_KEY -ne '')
        Required = $false
    }

    Write-TiTCLog "Prerequisites check complete. AllRequiredMet=$($result.AllRequiredMet)" `
        -Level Info -Component 'Prerequisites'

    return $result
}

# ============================================================================
# EXPORTS
# ============================================================================

Export-ModuleMember -Function @(
    # Auth
    'Connect-TiTCGraph'
    'Disconnect-TiTCGraph'
    'Test-TiTCConnection'

    # Graph API
    'Invoke-TiTCGraphRequest'
    'Initialize-TiTCCollectorCheckCatalog'
    'Set-TiTCCollectorCheckOutcome'
    'Complete-TiTCCollectorCheckOutcome'
    'Finalize-TiTCCollectorOutcome'

    # Config
    'Get-TiTCConfig'

    # Logging
    'Write-TiTCLog'
    'Initialize-TiTCLogging'
    'Export-TiTCLog'
    'Invoke-TiTCLogRotation'

    # Performance & Telemetry
    'Measure-TiTCOperation'
    'Get-TiTCApiCallSummary'
    'Write-TiTCAssessmentSummary'
    'Get-TiTCErrorSummary'

    # Prerequisites
    'Test-TiTCPrerequisites'

    # Factories (re-exported from nested TiTC.Models)
    'New-TiTCFinding'
    'New-TiTCCollectorResult'
    'New-TiTCAssessmentReport'
    'New-TiTCRiskScore'
    'New-TiTCLicenseWaste'

    # Utilities
    'Get-TiTCState'
    'Get-TiTCTenantInfo'
    'Merge-TiTCHashtable'
)
