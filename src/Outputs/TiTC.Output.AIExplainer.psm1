#Requires -Version 5.1
<#
.SYNOPSIS
    TakeItToCloud.Assess — AI-Powered Audit Explainer Integration.

.DESCRIPTION
    Enriches TiTCFinding objects with plain-English AI-generated explanations
    for non-technical business executives. Supports Claude (Anthropic) and
    OpenAI API providers.

    For each finding, generates:
    - Plain-English risk explanation
    - Business impact statement
    - Priority rating (1-5)
    - Non-technical remediation guidance

    Populates finding.AIExplanation, finding.AIBusinessImpact, finding.AIPriority.

.NOTES
    Module:     TiTC.Output.AIExplainer
    Author:     TakeItToCloud
    Version:    1.0.0
    Requires:   API key for chosen provider (Claude or OpenAI)
#>

# ============================================================================
# MODULE DEPENDENCIES
# ============================================================================

$CorePath = Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) 'src\Core\TiTC.Core.psm1'
if (Test-Path $CorePath) {
    Import-Module $CorePath -ErrorAction SilentlyContinue
}

$ModelsPath = Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) 'src\Core\Models\TiTC.Models.psm1'
if (Test-Path $ModelsPath) {
    Import-Module $ModelsPath -ErrorAction SilentlyContinue
}

# ============================================================================
# CONSTANTS
# ============================================================================

$script:COMPONENT         = 'Output.AIExplainer'
$script:CLAUDE_API_URL    = 'https://api.anthropic.com/v1/messages'
$script:OPENAI_API_URL    = 'https://api.openai.com/v1/chat/completions'
$script:DEFAULT_CLAUDE_MODEL = 'claude-sonnet-4-20250514'
$script:DEFAULT_OPENAI_MODEL = 'gpt-4o-mini'

# ============================================================================
# MAIN FUNCTION
# ============================================================================

function Invoke-TiTCAIExplainer {
    <#
    .SYNOPSIS
        Enriches findings with AI-generated plain-English explanations.

    .PARAMETER Findings
        Array of TiTCFinding objects to explain.

    .PARAMETER Provider
        AI provider: 'Claude' (Anthropic) or 'OpenAI'.

    .PARAMETER ApiKey
        API key for the chosen provider.

    .PARAMETER ApiEndpoint
        Optional override for API endpoint URL.

    .PARAMETER Model
        Model name to use. Defaults to claude-sonnet-4-20250514 or gpt-4o-mini.

    .PARAMETER MaxFindings
        Maximum number of findings to explain (cost control). Default: 20.

    .PARAMETER HighSeverityOnly
        When set, only explains Critical and High severity findings.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object[]]$Findings,

        [ValidateSet('OpenAI', 'Claude', 'Local')]
        [string]$Provider = 'Claude',

        [string]$ApiKey,
        [string]$ApiEndpoint,

        [string]$Model,

        [int]$MaxFindings = 20,

        [switch]$HighSeverityOnly
    )

    # Resolve API key from parameter or environment
    if (-not $ApiKey) {
        $ApiKey = switch ($Provider) {
            'Claude' { $env:ANTHROPIC_API_KEY }
            'OpenAI' { $env:OPENAI_API_KEY }
        }
    }

    if (-not $ApiKey -and $Provider -ne 'Local') {
        Write-TiTCLog "No API key provided for $Provider. Set environment variable ANTHROPIC_API_KEY or OPENAI_API_KEY." `
            -Level Error -Component $script:COMPONENT
        throw "AI Explainer requires an API key. Provide -ApiKey or set the environment variable."
    }

    # Resolve model
    if (-not $Model) {
        $Model = if ($Provider -eq 'OpenAI') { $script:DEFAULT_OPENAI_MODEL } else { $script:DEFAULT_CLAUDE_MODEL }
    }

    # Filter findings
    $toExplain = $Findings
    if ($HighSeverityOnly) {
        $toExplain = $Findings | Where-Object { $_.Severity -in @('Critical', 'High') }
    }
    $toExplain = $toExplain | Select-Object -First $MaxFindings

    Write-TiTCLog "AI Explainer: processing $($toExplain.Count) findings via $Provider ($Model)..." `
        -Level Info -Component $script:COMPONENT

    $enriched = [System.Collections.ArrayList]::new()
    $processed = 0
    $errors    = 0

    foreach ($finding in $toExplain) {
        try {
            $prompt = Build-TiTCAIPrompt -Finding $finding
            $response = Invoke-TiTCAIRequest -Provider $Provider -ApiKey $ApiKey `
                -ApiEndpoint $ApiEndpoint -Model $Model -Prompt $prompt

            if ($response) {
                $parsed = Parse-TiTCAIResponse -ResponseText $response
                $finding.AIExplanation  = $parsed.Risk
                $finding.AIBusinessImpact = $parsed.Impact
                $finding.AIPriority     = $parsed.Priority
            }

            $null = $enriched.Add($finding)
            $processed++

            Write-TiTCLog "AI explained: $($finding.Title)" -Level Debug -Component $script:COMPONENT
        }
        catch {
            Write-TiTCLog "Failed to explain finding '$($finding.Title)': $_" -Level Warning -Component $script:COMPONENT
            $null = $enriched.Add($finding)
            $errors++
        }
    }

    Write-TiTCLog "AI Explainer complete: $processed explained, $errors errors" `
        -Level Success -Component $script:COMPONENT

    return @($enriched)
}

# ============================================================================
# INPUT NORMALIZER
# ============================================================================

function Import-TiTCAuditData {
    <#
    .SYNOPSIS
        Imports and normalises security findings from multiple source formats.

    .PARAMETER InputFile
        Path to a single input file (.json or .csv).

    .PARAMETER InputFolder
        Path to a folder. All .json and .csv files are processed.

    .PARAMETER Format
        Input format. 'Auto' (default) detects from file extension and header row.
        Supported: Auto, AuditXpert, CSV, Qualys, Nessus, Defender.

    .OUTPUTS
        Array of finding-like objects compatible with Invoke-TiTCAIExplainer
        and Export-TiTCAIReport.
    #>
    [CmdletBinding(DefaultParameterSetName = 'File')]
    param(
        [Parameter(Mandatory, ParameterSetName = 'File')]
        [string]$InputFile,

        [Parameter(Mandatory, ParameterSetName = 'Folder')]
        [string]$InputFolder,

        [ValidateSet('Auto', 'AuditXpert', 'CSV', 'Qualys', 'Nessus', 'Defender')]
        [string]$Format = 'Auto'
    )

    $allFindings = [System.Collections.ArrayList]::new()

    if ($PSCmdlet.ParameterSetName -eq 'Folder') {
        if (-not (Test-Path $InputFolder)) {
            throw "Input folder not found: $InputFolder"
        }
        $files = Get-ChildItem -Path $InputFolder -File |
                    Where-Object { $_.Extension -in @('.json', '.csv') }
        Write-TiTCLog "Import-TiTCAuditData: found $($files.Count) file(s) in '$InputFolder'" `
            -Level Info -Component $script:COMPONENT
        foreach ($file in $files) {
            $found = Import-TiTCSingleFile -FilePath $file.FullName -Format $Format
            foreach ($f in $found) { $null = $allFindings.Add($f) }
        }
    }
    else {
        if (-not (Test-Path $InputFile)) {
            throw "Input file not found: $InputFile"
        }
        $found = Import-TiTCSingleFile -FilePath $InputFile -Format $Format
        foreach ($f in $found) { $null = $allFindings.Add($f) }
    }

    Write-TiTCLog "Import-TiTCAuditData: imported $($allFindings.Count) finding(s) total" `
        -Level Success -Component $script:COMPONENT
    return @($allFindings)
}

# ---- Private: dispatch a single file ----------------------------------------

function Import-TiTCSingleFile {
    [CmdletBinding()]
    param([string]$FilePath, [string]$Format)

    $ext = [System.IO.Path]::GetExtension($FilePath).ToLower()

    $detectedFormat = $Format
    if ($Format -in @('Auto', 'CSV')) {
        if ($ext -eq '.json') {
            $detectedFormat = 'AuditXpert'
        }
        elseif ($ext -eq '.csv') {
            $detectedFormat = Get-TiTCCSVFormat -FilePath $FilePath
        }
        else {
            Write-TiTCLog "Unsupported extension '$ext' — skipping: $FilePath" `
                -Level Warning -Component $script:COMPONENT
            return @()
        }
    }

    Write-TiTCLog "Importing '$([System.IO.Path]::GetFileName($FilePath))' as $detectedFormat" `
        -Level Info -Component $script:COMPONENT

    switch ($detectedFormat) {
        'AuditXpert' { return ConvertFrom-TiTCAuditXpertJson -FilePath $FilePath }
        'Qualys'     { return ConvertFrom-TiTCQualysCSV      -FilePath $FilePath }
        'Nessus'     { return ConvertFrom-TiTCNessusCSV      -FilePath $FilePath }
        'Defender'   { return ConvertFrom-TiTCDefenderCSV    -FilePath $FilePath }
        default      { return ConvertFrom-TiTCManualCSV      -FilePath $FilePath }
    }
}

# ---- Private: CSV format auto-detection -------------------------------------

function Get-TiTCCSVFormat {
    param([string]$FilePath)
    try {
        $firstRow  = Import-Csv -Path $FilePath | Select-Object -First 1
        $colString = ($firstRow.PSObject.Properties.Name -join ',').ToLower()
        if ($colString -match '\bqid\b')               { return 'Qualys'   }
        if ($colString -match 'plugin[ _]?id')         { return 'Nessus'   }
        if ($colString -match 'alertid|servicesource') { return 'Defender' }
        return 'CSV'
    }
    catch { return 'CSV' }
}

# ---- Private: factory for normalised findings (PSCustomObject) ---------------

function New-TiTCNormalizedFinding {
    param(
        [string]   $Title              = 'Unknown',
        [string]   $Severity           = 'Medium',
        [string]   $Description        = '',
        [string]   $Remediation        = '',
        [string]   $Status             = 'Open',
        [string]   $Domain             = 'External',
        [string[]] $Tags               = @(),
        [string[]] $ComplianceControls = @(),
        [object[]] $AffectedResources  = @(),
        [string]   $Source             = ''
    )

    $normalized = switch -Regex ($Severity) {
        '^(critical|5)$'          { 'Critical' }
        '^(high|4)$'              { 'High'     }
        '^(medium|moderate|3)$'   { 'Medium'   }
        '^(low|2)$'               { 'Low'      }
        default                   { 'Medium'   }
    }

    return [PSCustomObject]@{
        FindingId          = [System.Guid]::NewGuid().ToString()
        Title              = $Title
        Severity           = $normalized
        Description        = $Description
        Remediation        = $Remediation
        Status             = $Status
        Domain             = $Domain
        Tags               = $Tags
        ComplianceControls = $ComplianceControls
        AffectedResources  = $AffectedResources
        Source             = $Source
        Timestamp          = (Get-Date).ToString('o')
        AIExplanation      = $null
        AIBusinessImpact   = $null
        AIPriority         = $null
    }
}

# ---- Private: format parsers ------------------------------------------------

function ConvertFrom-TiTCAuditXpertJson {
    param([string]$FilePath)
    $raw = Get-Content $FilePath -Raw | ConvertFrom-Json
    if ($raw.AllFindings)        { return @($raw.AllFindings) }
    elseif ($raw -is [array])    { return @($raw) }
    else                         { return @() }
}

function ConvertFrom-TiTCQualysCSV {
    param([string]$FilePath)
    $rows   = Import-Csv -Path $FilePath
    $result = [System.Collections.ArrayList]::new()
    $sevMap = @{ '5' = 'Critical'; '4' = 'High'; '3' = 'Medium'; '2' = 'Low'; '1' = 'Informational' }

    foreach ($row in $rows) {
        $title   = if ($row.Title)              { $row.Title }
                   elseif ($row.'Vulnerability Title') { $row.'Vulnerability Title' }
                   else                         { 'Unknown Vulnerability' }

        $rawSev  = if ($row.'Severity Level')   { $row.'Severity Level' }
                   elseif ($row.Severity)        { $row.Severity }
                   else                         { '3' }
        $sev     = if ($sevMap[$rawSev])        { $sevMap[$rawSev] } else { 'Medium' }

        $desc    = if ($row.Threat)             { $row.Threat }
                   elseif ($row.Details)         { $row.Details }
                   else                         { '' }
        $remed   = if ($row.Solution)           { $row.Solution } else { '' }
        $host_   = if ($row.IP)                 { $row.IP } elseif ($row.DNS) { $row.DNS } else { '' }
        $cves    = if ($row.'CVE ID' -and $row.'CVE ID' -ne '') { @("CVE:$($row.'CVE ID')") } else { @() }

        $null = $result.Add((New-TiTCNormalizedFinding `
            -Title $title -Severity $sev -Description $desc -Remediation $remed `
            -Domain 'Network' -Tags @('Qualys', 'Vulnerability') `
            -ComplianceControls $cves `
            -AffectedResources @(if ($host_) { $host_ }) `
            -Source 'Qualys'))
    }
    return @($result)
}

function ConvertFrom-TiTCNessusCSV {
    param([string]$FilePath)
    $rows   = Import-Csv -Path $FilePath
    $result = [System.Collections.ArrayList]::new()

    foreach ($row in $rows) {
        $rawRisk = if ($row.Risk) { $row.Risk } else { 'Medium' }
        if ($rawRisk -eq 'None') { continue }   # skip informational

        $sev = switch ($rawRisk) {
            'Critical' { 'Critical' } 'High'   { 'High'   }
            'Medium'   { 'Medium'   } 'Low'    { 'Low'    }
            default    { 'Medium'   }
        }

        $title    = if ($row.Name)       { $row.Name }     else { 'Unknown' }
        $desc     = if ($row.Synopsis)   { $row.Synopsis } elseif ($row.Description) { $row.Description } else { '' }
        $remed    = if ($row.Solution)   { $row.Solution } else { '' }
        $host_    = if ($row.Host)       { $row.Host }     else { '' }
        $cves     = if ($row.CVE -and $row.CVE -ne '') { @("CVE:$($row.CVE)") } else { @() }
        $pluginId = if ($row.'Plugin ID' -and $row.'Plugin ID' -ne '') { "Nessus:$($row.'Plugin ID')" } else { $null }
        $controls = @($cves) + @(if ($pluginId) { $pluginId })

        $null = $result.Add((New-TiTCNormalizedFinding `
            -Title $title -Severity $sev -Description $desc -Remediation $remed `
            -Domain 'Network' -Tags @('Nessus', 'Vulnerability') `
            -ComplianceControls $controls `
            -AffectedResources @(if ($host_) { $host_ }) `
            -Source 'Nessus'))
    }
    return @($result)
}

function ConvertFrom-TiTCDefenderCSV {
    param([string]$FilePath)
    $rows   = Import-Csv -Path $FilePath
    $result = [System.Collections.ArrayList]::new()

    foreach ($row in $rows) {
        $title  = if ($row.Title)       { $row.Title }
                  elseif ($row.AlertTitle) { $row.AlertTitle }
                  else                  { 'Unknown Alert' }

        $rawSev = if ($row.Severity)    { $row.Severity }
                  elseif ($row.AlertSeverity) { $row.AlertSeverity }
                  else                  { 'Medium' }
        $sev = switch ($rawSev) {
            'Informational' { 'Low'      } 'Low'      { 'Low'      }
            'Medium'        { 'Medium'   } 'High'     { 'High'     }
            'Critical'      { 'Critical' } default    { 'Medium'   }
        }

        $desc   = if ($row.Description) { $row.Description }
                  elseif ($row.Category) { $row.Category }
                  else                  { '' }
        $status = if ($row.Status)      { $row.Status } else { 'Open' }
        $src    = if ($row.ServiceSource) { $row.ServiceSource } else { 'Defender' }

        $null = $result.Add((New-TiTCNormalizedFinding `
            -Title $title -Severity $sev -Description $desc -Status $status `
            -Domain 'ThreatDetection' -Tags @('Defender', $src) `
            -Source 'Defender'))
    }
    return @($result)
}

function ConvertFrom-TiTCManualCSV {
    param([string]$FilePath)
    $rows   = Import-Csv -Path $FilePath
    $result = [System.Collections.ArrayList]::new()

    foreach ($row in $rows) {
        # Supports Manual CSV (Title/Description/Severity) and CIS Benchmark exports
        $title  = if ($row.Title)          { $row.Title }
                  elseif ($row.Recommendation) { $row.Recommendation }
                  elseif ($row.Check)      { $row.Check }
                  else                     { 'Unknown' }

        $rawSev = if ($row.Severity)       { $row.Severity }
                  elseif ($row.Risk)        { $row.Risk }
                  elseif ($row.Level -and $row.Status -eq 'Failed') {
                      if ($row.Level -match '2') { 'High' } else { 'Medium' }
                  }
                  else                     { 'Medium' }

        $desc   = if ($row.Description)    { $row.Description }
                  elseif ($row.Details)     { $row.Details }
                  else                     { '' }
        $remed  = if ($row.Remediation)    { $row.Remediation }
                  elseif ($row.Fix)         { $row.Fix }
                  elseif ($row.Solution)    { $row.Solution }
                  else                     { '' }
        $status = if ($row.Status)         { $row.Status } else { 'Open' }

        $controls = @()
        if ($row.'Section #' -and $row.'Section #' -ne '') { $controls += "CIS:$($row.'Section #')" }
        if ($row.Control     -and $row.Control     -ne '') { $controls += "CIS:$($row.Control)"     }

        $null = $result.Add((New-TiTCNormalizedFinding `
            -Title $title -Severity $rawSev -Description $desc -Remediation $remed `
            -Status $status -ComplianceControls $controls -Source 'Manual'))
    }
    return @($result)
}

# ============================================================================
# REPORT GENERATOR
# ============================================================================

function Export-TiTCAIReport {
    <#
    .SYNOPSIS
        Generates a self-contained HTML report with per-finding AI explanation cards.

    .PARAMETER Findings
        Array of finding objects (TiTCFinding or normalised PSCustomObject).
        Should be pre-enriched with Invoke-TiTCAIExplainer.

    .PARAMETER OutputPath
        Destination .html file. Auto-generated name if omitted.

    .PARAMETER TenantName
        Tenant or client name shown in the report header.

    .PARAMETER CompanyName
        MSP / company name shown as the report author.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object[]]$Findings,

        [string]$OutputPath,

        [string]$TenantName   = 'M365 Tenant',

        [string]$CompanyName  = 'TakeItToCloud'
    )

    if (-not $OutputPath) {
        $OutputPath = Join-Path $PWD "ai-security-briefing-$(Get-Date -Format 'yyyyMMdd-HHmmss').html"
    }

    # ── Statistics ──────────────────────────────────────────────────────────
    $countTotal    = $Findings.Count
    $countCritical = ($Findings | Where-Object { $_.Severity -eq 'Critical' }).Count
    $countHigh     = ($Findings | Where-Object { $_.Severity -eq 'High'     }).Count
    $countMedium   = ($Findings | Where-Object { $_.Severity -eq 'Medium'   }).Count

    # ── Card builder ─────────────────────────────────────────────────────────
    $priorityMap = @{
        5 = @{ Label = 'P5 &middot; Fix immediately';   Class = 'p5' }
        4 = @{ Label = 'P4 &middot; Fix this month';    Class = 'p4' }
        3 = @{ Label = 'P3 &middot; Fix this quarter';  Class = 'p3' }
        2 = @{ Label = 'P2 &middot; Plan next quarter'; Class = 'p2' }
        1 = @{ Label = 'P1 &middot; Nice to have';      Class = 'p1' }
    }

    $cards = ''
    foreach ($f in $Findings) {
        $sevClass = switch ($f.Severity) {
            'Critical' { 'sev-critical' } 'High'   { 'sev-high'   }
            'Medium'   { 'sev-medium'   } 'Low'    { 'sev-low'    }
            default    { 'sev-info'     }
        }

        $pri = try { [int]$f.AIPriority } catch { 0 }
        if ($priorityMap.ContainsKey($pri)) {
            $priLabel = $priorityMap[$pri].Label
            $priClass = $priorityMap[$pri].Class
        }
        else {
            $priLabel = 'Unrated'
            $priClass = 'p-none'
        }

        $riskText   = if ($f.AIExplanation)    { [System.Web.HttpUtility]::HtmlEncode($f.AIExplanation) }
                      else                      { '<em class="empty-text">Run Invoke-TiTCAIExplainer to generate this explanation.</em>' }
        $impactText = if ($f.AIBusinessImpact) { [System.Web.HttpUtility]::HtmlEncode($f.AIBusinessImpact) }
                      else                      { '<em class="empty-text">No business impact analysis available.</em>' }
        $fixText    = if ($f.Remediation -and $f.Remediation -ne '') {
                          [System.Web.HttpUtility]::HtmlEncode($f.Remediation) -replace "`n", '<br>'
                      }
                      else { '<em class="empty-text">See finding details for remediation guidance.</em>' }

        # Compliance control pills
        $pills = ''
        if ($f.ComplianceControls) {
            foreach ($ctrl in $f.ComplianceControls) {
                if ($ctrl -and $ctrl -ne '') {
                    $pills += "<span class=`"control-pill`">$([System.Web.HttpUtility]::HtmlEncode($ctrl))</span>`n"
                }
            }
        }
        $controlsRow = if ($pills) {
            "<div class=`"controls`">$pills</div>"
        } else { '' }

        $safeTitle = [System.Web.HttpUtility]::HtmlEncode($f.Title)

        $cards += @"
<div class="card">
  <div class="card-header">
    <div class="card-title">$safeTitle</div>
    <div class="card-meta">
      <span class="sev $sevClass">$($f.Severity)</span>
      <span class="priority $priClass">$priLabel</span>
    </div>
  </div>
  <div class="card-body">
    <div class="section section-risk">
      <div class="section-label">What's the risk?</div>
      <div class="section-text">$riskText</div>
    </div>
    <div class="section section-impact">
      <div class="section-label">Business impact</div>
      <div class="section-text">$impactText</div>
    </div>
    <div class="section section-fix">
      <div class="section-label">How to fix this</div>
      <div class="section-text">$fixText</div>
    </div>
    $controlsRow
  </div>
</div>
"@
    }

    # ── Full HTML ─────────────────────────────────────────────────────────────
    $generatedDate = Get-Date -Format 'dd MMMM yyyy'

    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>AI Security Briefing — $([System.Web.HttpUtility]::HtmlEncode($TenantName))</title>
<style>
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
         background: #F1F5F9; color: #0F172A; font-size: 14px; }

  /* ── Header ── */
  .header { background: #0F172A; color: white; padding: 32px 48px; }
  .header h1 { font-size: 1.6rem; font-weight: 700; margin-bottom: 4px; }
  .header .meta { color: #94A3B8; font-size: 0.8rem; }
  .stats { display: flex; flex-wrap: wrap; gap: 16px; margin-top: 24px; }
  .stat-box { background: rgba(255,255,255,.08); border-radius: 8px; padding: 12px 20px; min-width: 100px; }
  .stat-box .value { font-size: 1.5rem; font-weight: 700; }
  .stat-box .label { font-size: 0.7rem; color: #94A3B8; margin-top: 2px; text-transform: uppercase; letter-spacing: .5px; }

  /* ── Main ── */
  .main { padding: 32px 48px; }
  .section-heading { font-size: 0.68rem; font-weight: 700; text-transform: uppercase;
                     letter-spacing: 1.5px; color: #64748B; margin-bottom: 20px; }

  /* ── Cards grid ── */
  .cards { display: grid; grid-template-columns: repeat(auto-fill, minmax(500px, 1fr)); gap: 20px; }

  /* ── Card ── */
  .card { background: white; border-radius: 12px; overflow: hidden;
          box-shadow: 0 1px 3px rgba(0,0,0,.08), 0 1px 2px rgba(0,0,0,.06); }
  .card-header { display: flex; align-items: flex-start; gap: 14px;
                 padding: 16px 20px; border-bottom: 1px solid #F1F5F9; }
  .card-title  { flex: 1; font-size: 0.9rem; font-weight: 600; line-height: 1.45; color: #0F172A; }
  .card-meta   { display: flex; flex-direction: column; align-items: flex-end; gap: 6px; flex-shrink: 0; }
  .card-body   { padding: 4px 20px 18px; }

  /* ── Severity badge ── */
  .sev { padding: 3px 10px; border-radius: 20px; font-size: 0.68rem;
         font-weight: 700; text-transform: uppercase; color: white; white-space: nowrap; }
  .sev-critical { background: #DC2626; }
  .sev-high     { background: #EA580C; }
  .sev-medium   { background: #D97706; }
  .sev-low      { background: #16A34A; }
  .sev-info     { background: #6B7280; }

  /* ── Priority pill ── */
  .priority { padding: 3px 10px; border-radius: 20px; font-size: 0.68rem;
              font-weight: 700; color: white; white-space: nowrap; }
  .p5     { background: #DC2626; }
  .p4     { background: #EA580C; }
  .p3     { background: #D97706; }
  .p2     { background: #2563EB; }
  .p1     { background: #6B7280; }
  .p-none { background: #9CA3AF; }

  /* ── Finding sections ── */
  .section       { border-left: 3px solid; padding: 10px 0 10px 14px; margin-top: 14px; }
  .section-risk   { border-color: #DC2626; }
  .section-impact { border-color: #D97706; }
  .section-fix    { border-color: #16A34A; }
  .section-label  { font-size: 0.65rem; font-weight: 700; text-transform: uppercase;
                    letter-spacing: 1px; color: #64748B; margin-bottom: 5px; }
  .section-text   { font-size: 0.84rem; line-height: 1.65; color: #334155; }
  .empty-text     { color: #94A3B8; font-style: italic; }

  /* ── Compliance pills ── */
  .controls    { display: flex; flex-wrap: wrap; gap: 6px; margin-top: 14px;
                 padding-top: 12px; border-top: 1px solid #F8FAFC; }
  .control-pill { background: #EFF6FF; color: #1D4ED8; border: 1px solid #BFDBFE;
                  padding: 2px 8px; border-radius: 10px; font-size: 0.68rem;
                  font-weight: 600; font-family: 'Cascadia Code', 'Consolas', monospace; }

  /* ── Print ── */
  @media print {
    body { background: white; }
    .header { background: #0F172A !important; -webkit-print-color-adjust: exact; print-color-adjust: exact; }
    .card { break-inside: avoid; box-shadow: none; border: 1px solid #E2E8F0; margin-bottom: 12px; }
    .cards { grid-template-columns: 1fr; }
  }
</style>
</head>
<body>
<div class="header">
  <h1>AI Security Briefing &mdash; $([System.Web.HttpUtility]::HtmlEncode($TenantName))</h1>
  <p class="meta">Prepared by $([System.Web.HttpUtility]::HtmlEncode($CompanyName)) &nbsp;&bull;&nbsp; Generated $generatedDate</p>
  <div class="stats">
    <div class="stat-box"><div class="value">$countTotal</div><div class="label">Total Findings</div></div>
    <div class="stat-box"><div class="value">$countCritical</div><div class="label">Critical</div></div>
    <div class="stat-box"><div class="value">$countHigh</div><div class="label">High</div></div>
    <div class="stat-box"><div class="value">$countMedium</div><div class="label">Medium</div></div>
  </div>
</div>
<div class="main">
  <div class="section-heading">Security Findings &mdash; AI Explained</div>
  <div class="cards">
$cards
  </div>
</div>
</body>
</html>
"@

    $html | Set-Content -Path $OutputPath -Encoding UTF8 -Force
    Write-TiTCLog "Export-TiTCAIReport: written to '$OutputPath'" -Level Success -Component $script:COMPONENT
    return $OutputPath
}

# ============================================================================
# HELPERS
# ============================================================================

function Build-TiTCAIPrompt {
    [CmdletBinding()]
    param([object]$Finding)

    $affectedCount = if ($Finding.AffectedResources) { $Finding.AffectedResources.Count } else { 0 }

    return @"
You are a cybersecurity analyst writing for a non-technical business executive.
For the following security finding, provide a structured response with exactly these 4 sections:

1. RISK: What is the risk in plain English? (2-3 sentences, no jargon)
2. IMPACT: What could happen to the business if this is not fixed? (2-3 sentences)
3. PRIORITY: Rate 1-5 (5=fix immediately this week, 4=fix this month, 3=fix this quarter, 2=plan for next quarter, 1=nice to have). Respond with just the number.
4. FIX: What should we do to fix this? (non-technical, 2-3 bullet points starting with action verbs)

Finding Title: $($Finding.Title)
Severity: $($Finding.Severity)
Description: $($Finding.Description)
Affected Resources: $affectedCount items
Current Status: $($Finding.Status)

Format your response as:
RISK: [your text]
IMPACT: [your text]
PRIORITY: [1-5]
FIX:
• [action]
• [action]
"@
}

function Invoke-TiTCAIRequest {
    [CmdletBinding()]
    param(
        [string]$Provider,
        [string]$ApiKey,
        [string]$ApiEndpoint,
        [string]$Model,
        [string]$Prompt
    )

    $content = $null

    switch ($Provider) {
        'Claude' {
            $url = if ($ApiEndpoint) { $ApiEndpoint } else { $script:CLAUDE_API_URL }
            $body = @{
                model      = $Model
                max_tokens = 600
                messages   = @(@{ role = 'user'; content = $Prompt })
            } | ConvertTo-Json -Depth 5

            $response = Invoke-RestMethod -Uri $url `
                -Method POST `
                -Headers @{
                    'x-api-key'         = $ApiKey
                    'anthropic-version' = '2023-06-01'
                    'Content-Type'      = 'application/json'
                } `
                -Body $body

            $content = $response.content[0].text
        }

        'OpenAI' {
            $url = if ($ApiEndpoint) { $ApiEndpoint } else { $script:OPENAI_API_URL }
            $body = @{
                model    = $Model
                messages = @(@{ role = 'user'; content = $Prompt })
                max_tokens = 600
            } | ConvertTo-Json -Depth 5

            $response = Invoke-RestMethod -Uri $url `
                -Method POST `
                -Headers @{
                    'Authorization' = "Bearer $ApiKey"
                    'Content-Type'  = 'application/json'
                } `
                -Body $body

            $content = $response.choices[0].message.content
        }

        'Local' {
            # Placeholder for local model integration (e.g., Ollama)
            $content = @"
RISK: This security finding represents a potential vulnerability in the organisation's Microsoft 365 environment.
IMPACT: If not addressed, this could expose the organisation to security breaches or compliance violations.
PRIORITY: 3
FIX:
• Review the finding details and assess the risk to your organisation
• Follow the recommended remediation steps provided in the security report
• Schedule a review with your IT security team to implement the fix
"@
        }
    }

    return $content
}

function Parse-TiTCAIResponse {
    [CmdletBinding()]
    param([string]$ResponseText)

    $result = @{
        Risk     = ''
        Impact   = ''
        Priority = 3
        Fix      = ''
    }

    if (-not $ResponseText) { return $result }

    # Extract RISK section
    if ($ResponseText -match 'RISK:\s*(.*?)(?=IMPACT:|$)') {
        $result.Risk = $Matches[1].Trim()
    }

    # Extract IMPACT section
    if ($ResponseText -match 'IMPACT:\s*(.*?)(?=PRIORITY:|$)') {
        $result.Impact = $Matches[1].Trim()
    }

    # Extract PRIORITY (1-5)
    if ($ResponseText -match 'PRIORITY:\s*([1-5])') {
        $result.Priority = [int]$Matches[1]
    }

    # Extract FIX section
    if ($ResponseText -match 'FIX:\s*(.*?)$') {
        $result.Fix = $Matches[1].Trim()
    }

    return $result
}

# ============================================================================
# MODULE EXPORT
# ============================================================================

Export-ModuleMember -Function @('Invoke-TiTCAIExplainer', 'Import-TiTCAuditData', 'Export-TiTCAIReport')
