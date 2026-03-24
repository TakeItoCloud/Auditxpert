#Requires -Version 5.1
<#
.SYNOPSIS
    M365 Risk & Compliance Snapshot — Product 1 Entry Point.

.DESCRIPTION
    Orchestrates a complete M365 security assessment by running all configured
    collectors, aggregating findings, calculating risk scores, and generating
    the deliverable report.

    This is the main command that customers or consultants run to produce
    a TakeItToCloud M365 Risk Snapshot.

.EXAMPLE
    # Interactive assessment with default settings
    .\Invoke-M365Snapshot.ps1 -TenantId "contoso.onmicrosoft.com"

.EXAMPLE
    # App-based assessment for MSP automation
    .\Invoke-M365Snapshot.ps1 -TenantId $tid -ClientId $cid -ClientSecret $secret -Profile MSPAudit

.EXAMPLE
    # Quick scan — identity and licensing only
    .\Invoke-M365Snapshot.ps1 -TenantId $tid -Profile Quick -Domains EntraID, Licensing

.NOTES
    Product:    M365 Risk & Compliance Snapshot
    Author:     TakeItToCloud
    Version:    1.0.0
#>

[CmdletBinding(DefaultParameterSetName = 'Interactive')]
param(
    # ── Connection ──────────────────────────────────────────────────
    [Parameter(Mandatory)]
    [string]$TenantId,

    [Parameter(ParameterSetName = 'AppAuth')]
    [string]$ClientId,

    [Parameter(ParameterSetName = 'AppAuth')]
    [string]$ClientSecret,

    [Parameter(ParameterSetName = 'CertAuth')]
    [string]$CertificateThumbprint,

    # ── Scope ───────────────────────────────────────────────────────
    [ValidateSet('Full', 'Quick', 'MSPAudit', 'LicenseOnly', 'ComplianceOnly')]
    [string]$Profile = 'Full',

    [ValidateSet('EntraID', 'Exchange', 'Intune', 'Defender', 'Licensing')]
    [string[]]$Domains,

    [string]$ConfigFile,

    # ── Output ──────────────────────────────────────────────────────
    [string]$OutputPath = (Join-Path $PWD "TiTC-Snapshot-$(Get-Date -Format 'yyyyMMdd-HHmmss')"),

    [ValidateSet('PDF', 'JSON', 'HTML', 'All')]
    [string]$OutputFormat = 'JSON',

    [string]$BrandingLogo,
    [string]$BrandingCompanyName,

    # ── Options ─────────────────────────────────────────────────────
    [switch]$IncludeEvidence,
    [switch]$IncludeAIExplainer,
    [switch]$SkipBanner,

    [ValidateSet('Debug', 'Info', 'Warning', 'Error')]
    [string]$LogLevel = 'Info'
)

# ============================================================================
# BOOTSTRAP
# ============================================================================

$ErrorActionPreference = 'Stop'
$scriptRoot = Split-Path $PSScriptRoot -Parent

# Import core modules
$corePath = Join-Path $scriptRoot 'src\Core\TiTC.Core.psm1'
$modelsPath = Join-Path $scriptRoot 'src\Core\Models\TiTC.Models.psm1'
$entraPath = Join-Path $scriptRoot 'src\Collectors\TiTC.Collector.EntraID.psm1'
$exchangePath = Join-Path $scriptRoot 'src\Collectors\TiTC.Collector.Exchange.psm1'
$intunePath = Join-Path $scriptRoot 'src\Collectors\TiTC.Collector.Intune.psm1'
$defenderPath = Join-Path $scriptRoot 'src\Collectors\TiTC.Collector.Defender.psm1'
$licensingPath = Join-Path $scriptRoot 'src\Collectors\TiTC.Collector.Licensing.psm1'
$riskAnalyzerPath = Join-Path $scriptRoot 'src\Analyzers\TiTC.Analyzer.Risk.psm1'
$reportPath = Join-Path $scriptRoot 'src\Outputs\TiTC.Output.Report.psm1'
$evidencePath = Join-Path $scriptRoot 'src\Outputs\TiTC.Output.Evidence.psm1'
$aiExplainerPath = Join-Path $scriptRoot 'src\Outputs\TiTC.Output.AIExplainer.psm1'

Import-Module $modelsPath -Force
Import-Module $corePath -Force
Import-Module $entraPath -Force
Import-Module $exchangePath -Force
Import-Module $intunePath -Force
Import-Module $defenderPath -Force
Import-Module $licensingPath -Force
Import-Module $riskAnalyzerPath -Force
Import-Module $reportPath -Force
Import-Module $evidencePath -Force
Import-Module $aiExplainerPath -Force

# ============================================================================
# BANNER
# ============================================================================

if (-not $SkipBanner) {
    $banner = @"

  ╔══════════════════════════════════════════════════════════════╗
  ║                                                              ║
  ║   ████████╗ █████╗ ██╗  ██╗███████╗██╗████████╗             ║
  ║   ╚══██╔══╝██╔══██╗██║ ██╔╝██╔════╝██║╚══██╔══╝             ║
  ║      ██║   ███████║█████╔╝ █████╗  ██║   ██║                ║
  ║      ██║   ██╔══██║██╔═██╗ ██╔══╝  ██║   ██║                ║
  ║      ██║   ██║  ██║██║  ██╗███████╗██║   ██║                ║
  ║      ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝   ╚═╝                ║
  ║                  TO CLOUD                                    ║
  ║                                                              ║
  ║   M365 Risk & Compliance Snapshot v1.0.0                     ║
  ║   Enterprise Security Assessment Platform                    ║
  ║                                                              ║
  ╚══════════════════════════════════════════════════════════════╝

"@
    Write-Host $banner -ForegroundColor Cyan
}

# ============================================================================
# PREREQUISITES
# ============================================================================

$prereqParams = @{ CheckOnly = $false }
if ($SkipBanner) { $prereqParams.AutoInstall = $true }   # SkipBanner implies automation — install silently

$prereqResult = Test-TiTCPrerequisites @prereqParams
if (-not $prereqResult.AllRequiredMet) {
    Write-Host ''
    Write-Host '  ERROR: Required PowerShell module(s) are missing.' -ForegroundColor Red
    Write-Host '  Run .\Install-Prerequisites.ps1 to check and install.' -ForegroundColor Yellow
    exit 1
}

# Run log rotation at the start of each assessment
Invoke-TiTCLogRotation

# ============================================================================
# INITIALIZE
# ============================================================================

# Setup logging
$logPath = Join-Path $OutputPath 'assessment.log'
Initialize-TiTCLogging -LogPath $logPath -LogLevel $LogLevel

Write-TiTCLog "═══ M365 Risk & Compliance Snapshot starting ═══" -Level Info -Component 'Snapshot'
Write-TiTCLog "Profile: $Profile | Output: $OutputPath" -Level Info -Component 'Snapshot'

# Create output directory
if (-not (Test-Path $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
}

# Load configuration
$configOverrides = @{}
if ($BrandingCompanyName) { $configOverrides['Output'] = @{ BrandingCompanyName = $BrandingCompanyName } }
if ($IncludeEvidence) { $configOverrides['Output'] = @{ IncludeEvidence = $true } }

$config = Get-TiTCConfig -ProfileName $Profile -ProfilePath $ConfigFile -Overrides $configOverrides

# Override domains if specified
if ($Domains) {
    $config.Domains.Keys | ForEach-Object { $config.Domains[$_] = $false }
    foreach ($d in $Domains) { $config.Domains[$d] = $true }
}

# ============================================================================
# CONNECT
# ============================================================================

$connectParams = @{ TenantId = $TenantId }

switch ($PSCmdlet.ParameterSetName) {
    'AppAuth' {
        $connectParams.ClientId = $ClientId
        $connectParams.ClientSecret = $ClientSecret
    }
    'CertAuth' {
        $connectParams.ClientId = $ClientId
        $connectParams.CertificateThumbprint = $CertificateThumbprint
    }
    'Interactive' {
        $connectParams.Interactive = $true
    }
}

$connectionResult = Connect-TiTCGraph @connectParams

# ============================================================================
# INITIALIZE REPORT
# ============================================================================

$report = New-TiTCAssessmentReport
$report.TenantId = $connectionResult.TenantId
$report.TenantName = $connectionResult.TenantName
$report.TenantDomain = $connectionResult.Domain
$report.AssessmentProfile = $Profile

$assessmentStart = Get-Date

# ============================================================================
# RUN COLLECTORS
# ============================================================================

Write-TiTCLog "═══ Running security collectors ═══" -Level Info -Component 'Snapshot'

# ── Entra ID ────────────────────────────────────────────────────────
if ($config.Domains.EntraID) {
    try {
        Write-TiTCLog "▶ Starting Entra ID collector..." -Level Info -Component 'Snapshot'
        $entraResult = Invoke-TiTCEntraIDCollector -Config $config
        $report.CollectorResults += $entraResult
        Write-TiTCLog "✓ Entra ID: $($entraResult.FindingsCount) findings ($($entraResult.DurationSeconds)s)" -Level Success -Component 'Snapshot'
    }
    catch {
        Write-TiTCLog "✗ Entra ID collector failed: $_" -Level Error -Component 'Snapshot'
    }
}

# ── Exchange (placeholder for next build) ───────────────────────────
if ($config.Domains.Exchange) {
    try {
        Write-TiTCLog "▶ Starting Exchange Online collector..." -Level Info -Component 'Snapshot'
        $exchangeResult = Invoke-TiTCExchangeCollector -Config $config
        $report.CollectorResults += $exchangeResult
        Write-TiTCLog "✓ Exchange: $($exchangeResult.FindingsCount) findings ($($exchangeResult.DurationSeconds)s)" -Level Success -Component 'Snapshot'
    }
    catch {
        Write-TiTCLog "✗ Exchange collector failed: $_" -Level Error -Component 'Snapshot'
    }
}

# ── Intune ─────────────────────────────────────────────────────────
if ($config.Domains.Intune) {
    try {
        Write-TiTCLog "▶ Starting Intune endpoint security collector..." -Level Info -Component 'Snapshot'
        $intuneResult = Invoke-TiTCIntuneCollector -Config $config
        $report.CollectorResults += $intuneResult
        Write-TiTCLog "✓ Intune: $($intuneResult.FindingsCount) findings ($($intuneResult.DurationSeconds)s)" -Level Success -Component 'Snapshot'
    }
    catch {
        Write-TiTCLog "✗ Intune collector failed: $_" -Level Error -Component 'Snapshot'
    }
}

# ── Defender ───────────────────────────────────────────────────────
if ($config.Domains.Defender) {
    try {
        Write-TiTCLog "▶ Starting Defender security collector..." -Level Info -Component 'Snapshot'
        $defenderResult = Invoke-TiTCDefenderCollector -Config $config
        $report.CollectorResults += $defenderResult
        Write-TiTCLog "✓ Defender: $($defenderResult.FindingsCount) findings ($($defenderResult.DurationSeconds)s)" -Level Success -Component 'Snapshot'
    }
    catch {
        Write-TiTCLog "✗ Defender collector failed: $_" -Level Error -Component 'Snapshot'
    }
}

# ── Licensing ──────────────────────────────────────────────────────
if ($config.Domains.Licensing) {
    try {
        Write-TiTCLog "▶ Starting Licensing & Cost Waste collector..." -Level Info -Component 'Snapshot'
        $licensingResult = Invoke-TiTCLicensingCollector -Config $config
        $report.CollectorResults += $licensingResult
        Write-TiTCLog "✓ Licensing: $($licensingResult.FindingsCount) findings ($($licensingResult.DurationSeconds)s)" -Level Success -Component 'Snapshot'

        # Propagate estimated waste to report
        if ($licensingResult.RawData['EstimatedMonthlyWaste']) {
            $report.EstimatedWaste = $licensingResult.RawData['EstimatedMonthlyWaste']
        }
    }
    catch {
        Write-TiTCLog "✗ Licensing collector failed: $_" -Level Error -Component 'Snapshot'
    }
}

# ============================================================================
# AGGREGATE & SCORE (Layer 2 — Risk Analysis Engine)
# ============================================================================

Write-TiTCLog "═══ Running risk analysis engine ═══" -Level Info -Component 'Snapshot'

$report.AggregateFindings()
$report.TotalDurationSeconds = ((Get-Date) - $assessmentStart).TotalSeconds

# Run full risk analysis
$riskAnalysis = Invoke-TiTCRiskAnalysis `
    -CollectorResults $report.CollectorResults `
    -Config $config `
    -ComplianceFrameworks $config.ComplianceFrameworks

# Update report with analysis results
$report.RiskScore = $riskAnalysis.RiskScore
$report.CompliancePosture = $riskAnalysis.ComplianceGaps

$summary = $report.ToExecutiveSummary()
$summary['CategoryScores'] = $riskAnalysis.CategoryScores
$summary['RemediationPlan'] = $riskAnalysis.RemediationPlan | Select-Object -First 10
$summary['QuickWins'] = $riskAnalysis.QuickWins
$summary['ExecutiveNarrative'] = $riskAnalysis.ExecutiveNarrative
$summary['EstimatedRemediationHours'] = $riskAnalysis.EstimatedEffortHours

Write-TiTCLog "Assessment complete" -Level Success -Component 'Snapshot' -Data @{
    OverallScore     = "$($summary.OverallScore)/100"
    OverallRating    = $summary.OverallRating
    TotalFindings    = $summary.TotalFindings
    CriticalFindings = $summary.CriticalFindings
    HighFindings     = $summary.HighFindings
    Duration         = "$([Math]::Round($report.TotalDurationSeconds, 1))s"
}

# ============================================================================
# GENERATE OUTPUT
# ============================================================================

Write-TiTCLog "═══ Generating outputs ═══" -Level Info -Component 'Snapshot'

# Always export JSON (machine-readable, used by AI explainer)
$jsonPath = Join-Path $OutputPath 'assessment-results.json'
$report | ConvertTo-Json -Depth 15 | Set-Content -Path $jsonPath -Force
Write-TiTCLog "JSON output: $jsonPath" -Level Info -Component 'Snapshot'

# Export findings CSV for quick review
$csvPath = Join-Path $OutputPath 'findings.csv'
$report.AllFindings | Select-Object `
    FindingId, Severity, Domain, Title, Description, `
    Remediation, Status, RiskWeight, DetectedBy, `
    @{N='ComplianceControls';E={$_.ComplianceControls -join '; '}}, `
    @{N='AffectedCount';E={$_.AffectedResources.Count}} |
    Export-Csv -Path $csvPath -NoTypeInformation -Force
Write-TiTCLog "CSV findings: $csvPath" -Level Info -Component 'Snapshot'

# Export executive summary
$summaryPath = Join-Path $OutputPath 'executive-summary.json'
$summary | ConvertTo-Json -Depth 10 | Set-Content -Path $summaryPath -Force
Write-TiTCLog "Executive summary: $summaryPath" -Level Info -Component 'Snapshot'

# Export risk analysis (complete Layer 2 output)
$analysisPath = Join-Path $OutputPath 'risk-analysis.json'
$riskAnalysis | ConvertTo-Json -Depth 15 | Set-Content -Path $analysisPath -Force
Write-TiTCLog "Risk analysis: $analysisPath" -Level Info -Component 'Snapshot'

# Export remediation plan CSV
$remPlanPath = Join-Path $OutputPath 'remediation-plan.csv'
$riskAnalysis.RemediationPlan | Export-Csv -Path $remPlanPath -NoTypeInformation -Force
Write-TiTCLog "Remediation plan: $remPlanPath" -Level Info -Component 'Snapshot'

# Export compliance gap reports
foreach ($fw in $riskAnalysis.ComplianceGaps.Keys) {
    $fwPath = Join-Path $OutputPath "compliance-$($fw.ToLower()).json"
    $riskAnalysis.ComplianceGaps[$fw] | ConvertTo-Json -Depth 10 | Set-Content -Path $fwPath -Force
    Write-TiTCLog "Compliance report ($fw): $fwPath" -Level Info -Component 'Snapshot'
}

# Generate HTML/PDF report (Layer 3)
if ($OutputFormat -in @('HTML', 'PDF', 'All')) {
    try {
        $assessmentData = @{
            Report            = $report
            RiskAnalysis      = $riskAnalysis
            ExecutiveSummary  = $summary
        }
        $reportFormat = if ($OutputFormat -eq 'All') { 'PDF' } else { $OutputFormat }
        $reportBasePath = Join-Path $OutputPath 'report\security-assessment-report'
        New-Item -ItemType Directory -Path (Join-Path $OutputPath 'report') -Force | Out-Null

        $reportFile = Export-TiTCReport `
            -AssessmentData $assessmentData `
            -OutputPath $reportBasePath `
            -Format $reportFormat `
            -CompanyName (if ($config.Output.BrandingCompanyName) { $config.Output.BrandingCompanyName } else { 'TakeItToCloud' }) `
            -LogoPath $BrandingLogo

        Write-TiTCLog "Report generated: $reportFile" -Level Success -Component 'Snapshot'
    }
    catch {
        Write-TiTCLog "Report generation failed: $_" -Level Error -Component 'Snapshot'
    }
}

# Export evidence packs if requested
if ($config.Output.IncludeEvidence) {
    try {
        $evidencePackPath = Export-TiTCEvidencePack `
            -Report $report `
            -OutputPath $OutputPath `
            -Frameworks @('All')
        Write-TiTCLog "Evidence packs exported to: $evidencePackPath" -Level Success -Component 'Snapshot'
    }
    catch {
        Write-TiTCLog "Evidence pack generation failed: $_" -Level Error -Component 'Snapshot'
    }
}

# Run AI Explainer if requested
if ($IncludeAIExplainer) {
    try {
        Write-TiTCLog "Running AI Explainer on findings..." -Level Info -Component 'Snapshot'
        $enrichedFindings = Invoke-TiTCAIExplainer `
            -Findings $report.AllFindings `
            -Provider 'Claude' `
            -HighSeverityOnly `
            -MaxFindings 20

        # Save enriched findings
        $enrichedPath = Join-Path $OutputPath 'findings-ai-enriched.json'
        $enrichedFindings | ConvertTo-Json -Depth 10 | Set-Content -Path $enrichedPath -Force
        Write-TiTCLog "AI-enriched findings: $enrichedPath" -Level Success -Component 'Snapshot'
    }
    catch {
        Write-TiTCLog "AI Explainer failed: $_" -Level Warning -Component 'Snapshot'
    }
}

# Export log
Export-TiTCLog -Path (Join-Path $OutputPath 'audit-trail.json')

# ============================================================================
# FINAL OUTPUT
# ============================================================================

Write-Host ""
Write-Host "  ┌─────────────────────────────────────────────────────────┐" -ForegroundColor Green
Write-Host "  │           ASSESSMENT COMPLETE                           │" -ForegroundColor Green
Write-Host "  ├─────────────────────────────────────────────────────────┤" -ForegroundColor Green
Write-Host "  │  Tenant:    $($report.TenantName.PadRight(42))│" -ForegroundColor White
Write-Host "  │  Score:     $("$($summary.OverallScore)/100 ($($summary.OverallRating))".PadRight(42))│" -ForegroundColor $(if ($summary.OverallScore -gt 60) { 'Red' } elseif ($summary.OverallScore -gt 30) { 'Yellow' } else { 'Green' })
Write-Host "  │  Findings:  $("$($summary.TotalFindings) total ($($summary.CriticalFindings) critical, $($summary.HighFindings) high)".PadRight(42))│" -ForegroundColor White
Write-Host "  │  Duration:  $("$([Math]::Round($report.TotalDurationSeconds, 1)) seconds".PadRight(42))│" -ForegroundColor White
Write-Host "  │  Output:    $($OutputPath.PadRight(42))│" -ForegroundColor White
Write-Host "  └─────────────────────────────────────────────────────────┘" -ForegroundColor Green
Write-Host ""

# ============================================================================
# CLEANUP
# ============================================================================

Disconnect-TiTCGraph

# Return report object for pipeline use
return $report
