#Requires -Version 5.1
<#
.SYNOPSIS
    MSP Audit Pack — Product 2 Entry Point.

.DESCRIPTION
    White-label M365 security audit pack orchestrator for Managed Service Providers.
    Runs all configured collectors, generates evidence packs for selected compliance
    frameworks, and produces a branded HTML/PDF report.

    Output structure:
    MSP-AuditPack-<timestamp>/
    ├── report/                    # Branded HTML + PDF report
    ├── evidence/                  # Compliance evidence packs (per framework)
    ├── data/                      # Raw JSON + CSV exports
    ├── compliance/                # Per-framework compliance gap reports
    └── metadata.json              # Pack metadata

.EXAMPLE
    # Full audit pack with ISO 27001 evidence
    .\Invoke-MSPAuditPack.ps1 -TenantId "contoso.onmicrosoft.com" `
        -ClientId $cid -ClientSecret $secret `
        -MSPCompanyName "SecureIT Solutions" `
        -AuditPacks ISO27001, CyberInsurance, CISControls

.EXAMPLE
    # Full pack with all frameworks and AI explainer
    .\Invoke-MSPAuditPack.ps1 -TenantId $tid -ClientId $cid -ClientSecret $secret `
        -MSPCompanyName "MyMSP" -MSPLogoPath "C:\branding\logo.png" `
        -AuditPacks Full -IncludeAIExplainer

.EXAMPLE
    # Certificate-based MSP pack run
    .\Invoke-MSPAuditPack.ps1 -TenantId $tid -ClientId $cid -CertificateThumbprint $thumb `
        -MSPCompanyName "SecureIT Solutions"

.NOTES
    Product:    MSP Automation Packs
    Author:     TakeItToCloud
    Version:    1.0.0
#>

[CmdletBinding(DefaultParameterSetName = 'Interactive')]
param(
    # ── Connection ──────────────────────────────────────────────────
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$TenantId,

    # Application (client) ID. Required for app-secret auth and certificate auth.
    [Parameter(Mandatory, ParameterSetName = 'AppAuth')]
    [Parameter(Mandatory, ParameterSetName = 'CertAuth')]
    [ValidateNotNullOrEmpty()]
    [string]$ClientId,

    # Client secret for app-secret authentication.
    [Parameter(Mandatory, ParameterSetName = 'AppAuth')]
    [ValidateNotNullOrEmpty()]
    [string]$ClientSecret,

    # Certificate thumbprint from Cert:\CurrentUser\My or Cert:\LocalMachine\My.
    [Parameter(Mandatory, ParameterSetName = 'CertAuth')]
    [ValidateNotNullOrEmpty()]
    [string]$CertificateThumbprint,

    # ── MSP Branding ────────────────────────────────────────────────
    [Parameter(Mandatory)]
    [string]$MSPCompanyName,

    [string]$MSPLogoPath,

    [hashtable]$MSPColors,

    # ── Pack Selection ──────────────────────────────────────────────
    [ValidateSet('ISO27001', 'SOC2Lite', 'CyberInsurance', 'CISControls', 'InternalRisk', 'Full')]
    [string[]]$AuditPacks = @('Full'),

    # ── Scope ───────────────────────────────────────────────────────
    [ValidateSet('EntraID', 'Exchange', 'Intune', 'Defender', 'Licensing')]
    [string[]]$Domains,

    [string]$ConfigFile,

    # ── Output ──────────────────────────────────────────────────────
    [string]$OutputPath = (Join-Path $PWD "MSP-AuditPack-$(Get-Date -Format 'yyyyMMdd-HHmmss')"),

    [ValidateSet('HTML', 'PDF', 'Both')]
    [string]$ReportFormat = 'HTML',

    # ── Options ─────────────────────────────────────────────────────
    [switch]$IncludeAIExplainer,
    [string]$AIApiKey,
    [ValidateSet('Auto', 'Claude', 'OpenAI')]
    [string]$AIProvider = 'Auto',

    [ValidateSet('Debug', 'Info', 'Warning', 'Error')]
    [string]$LogLevel = 'Info'
)

# ============================================================================
# BOOTSTRAP
# ============================================================================

$ErrorActionPreference = 'Stop'
$scriptRoot = Split-Path $PSScriptRoot -Parent

$corePath       = Join-Path $scriptRoot 'src\Core\TiTC.Core.psm1'
$modelsPath     = Join-Path $scriptRoot 'src\Core\Models\TiTC.Models.psm1'
$entraPath      = Join-Path $scriptRoot 'src\Collectors\TiTC.Collector.EntraID.psm1'
$exchangePath   = Join-Path $scriptRoot 'src\Collectors\TiTC.Collector.Exchange.psm1'
$intunePath     = Join-Path $scriptRoot 'src\Collectors\TiTC.Collector.Intune.psm1'
$defenderPath   = Join-Path $scriptRoot 'src\Collectors\TiTC.Collector.Defender.psm1'
$licensingPath  = Join-Path $scriptRoot 'src\Collectors\TiTC.Collector.Licensing.psm1'
$riskPath       = Join-Path $scriptRoot 'src\Analyzers\TiTC.Analyzer.Risk.psm1'
$reportModPath  = Join-Path $scriptRoot 'src\Outputs\TiTC.Output.Report.psm1'
$evidenceModPath= Join-Path $scriptRoot 'src\Outputs\TiTC.Output.Evidence.psm1'
$aiModPath      = Join-Path $scriptRoot 'src\Outputs\TiTC.Output.AIExplainer.psm1'

Import-Module $modelsPath    -Force
Import-Module $corePath      -Force
Import-Module $entraPath     -Force
Import-Module $exchangePath  -Force
Import-Module $intunePath    -Force
Import-Module $defenderPath  -Force
Import-Module $licensingPath -Force
Import-Module $riskPath      -Force
Import-Module $reportModPath -Force
Import-Module $evidenceModPath -Force
Import-Module $aiModPath     -Force

function Format-TiTCSummaryCell {
    param(
        [AllowNull()]
        [string]$Value,
        [int]$Width
    )

    if ($null -eq $Value) { $Value = '' }
    if ($Value.Length -gt $Width) {
        if ($Width -le 3) { return $Value.Substring(0, $Width) }
        return $Value.Substring(0, $Width - 3) + '...'
    }

    return $Value.PadRight($Width)
}

# ============================================================================
# BANNER
# ============================================================================

Write-Host ""
Write-Host "  ╔══════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "  ║  AuditXpert — MSP Audit Pack v1.0.0                     ║" -ForegroundColor Cyan
Write-Host "  ║  TakeItToCloud                                           ║" -ForegroundColor Cyan
$bannerClient = Format-TiTCSummaryCell -Value $MSPCompanyName -Width 35
Write-Host "  ║  White-label client: $bannerClient║" -ForegroundColor Cyan
Write-Host "  ╚══════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

# ============================================================================
# PREREQUISITES
# ============================================================================

# App-based auth implies automation mode — install missing modules silently
$prereqParams = @{ CheckOnly = $false }
if ($ClientId) { $prereqParams.AutoInstall = $true }

$prereqResult = Test-TiTCPrerequisites @prereqParams
if (-not $prereqResult.AllRequiredMet) {
    Write-Host ''
    Write-Host '  ERROR: Required PowerShell module(s) are missing.' -ForegroundColor Red
    Write-Host '  Run .\Install-Prerequisites.ps1 to check and install.' -ForegroundColor Yellow
    exit 1
}

Invoke-TiTCLogRotation

# ============================================================================
# INITIALIZE
# ============================================================================

$logPath = Join-Path $OutputPath 'assessment.log'
Initialize-TiTCLogging -LogPath $logPath -LogLevel $LogLevel

Write-TiTCLog "MSP Audit Pack starting for: $MSPCompanyName | Tenant: $TenantId" -Level Info -Component 'MSPAuditPack'

New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
foreach ($subDir in @('report','evidence','data','compliance')) {
    New-Item -ItemType Directory -Path (Join-Path $OutputPath $subDir) -Force | Out-Null
}

# Resolve audit packs to frameworks
$frameworksToRun = if ($AuditPacks -contains 'Full') {
    @('ISO27001', 'CyberInsurance', 'SOC2Lite', 'CISControls', 'InternalRisk')
} else { $AuditPacks }

# Load config
$config = Get-TiTCConfig -ProfileName MSPAudit -ProfilePath $ConfigFile

if ($Domains) {
    $config.Domains.Keys | ForEach-Object { $config.Domains[$_] = $false }
    foreach ($d in $Domains) { $config.Domains[$d] = $true }
}
$config.ComplianceFrameworks = $frameworksToRun
$config.Output.BrandingCompanyName = $MSPCompanyName
$config.Output.IncludeEvidence = $true

# ============================================================================
# CONNECT
# ============================================================================

$connectParams = @{ TenantId = $TenantId }
switch ($PSCmdlet.ParameterSetName) {
    'AppAuth'  {
        if ([string]::IsNullOrWhiteSpace($ClientId) -or [string]::IsNullOrWhiteSpace($ClientSecret)) {
            throw "AppAuth requires TenantId, ClientId, and ClientSecret."
        }
        $connectParams.ClientId = $ClientId
        $connectParams.ClientSecret = $ClientSecret
    }
    'CertAuth' {
        if ([string]::IsNullOrWhiteSpace($ClientId) -or [string]::IsNullOrWhiteSpace($CertificateThumbprint)) {
            throw "CertAuth requires TenantId, ClientId, and CertificateThumbprint."
        }
        $connectParams.ClientId = $ClientId
        $connectParams.CertificateThumbprint = $CertificateThumbprint
    }
    default    { $connectParams.Interactive = $true }
}
$connectionResult = Connect-TiTCGraph @connectParams

# ============================================================================
# INITIALIZE REPORT
# ============================================================================

$report = New-TiTCAssessmentReport
$report.TenantId          = $connectionResult.TenantId
$report.TenantName        = $connectionResult.TenantName
$report.TenantDomain      = $connectionResult.Domain
$report.AssessmentProfile = 'MSPAudit'
$assessmentStart          = Get-Date

# ============================================================================
# RUN COLLECTORS
# ============================================================================

Write-TiTCLog "═══ Running collectors ═══" -Level Info -Component 'MSPAuditPack'

$collectorMap = @{
    EntraID   = { Invoke-TiTCEntraIDCollector  -Config $config }
    Exchange  = { Invoke-TiTCExchangeCollector  -Config $config }
    Intune    = { Invoke-TiTCIntuneCollector    -Config $config }
    Defender  = { Invoke-TiTCDefenderCollector  -Config $config }
    Licensing = { Invoke-TiTCLicensingCollector -Config $config }
}

foreach ($domain in $collectorMap.Keys) {
    if ($config.Domains[$domain]) {
        try {
            Write-TiTCLog "▶ $domain collector..." -Level Info -Component 'MSPAuditPack'
            $result = & $collectorMap[$domain]
            $report.CollectorResults += $result
            Write-TiTCLog "✓ ${domain}: $($result.FindingsCount) findings" -Level Success -Component 'MSPAuditPack'
            if ($domain -eq 'Licensing' -and $result.RawData['EstimatedMonthlyWaste']) {
                $report.EstimatedWaste = $result.RawData['EstimatedMonthlyWaste']
            }
        }
        catch {
            Write-TiTCLog "✗ $domain failed: $_" -Level Error -Component 'MSPAuditPack'
        }
    }
}

# ============================================================================
# ANALYZE
# ============================================================================

Write-TiTCLog "═══ Running risk analysis ═══" -Level Info -Component 'MSPAuditPack'

$report.AggregateFindings()
$report.TotalDurationSeconds = ((Get-Date) - $assessmentStart).TotalSeconds

$riskAnalysis = Invoke-TiTCRiskAnalysis `
    -CollectorResults $report.CollectorResults `
    -Config $config `
    -ComplianceFrameworks $frameworksToRun

$report.RiskScore       = $riskAnalysis.RiskScore
$report.CompliancePosture = $riskAnalysis.ComplianceGaps

$summary = $report.ToExecutiveSummary()
$summary['CategoryScores']           = $riskAnalysis.CategoryScores
$summary['RemediationPlan']          = $riskAnalysis.RemediationPlan | Select-Object -First 10
$summary['QuickWins']                = $riskAnalysis.QuickWins
$summary['ExecutiveNarrative']       = $riskAnalysis.ExecutiveNarrative
$summary['EstimatedRemediationHours']= $riskAnalysis.EstimatedEffortHours

# ============================================================================
# AI EXPLAINER (optional)
# ============================================================================

if ($IncludeAIExplainer) {
    try {
        Write-TiTCLog "Running AI Explainer..." -Level Info -Component 'MSPAuditPack'
        $aiExplainerParams = @{
            Findings         = $report.AllFindings
            Provider         = $AIProvider
            HighSeverityOnly = $true
            MaxFindings      = 20
        }
        if ($AIApiKey) {
            $aiExplainerParams.ApiKey = $AIApiKey
        }
        $enrichedFindings = Invoke-TiTCAIExplainer @aiExplainerParams
        Write-TiTCLog "AI explanations complete: $($enrichedFindings.Count) findings enriched" -Level Success -Component 'MSPAuditPack'
    }
    catch {
        Write-TiTCLog "AI Explainer failed: $_" -Level Warning -Component 'MSPAuditPack'
    }
}

# ============================================================================
# GENERATE OUTPUTS
# ============================================================================

Write-TiTCLog "═══ Generating outputs ═══" -Level Info -Component 'MSPAuditPack'

# Data exports
$report | ConvertTo-Json -Depth 15 | Set-Content -Path (Join-Path $OutputPath 'data\assessment-results.json') -Force
$report.AllFindings | Select-Object FindingId,Severity,Domain,Title,Description,Remediation,Status,RiskWeight,
    @{N='ComplianceControls';E={$_.ComplianceControls -join '; '}},
    @{N='AffectedCount';E={$_.AffectedResources.Count}} |
    Export-Csv -Path (Join-Path $OutputPath 'data\findings.csv') -NoTypeInformation -Force
$summary | ConvertTo-Json -Depth 10 | Set-Content -Path (Join-Path $OutputPath 'data\executive-summary.json') -Force
$riskAnalysis.RemediationPlan | Export-Csv -Path (Join-Path $OutputPath 'data\remediation-plan.csv') -NoTypeInformation -Force

# Compliance gap reports
foreach ($fw in $riskAnalysis.ComplianceGaps.Keys) {
    $riskAnalysis.ComplianceGaps[$fw] | ConvertTo-Json -Depth 10 |
        Set-Content -Path (Join-Path $OutputPath "compliance\compliance-$($fw.ToLower()).json") -Force
}

# Evidence packs
try {
    $evidencePackRoot = Export-TiTCEvidencePack `
        -Report $report `
        -OutputPath (Join-Path $OutputPath 'evidence') `
        -Frameworks $frameworksToRun `
        -CompanyName $MSPCompanyName
    Write-TiTCLog "Evidence packs: $evidencePackRoot" -Level Success -Component 'MSPAuditPack'
}
catch {
    Write-TiTCLog "Evidence pack generation failed: $_" -Level Error -Component 'MSPAuditPack'
}

# HTML/PDF report
$reportArtifacts = $null
try {
    $assessmentData = @{ Report = $report; RiskAnalysis = $riskAnalysis; ExecutiveSummary = $summary }
    $reportBase = Join-Path $OutputPath 'report\security-assessment-report'
    $reportArtifacts = Export-TiTCReport `
        -AssessmentData $assessmentData `
        -OutputPath $reportBase `
        -Format $ReportFormat `
        -CompanyName $MSPCompanyName `
        -LogoPath $MSPLogoPath `
        -BrandingColors $MSPColors `
        -ReportType 'MSPAuditPack' `
        -PreparedBy $MSPCompanyName `
        -PreparedFor $report.TenantName

    if ($ReportFormat -eq 'Both') {
        Write-TiTCLog "Report HTML: $($reportArtifacts.HtmlPath)" -Level Success -Component 'MSPAuditPack'
        Write-TiTCLog "Report PDF: $($reportArtifacts.PdfPath)" -Level Success -Component 'MSPAuditPack'
    }
    else {
        Write-TiTCLog "Report: $reportArtifacts" -Level Success -Component 'MSPAuditPack'
    }
}
catch {
    Write-TiTCLog "Report generation failed: $_" -Level Error -Component 'MSPAuditPack'
}

# Metadata
@{
    PackType         = 'MSPAuditPack'
    GeneratedAt      = (Get-Date -Format 'yyyy-MM-ddTHH:mm:ssZ')
    TenantId         = $report.TenantId
    TenantDomain     = $report.TenantDomain
    TenantName       = $report.TenantName
    GeneratedBy      = $MSPCompanyName
    AuditPacks       = $frameworksToRun
    ToolVersion      = '1.0.0'
    OverallScore     = $summary.OverallScore
    OverallRating    = $summary.OverallRating
    TotalFindings    = $summary.TotalFindings
    CriticalFindings = $summary.CriticalFindings
    HighFindings     = $summary.HighFindings
} | ConvertTo-Json | Set-Content -Path (Join-Path $OutputPath 'metadata.json') -Force

Export-TiTCLog -Path (Join-Path $OutputPath 'audit-trail.json')

# ============================================================================
# SUMMARY
# ============================================================================

Disconnect-TiTCGraph

$summaryReportValue = if ($ReportFormat -eq 'Both' -and $reportArtifacts) {
    'HTML + PDF'
} elseif ($reportArtifacts) {
    $ReportFormat
} else {
    'Not generated'
}
$summaryReportLine = ("  │  Report:     {0}" -f (Format-TiTCSummaryCell -Value $summaryReportValue -Width 55)) + "│"

$summaryHtmlLine = $null
$summaryPdfLine = $null
if ($ReportFormat -eq 'Both' -and $reportArtifacts) {
    $htmlArtifact = Split-Path $reportArtifacts.HtmlPath -Leaf
    $pdfArtifact = Split-Path $reportArtifacts.PdfPath -Leaf
    $summaryHtmlLine = ("  │  HTML File:  {0}" -f (Format-TiTCSummaryCell -Value $htmlArtifact -Width 55)) + "│"
    $summaryPdfLine = ("  │  PDF File:   {0}" -f (Format-TiTCSummaryCell -Value $pdfArtifact -Width 55)) + "│"
}

$summaryClient = Format-TiTCSummaryCell -Value $MSPCompanyName -Width 55
$summaryTenant = Format-TiTCSummaryCell -Value $report.TenantName -Width 55
$summaryScore = Format-TiTCSummaryCell -Value "$($summary.OverallScore)/100 ($($summary.OverallRating))" -Width 55
$summaryFindings = Format-TiTCSummaryCell -Value "$($summary.TotalFindings) total ($($summary.CriticalFindings) critical, $($summary.HighFindings) high)" -Width 55
$summaryFrameworks = Format-TiTCSummaryCell -Value ($frameworksToRun -join ', ') -Width 55
$summaryOutput = Format-TiTCSummaryCell -Value $OutputPath -Width 55
$summaryScoreColor = if ($summary.OverallScore -gt 60) {'Red'} elseif ($summary.OverallScore -gt 30) {'Yellow'} else {'Green'}

Write-Host ""
Write-Host "  ┌──────────────────────────────────────────────────────────────────┐" -ForegroundColor Green
Write-Host "  │  MSP AUDIT PACK COMPLETE                                         │" -ForegroundColor Green
Write-Host "  ├──────────────────────────────────────────────────────────────────┤" -ForegroundColor Green
Write-Host "  │  Client:     $summaryClient│" -ForegroundColor White
Write-Host "  │  Tenant:     $summaryTenant│" -ForegroundColor White
Write-Host "  │  Score:      $summaryScore│" -ForegroundColor $summaryScoreColor
Write-Host "  │  Findings:   $summaryFindings│" -ForegroundColor White
Write-Host "  │  Frameworks: $summaryFrameworks│" -ForegroundColor White
Write-Host $summaryReportLine -ForegroundColor White
if ($summaryHtmlLine) { Write-Host $summaryHtmlLine -ForegroundColor White }
if ($summaryPdfLine) { Write-Host $summaryPdfLine -ForegroundColor White }
Write-Host "  │  Output:     $summaryOutput│" -ForegroundColor White
Write-Host "  └──────────────────────────────────────────────────────────────────┘" -ForegroundColor Green
Write-Host ""

return $report
