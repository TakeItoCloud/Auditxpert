#Requires -Version 5.1
<#
.SYNOPSIS
    TakeItToCloud.Assess — HTML/PDF Report Generator.

.DESCRIPTION
    Generates a professional HTML security assessment report from the
    TiTCAssessmentReport and risk analysis data. Supports optional PDF
    conversion via wkhtmltopdf.

    Report sections:
    - Cover page with risk score badge
    - Executive summary narrative
    - Risk score dashboard (overall + category + domain)
    - Severity distribution chart
    - Top 10 critical findings
    - Full findings detail (grouped by domain)
    - Remediation plan checklist
    - Quick wins section
    - Compliance posture summary
    - License waste summary
    - Methodology appendix

.NOTES
    Module:     TiTC.Output.Report
    Author:     TakeItToCloud
    Version:    1.0.0
#>

# ============================================================================
# MODULE DEPENDENCIES
# ============================================================================

$CorePath = Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) 'src\Core\TiTC.Core.psm1'
if (Test-Path $CorePath) {
    Import-Module $CorePath -ErrorAction SilentlyContinue
}

# ============================================================================
# CONSTANTS
# ============================================================================

$script:COMPONENT   = 'Output.Report'
$script:TOOL_VERSION = '1.0.0'

$script:SEVERITY_COLORS = @{
    Critical = '#DC2626'
    High     = '#EA580C'
    Medium   = '#D97706'
    Low      = '#2563EB'
    Info     = '#6B7280'
}

$script:RATING_COLORS = @{
    'A+' = '#10B981'; 'A' = '#10B981'
    'B+' = '#84CC16'; 'B' = '#84CC16'
    'C+' = '#F59E0B'; 'C' = '#F59E0B'
    'D'  = '#EF4444'; 'D-'= '#EF4444'
    'F'  = '#DC2626'
}

# ============================================================================
# MAIN EXPORT FUNCTION
# ============================================================================

function Export-TiTCReport {
    <#
    .SYNOPSIS
        Generates an HTML (or PDF) security assessment report.

    .PARAMETER AssessmentData
        Hashtable containing Report, RiskAnalysis, and ExecutiveSummary from the orchestrator.

    .PARAMETER OutputPath
        Full file path (without extension) for the output file.

    .PARAMETER Format
        'HTML' generates a .html file. 'PDF' attempts wkhtmltopdf conversion.
        'Both' generates both artifacts and returns both paths.

    .PARAMETER LogoPath
        Optional path to a logo image file for white-label branding.

    .PARAMETER CompanyName
        Company name displayed in the report header.

    .PARAMETER BrandingColors
        Hashtable to override default branding colors.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$AssessmentData,

        [string]$OutputPath,

        [ValidateSet('HTML', 'PDF', 'Both')]
        [string]$Format = 'HTML',

        [string]$LogoPath,
        [string]$CompanyName = 'TakeItToCloud',
        [string]$PreparedBy,
        [string]$PreparedFor,
        [ValidateSet('Snapshot', 'MSPAuditPack')]
        [string]$ReportType = 'Snapshot',
        [hashtable]$BrandingColors
    )

    $colors = @{
        primary = '#0F172A'
        accent  = '#10B981'
        warning = '#F59E0B'
        danger  = '#EF4444'
    }
    if ($BrandingColors) { foreach ($k in $BrandingColors.Keys) { $colors[$k] = $BrandingColors[$k] } }

    if (-not $OutputPath) {
        $OutputPath = Join-Path $PWD "TiTC-Report-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
    }

    $resolvedPreparedBy = if ($PreparedBy) { $PreparedBy } else { $CompanyName }

    $htmlPath = "$OutputPath.html"

    Write-TiTCLog "Generating HTML report ($ReportType): $htmlPath" -Level Info -Component $script:COMPONENT

    $html = Build-TiTCReportHTML -AssessmentData $AssessmentData -Colors $colors `
                                  -CompanyName $CompanyName -LogoPath $LogoPath `
                                  -PreparedBy $resolvedPreparedBy -PreparedFor $PreparedFor `
                                  -ReportType $ReportType

    $html | Set-Content -Path $htmlPath -Encoding UTF8 -Force
    Write-TiTCLog "HTML report saved: $htmlPath" -Level Success -Component $script:COMPONENT

    if ($Format -in @('PDF', 'Both')) {
        $pdfPath = "$OutputPath.pdf"
        $wk = Get-Command wkhtmltopdf -ErrorAction SilentlyContinue
        if ($wk) {
            Write-TiTCLog "Converting to PDF via wkhtmltopdf..." -Level Info -Component $script:COMPONENT
            & wkhtmltopdf --enable-local-file-access --page-size A4 `
                --margin-top 15 --margin-bottom 15 --margin-left 12 --margin-right 12 `
                --footer-center "Confidential — $CompanyName | Page [page] of [topage]" `
                --footer-font-size 8 `
                $htmlPath $pdfPath 2>$null
            if (Test-Path $pdfPath) {
                Write-TiTCLog "PDF report saved: $pdfPath" -Level Success -Component $script:COMPONENT
                if ($Format -eq 'Both') {
                    return [PSCustomObject]@{
                        HtmlPath = $htmlPath
                        PdfPath  = $pdfPath
                    }
                }
                return $pdfPath
            }
        }
        else {
            if ($Format -eq 'Both') {
                throw "Report format 'Both' requires wkhtmltopdf to generate the PDF artifact."
            }
            Write-TiTCLog "wkhtmltopdf not found. HTML report generated — open in browser and print to PDF." -Level Warning -Component $script:COMPONENT
        }
    }

    return $htmlPath
}

# ============================================================================
# HTML BUILDER
# ============================================================================

function Build-TiTCReportHTML {
    [CmdletBinding()]
    param(
        [hashtable]$AssessmentData,
        [hashtable]$Colors,
        [string]$CompanyName,
        [string]$LogoPath,
        [string]$PreparedBy,
        [string]$PreparedFor,
        [string]$ReportType = 'Snapshot'
    )

    $report    = $AssessmentData.Report
    $riskData  = $AssessmentData.RiskAnalysis
    $summary   = $AssessmentData.ExecutiveSummary

    $tenantName   = $report.TenantName
    if (-not $tenantName -or $tenantName -eq $report.TenantId) {
        $tenantName = if ($report.TenantDomain) { $report.TenantDomain } else { $report.TenantId }
    }
    $assessDate   = if ($report.AssessmentDate) { ([datetime]$report.AssessmentDate).ToString('dd MMMM yyyy') } else { Get-Date -Format 'dd MMMM yyyy' }
    $overallScore = if ($summary.OverallScore) { $summary.OverallScore } else { 0 }
    $rating       = if ($summary.OverallRating) { $summary.OverallRating } else { 'N/A' }
    $ratingColor  = if ($script:RATING_COLORS[$rating]) { $script:RATING_COLORS[$rating] } else { '#6B7280' }

    $allFindings  = if ($report.AllFindings) { @($report.AllFindings) } else { @() }

    # Severity counts
    $critCount = ($allFindings | Where-Object { $_.Severity -eq 'Critical' }).Count
    $highCount = ($allFindings | Where-Object { $_.Severity -eq 'High' }).Count
    $medCount  = ($allFindings | Where-Object { $_.Severity -eq 'Medium' }).Count
    $lowCount  = ($allFindings | Where-Object { $_.Severity -eq 'Low' }).Count
    $infoCount = ($allFindings | Where-Object { $_.Severity -eq 'Info' }).Count
    $totalFindings = $allFindings.Count

    # Top 10 findings by priority
    $top10 = $allFindings | Sort-Object { @('Critical','High','Medium','Low','Info').IndexOf($_.Severity) } |
        Select-Object -First 10

    # Findings grouped by domain
    $findingsByDomain = $allFindings | Group-Object Domain

    # Remediation plan
    $remPlan = if ($riskData.RemediationPlan) { @($riskData.RemediationPlan) } else { @() }
    $quickWins = if ($riskData.QuickWins) { @($riskData.QuickWins) } else { @() }

    # Category scores
    $catScores = if ($summary.CategoryScores) { $summary.CategoryScores } else { @{} }

    # Compliance gaps
    $compGaps = if ($riskData.ComplianceGaps) { $riskData.ComplianceGaps } else { @{} }

    # License waste
    $licenseWaste = $summary.LicenseWaste

    # Severity color + name maps — handles both enum name ('Critical') and int ('4') forms
    # TiTCSeverity enum: Info=0, Low=1, Medium=2, High=3, Critical=4
    $sevColorMap = @{
        'Critical' = '#DC2626'; '4' = '#DC2626'
        'High'     = '#EA580C'; '3' = '#EA580C'
        'Medium'   = '#D97706'; '2' = '#D97706'
        'Low'      = '#2563EB'; '1' = '#2563EB'
        'Info'     = '#6B7280'; '0' = '#6B7280'
    }
    $sevNameMap = @{ '0' = 'Info'; '1' = 'Low'; '2' = 'Medium'; '3' = 'High'; '4' = 'Critical' }

    # Logo tag
    $logoTag = if ($LogoPath -and (Test-Path $LogoPath)) {
        $ext = [System.IO.Path]::GetExtension($LogoPath).TrimStart('.')
        $b64 = [Convert]::ToBase64String([System.IO.File]::ReadAllBytes($LogoPath))
        "<img src='data:image/$ext;base64,$b64' alt='$CompanyName' style='height:40px;'>"
    } else {
        "<span style='font-size:1.4rem;font-weight:800;color:$($Colors.accent);'>$CompanyName</span>"
    }

    # Executive narrative — may be an OrderedDictionary or plain string
    $narrativeSrc = $riskData.ExecutiveNarrative
    $narrative = if (-not $narrativeSrc) {
        "<p>Assessment complete. Review findings below for details.</p>"
    } elseif ($narrativeSrc -is [System.Collections.IDictionary]) {
        $parts = [System.Collections.ArrayList]::new()
        if ($narrativeSrc['OverallAssessment']) {
            $null = $parts.Add("<p style='margin-bottom:12px;'>$($narrativeSrc['OverallAssessment'])</p>")
        }
        if ($narrativeSrc['HighestRiskArea']) {
            $null = $parts.Add("<p style='margin-bottom:12px;'><strong>Highest Risk Area:</strong> $($narrativeSrc['HighestRiskArea'])</p>")
        }
        if ($narrativeSrc['ImmediateActions']) {
            $null = $parts.Add("<p style='margin-bottom:12px;'><strong>Immediate Actions:</strong> $($narrativeSrc['ImmediateActions'])</p>")
        }
        if ($narrativeSrc['ComplianceStatus']) {
            $null = $parts.Add("<p style='margin-bottom:12px;'><strong>Compliance Status:</strong> $($narrativeSrc['ComplianceStatus'])</p>")
        }
        if ($parts.Count -gt 0) { $parts -join "`n" } else { "<p>Assessment complete. Review findings below for details.</p>" }
    } else {
        ($narrativeSrc -split "`n" | Where-Object { $_.Trim() } |
            ForEach-Object { "<p>$($_.Trim())</p>" }) -join "`n"
    }

    # Score gauge SVG (circular)
    $gaugeColor = if ($overallScore -le 20) { '#10B981' }
                  elseif ($overallScore -le 40) { '#84CC16' }
                  elseif ($overallScore -le 60) { '#F59E0B' }
                  else { '#EF4444' }

    $dashOffset = [Math]::Round(283 - (283 * ($overallScore / 100)), 1)

    # Domain score cards HTML
    $domainCards = ''
    if ($report.CollectorResults) {
        foreach ($cr in $report.CollectorResults) {
            $domainKey = [string]$cr.Domain
            $domScoreEntry = if ($riskData.RiskScore -and $riskData.RiskScore.DomainScores -and
                                 $riskData.RiskScore.DomainScores[$domainKey]) {
                $riskData.RiskScore.DomainScores[$domainKey]
            } else { $null }
            $domScoreNum     = if ($domScoreEntry) { [double]$domScoreEntry.Score } else { $null }
            $domScoreDisplay = if ($null -ne $domScoreNum) { "$domScoreNum ($($domScoreEntry.Rating))" } else { 'N/A' }
            $findCount  = $cr.FindingsCount
            $checkResults = if ($cr.Metadata -and $cr.Metadata['CheckResults']) { @($cr.Metadata['CheckResults'].Values) } else { @() }
            $permSkipped = @($checkResults | Where-Object { $_.Status -eq 'SkippedInsufficientPermissions' }).Count
            $modeSkipped = @($checkResults | Where-Object { $_.Status -eq 'SkippedUnsupportedMode' }).Count
            $featureSkipped = @($checkResults | Where-Object { $_.Status -eq 'SkippedFeatureUnavailable' }).Count
            $failedChecks = @($checkResults | Where-Object { $_.Status -eq 'Failed' }).Count
            $cardColor  = if ($null -ne $domScoreNum -and $domScoreNum -gt 60) { $Colors.danger }
                          elseif ($null -ne $domScoreNum -and $domScoreNum -gt 30) { $Colors.warning }
                          else { $Colors.accent }
            $domainMeta = "$findCount findings"
            if ($checkResults.Count -gt 0) {
                $domainMeta = "$domainMeta | $($cr.Status)"
                if (($permSkipped + $modeSkipped + $featureSkipped + $failedChecks) -gt 0) {
                    $domainMeta += " | $permSkipped permission-skip, $modeSkipped mode-skip, $featureSkipped feature-skip, $failedChecks failed"
                }
            }
            $domainCards += @"
<div class="domain-card">
  <div class="domain-name">$($cr.Domain)</div>
  <div class="domain-score" style="color:$cardColor">$domScoreDisplay</div>
  <div class="domain-meta">$domainMeta</div>
</div>
"@
        }
    }

    # Category bars HTML
    $categoryBars = ''
    $catOrder = @('Identity & Access','Data Protection','Threat Detection','Device & Endpoint','Governance & Config')
    foreach ($cat in $catOrder) {
        $rawCat = if ($catScores[$cat]) { $catScores[$cat] } else { 0 }
        # CategoryScores values may be [ordered]@{Score=...; Rating=...} dicts
        $score = if ($rawCat -is [System.Collections.IDictionary]) {
            if ($null -ne $rawCat['Score']) { [double]$rawCat['Score'] } else { 0 }
        } else {
            [double]$rawCat
        }
        $barColor = if ($score -gt 60) { $Colors.danger } elseif ($score -gt 30) { $Colors.warning } else { $Colors.accent }
        $categoryBars += @"
<div class="cat-row">
  <div class="cat-label">$cat</div>
  <div class="cat-bar-wrap">
    <div class="cat-bar" style="width:$score%;background:$barColor;"></div>
  </div>
  <div class="cat-score">$score</div>
</div>
"@
    }

    # Top 10 findings table rows
    $top10Rows = ''
    $priority = 1
    foreach ($f in $top10) {
        $sevKey   = [string]$f.Severity
        $sevColor = if ($sevColorMap[$sevKey]) { $sevColorMap[$sevKey] } else { '#6B7280' }
        $sevName  = if ($sevNameMap[$sevKey]) { $sevNameMap[$sevKey] } else { $sevKey }
        $affCount = if ($f.AffectedResources) { $f.AffectedResources.Count } else { 0 }
        $top10Rows += @"
<tr>
  <td>$priority</td>
  <td><span class="badge" style="background:$sevColor">$sevName</span></td>
  <td>$($f.Domain)</td>
  <td>$($f.Title)</td>
  <td>$affCount</td>
</tr>
"@
        $priority++
    }

    # Full findings detail HTML
    $findingsDetail = ''
    foreach ($group in ($findingsByDomain | Sort-Object Name)) {
        $findingsDetail += "<div class='domain-section'><h3 class='domain-header'>$($group.Name)</h3>"
        $sortedF = $group.Group | Sort-Object { @('Critical','High','Medium','Low','Info').IndexOf($_.Severity) }
        foreach ($f in $sortedF) {
            $sevKey   = [string]$f.Severity
            $sevColor = if ($sevColorMap[$sevKey]) { $sevColorMap[$sevKey] } else { '#6B7280' }
            $sevName  = if ($sevNameMap[$sevKey]) { $sevNameMap[$sevKey] } else { $sevKey }
            $affectedHtml = ''
            if ($f.AffectedResources -and $f.AffectedResources.Count -gt 0) {
                $shown = $f.AffectedResources | Select-Object -First 10
                $moreHtml = if ($f.AffectedResources.Count -gt 10) { "<li><em>... and $($f.AffectedResources.Count - 10) more</em></li>" } else { '' }
                $affectedHtml = "<div class='affected-list'><strong>Affected ($($f.AffectedResources.Count)):</strong><ul>" +
                    ($shown | ForEach-Object { "<li>$_</li>" } | Out-String) +
                    $moreHtml +
                    "</ul></div>"
            }
            $controls = if ($f.ComplianceControls) { $f.ComplianceControls -join ' &bull; ' } else { '' }
            $controlsHtml = if ($controls) { "<div class='controls'><strong>Controls:</strong> $controls</div>" } else { '' }
            $findingsDetail += @"
<div class='finding-card'>
  <div class='finding-header'>
    <span class='badge' style='background:$sevColor'>$sevName</span>
    <strong>$($f.Title)</strong>
    <span class='finding-id'>$($f.FindingId)</span>
  </div>
  <p class='finding-desc'>$($f.Description)</p>
  $affectedHtml
  <div class='remediation'><strong>Remediation:</strong> $($f.Remediation)</div>
  $controlsHtml
</div>
"@
        }
        $findingsDetail += "</div>"
    }

    # Remediation plan table rows
    $remRows = ''
    $remPriority = 1
    foreach ($item in ($remPlan | Select-Object -First 25)) {
        $sevKey   = [string]$item.Severity
        $sevColor = if ($sevColorMap[$sevKey]) { $sevColorMap[$sevKey] } else { '#6B7280' }
        $sevName  = if ($sevNameMap[$sevKey]) { $sevNameMap[$sevKey] } else { $sevKey }
        $hasScript = if ($item.HasRemediationScript) { '&#10003;' } else { '&mdash;' }
        $effort = if ($item.EffortHours) { "$($item.EffortHours)h" } else { 'TBD' }
        $remRows += @"
<tr>
  <td>$remPriority</td>
  <td>$($item.Title)</td>
  <td><span class="badge" style="background:$sevColor">$sevName</span></td>
  <td>$effort</td>
  <td style="text-align:center">$hasScript</td>
</tr>
"@
        $remPriority++
    }

    # Quick wins HTML
    $quickWinCards = ''
    foreach ($qw in ($quickWins | Select-Object -First 8)) {
        $sevKey   = [string]$qw.Severity
        $sevColor = if ($sevColorMap[$sevKey]) { $sevColorMap[$sevKey] } else { '#6B7280' }
        $sevName  = if ($sevNameMap[$sevKey]) { $sevNameMap[$sevKey] } else { $sevKey }
        $quickWinCards += @"
<div class="qw-card">
  <span class="badge" style="background:$sevColor">$sevName</span>
  <strong>$($qw.Title)</strong>
  <p>$($qw.Remediation)</p>
</div>
"@
    }

    # Compliance posture HTML
    $complianceHtml = ''
    foreach ($fw in $compGaps.Keys) {
        $fwData = $compGaps[$fw]
        if (-not $fwData) { continue }
        $coverage = if ($null -ne $fwData['CoveragePercent'] -and $fwData['CoveragePercent'] -ne '') {
            [double]$fwData['CoveragePercent']
        } elseif ($null -ne $fwData.CoveragePercent) {
            [double]$fwData.CoveragePercent
        } else { 0 }
        $barColor = if ($coverage -ge 70) { $Colors.accent } elseif ($coverage -ge 40) { $Colors.warning } else { $Colors.danger }
        $complianceHtml += @"
<div class="compliance-fw">
  <div class="fw-name">$fw</div>
  <div class="fw-bar-wrap">
    <div class="fw-bar" style="width:$coverage%;background:$barColor;"></div>
  </div>
  <div class="fw-pct">$coverage%</div>
</div>
"@
    }

    # License waste section
    $licenseWasteHtml = ''
    if ($licenseWaste -and $licenseWaste -ne '€0/month') {
        $licenseWasteHtml = @"
<section class="section page-break">
  <h2 class="section-title">License Waste Analysis</h2>
  <div class="waste-callout">
    <div class="waste-amount">$licenseWaste</div>
    <div class="waste-label">estimated monthly waste</div>
  </div>
  <p>Unused license assignments were detected. Review the Licensing collector findings for detailed breakdown and remediation steps.</p>
</section>
"@
    }

    $severitySectionHtml = "<p style='color:#64748B'>No findings detected.</p>"
    if ($totalFindings -gt 0) {
        $critPct = [Math]::Round(($critCount / $totalFindings) * 100)
        $highPct = [Math]::Round(($highCount / $totalFindings) * 100)
        $medPct  = [Math]::Round(($medCount  / $totalFindings) * 100)
        $lowPct  = [Math]::Round(($lowCount  / $totalFindings) * 100)
        $infoPct = [Math]::Max(0, 100 - $critPct - $highPct - $medPct - $lowPct)

        $distSegments = @()
        $critLabel = if ($critPct -gt 5) { "$critCount" } else { '' }
        $highLabel = if ($highPct -gt 5) { "$highCount" } else { '' }
        $medLabel  = if ($medPct  -gt 5) { "$medCount"  } else { '' }
        $lowLabel  = if ($lowPct  -gt 5) { "$lowCount"  } else { '' }
        $infoLabel = if ($infoPct -gt 5) { "$infoCount" } else { '' }
        if ($critPct -gt 0) { $distSegments += "<div class='dist-seg' style='width:$critPct%;background:#DC2626;'>$critLabel</div>" }
        if ($highPct -gt 0) { $distSegments += "<div class='dist-seg' style='width:$highPct%;background:#EA580C;'>$highLabel</div>" }
        if ($medPct  -gt 0) { $distSegments += "<div class='dist-seg' style='width:$medPct%;background:#D97706;'>$medLabel</div>" }
        if ($lowPct  -gt 0) { $distSegments += "<div class='dist-seg' style='width:$lowPct%;background:#2563EB;'>$lowLabel</div>" }
        if ($infoPct -gt 0 -and $infoCount -gt 0) { $distSegments += "<div class='dist-seg' style='width:$infoPct%;background:#6B7280;'>$infoLabel</div>" }

        $severitySectionHtml = @"
<div class="dist-bar">
  $($distSegments -join "`n  ")
</div>
<div class="dist-legend">
  <div class="dist-legend-item"><div class="legend-dot" style="background:#DC2626"></div>Critical ($critCount)</div>
  <div class="dist-legend-item"><div class="legend-dot" style="background:#EA580C"></div>High ($highCount)</div>
  <div class="dist-legend-item"><div class="legend-dot" style="background:#D97706"></div>Medium ($medCount)</div>
  <div class="dist-legend-item"><div class="legend-dot" style="background:#2563EB"></div>Low ($lowCount)</div>
  <div class="dist-legend-item"><div class="legend-dot" style="background:#6B7280"></div>Info ($infoCount)</div>
</div>
"@
    }

    $quickWinsSectionHtml = ''
    if ($quickWins.Count -gt 0) {
        $quickWinsSectionHtml = @"
<section class='section'>
  <h2 class='section-title'>&#9889; Quick Wins</h2>
  <p style='color:#64748B;margin-bottom:20px;'>These findings can be resolved quickly with minimal effort and no significant disruption.</p>
  <div class='qw-grid'>$quickWinCards</div>
</section>
"@
    }

    $complianceSectionHtml = ''
    if ($compGaps.Keys.Count -gt 0) {
        $complianceSectionHtml = @"
<section class='section page-break'>
  <h2 class='section-title'>Compliance Posture</h2>
  $complianceHtml
</section>
"@
    }

    $collectorCoverageHtml = ''
    if ($report.CollectorResults) {
        $coverageRows = ''
        foreach ($cr in $report.CollectorResults) {
            $checkResults = if ($cr.Metadata -and $cr.Metadata['CheckResults']) { @($cr.Metadata['CheckResults'].Values) } else { @() }
            if ($checkResults.Count -eq 0) { continue }

            $passedChecks = @($checkResults | Where-Object { $_.Status -eq 'Passed' }).Count
            $findingChecks = @($checkResults | Where-Object { $_.Status -eq 'FindingDetected' }).Count
            $permSkipped = @($checkResults | Where-Object { $_.Status -eq 'SkippedInsufficientPermissions' }).Count
            $modeSkipped = @($checkResults | Where-Object { $_.Status -eq 'SkippedUnsupportedMode' }).Count
            $featureSkipped = @($checkResults | Where-Object { $_.Status -eq 'SkippedFeatureUnavailable' }).Count
            $failedChecks = @($checkResults | Where-Object { $_.Status -eq 'Failed' }).Count

            $coverageRows += @"
<tr>
  <td>$($cr.Domain)</td>
  <td>$($cr.Status)</td>
  <td>$passedChecks</td>
  <td>$findingChecks</td>
  <td>$permSkipped</td>
  <td>$modeSkipped</td>
  <td>$featureSkipped</td>
  <td>$failedChecks</td>
</tr>
"@
        }

        if ($coverageRows) {
            $collectorCoverageHtml = @"
<section class="section">
  <h2 class="section-title">Collector Coverage</h2>
  <table>
    <thead><tr><th>Domain</th><th>Status</th><th>Passed</th><th>Findings</th><th>Permission Skips</th><th>Mode Skips</th><th>Feature Skips</th><th>Failed</th></tr></thead>
    <tbody>$coverageRows</tbody>
  </table>
</section>
"@
        }
    }

    # ── Cover variables ─────────────────────────────────────────────────
    $coverSubtitle  = if ($ReportType -eq 'MSPAuditPack') { 'M365 Security &amp; Compliance Audit Pack' } else { 'M365 Risk &amp; Compliance Assessment' }
    $preparedByLine  = if ($PreparedBy)  { "<div class='cover-subtitle'>Prepared by: $PreparedBy</div>"  } else { '' }
    $preparedForLine = if ($PreparedFor) { "<div class='cover-subtitle'>Prepared for: $PreparedFor</div>" } else { '' }

    # ── Evidence pack summary section (MSP only) ────────────────────────
    $evidencePackSectionHtml = ''
    if ($ReportType -eq 'MSPAuditPack' -and $compGaps.Keys.Count -gt 0) {
        $evRows = ''
        foreach ($fw in $compGaps.Keys) {
            $fwD = $compGaps[$fw]; if (-not $fwD) { continue }
            $evCov   = if ($null -ne $fwD['CoveragePercent'])  { [double]$fwD['CoveragePercent']  } elseif ($null -ne $fwD.CoveragePercent)  { [double]$fwD.CoveragePercent  } else { 0 }
            $evTotal = if ($null -ne $fwD['TotalControls'])    { $fwD['TotalControls']    } elseif ($null -ne $fwD.TotalControls)    { $fwD.TotalControls    } else { 0 }
            $evPass  = if ($null -ne $fwD['Compliant'])        { $fwD['Compliant']        } elseif ($null -ne $fwD.Compliant)        { $fwD.Compliant        } else { 0 }
            $evFail  = if ($null -ne $fwD['NonCompliant'])     { $fwD['NonCompliant']     } elseif ($null -ne $fwD.NonCompliant)     { $fwD.NonCompliant     } else { 0 }
            $evColor = if ($evCov -ge 70) { '#10B981' } elseif ($evCov -ge 40) { '#F59E0B' } else { '#EF4444' }
            $evRows += "<tr><td>$fw</td><td>$evTotal</td><td style='color:#10B981;font-weight:600'>$evPass</td><td style='color:#EF4444;font-weight:600'>$evFail</td><td><strong style='color:$evColor'>$evCov%</strong></td><td style='color:#64748B;font-size:0.8rem'>evidence/$($fw.ToLower())/</td></tr>"
        }
        $evidencePackSectionHtml = @"
<section class='section page-break'>
  <h2 class='section-title'>Evidence Pack Summary</h2>
  <p style='color:#64748B;margin-bottom:16px;'>Compliance evidence files are in the <strong>evidence/</strong> folder alongside this report. Each framework subfolder contains per-control evidence JSON and findings CSV files.</p>
  <table>
    <thead><tr><th>Framework</th><th>Assessed</th><th>Passing</th><th>Failing</th><th>Coverage</th><th>Evidence Path</th></tr></thead>
    <tbody>$evRows</tbody>
  </table>
</section>
"@
    }

    # ── Expanded compliance section for MSP (shows non-compliant controls) ──
    $complianceSectionForMSP = $complianceSectionHtml
    if ($ReportType -eq 'MSPAuditPack' -and $compGaps.Keys.Count -gt 0) {
        $mspCompBody = ''
        foreach ($fw in $compGaps.Keys) {
            $fwD = $compGaps[$fw]; if (-not $fwD) { continue }
            $mspCov = if ($null -ne $fwD['CoveragePercent']) { [double]$fwD['CoveragePercent'] } elseif ($null -ne $fwD.CoveragePercent) { [double]$fwD.CoveragePercent } else { 0 }
            $barC   = if ($mspCov -ge 70) { '#10B981' } elseif ($mspCov -ge 40) { '#F59E0B' } else { '#EF4444' }
            $ctrlDetails = if ($fwD['ControlDetails']) { $fwD['ControlDetails'] } else { $fwD.ControlDetails }
            $gapsHtml = ''
            if ($ctrlDetails) {
                $ctrlKeys = try { $ctrlDetails.Keys } catch { $ctrlDetails | Get-Member -MemberType NoteProperty | Select-Object -ExpandProperty Name }
                $failItems = foreach ($cid in $ctrlKeys) {
                    $cd = if ($ctrlDetails -is [System.Collections.IDictionary]) { $ctrlDetails[$cid] } else { $ctrlDetails.$cid }
                    $cdStatus = if ($cd -is [System.Collections.IDictionary]) { $cd['Status'] } else { $cd.Status }
                    if ($cdStatus -eq 'NonCompliant') {
                        $cdTitle = if ($cd -is [System.Collections.IDictionary]) { $cd['Title'] } else { $cd.Title }
                        "<li><code style='color:#EF4444'>$cid</code> &mdash; $cdTitle</li>"
                    }
                }
                if ($failItems) { $gapsHtml = "<ul style='margin:8px 0 0 20px;font-size:0.82rem;color:#64748B;'>$($failItems -join '')</ul>" }
            }
            $mspCompBody += @"
<div style='margin-bottom:20px;padding:16px;background:#F8FAFC;border-radius:6px;border:1px solid #E2E8F0;'>
  <div style='display:flex;align-items:center;gap:12px;margin-bottom:8px;'>
    <span style='font-weight:700;font-size:1rem;min-width:160px;'>$fw</span>
    <div style='flex:1;background:#E2E8F0;border-radius:4px;height:14px;overflow:hidden;'><div style='width:$mspCov%;height:100%;background:$barC;border-radius:4px;'></div></div>
    <span style='font-weight:800;color:$barC;min-width:52px;text-align:right;'>$mspCov%</span>
  </div>
  $gapsHtml
  <div style='margin-top:8px;font-size:0.78rem;color:#94A3B8;'>See: <code>evidence/$($fw.ToLower())/</code></div>
</div>
"@
        }
        $complianceSectionForMSP = @"
<section class='section page-break'>
  <h2 class='section-title'>Compliance Posture</h2>
  <p style='color:#64748B;margin-bottom:16px;'>Framework coverage based on open security findings mapped to compliance controls.</p>
  $mspCompBody
</section>
"@
    }

    # ── Standard body section strings ───────────────────────────────────
    $secExecSummary = @"
<section class="section">
  <h2 class="section-title">Executive Summary</h2>
  $narrative
  <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(140px,1fr));gap:16px;margin-top:20px;">
    <div style="text-align:center;padding:16px;background:#FEF2F2;border-radius:8px;"><div style="font-size:2rem;font-weight:800;color:#DC2626;">$critCount</div><div style="font-size:0.75rem;color:#6B7280;">Critical</div></div>
    <div style="text-align:center;padding:16px;background:#FFF7ED;border-radius:8px;"><div style="font-size:2rem;font-weight:800;color:#EA580C;">$highCount</div><div style="font-size:0.75rem;color:#6B7280;">High</div></div>
    <div style="text-align:center;padding:16px;background:#FFFBEB;border-radius:8px;"><div style="font-size:2rem;font-weight:800;color:#D97706;">$medCount</div><div style="font-size:0.75rem;color:#6B7280;">Medium</div></div>
    <div style="text-align:center;padding:16px;background:#EFF6FF;border-radius:8px;"><div style="font-size:2rem;font-weight:800;color:#2563EB;">$lowCount</div><div style="font-size:0.75rem;color:#6B7280;">Low</div></div>
    <div style="text-align:center;padding:16px;background:#F9FAFB;border-radius:8px;"><div style="font-size:2rem;font-weight:800;color:#6B7280;">$totalFindings</div><div style="font-size:0.75rem;color:#6B7280;">Total</div></div>
  </div>
</section>
"@

    $secRiskDashboard = @"
<section class="section page-break">
  <h2 class="section-title">Risk Score Dashboard</h2>
  <div class="gauge-wrap">
    <svg class="gauge-svg" width="140" height="140" viewBox="0 0 120 120">
      <circle cx="60" cy="60" r="45" fill="none" stroke="#E2E8F0" stroke-width="10"/>
      <circle cx="60" cy="60" r="45" fill="none" stroke="$gaugeColor" stroke-width="10"
        stroke-dasharray="283" stroke-dashoffset="$dashOffset"
        stroke-linecap="round" transform="rotate(-90 60 60)"/>
      <text x="60" y="56" class="gauge-text" font-size="22" font-weight="800" fill="$gaugeColor">$overallScore</text>
      <text x="60" y="72" class="gauge-text" font-size="11" fill="#64748B">/ 100</text>
      <text x="60" y="86" class="gauge-text" font-size="13" font-weight="700" fill="$ratingColor">$rating</text>
    </svg>
    <div style="flex:1">
      <h3 style="margin-bottom:16px;font-size:0.9rem;color:#64748B;text-transform:uppercase;letter-spacing:0.5px;">Security Categories</h3>
      $categoryBars
    </div>
  </div>
  <h3 style="margin:24px 0 16px;font-size:0.9rem;color:#64748B;text-transform:uppercase;letter-spacing:0.5px;">Domain Scores</h3>
  <div class="domain-grid">$domainCards</div>
</section>
"@

    $secSeverityDist = @"
<section class="section">
  <h2 class="section-title">Severity Distribution</h2>
  $severitySectionHtml
</section>
"@

    $secTop10 = @"
<section class="section page-break">
  <h2 class="section-title">Top 10 Priority Findings</h2>
  <table>
    <thead><tr><th>#</th><th>Severity</th><th>Domain</th><th>Finding</th><th>Affected</th></tr></thead>
    <tbody>$top10Rows</tbody>
  </table>
</section>
"@

    $secFindingsDetail = @"
<section class="section page-break">
  <h2 class="section-title">Full Findings Detail</h2>
  $findingsDetail
</section>
"@

    $secRemediation = @"
<section class="section page-break">
  <h2 class="section-title">Prioritised Remediation Plan</h2>
  <table>
    <thead><tr><th>#</th><th>Finding</th><th>Severity</th><th>Effort</th><th>Script</th></tr></thead>
    <tbody>$remRows</tbody>
  </table>
</section>
"@

    $appendixPreparedBy = if ($PreparedBy) { $PreparedBy } else { $CompanyName }
    $secAppendix = @"
<section class="section page-break">
  <h2 class="section-title">Appendix &mdash; Methodology &amp; Scope</h2>
  <div class="appendix-grid">
    <div class="appendix-item"><strong>Tool</strong>AuditXpert by TakeItToCloud v$($script:TOOL_VERSION)</div>
    <div class="appendix-item"><strong>Assessment Profile</strong>$($report.AssessmentProfile)</div>
    <div class="appendix-item"><strong>Tenant</strong>$tenantName ($($report.TenantId))</div>
    <div class="appendix-item"><strong>Assessment Date</strong>$assessDate</div>
    <div class="appendix-item"><strong>Prepared By</strong>$appendixPreparedBy</div>
    <div class="appendix-item"><strong>Total Findings</strong>$totalFindings</div>
  </div>
  <h3 style="margin:20px 0 12px;font-size:0.9rem;">Methodology</h3>
  <p style="color:#64748B;font-size:0.85rem;">This assessment uses read-only Microsoft Graph API calls to evaluate the security configuration of the tenant. No changes are made to tenant configuration. All data is collected at the time of assessment and reflects a point-in-time snapshot.</p>
  <h3 style="margin:20px 0 12px;font-size:0.9rem;">Required Permissions</h3>
  <p style="color:#64748B;font-size:0.85rem;">Directory.Read.All &bull; Policy.Read.All &bull; SecurityEvents.Read.All &bull; DeviceManagementConfiguration.Read.All &bull; DeviceManagementManagedDevices.Read.All &bull; Reports.Read.All &bull; RoleManagement.Read.Directory &bull; User.Read.All &bull; AuditLog.Read.All</p>
</section>
"@

    # ── Assemble sections in report-type order ───────────────────────────
    $bodySections = if ($ReportType -eq 'MSPAuditPack') {
        @($secExecSummary, $complianceSectionForMSP, $evidencePackSectionHtml, $secRiskDashboard,
          $secSeverityDist, $secTop10, $secFindingsDetail, $secRemediation,
          $quickWinsSectionHtml, $collectorCoverageHtml, $licenseWasteHtml, $secAppendix)
    } else {
        @($secExecSummary, $secRiskDashboard, $secSeverityDist, $secTop10, $secFindingsDetail,
          $secRemediation, $quickWinsSectionHtml, $complianceSectionHtml,
          $collectorCoverageHtml, $licenseWasteHtml, $secAppendix)
    }
    $bodyHtml = ($bodySections | Where-Object { $_ }) -join "`n"

    $reportTitle = if ($ReportType -eq 'MSPAuditPack') { "M365 MSP Audit Pack — $tenantName" } else { "M365 Security Assessment — $tenantName" }

    # ── Build final HTML ─────────────────────────────────────────────────
    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>$reportTitle</title>
<style>
  :root {
    --primary: $($Colors.primary);
    --accent: $($Colors.accent);
    --warning: $($Colors.warning);
    --danger: $($Colors.danger);
    --bg: #F8FAFC;
    --card: #FFFFFF;
    --text: #1E293B;
    --muted: #64748B;
    --border: #E2E8F0;
  }
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: 'Segoe UI', 'Manrope', -apple-system, sans-serif; background: var(--bg); color: var(--text); font-size: 14px; line-height: 1.6; }
  a { color: var(--accent); }

  /* Layout */
  .container { max-width: 1100px; margin: 0 auto; padding: 0 24px; }
  .section { background: var(--card); border-radius: 8px; padding: 28px 32px; margin-bottom: 24px; border: 1px solid var(--border); }
  .section-title { font-size: 1.25rem; font-weight: 700; color: var(--primary); margin-bottom: 20px; padding-bottom: 10px; border-bottom: 2px solid var(--accent); }

  /* Cover */
  .cover { background: var(--primary); color: white; padding: 60px 40px; text-align: center; margin-bottom: 24px; position: relative; overflow: hidden; }
  .cover::after { content: 'CONFIDENTIAL'; position: absolute; top: 50%; left: 50%; transform: translate(-50%,-50%) rotate(-35deg); font-size: 6rem; font-weight: 900; opacity: 0.04; white-space: nowrap; pointer-events: none; }
  .cover-logo { margin-bottom: 32px; }
  .cover-tenant { font-size: 2rem; font-weight: 700; margin-bottom: 8px; }
  .cover-subtitle { color: rgba(255,255,255,0.6); font-size: 0.9rem; margin-bottom: 32px; }
  .score-badge { display: inline-block; background: $ratingColor; color: white; font-size: 3rem; font-weight: 900; width: 100px; height: 100px; line-height: 100px; border-radius: 50%; margin: 0 auto 16px; }
  .cover-score-label { color: rgba(255,255,255,0.7); font-size: 0.85rem; letter-spacing: 1px; text-transform: uppercase; }

  /* Gauge */
  .gauge-wrap { display: flex; align-items: center; gap: 32px; flex-wrap: wrap; }
  .gauge-svg { flex-shrink: 0; }
  .gauge-text { text-anchor: middle; }
  .domain-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(150px, 1fr)); gap: 16px; margin-top: 20px; }
  .domain-card { background: var(--bg); border: 1px solid var(--border); border-radius: 8px; padding: 16px; text-align: center; }
  .domain-name { font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.5px; color: var(--muted); margin-bottom: 8px; }
  .domain-score { font-size: 2rem; font-weight: 800; }
  .domain-meta { font-size: 0.75rem; color: var(--muted); }

  /* Category bars */
  .cat-row { display: flex; align-items: center; gap: 12px; margin-bottom: 12px; }
  .cat-label { width: 200px; font-size: 0.85rem; flex-shrink: 0; }
  .cat-bar-wrap { flex: 1; background: var(--border); border-radius: 4px; height: 12px; overflow: hidden; }
  .cat-bar { height: 100%; border-radius: 4px; transition: width 0.3s; min-width: 4px; }
  .cat-score { width: 36px; text-align: right; font-weight: 700; font-size: 0.85rem; }

  /* Severity distribution */
  .dist-bar { display: flex; height: 28px; border-radius: 6px; overflow: hidden; gap: 2px; margin-bottom: 12px; }
  .dist-seg { display: flex; align-items: center; justify-content: center; color: white; font-size: 0.75rem; font-weight: 700; transition: all 0.3s; }
  .dist-legend { display: flex; gap: 16px; flex-wrap: wrap; }
  .dist-legend-item { display: flex; align-items: center; gap: 6px; font-size: 0.8rem; }
  .legend-dot { width: 10px; height: 10px; border-radius: 50%; }

  /* Badge */
  .badge { display: inline-block; padding: 2px 10px; border-radius: 12px; color: white; font-size: 0.75rem; font-weight: 600; }

  /* Table */
  table { width: 100%; border-collapse: collapse; }
  th { background: var(--primary); color: white; padding: 10px 12px; text-align: left; font-size: 0.8rem; font-weight: 600; text-transform: uppercase; letter-spacing: 0.5px; }
  td { padding: 10px 12px; border-bottom: 1px solid var(--border); vertical-align: top; }
  tr:last-child td { border-bottom: none; }
  tr:hover td { background: var(--bg); }

  /* Findings */
  .finding-card { border: 1px solid var(--border); border-radius: 6px; padding: 16px; margin-bottom: 16px; }
  .finding-header { display: flex; align-items: center; gap: 10px; margin-bottom: 8px; flex-wrap: wrap; }
  .finding-id { color: var(--muted); font-size: 0.75rem; margin-left: auto; }
  .finding-desc { color: var(--text); margin-bottom: 10px; }
  .affected-list ul { margin: 6px 0 0 20px; font-size: 0.8rem; color: var(--muted); }
  .remediation { background: #F0FDF4; border-left: 3px solid var(--accent); padding: 10px 14px; border-radius: 0 4px 4px 0; margin-top: 10px; font-size: 0.85rem; }
  .controls { margin-top: 8px; font-size: 0.75rem; color: var(--muted); }
  .domain-section { margin-bottom: 32px; }
  .domain-header { font-size: 1rem; font-weight: 700; color: var(--primary); padding: 8px 0; border-bottom: 1px solid var(--border); margin-bottom: 16px; }

  /* Quick wins */
  .qw-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(280px, 1fr)); gap: 16px; }
  .qw-card { border: 1px solid var(--accent); border-radius: 8px; padding: 16px; }
  .qw-card strong { display: block; margin: 8px 0 4px; }
  .qw-card p { font-size: 0.82rem; color: var(--muted); }

  /* Compliance */
  .compliance-fw { display: flex; align-items: center; gap: 12px; margin-bottom: 12px; }
  .fw-name { width: 180px; font-size: 0.85rem; flex-shrink: 0; }
  .fw-bar-wrap { flex: 1; background: var(--border); border-radius: 4px; height: 16px; overflow: hidden; }
  .fw-bar { height: 100%; border-radius: 4px; }
  .fw-pct { width: 48px; text-align: right; font-weight: 700; }

  /* Waste */
  .waste-callout { display: inline-block; background: #FEF3C7; border: 2px solid var(--warning); border-radius: 8px; padding: 16px 32px; text-align: center; margin-bottom: 16px; }
  .waste-amount { font-size: 2rem; font-weight: 800; color: var(--warning); }
  .waste-label { font-size: 0.8rem; color: var(--muted); }

  /* Appendix */
  .appendix-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }
  .appendix-item strong { display: block; color: var(--muted); font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 4px; }

  @media print {
    body { background: white; }
    .section { box-shadow: none; border: 1px solid #ddd; }
    .page-break { page-break-before: always; }
    .cover { background: var(--primary) !important; -webkit-print-color-adjust: exact; print-color-adjust: exact; }
    .badge, th, .cat-bar, .fw-bar, .dist-seg { -webkit-print-color-adjust: exact; print-color-adjust: exact; }
  }
</style>
</head>
<body>

<!-- COVER PAGE -->
<div class="cover">
  <div class="cover-logo">$logoTag</div>
  <div class="cover-tenant">$tenantName</div>
  <div class="cover-subtitle">$coverSubtitle &mdash; $assessDate</div>
  $preparedByLine
  $preparedForLine
  <div class="score-badge">$rating</div>
  <div class="cover-score-label">Overall Risk Rating &mdash; Score: $overallScore / 100</div>
</div>

<div class="container">
$bodyHtml
</div><!-- /container -->
</body>
</html>
"@

    return $html
}

# ============================================================================
# MODULE EXPORT
# ============================================================================

Export-ModuleMember -Function @('Export-TiTCReport')
