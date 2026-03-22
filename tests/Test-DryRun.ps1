using module ..\src\Core\Models\TiTC.Models.psm1
#Requires -Version 7.0
<#
.SYNOPSIS
    Phase C — Dry-Run Simulation for AuditXpert.

.DESCRIPTION
    Simulates a full assessment without Graph connectivity. Builds fake collector
    results, runs the risk analyzer, exercises every output module, and verifies
    the complete data flow end-to-end.

.NOTES
    Run with: pwsh -ExecutionPolicy Bypass -File .\tests\Test-DryRun.ps1
#>

$ErrorActionPreference = 'Stop'
$root    = Split-Path $PSScriptRoot -Parent
$outRoot = Join-Path $env:TEMP "AuditXpert-DryRun-$(Get-Date -Format 'yyyyMMddHHmmss')"

$pass    = 0
$fail    = 0
$results = [System.Collections.ArrayList]::new()

function Test-Step {
    param([string]$Name, [scriptblock]$Block)
    try {
        & $Block
        $null = $script:results.Add([PSCustomObject]@{ Name = $Name; Status = 'PASS'; Detail = '' })
        $script:pass++
    }
    catch {
        $null = $script:results.Add([PSCustomObject]@{ Name = $Name; Status = 'FAIL'; Detail = $_.Exception.Message })
        $script:fail++
    }
}

Write-Host ''
Write-Host '  AuditXpert — Phase C: Dry-Run Simulation' -ForegroundColor Cyan
Write-Host '  -----------------------------------------' -ForegroundColor DarkGray
Write-Host "  Output: $outRoot" -ForegroundColor DarkGray

# ── Load all modules ──────────────────────────────────────────────────────────
Import-Module (Join-Path $root 'src\Core\Models\TiTC.Models.psm1') -Force
Import-Module (Join-Path $root 'src\Core\TiTC.Core.psm1') -Force
Import-Module (Join-Path $root 'src\Analyzers\TiTC.Analyzer.Risk.psm1') -Force
Import-Module (Join-Path $root 'src\Outputs\TiTC.Output.Report.psm1') -Force
Import-Module (Join-Path $root 'src\Outputs\TiTC.Output.Evidence.psm1') -Force
Import-Module (Join-Path $root 'src\Outputs\TiTC.Output.AIExplainer.psm1') -Force

# ── Create output directories ─────────────────────────────────────────────────
New-Item -ItemType Directory -Path $outRoot -Force | Out-Null
foreach ($sub in @('report','evidence','data','compliance')) {
    New-Item -ItemType Directory -Path (Join-Path $outRoot $sub) -Force | Out-Null
}

# ── Helpers ───────────────────────────────────────────────────────────────────
function New-FakeFinding {
    param([string]$Sev='High', [string]$Domain='EntraID', [string]$Title='Test Finding',
          [string[]]$Controls = @('ISO-A.9.1'), [int]$Weight = 3)
    New-TiTCFinding -Severity $Sev -Domain $Domain -Title $Title `
        -Description "DryRun: $Title" -Remediation 'Fix in dry-run' `
        -RiskWeight $Weight -ComplianceControls $Controls
}

# ============================================================================
# PHASE C-1: Collector Result Construction
# ============================================================================

$entraResult = $null
Test-Step 'C1: Build EntraID collector result' {
    $script:entraResult = New-TiTCCollectorResult -Domain 'EntraID'
    $f1 = New-FakeFinding -Sev 'Critical' -Domain 'EntraID' -Title 'MFA not enforced' -Controls @('ISO-A.9.4.2','CIS-1.1')
    $f2 = New-FakeFinding -Sev 'High'     -Domain 'EntraID' -Title 'Stale admin accounts' -Controls @('ISO-A.9.2.1')
    $f3 = New-FakeFinding -Sev 'Medium'   -Domain 'EntraID' -Title 'Legacy auth not blocked' -Controls @('CIS-1.2')
    $script:entraResult.Findings += $f1; $script:entraResult.Findings += $f2; $script:entraResult.Findings += $f3
    $script:entraResult.Complete()
    if ($script:entraResult.FindingsCount -ne 3) { throw "Expected 3 findings, got $($script:entraResult.FindingsCount)" }
}

$exchangeResult = $null
Test-Step 'C1: Build Exchange collector result' {
    $script:exchangeResult = New-TiTCCollectorResult -Domain 'Exchange'
    $f1 = New-FakeFinding -Sev 'Critical' -Domain 'Exchange' -Title 'External forwarding detected' -Controls @('ISO-A.13.2')
    $f2 = New-FakeFinding -Sev 'High'     -Domain 'Exchange' -Title 'DMARC not configured' -Controls @('CIS-2.1')
    $script:exchangeResult.Findings += $f1; $script:exchangeResult.Findings += $f2
    $script:exchangeResult.Complete()
    if ($script:exchangeResult.FindingsCount -ne 2) { throw "Expected 2 findings" }
}

$intuneResult = $null
Test-Step 'C1: Build Intune collector result' {
    $script:intuneResult = New-TiTCCollectorResult -Domain 'Intune'
    $f1 = New-FakeFinding -Sev 'High'   -Domain 'Intune' -Title 'Devices not encrypted' -Controls @('ISO-A.10.1')
    $f2 = New-FakeFinding -Sev 'Medium' -Domain 'Intune' -Title 'Stale device records'  -Controls @()
    $script:intuneResult.Findings += $f1; $script:intuneResult.Findings += $f2
    $script:intuneResult.Complete()
}

$defenderResult = $null
Test-Step 'C1: Build Defender collector result' {
    $script:defenderResult = New-TiTCCollectorResult -Domain 'Defender'
    $f1 = New-FakeFinding -Sev 'High' -Domain 'Defender' -Title 'Unresolved critical alerts' -Weight 5 -Controls @('CIS-4.1')
    $script:defenderResult.Findings += $f1
    $script:defenderResult.Complete()
}

$licensingResult = $null
Test-Step 'C1: Build Licensing collector result with waste' {
    $script:licensingResult = New-TiTCCollectorResult -Domain 'Licensing'
    $script:licensingResult.RawData['EstimatedMonthlyWaste'] = 1250.00
    $f1 = New-FakeFinding -Sev 'Low' -Domain 'Licensing' -Title 'Unused E5 licenses' -Controls @()
    $script:licensingResult.Findings += $f1
    $script:licensingResult.Complete()
}

# ============================================================================
# PHASE C-2: Report Assembly
# ============================================================================

$report = $null
Test-Step 'C2: Assemble TiTCAssessmentReport' {
    $script:report = [TiTCAssessmentReport]::new()
    $script:report.TenantId          = 'dryrun-tenant-id'
    $script:report.TenantName        = 'DryRun Corp'
    $script:report.TenantDomain      = 'dryrun.onmicrosoft.com'
    $script:report.AssessmentProfile = 'Full'
    $script:report.CollectorResults  += $script:entraResult
    $script:report.CollectorResults  += $script:exchangeResult
    $script:report.CollectorResults  += $script:intuneResult
    $script:report.CollectorResults  += $script:defenderResult
    $script:report.CollectorResults  += $script:licensingResult
    $script:report.EstimatedWaste    = 1250.00
}

Test-Step 'C2: AggregateFindings aggregates correctly' {
    $script:report.AggregateFindings()
    $expected = 3 + 2 + 2 + 1 + 1  # sum from all collectors
    if ($script:report.AllFindings.Count -ne $expected) {
        throw "Expected $expected findings, got $($script:report.AllFindings.Count)"
    }
}

Test-Step 'C2: ToExecutiveSummary returns required keys' {
    $summary = $script:report.ToExecutiveSummary()
    if ($null -eq $summary)                              { throw 'ToExecutiveSummary returned null' }
    foreach ($key in @('TotalFindings','CriticalFindings','HighFindings','OverallScore','OverallRating')) {
        if (-not $summary.ContainsKey($key)) { throw "Missing key: $key" }
    }
}

# ============================================================================
# PHASE C-3: Risk Analyzer
# ============================================================================

$riskAnalysis = $null
Test-Step 'C3: Invoke-TiTCRiskAnalysis returns valid result' {
    $config = Get-TiTCConfig -ProfileName Full
    $config.ComplianceFrameworks = @('ISO27001','CyberInsurance','InternalRisk')
    $script:riskAnalysis = Invoke-TiTCRiskAnalysis `
        -CollectorResults $script:report.CollectorResults `
        -Config $config `
        -ComplianceFrameworks @('ISO27001','CyberInsurance','InternalRisk')
    if ($null -eq $script:riskAnalysis) { throw 'Risk analysis returned null' }
}

Test-Step 'C3: RiskAnalysis has RiskScore 0-100' {
    $s = $script:riskAnalysis.RiskScore.OverallScore
    if ($s -lt 0 -or $s -gt 100) { throw "RiskScore out of range: $s" }
}

Test-Step 'C3: RiskAnalysis ComplianceGaps has expected frameworks' {
    foreach ($fw in @('ISO27001','CyberInsurance','InternalRisk')) {
        if (-not $script:riskAnalysis.ComplianceGaps.ContainsKey($fw)) {
            throw "Missing framework in ComplianceGaps: $fw"
        }
    }
}

Test-Step 'C3: RiskAnalysis RemediationPlan is non-empty' {
    if ($script:riskAnalysis.RemediationPlan.Count -eq 0) { throw 'RemediationPlan is empty' }
}

Test-Step 'C3: RiskAnalysis QuickWins key exists' {
    # QuickWins may be null or empty when no findings match quick-win criteria — that is valid
    if (-not $script:riskAnalysis.Contains('QuickWins')) { throw 'QuickWins key missing from result' }
}

# ============================================================================
# PHASE C-4: Data Exports (JSON / CSV)
# ============================================================================

$summary = $null
Test-Step 'C4: Build executive summary hashtable' {
    $script:report.RiskScore        = $script:riskAnalysis.RiskScore
    $script:report.CompliancePosture= $script:riskAnalysis.ComplianceGaps
    $script:report.TotalDurationSeconds = 42
    $script:summary = $script:report.ToExecutiveSummary()
    $script:summary['CategoryScores']   = $script:riskAnalysis.CategoryScores
    $script:summary['RemediationPlan']  = $script:riskAnalysis.RemediationPlan | Select-Object -First 10
    $script:summary['QuickWins']        = $script:riskAnalysis.QuickWins
}

Test-Step 'C4: Export assessment-results.json' {
    $jsonPath = Join-Path $outRoot 'data\assessment-results.json'
    $script:report | ConvertTo-Json -Depth 15 | Set-Content $jsonPath -Force
    if (-not (Test-Path $jsonPath)) { throw 'JSON not written' }
    $size = (Get-Item $jsonPath).Length
    if ($size -lt 100) { throw "JSON too small: $size bytes" }
}

Test-Step 'C4: Export findings.csv' {
    $csvPath = Join-Path $outRoot 'data\findings.csv'
    $script:report.AllFindings | Select-Object Severity, Domain, Title, Remediation,
        @{N='ComplianceControls';E={$_.ComplianceControls -join '; '}} |
        Export-Csv $csvPath -NoTypeInformation -Force
    if (-not (Test-Path $csvPath)) { throw 'CSV not written' }
    $rows = (Import-Csv $csvPath).Count
    if ($rows -ne $script:report.AllFindings.Count) { throw "CSV row count mismatch: $rows vs $($script:report.AllFindings.Count)" }
}

Test-Step 'C4: Export executive-summary.json' {
    $path = Join-Path $outRoot 'data\executive-summary.json'
    $script:summary | ConvertTo-Json -Depth 10 | Set-Content $path -Force
    if (-not (Test-Path $path)) { throw 'Executive summary JSON not written' }
}

Test-Step 'C4: Export compliance gap JSON per framework' {
    foreach ($fw in $script:riskAnalysis.ComplianceGaps.Keys) {
        $path = Join-Path $outRoot "compliance\compliance-$($fw.ToLower()).json"
        $script:riskAnalysis.ComplianceGaps[$fw] | ConvertTo-Json -Depth 10 | Set-Content $path -Force
        if (-not (Test-Path $path)) { throw "Missing compliance file for $fw" }
    }
}

# ============================================================================
# PHASE C-5: HTML Report
# ============================================================================

Test-Step 'C5: Export-TiTCReport generates HTML' {
    $assessmentData = @{ Report = $script:report; RiskAnalysis = $script:riskAnalysis; ExecutiveSummary = $script:summary }
    $reportBase = Join-Path $outRoot 'report\security-assessment-report'
    $out = Export-TiTCReport `
        -AssessmentData $assessmentData `
        -OutputPath $reportBase `
        -Format HTML `
        -CompanyName 'DryRun Corp'
    if (-not (Test-Path $out)) { throw "Report not written: $out" }
    $size = (Get-Item $out).Length
    if ($size -lt 1000) { throw "HTML too small: $size bytes" }
}

# ============================================================================
# PHASE C-6: Evidence Pack
# ============================================================================

Test-Step 'C6: Export-TiTCEvidencePack generates folder' {
    $evidenceOut = Export-TiTCEvidencePack `
        -Report $script:report `
        -OutputPath (Join-Path $outRoot 'evidence') `
        -Frameworks @('ISO27001','CyberInsurance') `
        -CompanyName 'DryRun Corp'
    if (-not (Test-Path $evidenceOut)) { throw "Evidence folder not created: $evidenceOut" }
}

# ============================================================================
# PHASE C-7: AI Explainer Input Normalizer
# ============================================================================

$csvTestPath = Join-Path $env:TEMP 'titc-test-manual.csv'
Test-Step 'C7: Import-TiTCAuditData reads AuditXpert JSON' {
    $jsonPath = Join-Path $outRoot 'data\assessment-results.json'
    $findings = Import-TiTCAuditData -InputFile $jsonPath -Format AuditXpert
    if ($findings.Count -eq 0) { throw 'No findings imported from JSON' }
    $first = $findings[0]
    if (-not $first.PSObject.Properties['Title']) { throw 'Imported finding missing Title property' }
}

Test-Step 'C7: Import-TiTCAuditData reads manual CSV (auto-detect)' {
    @'
Title,Severity,Domain,Description,Remediation
"No MFA","High","Identity","MFA is not configured","Enable MFA in AAD"
"Weak passwords","Medium","Identity","Password policy weak","Set complexity requirements"
'@ | Set-Content $csvTestPath -Force
    $findings = Import-TiTCAuditData -InputFile $csvTestPath
    if ($findings.Count -lt 2) { throw "Expected >=2 findings, got $($findings.Count)" }
}

Test-Step 'C7: Import-TiTCAuditData reads Qualys-format CSV' {
    $qualysPath = Join-Path $env:TEMP 'titc-test-qualys.csv'
    @'
QID,Title,Severity,Category,Result,Solution
12345,"SSL Certificate Expired",5,"General","Certificate expired","Renew SSL certificate"
12346,"Open SSH Port",3,"Network","Port 22 open","Restrict SSH access"
'@ | Set-Content $qualysPath -Force
    $findings = Import-TiTCAuditData -InputFile $qualysPath -Format Qualys
    if ($findings.Count -lt 2) { throw "Expected >=2 Qualys findings, got $($findings.Count)" }
}

Test-Step 'C7: Export-TiTCAIReport generates HTML card report' {
    # Build minimal enriched findings
    $enriched = @(
        [PSCustomObject]@{
            FindingId       = 'DRY-001'; Title = 'MFA Not Enforced'; Severity = 'Critical'
            Domain          = 'EntraID'; Description = 'Test'; Remediation = 'Enable MFA'
            ComplianceControls = @('ISO-A.9.4.2'); AffectedResources = @('user@test.com')
            RiskWeight      = 5; Status = 'Open'
            AIExplanation   = 'Without MFA, anyone with your password can access your systems.'
            AIBusinessImpact= 'Credential theft would give attackers full access to corporate data.'
            AIPriority      = 5
        },
        [PSCustomObject]@{
            FindingId       = 'DRY-002'; Title = 'Stale Admin Accounts'; Severity = 'High'
            Domain          = 'EntraID'; Description = 'Test'; Remediation = 'Remove stale accounts'
            ComplianceControls = @(); AffectedResources = @()
            RiskWeight      = 3; Status = 'Open'
            AIExplanation   = 'Old admin accounts are a common entry point for attackers.'
            AIBusinessImpact= 'Unauthorized privileged access.'
            AIPriority      = 4
        }
    )
    $aiHtmlPath = Join-Path $outRoot 'report\ai-briefing.html'
    $out = Export-TiTCAIReport `
        -Findings $enriched `
        -OutputPath $aiHtmlPath `
        -TenantName 'DryRun Corp' `
        -CompanyName 'AuditXpert'
    if (-not (Test-Path $out)) { throw "AI HTML not written: $out" }
    $content = Get-Content $out -Raw
    if ($content -notmatch 'MFA Not Enforced') { throw 'Finding title not in AI report' }
    if ($content -notmatch 'Critical')          { throw 'Severity badge missing in AI report' }
}

# ============================================================================
# PHASE C-8: Metadata
# ============================================================================

Test-Step 'C8: metadata.json written and parseable' {
    $metaPath = Join-Path $outRoot 'metadata.json'
    @{
        GeneratedAt    = (Get-Date -Format 'yyyy-MM-ddTHH:mm:ssZ')
        TenantId       = $script:report.TenantId
        TenantName     = $script:report.TenantName
        AuditPacks     = @('ISO27001','CyberInsurance')
        ToolVersion    = '1.0.0'
        OverallScore   = $script:summary.OverallScore
        OverallRating  = $script:summary.OverallRating
        TotalFindings  = $script:summary.TotalFindings
    } | ConvertTo-Json | Set-Content $metaPath -Force
    $meta = Get-Content $metaPath -Raw | ConvertFrom-Json
    if ($meta.TenantId -ne 'dryrun-tenant-id') { throw "TenantId mismatch in metadata" }
}

# ── Results ───────────────────────────────────────────────────────────────────
Write-Host ''
Write-Host '  Results' -ForegroundColor White
Write-Host '  -----------------------------------------' -ForegroundColor DarkGray

foreach ($r in $results) {
    if ($r.Status -eq 'PASS') {
        Write-Host "  PASS  $($r.Name)" -ForegroundColor Green
    } else {
        Write-Host "  FAIL  $($r.Name)" -ForegroundColor Red
        Write-Host "        $($r.Detail)" -ForegroundColor DarkRed
    }
}

Write-Host ''
$color = if ($fail -eq 0) { 'Green' } else { 'Red' }
Write-Host "  TOTAL: $pass passed, $fail failed" -ForegroundColor $color
Write-Host "  Output: $outRoot" -ForegroundColor DarkGray
Write-Host ''

# Cleanup temp CSV test files
Remove-Item $csvTestPath -ErrorAction SilentlyContinue
Remove-Item (Join-Path $env:TEMP 'titc-test-qualys.csv') -ErrorAction SilentlyContinue

if ($fail -gt 0) { exit 1 }
