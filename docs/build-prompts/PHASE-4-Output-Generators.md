# PHASE 4 — BUILD: Layer 3 Output Generators
# ═════════════════════════════════════════════
# Pre-requisite: Phases 1-3C complete (all collectors + risk analyzer built)
# ═════════════════════════════════════════════

## CONTEXT
Read `AUDITXPERT-BUILD-SPEC.md`. Root: `C:\Scripts\Assessment\AuditXpert`.
All Layer 1 collectors and Layer 2 analyzer are complete. Now build Layer 3 — the outputs.

## BUILD 3 FILES

---

## FILE 1: HTML/PDF Report Generator
Path: `C:\Scripts\Assessment\AuditXpert\src\Outputs\TiTC.Output.Report.psm1`
Entry point: `Export-TiTCReport`

### Function Signature
```powershell
function Export-TiTCReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$AssessmentData,  # Output from Invoke-TiTCRiskAnalysis
        [Parameter(Mandatory)][TiTCAssessmentReport]$Report,
        [string]$OutputPath = (Join-Path $PWD 'assessment-report.html'),
        [ValidateSet('HTML','PDF')][string]$Format = 'HTML',
        [string]$LogoPath,
        [string]$CompanyName = 'TakeItToCloud',
        [hashtable]$BrandingColors = @{
            Primary = '#0F172A'; Accent = '#10B981'
            Warning = '#F59E0B'; Danger = '#EF4444'
        }
    )
```

### Implementation Approach
Build the HTML as a single self-contained file with inline CSS. Use a `StringBuilder` or `here-string` approach:

```powershell
$css = @"
<style>
    :root {
        --primary: $($BrandingColors.Primary);
        --accent: $($BrandingColors.Accent);
        --warning: $($BrandingColors.Warning);
        --danger: $($BrandingColors.Danger);
    }
    * { margin:0; padding:0; box-sizing:border-box; }
    body { font-family:'Segoe UI','Manrope',-apple-system,sans-serif; color:#1e293b; line-height:1.6; }
    .page { page-break-before:always; padding:40px; }
    .page:first-child { page-break-before:avoid; }
    /* ... all styles inline ... */
    @media print {
        .page { page-break-before:always; }
        .no-print { display:none; }
    }
</style>
"@
```

### Report Sections to Generate (as HTML divs with class="page")

**Section 1 — Cover Page**
```html
<div class="cover-page">
    <img src="[logo]" class="logo" />
    <h1>M365 Security & Compliance Assessment</h1>
    <div class="tenant-name">[TenantName]</div>
    <div class="date">[AssessmentDate]</div>
    <div class="score-badge [color-class]">
        <span class="score">[OverallScore]</span>
        <span class="rating">[OverallRating]</span>
    </div>
    <div class="confidential">CONFIDENTIAL</div>
</div>
```

**Section 2 — Executive Summary**
Render `$AssessmentData.ExecutiveNarrative` fields as formatted paragraphs.

**Section 3 — Risk Score Dashboard**
Build SVG inline for the score gauge:
```powershell
function Get-TiTCScoreGaugeSVG {
    param([double]$Score, [string]$Rating)
    $angle = [Math]::Min(360, $Score * 3.6)
    $color = if ($Score -le 30) { '#10B981' } elseif ($Score -le 60) { '#F59E0B' } else { '#EF4444' }
    # Return SVG circle gauge...
}
```
Category scores as horizontal progress bars. Domain scores as cards in a grid.

**Section 4 — Severity Distribution**
HTML table or inline SVG stacked bar:
```powershell
$dist = $AssessmentData.SeverityDistribution
# Build colored bar segments for Critical/High/Medium/Low
```

**Section 5 — Top 10 Findings**
```powershell
$top10 = $AssessmentData.RemediationPlan | Select-Object -First 10
# Build HTML table with severity color badges
```

**Section 6 — Full Findings Detail**
Group `$Report.AllFindings` by Domain, sort by Severity within each group.
Each finding as a card:
```html
<div class="finding-card severity-[severity]">
    <div class="finding-header">
        <span class="severity-badge">[SEVERITY]</span>
        <span class="finding-id">[FindingId]</span>
    </div>
    <h3>[Title]</h3>
    <p>[Description]</p>
    <div class="affected">Affected: [count] resources</div>
    <div class="remediation">
        <h4>Remediation</h4>
        <p>[Remediation]</p>
        <a href="[RemediationUrl]">Microsoft Documentation →</a>
    </div>
    <div class="compliance-tags">[ComplianceControls as pills]</div>
</div>
```

**Section 7 — Remediation Plan**
HTML table from `$AssessmentData.RemediationPlan`:
Columns: `#, Title, Severity, Domain, Effort (hrs), Has Script, Priority Score`

**Section 8 — Quick Wins**
Highlighted box with `$AssessmentData.QuickWins`.

**Section 9 — Compliance Posture**
For each framework in `$AssessmentData.ComplianceGaps`:
- Framework name + coverage % progress bar
- Table of non-compliant controls

**Section 10 — License Waste** (conditional)
If `$Report.EstimatedWaste -gt 0`, render waste table.

**Section 11 — Appendix**
Methodology, permissions, timestamps, tool version.

### PDF Conversion
```powershell
if ($Format -eq 'PDF') {
    $pdfPath = [System.IO.Path]::ChangeExtension($OutputPath, '.pdf')
    $wk = Get-Command wkhtmltopdf -ErrorAction SilentlyContinue
    if ($wk) {
        & wkhtmltopdf --enable-local-file-access --page-size A4 --margin-top 15mm --margin-bottom 15mm --margin-left 15mm --margin-right 15mm $OutputPath $pdfPath
        Write-TiTCLog "PDF generated: $pdfPath" -Level Success -Component 'Report'
    } else {
        Write-TiTCLog "wkhtmltopdf not found. Open HTML in browser and print to PDF." -Level Warning -Component 'Report'
    }
}
```

### Export
```powershell
Export-ModuleMember -Function @('Export-TiTCReport')
```

---

## FILE 2: Evidence Pack Generator
Path: `C:\Scripts\Assessment\AuditXpert\src\Outputs\TiTC.Output.Evidence.psm1`
Entry point: `Export-TiTCEvidencePack`

### Function Signature
```powershell
function Export-TiTCEvidencePack {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][TiTCAssessmentReport]$Report,
        [Parameter(Mandatory)][hashtable]$RiskAnalysis,
        [Parameter(Mandatory)][string]$OutputPath,
        [ValidateSet('ISO27001','SOC2Lite','CyberInsurance','CISControls','All')]
        [string[]]$Frameworks = @('All'),
        [string]$CompanyName = 'TakeItToCloud'
    )
```

### Implementation
```powershell
# 1. Create base structure
$basePath = Join-Path $OutputPath 'evidence-pack'
New-Item -ItemType Directory -Path $basePath -Force | Out-Null

# 2. Write metadata
$metadata = @{
    GeneratedAt = (Get-Date -Format 'o')
    GeneratedBy = $CompanyName
    Tool        = 'AuditXpert v1.0.0'
    TenantId    = $Report.TenantId
    TenantName  = $Report.TenantName
    Domain      = $Report.TenantDomain
    Frameworks  = $Frameworks
}
$metadata | ConvertTo-Json | Set-Content (Join-Path $basePath 'metadata.json')

# 3. For each framework, create folder structure
$frameworksToProcess = if ($Frameworks -contains 'All') {
    @('ISO27001', 'SOC2Lite', 'CyberInsurance', 'CISControls')
} else { $Frameworks }

foreach ($fw in $frameworksToProcess) {
    $fwPath = Join-Path $basePath $fw
    New-Item -ItemType Directory -Path $fwPath -Force | Out-Null

    # Load framework mapping
    $compliancePath = Join-Path $PSScriptRoot '..\..\compliance'
    $fwFiles = @{
        'ISO27001'       = 'iso27001.json'
        'CyberInsurance' = 'cyber-insurance.json'
        'SOC2Lite'       = 'soc2-lite.json'
        'CISControls'    = 'cis-controls.json'
    }
    $fwFile = Join-Path $compliancePath $fwFiles[$fw]

    if (-not (Test-Path $fwFile)) {
        Write-TiTCLog "Framework file not found: $fwFile" -Level Warning -Component 'Evidence'
        continue
    }

    $fwData = Get-Content $fwFile -Raw | ConvertFrom-Json -AsHashtable

    # 4. Create control-summary.csv
    $controlSummary = foreach ($controlId in $fwData.controls.Keys) {
        $control = $fwData.controls[$controlId]
        $relatedFindings = $Report.AllFindings | Where-Object {
            $_.ComplianceControls -match $controlId
        }
        $openIssues = $relatedFindings | Where-Object { $_.Status -eq 'Open' }

        [PSCustomObject]@{
            ControlId    = $controlId
            Title        = $control.title
            Status       = if ($openIssues.Count -gt 0) { 'Non-Compliant' }
                          elseif ($relatedFindings.Count -gt 0) { 'Compliant' }
                          else { 'Not Assessed' }
            FindingCount = $relatedFindings.Count
            OpenIssues   = $openIssues.Count
            Evidence     = $control.evidence
        }
    }
    $controlSummary | Export-Csv (Join-Path $fwPath 'control-summary.csv') -NoTypeInformation

    # 5. Create per-control evidence folders
    foreach ($controlId in $fwData.controls.Keys) {
        $control = $fwData.controls[$controlId]
        $safeName = $controlId -replace '[^a-zA-Z0-9._-]', '-'
        $controlPath = Join-Path $fwPath "$safeName-$($control.title -replace '[^a-zA-Z0-9 ]','' -replace ' ','-' | Select-Object -First 1)"
        $controlPath = $controlPath.Substring(0, [Math]::Min($controlPath.Length, 100))
        New-Item -ItemType Directory -Path $controlPath -Force | Out-Null

        # Related findings
        $relatedFindings = $Report.AllFindings | Where-Object {
            $_.ComplianceControls -match $controlId
        }
        if ($relatedFindings) {
            $relatedFindings | Select-Object FindingId, Severity, Title, Description, Status, Remediation |
                Export-Csv (Join-Path $controlPath 'findings.csv') -NoTypeInformation
        }

        # Raw evidence from collectors
        $evidenceData = @{}
        foreach ($check in $control.checks) {
            foreach ($cr in $Report.CollectorResults) {
                if ($cr.RawData[$check]) {
                    $evidenceData[$check] = $cr.RawData[$check]
                }
            }
        }
        if ($evidenceData.Count -gt 0) {
            $evidenceData | ConvertTo-Json -Depth 10 |
                Set-Content (Join-Path $controlPath 'evidence.json')
        }
    }
}

# 6. Write summary
$summary = @{
    Frameworks = $frameworksToProcess | ForEach-Object {
        $gaps = $RiskAnalysis.ComplianceGaps[$_]
        @{
            Framework  = $_
            Coverage   = $gaps.CoveragePercent ?? 0
            Compliant  = $gaps.Compliant ?? 0
            NonCompliant = $gaps.NonCompliant ?? 0
        }
    }
}
$summary | ConvertTo-Json -Depth 5 | Set-Content (Join-Path $basePath 'summary.json')

Write-TiTCLog "Evidence pack generated: $basePath" -Level Success -Component 'Evidence'
```

### Export
```powershell
Export-ModuleMember -Function @('Export-TiTCEvidencePack')
```

---

## FILE 3: AI Explainer Integration
Path: `C:\Scripts\Assessment\AuditXpert\src\Outputs\TiTC.Output.AIExplainer.psm1`

This module has TWO entry points:
- `Invoke-TiTCAIExplainer` — Core AI engine (takes TiTCFinding objects)
- `Import-TiTCAuditData` — Input normalizer (converts any format to TiTCFinding objects)
- `Export-TiTCAIReport` — HTML report generator for explainer output

### CRITICAL DESIGN: Multi-Source Input
The AI Explainer is NOT limited to AuditXpert data. It must accept:
1. AuditXpert's own assessment-results.json
2. Third-party audit exports (CSV/JSON from Qualys, Nessus, CIS Benchmark, Defender)
3. Manual findings (simple CSV with Title, Description, Severity columns)

Input folder: `C:\Scripts\Assessment\AuditXpert\input\`
- `input\auditxpert\` — AuditXpert JSON files
- `input\third-party\` — Third-party exports
- `input\manual\` — Manual CSV/JSON

### Function 1: Import-TiTCAuditData (Input Normalizer)
```powershell
function Import-TiTCAuditData {
    [CmdletBinding()]
    [OutputType([TiTCFinding[]])]
    param(
        [Parameter(Mandatory, ParameterSetName = 'File')]
        [string]$InputFile,

        [Parameter(Mandatory, ParameterSetName = 'Folder')]
        [string]$InputFolder,

        [ValidateSet('Auto', 'AuditXpert', 'CSV', 'JSON', 'Qualys', 'Nessus', 'Defender')]
        [string]$Format = 'Auto'
    )

    # Auto-detect format from file extension and content
    # For 'AuditXpert': parse assessment-results.json → extract AllFindings
    # For 'CSV': map columns Title,Description,Severity,Domain → TiTCFinding
    # For 'JSON': check for known structures (Qualys, Nessus, generic)
    # For 'Defender': parse Defender export format
    # For 'Folder': process each file in the folder, return combined findings

    # CSV column mapping (minimum required columns):
    $csvMapping = @{
        'Title'       = @('Title', 'FindingTitle', 'Name', 'Rule', 'CheckName', 'Vulnerability')
        'Description' = @('Description', 'Details', 'Synopsis', 'Summary', 'Info')
        'Severity'    = @('Severity', 'Risk', 'Level', 'Priority', 'RiskLevel', 'Criticality')
        'Domain'      = @('Domain', 'Category', 'Area', 'Component', 'Plugin Family')
    }
    # Map severity strings: Critical/High/Medium/Low/Info + numeric (1-5) + Qualys (1-5)

    # Return: array of TiTCFinding objects
}
```

### Function 2: Invoke-TiTCAIExplainer (Core AI Engine)
```powershell
function Invoke-TiTCAIExplainer {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][TiTCFinding[]]$Findings,
        [ValidateSet('Claude','OpenAI')][string]$Provider = 'Claude',
        [Parameter(Mandatory)][string]$ApiKey,
        [string]$Model,
        [int]$MaxFindings = 50,
        [switch]$HighSeverityOnly
    )

    # Default models
    if (-not $Model) {
        $Model = switch ($Provider) {
            'Claude' { 'claude-sonnet-4-20250514' }
            'OpenAI' { 'gpt-4o' }
        }
    }

    # Filter and sort findings
    $targetFindings = $Findings
    if ($HighSeverityOnly) {
        $targetFindings = $Findings | Where-Object { $_.Severity -in @('Critical', 'High') }
    }
    $targetFindings = $targetFindings |
        Sort-Object @{E={switch($_.Severity){'Critical'{4};'High'{3};'Medium'{2};default{1}}}; A=$false} |
        Select-Object -First $MaxFindings

    # Process each finding individually
    foreach ($finding in $targetFindings) {
        $prompt = @"
You are a cybersecurity analyst writing for a non-technical business executive.
For this security finding, provide exactly this JSON structure (no markdown, no backticks):
{
    "risk": "What is the risk in plain English (2-3 sentences)",
    "impact": "What could happen to the business if not fixed (2-3 sentences)",
    "priority": 1-5 integer (5=fix immediately, 1=nice to have),
    "fix": "What to do in non-technical language (2-3 actionable steps)"
}

Finding: $($finding.Title)
Severity: $($finding.Severity)
Description: $($finding.Description)
Affected: $($finding.AffectedResources.Count) resources
"@

        $aiResponse = Invoke-TiTCAICall -Provider $Provider -ApiKey $ApiKey -Model $Model -Prompt $prompt
        $parsed = $aiResponse | ConvertFrom-Json -ErrorAction Stop

        $finding.AIExplanation = $parsed.risk
        $finding.AIBusinessImpact = $parsed.impact
        $finding.AIPriority = [int]$parsed.priority

        Start-Sleep -Milliseconds 500  # Rate limiting
    }

    return $targetFindings
}
```

### Function 3: Export-TiTCAIReport (HTML Report)
```powershell
function Export-TiTCAIReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][TiTCFinding[]]$Findings,
        [Parameter(Mandatory)][string]$OutputPath,
        [string]$TenantName = 'Assessment',
        [string]$SourceFile = 'manual input',
        [string]$CompanyName = 'TakeItToCloud'
    )

    # Generate self-contained HTML report with this structure:
    # HEADER: Company name, tenant, date, source file, finding count
    # SUMMARY CARDS: 4 metric cards showing P5/P4/P3-1 counts + total
    # FINDINGS: Each finding as a card with 3 AI sections:
    #   - "What's the risk?" (border-left: danger color)
    #   - "Business impact" (border-left: warning color)
    #   - "How to fix this" (border-left: success color)
    #   - Compliance control pills at bottom
    #   - Priority badge (P5=Fix immediately, P4=Fix this week, P3=Fix this month, P2=Plan, P1=Nice to have)
    # FOOTER: Generated by, timestamp, tool version

    # Severity badge colors:
    # Critical = background-danger, High = background-warning,
    # Medium = amber-ish, Low = background-info, Info = gray

    # Priority label mapping:
    # 5 = "Fix immediately" (danger), 4 = "Fix this week" (warning),
    # 3 = "Fix this month" (amber), 2 = "Plan to fix" (info), 1 = "Nice to have" (gray)

    # Sort findings by AIPriority descending (P5 first), then by severity
}
```

### Function 4: Invoke-TiTCAICall (API wrapper — private)
```powershell
function Invoke-TiTCAICall {
    param([string]$Provider, [string]$ApiKey, [string]$Model, [string]$Prompt)

    switch ($Provider) {
        'Claude' {
            $body = @{
                model = $Model; max_tokens = 500
                messages = @(@{ role = 'user'; content = $Prompt })
            } | ConvertTo-Json -Depth 5
            $response = Invoke-RestMethod -Uri 'https://api.anthropic.com/v1/messages' `
                -Method POST -Headers @{
                    'x-api-key' = $ApiKey; 'anthropic-version' = '2023-06-01'
                    'Content-Type' = 'application/json'
                } -Body $body
            return $response.content[0].text
        }
        'OpenAI' {
            $body = @{
                model = $Model; max_tokens = 500
                response_format = @{ type = 'json_object' }
                messages = @(
                    @{ role = 'system'; content = 'Respond only with valid JSON.' }
                    @{ role = 'user'; content = $Prompt }
                )
            } | ConvertTo-Json -Depth 5
            $response = Invoke-RestMethod -Uri 'https://api.openai.com/v1/chat/completions' `
                -Method POST -Headers @{
                    'Authorization' = "Bearer $ApiKey"; 'Content-Type' = 'application/json'
                } -Body $body
            return $response.choices[0].message.content
        }
    }
}

Export-ModuleMember -Function @('Invoke-TiTCAIExplainer', 'Import-TiTCAuditData', 'Export-TiTCAIReport')
```

---

## AFTER BUILDING ALL 3 — UPDATE ORCHESTRATOR
In `profiles\Invoke-M365Snapshot.ps1`, add imports and wire into the pipeline:

```powershell
# Add imports
$reportPath = Join-Path $scriptRoot 'src\Outputs\TiTC.Output.Report.psm1'
$evidencePath = Join-Path $scriptRoot 'src\Outputs\TiTC.Output.Evidence.psm1'
$aiPath = Join-Path $scriptRoot 'src\Outputs\TiTC.Output.AIExplainer.psm1'
Import-Module $reportPath -Force
Import-Module $evidencePath -Force
Import-Module $aiPath -Force

# After risk analysis, generate report:
$reportHtmlPath = Join-Path $OutputPath 'security-assessment-report.html'
Export-TiTCReport -AssessmentData $riskAnalysis -Report $report -OutputPath $reportHtmlPath `
    -Format $OutputFormat -CompanyName ($config.Output.BrandingCompanyName ?? 'TakeItToCloud')

# Generate evidence packs if requested:
if ($config.Output.IncludeEvidence) {
    Export-TiTCEvidencePack -Report $report -RiskAnalysis $riskAnalysis `
        -OutputPath $OutputPath -Frameworks $config.ComplianceFrameworks
}

# Run AI explainer if requested:
if ($IncludeAIExplainer) {
    $aiKey = $env:ANTHROPIC_API_KEY ?? $env:OPENAI_API_KEY
    if ($aiKey) {
        $enrichedFindings = Invoke-TiTCAIExplainer -Findings $report.AllFindings `
            -Provider 'Claude' -ApiKey $aiKey -HighSeverityOnly
        # Generate standalone AI explainer HTML report
        $aiReportPath = Join-Path $OutputPath 'ai-audit-explanation.html'
        Export-TiTCAIReport -Findings $enrichedFindings -OutputPath $aiReportPath `
            -TenantName $report.TenantName
    } else {
        Write-TiTCLog "AI Explainer skipped: set ANTHROPIC_API_KEY or OPENAI_API_KEY environment variable" -Level Warning -Component 'Snapshot'
    }
}
```
