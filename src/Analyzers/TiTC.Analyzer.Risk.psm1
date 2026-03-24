#Requires -Version 5.1
<#
.SYNOPSIS
    TakeItToCloud.Assess — Risk Analysis & Scoring Engine (Layer 2).

.DESCRIPTION
    Consumes CollectorResult objects from Layer 1, performs multi-dimensional
    risk analysis, and produces:

    - Weighted composite risk score (0-100)
    - Per-domain risk breakdown
    - Risk category scores (Identity, Data Protection, Endpoint, Threat Detection)
    - Compliance gap analysis against selected frameworks
    - Remediation priority matrix (effort vs impact)
    - Executive risk narrative
    - Trend comparison (if historical data available)

    The scoring model is configurable via assessment profiles and weights can
    be tuned per customer vertical (finance, healthcare, MSP, etc.).

.NOTES
    Module:     TiTC.Analyzer.Risk
    Author:     TakeItToCloud
    Version:    1.0.0
#>

# ============================================================================
# MODULE DEPENDENCIES
# ============================================================================

$CorePath = Join-Path (Split-Path $PSScriptRoot -Parent) 'Core\TiTC.Core.psm1'
if (Test-Path $CorePath) { Import-Module $CorePath -ErrorAction Stop }

$ModelsPath = Join-Path (Split-Path $PSScriptRoot -Parent) 'Core\Models\TiTC.Models.psm1'
if (Test-Path $ModelsPath) { Import-Module $ModelsPath -ErrorAction Stop }

# ============================================================================
# CONSTANTS
# ============================================================================

$script:COMPONENT = 'Analyzer.Risk'

# Risk categories map findings to security pillars
$script:RISK_CATEGORIES = @{
    'Identity & Access'    = @{
        Tags     = @('MFA', 'Identity', 'PrivilegedAccess', 'PIM', 'StandingAccess',
                      'ConditionalAccess', 'LegacyAuth', 'AuthMethods', 'Passwordless',
                      'FIDO2', 'NumberMatching', 'MFAFatigue', 'PasswordPolicy',
                      'AccountHygiene', 'StaleAccounts', 'Lifecycle', 'GuestAccess',
                      'ExternalIdentity')
        Weight   = 35
        MaxScore = 100
    }
    'Data Protection'      = @{
        Tags     = @('ExternalForwarding', 'DataExfiltration', 'DataFlow',
                      'SharedMailbox', 'TransportRules', 'Encryption', 'DLP',
                      'InformationProtection', 'AutoForwarding', 'RemoteDomains')
        Weight   = 25
        MaxScore = 100
    }
    'Threat Detection'     = @{
        Tags     = @('IdentityProtection', 'SignInRisk', 'UserRisk',
                      'ActiveThreat', 'RiskyUsers', 'ThreatDetection',
                      'AntiPhishing', 'Impersonation', 'BEC', 'Spoofing',
                      'SafeLinks', 'SafeAttachments', 'DefenderForOffice365',
                      'Malware', 'EmailSecurity', 'URLProtection')
        Weight   = 25
        MaxScore = 100
    }
    'Device & Endpoint'    = @{
        Tags     = @('Intune', 'DeviceCompliance', 'Encryption', 'BitLocker',
                      'WindowsUpdate', 'PatchManagement', 'EndpointSecurity',
                      'DefenderForEndpoint', 'MDM', 'MAM')
        Weight   = 10
        MaxScore = 100
    }
    'Governance & Config'  = @{
        Tags     = @('Applications', 'Credentials', 'Permissions', 'LeastPrivilege',
                      'ServicePrincipal', 'NonHuman', 'LongLived', 'Expired',
                      'PolicyCoverage', 'CoverageGap', 'Exclusions', 'Groups',
                      'AttackSurface', 'Connectors', 'TLS', 'DMARC',
                      'EmailAuthentication', 'OWA', 'CostOptimization', 'License')
        Weight   = 5
        MaxScore = 100
    }
}

# Remediation effort estimates (hours)
$script:EFFORT_ESTIMATES = @{
    'Critical' = @{ Low = 1; Medium = 4; High = 16 }
    'High'     = @{ Low = 2; Medium = 8; High = 24 }
    'Medium'   = @{ Low = 1; Medium = 4; High = 12 }
    'Low'      = @{ Low = 0.5; Medium = 2; High = 8 }
}

# ============================================================================
# MAIN ANALYSIS ENTRY POINT
# ============================================================================

function Invoke-TiTCRiskAnalysis {
    <#
    .SYNOPSIS
        Performs comprehensive risk analysis on collector results.

    .DESCRIPTION
        Takes one or more CollectorResult objects and produces a complete
        risk analysis including scoring, categorization, compliance gaps,
        and remediation prioritization.

    .PARAMETER CollectorResults
        Array of TiTCCollectorResult objects from Layer 1 collectors.

    .PARAMETER Config
        Assessment configuration hashtable.

    .PARAMETER ComplianceFrameworks
        Compliance frameworks to evaluate against.

    .PARAMETER HistoricalReport
        Previous assessment report for trend comparison.

    .OUTPUTS
        Hashtable containing the complete risk analysis.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $CollectorResults,

        [hashtable]$Config = @{},

        [ValidateSet('ISO27001', 'SOC2Lite', 'CyberInsurance', 'CISControls', 'InternalRisk', 'All')]
        [string[]]$ComplianceFrameworks = @('ISO27001', 'CyberInsurance'),

        [hashtable]$HistoricalReport
    )

    Write-TiTCLog "═══ Starting risk analysis engine ═══" -Level Info -Component $script:COMPONENT

    if (-not $Config.Thresholds) {
        $Config = Get-TiTCConfig -ProfileName Full
    }

    $analysisStart = Get-Date

    # ── Aggregate all findings ──────────────────────────────────────
    $allFindings = $CollectorResults | ForEach-Object { $_.Findings } | Where-Object { $_ }
    Write-TiTCLog "Analyzing $($allFindings.Count) findings from $($CollectorResults.Count) collectors" -Level Info -Component $script:COMPONENT

    # ── Core scoring ────────────────────────────────────────────────
    $riskScore = Get-TiTCCompositeRiskScore -Findings $allFindings -Config $Config
    Write-TiTCLog "Composite risk score: $($riskScore.OverallScore)/100 ($($riskScore.OverallRating))" -Level Info -Component $script:COMPONENT

    # ── Category analysis ───────────────────────────────────────────
    $categoryScores = Get-TiTCCategoryScores -Findings $allFindings
    Write-TiTCLog "Category analysis complete" -Level Info -Component $script:COMPONENT

    # ── Severity distribution ───────────────────────────────────────
    $severityDist = Get-TiTCSeverityDistribution -Findings $allFindings

    # ── Remediation prioritization ──────────────────────────────────
    $remediationPlan = Get-TiTCRemediationPriorities -Findings $allFindings
    Write-TiTCLog "Remediation plan: $($remediationPlan.Count) items prioritized" -Level Info -Component $script:COMPONENT

    # ── Compliance gap analysis ─────────────────────────────────────
    $complianceGaps = @{}
    if ($ComplianceFrameworks -contains 'All') {
        $ComplianceFrameworks = @('ISO27001', 'SOC2Lite', 'CyberInsurance', 'CISControls', 'InternalRisk')
    }

    foreach ($framework in $ComplianceFrameworks) {
        $complianceGaps[$framework] = Get-TiTCComplianceGapAnalysis `
            -Findings $allFindings `
            -Framework $framework `
            -Config $Config
    }
    Write-TiTCLog "Compliance gap analysis complete for: $($ComplianceFrameworks -join ', ')" -Level Info -Component $script:COMPONENT

    # ── Trend analysis ──────────────────────────────────────────────
    $trend = $null
    if ($HistoricalReport) {
        $trend = Get-TiTCTrendAnalysis -CurrentFindings $allFindings -HistoricalReport $HistoricalReport
        Write-TiTCLog "Trend analysis: score moved from $($trend.PreviousScore) to $($riskScore.OverallScore)" -Level Info -Component $script:COMPONENT
    }

    # ── Quick wins identification ───────────────────────────────────
    $quickWins = Get-TiTCQuickWins -Findings $allFindings

    # ── Executive narrative ─────────────────────────────────────────
    $narrative = Get-TiTCExecutiveNarrative `
        -RiskScore $riskScore `
        -CategoryScores $categoryScores `
        -SeverityDist $severityDist `
        -ComplianceGaps $complianceGaps `
        -QuickWins $quickWins

    $analysisDuration = ((Get-Date) - $analysisStart).TotalSeconds

    # ── Assemble complete analysis ──────────────────────────────────
    $analysis = [ordered]@{
        # Metadata
        AnalysisVersion    = '1.0.0'
        AnalyzedAt         = (Get-Date -Format 'o')
        DurationSeconds    = [Math]::Round($analysisDuration, 2)
        FindingsAnalyzed   = $allFindings.Count
        CollectorsUsed     = $CollectorResults.Count

        # Scoring
        RiskScore          = $riskScore
        CategoryScores     = $categoryScores
        SeverityDistribution = $severityDist

        # Remediation
        RemediationPlan    = $remediationPlan
        QuickWins          = $quickWins
        EstimatedEffortHours = ($remediationPlan | Measure-Object -Property EstimatedHours -Sum).Sum

        # Compliance
        ComplianceGaps     = $complianceGaps

        # Trend
        Trend              = $trend

        # Narrative
        ExecutiveNarrative = $narrative

        # Raw
        AllFindings        = $allFindings
    }

    Write-TiTCLog "═══ Risk analysis complete ($([Math]::Round($analysisDuration, 1))s) ═══" -Level Success -Component $script:COMPONENT

    return $analysis
}

# ============================================================================
# COMPOSITE RISK SCORING
# ============================================================================

function Get-TiTCCompositeRiskScore {
    <#
    .SYNOPSIS
        Calculates the weighted composite risk score (0-100).

    .DESCRIPTION
        Uses a multi-factor scoring model:
        1. Base score from finding severity × risk weight
        2. Domain weight adjustment from config
        3. Penalty multipliers for critical/high clusters
        4. Credit for remediated findings
    #>
    [CmdletBinding()]
    param(
        $Findings,
        [hashtable]$Config
    )

    $score = New-TiTCRiskScore
    $score.Calculate($Findings)

    # ── Apply domain weight adjustments ─────────────────────────────
    $configWeights = $Config.Weights
    if ($configWeights -and $configWeights.Count -gt 0) {
        $weightedTotal = 0
        $weightSum = 0

        foreach ($domainKey in $score.DomainScores.Keys) {
            $domainWeight = $configWeights[$domainKey]
            if (-not $domainWeight) { $domainWeight = 10 }

            $weightedTotal += $score.DomainScores[$domainKey].Score * $domainWeight
            $weightSum += $domainWeight
        }

        if ($weightSum -gt 0) {
            $score.OverallScore = [Math]::Round($weightedTotal / $weightSum, 1)
            $score.OverallRating = $score.GetRating($score.OverallScore)
        }
    }

    # ── Critical cluster penalty ────────────────────────────────────
    # If multiple critical findings exist in the same domain, apply penalty
    $criticalByDomain = $Findings |
        Where-Object { $_.Severity -eq 'Critical' -and $_.Status -eq 'Open' } |
        Group-Object Domain

    foreach ($group in $criticalByDomain) {
        if ($group.Count -ge 3) {
            # 3+ critical findings in one domain = add 5 points penalty
            $score.OverallScore = [Math]::Min(100, $score.OverallScore + 5)
            Write-TiTCLog "Critical cluster penalty: $($group.Name) has $($group.Count) critical findings" -Level Debug -Component $script:COMPONENT
        }
    }

    # ── Remediation credit ──────────────────────────────────────────
    $remediatedCount = ($Findings | Where-Object { $_.Status -eq 'Remediated' }).Count
    if ($remediatedCount -gt 0 -and $Findings.Count -gt 0) {
        $remediatedRatio = $remediatedCount / $Findings.Count
        $credit = [Math]::Min(10, $remediatedRatio * 15)
        $score.OverallScore = [Math]::Max(0, $score.OverallScore - $credit)
    }

    $score.OverallScore = [Math]::Round($score.OverallScore, 1)
    $score.OverallRating = $score.GetRating($score.OverallScore)

    return $score
}

# ============================================================================
# CATEGORY SCORING
# ============================================================================

function Get-TiTCCategoryScores {
    <#
    .SYNOPSIS
        Scores findings by security category (pillar) rather than domain.

    .DESCRIPTION
        Maps findings to categories via their Tags property, then calculates
        a score for each category. This provides a different view than
        domain-based scoring — a single finding can contribute to multiple
        categories.
    #>
    [CmdletBinding()]
    param(
        $Findings
    )

    $categoryResults = [ordered]@{}

    foreach ($catName in $script:RISK_CATEGORIES.Keys) {
        $catConfig = $script:RISK_CATEGORIES[$catName]
        $catTags = $catConfig.Tags

        # Find findings whose tags overlap with this category
        $catFindings = $Findings | Where-Object {
            $findingTags = $_.Tags
            $overlap = $findingTags | Where-Object { $_ -in $catTags }
            $overlap.Count -gt 0
        }

        $openFindings = $catFindings | Where-Object { $_.Status -eq 'Open' -or $_.Status -eq 'InProgress' }

        # Calculate category risk
        $catRisk = 0
        $catMax = 0

        foreach ($f in $catFindings) {
            $sm = switch ($f.Severity) {
                'Critical' { 10 }; 'High' { 7 }; 'Medium' { 4 }; 'Low' { 2 }; 'Info' { 0 }
            }
            $w = [Math]::Max(1, [Math]::Min(10, $f.RiskWeight))

            if ($f.Status -eq 'Open' -or $f.Status -eq 'InProgress') {
                $catRisk += ($sm * $w)
            }
            $catMax += (10 * $w)
        }

        $catScore = if ($catMax -gt 0) {
            [Math]::Round(($catRisk / $catMax) * 100, 1)
        } else { 0 }

        $rating = switch ($catScore) {
            { $_ -le 10 } { 'A+' }; { $_ -le 20 } { 'A' }; { $_ -le 30 } { 'B+' }
            { $_ -le 40 } { 'B' }; { $_ -le 50 } { 'C+' }; { $_ -le 60 } { 'C' }
            { $_ -le 70 } { 'D' }; { $_ -le 80 } { 'D-' }; default { 'F' }
        }

        $categoryResults[$catName] = [ordered]@{
            Score        = $catScore
            Rating       = $rating
            Weight       = $catConfig.Weight
            TotalFindings = $catFindings.Count
            OpenFindings = $openFindings.Count
            Critical     = ($openFindings | Where-Object { $_.Severity -eq 'Critical' }).Count
            High         = ($openFindings | Where-Object { $_.Severity -eq 'High' }).Count
            Medium       = ($openFindings | Where-Object { $_.Severity -eq 'Medium' }).Count
            Low          = ($openFindings | Where-Object { $_.Severity -eq 'Low' }).Count
            TopFindings  = ($openFindings |
                Sort-Object @{E={switch($_.Severity){'Critical'{4};'High'{3};'Medium'{2};'Low'{1};default{0}}}; A=$false}, RiskWeight -Descending |
                Select-Object -First 3 |
                ForEach-Object { $_.ToSummary() })
        }
    }

    return $categoryResults
}

# ============================================================================
# SEVERITY DISTRIBUTION
# ============================================================================

function Get-TiTCSeverityDistribution {
    [CmdletBinding()]
    param($Findings)

    $open = $Findings | Where-Object { $_.Status -eq 'Open' -or $_.Status -eq 'InProgress' }

    return [ordered]@{
        Total    = $Findings.Count
        Open     = $open.Count
        Critical = ($open | Where-Object { $_.Severity -eq 'Critical' }).Count
        High     = ($open | Where-Object { $_.Severity -eq 'High' }).Count
        Medium   = ($open | Where-Object { $_.Severity -eq 'Medium' }).Count
        Low      = ($open | Where-Object { $_.Severity -eq 'Low' }).Count
        Info     = ($open | Where-Object { $_.Severity -eq 'Info' }).Count
        Remediated   = ($Findings | Where-Object { $_.Status -eq 'Remediated' }).Count
        Accepted     = ($Findings | Where-Object { $_.Status -eq 'Accepted' }).Count
        NotApplicable = ($Findings | Where-Object { $_.Status -eq 'NotApplicable' }).Count
    }
}

# ============================================================================
# REMEDIATION PRIORITIZATION
# ============================================================================

function Get-TiTCRemediationPriorities {
    <#
    .SYNOPSIS
        Creates a prioritized remediation plan ranked by impact vs effort.

    .DESCRIPTION
        Each finding gets a priority score based on:
        - Severity (Critical=10, High=7, Medium=4, Low=2)
        - Risk weight (1-10 from finding)
        - Compliance impact (more frameworks affected = higher priority)
        - Estimated effort (quick wins ranked higher)

        Output is sorted by priority score descending.
    #>
    [CmdletBinding()]
    param($Findings)

    $openFindings = $Findings | Where-Object { $_.Status -eq 'Open' -or $_.Status -eq 'InProgress' }

    $prioritized = foreach ($f in $openFindings) {
        $severityMultiplier = switch ($f.Severity) {
            'Critical' { 10 }; 'High' { 7 }; 'Medium' { 4 }; 'Low' { 2 }; 'Info' { 0 }
        }

        $complianceImpact = [Math]::Min(5, $f.ComplianceControls.Count)
        $affectedScale = switch ($f.AffectedResources.Count) {
            { $_ -gt 100 } { 3 }
            { $_ -gt 20 }  { 2 }
            { $_ -gt 5 }   { 1.5 }
            default         { 1 }
        }

        # Estimate effort
        $effortCategory = if ($f.RemediationScript) { 'Low' }
                         elseif ($f.RemediationUrl)  { 'Medium' }
                         else                         { 'High' }

        $effortHours = $script:EFFORT_ESTIMATES[$f.Severity.ToString()][$effortCategory]

        # Priority score: higher = fix first
        $priorityScore = ($severityMultiplier * $f.RiskWeight * $affectedScale) +
                         ($complianceImpact * 2) -
                         ($effortHours * 0.5)

        [PSCustomObject]@{
            FindingId        = $f.FindingId
            Title            = $f.Title
            Severity         = $f.Severity.ToString()
            Domain           = $f.Domain.ToString()
            PriorityScore    = [Math]::Round($priorityScore, 1)
            RiskWeight       = $f.RiskWeight
            AffectedCount    = $f.AffectedResources.Count
            ComplianceControls = $f.ComplianceControls.Count
            EffortCategory   = $effortCategory
            EstimatedHours   = $effortHours
            HasScript        = [bool]$f.RemediationScript
            HasDocLink       = [bool]$f.RemediationUrl
            Remediation      = $f.Remediation
        }
    }

    return $prioritized | Sort-Object PriorityScore -Descending
}

# ============================================================================
# QUICK WINS
# ============================================================================

function Get-TiTCQuickWins {
    <#
    .SYNOPSIS
        Identifies findings that can be fixed quickly with high impact.
    #>
    [CmdletBinding()]
    param($Findings)

    $openFindings = $Findings | Where-Object { $_.Status -eq 'Open' }

    $quickWins = $openFindings | Where-Object {
        # Has a script = automatable
        ($_.RemediationScript -and $_.Severity -in @('Critical', 'High', 'Medium')) -or
        # High severity with few affected resources = scoped fix
        ($_.Severity -in @('Critical', 'High') -and $_.AffectedResources.Count -le 10 -and $_.AffectedResources.Count -gt 0) -or
        # Policy change (CA, auth methods) = single config change with broad impact
        ($_.Tags -match 'ConditionalAccess|AuthMethods|PasswordPolicy' -and $_.Severity -in @('Critical', 'High'))
    } | Sort-Object @{E={switch($_.Severity){'Critical'{4};'High'{3};'Medium'{2};default{1}}}; A=$false} |
        Select-Object -First 5

    return $quickWins | ForEach-Object {
        [ordered]@{
            FindingId   = $_.FindingId
            Title       = $_.Title
            Severity    = $_.Severity.ToString()
            Domain      = $_.Domain.ToString()
            WhyQuickWin = if ($_.RemediationScript) { 'Automatable with included script' }
                         elseif ($_.AffectedResources.Count -le 10) { "Only $($_.AffectedResources.Count) resources to fix" }
                         else { 'Single policy change with broad security impact' }
            Remediation = $_.Remediation
        }
    }
}

# ============================================================================
# COMPLIANCE GAP ANALYSIS
# ============================================================================

function Get-TiTCComplianceGapAnalysis {
    <#
    .SYNOPSIS
        Evaluates findings against a compliance framework.

    .DESCRIPTION
        Loads the framework mapping file, maps findings to controls via their
        ComplianceControls property, and calculates coverage percentage.
    #>
    [CmdletBinding()]
    param(
        $Findings,

        [ValidateSet('ISO27001', 'SOC2Lite', 'CyberInsurance', 'CISControls', 'InternalRisk')]
        [string]$Framework,

        [hashtable]$Config
    )

    # Map framework to file
    $frameworkFiles = @{
        'ISO27001'       = 'iso27001.json'
        'CyberInsurance' = 'cyber-insurance.json'
        'SOC2Lite'       = 'soc2-lite.json'
        'CISControls'    = 'cis-controls.json'
        'InternalRisk'   = 'internal-risk.json'
    }

    $compliancePath = Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) "compliance\$($frameworkFiles[$Framework])"

    if (-not (Test-Path $compliancePath)) {
        Write-TiTCLog "Compliance mapping file not found: $compliancePath" -Level Warning -Component $script:COMPONENT
        return @{
            Framework      = $Framework
            Status         = 'MappingFileNotFound'
            CoveragePercent = 0
        }
    }

    $frameworkData = Get-Content $compliancePath -Raw | ConvertFrom-Json
    $controls = $frameworkData.controls
    $controlKeys = $controls | Get-Member -MemberType NoteProperty | Select-Object -ExpandProperty Name

    $controlResults = [ordered]@{}
    $totalControls = 0
    $coveredControls = 0
    $failedControls = 0

    foreach ($controlId in $controlKeys) {
        $control = $controls.$controlId
        $totalControls++

        # Find findings that map to this control
        $prefix = switch ($Framework) {
            'ISO27001'       { 'ISO27001' }
            'CyberInsurance' { 'CI' }
            'SOC2Lite'       { 'SOC2' }
            'CISControls'    { 'CIS' }
            'InternalRisk'   { 'IR' }
        }

        $matchingFindings = $Findings | Where-Object {
            $_.ComplianceControls | Where-Object { $_ -match "^$prefix" -or $_ -match $controlId }
        }

        $openIssues = $matchingFindings | Where-Object { $_.Status -eq 'Open' -or $_.Status -eq 'InProgress' }
        $criticalOrHigh = $openIssues | Where-Object { $_.Severity -in @('Critical', 'High') }

        # Determine control status
        $controlStatus = if ($matchingFindings.Count -eq 0) {
            'NotAssessed'
        }
        elseif ($criticalOrHigh.Count -gt 0) {
            $failedControls++
            'NonCompliant'
        }
        elseif ($openIssues.Count -gt 0) {
            'PartiallyCompliant'
            $coveredControls += 0.5
        }
        else {
            $coveredControls++
            'Compliant'
        }

        $controlResults[$controlId] = [ordered]@{
            Title        = $control.title
            Status       = $controlStatus
            FindingCount = $matchingFindings.Count
            OpenIssues   = $openIssues.Count
            CriticalHigh = $criticalOrHigh.Count
            Findings     = ($matchingFindings | ForEach-Object { $_.FindingId })
            Required     = if ($null -ne $control.required) { $control.required } else { $true }
        }
    }

    $coveragePercent = if ($totalControls -gt 0) {
        [Math]::Round(($coveredControls / $totalControls) * 100, 1)
    } else { 0 }

    $requiredControls = $controlResults.Values | Where-Object { $_.Required -eq $true }
    $requiredMet = ($requiredControls | Where-Object { $_.Status -eq 'Compliant' }).Count
    $requiredTotal = $requiredControls.Count
    $requiredCoverage = if ($requiredTotal -gt 0) {
        [Math]::Round(($requiredMet / $requiredTotal) * 100, 1)
    } else { 0 }

    return [ordered]@{
        Framework           = $Framework
        FrameworkName       = $frameworkData.framework
        TotalControls       = $totalControls
        Compliant           = [int]$coveredControls
        NonCompliant        = $failedControls
        PartiallyCompliant  = ($controlResults.Values | Where-Object { $_.Status -eq 'PartiallyCompliant' }).Count
        NotAssessed         = ($controlResults.Values | Where-Object { $_.Status -eq 'NotAssessed' }).Count
        CoveragePercent     = $coveragePercent
        RequiredCoverage    = $requiredCoverage
        ControlDetails      = $controlResults
        GapSummary          = ($controlResults.GetEnumerator() |
            Where-Object { $_.Value.Status -eq 'NonCompliant' } |
            ForEach-Object { "$($_.Key): $($_.Value.Title)" })
    }
}

# ============================================================================
# TREND ANALYSIS
# ============================================================================

function Get-TiTCTrendAnalysis {
    <#
    .SYNOPSIS
        Compares current findings with a historical report for trend detection.
    #>
    [CmdletBinding()]
    param(
        $CurrentFindings,
        [hashtable]$HistoricalReport
    )

    $previousScore = if ($HistoricalReport.RiskScore) { $HistoricalReport.RiskScore.OverallScore } else { 0 }
    $previousFindings = if ($HistoricalReport.AllFindings) { $HistoricalReport.AllFindings } else { @() }

    $currentScore = 0
    $currentOpen = ($CurrentFindings | Where-Object { $_.Status -eq 'Open' }).Count

    # Identify new findings (not in previous report)
    $previousIds = $previousFindings | ForEach-Object { $_.FindingId }
    $newFindings = $CurrentFindings | Where-Object { $_.FindingId -notin $previousIds }

    # Identify resolved findings
    $currentIds = $CurrentFindings | ForEach-Object { $_.FindingId }
    $resolvedFindings = $previousFindings | Where-Object {
        $_.FindingId -notin $currentIds -or
        ($_.Status -eq 'Open' -and ($CurrentFindings | Where-Object { $_.FindingId -eq $_.FindingId -and $_.Status -eq 'Remediated' }))
    }

    return [ordered]@{
        PreviousScore     = $previousScore
        PreviousDate      = $HistoricalReport.AssessmentDate
        ScoreChange       = [Math]::Round($currentScore - $previousScore, 1)
        Direction         = if ($currentScore -lt $previousScore) { 'Improved' }
                           elseif ($currentScore -gt $previousScore) { 'Worsened' }
                           else { 'Unchanged' }
        NewFindings       = $newFindings.Count
        ResolvedFindings  = $resolvedFindings.Count
        PreviousOpenCount = ($previousFindings | Where-Object { $_.Status -eq 'Open' }).Count
        CurrentOpenCount  = $currentOpen
    }
}

# ============================================================================
# EXECUTIVE NARRATIVE
# ============================================================================

function Get-TiTCExecutiveNarrative {
    <#
    .SYNOPSIS
        Generates a structured executive narrative from analysis results.

    .DESCRIPTION
        Produces a human-readable summary suitable for the executive section
        of the PDF report. Written in clear business language, not technical jargon.
        Designed to be further enhanced by the AI Explainer (Product 2.2).
    #>
    [CmdletBinding()]
    param(
        $RiskScore,
        [hashtable]$CategoryScores,
        [hashtable]$SeverityDist,
        [hashtable]$ComplianceGaps,
        [array]$QuickWins
    )

    $scoreLabel = switch ($RiskScore.OverallRating) {
        'A+' { 'Excellent' }; 'A'  { 'Strong' }; 'B+' { 'Good' }
        'B'  { 'Fair' };      'C+' { 'Below Average' }; 'C' { 'Concerning' }
        'D'  { 'Poor' };      'D-' { 'Very Poor' }; 'F' { 'Critical' }
    }

    # Identify worst category
    $worstCategory = $CategoryScores.GetEnumerator() |
        Sort-Object { $_.Value.Score } -Descending |
        Select-Object -First 1

    $bestCategory = $CategoryScores.GetEnumerator() |
        Where-Object { $_.Value.TotalFindings -gt 0 } |
        Sort-Object { $_.Value.Score } |
        Select-Object -First 1

    $narrative = [ordered]@{
        OverallAssessment   = "The organization's Microsoft 365 security posture is rated $scoreLabel ($($RiskScore.OverallRating)) with a risk score of $($RiskScore.OverallScore) out of 100. A total of $($SeverityDist.Total) security findings were identified, including $($SeverityDist.Critical) critical and $($SeverityDist.High) high-severity issues requiring immediate attention."

        HighestRiskArea     = if ($worstCategory) {
            "$($worstCategory.Key) is the area of highest concern (rating: $($worstCategory.Value.Rating)) with $($worstCategory.Value.Critical) critical and $($worstCategory.Value.High) high-severity findings."
        } else { "No high-risk areas identified." }

        StrongestArea       = if ($bestCategory) {
            "$($bestCategory.Key) is the strongest area (score: $($bestCategory.Value.Score)/100, rating: $($bestCategory.Value.Rating))."
        } else { "" }

        ImmediateActions    = if ($SeverityDist.Critical -gt 0) {
            "$($SeverityDist.Critical) critical findings require immediate remediation within 48 hours."
        } else {
            "No critical findings identified. Focus remediation on the $($SeverityDist.High) high-severity items."
        }

        ComplianceStatus    = ($ComplianceGaps.GetEnumerator() | ForEach-Object {
            $fwLabel = if ($_.Value.FrameworkName) { $_.Value.FrameworkName } else { $_.Key }
            $fwCov   = if ($null -ne $_.Value.CoveragePercent) { $_.Value.CoveragePercent } else { 0 }
            $fwFail  = if ($null -ne $_.Value.NonCompliant) { $_.Value.NonCompliant } else { 0 }
            "${fwLabel}: ${fwCov}% coverage (${fwFail} non-compliant controls)"
        }) -join '. '

        QuickWinCount       = $QuickWins.Count
        QuickWinSummary     = if ($QuickWins.Count -gt 0) {
            "$($QuickWins.Count) quick wins identified that can significantly improve security posture with minimal effort."
        } else { "" }
    }

    return $narrative
}

# ============================================================================
# EXPORTS
# ============================================================================

Export-ModuleMember -Function @(
    'Invoke-TiTCRiskAnalysis'
    'Get-TiTCCompositeRiskScore'
    'Get-TiTCCategoryScores'
    'Get-TiTCRemediationPriorities'
    'Get-TiTCComplianceGapAnalysis'
    'Get-TiTCQuickWins'
    'Get-TiTCExecutiveNarrative'
    'Get-TiTCSeverityDistribution'
)
