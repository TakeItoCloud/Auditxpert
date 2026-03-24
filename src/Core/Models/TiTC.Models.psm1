#Requires -Version 5.1
<#
.SYNOPSIS
    TakeItToCloud.Assess — Shared data models and schema definitions.

.DESCRIPTION
    Defines the standardized data contracts used across all collectors, analyzers,
    and output generators. Every component in the platform communicates through
    these models, ensuring consistency across Product 1 (Snapshot), Product 2
    (MSP Packs), and Product 2.2 (AI Explainer).

.NOTES
    Module:     TiTC.Models
    Author:     TakeItToCloud
    Version:    1.0.0
#>

# ============================================================================
# ENUMS
# ============================================================================

enum TiTCSeverity {
    Info        = 0
    Low         = 1
    Medium      = 2
    High        = 3
    Critical    = 4
}

enum TiTCDomain {
    EntraID
    Exchange
    Intune
    Defender
    Licensing
    SharePoint
    Teams
    Purview
}

enum TiTCComplianceFramework {
    ISO27001
    SOC2Lite
    CyberInsurance
    CISControls
    InternalRisk
    NIST
}

enum TiTCFindingStatus {
    Open
    Remediated
    Accepted
    InProgress
    NotApplicable
}

enum TiTCCollectorStatus {
    Success
    PartialSuccess
    Failed
    Skipped
    AuthError
}

# ============================================================================
# CLASS: TiTCFinding — A single security/compliance finding
# ============================================================================

class TiTCFinding {
    # Identity
    [string]$FindingId
    [string]$Title
    [string]$Description

    # Classification
    [TiTCSeverity]$Severity
    [TiTCDomain]$Domain
    [TiTCFindingStatus]$Status = [TiTCFindingStatus]::Open

    # Scoring
    [int]$RiskWeight = 1                  # 1-10 scale, used by scoring engine
    [double]$RiskScore = 0.0              # Calculated: severity * weight * factor

    # Compliance mapping
    [string[]]$ComplianceControls = @()   # e.g., 'ISO27001:A.9.2.3', 'CIS:1.1.1'
    [string[]]$AffectedResources = @()    # Object IDs, UPNs, or display names

    # Remediation
    [string]$Remediation                  # Plain-English fix
    [string]$RemediationScript            # Optional PowerShell snippet
    [string]$RemediationUrl               # Link to Microsoft docs or KB

    # Evidence
    [hashtable]$Evidence = @{}            # Raw data supporting this finding
    [string]$EvidenceQuery                # Graph/PowerShell query that produced this

    # Metadata
    [datetime]$DetectedAt = (Get-Date -Format 'o' | Get-Date)
    [string]$DetectedBy                   # Collector module that found this
    [string[]]$Tags = @()                 # Freeform tags for filtering

    # AI Explainer fields (populated by Layer 3)
    [string]$AIExplanation
    [string]$AIBusinessImpact
    [int]$AIPriority = 0                  # 1-5, set by AI analysis

    TiTCFinding() {
        $this.FindingId = "TITC-$(Get-Random -Minimum 10000 -Maximum 99999)"
    }

    [string] ToSummary() {
        return "[{0}] {1}: {2}" -f $this.Severity, $this.FindingId, $this.Title
    }
}

# ============================================================================
# CLASS: TiTCCollectorResult — Output from a single collector run
# ============================================================================

class TiTCCollectorResult {
    [TiTCDomain]$Domain
    [TiTCCollectorStatus]$Status = [TiTCCollectorStatus]::Success
    [string]$CollectorVersion = '1.0.0'

    # Timing
    [datetime]$StartedAt
    [datetime]$CompletedAt
    [double]$DurationSeconds

    # Data
    [TiTCFinding[]]$Findings = @()
    [hashtable]$RawData = @{}              # Full collector output for evidence packs
    [hashtable]$Metadata = @{}             # Tenant info, permissions used, etc.

    # Errors
    [string[]]$Errors = @()
    [string[]]$Warnings = @()
    [int]$ApiCallCount = 0

    # Counts
    [int]$ObjectsScanned = 0
    [int]$FindingsCount = 0

    [void] Complete() {
        $this.CompletedAt = Get-Date
        $this.DurationSeconds = ($this.CompletedAt - $this.StartedAt).TotalSeconds
        $this.FindingsCount = $this.Findings.Count
    }

    [hashtable] ToSummary() {
        return @{
            Domain           = $this.Domain.ToString()
            Status           = $this.Status.ToString()
            Duration         = '{0:N1}s' -f $this.DurationSeconds
            ObjectsScanned   = $this.ObjectsScanned
            Findings         = $this.FindingsCount
            Critical         = ($this.Findings | Where-Object { $_.Severity -eq 'Critical' }).Count
            High             = ($this.Findings | Where-Object { $_.Severity -eq 'High' }).Count
            Errors           = $this.Errors.Count
        }
    }
}

# ============================================================================
# CLASS: TiTCRiskScore — Aggregated risk assessment
# ============================================================================

class TiTCRiskScore {
    [double]$OverallScore = 0.0            # 0-100 (0 = perfect, 100 = critical)
    [string]$OverallRating                  # A+ through F
    [hashtable]$DomainScores = @{}          # Per-domain breakdown
    [hashtable]$CategoryScores = @{}        # Identity, Data, Endpoint, etc.

    # Benchmarking
    [double]$IndustryAverage = 0.0
    [string]$Percentile

    [string] GetRating([double]$score) {
        switch ($score) {
            { $_ -le 10 } { return 'A+' }
            { $_ -le 20 } { return 'A'  }
            { $_ -le 30 } { return 'B+' }
            { $_ -le 40 } { return 'B'  }
            { $_ -le 50 } { return 'C+' }
            { $_ -le 60 } { return 'C'  }
            { $_ -le 70 } { return 'D'  }
            { $_ -le 80 } { return 'D-' }
            default        { return 'F'  }
        }
        return 'F'
    }

    [void] Calculate([TiTCFinding[]]$findings) {
        if ($findings.Count -eq 0) {
            $this.OverallScore = 0
            $this.OverallRating = $this.GetRating(0)
            return
        }

        # Weighted severity scoring
        $maxPossible = 0
        $actualRisk = 0

        foreach ($f in $findings) {
            $severityMultiplier = switch ($f.Severity) {
                'Critical' { 10 }
                'High'     { 7  }
                'Medium'   { 4  }
                'Low'      { 2  }
                'Info'     { 0  }
            }

            $weight = [Math]::Max(1, [Math]::Min(10, $f.RiskWeight))
            $itemRisk = $severityMultiplier * $weight

            if ($f.Status -eq 'Open' -or $f.Status -eq 'InProgress') {
                $actualRisk += $itemRisk
            }
            $maxPossible += (10 * $weight)  # Max severity * weight
        }

        if ($maxPossible -gt 0) {
            $this.OverallScore = [Math]::Round(($actualRisk / $maxPossible) * 100, 1)
        }

        $this.OverallRating = $this.GetRating($this.OverallScore)

        # Per-domain breakdown
        $domains = $findings | Group-Object -Property Domain
        foreach ($group in $domains) {
            $domainFindings = $group.Group
            $domainMax = 0
            $domainActual = 0

            foreach ($f in $domainFindings) {
                $sm = switch ($f.Severity) {
                    'Critical' { 10 }; 'High' { 7 }; 'Medium' { 4 }; 'Low' { 2 }; 'Info' { 0 }
                }
                $w = [Math]::Max(1, [Math]::Min(10, $f.RiskWeight))
                if ($f.Status -eq 'Open' -or $f.Status -eq 'InProgress') {
                    $domainActual += ($sm * $w)
                }
                $domainMax += (10 * $w)
            }

            $domainScore = if ($domainMax -gt 0) {
                [Math]::Round(($domainActual / $domainMax) * 100, 1)
            } else { 0 }

            $this.DomainScores[$group.Name] = @{
                Score    = $domainScore
                Rating   = $this.GetRating($domainScore)
                Findings = $domainFindings.Count
                Critical = ($domainFindings | Where-Object { $_.Severity -eq 'Critical' }).Count
                High     = ($domainFindings | Where-Object { $_.Severity -eq 'High' }).Count
            }
        }
    }
}

# ============================================================================
# CLASS: TiTCAssessmentReport — Complete assessment output
# ============================================================================

class TiTCAssessmentReport {
    # Identity
    [string]$ReportId
    [string]$ReportTitle = 'M365 Security & Compliance Assessment'
    [string]$ReportVersion = '1.0.0'

    # Tenant
    [string]$TenantId
    [string]$TenantName
    [string]$TenantDomain

    # Timing
    [datetime]$AssessmentDate = (Get-Date)
    [double]$TotalDurationSeconds

    # Results
    [TiTCRiskScore]$RiskScore
    [TiTCCollectorResult[]]$CollectorResults = @()
    [TiTCFinding[]]$AllFindings = @()

    # License analysis
    [hashtable]$LicenseSummary = @{}
    [double]$EstimatedWaste = 0.0          # Monthly cost waste in EUR

    # Compliance
    [hashtable]$CompliancePosture = @{}     # Framework → coverage percentage

    # Metadata
    [string]$AssessedBy = 'TakeItToCloud.Assess'
    [string]$AssessmentProfile              # Which profile was used (full, quick, msp-audit)
    [string[]]$DomainsAssessed = @()
    [hashtable]$PermissionsUsed = @{}

    TiTCAssessmentReport() {
        $this.ReportId = "TITC-RPT-{0:yyyyMMdd}-{1}" -f (Get-Date), (Get-Random -Minimum 1000 -Maximum 9999)
        $this.RiskScore = [TiTCRiskScore]::new()
    }

    [void] AggregateFindings() {
        $this.AllFindings = $this.CollectorResults | ForEach-Object { $_.Findings } | Where-Object { $_ }
        $this.RiskScore.Calculate($this.AllFindings)
        $this.DomainsAssessed = ($this.CollectorResults | ForEach-Object { $_.Domain.ToString() }) | Select-Object -Unique
    }

    [hashtable] ToExecutiveSummary() {
        return @{
            ReportId         = $this.ReportId
            TenantName       = $this.TenantName
            AssessmentDate   = $this.AssessmentDate.ToString('yyyy-MM-dd')
            OverallScore     = $this.RiskScore.OverallScore
            OverallRating    = $this.RiskScore.OverallRating
            TotalFindings    = $this.AllFindings.Count
            CriticalFindings = ($this.AllFindings | Where-Object { $_.Severity -eq 'Critical' }).Count
            HighFindings     = ($this.AllFindings | Where-Object { $_.Severity -eq 'High' }).Count
            DomainsAssessed  = $this.DomainsAssessed
            LicenseWaste     = '€{0:N0}/month' -f $this.EstimatedWaste
            DomainScores     = $this.RiskScore.DomainScores
        }
    }
}

# ============================================================================
# CLASS: TiTCLicenseWaste — License optimization finding
# ============================================================================

class TiTCLicenseWaste {
    [string]$SkuName
    [string]$SkuId
    [int]$TotalLicenses
    [int]$AssignedLicenses
    [int]$ConsumedLicenses
    [int]$UnusedLicenses
    [double]$MonthlyUnitCost              # EUR
    [double]$MonthlyWaste                 # EUR
    [double]$AnnualWaste                  # EUR
    [string]$Recommendation

    [void] Calculate() {
        $this.UnusedLicenses = $this.TotalLicenses - $this.ConsumedLicenses
        $this.MonthlyWaste = $this.UnusedLicenses * $this.MonthlyUnitCost
        $this.AnnualWaste = $this.MonthlyWaste * 12
    }
}

# ============================================================================
# FACTORY FUNCTIONS
# ============================================================================

function New-TiTCFinding {
    [CmdletBinding()]
    [OutputType([TiTCFinding])]
    param(
        [Parameter(Mandatory)]
        [string]$Title,

        [Parameter(Mandatory)]
        [string]$Description,

        [Parameter(Mandatory)]
        [TiTCSeverity]$Severity,

        [Parameter(Mandatory)]
        [TiTCDomain]$Domain,

        [string]$Remediation,
        [string]$RemediationUrl,
        [string]$RemediationScript,
        [int]$RiskWeight = 1,
        [string[]]$ComplianceControls = @(),
        [string[]]$AffectedResources = @(),
        [hashtable]$Evidence = @{},
        [string]$EvidenceQuery,
        [string]$DetectedBy,
        [string[]]$Tags = @()
    )

    $finding = [TiTCFinding]::new()
    $finding.Title = $Title
    $finding.Description = $Description
    $finding.Severity = $Severity
    $finding.Domain = $Domain
    $finding.Remediation = $Remediation
    $finding.RemediationUrl = $RemediationUrl
    $finding.RemediationScript = $RemediationScript
    $finding.RiskWeight = $RiskWeight
    $finding.ComplianceControls = $ComplianceControls
    $finding.AffectedResources = $AffectedResources
    $finding.Evidence = $Evidence
    $finding.EvidenceQuery = $EvidenceQuery
    $finding.DetectedBy = $DetectedBy
    $finding.Tags = $Tags

    return $finding
}

function New-TiTCCollectorResult {
    [CmdletBinding()]
    [OutputType([TiTCCollectorResult])]
    param(
        [Parameter(Mandatory)]
        [TiTCDomain]$Domain
    )

    $result = [TiTCCollectorResult]::new()
    $result.Domain = $Domain
    $result.StartedAt = Get-Date
    return $result
}

function New-TiTCAssessmentReport {
    [CmdletBinding()]
    [OutputType([TiTCAssessmentReport])]
    param()
    return [TiTCAssessmentReport]::new()
}

function New-TiTCRiskScore {
    [CmdletBinding()]
    [OutputType([TiTCRiskScore])]
    param()
    return [TiTCRiskScore]::new()
}

function New-TiTCLicenseWaste {
    [CmdletBinding()]
    [OutputType([TiTCLicenseWaste])]
    param()
    return [TiTCLicenseWaste]::new()
}

# ============================================================================
# EXPORTS
# ============================================================================

Export-ModuleMember -Function @(
    'New-TiTCFinding'
    'New-TiTCCollectorResult'
    'New-TiTCAssessmentReport'
    'New-TiTCRiskScore'
    'New-TiTCLicenseWaste'
)
