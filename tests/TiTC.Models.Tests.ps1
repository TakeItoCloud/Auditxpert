#Requires -Version 5.1
<#
.SYNOPSIS
    Pester tests for TiTC.Models — data contracts and factory functions.
#>

BeforeAll {
    $ProjectRoot = Split-Path $PSScriptRoot -Parent
    Import-Module "$ProjectRoot\src\Core\Models\TiTC.Models.psm1" -Force
    Import-Module "$ProjectRoot\src\Core\TiTC.Core.psm1" -Force
}

Describe 'New-TiTCFinding' {
    It 'Creates a finding with required parameters' {
        $f = New-TiTCFinding -Title 'Test Finding' -Description 'Test description' -Severity High -Domain EntraID
        $f | Should -Not -BeNullOrEmpty
        $f.Title | Should -Be 'Test Finding'
        $f.Severity | Should -Be 'High'
        $f.Domain | Should -Be 'EntraID'
    }

    It 'Assigns a FindingId in TITC-XXXXX format' {
        $f = New-TiTCFinding -Title 'ID Test' -Description 'desc' -Severity Medium -Domain Exchange
        $f.FindingId | Should -Match '^TITC-\d{5}$'
    }

    It 'Assigns default Status of Open' {
        $f = New-TiTCFinding -Title 'Status Test' -Description 'desc' -Severity Low -Domain Intune
        $f.Status | Should -Be 'Open'
    }

    It 'Stores compliance controls' {
        $f = New-TiTCFinding -Title 'Controls Test' -Description 'desc' -Severity High -Domain EntraID `
            -ComplianceControls @('ISO27001:A.9.2.3', 'CIS:1.1.4')
        $f.ComplianceControls | Should -Contain 'ISO27001:A.9.2.3'
        $f.ComplianceControls | Should -Contain 'CIS:1.1.4'
    }

    It 'Stores affected resources' {
        $resources = @('user1@test.com', 'user2@test.com')
        $f = New-TiTCFinding -Title 'Resources Test' -Description 'desc' -Severity Medium -Domain EntraID `
            -AffectedResources $resources
        $f.AffectedResources.Count | Should -Be 2
    }

    It 'Stores evidence hashtable' {
        $evidence = @{ Count = 5; Threshold = 10 }
        $f = New-TiTCFinding -Title 'Evidence Test' -Description 'desc' -Severity Low -Domain Licensing `
            -Evidence $evidence
        $f.Evidence.Count | Should -Be 5
    }

    It 'Stores tags' {
        $f = New-TiTCFinding -Title 'Tags Test' -Description 'desc' -Severity High -Domain Defender `
            -Tags @('Alerts', 'ThreatDetection')
        $f.Tags | Should -Contain 'Alerts'
        $f.Tags | Should -Contain 'ThreatDetection'
    }

    It 'Records DetectedBy component' {
        $f = New-TiTCFinding -Title 'Component Test' -Description 'desc' -Severity Info -Domain EntraID `
            -DetectedBy 'Collector.EntraID'
        $f.DetectedBy | Should -Be 'Collector.EntraID'
    }

    It 'Stores RiskWeight' {
        $f = New-TiTCFinding -Title 'Weight Test' -Description 'desc' -Severity Critical -Domain Intune `
            -RiskWeight 9
        $f.RiskWeight | Should -Be 9
    }

    It 'Stores remediation text and URL' {
        $f = New-TiTCFinding -Title 'Rem Test' -Description 'desc' -Severity High -Domain Exchange `
            -Remediation 'Enable MFA for all users' `
            -RemediationUrl 'https://learn.microsoft.com/test'
        $f.Remediation | Should -Be 'Enable MFA for all users'
        $f.RemediationUrl | Should -Be 'https://learn.microsoft.com/test'
    }
}

Describe 'TiTCFinding.ToSummary()' {
    It 'Returns a hashtable with expected keys' {
        $f = New-TiTCFinding -Title 'Summary Test' -Description 'desc' -Severity High -Domain EntraID
        $s = $f.ToSummary()
        $s | Should -Not -BeNullOrEmpty
        $s.FindingId | Should -Not -BeNullOrEmpty
        $s.Title    | Should -Be 'Summary Test'
        $s.Severity | Should -Be 'High'
    }
}

Describe 'New-TiTCCollectorResult' {
    It 'Creates a collector result for a given domain' {
        $r = New-TiTCCollectorResult -Domain EntraID
        $r | Should -Not -BeNullOrEmpty
        $r.Domain | Should -Be 'EntraID'
        $r.Status | Should -Be 'Running'
        $r.Findings | Should -Not -BeNullOrEmpty
        $r.Findings.Count | Should -Be 0
    }

    It 'Timestamps start time on creation' {
        $r = New-TiTCCollectorResult -Domain Exchange
        $r.StartTime | Should -Not -BeNullOrEmpty
    }

    It 'Complete() sets EndTime and duration' {
        $r = New-TiTCCollectorResult -Domain Intune
        Start-Sleep -Milliseconds 50
        $r.Complete()
        $r.EndTime | Should -Not -BeNullOrEmpty
        $r.DurationSeconds | Should -BeGreaterThan 0
    }

    It 'Complete() sets Status to Success' {
        $r = New-TiTCCollectorResult -Domain Defender
        $r.Complete()
        $r.Status | Should -Be 'Success'
    }

    It 'FindingsCount reflects added findings' {
        $r = New-TiTCCollectorResult -Domain EntraID
        $r.Findings += New-TiTCFinding -Title 'F1' -Description 'd' -Severity High -Domain EntraID
        $r.Findings += New-TiTCFinding -Title 'F2' -Description 'd' -Severity Medium -Domain EntraID
        $r.FindingsCount | Should -Be 2
    }

    It 'ToSummary() returns a hashtable with finding counts' {
        $r = New-TiTCCollectorResult -Domain Exchange
        $r.Findings += New-TiTCFinding -Title 'F1' -Description 'd' -Severity Critical -Domain Exchange
        $r.Complete()
        $s = $r.ToSummary()
        $s.TotalFindings | Should -Be 1
        $s.Critical | Should -Be 1
    }
}

Describe 'TiTCRiskScore' {
    It 'GetRating() returns A+ for score 0-10' {
        $rs = [TiTCRiskScore]::new()
        $rs.OverallScore = 5
        $rs.GetRating() | Should -Be 'A+'
    }

    It 'GetRating() returns F for score 81-100' {
        $rs = [TiTCRiskScore]::new()
        $rs.OverallScore = 85
        $rs.GetRating() | Should -Be 'F'
    }

    It 'GetRating() returns D for score 61-70' {
        $rs = [TiTCRiskScore]::new()
        $rs.OverallScore = 65
        $rs.GetRating() | Should -Be 'D'
    }

    It 'GetRating() returns B for score 31-40' {
        $rs = [TiTCRiskScore]::new()
        $rs.OverallScore = 35
        $rs.GetRating() | Should -Be 'B'
    }
}

Describe 'TiTCAssessmentReport.AggregateFindings()' {
    It 'Aggregates findings from multiple collector results' {
        $report = [TiTCAssessmentReport]::new()

        $cr1 = New-TiTCCollectorResult -Domain EntraID
        $cr1.Findings += New-TiTCFinding -Title 'F1' -Description 'd' -Severity High    -Domain EntraID
        $cr1.Findings += New-TiTCFinding -Title 'F2' -Description 'd' -Severity Critical -Domain EntraID
        $cr1.Complete()

        $cr2 = New-TiTCCollectorResult -Domain Exchange
        $cr2.Findings += New-TiTCFinding -Title 'F3' -Description 'd' -Severity Medium  -Domain Exchange
        $cr2.Complete()

        $report.CollectorResults += $cr1
        $report.CollectorResults += $cr2
        $report.AggregateFindings()

        $report.AllFindings.Count | Should -Be 3
    }
}

Describe 'TiTCLicenseWaste.Calculate()' {
    It 'Calculates unused licenses and monthly waste' {
        $w = [TiTCLicenseWaste]::new()
        $w.SkuName         = 'Microsoft 365 E3'
        $w.TotalLicenses   = 100
        $w.ConsumedLicenses = 70
        $w.MonthlyUnitCost = 33.00
        $w.Calculate()

        $w.UnusedLicenses | Should -Be 30
        $w.MonthlyWaste   | Should -Be 990.0
        $w.AnnualWaste    | Should -Be 11880.0
    }

    It 'Handles zero unused (no waste)' {
        $w = [TiTCLicenseWaste]::new()
        $w.TotalLicenses   = 50
        $w.ConsumedLicenses = 50
        $w.MonthlyUnitCost = 54.75
        $w.Calculate()

        $w.UnusedLicenses | Should -Be 0
        $w.MonthlyWaste   | Should -Be 0.0
    }
}
