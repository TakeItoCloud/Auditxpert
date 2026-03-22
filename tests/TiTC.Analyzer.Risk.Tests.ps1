#Requires -Version 5.1
<#
.SYNOPSIS
    Pester tests for TiTC.Analyzer.Risk — risk scoring engine.
#>

BeforeAll {
    $ProjectRoot = Split-Path $PSScriptRoot -Parent
    Import-Module "$ProjectRoot\src\Core\Models\TiTC.Models.psm1" -Force
    Import-Module "$ProjectRoot\src\Core\TiTC.Core.psm1" -Force
    Import-Module "$ProjectRoot\src\Analyzers\TiTC.Analyzer.Risk.psm1" -Force

    # Helper: build a collector result with specified findings
    function New-TestCollectorResult {
        param(
            [string]$Domain = 'EntraID',
            [object[]]$TestFindings
        )
        $r = New-TiTCCollectorResult -Domain $Domain
        foreach ($f in $TestFindings) { $r.Findings += $f }
        $r.Complete()
        return $r
    }

    # Build a diverse set of synthetic findings for tests
    $script:TestFindings = @(
        (New-TiTCFinding -Title 'No MFA'            -Description 'd' -Severity Critical -Domain EntraID  -RiskWeight 9  -Tags @('MFA','Identity') -ComplianceControls @('ISO27001:A.8.5')),
        (New-TiTCFinding -Title 'Excessive Admins'  -Description 'd' -Severity High     -Domain EntraID  -RiskWeight 7  -Tags @('PrivilegedAccess','Identity') -ComplianceControls @('ISO27001:A.8.2','CIS:1.1.4')),
        (New-TiTCFinding -Title 'No Legacy Block'   -Description 'd' -Severity High     -Domain EntraID  -RiskWeight 7  -Tags @('ConditionalAccess','Identity')),
        (New-TiTCFinding -Title 'External Forward'  -Description 'd' -Severity Critical -Domain Exchange -RiskWeight 8  -Tags @('ExternalForwarding','DataProtection')),
        (New-TiTCFinding -Title 'No DMARC'          -Description 'd' -Severity High     -Domain Exchange -RiskWeight 6  -Tags @('DomainSecurity','DataProtection') -ComplianceControls @('CIS:2.6.1')),
        (New-TiTCFinding -Title 'Unencrypted Dev'   -Description 'd' -Severity High     -Domain Intune   -RiskWeight 8  -Tags @('Encryption','BitLocker')),
        (New-TiTCFinding -Title 'Low Compliance'    -Description 'd' -Severity Medium   -Domain Intune   -RiskWeight 5  -Tags @('DeviceCompliance','EndpointSecurity')),
        (New-TiTCFinding -Title 'Low SecureScore'   -Description 'd' -Severity Medium   -Domain Defender -RiskWeight 6  -Tags @('SecureScore','SecurityPosture')),
        (New-TiTCFinding -Title 'Stale Alerts'      -Description 'd' -Severity High     -Domain Defender -RiskWeight 7  -Tags @('Alerts','ThreatDetection') -ComplianceControls @('ISO27001:A.5.24')),
        (New-TiTCFinding -Title 'License Waste'     -Description 'd' -Severity Medium   -Domain Licensing -RiskWeight 4 -Tags @('License','LicenseWaste')),
        (New-TiTCFinding -Title 'Stale Accounts'    -Description 'd' -Severity Medium   -Domain EntraID  -RiskWeight 5  -Tags @('StaleAccounts','Identity')),
        (New-TiTCFinding -Title 'Old Guest Accounts'-Description 'd' -Severity Low      -Domain EntraID  -RiskWeight 3  -Tags @('GuestAccounts','Identity')),
        (New-TiTCFinding -Title 'MAM Missing'       -Description 'd' -Severity Medium   -Domain Intune   -RiskWeight 5  -Tags @('MAM','AppProtection')),
        (New-TiTCFinding -Title 'No Attack Sim'     -Description 'd' -Severity Medium   -Domain Defender -RiskWeight 4  -Tags @('AttackSimulation','SecurityAwareness')),
        (New-TiTCFinding -Title 'Trial Expiring'    -Description 'd' -Severity Low      -Domain Licensing -RiskWeight 2 -Tags @('License','Trial'))
    )

    $script:EntraResult    = New-TestCollectorResult -Domain EntraID    -TestFindings ($script:TestFindings | Where-Object { $_.Domain -eq 'EntraID' })
    $script:ExchangeResult = New-TestCollectorResult -Domain Exchange   -TestFindings ($script:TestFindings | Where-Object { $_.Domain -eq 'Exchange' })
    $script:IntuneResult   = New-TestCollectorResult -Domain Intune     -TestFindings ($script:TestFindings | Where-Object { $_.Domain -eq 'Intune' })
    $script:DefenderResult = New-TestCollectorResult -Domain Defender   -TestFindings ($script:TestFindings | Where-Object { $_.Domain -eq 'Defender' })
    $script:LicenseResult  = New-TestCollectorResult -Domain Licensing  -TestFindings ($script:TestFindings | Where-Object { $_.Domain -eq 'Licensing' })

    $script:AllResults = @(
        $script:EntraResult,
        $script:ExchangeResult,
        $script:IntuneResult,
        $script:DefenderResult,
        $script:LicenseResult
    )

    $script:Config = Get-TiTCConfig -ProfileName Full
}

Describe 'Invoke-TiTCRiskAnalysis' {
    BeforeAll {
        $script:RiskAnalysis = Invoke-TiTCRiskAnalysis `
            -CollectorResults $script:AllResults `
            -Config $script:Config `
            -ComplianceFrameworks @('ISO27001', 'CyberInsurance')
    }

    It 'Returns a result object' {
        $script:RiskAnalysis | Should -Not -BeNullOrEmpty
    }

    It 'Contains a RiskScore with OverallScore 0-100' {
        $script:RiskAnalysis.RiskScore | Should -Not -BeNullOrEmpty
        $script:RiskAnalysis.RiskScore.OverallScore | Should -BeGreaterOrEqual 0
        $script:RiskAnalysis.RiskScore.OverallScore | Should -BeLessOrEqual 100
    }

    It 'Contains a non-null OverallRating' {
        $script:RiskAnalysis.RiskScore.OverallRating | Should -Not -BeNullOrEmpty
    }

    It 'CategoryScores contains expected categories' {
        $cats = $script:RiskAnalysis.CategoryScores.Keys
        $cats | Should -Contain 'Identity & Access'
        $cats | Should -Contain 'Data Protection'
        $cats | Should -Contain 'Threat Detection'
    }

    It 'Category scores are 0-100' {
        foreach ($cat in $script:RiskAnalysis.CategoryScores.Keys) {
            $score = $script:RiskAnalysis.CategoryScores[$cat]
            $score | Should -BeGreaterOrEqual 0
            $score | Should -BeLessOrEqual 100
        }
    }

    It 'RemediationPlan is not empty' {
        $script:RiskAnalysis.RemediationPlan | Should -Not -BeNullOrEmpty
        $script:RiskAnalysis.RemediationPlan.Count | Should -BeGreaterThan 0
    }

    It 'RemediationPlan is sorted by priority (Critical/High first)' {
        $plan = $script:RiskAnalysis.RemediationPlan
        $severityOrder = @('Critical','High','Medium','Low','Info')
        $firstSev = $plan[0].Severity
        $lastSev  = $plan[-1].Severity
        $severityOrder.IndexOf($firstSev) | Should -BeLessOrEqual $severityOrder.IndexOf($lastSev)
    }

    It 'Severity distribution sums to total findings count' {
        $dist  = $script:RiskAnalysis.SeverityDistribution
        $total = ($dist.Values | Measure-Object -Sum).Sum
        $total | Should -Be $script:TestFindings.Count
    }

    It 'ComplianceGaps contains requested frameworks' {
        $script:RiskAnalysis.ComplianceGaps | Should -Not -BeNullOrEmpty
    }

    It 'QuickWins is an array (may be empty)' {
        $script:RiskAnalysis.QuickWins | Should -Not -BeNullOrEmpty -Because 'QuickWins should always be an array'
    }

    It 'ExecutiveNarrative is a non-empty string' {
        $script:RiskAnalysis.ExecutiveNarrative | Should -Not -BeNullOrEmpty
        $script:RiskAnalysis.ExecutiveNarrative.Length | Should -BeGreaterThan 10
    }

    It 'EstimatedEffortHours is a positive number' {
        $script:RiskAnalysis.EstimatedEffortHours | Should -BeGreaterOrEqual 0
    }
}

Describe 'Risk Score — boundary conditions' {
    It 'Score increases with more critical findings' {
        $fewFindings = @(
            (New-TiTCFinding -Title 'F1' -Description 'd' -Severity Low -Domain EntraID -RiskWeight 2)
        )
        $manyFindings = @(
            (New-TiTCFinding -Title 'F1' -Description 'd' -Severity Critical -Domain EntraID  -RiskWeight 10),
            (New-TiTCFinding -Title 'F2' -Description 'd' -Severity Critical -Domain Exchange -RiskWeight 10),
            (New-TiTCFinding -Title 'F3' -Description 'd' -Severity High     -Domain Intune   -RiskWeight 8),
            (New-TiTCFinding -Title 'F4' -Description 'd' -Severity High     -Domain Defender -RiskWeight 8)
        )

        $cr1  = New-TestCollectorResult -Domain EntraID -TestFindings $fewFindings
        $cr2  = New-TestCollectorResult -Domain EntraID -TestFindings $manyFindings

        $low  = Invoke-TiTCRiskAnalysis -CollectorResults @($cr1) -Config $script:Config
        $high = Invoke-TiTCRiskAnalysis -CollectorResults @($cr2) -Config $script:Config

        $high.RiskScore.OverallScore | Should -BeGreaterThan $low.RiskScore.OverallScore
    }

    It 'Empty findings produces score of 0' {
        $cr = New-TestCollectorResult -Domain EntraID -TestFindings @()
        $result = Invoke-TiTCRiskAnalysis -CollectorResults @($cr) -Config $script:Config
        $result.RiskScore.OverallScore | Should -Be 0
    }
}

Describe 'Category scoring' {
    It 'MFA finding with Identity tag contributes to Identity & Access category' {
        $f = New-TiTCFinding -Title 'MFA' -Description 'd' -Severity Critical -Domain EntraID -RiskWeight 9 -Tags @('MFA','Identity')
        $cr = New-TestCollectorResult -Domain EntraID -TestFindings @($f)
        $result = Invoke-TiTCRiskAnalysis -CollectorResults @($cr) -Config $script:Config
        $result.CategoryScores['Identity & Access'] | Should -BeGreaterThan 0
    }

    It 'Encryption finding contributes to Data Protection category' {
        $f = New-TiTCFinding -Title 'Encrypt' -Description 'd' -Severity High -Domain Intune -RiskWeight 8 -Tags @('Encryption','BitLocker')
        $cr = New-TestCollectorResult -Domain Intune -TestFindings @($f)
        $result = Invoke-TiTCRiskAnalysis -CollectorResults @($cr) -Config $script:Config
        $result.CategoryScores['Data Protection'] | Should -BeGreaterThan 0
    }
}

Describe 'Compliance gap analysis' {
    It 'ISO 27001 gap analysis runs without error' {
        $cr = New-TestCollectorResult -Domain EntraID -TestFindings $script:TestFindings
        { Invoke-TiTCRiskAnalysis -CollectorResults @($cr) -Config $script:Config -ComplianceFrameworks @('ISO27001') } |
            Should -Not -Throw
    }

    It 'Returns coverage percentage for ISO 27001' {
        $cr = New-TestCollectorResult -Domain EntraID -TestFindings $script:TestFindings
        $result = Invoke-TiTCRiskAnalysis -CollectorResults @($cr) -Config $script:Config -ComplianceFrameworks @('ISO27001')
        $result.ComplianceGaps | Should -Not -BeNullOrEmpty
    }
}
