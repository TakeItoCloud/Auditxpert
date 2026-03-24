#Requires -Version 5.1
<#
.SYNOPSIS
    Focused regression tests for TiTC.Core collector outcome tracking.
#>

BeforeAll {
    $ProjectRoot = Split-Path $PSScriptRoot -Parent
    Import-Module (Join-Path $ProjectRoot 'src\Core\Models\TiTC.Models.psm1') -Force
    Import-Module (Join-Path $ProjectRoot 'src\Core\TiTC.Core.psm1') -Force
}

Describe 'TiTC.Core collector outcome helpers' {
    It 'tracks explicit skipped outcomes without being overwritten by completion logic' {
        $result = [pscustomobject]@{
            Findings = [System.Collections.ArrayList]::new()
            Metadata = @{}
            Status = 'Success'
        }

        Initialize-TiTCCollectorCheckCatalog -Result $result -CheckSupportMap @{ SignInRisk = 'AppOnlyPreferred' }
        Set-TiTCCollectorCheckOutcome -Result $result -CheckName 'SignInRisk' -Status SkippedInsufficientPermissions -Reason 'Missing consent' -Support 'AppOnlyPreferred'
        Complete-TiTCCollectorCheckOutcome -Result $result -CheckName 'SignInRisk' -FindingsBefore 0

        $result.Metadata.CheckResults['SignInRisk'].Status | Should -Be 'SkippedInsufficientPermissions'
        $result.Metadata.CheckResults['SignInRisk'].Support | Should -Be 'AppOnlyPreferred'
    }

    It 'marks checks with new findings as FindingDetected' {
        $result = [pscustomobject]@{
            Findings = [System.Collections.ArrayList]::new()
            Metadata = @{}
            Status = 'Success'
        }

        Initialize-TiTCCollectorCheckCatalog -Result $result -CheckSupportMap @{ MFA = 'FullySupported' }
        $null = $result.Findings.Add([pscustomobject]@{ Severity = 'High' })
        Complete-TiTCCollectorCheckOutcome -Result $result -CheckName 'MFA' -FindingsBefore 0

        $result.Metadata.CheckResults['MFA'].Status | Should -Be 'FindingDetected'
    }

    It 'accepts the collector array shape used by entry-point scripts in the assessment summary' {
        InModuleScope 'TiTC.Core' {
            Mock Write-Host {}
            Mock Write-TiTCLog {}
            Mock Get-TiTCApiCallSummary { return $null }

            $collector = [pscustomobject]@{
                Domain = 'EntraID'
                Status = 'PartialSuccess'
                Findings = @([pscustomobject]@{ Severity = 'High' })
                ObjectsScanned = 5
                Metadata = @{
                    CheckResults = @{
                        MFA = @{ Status = 'FindingDetected' }
                        SignInRisk = @{ Status = 'SkippedInsufficientPermissions' }
                    }
                }
            }

            $report = [pscustomobject]@{
                AllFindings = @([pscustomobject]@{ Severity = 'High' })
                EstimatedWaste = 0
            }

            { Write-TiTCAssessmentSummary -Report $report -CollectorResults @($collector) -Outputs @{} -Profile 'Full' } | Should -Not -Throw
            Should -Invoke Write-Host -ParameterFilter { $Object -like '*permission-skipped*' -and $Object -like '*PartialSuccess*' }
        }
    }

    It 'finalizes collector status as Skipped when every check is skipped' {
        $result = [pscustomobject]@{
            Findings = [System.Collections.ArrayList]::new()
            Metadata = @{
                CheckResults = @{
                    TransportRules = @{ Status = 'SkippedUnsupportedMode'; Support = 'ExchangeOnlineManagementRequired' }
                    AntiPhishing = @{ Status = 'SkippedUnsupportedMode'; Support = 'ExchangeOnlineManagementRequired' }
                }
            }
            Status = 'Success'
        }

        Finalize-TiTCCollectorOutcome -Result $result

        $result.Status | Should -Be 'Skipped'
    }

    It 'finalizes collector status as PartialSuccess when a check truly fails' {
        $result = [pscustomobject]@{
            Findings = [System.Collections.ArrayList]::new()
            Metadata = @{
                CheckResults = @{
                    MFA = @{ Status = 'Passed'; Support = 'FullySupported' }
                    SignInRisk = @{ Status = 'Failed'; Support = 'AppOnlyPreferred' }
                }
            }
            Status = 'Success'
        }

        Finalize-TiTCCollectorOutcome -Result $result

        $result.Status | Should -Be 'PartialSuccess'
    }
}
