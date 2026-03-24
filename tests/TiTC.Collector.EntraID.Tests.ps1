#Requires -Version 5.1
<#
.SYNOPSIS
    Focused regression tests for TiTC.Collector.EntraID.
#>

BeforeAll {
    $ProjectRoot = Split-Path $PSScriptRoot -Parent
    Import-Module (Join-Path $ProjectRoot 'src\Core\Models\TiTC.Models.psm1') -Force
    Import-Module (Join-Path $ProjectRoot 'src\Core\TiTC.Core.psm1') -Force
    Import-Module (Join-Path $ProjectRoot 'src\Collectors\TiTC.Collector.EntraID.psm1') -Force
}

Describe 'TiTC.Collector.EntraID sign-in risk checks' {
    It 'marks risky users as skipped when Graph returns insufficient permissions' {
        InModuleScope 'TiTC.Collector.EntraID' {
            Mock Write-TiTCLog {}
            Mock Invoke-TiTCGraphRequest {
                if ($Endpoint -eq '/identity/conditionalAccess/policies') {
                    return @{ value = @() }
                }

                if ($Endpoint -eq '/identityProtection/riskyUsers') {
                    throw 'Insufficient permissions for /identityProtection/riskyUsers. Ensure the app has the required Graph API permissions.'
                }

                throw "Unexpected endpoint: $Endpoint"
            }

            $result = [pscustomobject]@{
                Findings = [System.Collections.ArrayList]::new()
                Warnings = @()
                RawData = @{}
            }

            { Test-TiTCSignInRiskPolicies -Config @{} -Result $result } | Should -Not -Throw
            $result.RawData['SignInRisk'].RiskyUsersStatus | Should -Be 'SkippedInsufficientPermissions'
            $result.RawData['SignInRisk'].RiskyUsersCount | Should -Be 0
            $result.Warnings | Should -Contain 'Risky users check skipped: insufficient delegated permission, admin consent, or Entra ID P2 licensing for Identity Protection.'
        }
    }

    It 'records no-data status when the risky users query succeeds with an empty result' {
        InModuleScope 'TiTC.Collector.EntraID' {
            Mock Write-TiTCLog {}
            Mock Invoke-TiTCGraphRequest {
                if ($Endpoint -eq '/identity/conditionalAccess/policies') {
                    return @{ value = @() }
                }

                if ($Endpoint -eq '/identityProtection/riskyUsers') {
                    return @{ value = @() }
                }

                throw "Unexpected endpoint: $Endpoint"
            }

            $result = [pscustomobject]@{
                Findings = [System.Collections.ArrayList]::new()
                Warnings = @()
                RawData = @{}
            }

            { Test-TiTCSignInRiskPolicies -Config @{} -Result $result } | Should -Not -Throw
            $result.RawData['SignInRisk'].RiskyUsersStatus | Should -Be 'NoData'
            $result.RawData['SignInRisk'].RiskyUsersCount | Should -Be 0
            @($result.Findings).Count | Should -Be 2
        }
    }
}
