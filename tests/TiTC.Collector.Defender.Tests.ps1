#Requires -Version 5.1
<#
.SYNOPSIS
    Focused regression tests for TiTC.Collector.Defender.
#>

BeforeAll {
    $ProjectRoot = Split-Path $PSScriptRoot -Parent
    Import-Module (Join-Path $ProjectRoot 'src\Core\Models\TiTC.Models.psm1') -Force
    Import-Module (Join-Path $ProjectRoot 'src\Core\TiTC.Core.psm1') -Force
    Import-Module (Join-Path $ProjectRoot 'src\Collectors\TiTC.Collector.Defender.psm1') -Force
}

Describe 'TiTC.Collector.Defender incident paging' {
    It 'requests /security/incidents with Top 50 and AllPages enabled' {
        InModuleScope 'TiTC.Collector.Defender' {
            Mock Write-TiTCLog {}
            Mock Invoke-TiTCGraphRequest {
                throw 'stop after verifying incidents query shape'
            } -ParameterFilter {
                $Endpoint -eq '/security/incidents' -and
                $Top -eq 50 -and
                $AllPages.IsPresent -and
                $Filter -eq "status ne 'resolved'"
            }

            $result = [pscustomobject]@{
                ObjectsScanned = 0
                RawData = @{}
                Findings = [System.Collections.ArrayList]::new()
            }

            { Test-TiTCIncidents -Config @{} -Result $result } | Should -Not -Throw

            Should -Invoke Invoke-TiTCGraphRequest -Times 1 -Exactly -ParameterFilter {
                $Endpoint -eq '/security/incidents' -and
                $Top -eq 50 -and
                $AllPages.IsPresent -and
                $Filter -eq "status ne 'resolved'"
            }
        }
    }
}
