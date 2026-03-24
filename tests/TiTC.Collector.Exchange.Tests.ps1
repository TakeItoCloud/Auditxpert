#Requires -Version 5.1
<#
.SYNOPSIS
    Focused regression tests for TiTC.Collector.Exchange.
#>

BeforeAll {
    $ProjectRoot = Split-Path $PSScriptRoot -Parent
    Import-Module (Join-Path $ProjectRoot 'src\Core\Models\TiTC.Models.psm1') -Force
    Import-Module (Join-Path $ProjectRoot 'src\Core\TiTC.Core.psm1') -Force
    Import-Module (Join-Path $ProjectRoot 'src\Collectors\TiTC.Collector.Exchange.psm1') -Force
}

Describe 'TiTC.Collector.Exchange unsupported Graph fallbacks' {
    It 'skips transport rule analysis cleanly when ExchangeOnlineManagement is unavailable' {
        InModuleScope 'TiTC.Collector.Exchange' {
            Mock Write-TiTCLog {}
            Mock Invoke-TiTCGraphRequest { throw 'Graph should not be called for transport rules without EXO.' }

            $result = [pscustomobject]@{
                Findings = [System.Collections.ArrayList]::new()
                Warnings = @()
                RawData = @{}
            }

            { Test-TiTCTransportRules -Config @{} -Result $result -ExoConnected:$false } | Should -Not -Throw
            $result.RawData['TransportRules'].Status | Should -Be 'Skipped'
            Should -Invoke Invoke-TiTCGraphRequest -Times 0
        }
    }

    It 'skips anti-phishing analysis cleanly when ExchangeOnlineManagement is unavailable' {
        InModuleScope 'TiTC.Collector.Exchange' {
            Mock Write-TiTCLog {}
            Mock Invoke-TiTCGraphRequest { throw 'Graph should not be called for anti-phishing without EXO.' }

            $result = [pscustomobject]@{
                Findings = [System.Collections.ArrayList]::new()
                Warnings = @()
                RawData = @{}
            }

            { Test-TiTCAntiPhishingPolicies -Config @{} -Result $result -ExoConnected:$false } | Should -Not -Throw
            $result.RawData['AntiPhishing'].Status | Should -Be 'Skipped'
            Should -Invoke Invoke-TiTCGraphRequest -Times 0
        }
    }

    It 'skips shared mailbox analysis cleanly when ExchangeOnlineManagement is unavailable' {
        InModuleScope 'TiTC.Collector.Exchange' {
            Mock Write-TiTCLog {}
            Mock Invoke-TiTCGraphRequest { throw 'Graph should not be called for shared mailbox analysis without EXO.' }

            $result = [pscustomobject]@{
                Findings = [System.Collections.ArrayList]::new()
                Warnings = @()
                RawData = @{}
            }

            { Test-TiTCSharedMailboxSecurity -Config @{} -Result $result -ExoConnected:$false } | Should -Not -Throw
            $result.RawData['SharedMailboxes'].Status | Should -Be 'Skipped'
            Should -Invoke Invoke-TiTCGraphRequest -Times 0
        }
    }
}
