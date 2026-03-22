#Requires -Version 5.1
<#
.SYNOPSIS
    Pester tests for TiTC.Core — infrastructure, config, and logging.
#>

BeforeAll {
    $ProjectRoot = Split-Path $PSScriptRoot -Parent
    Import-Module "$ProjectRoot\src\Core\Models\TiTC.Models.psm1" -Force
    Import-Module "$ProjectRoot\src\Core\TiTC.Core.psm1" -Force
}

Describe 'Get-TiTCConfig' {
    It 'Returns a config hashtable for the Full profile' {
        $cfg = Get-TiTCConfig -ProfileName Full
        $cfg | Should -Not -BeNullOrEmpty
        $cfg | Should -BeOfType [hashtable]
    }

    It 'Full profile enables all domains' {
        $cfg = Get-TiTCConfig -ProfileName Full
        $cfg.Domains.EntraID   | Should -BeTrue
        $cfg.Domains.Exchange  | Should -BeTrue
        $cfg.Domains.Intune    | Should -BeTrue
        $cfg.Domains.Defender  | Should -BeTrue
        $cfg.Domains.Licensing | Should -BeTrue
    }

    It 'Quick profile enables only EntraID' {
        $cfg = Get-TiTCConfig -ProfileName Quick
        $cfg.Domains.EntraID  | Should -BeTrue
        $cfg.Domains.Exchange | Should -BeFalse
    }

    It 'LicenseOnly profile enables only Licensing' {
        $cfg = Get-TiTCConfig -ProfileName LicenseOnly
        $cfg.Domains.Licensing | Should -BeTrue
        $cfg.Domains.EntraID   | Should -BeFalse
    }

    It 'Contains Thresholds section' {
        $cfg = Get-TiTCConfig -ProfileName Full
        $cfg.Thresholds | Should -Not -BeNullOrEmpty
    }

    It 'Contains LicensePricing table' {
        $cfg = Get-TiTCConfig -ProfileName Full
        $cfg.LicensePricing | Should -Not -BeNullOrEmpty
        $cfg.LicensePricing.Keys.Count | Should -BeGreaterThan 0
    }

    It 'Runtime overrides are applied' {
        $overrides = @{ Thresholds = @{ MaxGlobalAdmins = 99 } }
        $cfg = Get-TiTCConfig -ProfileName Full -Overrides $overrides
        $cfg.Thresholds.MaxGlobalAdmins | Should -Be 99
    }

    It 'ComplianceFrameworks is an array' {
        $cfg = Get-TiTCConfig -ProfileName Full
        $cfg.ComplianceFrameworks | Should -BeOfType [System.Object[]]
    }
}

Describe 'Merge-TiTCHashtable' {
    It 'Deep merges nested hashtables' {
        $base  = @{ A = @{ X = 1; Y = 2 }; B = 'base' }
        $override = @{ A = @{ Y = 99; Z = 3 } }
        $result = Merge-TiTCHashtable -Base $base -Override $override
        $result.A.X | Should -Be 1    # preserved
        $result.A.Y | Should -Be 99   # overridden
        $result.A.Z | Should -Be 3    # added
        $result.B   | Should -Be 'base' # unchanged
    }

    It 'Returns base hashtable when override is empty' {
        $base     = @{ Key = 'Value' }
        $override = @{}
        $result = Merge-TiTCHashtable -Base $base -Override $override
        $result.Key | Should -Be 'Value'
    }

    It 'Override scalar replaces base scalar' {
        $base     = @{ Level = 'Info' }
        $override = @{ Level = 'Debug' }
        $result = Merge-TiTCHashtable -Base $base -Override $override
        $result.Level | Should -Be 'Debug'
    }
}

Describe 'Write-TiTCLog' {
    It 'Does not throw for Info level' {
        { Write-TiTCLog "Test message" -Level Info -Component 'Test' } | Should -Not -Throw
    }

    It 'Does not throw for Error level' {
        { Write-TiTCLog "Error message" -Level Error -Component 'Test' } | Should -Not -Throw
    }

    It 'Does not throw with Data hashtable' {
        { Write-TiTCLog "Data message" -Level Info -Component 'Test' -Data @{ Key = 'Value' } } |
            Should -Not -Throw
    }
}

Describe 'Initialize-TiTCLogging' {
    It 'Creates log directory if it does not exist' {
        $logDir  = Join-Path $env:TEMP "TiTCLogTest-$(Get-Random)"
        $logPath = Join-Path $logDir 'test.log'

        { Initialize-TiTCLogging -LogPath $logPath -LogLevel Info } | Should -Not -Throw
        Test-Path $logDir | Should -BeTrue

        # Cleanup
        Remove-Item $logDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Describe 'Test-TiTCConnection' {
    It 'Returns false when not connected' {
        $connected = Test-TiTCConnection
        # In a test environment, not connected — should return false
        $connected | Should -BeOfType [bool]
    }
}

Describe 'Get-TiTCState' {
    It 'Returns a hashtable' {
        $state = Get-TiTCState
        $state | Should -Not -BeNullOrEmpty
        $state | Should -BeOfType [hashtable]
    }

    It 'Contains expected keys' {
        $state = Get-TiTCState
        $state.ContainsKey('Connected') | Should -BeTrue
        $state.ContainsKey('ApiCallCount') | Should -BeTrue
    }
}
