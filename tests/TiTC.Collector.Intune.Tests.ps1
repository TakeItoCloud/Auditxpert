#Requires -Version 5.1
<#
.SYNOPSIS
    Focused regression tests for TiTC.Collector.Intune.
#>

BeforeAll {
    $ProjectRoot = Split-Path $PSScriptRoot -Parent
    Import-Module (Join-Path $ProjectRoot 'src\Core\Models\TiTC.Models.psm1') -Force
    Import-Module (Join-Path $ProjectRoot 'src\Core\TiTC.Core.psm1') -Force
    Import-Module (Join-Path $ProjectRoot 'src\Collectors\TiTC.Collector.Intune.psm1') -Force
}

Describe 'TiTC.Collector.Intune OS update compliance' {
    It 'does not throw when managed devices are empty' {
        InModuleScope 'TiTC.Collector.Intune' {
            Mock Write-TiTCLog {}
            Mock Invoke-TiTCGraphRequest {
                if ($Endpoint -eq '/deviceManagement/managedDevices') {
                    return @{ value = @() }
                }

                return @{ value = @() }
            }

            $result = [pscustomobject]@{
                ObjectsScanned = 0
                RawData = @{}
                Findings = [System.Collections.ArrayList]::new()
            }

            { Test-TiTCOSUpdateCompliance -Config @{} -Result $result } | Should -Not -Throw
            @($result.RawData['OutdatedDevices']).Count | Should -Be 0
        }
    }

    It 'does not throw when a device record is missing operatingSystem or osVersion' {
        InModuleScope 'TiTC.Collector.Intune' {
            Mock Write-TiTCLog {}
            Mock Invoke-TiTCGraphRequest {
                if ($Endpoint -eq '/deviceManagement/managedDevices') {
                    return @{
                        value = @(
                            [pscustomobject]@{
                                deviceName = 'Unknown OS Device'
                                operatingSystem = $null
                                osVersion = '10.0.19044'
                                userPrincipalName = 'user1@contoso.com'
                            },
                            [pscustomobject]@{
                                deviceName = 'Unknown Version Device'
                                operatingSystem = 'Windows'
                                osVersion = $null
                                userPrincipalName = 'user2@contoso.com'
                            }
                        )
                    }
                }

                return @{ value = @() }
            }

            $result = [pscustomobject]@{
                ObjectsScanned = 0
                RawData = @{}
                Findings = [System.Collections.ArrayList]::new()
            }

            { Test-TiTCOSUpdateCompliance -Config @{} -Result $result } | Should -Not -Throw
            $result.RawData['OSUpdateCompliance'].DevicesMissingOSData | Should -Be 2
            @($result.RawData['OutdatedDevices']).Count | Should -Be 0
        }
    }
}
