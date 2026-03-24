#Requires -Version 5.1
<#
.SYNOPSIS
    Focused regression tests for TiTC.Core Graph error diagnostics.
#>

BeforeAll {
    $ProjectRoot = Split-Path $PSScriptRoot -Parent
    Import-Module (Join-Path $ProjectRoot 'src\Core\Models\TiTC.Models.psm1') -Force
    Import-Module (Join-Path $ProjectRoot 'src\Core\TiTC.Core.psm1') -Force
}

Describe 'TiTC.Core Graph error diagnostics' {
    It 'classifies invalid Top limit errors as InvalidTop' {
        InModuleScope 'TiTC.Core' {
            $category = Get-TiTCGraphErrorCategory -ErrorDetails @{
                StatusCode = 400
                ResponseMessage = "The limit of '50' for Top query has been exceeded. The value from the incoming request is '999'."
            }

            $category | Should -Be 'InvalidTop'
        }
    }

    It 'classifies unsupported filter errors as UnsupportedFilter' {
        InModuleScope 'TiTC.Core' {
            $category = Get-TiTCGraphErrorCategory -ErrorDetails @{
                StatusCode = 400
                ResponseMessage = "Unsupported or invalid query filter clause specified for property 'mailboxSettings/userPurpose'."
            }

            $category | Should -Be 'UnsupportedFilter'
        }
    }

    It 'classifies delegated-mode endpoint restrictions distinctly from generic 403s' {
        InModuleScope 'TiTC.Core' {
            $category = Get-TiTCGraphErrorCategory -ErrorDetails @{
                StatusCode = 403
                ResponseMessage = 'This endpoint is not supported in delegated mode and requires application permissions.'
            }

            $category | Should -Be 'UnsupportedEndpointDelegated'
        }
    }

    It 'formats request targets without logging the full Graph host' {
        InModuleScope 'TiTC.Core' {
            $target = Format-TiTCGraphRequestTarget -RequestUri 'https://graph.microsoft.com/v1.0/security/incidents?$filter=status%20ne%20%27resolved%27&$top=50' -Endpoint '/security/incidents'
            $target | Should -Be '/v1.0/security/incidents?$filter=status%20ne%20%27resolved%27&$top=50'
        }
    }
}
