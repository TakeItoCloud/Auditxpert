#Requires -Version 5.1
<#
.SYNOPSIS
    TakeItToCloud.Assess — Compliance Evidence Pack Generator.

.DESCRIPTION
    Generates structured evidence packs for compliance frameworks by mapping
    assessment findings and raw collector data to framework controls.
    Designed for MSP Automation Pack (Product 2) white-label delivery.

    Output structure:
    evidence-pack/
    ├── metadata.json
    ├── ISO27001/
    │   ├── control-summary.csv
    │   └── <ControlId>-<title>/
    │       ├── evidence.json
    │       └── findings.csv
    ├── CyberInsurance/
    │   ├── questionnaire-answers.csv
    │   └── <ControlId>-<title>/
    │       ├── evidence.json
    │       └── findings.csv
    └── summary.json

.NOTES
    Module:     TiTC.Output.Evidence
    Author:     TakeItToCloud
    Version:    1.0.0
#>

# ============================================================================
# MODULE DEPENDENCIES
# ============================================================================

$CorePath = Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) 'src\Core\TiTC.Core.psm1'
if (Test-Path $CorePath) {
    Import-Module $CorePath -ErrorAction SilentlyContinue
}

# ============================================================================
# CONSTANTS
# ============================================================================

$script:COMPONENT    = 'Output.Evidence'
$script:TOOL_VERSION = '1.0.0'

# Use module file's absolute path for reliable resolution regardless of $PSScriptRoot context
$script:COMPLIANCE_MAP_DIR = Join-Path (Split-Path (Split-Path (Split-Path $MyInvocation.MyCommand.Path -Parent) -Parent) -Parent) 'compliance'

# ============================================================================
# HELPERS
# ============================================================================

function ConvertTo-SerializableObject {
    param($InputObject)
    if ($null -eq $InputObject) { return $null }
    if ($InputObject -is [hashtable] -or $InputObject -is [System.Collections.Specialized.OrderedDictionary]) {
        $ordered = [ordered]@{}
        foreach ($key in $InputObject.Keys) {
            $ordered[[string]$key] = ConvertTo-SerializableObject $InputObject[$key]
        }
        return $ordered
    }
    if ($InputObject -is [System.Collections.IList] -and $InputObject -isnot [string]) {
        return @($InputObject | ForEach-Object { ConvertTo-SerializableObject $_ })
    }
    return $InputObject
}

# ============================================================================
# MAIN EXPORT FUNCTION
# ============================================================================

function Export-TiTCEvidencePack {
    <#
    .SYNOPSIS
        Generates compliance evidence packs from an assessment report.

    .PARAMETER Report
        TiTCAssessmentReport object from the assessment.

    .PARAMETER OutputPath
        Directory path for the evidence pack output.

    .PARAMETER Frameworks
        Compliance frameworks to generate evidence for.

    .PARAMETER CompanyName
        Branding company name for white-label MSP packs.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Report,

        [Parameter(Mandatory)]
        [string]$OutputPath,

        [ValidateSet('ISO27001', 'SOC2Lite', 'CyberInsurance', 'CISControls', 'InternalRisk', 'All')]
        [string[]]$Frameworks = @('All'),

        [string]$CompanyName = 'TakeItToCloud'
    )

    $packRoot = Join-Path $OutputPath 'evidence-pack'
    if (-not (Test-Path $packRoot)) {
        New-Item -ItemType Directory -Path $packRoot -Force | Out-Null
    }

    Write-TiTCLog "Generating evidence pack: $packRoot" -Level Info -Component $script:COMPONENT

    # Build findings lookup: control ID → findings
    $allFindings = if ($Report.AllFindings) { @($Report.AllFindings) } else { @() }
    $findingsByControl = @{}
    foreach ($f in $allFindings) {
        if ($f.ComplianceControls) {
            foreach ($ctrl in $f.ComplianceControls) {
                if (-not $findingsByControl[$ctrl]) { $findingsByControl[$ctrl] = [System.Collections.ArrayList]::new() }
                $null = $findingsByControl[$ctrl].Add($f)
            }
        }
    }

    # Determine which frameworks to process
    $frameworkFiles = @{
        'ISO27001'      = 'iso27001.json'
        'CyberInsurance'= 'cyber-insurance.json'
        'SOC2Lite'      = 'soc2-lite.json'
        'CISControls'   = 'cis-controls.json'
        'InternalRisk'  = 'internal-risk.json'
    }

    $runAll = $Frameworks -contains 'All'
    $toProcess = if ($runAll) { $frameworkFiles.Keys } else { $Frameworks }

    $packSummary = @{
        GeneratedAt   = (Get-Date -Format 'yyyy-MM-ddTHH:mm:ssZ')
        TenantId      = $Report.TenantId
        TenantName    = $Report.TenantName
        CompanyName   = $CompanyName
        ToolVersion   = $script:TOOL_VERSION
        Frameworks    = @{}
    }

    foreach ($fwKey in $toProcess) {
        $fwFile = $frameworkFiles[$fwKey]
        if (-not $fwFile) { continue }

        $fwPath = Join-Path $script:COMPLIANCE_MAP_DIR $fwFile
        if (-not (Test-Path $fwPath)) {
            Write-TiTCLog "Compliance mapping not found: $fwPath — skipping $fwKey" -Level Warning -Component $script:COMPONENT
            continue
        }

        Write-TiTCLog "Building $fwKey evidence pack..." -Level Info -Component $script:COMPONENT

        $fwData = Get-Content $fwPath -Raw | ConvertFrom-Json
        $fwDir  = Join-Path $packRoot $fwKey
        New-Item -ItemType Directory -Path $fwDir -Force | Out-Null

        $controlSummary = [System.Collections.ArrayList]::new()
        $controlsPassing = 0
        $controlsTotal   = 0

        # Convert controls from PSObject
        $controls = $fwData.controls
        $controlKeys = $controls | Get-Member -MemberType NoteProperty | Select-Object -ExpandProperty Name

        foreach ($controlId in $controlKeys) {
            $control = $controls.$controlId
            $controlsTotal++

            # Find findings mapped to this control
            $controlFindings = [System.Collections.ArrayList]::new()
            foreach ($key in $findingsByControl.Keys) {
                if ($key -match [regex]::Escape($controlId)) {
                    foreach ($f in $findingsByControl[$key]) {
                        $null = $controlFindings.Add($f)
                    }
                }
            }

            # Also match by check name from the checks array
            if ($control.checks) {
                foreach ($checkName in $control.checks) {
                    $matchedByTag = $allFindings | Where-Object {
                        $_.Tags -contains $checkName -or $_.DetectedBy -match $checkName
                    }
                    foreach ($f in $matchedByTag) {
                        if ($controlFindings -notcontains $f) {
                            $null = $controlFindings.Add($f)
                        }
                    }
                }
            }

            # Determine status
            $critOrHigh = $controlFindings | Where-Object { $_.Severity -in @('Critical','High') }
            $status = if ($controlFindings.Count -eq 0)   { 'Pass' }
                      elseif ($critOrHigh.Count -gt 0)     { 'Fail' }
                      else                                 { 'Partial' }

            if ($status -eq 'Pass') { $controlsPassing++ }

            # Create control subfolder
            $safeName = "$controlId-$($control.title -replace '[^\w\s-]','' -replace '\s+','-')" -replace '--+','-'
            $safeName = $safeName.Substring(0, [Math]::Min(60, $safeName.Length))
            $ctrlDir  = Join-Path $fwDir $safeName
            New-Item -ItemType Directory -Path $ctrlDir -Force | Out-Null

            # Gather raw evidence from collector results
            $rawEvidence = @{
                ControlId   = $controlId
                Title       = $control.title
                Status      = $status
                FindingCount= $controlFindings.Count
                Checks      = $control.checks
                EvidenceNote= $control.evidence
                CollectedAt = (Get-Date -Format 'yyyy-MM-ddTHH:mm:ssZ')
                TenantId    = $Report.TenantId
            }

            # Attach relevant raw data from collectors
            if ($Report.CollectorResults -and $control.checks) {
                $rawEvidence['CollectorData'] = @{}
                foreach ($checkName in $control.checks) {
                    foreach ($cr in $Report.CollectorResults) {
                        if ($cr.Domain -match $checkName -or $cr.RawData.Keys -contains $checkName) {
                            $rawEvidence['CollectorData'][$cr.Domain] = $cr.RawData
                        }
                    }
                }
            }

            (ConvertTo-SerializableObject $rawEvidence) | ConvertTo-Json -Depth 8 |
                Set-Content -Path (Join-Path $ctrlDir 'evidence.json') -Encoding UTF8 -Force

            # Write findings CSV for this control
            if ($controlFindings.Count -gt 0) {
                $controlFindings | Select-Object FindingId, Severity, Domain, Title, Description,
                    Remediation, Status, RiskWeight,
                    @{N='AffectedCount'; E={ $_.AffectedResources.Count }},
                    @{N='ComplianceControls'; E={ $_.ComplianceControls -join '; ' }} |
                    Export-Csv -Path (Join-Path $ctrlDir 'findings.csv') -NoTypeInformation -Encoding UTF8 -Force
            }

            $summaryRow = [PSCustomObject]@{
                ControlId    = $controlId
                Title        = $control.title
                Status       = $status
                FindingCount = $controlFindings.Count
                CritHigh     = $critOrHigh.Count
                Evidence     = $control.evidence
            }
            $null = $controlSummary.Add($summaryRow)
        }

        # Write control summary CSV
        $controlSummary | Export-Csv -Path (Join-Path $fwDir 'control-summary.csv') -NoTypeInformation -Encoding UTF8 -Force

        # For Cyber Insurance: also write questionnaire-answers.csv
        if ($fwKey -eq 'CyberInsurance' -and $fwData.controls) {
            $qaRows = foreach ($controlId in $controlKeys) {
                $control = $controls.$controlId
                $ctrlFindings = $controlSummary | Where-Object { $_.ControlId -eq $controlId }
                [PSCustomObject]@{
                    ControlId   = $controlId
                    Question    = $control.question
                    Status      = if ($ctrlFindings) { $ctrlFindings.Status } else { 'Unknown' }
                    Required    = $control.required
                    ImpactNote  = $control.typical_impact
                }
            }
            $qaRows | Export-Csv -Path (Join-Path $fwDir 'questionnaire-answers.csv') -NoTypeInformation -Encoding UTF8 -Force
        }

        $coveragePct = if ($controlsTotal -gt 0) { [Math]::Round(($controlsPassing / $controlsTotal) * 100, 1) } else { 0 }
        $packSummary.Frameworks[$fwKey] = @{
            TotalControls   = $controlsTotal
            PassingControls = $controlsPassing
            CoveragePercent = $coveragePct
        }

        Write-TiTCLog "$fwKey evidence pack: $coveragePct% coverage ($controlsPassing/$controlsTotal controls passing)" `
            -Level Info -Component $script:COMPONENT
    }

    # Write metadata and summary
    $metadata = @{
        GeneratedAt   = $packSummary.GeneratedAt
        TenantId      = $Report.TenantId
        TenantName    = $Report.TenantName
        CompanyName   = $CompanyName
        ToolVersion   = $script:TOOL_VERSION
        AssessmentProfile = $Report.AssessmentProfile
        TotalFindings = $allFindings.Count
    }
    (ConvertTo-SerializableObject $metadata) | ConvertTo-Json -Depth 5 |
        Set-Content -Path (Join-Path $packRoot 'metadata.json') -Encoding UTF8 -Force

    (ConvertTo-SerializableObject $packSummary) | ConvertTo-Json -Depth 5 |
        Set-Content -Path (Join-Path $packRoot 'summary.json') -Encoding UTF8 -Force

    Write-TiTCLog "Evidence pack complete: $packRoot" -Level Success -Component $script:COMPONENT

    return $packRoot
}

# ============================================================================
# MODULE EXPORT
# ============================================================================

Export-ModuleMember -Function @('Export-TiTCEvidencePack')
