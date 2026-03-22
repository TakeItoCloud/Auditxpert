using module ..\src\Core\Models\TiTC.Models.psm1
#Requires -Version 7.0
<#
.SYNOPSIS
    Phase B — Import Chain Test for AuditXpert.

.DESCRIPTION
    Verifies that every module can be imported cleanly and that all expected
    exported functions exist after import. Does not require Graph connectivity.

.NOTES
    Run with: pwsh -ExecutionPolicy Bypass -File .\tests\Test-ImportChain.ps1
#>

$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent

$pass  = 0
$fail  = 0
$results = [System.Collections.ArrayList]::new()

function Test-Step {
    param([string]$Name, [scriptblock]$Block)
    try {
        & $Block
        $null = $script:results.Add([PSCustomObject]@{ Name = $Name; Status = 'PASS'; Detail = '' })
        $script:pass++
    }
    catch {
        $null = $script:results.Add([PSCustomObject]@{ Name = $Name; Status = 'FAIL'; Detail = $_.Exception.Message })
        $script:fail++
    }
}

Write-Host ''
Write-Host '  AuditXpert — Phase B: Import Chain Test' -ForegroundColor Cyan
Write-Host '  -----------------------------------------' -ForegroundColor DarkGray

# ── Module paths ─────────────────────────────────────────────────────────────
$modelsPath    = Join-Path $root 'src\Core\Models\TiTC.Models.psm1'
$corePath      = Join-Path $root 'src\Core\TiTC.Core.psm1'
$entraPath     = Join-Path $root 'src\Collectors\TiTC.Collector.EntraID.psm1'
$exchangePath  = Join-Path $root 'src\Collectors\TiTC.Collector.Exchange.psm1'
$intunePath    = Join-Path $root 'src\Collectors\TiTC.Collector.Intune.psm1'
$defenderPath  = Join-Path $root 'src\Collectors\TiTC.Collector.Defender.psm1'
$licensingPath = Join-Path $root 'src\Collectors\TiTC.Collector.Licensing.psm1'
$riskPath      = Join-Path $root 'src\Analyzers\TiTC.Analyzer.Risk.psm1'
$reportPath    = Join-Path $root 'src\Outputs\TiTC.Output.Report.psm1'
$evidencePath  = Join-Path $root 'src\Outputs\TiTC.Output.Evidence.psm1'
$aiPath        = Join-Path $root 'src\Outputs\TiTC.Output.AIExplainer.psm1'

# ── File existence ────────────────────────────────────────────────────────────
$allMods = @($modelsPath,$corePath,$entraPath,$exchangePath,$intunePath,
             $defenderPath,$licensingPath,$riskPath,$reportPath,$evidencePath,$aiPath)
foreach ($m in $allMods) {
    Test-Step "File exists: $(Split-Path $m -Leaf)" {
        if (-not (Test-Path $m)) { throw "Not found: $m" }
    }
}

# ── Import modules ────────────────────────────────────────────────────────────
Test-Step 'Import TiTC.Models' {
    Import-Module $modelsPath -Force
}

Test-Step 'Import TiTC.Core' {
    Import-Module $corePath -Force
}

Test-Step 'Import TiTC.Collector.EntraID' {
    Import-Module $entraPath -Force
}

Test-Step 'Import TiTC.Collector.Exchange' {
    Import-Module $exchangePath -Force
}

Test-Step 'Import TiTC.Collector.Intune' {
    Import-Module $intunePath -Force
}

Test-Step 'Import TiTC.Collector.Defender' {
    Import-Module $defenderPath -Force
}

Test-Step 'Import TiTC.Collector.Licensing' {
    Import-Module $licensingPath -Force
}

Test-Step 'Import TiTC.Analyzer.Risk' {
    Import-Module $riskPath -Force
}

Test-Step 'Import TiTC.Output.Report' {
    Import-Module $reportPath -Force
}

Test-Step 'Import TiTC.Output.Evidence' {
    Import-Module $evidencePath -Force
}

Test-Step 'Import TiTC.Output.AIExplainer' {
    Import-Module $aiPath -Force
}

# ── Function exports: Core ────────────────────────────────────────────────────
$coreFns = @(
    'Connect-TiTCGraph','Disconnect-TiTCGraph','Invoke-TiTCGraphRequest',
    'Initialize-TiTCLogging','Write-TiTCLog','Export-TiTCLog',
    'Get-TiTCConfig','New-TiTCFinding','New-TiTCCollectorResult',
    'Invoke-TiTCLogRotation','Write-TiTCAssessmentSummary',
    'Get-TiTCErrorSummary','Test-TiTCPrerequisites',
    'Measure-TiTCOperation','Get-TiTCApiCallSummary'
)
foreach ($fn in $coreFns) {
    Test-Step "Core exports: $fn" {
        if (-not (Get-Command $fn -ErrorAction SilentlyContinue)) { throw "Missing: $fn" }
    }
}

# ── Function exports: Collectors ─────────────────────────────────────────────
foreach ($fn in @('Invoke-TiTCEntraIDCollector','Invoke-TiTCExchangeCollector',
                  'Invoke-TiTCIntuneCollector','Invoke-TiTCDefenderCollector',
                  'Invoke-TiTCLicensingCollector')) {
    Test-Step "Collector exports: $fn" {
        if (-not (Get-Command $fn -ErrorAction SilentlyContinue)) { throw "Missing: $fn" }
    }
}

# ── Function exports: Analyzer ────────────────────────────────────────────────
Test-Step 'Analyzer exports: Invoke-TiTCRiskAnalysis' {
    if (-not (Get-Command 'Invoke-TiTCRiskAnalysis' -ErrorAction SilentlyContinue)) {
        throw 'Missing: Invoke-TiTCRiskAnalysis'
    }
}

# ── Function exports: Outputs ─────────────────────────────────────────────────
foreach ($fn in @('Export-TiTCReport','Export-TiTCEvidencePack',
                  'Invoke-TiTCAIExplainer','Import-TiTCAuditData','Export-TiTCAIReport')) {
    Test-Step "Output exports: $fn" {
        if (-not (Get-Command $fn -ErrorAction SilentlyContinue)) { throw "Missing: $fn" }
    }
}

# ── PS class availability (requires 'using module' at top) ───────────────────
Test-Step 'Class: TiTCFinding instantiable' {
    $f = [TiTCFinding]::new()
    if ($null -eq $f) { throw 'TiTCFinding::new() returned null' }
}

Test-Step 'Class: TiTCAssessmentReport instantiable' {
    $r = [TiTCAssessmentReport]::new()
    if ($null -eq $r) { throw 'TiTCAssessmentReport::new() returned null' }
}

Test-Step 'Class: TiTCRiskScore instantiable' {
    $s = [TiTCRiskScore]::new()
    if ($null -eq $s) { throw 'TiTCRiskScore::new() returned null' }
}

# ── Factory: New-TiTCFinding ──────────────────────────────────────────────────
Test-Step 'Factory: New-TiTCFinding creates valid finding' {
    $f = New-TiTCFinding -Severity 'High' -Domain 'EntraID' `
         -Title 'Test Finding' -Description 'Desc' -Remediation 'Fix it'
    if ($null -eq $f)             { throw 'New-TiTCFinding returned null' }
    if ($f.Severity -ne 'High')   { throw "Severity mismatch: $($f.Severity)" }
    if ($f.Domain -ne 'EntraID')  { throw "Domain mismatch: $($f.Domain)" }
    if ($f.Title -ne 'Test Finding') { throw "Title mismatch: $($f.Title)" }
}

# ── Factory: New-TiTCCollectorResult ─────────────────────────────────────────
Test-Step 'Factory: New-TiTCCollectorResult creates valid result' {
    $r = New-TiTCCollectorResult -Domain 'EntraID'
    if ($null -eq $r)             { throw 'New-TiTCCollectorResult returned null' }
    if ($r.Domain -ne 'EntraID') { throw "Domain mismatch: $($r.Domain)" }
}

# ── GetRating boundary check ──────────────────────────────────────────────────
Test-Step 'RiskScore.GetRating: boundaries correct' {
    $s = [TiTCRiskScore]::new()
    $checks = @(
        @{Score=5;   Expected='A+'}
        @{Score=15;  Expected='A' }
        @{Score=50;  Expected='C+'}
        @{Score=100; Expected='F' }
    )
    foreach ($c in $checks) {
        $got = $s.GetRating($c.Score)
        if ($got -ne $c.Expected) { throw "Score $($c.Score): expected $($c.Expected), got $got" }
    }
}

# ── Get-TiTCConfig returns non-null ───────────────────────────────────────────
Test-Step 'Get-TiTCConfig returns config object' {
    $cfg = Get-TiTCConfig -ProfileName Full
    if ($null -eq $cfg)          { throw 'Get-TiTCConfig returned null' }
    if ($null -eq $cfg.Domains)  { throw 'Config missing Domains key' }
}

# ── Results ───────────────────────────────────────────────────────────────────
Write-Host ''
Write-Host '  Results' -ForegroundColor White
Write-Host '  -----------------------------------------' -ForegroundColor DarkGray

foreach ($r in $results) {
    if ($r.Status -eq 'PASS') {
        Write-Host "  PASS  $($r.Name)" -ForegroundColor Green
    } else {
        Write-Host "  FAIL  $($r.Name)" -ForegroundColor Red
        Write-Host "        $($r.Detail)" -ForegroundColor DarkRed
    }
}

Write-Host ''
$color = if ($fail -eq 0) { 'Green' } else { 'Red' }
Write-Host "  TOTAL: $pass passed, $fail failed" -ForegroundColor $color
Write-Host ''

if ($fail -gt 0) { exit 1 }
