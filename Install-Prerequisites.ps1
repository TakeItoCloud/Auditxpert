#Requires -Version 5.1
<#
.SYNOPSIS
    AuditXpert — Interactive Prerequisites Installer & Validator.

.DESCRIPTION
    Checks for and optionally installs all required and optional dependencies
    for AuditXpert. Run once before first use, and any time after upgrading.

    For each missing required module you are asked: Install? (Y)es / (N)o / (A)ll
    'A' installs this and all remaining modules without further prompting.

    Optional tools (wkhtmltopdf) and AI API keys are checked but never
    installed automatically — instructions are shown instead.

.EXAMPLE
    .\Install-Prerequisites.ps1

.EXAMPLE
    # Install to AllUsers scope (requires elevation)
    .\Install-Prerequisites.ps1 -Scope AllUsers

.EXAMPLE
    # Install everything without prompting
    .\Install-Prerequisites.ps1 -InstallAll

.EXAMPLE
    # Include optional modules (ExchangeOnlineManagement, Pester)
    .\Install-Prerequisites.ps1 -IncludeOptional

.NOTES
    Author:  TakeItToCloud
    Version: 2.0.0
#>

[CmdletBinding()]
param(
    [ValidateSet('CurrentUser', 'AllUsers')]
    [string]$Scope = 'CurrentUser',

    [switch]$IncludeOptional,

    [switch]$InstallAll   # Skip all prompts and install every missing module
)

$ErrorActionPreference = 'Stop'

# ============================================================================
# DATA
# ============================================================================

$requiredModules = @(
    @{
        Name        = 'Microsoft.Graph.Authentication'
        MinVersion  = '2.0.0'
        Description = 'Graph API authentication'
        WhyNeeded   = 'Required for ALL assessments. Without it nothing runs.'
    }
)

$optionalModules = @(
    @{
        Name        = 'ExchangeOnlineManagement'
        MinVersion  = '3.0.0'
        Description = 'Exchange Online PowerShell module'
        WhyNeeded   = 'Enables deep Exchange checks (transport rules, connectors, DMARC). Without it, Exchange collector runs in Graph-only mode with reduced coverage.'
        Feature     = 'Exchange deep-scan'
    },
    @{
        Name        = 'Pester'
        MinVersion  = '5.0.0'
        Description = 'PowerShell testing framework'
        WhyNeeded   = 'Only required to run the unit test suite. Not needed for assessments.'
        Feature     = 'Unit tests (tests\ folder)'
    }
)

# ============================================================================
# BANNER
# ============================================================================

Write-Host ''
Write-Host '  AuditXpert — Prerequisites Installer' -ForegroundColor Cyan
Write-Host '  TakeItToCloud v2.0.0' -ForegroundColor DarkCyan
Write-Host '  ─────────────────────────────────────────────────' -ForegroundColor DarkGray
Write-Host ''

# ============================================================================
# POWERSHELL VERSION
# ============================================================================

$psVer = $PSVersionTable.PSVersion
Write-Host '  PowerShell version...' -NoNewline
if ($psVer.Major -lt 5 -or ($psVer.Major -eq 5 -and $psVer.Minor -lt 1)) {
    Write-Host " FAIL (v$psVer)" -ForegroundColor Red
    Write-Host "  ERROR: PowerShell 5.1 or higher is required. Download from https://aka.ms/powershell" -ForegroundColor Red
    exit 1
}
elseif ($psVer.Major -lt 7) {
    Write-Host " OK (v$psVer — PowerShell 7.x is recommended for best performance)" -ForegroundColor Yellow
}
else {
    Write-Host " OK (v$psVer)" -ForegroundColor Green
}

# ============================================================================
# TRACK RESULTS
# ============================================================================

$summary = [ordered]@{}

# ============================================================================
# REQUIRED MODULES
# ============================================================================

Write-Host ''
Write-Host '  Required Modules' -ForegroundColor White
Write-Host '  ─────────────────────────────────────────────────' -ForegroundColor DarkGray

$installAllFlag = $InstallAll.IsPresent

foreach ($mod in $requiredModules) {
    Write-Host "  $($mod.Name)" -NoNewline -ForegroundColor White

    $installed = Get-Module -ListAvailable -Name $mod.Name |
        Where-Object { $_.Version -ge [version]$mod.MinVersion } |
        Select-Object -First 1

    if ($installed) {
        Write-Host "  OK (v$($installed.Version))" -ForegroundColor Green
        $summary[$mod.Name] = @{ Status = 'OK'; Detail = "v$($installed.Version)"; Required = $true }
        continue
    }

    Write-Host "  NOT FOUND" -ForegroundColor Yellow
    Write-Host "  → $($mod.WhyNeeded)" -ForegroundColor DarkGray

    $answer = 'N'
    if (-not $installAllFlag) {
        Write-Host ''
        $answer = Read-Host "  Install $($mod.Name)? (Y)es / (N)o / (A)ll"
        if ($answer -match '^[Aa]') { $installAllFlag = $true }
    }

    if ($installAllFlag -or $answer -match '^[Yy]') {
        Write-Host "  Installing $($mod.Name)..." -NoNewline -ForegroundColor Cyan
        try {
            Install-Module -Name $mod.Name -Scope $Scope `
                -MinimumVersion $mod.MinVersion -Force -AllowClobber -Repository PSGallery
            $newVer = (Get-Module -ListAvailable -Name $mod.Name |
                Sort-Object Version -Descending | Select-Object -First 1).Version
            Write-Host " Installed (v$newVer)" -ForegroundColor Green
            $summary[$mod.Name] = @{ Status = 'Installed'; Detail = "v$newVer"; Required = $true }
        }
        catch {
            Write-Host " FAILED: $_" -ForegroundColor Red
            $summary[$mod.Name] = @{ Status = 'Failed'; Detail = $_.ToString(); Required = $true }
        }
    }
    else {
        Write-Host "  SKIPPED — assessments will not run without this module." -ForegroundColor DarkYellow
        $summary[$mod.Name] = @{ Status = 'Skipped'; Detail = 'user skipped'; Required = $true }
    }
}

# ============================================================================
# OPTIONAL MODULES
# ============================================================================

if ($IncludeOptional) {
    Write-Host ''
    Write-Host '  Optional Modules' -ForegroundColor White
    Write-Host '  ─────────────────────────────────────────────────' -ForegroundColor DarkGray

    foreach ($mod in $optionalModules) {
        Write-Host "  $($mod.Name)" -NoNewline -ForegroundColor White

        $installed = Get-Module -ListAvailable -Name $mod.Name |
            Where-Object { $_.Version -ge [version]$mod.MinVersion } |
            Select-Object -First 1

        if ($installed) {
            Write-Host "  OK (v$($installed.Version))" -ForegroundColor Green
            $summary[$mod.Name] = @{ Status = 'OK'; Detail = "v$($installed.Version)"; Required = $false }
            continue
        }

        Write-Host "  NOT FOUND (optional)" -ForegroundColor DarkYellow
        Write-Host "  → $($mod.WhyNeeded)" -ForegroundColor DarkGray

        $answer = 'N'
        if (-not $installAllFlag) {
            $answer = Read-Host "  Install $($mod.Name)? (Y)es / (N)o / (A)ll"
            if ($answer -match '^[Aa]') { $installAllFlag = $true }
        }

        if ($installAllFlag -or $answer -match '^[Yy]') {
            Write-Host "  Installing $($mod.Name)..." -NoNewline -ForegroundColor Cyan
            try {
                Install-Module -Name $mod.Name -Scope $Scope -Force -AllowClobber -Repository PSGallery
                $newVer = (Get-Module -ListAvailable -Name $mod.Name |
                    Sort-Object Version -Descending | Select-Object -First 1).Version
                Write-Host " Installed (v$newVer)" -ForegroundColor Green
                $summary[$mod.Name] = @{ Status = 'Installed'; Detail = "v$newVer"; Required = $false }
            }
            catch {
                Write-Host " FAILED (optional): $_" -ForegroundColor DarkYellow
                $summary[$mod.Name] = @{ Status = 'Failed'; Detail = $_.ToString(); Required = $false }
            }
        }
        else {
            $summary[$mod.Name] = @{ Status = 'Skipped'; Detail = $mod.Feature; Required = $false }
        }
    }
}
else {
    Write-Host ''
    Write-Host '  Optional modules not checked. Run with -IncludeOptional to check/install:' -ForegroundColor DarkGray
    foreach ($mod in $optionalModules) {
        Write-Host "    $($mod.Name) — $($mod.Feature)" -ForegroundColor DarkGray
    }
}

# ============================================================================
# OPTIONAL TOOLS — wkhtmltopdf
# ============================================================================

Write-Host ''
Write-Host '  Optional Tools' -ForegroundColor White
Write-Host '  ─────────────────────────────────────────────────' -ForegroundColor DarkGray

Write-Host '  wkhtmltopdf' -NoNewline -ForegroundColor White
$wkhtmltopdfCmd = Get-Command 'wkhtmltopdf' -ErrorAction SilentlyContinue
if ($wkhtmltopdfCmd) {
    Write-Host "  Found at $($wkhtmltopdfCmd.Source)" -ForegroundColor Green
    $summary['wkhtmltopdf'] = @{ Status = 'Found'; Detail = $wkhtmltopdfCmd.Source; Required = $false }
}
else {
    Write-Host '  NOT FOUND' -ForegroundColor DarkYellow
    Write-Host '  → Used for automatic PDF conversion. Without it, HTML reports still work.' -ForegroundColor DarkGray
    Write-Host '    Download: https://wkhtmltopdf.org/downloads.html' -ForegroundColor DarkGray
    Write-Host '    Install to: C:\Program Files\wkhtmltopdf\  (default installer path)' -ForegroundColor DarkGray
    $summary['wkhtmltopdf'] = @{ Status = 'NotFound'; Detail = 'PDF auto-conversion disabled'; Required = $false }
}

# ============================================================================
# AI API KEYS
# ============================================================================

Write-Host ''
Write-Host '  AI API Keys  (for Invoke-AuditExplainer.ps1)' -ForegroundColor White
Write-Host '  ─────────────────────────────────────────────────' -ForegroundColor DarkGray

Write-Host '  ANTHROPIC_API_KEY' -NoNewline -ForegroundColor White
if ($env:ANTHROPIC_API_KEY -and $env:ANTHROPIC_API_KEY -ne '') {
    Write-Host '  SET' -ForegroundColor Green
    $summary['ANTHROPIC_API_KEY'] = @{ Status = 'Set'; Detail = 'Claude — default AI provider'; Required = $false }
}
else {
    Write-Host '  NOT SET' -ForegroundColor DarkYellow
    Write-Host '  → Get a key at https://console.anthropic.com  then set it:' -ForegroundColor DarkGray
    Write-Host '    $env:ANTHROPIC_API_KEY = "sk-ant-api03-..."' -ForegroundColor DarkGray
    Write-Host '    To persist: add that line to your PowerShell $PROFILE.' -ForegroundColor DarkGray
    $summary['ANTHROPIC_API_KEY'] = @{ Status = 'NotSet'; Detail = 'AI Explainer will need -ApiKey param'; Required = $false }
}

Write-Host '  OPENAI_API_KEY' -NoNewline -ForegroundColor White
if ($env:OPENAI_API_KEY -and $env:OPENAI_API_KEY -ne '') {
    Write-Host '  SET' -ForegroundColor Green
    $summary['OPENAI_API_KEY'] = @{ Status = 'Set'; Detail = 'OpenAI — alternative provider'; Required = $false }
}
else {
    Write-Host '  NOT SET  (optional — Claude is the default)' -ForegroundColor DarkGray
    $summary['OPENAI_API_KEY'] = @{ Status = 'NotSet'; Detail = 'optional'; Required = $false }
}

# ============================================================================
# VERIFY PROJECT FILES
# ============================================================================

Write-Host ''
Write-Host '  Verifying project files' -ForegroundColor White
Write-Host '  ─────────────────────────────────────────────────' -ForegroundColor DarkGray

$criticalFiles = @(
    'src\Core\TiTC.Core.psm1',
    'src\Core\Models\TiTC.Models.psm1',
    'src\Collectors\TiTC.Collector.EntraID.psm1',
    'src\Collectors\TiTC.Collector.Exchange.psm1',
    'src\Collectors\TiTC.Collector.Intune.psm1',
    'src\Collectors\TiTC.Collector.Defender.psm1',
    'src\Collectors\TiTC.Collector.Licensing.psm1',
    'src\Analyzers\TiTC.Analyzer.Risk.psm1',
    'src\Outputs\TiTC.Output.Report.psm1',
    'src\Outputs\TiTC.Output.Evidence.psm1',
    'src\Outputs\TiTC.Output.AIExplainer.psm1',
    'profiles\Invoke-M365Snapshot.ps1',
    'profiles\Invoke-MSPAuditPack.ps1',
    'profiles\Invoke-AuditExplainer.ps1',
    'compliance\iso27001.json',
    'compliance\cyber-insurance.json',
    'compliance\soc2-lite.json',
    'compliance\cis-controls.json',
    'compliance\internal-risk.json'
)

$missingFiles = @()
foreach ($f in $criticalFiles) {
    $fullPath = Join-Path $PSScriptRoot $f
    if (Test-Path $fullPath) {
        Write-Host "  OK  $f" -ForegroundColor Green
    }
    else {
        Write-Host "  MISSING  $f" -ForegroundColor Red
        $missingFiles += $f
    }
}

# ============================================================================
# SUMMARY
# ============================================================================

Write-Host ''
Write-Host '  ═════════════════════════════════════════════════' -ForegroundColor DarkGray
Write-Host '  SUMMARY' -ForegroundColor White
Write-Host '  ─────────────────────────────────────────────────' -ForegroundColor DarkGray

$hasFailure = $false

foreach ($name in $summary.Keys) {
    $s = $summary[$name]
    switch ($s.Status) {
        'OK'        { Write-Host "  ✓ $name $($s.Detail)" -ForegroundColor Green }
        'Installed' { Write-Host "  ✓ $name $($s.Detail) — just installed" -ForegroundColor Green }
        'Found'     { Write-Host "  ✓ $name found at $($s.Detail)" -ForegroundColor Green }
        'Set'       { Write-Host "  ✓ $name — $($s.Detail)" -ForegroundColor Green }
        'Skipped'   {
            if ($s.Required) {
                Write-Host "  ✗ $name — SKIPPED ($($s.Detail))" -ForegroundColor DarkYellow
                $hasFailure = $true
            } else {
                Write-Host "  - $name — skipped ($($s.Detail))" -ForegroundColor DarkGray
            }
        }
        'Failed'    {
            Write-Host "  ✗ $name — FAILED" -ForegroundColor Red
            if ($s.Required) { $hasFailure = $true }
        }
        'NotFound'  { Write-Host "  ⚠ $name — NOT FOUND ($($s.Detail))" -ForegroundColor DarkYellow }
        'NotSet'    {
            if ($s.Detail -ne 'optional') {
                Write-Host "  ⚠ $name — NOT SET ($($s.Detail))" -ForegroundColor DarkYellow
            } else {
                Write-Host "  - $name — not set (optional)" -ForegroundColor DarkGray
            }
        }
    }
}

if ($missingFiles.Count -gt 0) {
    Write-Host "  ✗ $($missingFiles.Count) project file(s) missing — re-extract the AuditXpert package." -ForegroundColor Red
    $hasFailure = $true
}

Write-Host ''

if (-not $hasFailure -and $missingFiles.Count -eq 0) {
    Write-Host '  ✓ All prerequisites met. AuditXpert is ready to use.' -ForegroundColor Green
    Write-Host ''
    Write-Host '  Quick start:' -ForegroundColor Cyan
    Write-Host "    .\profiles\Invoke-M365Snapshot.ps1 -TenantId 'contoso.onmicrosoft.com'" -ForegroundColor White
    Write-Host '  Full documentation: docs\HOWTO.md' -ForegroundColor DarkGray
    Write-Host ''
    return $true
}
else {
    if ($hasFailure) {
        Write-Host '  ✗ One or more required components are missing or failed. See errors above.' -ForegroundColor Red
    }
    Write-Host ''
    exit 1
}
