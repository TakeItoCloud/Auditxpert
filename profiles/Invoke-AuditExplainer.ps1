#Requires -Version 5.1
<#
.SYNOPSIS
    AI Audit Explainer — Product 2.2 Entry Point.

.DESCRIPTION
    Standalone AI-powered plain-English explainer for security findings.
    Accepts AuditXpert JSON, Qualys/Nessus/Defender/CIS CSV exports, a manual
    CSV, or pipeline input. Enriches findings with AI-generated business-language
    explanations and outputs a card-based HTML report (or JSON / console).

.EXAMPLE
    # Explain an AuditXpert assessment (auto-detects format)
    .\Invoke-AuditExplainer.ps1 -InputFile ".\TiTC-Snapshot-20260322\assessment-results.json"

.EXAMPLE
    # Explain a Nessus CSV export
    .\Invoke-AuditExplainer.ps1 -InputFile .\nessus-export.csv -InputFormat Nessus `
        -TenantName "Contoso" -OutputPath .\contoso-briefing.html

.EXAMPLE
    # Process every file in a folder (mixed formats)
    .\Invoke-AuditExplainer.ps1 -InputFolder .\scans\ -HighSeverityOnly

.EXAMPLE
    # Use OpenAI instead of Claude
    .\Invoke-AuditExplainer.ps1 -InputFile .\assessment-results.json `
        -Provider OpenAI -ApiKey $env:OPENAI_API_KEY

.EXAMPLE
    # Pipeline input from another script
    $findings | .\Invoke-AuditExplainer.ps1 -OutputFormat Console

.NOTES
    Product:    AI-Assisted Audit Explainer (Product 2.2)
    Author:     TakeItToCloud
    Version:    2.0.0
#>

[CmdletBinding(DefaultParameterSetName = 'File')]
param(
    # ── Input ──────────────────────────────────────────────────────────────────
    [Parameter(Mandatory, ParameterSetName = 'File')]
    [string]$InputFile,

    [Parameter(Mandatory, ParameterSetName = 'Folder')]
    [string]$InputFolder,

    [Parameter(Mandatory, ParameterSetName = 'Pipeline', ValueFromPipeline)]
    [object[]]$Findings,

    [ValidateSet('Auto', 'AuditXpert', 'CSV', 'Qualys', 'Nessus', 'Defender')]
    [string]$InputFormat = 'Auto',

    # ── AI Provider ────────────────────────────────────────────────────────────
    [ValidateSet('Claude', 'OpenAI')]
    [string]$Provider = 'Claude',

    [string]$ApiKey,

    [string]$Model,

    # ── Scope ──────────────────────────────────────────────────────────────────
    [switch]$HighSeverityOnly,

    [int]$MaxFindings = 20,

    # ── Branding ───────────────────────────────────────────────────────────────
    [string]$TenantName  = 'M365 Tenant',

    [string]$CompanyName = 'TakeItToCloud',

    # ── Output ─────────────────────────────────────────────────────────────────
    [string]$OutputPath,

    [ValidateSet('JSON', 'HTML', 'Console')]
    [string]$OutputFormat = 'HTML'
)

begin {
    $ErrorActionPreference = 'Stop'
    $scriptRoot = Split-Path $PSScriptRoot -Parent

    $modelsPath = Join-Path $scriptRoot 'src\Core\Models\TiTC.Models.psm1'
    $corePath   = Join-Path $scriptRoot 'src\Core\TiTC.Core.psm1'
    $aiModPath  = Join-Path $scriptRoot 'src\Outputs\TiTC.Output.AIExplainer.psm1'

    Import-Module $modelsPath -Force
    Import-Module $corePath   -Force
    Import-Module $aiModPath  -Force

    $pipelineFindings = [System.Collections.ArrayList]::new()
}

process {
    # Accumulate pipeline input
    if ($PSCmdlet.ParameterSetName -eq 'Pipeline' -and $Findings) {
        foreach ($f in $Findings) { $null = $pipelineFindings.Add($f) }
    }
}

end {
    # ============================================================================
    # API KEY RESOLUTION
    # ============================================================================

    # Resolve API key: param > environment variable > interactive prompt
    if (-not $ApiKey) {
        $ApiKey = if ($Provider -eq 'OpenAI') { $env:OPENAI_API_KEY } else { $env:ANTHROPIC_API_KEY }
    }

    if (-not $ApiKey) {
        $envVarName = if ($Provider -eq 'OpenAI') { 'OPENAI_API_KEY' } else { 'ANTHROPIC_API_KEY' }
        Write-Host ''
        Write-Host "  No API key found for $Provider." -ForegroundColor Yellow
        Write-Host "  Set `$env:$envVarName or pass -ApiKey to skip this prompt." -ForegroundColor DarkGray
        Write-Host ''

        try {
            $secureKey = Read-Host "  Enter $Provider API key" -AsSecureString
            $bstr   = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureKey)
            $ApiKey = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
            [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
        }
        catch {
            # Non-interactive context — Read-Host not available
            $ApiKey = $null
        }

        if (-not $ApiKey -or $ApiKey.Trim() -eq '') {
            Write-Host "  No API key provided. Aborting." -ForegroundColor Red
            Write-Host "  To set permanently: add to `$PROFILE: `$env:$envVarName = 'your-key'" -ForegroundColor DarkGray
            exit 1
        }
    }

    # ============================================================================
    # LOAD FINDINGS
    # ============================================================================

    $allFindings = @()

    switch ($PSCmdlet.ParameterSetName) {
        'File' {
            Write-Host "  Loading findings from: $InputFile" -ForegroundColor Cyan
            $allFindings = Import-TiTCAuditData -InputFile $InputFile -Format $InputFormat
        }
        'Folder' {
            Write-Host "  Loading findings from folder: $InputFolder" -ForegroundColor Cyan
            $allFindings = Import-TiTCAuditData -InputFolder $InputFolder -Format $InputFormat
        }
        'Pipeline' {
            $allFindings = @($pipelineFindings)
        }
    }

    if ($allFindings.Count -eq 0) {
        Write-Host "  No findings to explain." -ForegroundColor Yellow
        exit 0
    }

    Write-Host "  Loaded $($allFindings.Count) finding(s)." -ForegroundColor Cyan

    # ============================================================================
    # RUN AI EXPLAINER
    # ============================================================================

    $explainerParams = @{
        Findings         = $allFindings
        Provider         = $Provider
        MaxFindings      = $MaxFindings
        HighSeverityOnly = $HighSeverityOnly
    }
    if ($ApiKey) { $explainerParams.ApiKey = $ApiKey }
    if ($Model)  { $explainerParams.Model  = $Model  }

    $enriched = Invoke-TiTCAIExplainer @explainerParams

    # ============================================================================
    # OUTPUT
    # ============================================================================

    switch ($OutputFormat) {

        'HTML' {
            $outPath = if ($OutputPath) { $OutputPath } else {
                Join-Path $PWD "ai-security-briefing-$(Get-Date -Format 'yyyyMMdd-HHmmss').html"
            }
            $written = Export-TiTCAIReport `
                -Findings     $enriched `
                -OutputPath   $outPath `
                -TenantName   $TenantName `
                -CompanyName  $CompanyName
            Write-Host "  HTML report: $written" -ForegroundColor Green
        }

        'JSON' {
            $outPath = if ($OutputPath) { $OutputPath } else {
                Join-Path $PWD "findings-explained-$(Get-Date -Format 'yyyyMMdd-HHmmss').json"
            }
            $enriched | ConvertTo-Json -Depth 10 | Set-Content -Path $outPath -Force
            Write-Host "  JSON output: $outPath" -ForegroundColor Green
        }

        'Console' {
            Write-Host ""
            Write-Host "  AI-EXPLAINED FINDINGS" -ForegroundColor Cyan
            Write-Host "  ══════════════════════════════════════════════════════" -ForegroundColor Cyan
            foreach ($f in $enriched | Where-Object { $_.AIExplanation }) {
                Write-Host ""
                $sevColor = switch ($f.Severity) {
                    'Critical' { 'Red' } 'High' { 'DarkYellow' } 'Medium' { 'Yellow' } default { 'White' }
                }
                Write-Host "  [$($f.Severity)] $($f.Title)" -ForegroundColor $sevColor
                Write-Host "  Risk:     $($f.AIExplanation)"    -ForegroundColor White
                Write-Host "  Impact:   $($f.AIBusinessImpact)" -ForegroundColor Gray
                $priColor = if ($f.AIPriority -ge 4) { 'Red' } else { 'Yellow' }
                Write-Host "  Priority: $($f.AIPriority)/5"    -ForegroundColor $priColor
            }
            Write-Host ""
        }
    }

    return $enriched
}
