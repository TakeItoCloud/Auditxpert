# PHASE 6 — BUILD: Testing, Manifests & Polish
# ═══════════════════════════════════════════════
# Feed this prompt to Claude in VS Code
# Pre-requisite: Phases 1-5 complete
# ═══════════════════════════════════════════════

## CONTEXT
Read `AUDITXPERT-BUILD-SPEC.md` for full project context.
Root: `C:\Scripts\Assessment\AuditXpert`
All modules, collectors, analyzers, outputs, orchestrators, and compliance mappings are built.

## TASKS

---

### TASK 6A: Pester Tests
Create tests in `C:\Scripts\Assessment\AuditXpert\tests\`

#### File: tests/TiTC.Models.Tests.ps1
Test all model classes:
- TiTCFinding creation via New-TiTCFinding with all parameters
- TiTCFinding default FindingId format (TITC-XXXXX)
- TiTCFinding.ToSummary() format
- TiTCCollectorResult creation, Complete(), ToSummary()
- TiTCRiskScore.Calculate() with various finding mixes
- TiTCRiskScore.GetRating() boundaries (A+ through F)
- TiTCAssessmentReport.AggregateFindings()
- TiTCLicenseWaste.Calculate()

#### File: tests/TiTC.Core.Tests.ps1
Test core infrastructure (mock Graph where needed):
- Get-TiTCConfig returns correct defaults for each profile
- Get-TiTCConfig profile overrides work
- Merge-TiTCHashtable deep merges correctly
- Write-TiTCLog respects log level filtering
- Initialize-TiTCLogging creates log directory
- Get-TiTCState returns expected structure
- Test-TiTCConnection returns false when not connected

#### File: tests/TiTC.Analyzer.Risk.Tests.ps1
Test the scoring engine with synthetic findings:
- Create 10-20 test findings across domains and severities
- Verify composite score calculation
- Verify category scoring maps findings to correct categories via tags
- Verify remediation prioritization order
- Verify quick wins selection criteria
- Verify severity distribution counts
- Verify compliance gap analysis with mock framework data

#### Pattern for all tests:
```powershell
BeforeAll {
    $ProjectRoot = Split-Path $PSScriptRoot -Parent
    Import-Module "$ProjectRoot\src\Core\Models\TiTC.Models.psm1" -Force
    Import-Module "$ProjectRoot\src\Core\TiTC.Core.psm1" -Force
}

Describe 'TiTCFinding' {
    It 'Creates a finding with default ID' {
        $finding = New-TiTCFinding -Title 'Test' -Description 'Test desc' -Severity High -Domain EntraID
        $finding.FindingId | Should -Match '^TITC-\d{5}$'
    }
}
```

---

### TASK 6B: Module Manifests
Create `.psd1` manifest files for PowerShell Gallery compatibility.

#### File: src/Core/TiTC.Core.psd1
```powershell
@{
    RootModule        = 'TiTC.Core.psm1'
    ModuleVersion     = '1.0.0'
    GUID              = '<generate-new-guid>'
    Author            = 'TakeItToCloud'
    CompanyName       = 'TakeItToCloud'
    Copyright         = '(c) 2026 TakeItToCloud. All rights reserved.'
    Description       = 'Core infrastructure for AuditXpert M365 Security Assessment Platform'
    PowerShellVersion = '5.1'
    RequiredModules   = @('Microsoft.Graph.Authentication')
    FunctionsToExport = @(
        'Connect-TiTCGraph', 'Disconnect-TiTCGraph', 'Test-TiTCConnection',
        'Invoke-TiTCGraphRequest', 'Get-TiTCConfig', 'Write-TiTCLog',
        'Initialize-TiTCLogging', 'Export-TiTCLog', 'Get-TiTCState',
        'Get-TiTCTenantInfo', 'Merge-TiTCHashtable'
    )
    PrivateData = @{ PSData = @{
        Tags = @('Microsoft365', 'Security', 'Assessment', 'AuditXpert')
        ProjectUri = 'https://github.com/TakeItoCloud/AuditXpert'
    }}
}
```

Create similar manifests for each module (Models, each Collector, Analyzer, each Output).

---

### TASK 6C: CHANGELOG.md
File: `C:\Scripts\Assessment\AuditXpert\CHANGELOG.md`

Document all phases:
- v1.0.0 — Core, Models, Entra ID Collector, Exchange Collector, Risk Analyzer
- v1.1.0 — Intune Collector, Defender Collector
- v1.2.0 — Licensing Collector, complete Layer 1
- v1.3.0 — PDF Report Generator, Evidence Packs, AI Explainer
- v1.4.0 — MSP Audit Pack, Audit Explainer orchestrators
- v1.5.0 — Full compliance mappings, testing, manifests

---

### TASK 6D: .gitignore
File: `C:\Scripts\Assessment\AuditXpert\.gitignore`
```
# Output artifacts
TiTC-Snapshot-*/
MSP-AuditPack-*/
*.log

# Sensitive
*.secret
appsettings.local.json

# IDE
.vscode/
*.code-workspace

# PowerShell
PSModulePath/
```

---

### TASK 6E: Quick Start Script
File: `C:\Scripts\Assessment\AuditXpert\Install-Prerequisites.ps1`

Script that checks and installs required modules:
```powershell
# Check and install required modules
$requiredModules = @(
    'Microsoft.Graph.Authentication',
    'ExchangeOnlineManagement',
    'Pester'
)
foreach ($mod in $requiredModules) {
    if (-not (Get-Module -ListAvailable -Name $mod)) {
        Write-Host "Installing $mod..." -ForegroundColor Cyan
        Install-Module $mod -Scope CurrentUser -Force -AllowClobber
    } else {
        Write-Host "✓ $mod already installed" -ForegroundColor Green
    }
}
```
