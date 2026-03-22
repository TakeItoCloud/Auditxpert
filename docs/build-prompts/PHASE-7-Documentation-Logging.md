# PHASE 7 — BUILD: HowTo Documentation + Enhanced Logging
# ═══════════════════════════════════════════════════════════
# Feed this prompt to Claude in VS Code AFTER all previous phases are complete.
# Pre-requisite: Phases 1-6 complete (all modules built and tested)
# ═══════════════════════════════════════════════════════════

## CONTEXT
Read `AUDITXPERT-BUILD-SPEC.md` for full context. Root: `C:\Scripts\Assessment\AuditXpert`.
All modules, collectors, analyzers, outputs, orchestrators, tests, and compliance mappings are built.

## TASK 7A: Create HowTo Documentation

Create file: `C:\Scripts\Assessment\AuditXpert\docs\HOWTO.md`

This must be a comprehensive, standalone operations manual. Write it for someone who has never seen the project before — a consultant on your team, an MSP partner, or your future self in 6 months.

### Document Structure — include ALL of the following sections:

---

#### 1. PREREQUISITES & INSTALLATION

Cover:
- PowerShell version requirements (5.1+ / 7.x recommended)
- Required modules with install commands:
  ```powershell
  Install-Module Microsoft.Graph.Authentication -Scope CurrentUser
  Install-Module ExchangeOnlineManagement -Scope CurrentUser  # Optional, for deep Exchange checks
  ```
- Optional tools: `wkhtmltopdf` for PDF generation (where to download, how to install, verify with `wkhtmltopdf --version`)
- Azure AD App Registration steps for automated/MSP use:
  - Step-by-step: Azure Portal → App Registrations → New → name it "AuditXpert Scanner"
  - API Permissions to add (list ALL required Graph permissions from the build spec)
  - How to create a client secret
  - How to create a certificate (PowerShell commands to generate self-signed cert)
  - How to grant admin consent
  - Where to store credentials securely (environment variables, not hardcoded)
- AI Explainer setup: how to get API keys for Claude (api.anthropic.com) and OpenAI, where to set them:
  ```powershell
  $env:ANTHROPIC_API_KEY = "sk-ant-api03-..."
  # Or persist in PowerShell profile:
  # Add to $PROFILE: $env:ANTHROPIC_API_KEY = "sk-ant-api03-..."
  ```
- Running `Install-Prerequisites.ps1` to auto-check everything

---

#### 2. FOLDER STRUCTURE REFERENCE

Show the COMPLETE folder tree with annotations explaining every folder and file:

```
C:\Scripts\Assessment\AuditXpert\
├── src\                          # Source modules — DO NOT MODIFY unless developing
│   ├── Core\                     # Shared infrastructure
│   │   ├── TiTC.Core.psm1       # Auth, Graph API wrapper, config, logging
│   │   └── Models\
│   │       └── TiTC.Models.psm1  # Data contracts (Finding, Report, RiskScore)
│   ├── Collectors\               # Layer 1 — one per M365 domain
│   │   ├── TiTC.Collector.EntraID.psm1
│   │   ├── TiTC.Collector.Exchange.psm1
│   │   ├── TiTC.Collector.Intune.psm1
│   │   ├── TiTC.Collector.Defender.psm1
│   │   └── TiTC.Collector.Licensing.psm1
│   ├── Analyzers\                # Layer 2 — scoring & analysis
│   │   └── TiTC.Analyzer.Risk.psm1
│   └── Outputs\                  # Layer 3 — report generation
│       ├── TiTC.Output.Report.psm1       # HTML/PDF reports
│       ├── TiTC.Output.Evidence.psm1     # Compliance evidence packs
│       └── TiTC.Output.AIExplainer.psm1  # AI-powered explanations
│
├── profiles\                     # ENTRY POINTS — run these scripts
│   ├── Invoke-M365Snapshot.ps1           # Product 1: Full assessment
│   ├── Invoke-MSPAuditPack.ps1           # Product 2: White-label MSP pack
│   └── Invoke-AuditExplainer.ps1         # Product 2.2: Standalone AI explainer
│
├── input\                        # AI EXPLAINER INPUT — drop files here
│   ├── auditxpert\               # AuditXpert's own assessment-results.json
│   ├── third-party\              # Qualys, Nessus, CIS Benchmark, Defender exports
│   └── manual\                   # Manual CSV (columns: Title, Description, Severity)
│
├── compliance\                   # Framework mappings (JSON) — referenced by analyzer
│   ├── iso27001.json
│   ├── cyber-insurance.json
│   ├── soc2-lite.json
│   ├── cis-controls.json
│   └── internal-risk.json
│
├── templates\                    # Report branding assets
│   └── branding\                 # Logos, color overrides
│
├── tests\                        # Pester tests
├── docs\                         # Documentation
│   ├── HOWTO.md                  # THIS FILE
│   ├── AUDITXPERT-BUILD-SPEC.md  # Technical build specification
│   └── build-prompts\            # Claude Code build prompts (development only)
│
├── logs\                         # Runtime logs (auto-created)
├── README.md
├── CHANGELOG.md
└── Install-Prerequisites.ps1     # One-time setup script
```

---

#### 3. PRODUCT 1: M365 RISK & COMPLIANCE SNAPSHOT

Full end-to-end walkthrough with every switch explained:

##### 3.1 Quick Start (simplest possible run)
```powershell
cd C:\Scripts\Assessment\AuditXpert
.\profiles\Invoke-M365Snapshot.ps1 -TenantId "contoso.onmicrosoft.com"
# Browser opens → sign in → assessment runs → output folder created
```

##### 3.2 All Parameters Reference
Create a table listing EVERY parameter with:
- Parameter name
- Type
- Required/Optional
- Default value
- Description
- Example

Example format:
| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `-TenantId` | string | Yes | — | Azure AD tenant ID or domain |
| `-ClientId` | string | For app auth | — | App registration client ID |
| `-ClientSecret` | string | For app auth | — | App registration secret |
| `-CertificateThumbprint` | string | For cert auth | — | Certificate thumbprint |
| `-Profile` | string | No | Full | Assessment profile: Full, Quick, MSPAudit, LicenseOnly, ComplianceOnly |
| `-Domains` | string[] | No | All | Which domains to scan: EntraID, Exchange, Intune, Defender, Licensing |
| `-OutputPath` | string | No | .\TiTC-Snapshot-[timestamp] | Where to save results |
| `-OutputFormat` | string | No | JSON | Report format: PDF, JSON, HTML, All |
| `-IncludeEvidence` | switch | No | off | Generate compliance evidence packs |
| `-IncludeAIExplainer` | switch | No | off | Run AI explainer on findings |
| `-BrandingLogo` | string | No | — | Path to custom logo file |
| `-BrandingCompanyName` | string | No | TakeItToCloud | Company name in report header |
| `-ConfigFile` | string | No | — | Path to custom config JSON |
| `-LogLevel` | string | No | Info | Verbosity: Debug, Info, Warning, Error |
| `-SkipBanner` | switch | No | off | Suppress the ASCII banner |

##### 3.3 Common Usage Examples
Provide 8-10 real-world examples:

```powershell
# Example 1: Full assessment with interactive auth
.\profiles\Invoke-M365Snapshot.ps1 -TenantId "contoso.onmicrosoft.com"

# Example 2: App-based auth (for automation / scheduled tasks)
.\profiles\Invoke-M365Snapshot.ps1 `
    -TenantId "contoso.onmicrosoft.com" `
    -ClientId "12345678-abcd-efgh-ijkl-123456789012" `
    -ClientSecret "your-secret-here"

# Example 3: Certificate-based auth (most secure for automation)
.\profiles\Invoke-M365Snapshot.ps1 `
    -TenantId "contoso.onmicrosoft.com" `
    -ClientId "12345678-abcd-efgh-ijkl-123456789012" `
    -CertificateThumbprint "A1B2C3D4E5F6..."

# Example 4: Quick scan — identity only
.\profiles\Invoke-M365Snapshot.ps1 `
    -TenantId "contoso.onmicrosoft.com" `
    -Profile Quick `
    -Domains EntraID

# Example 5: Full assessment with HTML report and evidence
.\profiles\Invoke-M365Snapshot.ps1 `
    -TenantId "contoso.onmicrosoft.com" `
    -OutputFormat HTML `
    -IncludeEvidence `
    -OutputPath "C:\Reports\Contoso-Assessment"

# Example 6: Full assessment with AI explainer
$env:ANTHROPIC_API_KEY = "sk-ant-..."
.\profiles\Invoke-M365Snapshot.ps1 `
    -TenantId "contoso.onmicrosoft.com" `
    -IncludeAIExplainer `
    -OutputFormat HTML

# Example 7: Custom branded report
.\profiles\Invoke-M365Snapshot.ps1 `
    -TenantId "contoso.onmicrosoft.com" `
    -BrandingCompanyName "Acme Security Consulting" `
    -BrandingLogo "C:\branding\acme-logo.png" `
    -OutputFormat HTML

# Example 8: License-only scan (cost optimization focus)
.\profiles\Invoke-M365Snapshot.ps1 `
    -TenantId "contoso.onmicrosoft.com" `
    -Profile LicenseOnly `
    -Domains Licensing

# Example 9: Debug mode (verbose logging)
.\profiles\Invoke-M365Snapshot.ps1 `
    -TenantId "contoso.onmicrosoft.com" `
    -LogLevel Debug

# Example 10: Scheduled task (Windows Task Scheduler)
# Create a .ps1 wrapper:
# C:\Scripts\scheduled-assessment.ps1
$env:ANTHROPIC_API_KEY = "sk-ant-..."
Set-Location "C:\Scripts\Assessment\AuditXpert"
.\profiles\Invoke-M365Snapshot.ps1 `
    -TenantId "contoso.onmicrosoft.com" `
    -ClientId "..." -ClientSecret "..." `
    -Profile Full -OutputFormat HTML `
    -IncludeEvidence -IncludeAIExplainer `
    -OutputPath "C:\Reports\Scheduled\$(Get-Date -Format 'yyyy-MM-dd')" `
    -SkipBanner
```

##### 3.4 Output Files Explained
List every file in the output folder with what it contains, who it's for, and what to do with it:

| File | Purpose | Audience | Action |
|------|---------|----------|--------|
| `security-assessment-report.html` | Full branded report | Client executives | Open in browser, print to PDF |
| `findings.csv` | All findings in spreadsheet format | Technical team | Open in Excel, filter/sort |
| `remediation-plan.csv` | Prioritized fix list with effort hours | IT manager | Use as project plan |
| `executive-summary.json` | Scores, ratings, narrative | API consumers | Feed to dashboards |
| `risk-analysis.json` | Category scores, quick wins | Analysts | Detailed analysis review |
| `assessment-results.json` | Complete raw assessment data | AI Explainer / archival | Input for AI explainer, historical comparison |
| `compliance-iso27001.json` | ISO 27001 gap analysis | Auditors | Evidence for certification |
| `compliance-cyberinsurance.json` | Insurer requirement status | Insurance broker | Attach to policy application |
| `ai-audit-explanation.html` | AI-generated risk explanations | Non-technical stakeholders | Share with management |
| `evidence\` | Per-framework evidence folders | External auditors | Hand to auditor as-is |
| `audit-trail.json` | Complete operation log | Internal audit | Proves what was scanned and when |
| `assessment.log` | Runtime log with timestamps | Support / debugging | Review if something went wrong |

---

#### 4. PRODUCT 2: MSP AUDIT PACK

Same structure as Product 1 section above. Cover:

##### 4.1 Quick Start
##### 4.2 All Parameters Reference (table)
Include MSP-specific params: `-MSPCompanyName`, `-MSPLogoPath`, `-MSPColors`, `-AuditPacks`
##### 4.3 Common Usage Examples (5-6 examples)
##### 4.4 Output Folder Structure
Show the full MSP output structure:
```
MSP-AuditPack-[timestamp]\
├── report\
│   ├── security-assessment-report.html
│   └── security-assessment-report.pdf
├── evidence\
│   ├── ISO27001\
│   │   ├── control-summary.csv
│   │   ├── A.5.15-access-control\
│   │   │   ├── evidence.json
│   │   │   └── findings.csv
│   │   └── ...
│   ├── CyberInsurance\
│   │   ├── questionnaire-answers.csv
│   │   └── ...
│   └── SOC2Lite\
│       └── ...
├── data\
│   ├── assessment-results.json
│   ├── findings.csv
│   ├── remediation-plan.csv
│   └── executive-summary.json
├── compliance\
│   ├── compliance-iso27001.json
│   └── compliance-cyberinsurance.json
└── metadata.json
```

##### 4.5 How MSPs Use This
- Run against client tenant with app credentials
- Customize branding per MSP
- Hand `evidence\ISO27001\` folder to client's auditor
- Hand `report\` folder to client management
- Use `data\assessment-results.json` as input for AI Explainer

---

#### 5. PRODUCT 2.2: AI AUDIT EXPLAINER

##### 5.1 Quick Start
##### 5.2 Input Sources & Formats

Full table of supported input formats:

| Source | Format | How to Use | Example |
|--------|--------|-----------|---------|
| AuditXpert results | JSON | `-InputFile path\assessment-results.json` | From Product 1/2 output |
| Third-party scan (Qualys) | CSV | `-InputFile path\qualys.csv -InputFormat Qualys` | Export from Qualys console |
| Third-party scan (Nessus) | CSV | `-InputFile path\nessus.csv -InputFormat Nessus` | Export from Nessus |
| Defender export | JSON/CSV | `-InputFile path\defender.json -InputFormat Defender` | Export from Defender portal |
| CIS Benchmark | CSV/JSON | `-InputFile path\cis.csv` | CIS-CAT Pro output |
| Manual findings | CSV | `-InputFile path\findings.csv` | Custom CSV (see format below) |
| Folder of files | Mixed | `-InputFolder path\input\third-party\` | Processes each file |
| Pipeline | TiTCFinding[] | `$findings | .\Invoke-AuditExplainer.ps1` | From M365Snapshot |

##### 5.3 Manual CSV Format
Show the exact CSV format required:
```csv
Title,Description,Severity,Domain
"MFA not enforced","42 users have no MFA registered","High","Identity"
"Outdated OS on 12 devices","Windows 10 21H2 is end of life","Medium","Endpoint"
"Admin account without PIM","3 permanent Global Admins","Critical","Identity"
```
Minimum required columns: `Title`, `Description`, `Severity`
Optional columns: `Domain`, `Remediation`, `AffectedCount`, `ComplianceControls`
Severity values accepted: Critical, High, Medium, Low, Info (or numeric 1-5)

##### 5.4 Where to Place Input Files
```
C:\Scripts\Assessment\AuditXpert\input\
├── auditxpert\     ← AuditXpert JSON files go here
├── third-party\    ← Qualys, Nessus, Defender exports go here
└── manual\         ← Your manual CSV files go here
```

##### 5.5 All Parameters Reference (table)
##### 5.6 Usage Examples (8-10 examples)
```powershell
# Example 1: Explain AuditXpert results
.\profiles\Invoke-AuditExplainer.ps1 `
    -InputFile ".\TiTC-Snapshot-20260322\assessment-results.json"

# Example 2: Explain a Qualys scan
.\profiles\Invoke-AuditExplainer.ps1 `
    -InputFile "C:\exports\qualys-scan.csv" `
    -InputFormat Qualys `
    -OutputFormat HTML

# Example 3: Explain all files in a folder
.\profiles\Invoke-AuditExplainer.ps1 `
    -InputFolder "C:\Scripts\Assessment\AuditXpert\input\third-party\"

# Example 4: High severity only, limit to 10
.\profiles\Invoke-AuditExplainer.ps1 `
    -InputFile ".\findings.csv" `
    -HighSeverityOnly `
    -MaxFindings 10

# Example 5: Use OpenAI instead of Claude
.\profiles\Invoke-AuditExplainer.ps1 `
    -InputFile ".\results.json" `
    -Provider OpenAI `
    -ApiKey $env:OPENAI_API_KEY

# Example 6: Pipeline from M365Snapshot
$report = .\profiles\Invoke-M365Snapshot.ps1 -TenantId "contoso.com"
$report.AllFindings | .\profiles\Invoke-AuditExplainer.ps1 -OutputFormat HTML

# Example 7: Manual CSV input
.\profiles\Invoke-AuditExplainer.ps1 `
    -InputFile "C:\Scripts\Assessment\AuditXpert\input\manual\my-findings.csv" `
    -OutputFormat HTML `
    -TenantName "Acme Corp"

# Example 8: JSON output for API consumption
.\profiles\Invoke-AuditExplainer.ps1 `
    -InputFile ".\results.json" `
    -OutputFormat JSON `
    -OutputPath "C:\Reports\ai-enriched-findings.json"
```

##### 5.7 Output Formats
- **HTML**: Self-contained HTML report with finding cards (risk/impact/fix sections, priority badges, compliance pills). Open in browser, print to PDF.
- **JSON**: Enriched findings JSON with `AIExplanation`, `AIBusinessImpact`, `AIPriority` fields populated.
- **Console**: Formatted table in terminal showing Priority, Severity, Title, Risk Summary (truncated).

##### 5.8 AI Provider Configuration
- Claude (default): requires `ANTHROPIC_API_KEY` env var or `-ApiKey` param
- OpenAI: requires `OPENAI_API_KEY` env var or `-ApiKey` param with `-Provider OpenAI`
- Approximate API cost: ~$0.003 per finding (Claude Sonnet), ~$0.005 per finding (GPT-4o)
- Rate limiting: built-in 500ms delay between calls to avoid throttling

---

#### 6. LOGGING & AUDIT TRAIL

##### 6.1 Log Locations
| Log | Location | Content |
|-----|----------|---------|
| Runtime log | `[OutputPath]\assessment.log` | Timestamped operations log |
| Audit trail | `[OutputPath]\audit-trail.json` | Structured JSON log of all operations |
| Global log | `C:\Scripts\Assessment\AuditXpert\logs\auditxpert.log` | Persistent log across all runs |

##### 6.2 Log Levels
- `Debug`: Everything including Graph API calls, timing, pagination
- `Info` (default): Key operations, progress, summaries
- `Warning`: Non-fatal issues (missing permissions, skipped checks)
- `Error`: Fatal errors (auth failures, API errors)

##### 6.3 Reading Logs
```powershell
# View runtime log
Get-Content ".\TiTC-Snapshot-20260322-143000\assessment.log"

# Search audit trail for errors
$audit = Get-Content ".\TiTC-Snapshot-20260322-143000\audit-trail.json" | ConvertFrom-Json
$audit | Where-Object { $_.Level -eq 'Error' } | Format-Table Timestamp, Component, Message

# View Graph API call count
$audit | Where-Object { $_.Component -eq 'GraphAPI' } | Measure-Object
```

---

#### 7. CONFIGURATION

##### 7.1 Built-in Profiles
| Profile | Domains | Evidence | Use Case |
|---------|---------|----------|----------|
| Full | All 5 | Optional | Complete assessment |
| Quick | EntraID + Exchange + Licensing | No | Fast check |
| MSPAudit | All 5 | Yes | MSP client audit |
| LicenseOnly | Licensing | No | Cost optimization |
| ComplianceOnly | EntraID + Exchange | Yes | Compliance prep |

##### 7.2 Custom Configuration
Show how to create a custom config JSON file:
```json
{
    "Profile": "Custom",
    "Domains": {
        "EntraID": true,
        "Exchange": true,
        "Intune": false,
        "Defender": true,
        "Licensing": true
    },
    "Thresholds": {
        "StaleAccountDays": 60,
        "MFAEnforcementTarget": 100,
        "AdminAccountMaxCount": 3,
        "DeviceComplianceTarget": 98,
        "UnusedLicenseThreshold": 5
    },
    "ComplianceFrameworks": ["ISO27001", "CyberInsurance", "SOC2Lite"],
    "Output": {
        "BrandingCompanyName": "My Company",
        "IncludeEvidence": true,
        "IncludeAIExplainer": true
    }
}
```
Usage: `.\Invoke-M365Snapshot.ps1 -TenantId "..." -ConfigFile "C:\config\custom-profile.json"`

##### 7.3 Threshold Reference
Table of all configurable thresholds with defaults and what they control.

---

#### 8. TROUBLESHOOTING

Cover common issues:
- "Missing required module" → install commands
- "Insufficient permissions" → which Graph permissions to add
- "429 Throttled" → automatic retry, no action needed
- "signInActivity requires Azure AD P1" → expected on free tenants, stale account check is skipped
- "wkhtmltopdf not found" → HTML report works, print to PDF from browser
- "AI explainer timeout" → check API key, try OpenAI as fallback
- "No findings generated" → check if tenant has the services configured
- "Evidence pack empty for framework" → compliance mapping file may need custom entries

---

#### 9. SECURITY CONSIDERATIONS

- All scans are READ-ONLY — zero changes to the tenant
- Client secrets should be stored in environment variables or Azure Key Vault, never in scripts
- Certificate-based auth is recommended for production/scheduled use
- AI Explainer sends finding titles/descriptions to Claude/OpenAI API — no raw data, no tenant IDs
- Output reports contain sensitive configuration data — handle as confidential
- Audit trail provides non-repudiation of what was scanned and when

---

## TASK 7B: Enhanced Logging Implementation

Review the existing `Write-TiTCLog` function in `TiTC.Core.psm1` and enhance it with:

### 1. Persistent Global Log
Add a global log file that persists across runs:
```powershell
$script:GlobalLogPath = Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) 'logs\auditxpert.log'
```
Create the `logs\` directory on first use. Every `Write-TiTCLog` call writes to BOTH the per-run log and the global log.

### 2. Log Rotation
Add a `Invoke-TiTCLogRotation` function:
- Keep last 30 days of global log entries
- Archive older entries to `logs\archive\auditxpert-[date].log`
- Called automatically at the start of each assessment run

### 3. Performance Timing
Add a `Measure-TiTCOperation` function for timing blocks:
```powershell
function Measure-TiTCOperation {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][scriptblock]$ScriptBlock,
        [string]$Component = 'Performance'
    )
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $result = & $ScriptBlock
    $sw.Stop()
    Write-TiTCLog "$Name completed in $($sw.Elapsed.TotalSeconds.ToString('F2'))s" -Level Info -Component $Component -Data @{ Operation = $Name; DurationMs = $sw.ElapsedMilliseconds }
    return $result
}
```
Use in collectors: `$devices = Measure-TiTCOperation -Name 'Fetch managed devices' { Invoke-TiTCGraphRequest ... }`

### 4. Graph API Call Logging
Enhance `Invoke-TiTCGraphRequest` to log:
- Endpoint, method, response time, result count
- Store in a `$script:ApiCallLog` array for performance summary
- Add `Get-TiTCApiCallSummary` function that returns total calls, avg response time, slowest endpoints

### 5. Assessment Summary Report
Add a `Write-TiTCAssessmentSummary` function called at the end of each run:
```
═══════════════════════════════════════════════════════════════
 ASSESSMENT SUMMARY
═══════════════════════════════════════════════════════════════
 Tenant:        Contoso Ltd (contoso.onmicrosoft.com)
 Profile:       Full
 Duration:      4m 32s
 API Calls:     147 (avg 890ms, slowest: /users 3.2s)
 
 Collectors:    5 ran, 5 succeeded, 0 failed
   EntraID:     19 checks → 8 findings (2 critical, 3 high)
   Exchange:    15 checks → 5 findings (1 critical, 2 high)
   Intune:       8 checks → 3 findings (0 critical, 1 high)
   Defender:     7 checks → 2 findings (0 critical, 0 high)
   Licensing:    7 checks → 4 findings (0 critical, 1 high)
 
 Risk Score:    47.3/100 (C+)
 Total Findings: 22 (3 critical, 7 high, 8 medium, 4 low)
 License Waste: €1,247/month (€14,964/year)
 
 Outputs:
   Report:      C:\Reports\security-assessment-report.html
   Evidence:    C:\Reports\evidence\ (3 frameworks)
   AI Report:   C:\Reports\ai-audit-explanation.html
   Full Data:   C:\Reports\assessment-results.json
   Log:         C:\Reports\assessment.log
═══════════════════════════════════════════════════════════════
```

### 6. Error Aggregation
Add `Get-TiTCErrorSummary` that collects all errors/warnings from the run and displays them grouped by component at the end:
```
 WARNINGS (3):
   [Exchange] ExchangeOnlineManagement module not available
   [Intune] signInActivity requires Azure AD P1
   [Defender] Attack Simulation API returned 403
   
 ERRORS (0): None
```

---

## TASK 7C: Update README.md

Update `C:\Scripts\Assessment\AuditXpert\README.md` with:
- Link to HOWTO.md for detailed documentation
- Updated roadmap marking all phases complete
- Quick reference table of all 3 products with one-line usage
- Full list of security checks across all collectors (count per domain)
- Badge-style indicators: total checks, compliance frameworks, etc.
