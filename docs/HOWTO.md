# AuditXpert — Operations Manual

**Version 1.6.0 · TakeItToCloud**

This is the complete operations manual for AuditXpert. It covers installation, all three products, configuration, logging, and troubleshooting. Written for consultants, MSP partners, and anyone running the platform for the first time.

---

## Table of Contents

1. [Prerequisites & Installation](#1-prerequisites--installation)
2. [Folder Structure Reference](#2-folder-structure-reference)
3. [Product 1: M365 Risk & Compliance Snapshot](#3-product-1-m365-risk--compliance-snapshot)
4. [Product 2: MSP Audit Pack](#4-product-2-msp-audit-pack)
5. [Product 2.2: AI Audit Explainer](#5-product-22-ai-audit-explainer)
6. [Logging & Audit Trail](#6-logging--audit-trail)
7. [Configuration](#7-configuration)
8. [Troubleshooting](#8-troubleshooting)
9. [Security Considerations](#9-security-considerations)

---

## 1. Prerequisites & Installation

### 1.1 PowerShell Version

| Version | Support |
|---------|---------|
| PowerShell 5.1 | Minimum — all features work |
| PowerShell 7.x | Recommended — faster, better error messages |

Check your version:
```powershell
$PSVersionTable.PSVersion
```

Install PowerShell 7: [aka.ms/powershell](https://aka.ms/powershell)

---

### 1.2 Required PowerShell Modules

#### Microsoft.Graph.Authentication (required)

Used for all Graph API authentication. Required before any assessment can run.

```powershell
Install-Module Microsoft.Graph.Authentication -Scope CurrentUser -Force
```

Minimum version: **2.0.0**

#### ExchangeOnlineManagement (optional)

Enables deep Exchange Online checks (transport rules, connectors, DMARC) beyond what Graph API exposes. Without it, Exchange collector still runs in Graph-only mode with reduced coverage.

```powershell
Install-Module ExchangeOnlineManagement -Scope CurrentUser -Force
```

Minimum version: **3.0.0**

#### Pester (optional — testing only)

Required to run the Pester unit test suite. Not needed for assessments.

```powershell
Install-Module Pester -Scope CurrentUser -Force
```

Minimum version: **5.0.0**

---

### 1.3 Auto-Check Everything

Run the included prerequisite checker before first use:

```powershell
cd C:\Scripts\Assessment\AuditXpert
.\Install-Prerequisites.ps1
```

The script checks each module, prompts whether to install missing ones, and verifies all project files are present. Add `-IncludeOptional` to also install ExchangeOnlineManagement.

---

### 1.4 Optional Tools

#### wkhtmltopdf (PDF generation)

AuditXpert generates HTML reports natively. To automatically convert them to PDF, install wkhtmltopdf:

1. Download from [wkhtmltopdf.org](https://wkhtmltopdf.org/downloads.html) (Windows installer)
2. Install to `C:\Program Files\wkhtmltopdf\`
3. Verify: `wkhtmltopdf --version`

Without wkhtmltopdf, HTML reports still open correctly in any browser and can be printed to PDF using the browser's built-in print function (`Ctrl+P → Save as PDF`).

---

### 1.5 Azure AD App Registration (for automation / MSP use)

Interactive authentication works for one-off assessments. For scheduled tasks, MSP pipelines, or unattended use, create an App Registration:

#### Step-by-step

1. Go to **Azure Portal** → **Azure Active Directory** → **App Registrations** → **New Registration**
2. Name: `AuditXpert Scanner`
3. Supported account types: **Single tenant**
4. Redirect URI: leave blank
5. Click **Register**
6. Copy the **Application (client) ID** — this is your `-ClientId`
7. Copy the **Directory (tenant) ID** — this is your `-TenantId`

#### Add API Permissions

Under **API Permissions** → **Add a permission** → **Microsoft Graph** → **Application permissions**, add:

| Permission | Used By |
|-----------|---------|
| `Directory.Read.All` | EntraID — users, groups, roles |
| `Policy.Read.All` | EntraID — CA policies, auth methods |
| `SecurityEvents.Read.All` | Defender — alerts, incidents |
| `DeviceManagementConfiguration.Read.All` | Intune — compliance policies |
| `DeviceManagementManagedDevices.Read.All` | Intune — device inventory |
| `MailboxSettings.Read` | Exchange — mailbox configuration |
| `Organization.Read.All` | Core — tenant info |
| `Reports.Read.All` | Licensing — usage reports |
| `RoleManagement.Read.Directory` | EntraID — role assignments |
| `User.Read.All` | All collectors — user data |
| `Group.Read.All` | EntraID — group memberships |
| `Application.Read.All` | EntraID — service principals |
| `AuditLog.Read.All` | EntraID — sign-in logs |
| `SecurityActions.Read.All` | Defender — secure score |
| `IdentityRiskEvent.Read.All` | EntraID — risky sign-ins |
| `IdentityRiskyUser.Read.All` | EntraID — risky users |

Click **Grant admin consent** after adding all permissions.

#### Create a Client Secret

1. **Certificates & Secrets** → **New client secret**
2. Set expiry: 12 or 24 months
3. Copy the **Value** immediately — it won't be shown again
4. Store securely (see Section 9)

#### Create a Certificate (recommended for production)

```powershell
# Generate a self-signed certificate (valid 2 years)
$cert = New-SelfSignedCertificate `
    -Subject "CN=AuditXpert-Scanner" `
    -CertStoreLocation "Cert:\CurrentUser\My" `
    -KeyExportPolicy Exportable `
    -KeySpec Signature `
    -KeyLength 2048 `
    -HashAlgorithm SHA256 `
    -NotAfter (Get-Date).AddYears(2)

# Note the thumbprint
Write-Host "Thumbprint: $($cert.Thumbprint)"

# Export the public key (.cer) to upload to Azure
Export-Certificate -Cert $cert `
    -FilePath "C:\Certs\AuditXpert-Scanner.cer"
```

Upload the `.cer` file under **Certificates & Secrets** → **Certificates** → **Upload certificate**.

---

### 1.6 Store Credentials Securely

**Never hardcode credentials in scripts.** Use environment variables:

```powershell
# Set for current session only
$env:AUDITXPERT_CLIENT_ID     = "12345678-abcd-efgh-ijkl-123456789012"
$env:AUDITXPERT_CLIENT_SECRET = "your-secret-here"
$env:AUDITXPERT_TENANT_ID     = "contoso.onmicrosoft.com"

# Persist in PowerShell profile (add to $PROFILE)
notepad $PROFILE
# Add the lines above, save, restart PowerShell
```

For production/server environments, use **Azure Key Vault** or **Windows Credential Manager**.

---

### 1.7 AI Explainer API Keys

The AI Explainer (Product 2.2) requires an API key from either Anthropic (Claude) or OpenAI.

#### Claude (Anthropic) — default provider

Get your key at [console.anthropic.com](https://console.anthropic.com):

```powershell
# Set for current session
$env:ANTHROPIC_API_KEY = "sk-ant-api03-..."

# Persist in PowerShell profile
# Add to $PROFILE:
$env:ANTHROPIC_API_KEY = "sk-ant-api03-..."
```

#### OpenAI

Get your key at [platform.openai.com](https://platform.openai.com):

```powershell
$env:OPENAI_API_KEY = "sk-proj-..."
```

Approximate cost per finding: ~$0.003 (Claude Sonnet), ~$0.005 (GPT-4o)

---

## 2. Folder Structure Reference

```
C:\Scripts\Assessment\AuditXpert\
├── src\                              # Source modules — do not modify unless developing
│   ├── Core\                         # Shared infrastructure
│   │   ├── TiTC.Core.psm1           # Auth, Graph API wrapper, config, logging
│   │   ├── TiTC.Core.psd1           # Module manifest
│   │   └── Models\
│   │       ├── TiTC.Models.psm1     # Data contracts (Finding, Report, RiskScore, LicenseWaste)
│   │       └── TiTC.Models.psd1
│   ├── Collectors\                   # Layer 1 — one module per M365 domain
│   │   ├── TiTC.Collector.EntraID.psm1      # 19 identity & access checks
│   │   ├── TiTC.Collector.EntraID.psd1
│   │   ├── TiTC.Collector.Exchange.psm1     # 15 mail flow & security checks
│   │   ├── TiTC.Collector.Exchange.psd1
│   │   ├── TiTC.Collector.Intune.psm1       # 8 endpoint & device checks
│   │   ├── TiTC.Collector.Intune.psd1
│   │   ├── TiTC.Collector.Defender.psm1     # 7 threat protection checks
│   │   ├── TiTC.Collector.Defender.psd1
│   │   ├── TiTC.Collector.Licensing.psm1    # 7 license optimization checks
│   │   └── TiTC.Collector.Licensing.psd1
│   ├── Analyzers\                    # Layer 2 — risk scoring & compliance mapping
│   │   ├── TiTC.Analyzer.Risk.psm1  # Composite risk score, gap analysis, narratives
│   │   └── TiTC.Analyzer.Risk.psd1
│   └── Outputs\                      # Layer 3 — report & evidence generation
│       ├── TiTC.Output.Report.psm1          # HTML/PDF branded report (11 sections)
│       ├── TiTC.Output.Report.psd1
│       ├── TiTC.Output.Evidence.psm1        # Compliance evidence pack (per framework)
│       ├── TiTC.Output.Evidence.psd1
│       ├── TiTC.Output.AIExplainer.psm1     # AI plain-English explainer + card report
│       └── TiTC.Output.AIExplainer.psd1
│
├── profiles\                         # ENTRY POINTS — these are the scripts you run
│   ├── Invoke-M365Snapshot.ps1       # Product 1: Full M365 assessment
│   ├── Invoke-MSPAuditPack.ps1       # Product 2: White-label MSP audit pack
│   └── Invoke-AuditExplainer.ps1     # Product 2.2: Standalone AI explainer
│
├── input\                            # AI EXPLAINER INPUT — drop source files here
│   ├── auditxpert\                   # AuditXpert assessment-results.json files
│   ├── third-party\                  # Qualys, Nessus, CIS Benchmark, Defender exports
│   └── manual\                       # Manual CSV files (Title, Description, Severity)
│
├── compliance\                       # Framework control mappings (JSON)
│   ├── iso27001.json                 # 15 ISO 27001:2022 Annex A controls
│   ├── cyber-insurance.json          # 12 cyber insurance requirements
│   ├── soc2-lite.json                # 11 SOC 2 Trust Service Criteria
│   ├── cis-controls.json             # 22 CIS M365 Foundations v3.1 controls
│   └── internal-risk.json            # 10 internal risk review controls
│
├── templates\                        # Report branding assets
│   └── branding\                     # Logo files, color overrides
│
├── tests\                            # Pester unit tests
│   ├── TiTC.Models.Tests.ps1         # 20 tests — data model
│   ├── TiTC.Core.Tests.ps1           # 12 tests — core functions
│   └── TiTC.Analyzer.Risk.Tests.ps1  # 15 tests — risk scoring
│
├── docs\                             # Documentation
│   ├── HOWTO.md                      # THIS FILE — operations manual
│   ├── AUDITXPERT-BUILD-SPEC.md      # Technical architecture specification
│   └── build-prompts\                # Claude Code build prompts (development only)
│
├── logs\                             # Runtime logs (auto-created on first run)
│   ├── auditxpert.log                # Persistent global log across all runs
│   └── archive\                      # Rotated logs (entries older than 30 days)
│
├── README.md                         # Project overview and quick start
├── CHANGELOG.md                      # Version history
└── Install-Prerequisites.ps1         # One-time setup and validation script
```

**Output folders** (auto-created per run, excluded from git):
```
TiTC-Snapshot-[timestamp]\    # Product 1 output
MSP-AuditPack-[timestamp]\    # Product 2 output
```

---

## 3. Product 1: M365 Risk & Compliance Snapshot

Runs a full M365 security assessment and produces a branded report, prioritized remediation plan, and optional compliance evidence packs.

### 3.1 Quick Start

The simplest possible run — browser opens for interactive sign-in:

```powershell
cd C:\Scripts\Assessment\AuditXpert
.\profiles\Invoke-M365Snapshot.ps1 -TenantId "contoso.onmicrosoft.com"
```

What happens:
1. Prerequisite check runs
2. Browser opens → sign in with Global Reader or Security Reader account
3. All 5 collectors run (56 checks total)
4. Risk analyzer scores results
5. HTML report, CSV findings, and JSON data saved to `.\TiTC-Snapshot-[timestamp]\`

---

### 3.2 All Parameters Reference

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `-TenantId` | string | **Yes** | — | Azure AD tenant ID (GUID) or domain name (e.g. `contoso.onmicrosoft.com`) |
| `-ClientId` | string | App auth | — | App registration client ID |
| `-ClientSecret` | string | App auth | — | App registration client secret |
| `-CertificateThumbprint` | string | Cert auth | — | Certificate thumbprint from local cert store |
| `-Profile` | string | No | `Full` | Assessment scope: `Full`, `Quick`, `MSPAudit`, `LicenseOnly`, `ComplianceOnly` |
| `-Domains` | string[] | No | All | Which collectors to run: `EntraID`, `Exchange`, `Intune`, `Defender`, `Licensing` |
| `-OutputPath` | string | No | `.\TiTC-Snapshot-[timestamp]` | Destination folder for all output files |
| `-OutputFormat` | string | No | `JSON` | Report format: `PDF`, `HTML`, `JSON`, `All` |
| `-IncludeEvidence` | switch | No | off | Generate compliance evidence packs alongside the report |
| `-IncludeAIExplainer` | switch | No | off | Run AI explainer on findings (requires API key) |
| `-BrandingLogo` | string | No | — | Path to PNG/SVG logo file for report header |
| `-BrandingCompanyName` | string | No | `TakeItToCloud` | Company name shown in report header and footer |
| `-ConfigFile` | string | No | — | Path to custom config JSON (see Section 7.2) |
| `-LogLevel` | string | No | `Info` | Log verbosity: `Debug`, `Info`, `Warning`, `Error` |
| `-SkipBanner` | switch | No | off | Suppress the ASCII art banner (useful for automation) |

---

### 3.3 Common Usage Examples

```powershell
# Example 1: Full assessment — interactive auth
.\profiles\Invoke-M365Snapshot.ps1 -TenantId "contoso.onmicrosoft.com"

# Example 2: App-based auth (for automation / scheduled tasks)
.\profiles\Invoke-M365Snapshot.ps1 `
    -TenantId "contoso.onmicrosoft.com" `
    -ClientId "12345678-abcd-efgh-ijkl-123456789012" `
    -ClientSecret $env:AUDITXPERT_CLIENT_SECRET

# Example 3: Certificate-based auth (most secure for production)
.\profiles\Invoke-M365Snapshot.ps1 `
    -TenantId "contoso.onmicrosoft.com" `
    -ClientId "12345678-abcd-efgh-ijkl-123456789012" `
    -CertificateThumbprint "A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6A1B2"

# Example 4: Quick scan — identity only (fastest)
.\profiles\Invoke-M365Snapshot.ps1 `
    -TenantId "contoso.onmicrosoft.com" `
    -Profile Quick `
    -Domains EntraID

# Example 5: Full assessment with HTML report and evidence packs
.\profiles\Invoke-M365Snapshot.ps1 `
    -TenantId "contoso.onmicrosoft.com" `
    -OutputFormat HTML `
    -IncludeEvidence `
    -OutputPath "C:\Reports\Contoso-Assessment"

# Example 6: Full assessment with AI-generated explanations
$env:ANTHROPIC_API_KEY = "sk-ant-..."
.\profiles\Invoke-M365Snapshot.ps1 `
    -TenantId "contoso.onmicrosoft.com" `
    -IncludeAIExplainer `
    -OutputFormat HTML

# Example 7: Custom branded report for a client
.\profiles\Invoke-M365Snapshot.ps1 `
    -TenantId "contoso.onmicrosoft.com" `
    -BrandingCompanyName "Acme Security Consulting" `
    -BrandingLogo "C:\branding\acme-logo.png" `
    -OutputFormat HTML

# Example 8: License-only scan (cost optimisation focus)
.\profiles\Invoke-M365Snapshot.ps1 `
    -TenantId "contoso.onmicrosoft.com" `
    -Profile LicenseOnly `
    -Domains Licensing

# Example 9: Debug mode — verbose logging for troubleshooting
.\profiles\Invoke-M365Snapshot.ps1 `
    -TenantId "contoso.onmicrosoft.com" `
    -LogLevel Debug

# Example 10: Scheduled task (Windows Task Scheduler automation)
# Create a wrapper script at C:\Scripts\scheduled-assessment.ps1:
$env:ANTHROPIC_API_KEY = "sk-ant-..."
Set-Location "C:\Scripts\Assessment\AuditXpert"
.\profiles\Invoke-M365Snapshot.ps1 `
    -TenantId "contoso.onmicrosoft.com" `
    -ClientId $env:AUDITXPERT_CLIENT_ID `
    -ClientSecret $env:AUDITXPERT_CLIENT_SECRET `
    -Profile Full `
    -OutputFormat HTML `
    -IncludeEvidence -IncludeAIExplainer `
    -OutputPath "C:\Reports\Scheduled\$(Get-Date -Format 'yyyy-MM-dd')" `
    -SkipBanner
```

---

### 3.4 Output Files Explained

All files are written to the `-OutputPath` folder.

| File | Purpose | Audience | Action |
|------|---------|----------|--------|
| `security-assessment-report.html` | Full branded security report | Client executives, management | Open in browser; print to PDF (`Ctrl+P`) |
| `security-assessment-report.pdf` | PDF version (requires wkhtmltopdf) | Same as above | Send directly to client |
| `findings.csv` | All findings in spreadsheet format | Technical team | Open in Excel, filter by Severity/Domain |
| `remediation-plan.csv` | Prioritised fix list with effort estimates | IT manager | Use as project plan / ticket backlog |
| `executive-summary.json` | Risk scores, ratings, narrative text | API consumers, dashboards | Feed into client portal or SIEM |
| `risk-analysis.json` | Category scores, quick wins, trends | Security analysts | Detailed analysis and benchmarking |
| `assessment-results.json` | Complete raw assessment data | AI Explainer, archival | Input for AI explainer; compare across runs |
| `compliance-iso27001.json` | ISO 27001:2022 gap analysis | External auditors | Evidence for certification gap assessment |
| `compliance-cyberinsurance.json` | Cyber insurer requirement status | Broker, underwriter | Attach to insurance application / renewal |
| `ai-security-briefing.html` | AI-generated finding cards | Non-technical stakeholders | Share with board/management |
| `evidence\` | Per-framework evidence folders | External auditors | Hand to auditor as-is (see Section 4.4) |
| `audit-trail.json` | Structured log of all operations | Internal compliance | Proves what was scanned, when, by whom |
| `assessment.log` | Human-readable runtime log | Support, debugging | Review when something goes wrong |

---

## 4. Product 2: MSP Audit Pack

White-label audit pack for MSPs. Runs a full assessment and produces client-ready deliverables with your branding — one command, ready to hand over.

### 4.1 Quick Start

```powershell
cd C:\Scripts\Assessment\AuditXpert
.\profiles\Invoke-MSPAuditPack.ps1 `
    -TenantId "client.onmicrosoft.com" `
    -MSPCompanyName "SecureIT Solutions"
```

---

### 4.2 All Parameters Reference

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `-TenantId` | string | **Yes** | — | Client tenant ID or domain |
| `-MSPCompanyName` | string | **Yes** | — | Your MSP company name (appears on all reports) |
| `-ClientId` | string | App auth | — | App registration client ID |
| `-ClientSecret` | string | App auth | — | Client secret |
| `-CertificateThumbprint` | string | Cert auth | — | Certificate thumbprint |
| `-MSPLogoPath` | string | No | — | Path to your MSP logo (PNG/SVG, max 200×60px) |
| `-MSPColors` | hashtable | No | TiTC defaults | Brand colors: `@{ Primary='#0F172A'; Accent='#10B981' }` |
| `-AuditPacks` | string[] | No | `Full` | Which frameworks to include: `ISO27001`, `SOC2Lite`, `CyberInsurance`, `InternalRisk`, `Full` |
| `-Domains` | string[] | No | All | Which collectors to run |
| `-OutputPath` | string | No | `.\MSP-AuditPack-[timestamp]` | Destination for all output |
| `-ReportFormat` | string | No | `HTML` | Report format: `HTML`, `PDF`, `Both` |
| `-IncludeAIExplainer` | switch | No | off | Run AI explainer (requires API key) |
| `-LogLevel` | string | No | `Info` | Log verbosity |
| `-SkipBanner` | switch | No | off | Suppress banner (automation mode) |

---

### 4.3 Common Usage Examples

```powershell
# Example 1: ISO 27001 + Cyber Insurance evidence pack
.\profiles\Invoke-MSPAuditPack.ps1 `
    -TenantId "client.onmicrosoft.com" `
    -ClientId $cid -ClientSecret $secret `
    -MSPCompanyName "SecureIT Solutions" `
    -MSPLogoPath "C:\branding\secureit-logo.png" `
    -AuditPacks ISO27001, CyberInsurance

# Example 2: Full pack — all frameworks, PDF output
.\profiles\Invoke-MSPAuditPack.ps1 `
    -TenantId "client.onmicrosoft.com" `
    -ClientId $cid -ClientSecret $secret `
    -MSPCompanyName "SecureIT Solutions" `
    -AuditPacks Full `
    -ReportFormat PDF

# Example 3: Full pack with AI explanations
$env:ANTHROPIC_API_KEY = "sk-ant-..."
.\profiles\Invoke-MSPAuditPack.ps1 `
    -TenantId "client.onmicrosoft.com" `
    -ClientId $cid -ClientSecret $secret `
    -MSPCompanyName "SecureIT Solutions" `
    -AuditPacks Full -IncludeAIExplainer

# Example 4: Custom branded colors
.\profiles\Invoke-MSPAuditPack.ps1 `
    -TenantId "client.onmicrosoft.com" `
    -MSPCompanyName "Blue Shield IT" `
    -MSPColors @{ Primary = '#1E3A5F'; Accent = '#2196F3' } `
    -AuditPacks ISO27001

# Example 5: Quick compliance-only audit
.\profiles\Invoke-MSPAuditPack.ps1 `
    -TenantId "client.onmicrosoft.com" `
    -MSPCompanyName "MyMSP" `
    -Domains EntraID, Exchange `
    -AuditPacks CyberInsurance

# Example 6: Scheduled monthly audit (automated)
.\profiles\Invoke-MSPAuditPack.ps1 `
    -TenantId $env:CLIENT_TENANT_ID `
    -ClientId $env:CLIENT_APP_ID `
    -CertificateThumbprint $env:CERT_THUMBPRINT `
    -MSPCompanyName "SecureIT Solutions" `
    -AuditPacks Full -ReportFormat PDF `
    -OutputPath "C:\ClientReports\$(Get-Date -Format 'yyyy-MM')" `
    -SkipBanner
```

---

### 4.4 Output Folder Structure

```
MSP-AuditPack-[timestamp]\
├── report\
│   ├── security-assessment-report.html     # Branded HTML report
│   └── security-assessment-report.pdf      # PDF version (if wkhtmltopdf available)
│
├── evidence\
│   ├── ISO27001\
│   │   ├── control-summary.csv             # All controls: status, finding count
│   │   ├── A.5.15-access-control\
│   │   │   ├── evidence.json               # Full evidence for this control
│   │   │   └── findings.csv               # Findings mapped to this control
│   │   ├── A.8.3-information-access\
│   │   │   └── ...
│   │   └── ...                             # One folder per control with findings
│   ├── CyberInsurance\
│   │   ├── questionnaire-answers.csv       # Insurance questionnaire format
│   │   └── ...
│   ├── SOC2Lite\
│   │   └── ...
│   └── InternalRisk\
│       └── ...
│
├── data\
│   ├── assessment-results.json             # Complete raw data (input for AI Explainer)
│   ├── findings.csv                        # All findings in spreadsheet format
│   ├── remediation-plan.csv               # Prioritised remediation list
│   └── executive-summary.json             # Scores, ratings, narrative
│
├── compliance\
│   ├── compliance-iso27001.json            # ISO 27001 gap analysis
│   └── compliance-cyberinsurance.json      # Insurer requirement status
│
└── metadata.json                           # Run metadata: tenant, MSP, timestamps
```

---

### 4.5 How MSPs Use This in Practice

1. **Run** against the client tenant using certificate-based app credentials (no interactive login needed)
2. **Hand `evidence\ISO27001\`** to the client's external ISO 27001 auditor — the folder structure matches what auditors expect
3. **Hand `report\`** to client management — the PDF is board-ready
4. **Hand `evidence\CyberInsurance\questionnaire-answers.csv`** to the insurance broker — answers map directly to underwriter questions
5. **Feed `data\assessment-results.json`** into the AI Explainer for executive briefing documents
6. **Archive** to `C:\ClientReports\[ClientName]\[Date]\` for historical comparison

---

## 5. Product 2.2: AI Audit Explainer

Standalone AI-powered tool that takes security findings from any source and produces plain-English explanations for business executives.

### 5.1 Quick Start

```powershell
cd C:\Scripts\Assessment\AuditXpert
.\profiles\Invoke-AuditExplainer.ps1 `
    -InputFile ".\TiTC-Snapshot-20260322-143000\assessment-results.json"
# An HTML report opens in your output folder
```

---

### 5.2 Input Sources & Formats

| Source | Format | How to Use | Notes |
|--------|--------|-----------|-------|
| AuditXpert results | JSON | `-InputFile path\assessment-results.json` | Auto-detected; `AllFindings` array |
| Qualys export | CSV | `-InputFile path\qualys.csv -InputFormat Qualys` | Export from Qualys console → CSV |
| Nessus export | CSV | `-InputFile path\nessus.csv -InputFormat Nessus` | Nessus → Report → CSV export |
| Defender export | CSV | `-InputFile path\defender.csv -InputFormat Defender` | Security portal → Alerts → Export |
| CIS Benchmark | CSV | `-InputFile path\cis.csv` | CIS-CAT Pro CSV output; auto-detected |
| Manual findings | CSV | `-InputFile path\findings.csv` | See format below |
| Folder of files | Mixed | `-InputFolder path\input\third-party\` | Each file auto-detected |
| Pipeline | objects | `$findings \| .\Invoke-AuditExplainer.ps1` | TiTCFinding or PSCustomObject |

---

### 5.3 Manual CSV Format

Minimum required columns: `Title`, `Description`, `Severity`

```csv
Title,Description,Severity,Remediation
"MFA not enforced","42 users have no MFA registered. Any compromised password = full account access.","High","Enable MFA in Azure AD and create a Conditional Access policy requiring MFA for all users."
"Outdated OS on 12 devices","Windows 10 21H2 is end-of-life and no longer receiving security patches.","Medium","Enroll devices in Windows Update for Business and set a compliance policy requiring current OS."
"3 permanent Global Admins","Permanent Global Admin access violates least-privilege. Should use PIM.","Critical","Enable Azure AD PIM. Assign Global Admin as eligible-only and require approval for activation."
```

**Accepted Severity values:** `Critical`, `High`, `Medium`, `Low`, `Info` (or numeric `5`, `4`, `3`, `2`, `1`)

**Optional columns:** `Domain`, `Remediation`, `ComplianceControls`

---

### 5.4 Where to Place Input Files

```
C:\Scripts\Assessment\AuditXpert\input\
├── auditxpert\     ← AuditXpert assessment-results.json files go here
├── third-party\    ← Qualys, Nessus, Defender, CIS exports go here
└── manual\         ← Your manual CSV findings files go here
```

Then process a whole folder in one command:
```powershell
.\profiles\Invoke-AuditExplainer.ps1 -InputFolder ".\input\third-party\"
```

---

### 5.5 All Parameters Reference

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `-InputFile` | string | File mode | — | Single input file (any supported format) |
| `-InputFolder` | string | Folder mode | — | Process all .json and .csv files in this folder |
| `-Findings` | object[] | Pipeline | — | TiTCFinding or PSCustomObject array via pipeline |
| `-InputFormat` | string | No | `Auto` | Force format: `Auto`, `AuditXpert`, `CSV`, `Qualys`, `Nessus`, `Defender` |
| `-Provider` | string | No | `Claude` | AI provider: `Claude` or `OpenAI` |
| `-ApiKey` | string | No | env var | API key (overrides `ANTHROPIC_API_KEY` / `OPENAI_API_KEY`) |
| `-Model` | string | No | model default | Override the AI model name |
| `-HighSeverityOnly` | switch | No | off | Only explain Critical and High severity findings |
| `-MaxFindings` | int | No | `20` | Cap on findings sent to AI (cost control) |
| `-TenantName` | string | No | `M365 Tenant` | Client name shown in report header |
| `-CompanyName` | string | No | `TakeItToCloud` | MSP/author name in report |
| `-OutputPath` | string | No | auto-generated | Destination .html or .json file |
| `-OutputFormat` | string | No | `HTML` | Output format: `HTML`, `JSON`, `Console` |

---

### 5.6 Usage Examples

```powershell
# Example 1: Explain AuditXpert results (auto-detected format)
.\profiles\Invoke-AuditExplainer.ps1 `
    -InputFile ".\TiTC-Snapshot-20260322\assessment-results.json"

# Example 2: Explain a Qualys scan export
.\profiles\Invoke-AuditExplainer.ps1 `
    -InputFile "C:\exports\qualys-scan-20260322.csv" `
    -InputFormat Qualys `
    -TenantName "Contoso" `
    -OutputPath "C:\Reports\contoso-ai-briefing.html"

# Example 3: Explain all files in the input folder
.\profiles\Invoke-AuditExplainer.ps1 `
    -InputFolder "C:\Scripts\Assessment\AuditXpert\input\third-party\"

# Example 4: Critical and high findings only, limit to 10
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
$report.AllFindings | .\profiles\Invoke-AuditExplainer.ps1 `
    -TenantName "Contoso" -OutputFormat HTML

# Example 7: Manual CSV with tenant branding
.\profiles\Invoke-AuditExplainer.ps1 `
    -InputFile ".\input\manual\acme-findings.csv" `
    -OutputFormat HTML `
    -TenantName "Acme Corp" `
    -CompanyName "SecureIT Solutions"

# Example 8: JSON output for API/dashboard consumption
.\profiles\Invoke-AuditExplainer.ps1 `
    -InputFile ".\results.json" `
    -OutputFormat JSON `
    -OutputPath "C:\Reports\ai-enriched-findings.json"

# Example 9: Console output (quick review in terminal)
.\profiles\Invoke-AuditExplainer.ps1 `
    -InputFile ".\results.json" `
    -OutputFormat Console `
    -HighSeverityOnly
```

---

### 5.7 HTML Report Structure

The HTML output (`Export-TiTCAIReport`) generates a self-contained card-based briefing:

- **Header**: Tenant name, company, generation date, and finding count summary (total / critical / high / medium)
- **Finding cards**: One card per finding, containing:
  - Severity badge (colour-coded: red=Critical, orange=High, amber=Medium, green=Low)
  - Priority pill (P5=Fix immediately → P1=Nice to have)
  - **"What's the risk?"** section (red left border) — plain-English AI explanation
  - **"Business impact"** section (amber left border) — what could go wrong
  - **"How to fix this"** section (green left border) — structured remediation steps
  - Compliance control pills (e.g., `ISO27001:A.9.4.2`, `CIS:1.1.4`)

The report is self-contained (no external dependencies) and prints cleanly to PDF from any browser.

---

### 5.8 AI Provider Configuration

| Setting | Claude (default) | OpenAI |
|---------|-----------------|--------|
| Environment variable | `ANTHROPIC_API_KEY` | `OPENAI_API_KEY` |
| Default model | `claude-sonnet-4-20250514` | `gpt-4o-mini` |
| Approx cost / finding | ~$0.003 | ~$0.005 |
| Override model | `-Model claude-opus-4-20250514` | `-Model gpt-4o` |

Both providers have built-in rate-limiting protection. The module retries on 429 errors automatically.

---

## 6. Logging & Audit Trail

### 6.1 Log Locations

| Log | Location | Content | Persists? |
|-----|----------|---------|-----------|
| Runtime log | `[OutputPath]\assessment.log` | Timestamped operations for this run | Per-run |
| Audit trail | `[OutputPath]\audit-trail.json` | Structured JSON of all operations | Per-run |
| Global log | `logs\auditxpert.log` | All log entries across all runs | Persistent |
| Archived logs | `logs\archive\auditxpert-[date].log` | Rotated entries older than 30 days | 30+ days old |

### 6.2 Log Levels

| Level | What it includes | Use when |
|-------|-----------------|----------|
| `Debug` | Everything: Graph API calls, timing, pagination, every operation | Troubleshooting a specific issue |
| `Info` | Key operations, progress markers, summaries | Normal operation (default) |
| `Warning` | Non-fatal issues (missing permissions, skipped checks) | Always captured |
| `Error` | Fatal errors (auth failures, API errors) | Always captured |

Set log level: `-LogLevel Debug`

### 6.3 Reading Logs

```powershell
# View runtime log
Get-Content ".\TiTC-Snapshot-20260322-143000\assessment.log"

# Search structured audit trail for errors
$audit = Get-Content ".\TiTC-Snapshot-20260322-143000\audit-trail.json" | ConvertFrom-Json
$audit | Where-Object { $_.Level -eq 'Error' } | Format-Table Timestamp, Component, Message

# Count Graph API calls in a run
$audit | Where-Object { $_.Component -eq 'GraphAPI' } | Measure-Object

# View slowest API calls
$audit | Where-Object { $_.Data.DurationMs -gt 5000 } |
    Select-Object Timestamp, Message, @{N='DurationMs';E={$_.Data.DurationMs}} |
    Sort-Object DurationMs -Descending

# View global log (all runs)
Get-Content "logs\auditxpert.log" | Select-Object -Last 100

# Search global log for errors across all runs
Get-Content "logs\auditxpert.log" | Where-Object { $_ -match '\[ERROR\]' }
```

### 6.4 Assessment Summary

At the end of each run, the platform prints a summary to console and logs it:

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
   AI Report:   C:\Reports\ai-security-briefing.html
   Full Data:   C:\Reports\assessment-results.json
   Log:         C:\Reports\assessment.log
═══════════════════════════════════════════════════════════════
```

---

## 7. Configuration

### 7.1 Built-in Assessment Profiles

| Profile | Domains | Evidence | Speed | Use Case |
|---------|---------|----------|-------|----------|
| `Full` | All 5 | Optional | ~4–6 min | Complete M365 assessment |
| `Quick` | EntraID + Exchange + Licensing | No | ~1–2 min | Fast health check |
| `MSPAudit` | All 5 | Yes | ~5–7 min | MSP client audit delivery |
| `LicenseOnly` | Licensing | No | ~30 sec | Cost optimisation focus |
| `ComplianceOnly` | EntraID + Exchange | Yes | ~2–3 min | Compliance preparation |

---

### 7.2 Custom Configuration File

Create a JSON config file and pass with `-ConfigFile`:

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

Usage:
```powershell
.\profiles\Invoke-M365Snapshot.ps1 -TenantId "..." -ConfigFile "C:\config\client-profile.json"
```

---

### 7.3 Threshold Reference

| Threshold | Default | What it controls |
|-----------|---------|-----------------|
| `StaleAccountDays` | `90` | Days since last sign-in before account is flagged as stale |
| `PasswordAgeDays` | `365` | Max password age before flagging |
| `MFAEnforcementTarget` | `100` | % of users with MFA (anything below = finding) |
| `GuestAccountMaxAge` | `180` | Days before a guest account is flagged as old |
| `AdminAccountMaxCount` | `5` | Max Global Admin count before flagging over-privilege |
| `UnusedLicenseThreshold` | `10` | % unused licenses before flagging waste |
| `ConditionalAccessMinPolicies` | `3` | Minimum CA policy count |
| `DeviceComplianceTarget` | `95` | % of devices compliant (below = finding) |

---

## 8. Troubleshooting

### "Missing required module: Microsoft.Graph.Authentication"

```powershell
Install-Module Microsoft.Graph.Authentication -Scope CurrentUser -Force
```

Or run `.\Install-Prerequisites.ps1` to check and install everything.

---

### "Insufficient permissions for /users"

The app registration is missing one or more Graph API permissions. Check the required permissions list in Section 1.5. Go to Azure Portal → App Registrations → your app → API Permissions, add any missing permissions, and click **Grant admin consent**.

---

### "429 Throttled" messages

This is normal for large tenants. The platform automatically retries with exponential backoff. No action needed — the assessment will complete, just slower. Use `-LogLevel Debug` to see retry details.

---

### "signInActivity requires Azure AD P1"

Expected on tenants without Azure AD Premium P1. The stale account check falls back to `createdDateTime` for sign-in data. This is logged as a Warning — not an error.

---

### "wkhtmltopdf not found — PDF generation skipped"

The HTML report still generates correctly. To produce PDF:
- Option A: Install wkhtmltopdf (Section 1.4)
- Option B: Open the HTML in Chrome/Edge → `Ctrl+P` → **Save as PDF** → ensures correct formatting

---

### "AI explainer returned no explanations"

Check: (1) API key is set correctly — `echo $env:ANTHROPIC_API_KEY` (2) API key has credits/quota remaining (3) Network can reach `api.anthropic.com`. Try OpenAI as fallback: `-Provider OpenAI -ApiKey $env:OPENAI_API_KEY`.

---

### "No findings generated for a collector"

If a collector returns 0 findings, either: (a) the tenant is genuinely well-configured in that area (great!), or (b) the app lacks permissions for that collector. Check the audit trail for 403 warnings from that collector's component.

---

### "Evidence pack empty for a framework"

The compliance mapping JSON files must be present in the `compliance\` folder. Verify with:
```powershell
.\Install-Prerequisites.ps1
```
If files are missing, re-extract the AuditXpert package.

---

### Exchange checks show limited results

Without the `ExchangeOnlineManagement` module, Exchange collector runs in Graph-only mode. Install the module for full coverage:
```powershell
Install-Module ExchangeOnlineManagement -Scope CurrentUser -Force
```

---

## 9. Security Considerations

- **All scans are read-only.** AuditXpert never makes changes to the tenant. All Graph API permissions are read-only (`*.Read.*`).

- **Client secrets and certificates** must be stored in environment variables, Azure Key Vault, or Windows Credential Manager. Never hardcode them in scripts or commit them to source control. The `.gitignore` excludes common secret file types.

- **Certificate-based authentication** is recommended for all production and scheduled use. Unlike client secrets, certificates can be revoked instantly without regenerating the app registration.

- **AI Explainer data privacy**: The AI Explainer sends finding titles and descriptions to the Claude or OpenAI API. It does not send: tenant IDs, user email addresses, IP addresses, or any raw data. Review your organisation's AI/cloud policy before using this feature for sensitive clients.

- **Output reports contain sensitive security configuration data** — treat them as confidential. The `evidence\` folder in particular contains detailed findings suitable for an attacker. Handle and transmit accordingly (encrypted email, secure portal).

- **Audit trail** (`audit-trail.json`) provides non-repudiation of what was scanned, when, and by which authenticated identity. Retain these files as part of your assessment documentation.

- **App registration principle of least privilege**: Only add the permissions listed in Section 1.5. Do not add `*.ReadWrite.*` or `Mail.Read` permissions — they are not needed.

---

*AuditXpert by TakeItToCloud — Enterprise M365 Security Assessment Platform v1.6.0*
