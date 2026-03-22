# AuditXpert — Complete Build Specification & Knowledge Transfer
# ═══════════════════════════════════════════════════════════════
# This document is the single source of truth for building the AuditXpert platform.
# Feed this to Claude in VS Code as context for all development work.
# Root Path: C:\Scripts\Assessment\AuditXpert
# ═══════════════════════════════════════════════════════════════

## 1. PROJECT OVERVIEW

### What is AuditXpert?
AuditXpert (branded under TakeItToCloud) is a unified PowerShell-based enterprise platform that powers THREE sellable products from ONE codebase:

| Product | Target Buyer | Deliverable | Price Point |
|---------|-------------|-------------|-------------|
| **Product 1: M365 Risk & Compliance Snapshot** | Direct clients (enterprises) | PDF report + risk score + remediation checklist | Productized service fee |
| **Product 2: MSP Automation Packs** | Managed Service Providers (B2B) | White-label PowerShell modules + evidence generators | €199–€499/pack + annual updates |
| **Product 2.2: AI-Assisted Audit Explainer** | Internal → SaaS | AI-powered plain-English risk explanations | Internal tool → SaaS subscription |

### Architecture — 3 Layers
```
Layer 1: COLLECTORS    → Graph API + PowerShell scans per M365 domain
Layer 2: ANALYZERS     → Risk scoring, gap detection, compliance mapping
Layer 3: OUTPUTS       → PDF reports, evidence packs, JSON export, AI summaries
```
All three products share the same engine. Build once, sell three ways.

### Branding & Design
- Brand: TakeItToCloud
- Primary color: Deep navy #0F172A
- Accent color: Security green #10B981
- Warning: #F59E0B | Danger: #EF4444
- Typography: Manrope (body), Playfair Display (headings in reports)

---

## 2. FOLDER STRUCTURE

Root: `C:\Scripts\Assessment\AuditXpert`

```
AuditXpert/
├── src/
│   ├── Core/                              # Shared foundation
│   │   ├── TiTC.Core.psm1                # Auth, logging, config, Graph API wrapper
│   │   ├── Models/
│   │   │   └── TiTC.Models.psm1          # Data contracts (Finding, CollectorResult, RiskScore, Report)
│   │   └── Config/                        # Reserved for config templates
│   │
│   ├── Collectors/                        # Layer 1 — one module per M365 domain
│   │   ├── TiTC.Collector.EntraID.psm1   # ✅ BUILT — 19 identity security checks
│   │   ├── TiTC.Collector.Exchange.psm1  # ✅ BUILT — 15 mail flow/security checks
│   │   ├── TiTC.Collector.Intune.psm1    # ❌ TO BUILD — endpoint/device compliance
│   │   ├── TiTC.Collector.Defender.psm1  # ❌ TO BUILD — threat protection config
│   │   └── TiTC.Collector.Licensing.psm1 # ❌ TO BUILD — license waste/optimization
│   │
│   ├── Analyzers/                         # Layer 2 — scoring & analysis
│   │   ├── TiTC.Analyzer.Risk.psm1       # ✅ BUILT — composite scoring, categories, remediation
│   │   └── TiTC.Analyzer.Compliance.psm1 # ❌ TO BUILD — deep compliance mapping engine
│   │
│   └── Outputs/                           # Layer 3 — report & evidence generation
│       ├── TiTC.Output.Report.psm1       # ❌ TO BUILD — PDF report generator
│       ├── TiTC.Output.Evidence.psm1     # ❌ TO BUILD — compliance evidence packs
│       ├── TiTC.Output.Export.psm1       # ❌ TO BUILD — JSON/CSV/HTML export
│       └── TiTC.Output.AIExplainer.psm1  # ❌ TO BUILD — AI summary integration
│
├── profiles/                              # Product entry points (orchestrators)
│   ├── Invoke-M365Snapshot.ps1           # ✅ BUILT — Product 1 orchestrator
│   ├── Invoke-MSPAuditPack.ps1           # ❌ TO BUILD — Product 2 orchestrator
│   └── Invoke-AuditExplainer.ps1         # ❌ TO BUILD — Product 2.2 orchestrator
│
├── compliance/                            # Framework mapping files (JSON)
│   ├── iso27001.json                     # ✅ BUILT — 15 Annex A controls mapped
│   ├── cyber-insurance.json              # ✅ BUILT — 12 underwriter requirements
│   ├── soc2-lite.json                    # ❌ TO BUILD
│   ├── cis-controls.json                 # ❌ TO BUILD
│   └── internal-risk.json               # ❌ TO BUILD
│
├── templates/                             # Report templates
│   ├── report-template.html              # ❌ TO BUILD — HTML template for PDF
│   └── branding/                         # Logos, color schemes
│
├── tests/                                 # Pester tests
│   ├── TiTC.Models.Tests.ps1             # ❌ TO BUILD
│   ├── TiTC.Core.Tests.ps1              # ❌ TO BUILD
│   └── ...
│
└── README.md                             # ✅ BUILT
```

---

## 3. WHAT HAS BEEN BUILT (Phase 1 + Phase 2 — COMPLETE)

### 3.1 Core Foundation — TiTC.Core.psm1 (755 lines)
- **Authentication**: `Connect-TiTCGraph` supporting Interactive, ClientSecret, Certificate auth
- **Graph API Wrapper**: `Invoke-TiTCGraphRequest` with:
  - 429 throttling with exponential backoff
  - Automatic pagination via @odata.nextLink
  - Retry logic for 5xx errors
  - 403/404 graceful handling
  - API call counting/telemetry
- **Logging**: `Write-TiTCLog` with color-coded console output + file logging
- **Config Engine**: `Get-TiTCConfig` with profile support (Full, Quick, MSPAudit, LicenseOnly, ComplianceOnly)
  - Deep merge of base + file + runtime overrides
  - License pricing table (EUR) for waste calculation
  - Domain enable/disable toggles
  - Threshold configuration (stale days, MFA target, admin count, etc.)
- **Session State**: Connection tracking, tenant info caching

### 3.2 Data Models — TiTC.Models.psm1 (421 lines)
- **Enums**: TiTCSeverity (Info→Critical), TiTCDomain, TiTCComplianceFramework, TiTCFindingStatus, TiTCCollectorStatus
- **TiTCFinding**: Complete finding with severity, risk weight, compliance controls, remediation, evidence, AI fields
- **TiTCCollectorResult**: Collector output with timing, findings, raw data, errors/warnings
- **TiTCRiskScore**: Composite scoring with per-domain breakdown and rating (A+ through F)
- **TiTCAssessmentReport**: Complete report aggregating all collectors + scoring
- **TiTCLicenseWaste**: License optimization finding with cost calculations
- **Factory functions**: `New-TiTCFinding`, `New-TiTCCollectorResult`

### 3.3 Entra ID Collector — TiTC.Collector.EntraID.psm1 (1,139 lines)
Entry point: `Invoke-TiTCEntraIDCollector`
9 assessors, 19 checks:

| Assessor | Checks | Graph Endpoints |
|----------|--------|-----------------|
| MFA | Users without MFA, SMS-only MFA | /users/{id}/authentication/methods |
| PrivilegedAccess | Excessive Global Admins, standing access (no PIM), SPs with priv roles | /roleManagement/directory/roleAssignments, /roleDefinitions |
| ConditionalAccess | Policy count, legacy auth blocking, broad exclusions | /identity/conditionalAccess/policies |
| StaleAccounts | Dormant accounts (signInActivity) | /users (beta, signInActivity) |
| GuestAccounts | Old guests, pending invitations | /users (filter: Guest) |
| Applications | Expired creds, long-lived secrets, over-permissioned apps | /applications |
| PasswordPolicy | Password protection, SSPR | /organization, /policies/authenticationMethodsPolicy |
| AuthMethods | FIDO2 status, Authenticator number matching | /policies/authenticationMethodsPolicy |
| SignInRisk | Sign-in risk policy, user risk policy, active risky users | /identity/conditionalAccess/policies, /identityProtection/riskyUsers |

### 3.4 Exchange Collector — TiTC.Collector.Exchange.psm1 (1,057 lines)
Entry point: `Invoke-TiTCExchangeCollector`
9 assessors, ~15 checks. Supports two modes:
- **Graph-only mode**: Always available, covers forwarding, domain security, groups, shared mailboxes
- **Deep mode** (`-UseExchangeModule`): Transport rules, anti-phishing, Safe Links/Attachments, connectors, OWA

| Assessor | Checks |
|----------|--------|
| ExternalForwarding | Inbox rules forwarding to external addresses |
| TransportRules | Spam bypass (SCL), risky actions, auth header stripping |
| AntiPhishing | Impersonation protection, spoof intelligence, Safe Links, Safe Attachments |
| MailboxAuditing | Organization audit config |
| SharedMailboxes | Sign-in enabled, unnecessary license assignments |
| DomainSecurity | DMARC record presence + policy strength (live DNS) |
| OWAPolicy | External image proxy |
| Connectors | Inbound TLS enforcement |
| MailEnabledGroups | Security groups accepting external mail |

### 3.5 Risk Scoring Engine — TiTC.Analyzer.Risk.psm1 (775 lines)
Entry point: `Invoke-TiTCRiskAnalysis`

- **Composite Risk Score**: Weighted by domain config, with critical cluster penalty (+5 for 3+ criticals in same domain) and remediation credit
- **5 Security Categories**: Identity & Access (35%), Data Protection (25%), Threat Detection (25%), Device & Endpoint (10%), Governance & Config (5%)
- **Remediation Prioritization**: Ranked by (severity × weight × affected scale + compliance impact − effort), with effort estimates in hours
- **Quick Wins**: Identifies automatable, scoped, or single-config fixes
- **Compliance Gap Analysis**: Maps findings to framework controls, calculates coverage %
- **Trend Analysis**: Compare with historical report for delta tracking
- **Executive Narrative**: Structured text for report generation

### 3.6 Product 1 Orchestrator — Invoke-M365Snapshot.ps1 (346 lines)
Full CLI with parameter sets for Interactive/App/Cert auth. Runs collectors → risk analysis → exports:
- assessment-results.json (full report)
- findings.csv
- executive-summary.json
- risk-analysis.json
- remediation-plan.csv
- compliance-*.json (per framework)
- evidence/ folder (when -IncludeEvidence)
- audit-trail.json (log export)

### 3.7 Compliance Mappings
- **ISO 27001:2022**: 15 Annex A controls mapped to assessment checks
- **Cyber Insurance**: 12 common underwriter requirements with required flags and impact notes

---

## 4. TECHNICAL PATTERNS & CONVENTIONS

### Naming Conventions
- Module prefix: `TiTC.` (TakeItToCloud)
- Functions: `Verb-TiTC<Noun>` (e.g., `Connect-TiTCGraph`, `Invoke-TiTCEntraIDCollector`)
- Assessors: `Test-TiTC<CheckName>` (private to collector modules)
- Models: `TiTC<ClassName>` (e.g., `TiTCFinding`, `TiTCRiskScore`)
- Constants: `$script:COMPONENT`, `$script:PRIVILEGED_ROLES`

### Module Import Pattern
Every module imports its dependencies relative to its own location:
```powershell
$CorePath = Join-Path (Split-Path $PSScriptRoot -Parent) 'Core\TiTC.Core.psm1'
if (Test-Path $CorePath) { Import-Module $CorePath -Force -ErrorAction Stop }
```

### Finding Creation Pattern
All checks produce findings via the factory function:
```powershell
$Result.Findings += New-TiTCFinding `
    -Title "Short descriptive title" `
    -Description "Full description with data points and context" `
    -Severity High `
    -Domain EntraID `
    -RiskWeight 7 `
    -Remediation "Clear action steps" `
    -RemediationUrl 'https://learn.microsoft.com/...' `
    -RemediationScript '# Optional PowerShell fix' `
    -ComplianceControls @('ISO27001:A.9.2.3', 'CIS:1.1.4', 'SOC2:CC6.3') `
    -AffectedResources $affectedList `
    -Evidence @{ Key = $data } `
    -EvidenceQuery 'GET /endpoint' `
    -DetectedBy $script:COMPONENT `
    -Tags @('Category', 'SubCategory')
```

### Collector Structure
Every collector follows this pattern:
1. Import Core + Models
2. Define `$script:COMPONENT` constant
3. Main entry point `Invoke-TiTC<Domain>Collector` with `-Config` and `-Checks` params
4. Assessor dispatch table (ordered hashtable of scriptblocks)
5. Individual `Test-TiTC<Check>` functions
6. Each assessor increments `$Result.ObjectsScanned`, adds findings, stores `$Result.RawData`
7. Error handling per assessor (PartialSuccess on failure)
8. `$Result.Complete()` at end

### Graph API Call Pattern
All Graph calls go through `Invoke-TiTCGraphRequest`:
```powershell
$data = (Invoke-TiTCGraphRequest `
    -Endpoint '/users' `
    -Select 'id,displayName,userPrincipalName' `
    -Filter "userType eq 'Member'" `
    -AllPages `
    -Beta `           # Optional: use beta endpoint
    -Component $script:COMPONENT
).value
```

### Risk Score Rating Scale
| Score Range | Rating | Label |
|-------------|--------|-------|
| 0-10 | A+ | Excellent |
| 11-20 | A | Strong |
| 21-30 | B+ | Good |
| 31-40 | B | Fair |
| 41-50 | C+ | Below Average |
| 51-60 | C | Concerning |
| 61-70 | D | Poor |
| 71-80 | D- | Very Poor |
| 81-100 | F | Critical |

---

## 5. BUILD PHASES — REMAINING WORK

### Phase 3: Remaining Collectors
**Priority order: Intune → Defender → Licensing**

#### Phase 3A: Intune / Endpoint Collector
File: `src/Collectors/TiTC.Collector.Intune.psm1`
Entry point: `Invoke-TiTCIntuneCollector`

Assessors to build:
- **DeviceCompliance**: % of devices compliant, non-compliant device list
  - Endpoint: `/deviceManagement/managedDevices` + `/deviceManagement/deviceCompliancePolicies`
- **CompliancePolicies**: Policy coverage, assignment gaps, policy conflicts
  - Endpoint: `/deviceManagement/deviceCompliancePolicies`, `/deviceManagement/deviceCompliancePolicySettingStateSummaries`
- **ConditionalAccessDeviceCompliance**: CA policies requiring compliant devices
- **EncryptionStatus**: BitLocker/FileVault compliance
  - Endpoint: `/deviceManagement/managedDevices` (check `isEncrypted`)
- **OSUpdateCompliance**: Windows Update ring config, patch age
  - Endpoint: `/deviceManagement/windowsUpdateForBusinessConfigurations`
- **AppProtection**: MAM policies for BYOD
  - Endpoint: `/deviceAppManagement/managedAppPolicies`
- **SecurityBaselines**: Security baseline deployment status
  - Endpoint: `/deviceManagement/templates` (beta)
- **StaleDevices**: Devices not synced in X days
  - Endpoint: `/deviceManagement/managedDevices` filter by lastSyncDateTime

Tags to use: Intune, DeviceCompliance, Encryption, BitLocker, WindowsUpdate, PatchManagement, EndpointSecurity, MDM, MAM, DefenderForEndpoint

#### Phase 3B: Defender Collector
File: `src/Collectors/TiTC.Collector.Defender.psm1`
Entry point: `Invoke-TiTCDefenderCollector`

Assessors to build:
- **DefenderForEndpoint**: Onboarding status, sensor health
  - Endpoint: `/security/alerts_v2`, device onboarding via Intune check
- **DefenderForOffice365**: Policy configuration (if not covered by Exchange)
- **DefenderForIdentity**: Sensor deployment, configuration
- **SecureScore**: Microsoft Secure Score retrieval + analysis
  - Endpoint: `/security/secureScores`, `/security/secureScoreControlProfiles`
- **AlertAnalysis**: Open alerts by severity, stale alerts
  - Endpoint: `/security/alerts_v2`
- **IncidentAnalysis**: Active incidents, response status
  - Endpoint: `/security/incidents`
- **ThreatVulnerabilities**: Known vulnerabilities from TVM
  - Endpoint: `/security/threatVulnerabilityManagement` (beta)

Tags: DefenderForEndpoint, DefenderForOffice365, SecureScore, ThreatDetection, Alerts, Incidents

#### Phase 3C: Licensing / Cost Waste Collector
File: `src/Collectors/TiTC.Collector.Licensing.psm1`
Entry point: `Invoke-TiTCLicensingCollector`

Assessors to build:
- **LicenseInventory**: Total vs assigned vs consumed per SKU
  - Endpoint: `/subscribedSkus`
- **UnusedLicenses**: Licenses assigned but service not used (sign-in activity cross-ref)
- **DuplicateLicenses**: Users with overlapping SKUs (E3 + standalone Exchange)
- **OverProvisionedUsers**: Users with E5 using only E3 features
- **LicenseWasteCalculation**: EUR/month waste using Config.LicensePricing table
- **TrialExpiry**: Trial subscriptions approaching expiry
- **ServicePlanUsage**: Which service plans are actually used per SKU

Use the `TiTCLicenseWaste` class from Models for waste findings.
Tags: License, CostOptimization, LicenseWaste, Provisioning

### Phase 4: Layer 3 — Output Generators

#### Phase 4A: PDF Report Generator
File: `src/Outputs/TiTC.Output.Report.psm1`
Entry point: `Export-TiTCReport`

Build approach:
1. Generate HTML report from assessment data using an HTML template
2. Convert HTML → PDF using either:
   - `wkhtmltopdf` (if available on system)
   - Or generate the HTML report directly (customer prints to PDF)
3. Report sections:
   - Cover page (tenant name, date, overall score badge, branding)
   - Executive summary (narrative from risk analyzer)
   - Risk score dashboard (overall + per-category + per-domain)
   - Severity distribution chart
   - Top 10 findings table (sorted by priority)
   - Full findings detail (grouped by domain, sorted by severity)
   - Remediation plan (prioritized checklist with effort estimates)
   - Quick wins section
   - Compliance posture summary (per framework coverage %)
   - Compliance gap details
   - License waste summary (if licensing collector ran)
   - Appendix: methodology, permissions used, scan timestamp

#### Phase 4B: Evidence Pack Generator
File: `src/Outputs/TiTC.Output.Evidence.psm1`
Entry point: `Export-TiTCEvidencePack`

For MSP Automation Packs (Product 2):
- Generate per-framework evidence folders
- Each folder contains: control mapping, evidence data, pass/fail status
- Format: JSON + CSV per control area
- Include timestamp, tenant info, assessor metadata
- Support white-label (custom branding in output)

#### Phase 4C: AI Explainer Integration
File: `src/Outputs/TiTC.Output.AIExplainer.psm1`
Entry point: `Invoke-TiTCAIExplainer`

Approach:
1. Take findings JSON as input
2. Call OpenAI/Claude API with structured prompt
3. For each finding, generate:
   - Plain-English risk explanation
   - Business impact statement
   - Priority (1-5)
   - Recommended fix in non-technical language
4. Populate the AI fields on TiTCFinding objects
5. Return enriched findings

### Phase 5: Product Orchestrators

#### Phase 5A: MSP Audit Pack Orchestrator
File: `profiles/Invoke-MSPAuditPack.ps1`
- White-label support (custom branding, company name)
- Evidence generation for selected frameworks
- Module packaging for distribution

#### Phase 5B: AI Audit Explainer Orchestrator
File: `profiles/Invoke-AuditExplainer.ps1`
- Accept raw audit JSON input
- Run AI explainer
- Output enriched report

### Phase 6: Compliance Mappings

Build remaining framework files:
- `compliance/soc2-lite.json` — Trust Service Criteria (CC series)
- `compliance/cis-controls.json` — CIS Microsoft 365 Benchmark controls
- `compliance/internal-risk.json` — Generic internal risk assessment controls

### Phase 7: Testing & Polish
- Pester tests for Models, Core, each Collector
- Module manifests (.psd1) for PowerShell Gallery publishing
- CHANGELOG.md
- LICENSE

---

## 6. REQUIRED GRAPH API PERMISSIONS (COMPREHENSIVE)

### Application Permissions (for MSP/automation)
```
Directory.Read.All
Policy.Read.All
SecurityEvents.Read.All
DeviceManagementConfiguration.Read.All
DeviceManagementManagedDevices.Read.All
MailboxSettings.Read
Organization.Read.All
Reports.Read.All
RoleManagement.Read.Directory
User.Read.All
Group.Read.All
Application.Read.All
AuditLog.Read.All
SecurityActions.Read.All
ThreatAssessment.Read.All
IdentityRiskEvent.Read.All
IdentityRiskyUser.Read.All
```

### Optional Modules
- `Microsoft.Graph.Authentication` — Required
- `ExchangeOnlineManagement` — Optional (deep Exchange checks)

---

## 7. IMPORTANT NOTES FOR CLAUDE IN VS CODE

1. **All files use UTF-8 encoding** — PowerShell modules are .psm1, scripts are .ps1
2. **#Requires -Version 5.1** at the top of every module
3. **Every module exports its functions** via `Export-ModuleMember -Function @(...)`
4. **Error handling**: Each assessor runs in try/catch — one failure doesn't block others
5. **The Graph wrapper handles pagination** — collectors just pass `-AllPages`
6. **RawData is preserved** on CollectorResult for evidence pack generation
7. **Tags on findings** drive the category scoring in the risk analyzer — choose tags carefully
8. **Compliance control format**: `Framework:ControlId` (e.g., `ISO27001:A.9.2.3`, `CIS:1.1.1`, `SOC2:CC6.1`)
9. **The project was originally named TakeItToCloud.Assess** — the folder is now AuditXpert but module prefix remains `TiTC.`
10. **License pricing in Config is EUR** — used by Licensing collector for waste calculation
