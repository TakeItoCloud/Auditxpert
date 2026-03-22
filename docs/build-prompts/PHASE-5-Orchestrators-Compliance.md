# PHASE 5 — BUILD: Product Orchestrators + Compliance Mappings
# ═══════════════════════════════════════════════════════════════
# Feed this prompt to Claude in VS Code
# Pre-requisite: Phases 1-4 complete
# ═══════════════════════════════════════════════════════════════

## CONTEXT
Read `AUDITXPERT-BUILD-SPEC.md` for full project context.
Root: `C:\Scripts\Assessment\AuditXpert`
All collectors, analyzers, and output generators are built.

## TASKS

---

### TASK 5A: MSP Audit Pack Orchestrator
File: `C:\Scripts\Assessment\AuditXpert\profiles\Invoke-MSPAuditPack.ps1`

This is Product 2 — white-label audit packs for MSPs.

#### Parameters
```powershell
param(
    [Parameter(Mandatory)]
    [string]$TenantId,
    [string]$ClientId,
    [string]$ClientSecret,
    [string]$CertificateThumbprint,

    # MSP branding
    [Parameter(Mandatory)]
    [string]$MSPCompanyName,              # White-label company name
    [string]$MSPLogoPath,                 # Path to MSP logo file
    [hashtable]$MSPColors,                # Custom branding colors

    # Pack selection
    [ValidateSet('ISO27001', 'SOC2Lite', 'CyberInsurance', 'InternalRisk', 'Full')]
    [string[]]$AuditPacks = @('Full'),

    # Scope
    [ValidateSet('EntraID', 'Exchange', 'Intune', 'Defender', 'Licensing')]
    [string[]]$Domains,

    [string]$OutputPath = (Join-Path $PWD "MSP-AuditPack-$(Get-Date -Format 'yyyyMMdd-HHmmss')"),
    [switch]$IncludeAIExplainer
)
```

#### Flow
1. Connect to tenant (app auth preferred for MSP automation)
2. Load MSPAudit config profile (includes all compliance frameworks)
3. Run all selected collectors
4. Run risk analysis with all selected frameworks
5. Generate evidence packs for each selected framework
6. Generate HTML/PDF report with MSP branding
7. Optionally run AI explainer
8. Package everything into output folder structure:
```
MSP-AuditPack-20260322-143000/
├── report/
│   ├── security-assessment-report.html
│   └── security-assessment-report.pdf (if wkhtmltopdf available)
├── evidence/
│   ├── ISO27001/
│   ├── CyberInsurance/
│   └── ...
├── data/
│   ├── assessment-results.json
│   ├── findings.csv
│   ├── remediation-plan.csv
│   └── executive-summary.json
├── compliance/
│   ├── compliance-iso27001.json
│   └── compliance-cyberinsurance.json
└── metadata.json                          # Pack info, tenant, date, MSP brand
```
9. Print summary to console

---

### TASK 5B: AI Audit Explainer Orchestrator
File: `C:\Scripts\Assessment\AuditXpert\profiles\Invoke-AuditExplainer.ps1`

This is Product 2.2 — standalone AI explainer. NOT limited to AuditXpert data.
Accepts input from: AuditXpert JSON, third-party CSVs (Qualys, Nessus, CIS), manual findings, or pipeline.

#### Parameters
```powershell
param(
    # Input sources — pick one
    [Parameter(Mandatory, ParameterSetName = 'File')]
    [string]$InputFile,                    # Single file (JSON or CSV)

    [Parameter(Mandatory, ParameterSetName = 'Folder')]
    [string]$InputFolder,                  # Folder of files — process each

    [Parameter(Mandatory, ParameterSetName = 'Pipeline', ValueFromPipeline)]
    [TiTCFinding[]]$Findings,

    # Input format (auto-detected if not specified)
    [ValidateSet('Auto', 'AuditXpert', 'CSV', 'JSON', 'Qualys', 'Nessus', 'Defender')]
    [string]$InputFormat = 'Auto',

    # AI Provider
    [ValidateSet('Claude', 'OpenAI')]
    [string]$Provider = 'Claude',
    [string]$ApiKey,
    [string]$Model,

    # Options
    [switch]$HighSeverityOnly,
    [int]$MaxFindings = 50,

    # Output
    [string]$OutputPath,
    [ValidateSet('JSON', 'HTML', 'Console')]
    [string]$OutputFormat = 'HTML',

    [string]$TenantName = 'Security Assessment'
)
```

#### Flow
1. Resolve API key: param → env variable → prompt user
2. Load findings based on input source:
   - File/Folder: call `Import-TiTCAuditData` from Output module (normalizes any format to TiTCFinding)
   - Pipeline: use $Findings directly
3. Display: "Found X findings. Processing Y (filtered by severity/max)."
4. Call `Invoke-TiTCAIExplainer` from Output module
5. Output results:
   - Console: formatted table with columns: Priority, Severity, Title, AI Risk Summary (truncated)
   - JSON: enriched findings JSON file
   - HTML: call `Export-TiTCAIReport` — standalone HTML with finding cards showing risk/impact/fix
6. Print summary: "X findings explained. Report saved to: [path]"

#### Example usage:
```powershell
# From AuditXpert results
.\Invoke-AuditExplainer.ps1 -InputFile ".\TiTC-Snapshot-20260322\assessment-results.json"

# From a Qualys export
.\Invoke-AuditExplainer.ps1 -InputFile "C:\exports\qualys-scan.csv" -InputFormat Qualys

# From a folder of mixed audit files
.\Invoke-AuditExplainer.ps1 -InputFolder "C:\Scripts\Assessment\AuditXpert\input\third-party\"

# From pipeline (after running M365Snapshot)
$report = .\Invoke-M365Snapshot.ps1 -TenantId "contoso.com"
$report.AllFindings | .\Invoke-AuditExplainer.ps1 -OutputFormat HTML

# High severity only, cap at 10 findings
.\Invoke-AuditExplainer.ps1 -InputFile ".\findings.csv" -HighSeverityOnly -MaxFindings 10
```
```

#### Flow
1. Load findings from JSON file or pipeline
2. Filter by severity if requested
3. Call `Invoke-TiTCAIExplainer` from Output module
4. Output results based on format:
   - Console: formatted table with AI explanations
   - JSON: enriched findings JSON
   - HTML: standalone HTML page with findings + AI explanations

---

### TASK 5C: Compliance Framework Mappings
Create 3 JSON files following the exact same structure as `compliance/iso27001.json` and `compliance/cyber-insurance.json`.

#### File: `C:\Scripts\Assessment\AuditXpert\compliance\soc2-lite.json`
SOC 2 Type II — Trust Service Criteria (simplified for SMB/MSP use):
- CC1.1: COSO Principle 1 — Integrity and Ethical Values → map to PasswordPolicy, AuthMethods
- CC6.1: Logical Access Security — MFA, CA policies → map to MFA, ConditionalAccess, SignInRisk
- CC6.2: User Provisioning/Deprovisioning → map to StaleAccounts, GuestAccounts
- CC6.3: Role-Based Access → map to PrivilegedAccess
- CC6.6: Security Against External Threats → map to AntiPhishing, Exchange, Defender
- CC6.7: Data Protection in Transit/Rest → map to Encryption, Connectors, ExternalForwarding
- CC6.8: Endpoint Protection → map to Intune, DeviceCompliance
- CC7.1: Monitoring Security Events → map to SignInRisk, Defender
- CC7.2: Incident Response → map to Alerts, Incidents
- CC7.3: Vulnerability Management → map to SecureScore, PatchManagement
- CC8.1: Change Management → map to DeviceConfiguration, SecurityBaseline

Each control: `{ "title": "...", "checks": [...], "evidence": "..." }`

#### File: `C:\Scripts\Assessment\AuditXpert\compliance\cis-controls.json`
CIS Microsoft 365 Foundations Benchmark v3.1:
- 1.1.1: Ensure MFA for all users
- 1.1.4: Limit Global Admins to <5
- 1.1.5: Ensure PIM is used
- 1.1.6: Block legacy authentication
- 1.1.9: Require number matching for MFA
- 1.2.1: Conditional Access policies
- 1.2.2: Block legacy auth via CA
- 1.2.6: Sign-in risk policy
- 1.2.7: User risk policy
- 1.3.1: App credential lifetime
- 2.1.1: Block external forwarding
- 2.2.1: Anti-spam policies
- 2.3.1: Anti-phishing policies
- 2.3.2: Impersonation protection
- 2.4.1: Safe Links
- 2.4.2: Safe Attachments
- 2.5.1: Shared mailbox sign-in
- 2.6.1: DMARC records
- 3.1.1: Device compliance policies
- 3.4.1: BitLocker encryption
- 3.5.1: Update management
- 4.1.1: Defender for Endpoint

Each control: `{ "title": "...", "checks": [...], "evidence": "..." }`

#### File: `C:\Scripts\Assessment\AuditXpert\compliance\internal-risk.json`
Generic internal risk review framework (catch-all):
- IR.ID.1: Identity hygiene
- IR.ID.2: Privileged access management
- IR.AC.1: Access control policies
- IR.DP.1: Data protection controls
- IR.EP.1: Endpoint security
- IR.TD.1: Threat detection
- IR.IR.1: Incident response readiness
- IR.CM.1: Configuration management
- IR.LM.1: License management
- IR.GV.1: Governance and oversight

---

### TASK 5D: Update README.md
Update `C:\Scripts\Assessment\AuditXpert\README.md` with:
- Updated roadmap (mark completed phases)
- Usage examples for all 3 products
- Full list of all checks across all collectors
- Compliance framework coverage table
