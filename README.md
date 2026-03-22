# AuditXpert by TakeItToCloud

Enterprise M365 Security & Compliance Assessment Platform — v1.5.0

## Overview

A unified PowerShell-based platform that powers three sellable products from one codebase:

| Product | Target | Deliverable | Price Point |
|---------|--------|-------------|-------------|
| **M365 Risk & Compliance Snapshot** | Direct clients | PDF report + risk score + remediation checklist | Productized service fee |
| **MSP Automation Packs** | Managed Service Providers | White-label modules + evidence packs | €199–€499/pack |
| **AI-Assisted Audit Explainer** | Internal → SaaS | AI plain-English risk explanations | SaaS subscription |

All three products share the same engine — build once, sell three ways.

## Architecture

```
Layer 1: COLLECTORS    → Graph API + PowerShell scans per M365 domain
Layer 2: ANALYZERS     → Risk scoring, gap detection, compliance mapping
Layer 3: OUTPUTS       → PDF reports, evidence packs, JSON export, AI summaries
```

## Quick Start

```powershell
# 1. Install prerequisites
.\Install-Prerequisites.ps1

# 2. Run Product 1 — M365 Risk Snapshot (interactive auth)
.\profiles\Invoke-M365Snapshot.ps1 -TenantId "contoso.onmicrosoft.com"

# 3. Run with app auth (MSP/automation)
.\profiles\Invoke-M365Snapshot.ps1 -TenantId $tid -ClientId $cid -ClientSecret $secret

# 4. Quick scan — identity only
.\profiles\Invoke-M365Snapshot.ps1 -TenantId $tid -Profile Quick -Domains EntraID

# 5. Full scan with PDF report and evidence packs
.\profiles\Invoke-M365Snapshot.ps1 -TenantId $tid -OutputFormat PDF -IncludeEvidence
```

## Product Usage

### Product 1: M365 Risk & Compliance Snapshot

```powershell
# Standard assessment
.\profiles\Invoke-M365Snapshot.ps1 `
    -TenantId "contoso.onmicrosoft.com" `
    -Profile Full `
    -OutputFormat HTML `
    -IncludeEvidence

# With AI-powered explanations
.\profiles\Invoke-M365Snapshot.ps1 `
    -TenantId $tid `
    -IncludeAIExplainer `
    -OutputFormat PDF
```

### Product 2: MSP Audit Pack

```powershell
# ISO 27001 + Cyber Insurance evidence pack
.\profiles\Invoke-MSPAuditPack.ps1 `
    -TenantId "client.onmicrosoft.com" `
    -ClientId $cid -ClientSecret $secret `
    -MSPCompanyName "SecureIT Solutions" `
    -MSPLogoPath "C:\branding\logo.png" `
    -AuditPacks ISO27001, CyberInsurance

# Full pack with all frameworks
.\profiles\Invoke-MSPAuditPack.ps1 `
    -TenantId $tid -ClientId $cid -ClientSecret $secret `
    -MSPCompanyName "MyMSP" `
    -AuditPacks Full `
    -ReportFormat PDF `
    -IncludeAIExplainer
```

### Product 2.2: AI Audit Explainer

```powershell
# Explain AuditXpert findings (auto-detected format, HTML output by default)
.\profiles\Invoke-AuditExplainer.ps1 `
    -InputFile ".\TiTC-Snapshot-20260322\assessment-results.json"

# Explain a Qualys or Nessus CSV export
.\profiles\Invoke-AuditExplainer.ps1 `
    -InputFile .\qualys-scan.csv -InputFormat Qualys `
    -TenantName "Contoso" -OutputPath .\contoso-briefing.html

# Process an entire folder of scan files (mixed formats, auto-detected)
.\profiles\Invoke-AuditExplainer.ps1 `
    -InputFolder .\input\third-party\

# Use OpenAI instead of Claude
.\profiles\Invoke-AuditExplainer.ps1 `
    -InputFile .\assessment-results.json `
    -Provider OpenAI -ApiKey $env:OPENAI_API_KEY
```

## Checks Performed

### Entra ID (19 checks)
| Check | What It Detects |
|-------|----------------|
| MFA | Users without MFA registered, SMS-only MFA |
| PrivilegedAccess | Excessive Global Admins, standing access without PIM, over-privileged service principals |
| ConditionalAccess | Policy count, legacy auth not blocked, broad exclusions |
| StaleAccounts | Dormant accounts by last sign-in |
| GuestAccounts | Old guest users, pending invitations |
| Applications | Expired/long-lived credentials, over-permissioned apps |
| PasswordPolicy | Password protection, SSPR |
| AuthMethods | FIDO2 status, Authenticator number matching |
| SignInRisk | Sign-in and user risk policies, active risky users |

### Exchange Online (15 checks)
| Check | What It Detects |
|-------|----------------|
| ExternalForwarding | Inbox rules forwarding externally |
| TransportRules | Spam bypass, risky actions |
| AntiPhishing | Safe Links, Safe Attachments, impersonation protection |
| MailboxAuditing | Audit configuration |
| SharedMailboxes | Sign-in enabled, unnecessary licenses |
| DomainSecurity | DMARC record presence and policy strength |
| OWAPolicy | External image proxy settings |
| Connectors | Inbound TLS enforcement |
| MailEnabledGroups | Security groups accepting external mail |

### Intune / Endpoint (8 checks)
| Check | What It Detects |
|-------|----------------|
| DeviceCompliance | % of devices compliant, non-compliant device list |
| CompliancePolicies | Unassigned policies, missing platform coverage |
| EncryptionStatus | Unencrypted managed devices (BitLocker/FileVault) |
| OSUpdateCompliance | Outdated OS versions, missing Windows Update rings |
| StaleDevices | Devices not synced in 30+ days |
| AppProtection | MAM policies for iOS/Android BYOD |
| SecurityBaselines | Security baseline deployment status |
| DeviceConfigProfiles | Missing BitLocker, Firewall, Antivirus, Windows Hello profiles |

### Microsoft Defender (7 checks)
| Check | What It Detects |
|-------|----------------|
| SecureScore | Score below threshold, top improvement actions |
| SecurityAlerts | Unresolved high/critical alerts older than 48h |
| Incidents | Active security incidents |
| DefenderForEndpointCoverage | Windows devices not onboarded to Defender |
| EmailThreatPolicies | Missing preset security policies for email |
| AttackSimulation | No phishing simulation in last 90 days |
| AutoInvestigation | Automated Investigation and Response not active |

### Licensing (7 checks)
| Check | What It Detects |
|-------|----------------|
| LicenseInventory | Full SKU inventory, utilization % |
| UnusedLicenses | SKUs with >10% unused (EUR waste calculation) |
| DuplicateLicenses | Users with overlapping SKU assignments |
| OverProvisionedUsers | E5 users not using E5-exclusive features |
| TrialSubscriptions | Trial/expiring subscriptions |
| UnlicensedUsers | Enabled accounts without license |
| LicenseWasteSummary | Total monthly/annual waste estimate |

## Compliance Framework Coverage

| Framework | Controls Mapped | Key Areas |
|-----------|----------------|-----------|
| **ISO 27001:2022** | 15 Annex A controls | Access control, identity, endpoint, monitoring |
| **Cyber Insurance** | 12 underwriter requirements | MFA, EDR, patch, email, backup |
| **SOC 2 (Lite)** | 11 Trust Service Criteria | CC6 access, CC7 monitoring, CC8 change |
| **CIS M365 Benchmark v3.1** | 22 controls | Identity, email, device, app security |
| **Internal Risk** | 10 domain controls | All M365 security domains |

## Risk Scoring

| Score Range | Rating | Label |
|-------------|--------|-------|
| 0–10 | A+ | Excellent |
| 11–20 | A | Strong |
| 21–30 | B+ | Good |
| 31–40 | B | Fair |
| 41–50 | C+ | Below Average |
| 51–60 | C | Concerning |
| 61–70 | D | Poor |
| 71–80 | D– | Very Poor |
| 81–100 | F | Critical |

## Required Graph API Permissions

```
Directory.Read.All          Policy.Read.All
SecurityEvents.Read.All     DeviceManagementConfiguration.Read.All
DeviceManagementManagedDevices.Read.All
MailboxSettings.Read        Organization.Read.All
Reports.Read.All            RoleManagement.Read.Directory
User.Read.All               Group.Read.All
Application.Read.All        AuditLog.Read.All
SecurityActions.Read.All    IdentityRiskEvent.Read.All
IdentityRiskyUser.Read.All
```

## Documentation

For the complete operations manual — installation, examples, configuration, troubleshooting — see **[docs/HOWTO.md](docs/HOWTO.md)**.

## Build Roadmap

| Phase | Version | Status | Description |
|-------|---------|--------|-------------|
| 1+2 | v1.0.0 | ✅ Complete | Core, Models, Entra ID, Exchange, Risk Analyzer, Orchestrator |
| 3A | v1.1.0 | ✅ Complete | Intune Collector |
| 3B | v1.1.0 | ✅ Complete | Defender Collector |
| 3C | v1.2.0 | ✅ Complete | Licensing Collector |
| 4 | v1.3.0 | ✅ Complete | HTML/PDF Report, Evidence Packs, AI Explainer |
| 5 | v1.4.0 | ✅ Complete | MSP Orchestrator, AI Explainer Orchestrator, Compliance Mappings |
| 6 | v1.5.0 | ✅ Complete | Pester Tests, Module Manifests, CHANGELOG, Polish |
| 7 | v1.6.0 | ✅ Complete | HOWTO Docs, Enhanced Logging, AI Explainer multi-format input, Prerequisites |

## File Structure

```
AuditXpert/
├── profiles/
│   ├── Invoke-M365Snapshot.ps1        # Product 1 — M365 Risk Snapshot
│   ├── Invoke-MSPAuditPack.ps1        # Product 2 — MSP Audit Packs
│   └── Invoke-AuditExplainer.ps1      # Product 2.2 — AI Explainer
├── src/
│   ├── Core/
│   │   ├── TiTC.Core.psm1             # Auth, Graph API, logging, config
│   │   └── Models/TiTC.Models.psm1    # Data contracts
│   ├── Collectors/
│   │   ├── TiTC.Collector.EntraID.psm1
│   │   ├── TiTC.Collector.Exchange.psm1
│   │   ├── TiTC.Collector.Intune.psm1
│   │   ├── TiTC.Collector.Defender.psm1
│   │   └── TiTC.Collector.Licensing.psm1
│   ├── Analyzers/
│   │   └── TiTC.Analyzer.Risk.psm1
│   └── Outputs/
│       ├── TiTC.Output.Report.psm1    # HTML/PDF report generator
│       ├── TiTC.Output.Evidence.psm1  # Compliance evidence packs
│       └── TiTC.Output.AIExplainer.psm1
├── compliance/
│   ├── iso27001.json
│   ├── cyber-insurance.json
│   ├── soc2-lite.json
│   ├── cis-controls.json
│   └── internal-risk.json
├── tests/
│   ├── TiTC.Models.Tests.ps1
│   ├── TiTC.Core.Tests.ps1
│   └── TiTC.Analyzer.Risk.Tests.ps1
├── Install-Prerequisites.ps1
└── CHANGELOG.md
```

## Branding

- **Brand**: TakeItToCloud
- **Primary**: `#0F172A` (deep navy)
- **Accent**: `#10B981` (security green)
- **Warning**: `#F59E0B`
- **Danger**: `#EF4444`

---

*AuditXpert by TakeItToCloud — Enterprise M365 Security Assessment Platform*
