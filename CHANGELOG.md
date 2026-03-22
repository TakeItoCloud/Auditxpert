# Changelog

All notable changes to AuditXpert are documented in this file.

## [1.5.0] — 2026-03-22

### Added — Phase 6: Testing, Manifests & Polish
- **Pester Tests** (`tests/`):
  - `TiTC.Models.Tests.ps1` — 20 tests covering all model classes and factory functions
  - `TiTC.Core.Tests.ps1` — 12 tests covering config, logging, merge, and state functions
  - `TiTC.Analyzer.Risk.Tests.ps1` — 15 tests covering scoring, categories, compliance gap analysis
- **PowerShell Module Manifests** (`.psd1`) for all 10 modules — PowerShell Gallery compatible
- **CHANGELOG.md** — this file
- **.gitignore** — excludes output artifacts, secrets, IDE files
- **Install-Prerequisites.ps1** — prerequisite check and install script

---

## [1.4.0] — 2026-03-22

### Added — Phase 5: Product Orchestrators & Compliance Mappings
- **`profiles/Invoke-MSPAuditPack.ps1`** — Product 2: White-label MSP audit pack orchestrator
  - MSP branding (logo, company name, custom colors)
  - Multi-framework evidence generation in one run
  - Structured output folder (`report/`, `evidence/`, `data/`, `compliance/`)
- **`profiles/Invoke-AuditExplainer.ps1`** — Product 2.2: AI Audit Explainer standalone orchestrator
  - File or pipeline input
  - Console, JSON, and HTML output formats
  - Provider selection (Claude / OpenAI)
- **`compliance/soc2-lite.json`** — 11 SOC 2 Trust Service Criteria controls mapped
- **`compliance/cis-controls.json`** — 22 CIS Microsoft 365 Foundations Benchmark v3.1 controls mapped
- **`compliance/internal-risk.json`** — 10 generic internal risk review controls mapped
- **`README.md`** — Fully updated with all 3 products, all 49 checks, compliance coverage table

---

## [1.3.0] — 2026-03-22

### Added — Phase 4: Layer 3 Output Generators
- **`src/Outputs/TiTC.Output.Report.psm1`** — `Export-TiTCReport`
  - Single-page HTML report with inline CSS (11 sections)
  - SVG risk score gauge, category bars, severity distribution chart
  - Brand-color theming, white-label logo support
  - Optional PDF via wkhtmltopdf with `@media print` rules
- **`src/Outputs/TiTC.Output.Evidence.psm1`** — `Export-TiTCEvidencePack`
  - Per-framework evidence folder structure
  - Control summary CSV, per-control evidence JSON + findings CSV
  - Questionnaire-answers CSV for Cyber Insurance framework
- **`src/Outputs/TiTC.Output.AIExplainer.psm1`** — `Invoke-TiTCAIExplainer`
  - Claude (Anthropic) and OpenAI API support
  - Structured prompt engineering for executive-level explanations
  - Populates `AIExplanation`, `AIBusinessImpact`, `AIPriority` on findings
- **`profiles/Invoke-M365Snapshot.ps1`** — Updated to call all Layer 3 outputs

---

## [1.2.0] — 2026-03-22

### Added — Phase 3C: Licensing Collector
- **`src/Collectors/TiTC.Collector.Licensing.psm1`** — `Invoke-TiTCLicensingCollector`
  - 7 assessors: LicenseInventory, UnusedLicenses, DuplicateLicenses, OverProvisionedUsers, TrialSubscriptions, UnlicensedUsers, LicenseWasteSummary
  - EUR cost waste calculation using `TiTCLicenseWaste` class and `Config.LicensePricing`
  - Severity tiered by monthly waste: Critical (>€5,000), High (>€1,000), Medium (>€200)
  - `EstimatedWaste` propagated to `TiTCAssessmentReport` for report output
- **`profiles/Invoke-M365Snapshot.ps1`** — Updated with Licensing collector and waste propagation

---

## [1.1.0] — 2026-03-22

### Added — Phase 3A+3B: Intune & Defender Collectors
- **`src/Collectors/TiTC.Collector.Intune.psm1`** — `Invoke-TiTCIntuneCollector`
  - 8 assessors: DeviceCompliance, CompliancePolicies, EncryptionStatus, OSUpdateCompliance, StaleDevices, AppProtection, SecurityBaselines, DeviceConfigProfiles
  - Platform coverage gap detection (Windows, iOS, Android, macOS)
  - BitLocker remediation script included in encryption finding
- **`src/Collectors/TiTC.Collector.Defender.psm1`** — `Invoke-TiTCDefenderCollector`
  - 7 assessors: SecureScore, SecurityAlerts, Incidents, DefenderForEndpointCoverage, EmailThreatPolicies, AttackSimulation, AutoInvestigation
  - 48-hour SLA check for unresolved high/critical alerts
  - Attack simulation training recency check (90-day window)
- **`profiles/Invoke-M365Snapshot.ps1`** — Updated with Intune and Defender collector calls

---

## [1.0.0] — 2026-03-20

### Added — Phases 1+2: Core Platform
- **`src/Core/TiTC.Core.psm1`** — Authentication (Interactive/AppSecret/Certificate), Graph API wrapper with throttle/retry/pagination, logging, config engine with profiles
- **`src/Core/Models/TiTC.Models.psm1`** — Full data model: TiTCFinding, TiTCCollectorResult, TiTCRiskScore, TiTCAssessmentReport, TiTCLicenseWaste, enums
- **`src/Collectors/TiTC.Collector.EntraID.psm1`** — 19 identity security checks
- **`src/Collectors/TiTC.Collector.Exchange.psm1`** — 15 mail security checks (Graph + Exchange module modes)
- **`src/Analyzers/TiTC.Analyzer.Risk.psm1`** — Composite risk scoring, category scoring, remediation prioritization, quick wins, compliance gap analysis, trend analysis, executive narrative
- **`profiles/Invoke-M365Snapshot.ps1`** — Product 1 orchestrator with full CLI
- **`compliance/iso27001.json`** — 15 ISO 27001:2022 Annex A controls mapped
- **`compliance/cyber-insurance.json`** — 12 cyber insurance underwriter requirements mapped
- **`README.md`** — Project overview and quick start guide
