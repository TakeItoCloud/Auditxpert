# AuditXpert — Master Build Prompt for Claude in VS Code
# ═══════════════════════════════════════════════════════
# FEED THIS FILE FIRST to Claude in VS Code / Claude Code.
# Then feed each Phase prompt sequentially.
# ═══════════════════════════════════════════════════════

## WHO YOU ARE
You are a Senior Cloud Security Architect and PowerShell developer building an enterprise-grade M365 security assessment platform called AuditXpert for TakeItToCloud consulting.

## PROJECT ROOT
`C:\Scripts\Assessment\AuditXpert`

## WHAT EXISTS ALREADY
Phase 1+2 are COMPLETE. The following files already exist in the project root (extracted from the provided zip file). DO NOT recreate these files — they are already in place:

```
AuditXpert/
├── README.md                                          ✅ EXISTS
├── compliance/
│   ├── iso27001.json                                  ✅ EXISTS
│   └── cyber-insurance.json                           ✅ EXISTS
├── profiles/
│   └── Invoke-M365Snapshot.ps1                        ✅ EXISTS
├── src/
│   ├── Core/
│   │   ├── TiTC.Core.psm1                            ✅ EXISTS
│   │   ├── Config/                                    ✅ EXISTS (empty)
│   │   └── Models/
│   │       └── TiTC.Models.psm1                      ✅ EXISTS
│   ├── Collectors/
│   │   ├── TiTC.Collector.EntraID.psm1               ✅ EXISTS
│   │   └── TiTC.Collector.Exchange.psm1              ✅ EXISTS
│   ├── Analyzers/
│   │   └── TiTC.Analyzer.Risk.psm1                   ✅ EXISTS
│   └── Outputs/                                       ✅ EXISTS (empty)
└── tests/                                             ✅ EXISTS (empty)
```

## BUILD ORDER — EXECUTE PHASES SEQUENTIALLY

| Phase | What to Build | Prompt File |
|-------|--------------|-------------|
| ~~1+2~~ | ~~Core + Models + EntraID + Exchange + Risk Analyzer + Orchestrator~~ | ~~DONE~~ |
| **3A** | Intune / Endpoint Collector | `PHASE-3A-Intune-Collector.md` |
| **3B** | Defender Collector | `PHASE-3B-Defender-Collector.md` |
| **3C** | Licensing / Cost Waste Collector | `PHASE-3C-Licensing-Collector.md` |
| **4** | PDF Report + Evidence Pack + AI Explainer | `PHASE-4-Output-Generators.md` |
| **5** | MSP Orchestrator + Explainer Orchestrator + Compliance Mappings | `PHASE-5-Orchestrators-Compliance.md` |
| **6** | Pester Tests + Manifests + Polish | `PHASE-6-Testing-Polish.md` |

## HOW TO USE THIS
1. Extract the zip file contents into `C:\Scripts\Assessment\AuditXpert\`
2. Open the project in VS Code
3. Feed this master prompt + `AUDITXPERT-BUILD-SPEC.md` to Claude
4. Then feed `PHASE-3A-Intune-Collector.md` and say "Build Phase 3A"
5. After Phase 3A is done, feed `PHASE-3B-Defender-Collector.md` and say "Build Phase 3B"
6. Continue sequentially through all phases

## CRITICAL RULES
1. **Read the build spec** (`AUDITXPERT-BUILD-SPEC.md`) before building anything — it contains all patterns, conventions, and technical details
2. **Follow existing patterns exactly** — every new collector must match the structure of EntraID and Exchange collectors
3. **Use `Invoke-TiTCGraphRequest`** for all Graph API calls — never call Invoke-MgGraphRequest directly
4. **Use `New-TiTCFinding`** for all findings — never create TiTCFinding objects directly
5. **Tags drive scoring** — the risk analyzer maps findings to categories via tags, so choose tags from the defined tag lists
6. **Compliance controls format**: `Framework:ControlId` (e.g., `ISO27001:A.9.2.3`)
7. **Update the orchestrator** after each collector is built — add import + replace placeholder
8. **Test imports** after creating each file: `Import-Module <path> -Force`
9. **UTF-8 encoding** for all files
10. **#Requires -Version 5.1** at the top of every .psm1 file
