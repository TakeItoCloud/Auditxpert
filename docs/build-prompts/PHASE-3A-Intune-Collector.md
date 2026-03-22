# PHASE 3A — BUILD: Intune / Endpoint Collector
# ═══════════════════════════════════════════════
# Feed this prompt to Claude in VS Code after the Master Prompt + Build Spec.
# Pre-requisite: Phase 1+2 files already in C:\Scripts\Assessment\AuditXpert
# ═══════════════════════════════════════════════

## CONTEXT
You are building the AuditXpert M365 security assessment platform.
Read `AUDITXPERT-BUILD-SPEC.md` in the `docs/` folder for full project context, patterns, and conventions.
The project root is `C:\Scripts\Assessment\AuditXpert`.
Phase 1+2 are complete — Core, Models, Entra ID Collector, Exchange Collector, Risk Analyzer, and Orchestrator are already built.

## YOUR TASK
Create: `C:\Scripts\Assessment\AuditXpert\src\Collectors\TiTC.Collector.Intune.psm1`
Then update the orchestrator to wire it in.

## MODULE SKELETON — use this exact structure:

```powershell
#Requires -Version 5.1
# Import Core + Models using relative paths
$CorePath = Join-Path (Split-Path $PSScriptRoot -Parent) 'Core\TiTC.Core.psm1'
if (Test-Path $CorePath) { Import-Module $CorePath -Force -ErrorAction Stop }
$ModelsPath = Join-Path (Split-Path $PSScriptRoot -Parent) 'Core\Models\TiTC.Models.psm1'
if (Test-Path $ModelsPath) { Import-Module $ModelsPath -Force -ErrorAction Stop }

$script:COMPONENT = 'Collector.Intune'

function Invoke-TiTCIntuneCollector {
    [CmdletBinding()]
    [OutputType([TiTCCollectorResult])]
    param(
        [hashtable]$Config = @{},
        [ValidateSet('DeviceCompliance','CompliancePolicies','Encryption',
                     'OSUpdates','StaleDevices','AppProtection',
                     'SecurityBaselines','DeviceConfigProfiles','All')]
        [string[]]$Checks = @('All')
    )
    $result = New-TiTCCollectorResult -Domain Intune
    # ... dispatch assessors with try/catch ...
    $result.Complete()
    return $result
}
# ... assessor functions ...
Export-ModuleMember -Function @('Invoke-TiTCIntuneCollector')
```

## 8 ASSESSORS — IMPLEMENT ALL WITH FULL GRAPH API LOGIC

### 1. Test-TiTCDeviceCompliance
**Graph**: `GET /deviceManagement/managedDevices` — Select: id,deviceName,operatingSystem,osVersion,complianceState,lastSyncDateTime,userPrincipalName,isEncrypted,managementAgent — AllPages
- Count compliant vs non-compliant vs unknown
- Calculate compliance %
- Compare against `$Config.Thresholds.DeviceComplianceTarget` (default 95)
- Finding if below target. Severity: Critical if <70%, High if <85%, Medium if <95%
- RiskWeight: 8 | Tags: `Intune, DeviceCompliance, EndpointSecurity`
- Compliance: `ISO27001:A.8.1, CIS:3.1.1, SOC2:CC6.8, NIST:CM-6`
- AffectedResources: list non-compliant devices with name, UPN, OS
- RawData key: `DeviceCompliance` — store counts, percentage, breakdown by OS

### 2. Test-TiTCCompliancePolicies
**Graph**: `GET /deviceManagement/deviceCompliancePolicies` — Expand assignments — AllPages
- Finding A: Policies with zero assignments → "Unassigned compliance policies" (Low, RiskWeight 2)
- Finding B: Check `@odata.type` for platform coverage (windows10, iOS, android, macOS). Missing platforms → "Missing compliance policies for [platforms]" (Medium, RiskWeight 5)
- Tags: `Intune, DeviceCompliance, PolicyCoverage` | Compliance: `ISO27001:A.8.1, NIST:CM-2`

### 3. Test-TiTCEncryptionStatus
From managed devices (re-fetch or cache), filter `isEncrypted -eq $false`:
- Finding: "Devices without disk encryption" — list by OS (BitLocker=Windows, FileVault=macOS)
- Severity: High | RiskWeight: 7 | Tags: `Intune, Encryption, BitLocker`
- Compliance: `ISO27001:A.8.24, CIS:3.4.1, SOC2:CC6.7, NIST:SC-28`
- Include RemediationScript: Intune BitLocker configuration profile creation

### 4. Test-TiTCOSUpdateCompliance
**Graph**: `GET /deviceManagement/windowsUpdateForBusinessConfigurations` — AllPages
- Finding A: No update rings configured → "No Windows Update for Business rings" (High, RiskWeight 7)
**Graph**: From managed devices, analyze `osVersion` — group and identify outdated versions
- Finding B: Devices 2+ major versions behind → "Devices on outdated OS versions" (Medium, RiskWeight 5)
- Tags: `Intune, WindowsUpdate, PatchManagement` | Compliance: `ISO27001:A.8.8, CIS:3.5.1, NIST:SI-2`

### 5. Test-TiTCStaleDevices
From managed devices, filter `lastSyncDateTime` older than 30 days (threshold configurable):
- Finding: "Stale managed devices (not synced in 30+ days)" — severity by count
- RiskWeight: 4 | Tags: `Intune, StaleDevices, Lifecycle` | Compliance: `ISO27001:A.8.1, NIST:CM-8`
- Include RemediationScript to retire stale devices

### 6. Test-TiTCAppProtection
**Graph**: `GET /deviceAppManagement/managedAppPolicies` (use Beta) — AllPages
- Finding A: No MAM policies → "No app protection policies configured" (High, RiskWeight 7)
  "BYOD devices can access corporate data without data protection controls."
- Finding B: Missing iOS or Android coverage → (Medium, RiskWeight 4)
- Tags: `Intune, MAM, AppProtection` | Compliance: `ISO27001:A.8.1, NIST:AC-19`

### 7. Test-TiTCSecurityBaselines
**Graph**: `GET /deviceManagement/intents` (Beta) — these are deployed security baselines
- Finding: No security baselines deployed → (Medium, RiskWeight 5)
  "Security baselines provide Microsoft-recommended security settings."
- Tags: `Intune, SecurityBaseline, Configuration` | Compliance: `ISO27001:A.8.9, CIS:3.1.1, NIST:CM-6`

### 8. Test-TiTCDeviceConfigProfiles
**Graph**: `GET /deviceManagement/deviceConfigurations` — AllPages
Check for critical profile types by examining `@odata.type` and `displayName`:
- Missing encryption profile → note
- Missing firewall profile → note
- Missing antivirus profile → note
- Missing Windows Hello profile → note
- Finding: "Missing critical device configuration profiles: [list]" (Medium, RiskWeight 5)
- Tags: `Intune, DeviceConfiguration, EndpointSecurity` | Compliance: `ISO27001:A.8.1, NIST:CM-6`

## UPDATE ORCHESTRATOR
Edit `profiles\Invoke-M365Snapshot.ps1`:
1. Add `$intunePath` import near line ~86
2. Replace Intune placeholder with real collector call (same pattern as Exchange)

## VALIDATE
```powershell
Import-Module .\src\Collectors\TiTC.Collector.Intune.psm1 -Force
Get-Command -Module TiTC.Collector.Intune
```
