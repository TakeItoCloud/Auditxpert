# PHASE 3B — BUILD: Defender Collector
# ═══════════════════════════════════════
# Pre-requisite: Phases 1-3A complete
# ═══════════════════════════════════════

## CONTEXT
Read `AUDITXPERT-BUILD-SPEC.md` for full context. Root: `C:\Scripts\Assessment\AuditXpert`.

## YOUR TASK
Create: `C:\Scripts\Assessment\AuditXpert\src\Collectors\TiTC.Collector.Defender.psm1`
Then update orchestrator.

## MODULE SKELETON — same pattern as other collectors:
Entry point: `Invoke-TiTCDefenderCollector` | `$script:COMPONENT = 'Collector.Defender'`

## 7 ASSESSORS — FULL IMPLEMENTATION DETAIL

### 1. Test-TiTCSecureScore
**Graph**: `GET /security/secureScores?$top=1` (most recent score)
**Graph**: `GET /security/secureScoreControlProfiles` — AllPages — get improvement actions
```powershell
$scores = (Invoke-TiTCGraphRequest -Endpoint '/security/secureScores' -Top 1 -Component $script:COMPONENT).value
$currentScore = $scores[0].currentScore
$maxScore = $scores[0].maxScore
$percentage = [Math]::Round(($currentScore / $maxScore) * 100, 1)
```
- Finding if < 60%: list top 5 improvement actions sorted by score impact
- Severity: High if <40%, Medium if <60% | RiskWeight: 6
- Tags: `SecureScore, SecurityPosture` | Compliance: `ISO27001:A.5.1, NIST:CA-2`
- RawData: store current score, max, percentage, top actions

### 2. Test-TiTCSecurityAlerts
**Graph**: `GET /security/alerts_v2` — Filter: `status ne 'resolved'` — AllPages
```powershell
$alerts = (Invoke-TiTCGraphRequest -Endpoint '/security/alerts_v2' -Filter "status ne 'resolved'" -AllPages -Component $script:COMPONENT).value
$criticalAlerts = $alerts | Where-Object { $_.severity -eq 'high' -or $_.severity -eq 'critical' }
$staleAlerts = $alerts | Where-Object {
    $_.createdDateTime -and ([datetime]$_.createdDateTime -lt (Get-Date).AddHours(-48))
}
```
- Finding if critical/high alerts open >48 hours: "Unresolved critical security alerts"
- Severity: Critical if unresolved critical alerts, High otherwise | RiskWeight: 9
- Tags: `Alerts, ThreatDetection, IncidentResponse`
- Compliance: `ISO27001:A.5.24, SOC2:CC7.2, NIST:IR-4`
- AffectedResources: alert titles with severity and age

### 3. Test-TiTCIncidents
**Graph**: `GET /security/incidents` — Filter: `status ne 'resolved'` — AllPages
- Count active incidents by severity
- Finding if active incidents exist: "Active security incidents requiring attention"
- Severity: based on highest incident severity | RiskWeight: 8
- Tags: `Incidents, ThreatDetection` | Compliance: `ISO27001:A.5.24, NIST:IR-4`

### 4. Test-TiTCDefenderForEndpointCoverage
**Graph**: `GET /deviceManagement/managedDevices` — Select: id,deviceName,managementAgent — AllPages
Check which management agents include Defender (`managementAgent` contains 'mdm' or check device category).
Alternative: count devices vs Defender onboarded count from security API.
- Finding: "Devices not onboarded to Defender for Endpoint" — list gap
- Severity: High | RiskWeight: 7 | Tags: `DefenderForEndpoint, EndpointSecurity, Onboarding`
- Compliance: `ISO27001:A.8.7, CIS:4.1.1, NIST:SI-3`

### 5. Test-TiTCEmailThreatPolicies
**Graph (Beta)**: Try `GET /security/emailThreatSubmissionPolicies` or check for preset security policies.
If API not available, check Exchange connector for policy existence.
- Finding: "No preset security policies applied (Standard or Strict)"
- Description: "Microsoft's preset policies provide a recommended baseline for anti-phishing, anti-spam, and anti-malware. Without preset policies, protection relies on default settings."
- Severity: Medium | RiskWeight: 5 | Tags: `DefenderForOffice365, EmailSecurity, PresetPolicies`
- Compliance: `ISO27001:A.8.23, NIST:SI-8`

### 6. Test-TiTCAttackSimulation
**Graph (Beta)**: `GET /security/attackSimulation/simulations` — AllPages
```powershell
$simulations = (Invoke-TiTCGraphRequest -Endpoint '/security/attackSimulation/simulations' -Beta -AllPages -Component $script:COMPONENT).value
$recent = $simulations | Where-Object {
    $_.createdDateTime -and ([datetime]$_.createdDateTime -gt (Get-Date).AddDays(-90))
}
```
- Finding if no simulations in 90 days: "No attack simulation training conducted"
- Description: "Regular phishing simulations train employees to recognize social engineering. Without regular training, users remain the weakest link."
- Severity: Medium | RiskWeight: 4 | Tags: `AttackSimulation, SecurityAwareness, Training`
- Compliance: `ISO27001:A.6.3, NIST:AT-2`

### 7. Test-TiTCAutoInvestigation
Check if automated investigation and response is producing results:
**Graph**: Look for alerts with `automatedInvestigationId` populated
```powershell
$airAlerts = $alerts | Where-Object { $_.automatedInvestigationId }
```
- Finding if zero AIR actions found: "Automated investigation and response not active"
- Severity: Low | RiskWeight: 3 | Tags: `AutomatedResponse, AIR, IncidentResponse`
- Compliance: `ISO27001:A.5.24, NIST:IR-4`

## UPDATE ORCHESTRATOR
Add Defender import + replace placeholder in `profiles\Invoke-M365Snapshot.ps1`.
