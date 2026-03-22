# PHASE 3C — BUILD: Licensing / Cost Waste Collector
# ═══════════════════════════════════════════════════
# Pre-requisite: Phases 1-3B complete
# ═══════════════════════════════════════════════════

## CONTEXT
Read `AUDITXPERT-BUILD-SPEC.md`. Root: `C:\Scripts\Assessment\AuditXpert`.

## YOUR TASK
Create: `C:\Scripts\Assessment\AuditXpert\src\Collectors\TiTC.Collector.Licensing.psm1`
Then update orchestrator.

## MODULE SKELETON
Entry point: `Invoke-TiTCLicensingCollector` | `$script:COMPONENT = 'Collector.Licensing'`

## 7 ASSESSORS — FULL DETAIL WITH COST CALCULATION CODE

### 1. Test-TiTCLicenseInventory
**Graph**: `GET /subscribedSkus` — AllPages
```powershell
$skus = (Invoke-TiTCGraphRequest -Endpoint '/subscribedSkus' -AllPages -Component $script:COMPONENT).value

foreach ($sku in $skus) {
    $enabled = $sku.prepaidUnits.enabled
    $consumed = $sku.consumedUnits
    $available = $enabled - $consumed
    $utilization = if ($enabled -gt 0) { [Math]::Round(($consumed / $enabled) * 100, 1) } else { 0 }
    # Store per-SKU data...
}
```
- No finding here — this is the data collection step
- Store full inventory in `$Result.RawData['LicenseInventory']` with SKU name, id, enabled, consumed, available, utilization %

### 2. Test-TiTCUnusedLicenses
From subscribedSkus, identify waste using `TiTCLicenseWaste` class and `$Config.LicensePricing`:
```powershell
$totalMonthlyWaste = 0
$wasteItems = [System.Collections.ArrayList]::new()

foreach ($sku in $skus) {
    $skuName = $sku.skuPartNumber
    # Map skuPartNumber to friendly name for pricing lookup
    $friendlyName = Get-TiTCSkuFriendlyName -SkuPartNumber $skuName
    $pricePerUser = $Config.LicensePricing[$friendlyName]

    $unused = $sku.prepaidUnits.enabled - $sku.consumedUnits
    $unusedPercent = if ($sku.prepaidUnits.enabled -gt 0) {
        [Math]::Round(($unused / $sku.prepaidUnits.enabled) * 100, 1)
    } else { 0 }

    if ($unused -gt 0 -and $pricePerUser -and $unusedPercent -gt $Config.Thresholds.UnusedLicenseThreshold) {
        $waste = [TiTCLicenseWaste]::new()
        $waste.SkuName = $friendlyName
        $waste.SkuId = $sku.skuId
        $waste.TotalLicenses = $sku.prepaidUnits.enabled
        $waste.ConsumedLicenses = $sku.consumedUnits
        $waste.MonthlyUnitCost = $pricePerUser
        $waste.Calculate()

        $totalMonthlyWaste += $waste.MonthlyWaste
        $null = $wasteItems.Add($waste)
    }
}
```
- Finding with severity based on total waste: Critical >€5000/mo, High >€1000, Medium >€200, Low >€50
- Title: "License cost waste: €X/month (€Y/year)"
- Description: list top 5 SKUs by waste
- RiskWeight: 5 | Tags: `License, CostOptimization, LicenseWaste`
- Evidence: full waste breakdown

**Helper function** — add a `Get-TiTCSkuFriendlyName` function that maps common skuPartNumbers:
```powershell
function Get-TiTCSkuFriendlyName {
    param([string]$SkuPartNumber)
    $map = @{
        'SPE_E5'                    = 'Microsoft 365 E5'
        'SPE_E3'                    = 'Microsoft 365 E3'
        'SPE_E1'                    = 'Microsoft 365 E1'
        'O365_BUSINESS_PREMIUM'     = 'Microsoft 365 Business Premium'
        'O365_BUSINESS_ESSENTIALS'  = 'Microsoft 365 Business Basic'
        'SMB_BUSINESS'              = 'Microsoft 365 Business Standard'
        'ENTERPRISEPACK'            = 'Office 365 E3'
        'ENTERPRISEPREMIUM'         = 'Office 365 E5'
        'ATP_ENTERPRISE'            = 'Microsoft Defender for Office 365 P1'
        'THREAT_INTELLIGENCE'       = 'Microsoft Defender for Office 365 P2'
        'WIN_DEF_ATP'               = 'Microsoft Defender for Endpoint P2'
        'AAD_PREMIUM'               = 'Azure AD Premium P1'
        'AAD_PREMIUM_P2'            = 'Azure AD Premium P2'
        'EXCHANGESTANDARD'          = 'Exchange Online Plan 1'
        'EXCHANGEENTERPRISE'        = 'Exchange Online Plan 2'
        'INTUNE_A'                  = 'Intune Plan 1'
        'POWER_BI_PRO'              = 'Power BI Pro'
    }
    return $map[$SkuPartNumber] ?? $SkuPartNumber
}
```

### 3. Test-TiTCDuplicateLicenses
**Graph**: `GET /users` — Select: id,displayName,userPrincipalName,assignedLicenses — Filter: accountEnabled eq true — AllPages
Define overlap pairs:
```powershell
$overlapRules = @(
    @{ Higher = 'SPE_E5'; Lower = 'SPE_E3'; Name = 'E5 includes E3' }
    @{ Higher = 'SPE_E5'; Lower = 'ENTERPRISEPACK'; Name = 'M365 E5 includes O365 E3' }
    @{ Higher = 'SPE_E3'; Lower = 'EXCHANGEENTERPRISE'; Name = 'E3 includes Exchange Plan 2' }
    @{ Higher = 'SPE_E3'; Lower = 'EXCHANGESTANDARD'; Name = 'E3 includes Exchange Plan 1' }
    @{ Higher = 'O365_BUSINESS_PREMIUM'; Lower = 'INTUNE_A'; Name = 'Business Premium includes Intune' }
    @{ Higher = 'O365_BUSINESS_PREMIUM'; Lower = 'ATP_ENTERPRISE'; Name = 'Business Premium includes Defender' }
    @{ Higher = 'SPE_E5'; Lower = 'AAD_PREMIUM_P2'; Name = 'E5 includes AAD P2' }
    @{ Higher = 'SPE_E5'; Lower = 'WIN_DEF_ATP'; Name = 'E5 includes Defender for Endpoint' }
)
```
Check each user's assigned SKUs against overlap rules.
- Finding: "Users with duplicate/overlapping licenses" — list users + which SKUs overlap + estimated waste
- Severity: Medium | RiskWeight: 4 | Tags: `License, Duplicate, CostOptimization`

### 4. Test-TiTCOverProvisionedUsers
**Graph (Beta)**: `GET /reports/getOffice365ActiveUserDetail(period='D180')`
Compare user activity columns with license tier — users with E5 not using:
- Power BI, Phone System, advanced compliance, eDiscovery, advanced analytics
→ Could downgrade to E3
- Finding: "Users with E5 licenses using only E3-level features"
- Severity: Low | RiskWeight: 3 | Tags: `License, OverProvisioned, CostOptimization`
- Handle API errors gracefully — this report may require Reports.Read.All

### 5. Test-TiTCTrialSubscriptions
From subscribedSkus, filter `capabilityStatus -eq 'Warning'` or `appliesTo` contains trial indicators:
```powershell
$trials = $skus | Where-Object {
    $_.capabilityStatus -eq 'Warning' -or
    $_.skuPartNumber -match 'TRIAL|EVALUAT'
}
```
- Finding if trials expiring within 30 days
- Severity: Low | RiskWeight: 2 | Tags: `License, Trial, Expiry`

### 6. Test-TiTCUnlicensedUsers
**Graph**: `GET /users` — Filter: `accountEnabled eq true and assignedLicenses/$count eq 0` (or filter in code)
```powershell
$allUsers = (Invoke-TiTCGraphRequest -Endpoint '/users' -Select 'id,displayName,userPrincipalName,accountEnabled,assignedLicenses,userType' -Filter "accountEnabled eq true and userType eq 'Member'" -AllPages -Component $script:COMPONENT).value
$unlicensed = $allUsers | Where-Object { -not $_.assignedLicenses -or $_.assignedLicenses.Count -eq 0 }
```
- Finding: "Enabled user accounts without any licenses"
- Severity: Low | RiskWeight: 2 | Tags: `License, Provisioning, AccountHygiene`

### 7. Test-TiTCLicenseWasteSummary
Aggregate all waste from previous assessors:
```powershell
$totalMonthly = ($wasteItems | Measure-Object -Property MonthlyWaste -Sum).Sum
$totalAnnual = $totalMonthly * 12
```
- Store comprehensive summary in `$Result.RawData['LicenseWasteSummary']`:
  - Total monthly waste EUR, annual waste EUR
  - Top 5 waste SKUs
  - Duplicate license waste
  - Over-provisioned waste estimate
  - Recommendations
- This data feeds directly into the PDF report "License Waste Summary" section

## UPDATE ORCHESTRATOR
Add Licensing import + replace placeholder. Also after collectors run, set:
```powershell
$licensingResult = $report.CollectorResults | Where-Object { $_.Domain -eq 'Licensing' }
if ($licensingResult -and $licensingResult.RawData['LicenseWasteSummary']) {
    $report.EstimatedWaste = $licensingResult.RawData['LicenseWasteSummary'].TotalMonthlyWaste
}
```
