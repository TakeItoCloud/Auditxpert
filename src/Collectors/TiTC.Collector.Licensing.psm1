#Requires -Version 5.1
<#
.SYNOPSIS
    TakeItToCloud.Assess — License & Cost Waste Collector.

.DESCRIPTION
    Performs comprehensive Microsoft 365 license analysis via Graph API. Covers:

    - Complete license inventory (SKUs, assigned vs consumed vs available)
    - Unused license waste with EUR cost calculation
    - Duplicate/overlapping license assignments per user
    - Over-provisioned users (E5 features unused, E3 sufficient)
    - Trial subscriptions approaching expiry
    - Enabled users with no license assignments
    - Aggregate waste summary with monthly and annual totals

    All checks produce standardized TiTCFinding objects. Cost findings use
    the TiTCLicenseWaste class. Pricing is sourced from Config.LicensePricing.

.NOTES
    Module:     TiTC.Collector.Licensing
    Author:     TakeItToCloud
    Version:    1.0.0
    Requires:   TiTC.Core, Microsoft.Graph.Authentication
#>

# ============================================================================
# MODULE DEPENDENCIES
# ============================================================================

$CorePath = Join-Path (Split-Path $PSScriptRoot -Parent) 'Core\TiTC.Core.psm1'
if (Test-Path $CorePath) {
    Import-Module $CorePath -ErrorAction Stop
}

$ModelsPath = Join-Path (Split-Path $PSScriptRoot -Parent) 'Core\Models\TiTC.Models.psm1'
if (Test-Path $ModelsPath) {
    Import-Module $ModelsPath -ErrorAction Stop
}

# ============================================================================
# CONSTANTS
# ============================================================================

$script:COMPONENT = 'Collector.Licensing'

# SKU overlaps: key = higher-tier SKU part number, value = list of SKUs it supersedes
# Used to detect duplicate/redundant license assignments
$script:LICENSE_OVERLAPS = @{
    'SPE_E5'           = @('SPE_E3', 'EXCHANGEENTERPRISE', 'SHAREPOINTENTERPRISE', 'MCOSTANDARD', 'EMS', 'ATP_ENTERPRISE')
    'SPE_E3'           = @('EXCHANGEENTERPRISE', 'SHAREPOINTENTERPRISE', 'MCOSTANDARD', 'PROJECTCLIENT')
    'SPB'              = @('EMS', 'INTUNE_A', 'ATP_ENTERPRISE')  # Microsoft 365 Business Premium
    'ENTERPRISEPREMIUM'= @('ENTERPRISEPACK', 'EXCHANGEENTERPRISE', 'SHAREPOINTENTERPRISE')  # Office 365 E5 > E3
}

# Display name fragments for E5-exclusive features detection
$script:E5_EXCLUSIVE_SERVICE_PLANS = @(
    'POWER_BI_PRO',
    'MCOEV',                    # Phone System
    'THREAT_INTELLIGENCE',      # Defender for Office 365 Plan 2
    'COMMUNICATIONS_DLP',       # Communication Compliance
    'INFO_GOVERNANCE',          # Advanced Information Governance
    'CUSTOMER_KEY',             # Customer Key
    'PREMIUM_ENCRYPTION_CONSULTATION'
)

# ============================================================================
# MAIN COLLECTOR ENTRY POINT
# ============================================================================

function Invoke-TiTCLicensingCollector {
    <#
    .SYNOPSIS
        Runs all licensing and cost waste checks and returns a TiTCCollectorResult.

    .DESCRIPTION
        Orchestrates all licensing assessors against the connected tenant.
        Each assessor runs independently — a failure in one does not block others.
        Results are aggregated into a single CollectorResult with all findings.

    .PARAMETER Config
        Assessment configuration hashtable from Get-TiTCConfig.

    .PARAMETER Checks
        Specific checks to run. Default runs all checks.
    #>
    [CmdletBinding()]
    [OutputType([TiTCCollectorResult])]
    param(
        [hashtable]$Config = @{},

        [ValidateSet(
            'LicenseInventory', 'UnusedLicenses', 'DuplicateLicenses',
            'OverProvisionedUsers', 'TrialSubscriptions', 'UnlicensedUsers',
            'LicenseWasteSummary', 'All'
        )]
        [string[]]$Checks = @('All')
    )

    $result = New-TiTCCollectorResult -Domain Licensing
    Write-TiTCLog "Starting License & Cost Waste assessment..." -Level Info -Component $script:COMPONENT

    if (-not $Config.Thresholds) {
        $Config = Get-TiTCConfig -ProfileName Full
    }

    $runAll = $Checks -contains 'All'

    # ── Assessor dispatch ───────────────────────────────────────────────
    $assessors = [ordered]@{
        'LicenseInventory'    = { Test-TiTCLicenseInventory    -Config $Config -Result $result }
        'UnusedLicenses'      = { Test-TiTCUnusedLicenses      -Config $Config -Result $result }
        'DuplicateLicenses'   = { Test-TiTCDuplicateLicenses   -Config $Config -Result $result }
        'OverProvisionedUsers'= { Test-TiTCOverProvisionedUsers -Config $Config -Result $result }
        'TrialSubscriptions'  = { Test-TiTCTrialSubscriptions   -Config $Config -Result $result }
        'UnlicensedUsers'     = { Test-TiTCUnlicensedUsers      -Config $Config -Result $result }
        'LicenseWasteSummary' = { Test-TiTCLicenseWasteSummary  -Config $Config -Result $result }
    }

    foreach ($assessorName in $assessors.Keys) {
        if ($runAll -or $Checks -contains $assessorName) {
            try {
                Write-TiTCLog "Running check: $assessorName" -Level Info -Component $script:COMPONENT
                & $assessors[$assessorName]
            }
            catch {
                $errorMsg = "Check '$assessorName' failed: $($_.Exception.Message)"
                Write-TiTCLog $errorMsg -Level Error -Component $script:COMPONENT
                $result.Errors += $errorMsg

                if ($result.Status -eq 'Success') {
                    $result.Status = [TiTCCollectorStatus]::PartialSuccess
                }
            }
        }
    }

    $result.Complete()

    $summary = $result.ToSummary()
    Write-TiTCLog "Licensing assessment complete" -Level Success -Component $script:COMPONENT -Data $summary

    return $result
}

# ============================================================================
# ASSESSOR: License Inventory
# ============================================================================

function Test-TiTCLicenseInventory {
    [CmdletBinding()]
    param(
        [hashtable]$Config,
        [TiTCCollectorResult]$Result
    )

    Write-TiTCLog "Building license inventory..." -Level Info -Component $script:COMPONENT

    $skus = (Invoke-TiTCGraphRequest `
        -Endpoint '/subscribedSkus' `
        -Select 'id,skuId,skuPartNumber,prepaidUnits,consumedUnits,capabilityStatus,servicePlans,appliesTo' `
        -Component $script:COMPONENT
    ).value

    $Result.ObjectsScanned += $skus.Count
    $Result.RawData['SubscribedSkus'] = $skus

    if ($skus.Count -eq 0) {
        Write-TiTCLog "No subscribed SKUs found" -Level Warning -Component $script:COMPONENT
        return
    }

    # Build inventory summary
    $inventory = $skus | ForEach-Object {
        $enabled  = $_.prepaidUnits.enabled
        $consumed = $_.consumedUnits
        $unused   = [Math]::Max(0, $enabled - $consumed)
        $utilPct  = if ($enabled -gt 0) { [Math]::Round(($consumed / $enabled) * 100, 1) } else { 0 }

        [PSCustomObject]@{
            SkuPartNumber  = $_.skuPartNumber
            SkuId          = $_.skuId
            TotalLicenses  = $enabled
            Consumed       = $consumed
            Available      = $unused
            UtilizationPct = $utilPct
            Status         = $_.capabilityStatus
        }
    }

    $totalLicenses = ($inventory | Measure-Object TotalLicenses -Sum).Sum
    $totalConsumed = ($inventory | Measure-Object Consumed -Sum).Sum
    $totalUnused   = ($inventory | Measure-Object Available -Sum).Sum

    $Result.RawData['LicenseInventory'] = @{
        SKUs           = $inventory
        TotalLicenses  = $totalLicenses
        TotalConsumed  = $totalConsumed
        TotalUnused    = $totalUnused
        OverallUtilPct = if ($totalLicenses -gt 0) { [Math]::Round(($totalConsumed / $totalLicenses) * 100, 1) } else { 0 }
    }

    Write-TiTCLog "License inventory: $totalLicenses total, $totalConsumed consumed, $totalUnused unused across $($skus.Count) SKUs" `
        -Level Info -Component $script:COMPONENT
}

# ============================================================================
# ASSESSOR: Unused Licenses (waste by SKU)
# ============================================================================

function Test-TiTCUnusedLicenses {
    [CmdletBinding()]
    param(
        [hashtable]$Config,
        [TiTCCollectorResult]$Result
    )

    Write-TiTCLog "Checking for unused license waste..." -Level Info -Component $script:COMPONENT

    $skus = if ($Result.RawData['SubscribedSkus']) {
        $Result.RawData['SubscribedSkus']
    } else {
        (Invoke-TiTCGraphRequest `
            -Endpoint '/subscribedSkus' `
            -Select 'id,skuId,skuPartNumber,prepaidUnits,consumedUnits,capabilityStatus' `
            -Component $script:COMPONENT
        ).value
    }

    if ($skus.Count -eq 0) { return }

    $unusedThresholdPct = if ($Config.Thresholds.UnusedLicenseThreshold) {
        $Config.Thresholds.UnusedLicenseThreshold
    } else { 10 }

    $licensePricing = if ($Config.LicensePricing) { $Config.LicensePricing } else { @{} }

    $wasteFindings  = [System.Collections.ArrayList]::new()
    $totalMonthlyWaste = 0.0

    foreach ($sku in $skus) {
        if ($sku.capabilityStatus -ne 'Enabled') { continue }

        $enabled  = $sku.prepaidUnits.enabled
        $consumed = $sku.consumedUnits
        if ($enabled -le 0) { continue }

        $unused    = [Math]::Max(0, $enabled - $consumed)
        $unusedPct = [Math]::Round(($unused / $enabled) * 100, 1)

        if ($unusedPct -lt $unusedThresholdPct) { continue }

        # Try exact match then partial match for pricing
        $skuPartNumber = $sku.skuPartNumber
        $pricePerUser  = $licensePricing[$skuPartNumber]

        if (-not $pricePerUser) {
            # Try matching by display name fragment in pricing table
            foreach ($key in $licensePricing.Keys) {
                if ($skuPartNumber -like "*$key*" -or $key -like "*$skuPartNumber*") {
                    $pricePerUser = $licensePricing[$key]
                    break
                }
            }
        }

        $waste = [TiTCLicenseWaste]::new()
        $waste.SkuName          = $skuPartNumber
        $waste.SkuId            = $sku.skuId
        $waste.TotalLicenses    = $enabled
        $waste.ConsumedLicenses = $consumed
        $waste.MonthlyUnitCost  = if ($pricePerUser) { $pricePerUser } else { 0 }
        $waste.Calculate()

        $totalMonthlyWaste += $waste.MonthlyWaste
        $null = $wasteFindings.Add($waste)
    }

    $Result.RawData['UnusedLicenseWaste'] = $wasteFindings
    $Result.RawData['TotalMonthlyWaste']  = $totalMonthlyWaste

    if ($wasteFindings.Count -eq 0) {
        Write-TiTCLog "No significant unused license waste detected" -Level Info -Component $script:COMPONENT
        return
    }

    # Sort by waste and take top 5 for finding details
    $topWaste = $wasteFindings | Sort-Object MonthlyWaste -Descending | Select-Object -First 5

    $severity = if ($totalMonthlyWaste -gt 5000) { 'Critical' }
                elseif ($totalMonthlyWaste -gt 1000) { 'High' }
                elseif ($totalMonthlyWaste -gt 200)  { 'Medium' }
                else { 'Low' }

    $annualWaste = $totalMonthlyWaste * 12

    $affectedList = $topWaste | ForEach-Object {
        $monthStr  = if ($_.MonthlyWaste -gt 0) { "€$([Math]::Round($_.MonthlyWaste, 2))/mo" } else { 'price unknown' }
        "$($_.SkuName): $($_.UnusedLicenses) unused of $($_.TotalLicenses) ($monthStr)"
    }

    $Result.Findings += New-TiTCFinding `
        -Title "Unused License Waste Detected — €$([Math]::Round($totalMonthlyWaste, 0))/Month ($([Math]::Round($annualWaste, 0))/Year)" `
        -Description "$($wasteFindings.Count) license SKUs have more than $unusedThresholdPct% unused licenses. Total estimated waste: €$([Math]::Round($totalMonthlyWaste, 2))/month (€$([Math]::Round($annualWaste, 2))/year). The top 5 waste contributors are listed. Note: prices are based on configured list pricing and may differ from contracted rates." `
        -Severity $severity `
        -Domain Licensing `
        -RiskWeight 4 `
        -Remediation "1. Review each over-provisioned SKU and reclaim unused licenses from inactive or departed users. 2. Downgrade users who don't need the full feature set to a lower SKU. 3. Contact your Microsoft partner or account team to right-size your subscription quantities at renewal. 4. Enable license assignment automation to prevent future over-provisioning." `
        -RemediationUrl 'https://learn.microsoft.com/en-us/microsoft-365/admin/misc/license-management' `
        -ComplianceControls @() `
        -AffectedResources $affectedList `
        -Evidence @{
            TotalSKUsWithWaste  = $wasteFindings.Count
            TotalMonthlyWaste   = [Math]::Round($totalMonthlyWaste, 2)
            TotalAnnualWaste    = [Math]::Round($annualWaste, 2)
            UnusedThresholdPct  = $unusedThresholdPct
            TopWasteSKUs        = ($topWaste | Select-Object SkuName, UnusedLicenses, TotalLicenses, MonthlyWaste)
        } `
        -EvidenceQuery 'GET /subscribedSkus' `
        -DetectedBy $script:COMPONENT `
        -Tags @('License', 'CostOptimization', 'LicenseWaste')
}

# ============================================================================
# ASSESSOR: Duplicate / Overlapping Licenses
# ============================================================================

function Test-TiTCDuplicateLicenses {
    [CmdletBinding()]
    param(
        [hashtable]$Config,
        [TiTCCollectorResult]$Result
    )

    Write-TiTCLog "Checking for duplicate/overlapping license assignments..." -Level Info -Component $script:COMPONENT

    # Get all users with their assigned licenses
    $users = @()
    try {
        $users = (Invoke-TiTCGraphRequest `
            -Endpoint '/users' `
            -Select 'id,userPrincipalName,displayName,assignedLicenses,accountEnabled' `
            -Filter "accountEnabled eq true" `
            -AllPages `
            -Component $script:COMPONENT
        ).value
    }
    catch {
        Write-TiTCLog "Could not retrieve user license assignments: $_" -Level Warning -Component $script:COMPONENT
        return
    }

    $Result.ObjectsScanned += $users.Count
    $Result.RawData['UsersWithLicenses'] = $users

    # Get SKU ID to part number mapping for overlap detection
    $skuMap = @{}
    $skus = if ($Result.RawData['SubscribedSkus']) { $Result.RawData['SubscribedSkus'] } else { @() }
    foreach ($sku in $skus) {
        $skuMap[$sku.skuId] = $sku.skuPartNumber
    }

    $duplicateUsers = [System.Collections.ArrayList]::new()
    $licensePricing = if ($Config.LicensePricing) { $Config.LicensePricing } else { @{} }

    foreach ($user in $users) {
        if (-not $user.assignedLicenses -or $user.assignedLicenses.Count -lt 2) { continue }

        $userSkuPartNumbers = $user.assignedLicenses | ForEach-Object {
            $skuMap[$_.skuId]
        } | Where-Object { $_ }

        $foundOverlaps = [System.Collections.ArrayList]::new()

        foreach ($higherSku in $script:LICENSE_OVERLAPS.Keys) {
            if ($userSkuPartNumbers -notcontains $higherSku) { continue }

            foreach ($lowerSku in $script:LICENSE_OVERLAPS[$higherSku]) {
                if ($userSkuPartNumbers -contains $lowerSku) {
                    $null = $foundOverlaps.Add("$higherSku includes $lowerSku")
                }
            }
        }

        if ($foundOverlaps.Count -gt 0) {
            $null = $duplicateUsers.Add([PSCustomObject]@{
                UPN      = $user.userPrincipalName
                Overlaps = $foundOverlaps -join '; '
                SKUs     = $userSkuPartNumbers -join ', '
            })
        }
    }

    $Result.RawData['DuplicateLicenseUsers'] = $duplicateUsers

    if ($duplicateUsers.Count -gt 0) {
        $affectedList = $duplicateUsers | Select-Object -First 30 | ForEach-Object {
            "$($_.UPN) — $($_.Overlaps)"
        }

        $Result.Findings += New-TiTCFinding `
            -Title "Duplicate/Overlapping License Assignments ($($duplicateUsers.Count) users)" `
            -Description "$($duplicateUsers.Count) users have overlapping license assignments where a higher-tier SKU already includes the features of a separately assigned lower-tier SKU. These redundant assignments result in unnecessary license costs and management complexity." `
            -Severity Medium `
            -Domain Licensing `
            -RiskWeight 4 `
            -Remediation "Review each affected user's license assignments and remove the redundant lower-tier license. For example: a user with Microsoft 365 E5 does not need a separate Exchange Online Plan 2 as Exchange is included in E5. Use the Microsoft 365 Admin Center (admin.microsoft.com > Users > Active users > [user] > Licenses) or PowerShell to adjust assignments." `
            -RemediationUrl 'https://learn.microsoft.com/en-us/microsoft-365/admin/manage/assign-licenses-to-users' `
            -ComplianceControls @() `
            -AffectedResources $affectedList `
            -Evidence @{
                DuplicateUserCount = $duplicateUsers.Count
                TotalUsersChecked  = $users.Count
                OverlapTypes       = ($duplicateUsers | ForEach-Object { $_.Overlaps } | Sort-Object -Unique)
            } `
            -EvidenceQuery 'GET /users?$select=id,userPrincipalName,assignedLicenses' `
            -DetectedBy $script:COMPONENT `
            -Tags @('License', 'Duplicate', 'CostOptimization')
    }
}

# ============================================================================
# ASSESSOR: Over-Provisioned Users (E5 with only E3 usage)
# ============================================================================

function Test-TiTCOverProvisionedUsers {
    [CmdletBinding()]
    param(
        [hashtable]$Config,
        [TiTCCollectorResult]$Result
    )

    Write-TiTCLog "Checking for over-provisioned users (E5 with minimal feature usage)..." -Level Info -Component $script:COMPONENT

    # Get active user detail report for last 180 days
    $activeUserDetail = @()
    try {
        # This report returns a CSV blob — handle accordingly
        $reportResponse = Invoke-TiTCGraphRequest `
            -Endpoint '/reports/getOffice365ActiveUserDetail(period=''D180'')' `
            -Beta `
            -Component $script:COMPONENT

        # The response is CSV content
        if ($reportResponse -is [string]) {
            $csvLines = $reportResponse -split "`n" | Where-Object { $_ }
            if ($csvLines.Count -gt 1) {
                $headers = ($csvLines[0] -split ',') | ForEach-Object { $_.Trim('"') }
                $activeUserDetail = for ($i = 1; $i -lt $csvLines.Count; $i++) {
                    $values = $csvLines[$i] -split ','
                    $obj = [ordered]@{}
                    for ($j = 0; $j -lt $headers.Count -and $j -lt $values.Count; $j++) {
                        $obj[$headers[$j]] = $values[$j].Trim('"')
                    }
                    [PSCustomObject]$obj
                }
            }
        }
    }
    catch {
        Write-TiTCLog "Could not retrieve Office 365 active user report (requires Reports.Read.All): $_" -Level Warning -Component $script:COMPONENT
        $Result.Warnings += "Over-provisioning check skipped — Office 365 usage report unavailable"
        return
    }

    if ($activeUserDetail.Count -eq 0) {
        Write-TiTCLog "No active user detail data returned from report" -Level Warning -Component $script:COMPONENT
        return
    }

    $Result.ObjectsScanned += $activeUserDetail.Count
    $Result.RawData['O365ActiveUserDetail'] = $activeUserDetail | Select-Object -First 100  # cap stored data

    # Cross-reference: users with E5 SKU but not using E5-exclusive features
    $users = if ($Result.RawData['UsersWithLicenses']) {
        $Result.RawData['UsersWithLicenses']
    } else { @() }

    $skuMap = @{}
    $skus = if ($Result.RawData['SubscribedSkus']) { $Result.RawData['SubscribedSkus'] } else { @() }
    foreach ($sku in $skus) { $skuMap[$sku.skuId] = $sku.skuPartNumber }

    # Find E5 users
    $e5Users = $users | Where-Object {
        $userSkus = $_.assignedLicenses | ForEach-Object { $skuMap[$_.skuId] }
        $userSkus -contains 'SPE_E5' -or $userSkus -contains 'ENTERPRISEPREMIUM'
    }

    if ($e5Users.Count -eq 0) {
        Write-TiTCLog "No E5 users found — skipping over-provisioning check" -Level Info -Component $script:COMPONENT
        return
    }

    # Match activity report to identify inactive E5 users
    $inactiveE5Users = [System.Collections.ArrayList]::new()

    foreach ($e5User in $e5Users) {
        $activity = $activeUserDetail | Where-Object {
            $_.'User Principal Name' -eq $e5User.userPrincipalName
        } | Select-Object -First 1

        if (-not $activity) { continue }

        # Check if user is using any E5-exclusive features
        # Key columns: 'Exchange License Assign Date', 'Power BI (Free) Used', etc.
        $hasTeamsPhone  = $activity.'Teams License Assign Date' -and $activity.'Teams Calling Used' -eq 'True'
        $hasPowerBI     = $activity.'Power BI (Free) Used' -eq 'True'
        $hasAdvCompliance = $false  # Cannot easily detect from this report

        # If user uses only Exchange, Teams, SharePoint — they could be E3
        $usesOnlyE3Features = -not $hasTeamsPhone -and -not $hasPowerBI -and -not $hasAdvCompliance

        if ($usesOnlyE3Features) {
            $null = $inactiveE5Users.Add($e5User.userPrincipalName)
        }
    }

    $Result.RawData['PotentialE5Downgrades'] = $inactiveE5Users

    if ($inactiveE5Users.Count -gt 0) {
        $e5Price = if ($Config.LicensePricing['Microsoft 365 E5']) { $Config.LicensePricing['Microsoft 365 E5'] } else { 54.75 }
        $e3Price = if ($Config.LicensePricing['Microsoft 365 E3']) { $Config.LicensePricing['Microsoft 365 E3'] } else { 33.00 }
        $savingsPerUser  = $e5Price - $e3Price
        $monthlySavings  = [Math]::Round($inactiveE5Users.Count * $savingsPerUser, 2)
        $annualSavings   = [Math]::Round($monthlySavings * 12, 2)

        $Result.Findings += New-TiTCFinding `
            -Title "Potentially Over-Provisioned E5 Users ($($inactiveE5Users.Count) users — €$monthlySavings/month potential saving)" `
            -Description "$($inactiveE5Users.Count) users have Microsoft 365 E5 licenses but do not appear to use E5-exclusive features (Teams Phone System, Power BI Pro, Advanced Compliance) based on the last 180 days of activity. Downgrading these users to E3 could save approximately €$monthlySavings/month (€$annualSavings/year). This analysis is indicative — verify with detailed usage reports before downgrading." `
            -Severity Low `
            -Domain Licensing `
            -RiskWeight 3 `
            -Remediation "1. Review detailed E5 feature usage for flagged users in Microsoft 365 Admin Center > Reports > Usage. 2. Verify whether users need E5 for upcoming projects or compliance requirements. 3. Downgrade confirmed non-E5 users to Microsoft 365 E3 in Licensing admin. 4. Consider creating a licence review process quarterly." `
            -RemediationUrl 'https://learn.microsoft.com/en-us/microsoft-365/admin/misc/license-management' `
            -ComplianceControls @() `
            -AffectedResources ($inactiveE5Users | Select-Object -First 30) `
            -Evidence @{
                E5UserCount         = $e5Users.Count
                PotentialDowngrades = $inactiveE5Users.Count
                MonthlySavings      = $monthlySavings
                AnnualSavings       = $annualSavings
                E5Price             = $e5Price
                E3Price             = $e3Price
            } `
            -EvidenceQuery "GET /reports/getOffice365ActiveUserDetail(period='D180')" `
            -DetectedBy $script:COMPONENT `
            -Tags @('License', 'OverProvisioned', 'CostOptimization')
    }
}

# ============================================================================
# ASSESSOR: Trial Subscriptions Expiring
# ============================================================================

function Test-TiTCTrialSubscriptions {
    [CmdletBinding()]
    param(
        [hashtable]$Config,
        [TiTCCollectorResult]$Result
    )

    Write-TiTCLog "Checking for trial subscriptions nearing expiry..." -Level Info -Component $script:COMPONENT

    $skus = if ($Result.RawData['SubscribedSkus']) {
        $Result.RawData['SubscribedSkus']
    } else {
        (Invoke-TiTCGraphRequest `
            -Endpoint '/subscribedSkus' `
            -Select 'id,skuId,skuPartNumber,prepaidUnits,consumedUnits,capabilityStatus,appliesTo' `
            -Component $script:COMPONENT
        ).value
    }

    # Detect trial subscriptions
    # capabilityStatus of 'Warning' or 'Suspended' can indicate trial/expiry
    # Trial SKUs typically contain 'TRIAL' in the part number
    $trialSkus = $skus | Where-Object {
        $_.skuPartNumber -match 'TRIAL|DEVELOPERPACK|FLOW_FREE|POWER_BI_STANDARD' -or
        $_.capabilityStatus -in @('Warning', 'Suspended')
    }

    $Result.ObjectsScanned += $trialSkus.Count
    $Result.RawData['TrialSubscriptions'] = $trialSkus

    if ($trialSkus.Count -eq 0) {
        Write-TiTCLog "No trial subscriptions detected" -Level Info -Component $script:COMPONENT
        return
    }

    # Note: The Graph API subscribedSkus endpoint does not expose expiry dates directly.
    # We flag trial SKUs and warn about monitoring.
    $warningSkus   = $trialSkus | Where-Object { $_.capabilityStatus -eq 'Warning' }
    $suspendedSkus = $trialSkus | Where-Object { $_.capabilityStatus -eq 'Suspended' }
    $activeTrials  = $trialSkus | Where-Object { $_.capabilityStatus -eq 'Enabled' }

    $affectedList = $trialSkus | ForEach-Object {
        "$($_.skuPartNumber) — status: $($_.capabilityStatus) — consumed: $($_.consumedUnits) of $($_.prepaidUnits.enabled)"
    }

    $severity = if ($suspendedSkus.Count -gt 0) { 'High' }
                elseif ($warningSkus.Count -gt 0) { 'Medium' }
                else { 'Low' }

    $Result.Findings += New-TiTCFinding `
        -Title "Trial or Expiring Subscriptions Detected ($($trialSkus.Count) SKUs)" `
        -Description "$($trialSkus.Count) trial or expiring license subscriptions were found. $($suspendedSkus.Count) are suspended, $($warningSkus.Count) are in warning state, and $($activeTrials.Count) are active trials. When trial subscriptions expire, users lose access to the associated services. Suspended subscriptions have already lost service access." `
        -Severity $severity `
        -Domain Licensing `
        -RiskWeight 5 `
        -Remediation "1. Review trial subscriptions in Microsoft 365 Admin Center > Billing > Your products. 2. Convert trials to paid subscriptions before expiry if the services are in use. 3. For suspended subscriptions, renew immediately or migrate users to alternative services. 4. Remove trial licenses from users if the trial is not being adopted." `
        -RemediationUrl 'https://learn.microsoft.com/en-us/microsoft-365/commerce/subscriptions/renew-your-subscription' `
        -ComplianceControls @() `
        -AffectedResources $affectedList `
        -Evidence @{
            TotalTrialSKUs   = $trialSkus.Count
            SuspendedCount   = $suspendedSkus.Count
            WarningCount     = $warningSkus.Count
            ActiveTrials     = $activeTrials.Count
        } `
        -EvidenceQuery 'GET /subscribedSkus' `
        -DetectedBy $script:COMPONENT `
        -Tags @('License', 'Trial', 'Expiry')
}

# ============================================================================
# ASSESSOR: Unlicensed Enabled Users
# ============================================================================

function Test-TiTCUnlicensedUsers {
    [CmdletBinding()]
    param(
        [hashtable]$Config,
        [TiTCCollectorResult]$Result
    )

    Write-TiTCLog "Checking for unlicensed enabled accounts..." -Level Info -Component $script:COMPONENT

    # Re-use user data if already retrieved, else fetch a minimal set
    $users = if ($Result.RawData['UsersWithLicenses']) {
        $Result.RawData['UsersWithLicenses']
    } else {
        (Invoke-TiTCGraphRequest `
            -Endpoint '/users' `
            -Select 'id,userPrincipalName,displayName,assignedLicenses,accountEnabled,userType' `
            -Filter "accountEnabled eq true and userType eq 'Member'" `
            -AllPages `
            -Component $script:COMPONENT
        ).value
    }

    $Result.ObjectsScanned += $users.Count

    $unlicensedUsers = $users | Where-Object {
        $_.accountEnabled -eq $true -and
        $_.userType -ne 'Guest' -and
        (-not $_.assignedLicenses -or $_.assignedLicenses.Count -eq 0)
    }

    $Result.RawData['UnlicensedEnabledUsers'] = $unlicensedUsers

    if ($unlicensedUsers.Count -eq 0) {
        Write-TiTCLog "No unlicensed enabled accounts found" -Level Info -Component $script:COMPONENT
        return
    }

    $affectedList = $unlicensedUsers | Select-Object -First 30 -ExpandProperty userPrincipalName

    $Result.Findings += New-TiTCFinding `
        -Title "Enabled User Accounts Without License Assignments ($($unlicensedUsers.Count) accounts)" `
        -Description "$($unlicensedUsers.Count) enabled Member user accounts have no Microsoft 365 licenses assigned. These accounts can still authenticate with Azure AD credentials, access resources controlled by Conditional Access, and may represent incomplete user provisioning, retained accounts for former employees, or service accounts not using the recommended approach." `
        -Severity Low `
        -Domain Licensing `
        -RiskWeight 3 `
        -Remediation "1. Review each unlicensed enabled account. 2. If accounts belong to active employees who need M365 access, assign appropriate licenses. 3. If accounts are for departed employees, disable and schedule for deletion per your retention policy. 4. For service accounts or shared accounts, ensure they are using the correct account type and access controls." `
        -RemediationUrl 'https://learn.microsoft.com/en-us/microsoft-365/admin/add-users/add-users' `
        -ComplianceControls @() `
        -AffectedResources $affectedList `
        -Evidence @{
            UnlicensedCount   = $unlicensedUsers.Count
            TotalMemberUsers  = ($users | Where-Object { $_.userType -ne 'Guest' }).Count
        } `
        -EvidenceQuery "GET /users?`$filter=accountEnabled eq true and userType eq 'Member'" `
        -DetectedBy $script:COMPONENT `
        -Tags @('License', 'Provisioning', 'AccountHygiene')
}

# ============================================================================
# ASSESSOR: License Waste Summary (aggregate)
# ============================================================================

function Test-TiTCLicenseWasteSummary {
    [CmdletBinding()]
    param(
        [hashtable]$Config,
        [TiTCCollectorResult]$Result
    )

    Write-TiTCLog "Generating license waste summary..." -Level Info -Component $script:COMPONENT

    $totalMonthlyWaste = if ($Result.RawData['TotalMonthlyWaste']) {
        $Result.RawData['TotalMonthlyWaste']
    } else { 0.0 }

    # Count duplicate license waste (estimate: 1 redundant license per duplicate user)
    $duplicateUserCount = if ($Result.RawData['DuplicateLicenseUsers']) {
        $Result.RawData['DuplicateLicenseUsers'].Count
    } else { 0 }

    # Count E5 downgrade savings
    $e5DowngradeSavings = 0.0
    if ($Result.RawData['PotentialE5Downgrades']) {
        $e5Price = if ($Config.LicensePricing['Microsoft 365 E5']) { $Config.LicensePricing['Microsoft 365 E5'] } else { 54.75 }
        $e3Price = if ($Config.LicensePricing['Microsoft 365 E3']) { $Config.LicensePricing['Microsoft 365 E3'] } else { 33.00 }
        $e5DowngradeSavings = $Result.RawData['PotentialE5Downgrades'].Count * ($e5Price - $e3Price)
    }

    $totalPotentialSavings = $totalMonthlyWaste + $e5DowngradeSavings
    $annualPotentialSavings = [Math]::Round($totalPotentialSavings * 12, 2)

    $summary = @{
        TotalMonthlyWaste       = [Math]::Round($totalMonthlyWaste, 2)
        TotalAnnualWaste        = [Math]::Round($totalMonthlyWaste * 12, 2)
        E5DowngradeMonthlySaving= [Math]::Round($e5DowngradeSavings, 2)
        TotalPotentialMonthly   = [Math]::Round($totalPotentialSavings, 2)
        TotalPotentialAnnual    = $annualPotentialSavings
        DuplicateLicenseUsers   = $duplicateUserCount
        SKUsWithWaste           = if ($Result.RawData['UnusedLicenseWaste']) { $Result.RawData['UnusedLicenseWaste'].Count } else { 0 }
        TrialSubscriptions      = if ($Result.RawData['TrialSubscriptions'])  { $Result.RawData['TrialSubscriptions'].Count }  else { 0 }
    }

    $Result.RawData['LicenseWasteSummary'] = $summary

    Write-TiTCLog "License waste summary: €$([Math]::Round($totalPotentialSavings, 2))/month potential savings (€$annualPotentialSavings/year)" `
        -Level Info -Component $script:COMPONENT

    # Store total waste on Result for orchestrator to propagate to report
    $Result.RawData['EstimatedMonthlyWaste'] = [Math]::Round($totalPotentialSavings, 2)
}

# ============================================================================
# MODULE EXPORT
# ============================================================================

Export-ModuleMember -Function @('Invoke-TiTCLicensingCollector')
