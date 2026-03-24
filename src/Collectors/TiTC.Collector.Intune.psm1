#Requires -Version 5.1
<#
.SYNOPSIS
    TakeItToCloud.Assess — Intune / Endpoint Security Collector.

.DESCRIPTION
    Performs comprehensive endpoint security checks against Microsoft Intune
    via Graph API. Covers:

    - Device compliance status and policy coverage
    - Compliance policy deployment and platform gaps
    - Device encryption status (BitLocker / FileVault)
    - OS patch levels and Windows Update ring configuration
    - Stale/unsynced device hygiene
    - App protection (MAM) policy coverage for BYOD
    - Security baseline deployment status
    - Critical device configuration profiles

    All checks produce standardized TiTCFinding objects with compliance mappings.

.NOTES
    Module:     TiTC.Collector.Intune
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

$script:COMPONENT = 'Collector.Intune'

# Known current minimum OS versions for compliance checks
$script:MIN_OS_VERSIONS = @{
    'Windows'  = '10.0.19045'   # Windows 10 22H2
    'iOS'      = '17.0'
    'Android'  = '13.0'
    'macOS'    = '14.0'
}

# ============================================================================
# MAIN COLLECTOR ENTRY POINT
# ============================================================================

function Invoke-TiTCIntuneCollector {
    <#
    .SYNOPSIS
        Runs all Intune endpoint security checks and returns a TiTCCollectorResult.

    .DESCRIPTION
        Orchestrates all endpoint security assessors against the connected tenant.
        Each assessor runs independently — a failure in one does not block others.
        Results are aggregated into a single CollectorResult with all findings.

    .PARAMETER Config
        Assessment configuration hashtable from Get-TiTCConfig.

    .PARAMETER Checks
        Specific checks to run. Default runs all checks.
    #>
    [CmdletBinding()]
    [OutputType([PSObject])]
    param(
        [hashtable]$Config = @{},

        [ValidateSet(
            'DeviceCompliance', 'CompliancePolicies', 'EncryptionStatus',
            'OSUpdateCompliance', 'StaleDevices', 'AppProtection',
            'SecurityBaselines', 'DeviceConfigProfiles', 'All'
        )]
        [string[]]$Checks = @('All')
    )

    $result = New-TiTCCollectorResult -Domain Intune
    Write-TiTCLog "Starting Intune endpoint security assessment..." -Level Info -Component $script:COMPONENT

    # Load config defaults if not provided
    if (-not $Config.Thresholds) {
        $Config = Get-TiTCConfig -ProfileName Full
    }

    $runAll = $Checks -contains 'All'

    # ── Assessor dispatch ───────────────────────────────────────────────
    $assessors = [ordered]@{
        'DeviceCompliance'    = { Test-TiTCDeviceCompliance    -Config $Config -Result $result }
        'CompliancePolicies'  = { Test-TiTCCompliancePolicies  -Config $Config -Result $result }
        'EncryptionStatus'    = { Test-TiTCEncryptionStatus     -Config $Config -Result $result }
        'OSUpdateCompliance'  = { Test-TiTCOSUpdateCompliance   -Config $Config -Result $result }
        'StaleDevices'        = { Test-TiTCStaleDevices         -Config $Config -Result $result }
        'AppProtection'       = { Test-TiTCAppProtection        -Config $Config -Result $result }
        'SecurityBaselines'   = { Test-TiTCSecurityBaselines    -Config $Config -Result $result }
        'DeviceConfigProfiles'= { Test-TiTCDeviceConfigProfiles -Config $Config -Result $result }
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
                    $result.Status = 'PartialSuccess'
                }
            }
        }
    }

    $result.Complete()

    $summary = $result.ToSummary()
    Write-TiTCLog "Intune assessment complete" -Level Success -Component $script:COMPONENT -Data $summary

    return $result
}

# ============================================================================
# ASSESSOR: Device Compliance Status
# ============================================================================

function Test-TiTCDeviceCompliance {
    [CmdletBinding()]
    param(
        [hashtable]$Config,
        $Result
    )

    Write-TiTCLog "Checking device compliance status..." -Level Info -Component $script:COMPONENT

    # Get all managed devices
    $devices = (Invoke-TiTCGraphRequest `
        -Endpoint '/deviceManagement/managedDevices' `
        -Select 'id,deviceName,operatingSystem,complianceState,lastSyncDateTime,userPrincipalName,isEncrypted,managementAgent,osVersion' `
        -AllPages `
        -Component $script:COMPONENT
    ).value

    $Result.ObjectsScanned += $devices.Count
    $Result.RawData['ManagedDevices'] = $devices

    if ($devices.Count -eq 0) {
        Write-TiTCLog "No managed devices found — Intune may not be licensed or configured" -Level Warning -Component $script:COMPONENT
        return
    }

    # Get compliance policies for context
    $compliancePolicies = (Invoke-TiTCGraphRequest `
        -Endpoint '/deviceManagement/deviceCompliancePolicies' `
        -AllPages `
        -Component $script:COMPONENT
    ).value

    $Result.RawData['CompliancePolicies'] = $compliancePolicies

    # Calculate compliance
    $nonCompliant = $devices | Where-Object { $_.complianceState -eq 'noncompliant' }
    $compliant    = $devices | Where-Object { $_.complianceState -eq 'compliant' }
    $unknown      = $devices | Where-Object { $_.complianceState -in @('unknown', 'conflict', 'error', 'inGracePeriod') }

    $complianceThreshold = if ($Config.Thresholds.DeviceComplianceTarget) {
        $Config.Thresholds.DeviceComplianceTarget
    } else { 95 }

    $compliantPct = if ($devices.Count -gt 0) {
        [Math]::Round(($compliant.Count / $devices.Count) * 100, 1)
    } else { 100 }

    Write-TiTCLog "Device compliance: $compliantPct% ($($compliant.Count)/$($devices.Count) compliant)" -Level Info -Component $script:COMPONENT

    if ($compliantPct -lt $complianceThreshold) {
        $severity = if ($compliantPct -lt 70) { 'Critical' }
                    elseif ($compliantPct -lt 85) { 'High' }
                    else { 'Medium' }

        $nonCompliantList = $nonCompliant | Select-Object -First 50 | ForEach-Object {
            "$($_.deviceName) ($($_.userPrincipalName)) — $($_.operatingSystem)"
        }

        $Result.Findings += New-TiTCFinding `
            -Title "Device Compliance Below Threshold ($compliantPct%)" `
            -Description "Only $compliantPct% of managed devices ($($compliant.Count) of $($devices.Count)) are compliant with Intune compliance policies. The target threshold is $complianceThreshold%. Non-compliant devices may have unpatched vulnerabilities, missing security controls, or policy violations. $($unknown.Count) additional devices are in an unknown/grace-period state." `
            -Severity $severity `
            -Domain Intune `
            -RiskWeight 8 `
            -Remediation "1. Review non-compliant devices in Intune portal (Devices > Monitor > Noncompliant devices). 2. Investigate root causes (missing encryption, outdated OS, no passcode). 3. Remediate or retire devices unable to achieve compliance. 4. Consider enabling Conditional Access to block non-compliant device access." `
            -RemediationUrl 'https://learn.microsoft.com/en-us/mem/intune/protect/device-compliance-get-started' `
            -ComplianceControls @('ISO27001:A.8.1', 'CIS:3.1.1', 'SOC2:CC6.8', 'NIST:CM-6') `
            -AffectedResources $nonCompliantList `
            -Evidence @{
                TotalDevices        = $devices.Count
                CompliantDevices    = $compliant.Count
                NonCompliantDevices = $nonCompliant.Count
                UnknownDevices      = $unknown.Count
                CompliancePercent   = $compliantPct
                Threshold           = $complianceThreshold
                PolicyCount         = $compliancePolicies.Count
            } `
            -EvidenceQuery 'GET /deviceManagement/managedDevices' `
            -DetectedBy $script:COMPONENT `
            -Tags @('Intune', 'DeviceCompliance', 'EndpointSecurity')
    }

    # Warn if no compliance policies exist at all
    if ($compliancePolicies.Count -eq 0) {
        $Result.Findings += New-TiTCFinding `
            -Title "No Intune Device Compliance Policies Configured" `
            -Description "No device compliance policies were found in Intune. Without compliance policies, devices cannot be evaluated for compliance and cannot be targeted by Conditional Access policies requiring compliant devices. All $($devices.Count) managed devices are unmanaged from a compliance perspective." `
            -Severity Critical `
            -Domain Intune `
            -RiskWeight 9 `
            -Remediation "Create compliance policies for each managed platform (Windows, iOS, Android, macOS) in Microsoft Intune admin center under 'Devices > Compliance policies'. Configure policies to require encryption, minimum OS version, and device passcode at minimum." `
            -RemediationUrl 'https://learn.microsoft.com/en-us/mem/intune/protect/create-compliance-policy' `
            -ComplianceControls @('ISO27001:A.8.1', 'CIS:3.1.1', 'SOC2:CC6.8', 'NIST:CM-6') `
            -AffectedResources @("All $($devices.Count) managed devices") `
            -Evidence @{ DeviceCount = $devices.Count; PolicyCount = 0 } `
            -EvidenceQuery 'GET /deviceManagement/deviceCompliancePolicies' `
            -DetectedBy $script:COMPONENT `
            -Tags @('Intune', 'DeviceCompliance', 'PolicyCoverage', 'EndpointSecurity')
    }
}

# ============================================================================
# ASSESSOR: Compliance Policy Coverage
# ============================================================================

function Test-TiTCCompliancePolicies {
    [CmdletBinding()]
    param(
        [hashtable]$Config,
        $Result
    )

    Write-TiTCLog "Checking compliance policy coverage..." -Level Info -Component $script:COMPONENT

    # Get policies — no $select so @odata.type is included for platform coverage detection
    $policies = (Invoke-TiTCGraphRequest `
        -Endpoint '/deviceManagement/deviceCompliancePolicies' `
        -AllPages `
        -Component $script:COMPONENT
    ).value

    $Result.ObjectsScanned += $policies.Count

    if ($policies.Count -eq 0) {
        # Already handled by DeviceCompliance check
        return
    }

    # Check assignments for each policy
    $unassignedPolicies = [System.Collections.ArrayList]::new()

    foreach ($policy in $policies) {
        try {
            $assignments = (Invoke-TiTCGraphRequest `
                -Endpoint "/deviceManagement/deviceCompliancePolicies/$($policy.id)/assignments" `
                -Component $script:COMPONENT
            ).value

            if (-not $assignments -or $assignments.Count -eq 0) {
                $null = $unassignedPolicies.Add($policy.displayName)
            }
        }
        catch {
            Write-TiTCLog "Could not get assignments for policy '$($policy.displayName)': $_" -Level Debug -Component $script:COMPONENT
        }
    }

    if ($unassignedPolicies.Count -gt 0) {
        $Result.Findings += New-TiTCFinding `
            -Title "Compliance Policies Exist But Are Not Assigned ($($unassignedPolicies.Count) unassigned)" `
            -Description "$($unassignedPolicies.Count) of $($policies.Count) compliance policies have no group assignments and are therefore not enforced. Unassigned policies provide no security benefit and may create a false sense of coverage." `
            -Severity Medium `
            -Domain Intune `
            -RiskWeight 5 `
            -Remediation "In the Intune admin center, navigate to each unassigned policy under 'Devices > Compliance policies' and assign it to the appropriate device groups. Consider assigning to 'All Devices' or 'All Users' if broadly applicable." `
            -RemediationUrl 'https://learn.microsoft.com/en-us/mem/intune/protect/create-compliance-policy#assign-the-policy' `
            -ComplianceControls @('ISO27001:A.8.1', 'NIST:CM-2') `
            -AffectedResources $unassignedPolicies `
            -Evidence @{
                TotalPolicies      = $policies.Count
                UnassignedPolicies = $unassignedPolicies.Count
                PolicyNames        = $unassignedPolicies
            } `
            -EvidenceQuery 'GET /deviceManagement/deviceCompliancePolicies/{id}/assignments' `
            -DetectedBy $script:COMPONENT `
            -Tags @('Intune', 'DeviceCompliance', 'PolicyCoverage')
    }

    # Check for platform coverage gaps
    $platformTypes = @{
        'Windows'  = '#microsoft.graph.windows10CompliancePolicy'
        'iOS'      = '#microsoft.graph.iosCompliancePolicy'
        'Android'  = '#microsoft.graph.androidCompliancePolicy'
        'macOS'    = '#microsoft.graph.macOSCompliancePolicy'
    }

    $coveredPlatforms  = [System.Collections.ArrayList]::new()
    $missingPlatforms  = [System.Collections.ArrayList]::new()

    foreach ($platform in $platformTypes.Keys) {
        $hasPlatform = $policies | Where-Object { $_.'@odata.type' -eq $platformTypes[$platform] }
        if ($hasPlatform) {
            $null = $coveredPlatforms.Add($platform)
        } else {
            $null = $missingPlatforms.Add($platform)
        }
    }

    $Result.RawData['CompliancePolicyCoverage'] = @{
        CoveredPlatforms = $coveredPlatforms
        MissingPlatforms = $missingPlatforms
        UnassignedCount  = $unassignedPolicies.Count
    }

    if ($missingPlatforms.Count -gt 0) {
        $Result.Findings += New-TiTCFinding `
            -Title "Missing Compliance Policies for Platform(s): $($missingPlatforms -join ', ')" `
            -Description "No compliance policies are configured for the following platforms: $($missingPlatforms -join ', '). Devices running these operating systems cannot be evaluated for compliance and are implicitly trusted, bypassing device health requirements in Conditional Access." `
            -Severity Medium `
            -Domain Intune `
            -RiskWeight 6 `
            -Remediation "Create platform-specific compliance policies for each missing platform in Intune admin center > Devices > Compliance policies > + Create policy. At minimum configure: encryption required, minimum OS version, and screen lock/passcode." `
            -RemediationUrl 'https://learn.microsoft.com/en-us/mem/intune/protect/device-compliance-get-started#platform-support' `
            -ComplianceControls @('ISO27001:A.8.1', 'NIST:CM-2') `
            -AffectedResources $missingPlatforms `
            -Evidence @{
                CoveredPlatforms = $coveredPlatforms
                MissingPlatforms = $missingPlatforms
                TotalPolicies    = $policies.Count
            } `
            -EvidenceQuery 'GET /deviceManagement/deviceCompliancePolicies' `
            -DetectedBy $script:COMPONENT `
            -Tags @('Intune', 'DeviceCompliance', 'PolicyCoverage')
    }
}

# ============================================================================
# ASSESSOR: Encryption Status
# ============================================================================

function Test-TiTCEncryptionStatus {
    [CmdletBinding()]
    param(
        [hashtable]$Config,
        $Result
    )

    Write-TiTCLog "Checking device encryption status..." -Level Info -Component $script:COMPONENT

    # Re-use cached device data if available, otherwise fetch
    $devices = if ($Result.RawData['ManagedDevices']) {
        $Result.RawData['ManagedDevices']
    } else {
        (Invoke-TiTCGraphRequest `
            -Endpoint '/deviceManagement/managedDevices' `
            -Select 'id,deviceName,operatingSystem,isEncrypted,userPrincipalName,osVersion' `
            -AllPages `
            -Component $script:COMPONENT
        ).value
    }

    if ($devices.Count -eq 0) { return }

    # Only check platforms where encryption is enforceable via Intune
    $encryptableDevices = $devices | Where-Object {
        $_.operatingSystem -in @('Windows', 'macOS', 'iOS', 'Android')
    }

    $Result.ObjectsScanned += $encryptableDevices.Count

    $unencryptedDevices = $encryptableDevices | Where-Object { $_.isEncrypted -eq $false }

    $Result.RawData['EncryptionStatus'] = @{
        Total       = $encryptableDevices.Count
        Encrypted   = ($encryptableDevices | Where-Object { $_.isEncrypted -eq $true }).Count
        Unencrypted = $unencryptedDevices.Count
    }

    if ($unencryptedDevices.Count -gt 0) {
        $affectedList = $unencryptedDevices | Select-Object -First 50 | ForEach-Object {
            "$($_.deviceName) [$($_.operatingSystem)] — $($_.userPrincipalName)"
        }

        $Result.Findings += New-TiTCFinding `
            -Title "Unencrypted Managed Devices Detected ($($unencryptedDevices.Count) devices)" `
            -Description "$($unencryptedDevices.Count) managed devices do not have disk encryption enabled. Unencrypted devices expose all stored data if the device is lost or stolen, including cached credentials, emails, documents, and browser history. This is a direct data-at-rest protection failure." `
            -Severity High `
            -Domain Intune `
            -RiskWeight 8 `
            -Remediation "1. For Windows: Deploy a BitLocker policy via Intune (Endpoint security > Disk encryption > + Create policy > Windows > BitLocker). 2. For macOS: Deploy a FileVault policy (Endpoint security > Disk encryption > macOS > FileVault). 3. For mobile: Ensure compliance policies require encryption. 4. Add encryption as a compliance policy requirement to block non-encrypted device access." `
            -RemediationUrl 'https://learn.microsoft.com/en-us/mem/intune/protect/encrypt-devices' `
            -RemediationScript @'
# Enable BitLocker via Intune Configuration Profile (reference script)
# Navigate to: Intune admin center > Endpoint security > Disk encryption
# Create a new Windows BitLocker policy with these recommended settings:
# - Require device encryption: Yes
# - BitLocker base settings: Allow/require device encryption
# - BitLocker fixed drive settings: Require encryption for fixed data drives
# - BitLocker OS drive settings: Require encryption for OS drive
# For immediate remediation on a device:
# Enable-BitLocker -MountPoint "C:" -EncryptionMethod XtsAes256 -UsedSpaceOnly -TpmProtector
'@ `
            -ComplianceControls @('ISO27001:A.8.24', 'CIS:3.4.1', 'SOC2:CC6.7', 'NIST:SC-28') `
            -AffectedResources $affectedList `
            -Evidence @{
                TotalEncryptable  = $encryptableDevices.Count
                UnencryptedCount  = $unencryptedDevices.Count
                ByOS = ($unencryptedDevices | Group-Object operatingSystem | Select-Object Name, Count)
            } `
            -EvidenceQuery 'GET /deviceManagement/managedDevices?$select=id,deviceName,operatingSystem,isEncrypted' `
            -DetectedBy $script:COMPONENT `
            -Tags @('Intune', 'Encryption', 'BitLocker')
    }
}

# ============================================================================
# ASSESSOR: OS Update Compliance
# ============================================================================

function Test-TiTCOSUpdateCompliance {
    [CmdletBinding()]
    param(
        [hashtable]$Config,
        $Result
    )

    Write-TiTCLog "Checking OS update compliance and patch management..." -Level Info -Component $script:COMPONENT

    # Re-use cached devices or fetch
    $devices = if ($Result.RawData['ManagedDevices']) {
        $Result.RawData['ManagedDevices']
    } else {
        (Invoke-TiTCGraphRequest `
            -Endpoint '/deviceManagement/managedDevices' `
            -Select 'id,deviceName,operatingSystem,osVersion,userPrincipalName' `
            -AllPages `
            -Component $script:COMPONENT
        ).value
    }

    # Get Windows Update for Business rings (filter client-side — @odata.type not supported in $filter)
    $updateRings = @()
    try {
        $allConfigs = (Invoke-TiTCGraphRequest `
            -Endpoint '/deviceManagement/deviceConfigurations' `
            -Select 'id,displayName' `
            -AllPages `
            -Component $script:COMPONENT
        ).value
        $updateRings = @($allConfigs | Where-Object { $_.'@odata.type' -eq '#microsoft.graph.windowsUpdateForBusinessConfiguration' })
    }
    catch {
        Write-TiTCLog "Could not retrieve Windows Update rings: $_" -Level Debug -Component $script:COMPONENT
    }

    $Result.ObjectsScanned += $devices.Count
    $Result.RawData['WindowsUpdateRings'] = $updateRings

    # Check for outdated OS versions
    $outdatedDevices = [System.Collections.ArrayList]::new()

    foreach ($device in $devices) {
        $minVersion = $script:MIN_OS_VERSIONS[$device.operatingSystem]
        if (-not $minVersion -or -not $device.osVersion) { continue }

        try {
            $deviceVer = [System.Version]$device.osVersion
            $minVer    = [System.Version]$minVersion

            if ($deviceVer -lt $minVer) {
                $null = $outdatedDevices.Add([PSCustomObject]@{
                    DeviceName  = $device.deviceName
                    UPN         = $device.userPrincipalName
                    OS          = $device.operatingSystem
                    Version     = $device.osVersion
                    MinRequired = $minVersion
                })
            }
        }
        catch {
            # Skip devices with non-parseable version strings
        }
    }

    $Result.RawData['OutdatedDevices'] = $outdatedDevices

    if ($outdatedDevices.Count -gt 0) {
        $affectedList = $outdatedDevices | Select-Object -First 50 | ForEach-Object {
            "$($_.DeviceName) [$($_.OS) $($_.Version)] — min required: $($_.MinRequired) — $($_.UPN)"
        }

        $Result.Findings += New-TiTCFinding `
            -Title "Devices Running Outdated OS Versions ($($outdatedDevices.Count) devices)" `
            -Description "$($outdatedDevices.Count) managed devices are running operating system versions below the recommended minimum. Outdated OS versions contain known, publicly-disclosed vulnerabilities that attackers actively exploit. Patch management is a foundational security control." `
            -Severity High `
            -Domain Intune `
            -RiskWeight 7 `
            -Remediation "1. Configure Windows Update for Business rings in Intune to enforce automatic patching (Devices > Windows > Update rings). 2. Set compliance policy minimum OS version requirements to fail non-patched devices. 3. For mobile devices, configure a compliance policy minimum OS version. 4. Review and retire devices that cannot be updated." `
            -RemediationUrl 'https://learn.microsoft.com/en-us/mem/intune/protect/windows-update-for-business-configure' `
            -ComplianceControls @('ISO27001:A.8.8', 'CIS:3.5.1', 'NIST:SI-2') `
            -AffectedResources $affectedList `
            -Evidence @{
                TotalDevices    = $devices.Count
                OutdatedCount   = $outdatedDevices.Count
                ByOS            = ($outdatedDevices | Group-Object OS | Select-Object Name, Count)
                MinOSVersions   = $script:MIN_OS_VERSIONS
            } `
            -EvidenceQuery 'GET /deviceManagement/managedDevices?$select=id,deviceName,operatingSystem,osVersion' `
            -DetectedBy $script:COMPONENT `
            -Tags @('Intune', 'WindowsUpdate', 'PatchManagement')
    }

    # Check if Windows Update rings are configured
    $windowsDevices = $devices | Where-Object { $_.operatingSystem -eq 'Windows' }

    if ($windowsDevices.Count -gt 0 -and $updateRings.Count -eq 0) {
        $Result.Findings += New-TiTCFinding `
            -Title "No Windows Update for Business Rings Configured" `
            -Description "The tenant has $($windowsDevices.Count) Windows devices but no Windows Update for Business (WUfB) configuration rings are deployed via Intune. Without update rings, Windows devices depend entirely on user-initiated updates and Microsoft's default deferral settings, resulting in inconsistent patch levels across the organisation." `
            -Severity Medium `
            -Domain Intune `
            -RiskWeight 6 `
            -Remediation "Configure Windows Update for Business rings in Intune admin center: Devices > Windows > Update rings for Windows 10 and later > + Create profile. Recommended: create a Pilot ring (1-week deferral) and a Production ring (2-week deferral) for quality updates." `
            -RemediationUrl 'https://learn.microsoft.com/en-us/mem/intune/protect/windows-update-for-business-configure' `
            -ComplianceControls @('ISO27001:A.8.8', 'CIS:3.5.1', 'NIST:SI-2') `
            -AffectedResources @("$($windowsDevices.Count) Windows managed devices") `
            -Evidence @{ WindowsDeviceCount = $windowsDevices.Count; UpdateRingsConfigured = 0 } `
            -EvidenceQuery 'GET /deviceManagement/deviceConfigurations?$filter=@odata.type eq windowsUpdateForBusinessConfiguration' `
            -DetectedBy $script:COMPONENT `
            -Tags @('Intune', 'WindowsUpdate', 'PatchManagement')
    }
}

# ============================================================================
# ASSESSOR: Stale Devices
# ============================================================================

function Test-TiTCStaleDevices {
    [CmdletBinding()]
    param(
        [hashtable]$Config,
        $Result
    )

    Write-TiTCLog "Checking for stale/unsynced devices..." -Level Info -Component $script:COMPONENT

    $staleDaysThreshold = if ($Config.Thresholds.StaleDeviceDays) {
        $Config.Thresholds.StaleDeviceDays
    } else { 30 }

    $cutoffDate = (Get-Date).AddDays(-$staleDaysThreshold).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')

    $staleDevices = @()
    try {
        $staleDevices = (Invoke-TiTCGraphRequest `
            -Endpoint '/deviceManagement/managedDevices' `
            -Select 'id,deviceName,operatingSystem,lastSyncDateTime,userPrincipalName,complianceState,managementAgent' `
            -Filter "lastSyncDateTime le $cutoffDate" `
            -AllPages `
            -Component $script:COMPONENT
        ).value
    }
    catch {
        Write-TiTCLog "Filter-based stale device query failed, falling back to in-memory filter: $_" -Level Debug -Component $script:COMPONENT

        # Fallback: use cached devices
        $allDevices = if ($Result.RawData['ManagedDevices']) {
            $Result.RawData['ManagedDevices']
        } else { @() }

        $staleDevices = $allDevices | Where-Object {
            $_.lastSyncDateTime -and
            ([datetime]$_.lastSyncDateTime) -lt (Get-Date).AddDays(-$staleDaysThreshold)
        }
    }

    $Result.ObjectsScanned += $staleDevices.Count
    $Result.RawData['StaleDevices'] = $staleDevices

    if ($staleDevices.Count -gt 0) {
        $affectedList = $staleDevices | Select-Object -First 50 | ForEach-Object {
            $lastSync = if ($_.lastSyncDateTime) { [datetime]$_.lastSyncDateTime | Get-Date -Format 'yyyy-MM-dd' } else { 'Never' }
            "$($_.deviceName) [$($_.operatingSystem)] — last sync: $lastSync — $($_.userPrincipalName)"
        }

        $severity = if ($staleDevices.Count -gt 50) { 'High' } else { 'Medium' }

        $Result.Findings += New-TiTCFinding `
            -Title "Stale Managed Devices Detected ($($staleDevices.Count) not synced in $staleDaysThreshold+ days)" `
            -Description "$($staleDevices.Count) managed devices have not synced with Intune in more than $staleDaysThreshold days. Stale devices: (1) do not receive updated compliance policies or security configurations; (2) cannot be remotely wiped if lost/stolen; (3) may have outdated security baselines; (4) represent uncontrolled endpoints that may still have access to corporate resources." `
            -Severity $severity `
            -Domain Intune `
            -RiskWeight 5 `
            -Remediation "1. Contact users of stale devices to reconnect them to Intune (Company Portal app > Sync). 2. Retire devices that are confirmed lost or reassigned. 3. Enable Conditional Access requiring compliant device to force sync or block access. 4. Consider an auto-retire policy for devices not syncing within X days." `
            -RemediationUrl 'https://learn.microsoft.com/en-us/mem/intune/remote-actions/devices-wipe#retire' `
            -ComplianceControls @('ISO27001:A.8.1', 'NIST:CM-8') `
            -AffectedResources $affectedList `
            -Evidence @{
                StaleCount        = $staleDevices.Count
                ThresholdDays     = $staleDaysThreshold
                ByOS              = ($staleDevices | Group-Object operatingSystem | Select-Object Name, Count)
            } `
            -EvidenceQuery "GET /deviceManagement/managedDevices?`$filter=lastSyncDateTime le $cutoffDate" `
            -DetectedBy $script:COMPONENT `
            -Tags @('Intune', 'StaleDevices', 'Lifecycle')
    }
}

# ============================================================================
# ASSESSOR: App Protection (MAM) Policies
# ============================================================================

function Test-TiTCAppProtection {
    [CmdletBinding()]
    param(
        [hashtable]$Config,
        $Result
    )

    Write-TiTCLog "Checking App Protection (MAM) policy coverage..." -Level Info -Component $script:COMPONENT

    $mamPolicies = @()
    try {
        $mamPolicies = (Invoke-TiTCGraphRequest `
            -Endpoint '/deviceAppManagement/managedAppPolicies' `
            -Select 'id,displayName' `
            -AllPages `
            -Component $script:COMPONENT
        ).value
    }
    catch {
        Write-TiTCLog "Could not retrieve MAM policies: $_" -Level Warning -Component $script:COMPONENT
        return
    }

    $Result.ObjectsScanned += $mamPolicies.Count
    $Result.RawData['MAMPolicies'] = $mamPolicies

    # Check for iOS and Android MAM policies
    $iosPolicies     = $mamPolicies | Where-Object { $_.'@odata.type' -eq '#microsoft.graph.iosManagedAppProtection' }
    $androidPolicies = $mamPolicies | Where-Object { $_.'@odata.type' -eq '#microsoft.graph.androidManagedAppProtection' }

    $missingPlatforms = [System.Collections.ArrayList]::new()
    if (-not $iosPolicies)     { $null = $missingPlatforms.Add('iOS') }
    if (-not $androidPolicies) { $null = $missingPlatforms.Add('Android') }

    $Result.RawData['MAMCoverage'] = @{
        IOSPolicies     = $iosPolicies.Count
        AndroidPolicies = $androidPolicies.Count
        TotalPolicies   = $mamPolicies.Count
        MissingPlatforms= $missingPlatforms
    }

    if ($mamPolicies.Count -eq 0) {
        $Result.Findings += New-TiTCFinding `
            -Title "No App Protection (MAM) Policies Configured" `
            -Description "No Mobile Application Management (MAM) policies are configured in Intune. MAM policies protect corporate data within apps on personal (BYOD) and corporate devices without requiring full device enrollment. Without MAM policies, users can copy corporate data from managed apps (Outlook, Teams, OneDrive) to personal apps or cloud storage with no restrictions." `
            -Severity High `
            -Domain Intune `
            -RiskWeight 7 `
            -Remediation "Create App Protection policies for iOS and Android in Intune admin center: Apps > App protection policies > + Create policy. Configure data transfer restrictions (block copy/paste to unmanaged apps), require PIN, enable encryption, and block save-as to personal storage." `
            -RemediationUrl 'https://learn.microsoft.com/en-us/mem/intune/apps/app-protection-policies' `
            -ComplianceControls @('ISO27001:A.8.1', 'NIST:AC-19') `
            -AffectedResources @('iOS devices', 'Android devices') `
            -Evidence @{ TotalMAMPolicies = 0 } `
            -EvidenceQuery 'GET /deviceAppManagement/managedAppPolicies' `
            -DetectedBy $script:COMPONENT `
            -Tags @('Intune', 'MAM', 'AppProtection')
    }
    elseif ($missingPlatforms.Count -gt 0) {
        $Result.Findings += New-TiTCFinding `
            -Title "App Protection Policies Missing for Platform(s): $($missingPlatforms -join ', ')" `
            -Description "App Protection (MAM) policies are not configured for the following mobile platforms: $($missingPlatforms -join ', '). BYOD users on these platforms can access corporate apps (Outlook, Teams, OneDrive) without data-loss-prevention controls. Corporate data may be copied to personal apps or cloud storage." `
            -Severity Medium `
            -Domain Intune `
            -RiskWeight 6 `
            -Remediation "Create App Protection policies for the missing platforms in Intune admin center: Apps > App protection policies > + Create policy. Ensure iOS and Android policies both exist and are assigned to appropriate user groups." `
            -RemediationUrl 'https://learn.microsoft.com/en-us/mem/intune/apps/app-protection-policies' `
            -ComplianceControls @('ISO27001:A.8.1', 'NIST:AC-19') `
            -AffectedResources $missingPlatforms `
            -Evidence @{
                IOSPolicies     = $iosPolicies.Count
                AndroidPolicies = $androidPolicies.Count
                MissingPlatforms= $missingPlatforms
            } `
            -EvidenceQuery 'GET /deviceAppManagement/managedAppPolicies' `
            -DetectedBy $script:COMPONENT `
            -Tags @('Intune', 'MAM', 'AppProtection')
    }

    # Check for unassigned MAM policies
    $unassignedMAM = $mamPolicies | Where-Object { $_.isAssigned -eq $false }
    if ($unassignedMAM.Count -gt 0) {
        $Result.Findings += New-TiTCFinding `
            -Title "App Protection Policies Not Assigned ($($unassignedMAM.Count) unassigned)" `
            -Description "$($unassignedMAM.Count) App Protection policies exist but are not assigned to any users or groups. These policies provide no protection until assigned." `
            -Severity Low `
            -Domain Intune `
            -RiskWeight 3 `
            -Remediation "Assign the unassigned App Protection policies to the relevant user groups in Intune admin center: Apps > App protection policies > [select policy] > Assignments." `
            -RemediationUrl 'https://learn.microsoft.com/en-us/mem/intune/apps/app-protection-policies#assign-app-protection-policies' `
            -ComplianceControls @('ISO27001:A.8.1', 'NIST:AC-19') `
            -AffectedResources ($unassignedMAM | ForEach-Object { $_.displayName }) `
            -Evidence @{ UnassignedCount = $unassignedMAM.Count } `
            -EvidenceQuery 'GET /deviceAppManagement/managedAppPolicies' `
            -DetectedBy $script:COMPONENT `
            -Tags @('Intune', 'MAM', 'AppProtection')
    }
}

# ============================================================================
# ASSESSOR: Security Baselines
# ============================================================================

function Test-TiTCSecurityBaselines {
    [CmdletBinding()]
    param(
        [hashtable]$Config,
        $Result
    )

    Write-TiTCLog "Checking security baseline deployment..." -Level Info -Component $script:COMPONENT

    $baselines = @()
    try {
        # Security baselines are in the beta endpoint under intents
        $baselines = (Invoke-TiTCGraphRequest `
            -Endpoint '/deviceManagement/intents' `
            -Select 'id,displayName,isAssigned,templateId' `
            -AllPages `
            -Beta `
            -Component $script:COMPONENT
        ).value

        # Filter to known security baseline template IDs
        # These are the well-known security baseline template identifiers
        $baselineKeywords = @('Security Baseline', 'Windows Security Baseline', 'Microsoft 365 Apps Baseline',
                              'Edge Security Baseline', 'Defender for Endpoint Baseline', 'Windows 365 Security Baseline')

        $securityBaselines = $baselines | Where-Object {
            $name = $_.displayName
            $baselineKeywords | Where-Object { $name -like "*$_*" }
        }

        if ($securityBaselines.Count -eq 0) {
            # Broader check — look for any baseline-type intents
            $securityBaselines = $baselines | Where-Object {
                $_.displayName -match 'baseline|hardening|security'
            }
        }

        $Result.ObjectsScanned += $baselines.Count
        $Result.RawData['SecurityBaselines'] = $securityBaselines
    }
    catch {
        Write-TiTCLog "Could not retrieve security baselines (beta API): $_" -Level Warning -Component $script:COMPONENT

        # Fallback: check deviceConfigurations for security baseline profiles
        try {
            $configs = (Invoke-TiTCGraphRequest `
                -Endpoint '/deviceManagement/deviceConfigurations' `
                -Select 'id,displayName' `
                -AllPages `
                -Component $script:COMPONENT
            ).value

            $securityBaselines = $configs | Where-Object { $_.displayName -match 'baseline|hardening' }
            $Result.ObjectsScanned += $configs.Count
            $Result.RawData['SecurityBaselines'] = $securityBaselines
        }
        catch {
            Write-TiTCLog "Fallback baseline check also failed: $_" -Level Debug -Component $script:COMPONENT
            return
        }
    }

    if (-not $Result.RawData['SecurityBaselines'] -or $Result.RawData['SecurityBaselines'].Count -eq 0) {
        # Get Windows device count for context
        $windowsDeviceCount = 0
        if ($Result.RawData['ManagedDevices']) {
            $windowsDeviceCount = ($Result.RawData['ManagedDevices'] | Where-Object { $_.operatingSystem -eq 'Windows' }).Count
        }

        $Result.Findings += New-TiTCFinding `
            -Title "No Security Baselines Deployed in Intune" `
            -Description "No Microsoft Security Baselines have been deployed via Intune. Security baselines are pre-configured groups of Windows settings that help apply and enforce security best practices recommended by Microsoft security teams. Without baselines, device security settings must be configured manually across hundreds of individual policies, increasing the risk of misconfiguration." `
            -Severity Medium `
            -Domain Intune `
            -RiskWeight 6 `
            -Remediation "Deploy the Windows Security Baseline in Intune admin center: Endpoint security > Security baselines > Windows Security Baseline > + Create profile. Start with a pilot group before broad deployment. Also consider the Microsoft 365 Apps for Enterprise Security Baseline and Microsoft Defender for Endpoint baseline." `
            -RemediationUrl 'https://learn.microsoft.com/en-us/mem/intune/protect/security-baselines' `
            -ComplianceControls @('ISO27001:A.8.9', 'CIS:3.1.1', 'NIST:CM-6') `
            -AffectedResources @("$windowsDeviceCount Windows managed devices") `
            -Evidence @{
                BaselinesFound       = 0
                WindowsDeviceCount   = $windowsDeviceCount
            } `
            -EvidenceQuery 'GET /deviceManagement/intents (beta)' `
            -DetectedBy $script:COMPONENT `
            -Tags @('Intune', 'SecurityBaseline', 'Configuration')
    }
    else {
        # Check for unassigned baselines
        $unassignedBaselines = $Result.RawData['SecurityBaselines'] | Where-Object { $_.isAssigned -eq $false }

        if ($unassignedBaselines.Count -gt 0) {
            $Result.Findings += New-TiTCFinding `
                -Title "Security Baselines Exist But Not Assigned ($($unassignedBaselines.Count))" `
                -Description "$($unassignedBaselines.Count) security baselines are configured but not assigned to device groups. These baselines have no effect until assigned." `
                -Severity Low `
                -Domain Intune `
                -RiskWeight 3 `
                -Remediation "Assign the security baselines to device groups in Intune admin center: Endpoint security > Security baselines > [baseline] > Profiles > [profile] > Assignments." `
                -RemediationUrl 'https://learn.microsoft.com/en-us/mem/intune/protect/security-baselines-configure' `
                -ComplianceControls @('ISO27001:A.8.9', 'CIS:3.1.1', 'NIST:CM-6') `
                -AffectedResources ($unassignedBaselines | ForEach-Object { $_.displayName }) `
                -Evidence @{ UnassignedCount = $unassignedBaselines.Count } `
                -EvidenceQuery 'GET /deviceManagement/intents (beta)' `
                -DetectedBy $script:COMPONENT `
                -Tags @('Intune', 'SecurityBaseline', 'Configuration')
        }
    }
}

# ============================================================================
# ASSESSOR: Device Configuration Profiles
# ============================================================================

function Test-TiTCDeviceConfigProfiles {
    [CmdletBinding()]
    param(
        [hashtable]$Config,
        $Result
    )

    Write-TiTCLog "Checking critical device configuration profiles..." -Level Info -Component $script:COMPONENT

    $configProfiles = @()
    try {
        $configProfiles = (Invoke-TiTCGraphRequest `
            -Endpoint '/deviceManagement/deviceConfigurations' `
            -Select 'id,displayName,lastModifiedDateTime' `
            -AllPages `
            -Component $script:COMPONENT
        ).value
    }
    catch {
        Write-TiTCLog "Could not retrieve device configuration profiles: $_" -Level Warning -Component $script:COMPONENT
        return
    }

    $Result.ObjectsScanned += $configProfiles.Count
    $Result.RawData['DeviceConfigProfiles'] = $configProfiles

    # Define critical profile categories to look for (by keyword in name or type)
    $criticalProfileChecks = [ordered]@{
        'BitLocker / Disk Encryption' = {
            param($profiles)
            $profiles | Where-Object {
                $_.displayName -match 'bitlocker|encrypt|filevault' -or
                $_.'@odata.type' -in @(
                    '#microsoft.graph.windows10EndpointProtectionConfiguration',
                    '#microsoft.graph.macOSEndpointProtectionConfiguration'
                )
            }
        }
        'Firewall' = {
            param($profiles)
            $profiles | Where-Object {
                $_.displayName -match 'firewall' -or
                $_.'@odata.type' -eq '#microsoft.graph.windows10EndpointProtectionConfiguration'
            }
        }
        'Antivirus / Defender' = {
            param($profiles)
            $profiles | Where-Object {
                $_.displayName -match 'antivirus|defender|malware' -or
                $_.'@odata.type' -eq '#microsoft.graph.windows10EndpointProtectionConfiguration'
            }
        }
        'Windows Hello for Business' = {
            param($profiles)
            $profiles | Where-Object {
                $_.displayName -match 'windows hello|hello for business|WHfB' -or
                $_.'@odata.type' -eq '#microsoft.graph.windowsIdentityProtectionConfiguration'
            }
        }
    }

    $missingCriticalProfiles = [System.Collections.ArrayList]::new()
    $profileCoverage = @{}

    foreach ($profileType in $criticalProfileChecks.Keys) {
        $found = & $criticalProfileChecks[$profileType] $configProfiles
        $profileCoverage[$profileType] = $found.Count -gt 0

        if (-not $found -or $found.Count -eq 0) {
            $null = $missingCriticalProfiles.Add($profileType)
        }
    }

    $Result.RawData['CriticalProfileCoverage'] = $profileCoverage

    if ($missingCriticalProfiles.Count -gt 0) {
        $severity = if ($missingCriticalProfiles.Count -ge 3) { 'High' }
                    elseif ($missingCriticalProfiles.Count -ge 2) { 'Medium' }
                    else { 'Low' }

        $Result.Findings += New-TiTCFinding `
            -Title "Critical Device Configuration Profiles Not Detected ($($missingCriticalProfiles.Count) missing)" `
            -Description "The following critical device configuration profile categories were not detected in Intune: $($missingCriticalProfiles -join ', '). These profiles enforce foundational security controls across managed devices. Their absence suggests devices may lack consistent security hardening and key endpoint protections." `
            -Severity $severity `
            -Domain Intune `
            -RiskWeight 6 `
            -Remediation "Create device configuration profiles for the missing categories in Intune admin center: Devices > Configuration profiles > + Create profile. Priority order: (1) BitLocker/Encryption (Endpoint security > Disk encryption), (2) Defender Antivirus (Endpoint security > Antivirus), (3) Firewall (Endpoint security > Firewall), (4) Windows Hello for Business (Devices > Configuration > Settings catalog)." `
            -RemediationUrl 'https://learn.microsoft.com/en-us/mem/intune/configuration/device-profiles' `
            -ComplianceControls @('ISO27001:A.8.1', 'NIST:CM-6') `
            -AffectedResources $missingCriticalProfiles `
            -Evidence @{
                TotalProfiles           = $configProfiles.Count
                MissingCriticalProfiles = $missingCriticalProfiles
                ProfileCoverage         = $profileCoverage
            } `
            -EvidenceQuery 'GET /deviceManagement/deviceConfigurations' `
            -DetectedBy $script:COMPONENT `
            -Tags @('Intune', 'DeviceConfiguration', 'EndpointSecurity')
    }
}

# ============================================================================
# MODULE EXPORT
# ============================================================================

Export-ModuleMember -Function @('Invoke-TiTCIntuneCollector')
