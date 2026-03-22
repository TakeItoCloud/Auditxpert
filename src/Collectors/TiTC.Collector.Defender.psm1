#Requires -Version 5.1
<#
.SYNOPSIS
    TakeItToCloud.Assess — Microsoft Defender Security Collector.

.DESCRIPTION
    Performs comprehensive Microsoft Defender security posture checks via
    Graph Security API. Covers:

    - Microsoft Secure Score analysis and improvement actions
    - Open security alerts by severity and age
    - Active incident analysis
    - Defender for Endpoint device onboarding coverage
    - Email threat protection preset policy status
    - Attack simulation training activity
    - Automated Investigation and Response (AIR) configuration

    All checks produce standardized TiTCFinding objects with compliance mappings.

.NOTES
    Module:     TiTC.Collector.Defender
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

$script:COMPONENT = 'Collector.Defender'

# ============================================================================
# MAIN COLLECTOR ENTRY POINT
# ============================================================================

function Invoke-TiTCDefenderCollector {
    <#
    .SYNOPSIS
        Runs all Microsoft Defender security checks and returns a TiTCCollectorResult.

    .DESCRIPTION
        Orchestrates all Defender security assessors against the connected tenant.
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
            'SecureScore', 'SecurityAlerts', 'Incidents',
            'DefenderForEndpointCoverage', 'EmailThreatPolicies',
            'AttackSimulation', 'AutoInvestigation', 'All'
        )]
        [string[]]$Checks = @('All')
    )

    $result = New-TiTCCollectorResult -Domain Defender
    Write-TiTCLog "Starting Microsoft Defender security assessment..." -Level Info -Component $script:COMPONENT

    if (-not $Config.Thresholds) {
        $Config = Get-TiTCConfig -ProfileName Full
    }

    $runAll = $Checks -contains 'All'

    # ── Assessor dispatch ───────────────────────────────────────────────
    $assessors = [ordered]@{
        'SecureScore'                 = { Test-TiTCSecureScore                 -Config $Config -Result $result }
        'SecurityAlerts'              = { Test-TiTCSecurityAlerts               -Config $Config -Result $result }
        'Incidents'                   = { Test-TiTCIncidents                    -Config $Config -Result $result }
        'DefenderForEndpointCoverage' = { Test-TiTCDefenderForEndpointCoverage  -Config $Config -Result $result }
        'EmailThreatPolicies'         = { Test-TiTCEmailThreatPolicies          -Config $Config -Result $result }
        'AttackSimulation'            = { Test-TiTCAttackSimulation             -Config $Config -Result $result }
        'AutoInvestigation'           = { Test-TiTCAutoInvestigation            -Config $Config -Result $result }
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
    Write-TiTCLog "Defender assessment complete" -Level Success -Component $script:COMPONENT -Data $summary

    return $result
}

# ============================================================================
# ASSESSOR: Microsoft Secure Score
# ============================================================================

function Test-TiTCSecureScore {
    [CmdletBinding()]
    param(
        [hashtable]$Config,
        [TiTCCollectorResult]$Result
    )

    Write-TiTCLog "Checking Microsoft Secure Score..." -Level Info -Component $script:COMPONENT

    # Get the most recent Secure Score
    $scoreData = $null
    try {
        $scoreData = (Invoke-TiTCGraphRequest `
            -Endpoint '/security/secureScores' `
            -Select 'id,currentScore,maxScore,averageComparativeScores,createdDateTime,enabledServices' `
            -Component $script:COMPONENT
        ).value | Select-Object -First 1
    }
    catch {
        Write-TiTCLog "Could not retrieve Secure Score: $_" -Level Warning -Component $script:COMPONENT
        return
    }

    if (-not $scoreData) {
        Write-TiTCLog "No Secure Score data returned" -Level Warning -Component $script:COMPONENT
        return
    }

    $Result.ObjectsScanned += 1
    $Result.RawData['SecureScore'] = $scoreData

    $currentScore = $scoreData.currentScore
    $maxScore     = $scoreData.maxScore
    $percentage   = if ($maxScore -gt 0) { [Math]::Round(($currentScore / $maxScore) * 100, 1) } else { 0 }

    Write-TiTCLog "Secure Score: $currentScore / $maxScore ($percentage%)" -Level Info -Component $script:COMPONENT

    # Get improvement actions (control profiles) sorted by score impact
    $controlProfiles = @()
    try {
        $controlProfiles = (Invoke-TiTCGraphRequest `
            -Endpoint '/security/secureScoreControlProfiles' `
            -Select 'id,title,maxScore,implementationCost,threats,tier,rank' `
            -AllPages `
            -Component $script:COMPONENT
        ).value | Sort-Object rank | Select-Object -First 20
    }
    catch {
        Write-TiTCLog "Could not retrieve Secure Score control profiles: $_" -Level Debug -Component $script:COMPONENT
    }

    $Result.RawData['SecureScoreControlProfiles'] = $controlProfiles

    if ($percentage -lt 60) {
        $severity = if ($percentage -lt 40) { 'High' } else { 'Medium' }

        $topActions = $controlProfiles | Select-Object -First 10 | ForEach-Object {
            "$($_.title) (max: +$($_.maxScore) pts)"
        }

        $Result.Findings += New-TiTCFinding `
            -Title "Microsoft Secure Score Below Threshold ($percentage%)" `
            -Description "The tenant's Microsoft Secure Score is $currentScore out of a maximum $maxScore points ($percentage%). This score measures security posture across identity, devices, apps, and data. A score below 60% indicates significant unaddressed security improvements. The tenant is below the recommended security baseline." `
            -Severity $severity `
            -Domain Defender `
            -RiskWeight 7 `
            -Remediation "Review and action the Microsoft Secure Score improvement actions in the Microsoft Defender portal (security.microsoft.com > Secure Score > Recommended actions). Prioritise actions with high point value and low implementation cost. Top recommended actions for this tenant are listed in the evidence section." `
            -RemediationUrl 'https://learn.microsoft.com/en-us/microsoft-365/security/defender/microsoft-secure-score' `
            -ComplianceControls @('ISO27001:A.5.1', 'NIST:CA-2') `
            -AffectedResources $topActions `
            -Evidence @{
                CurrentScore    = $currentScore
                MaxScore        = $maxScore
                Percentage      = $percentage
                TopImprovements = $topActions
                RetrievedAt     = $scoreData.createdDateTime
            } `
            -EvidenceQuery 'GET /security/secureScores' `
            -DetectedBy $script:COMPONENT `
            -Tags @('SecureScore', 'SecurityPosture')
    }
}

# ============================================================================
# ASSESSOR: Open Security Alerts
# ============================================================================

function Test-TiTCSecurityAlerts {
    [CmdletBinding()]
    param(
        [hashtable]$Config,
        [TiTCCollectorResult]$Result
    )

    Write-TiTCLog "Checking open security alerts..." -Level Info -Component $script:COMPONENT

    $openAlerts = @()
    try {
        $openAlerts = (Invoke-TiTCGraphRequest `
            -Endpoint '/security/alerts_v2' `
            -Select 'id,title,severity,status,createdDateTime,classification,serviceSource,detectorId' `
            -Filter "status ne 'resolved'" `
            -AllPages `
            -Component $script:COMPONENT
        ).value
    }
    catch {
        Write-TiTCLog "Could not retrieve security alerts: $_" -Level Warning -Component $script:COMPONENT
        return
    }

    $Result.ObjectsScanned += $openAlerts.Count
    $Result.RawData['OpenAlerts'] = $openAlerts

    if ($openAlerts.Count -eq 0) {
        Write-TiTCLog "No open security alerts found" -Level Info -Component $script:COMPONENT
        return
    }

    $cutoff48h = (Get-Date).ToUniversalTime().AddHours(-48)

    $criticalAlerts = $openAlerts | Where-Object { $_.severity -eq 'high' -or $_.severity -eq 'critical' }
    $staleAlerts    = $openAlerts | Where-Object {
        $_.createdDateTime -and ([datetime]$_.createdDateTime) -lt $cutoff48h
    }
    $staleCritical  = $staleAlerts | Where-Object { $_.severity -eq 'high' -or $_.severity -eq 'critical' }

    $alertsBySeverity = $openAlerts | Group-Object severity | Select-Object Name, Count

    Write-TiTCLog "Open alerts: $($openAlerts.Count) total, $($criticalAlerts.Count) high/critical" -Level Info -Component $script:COMPONENT

    if ($staleCritical.Count -gt 0) {
        $affectedList = $staleCritical | Select-Object -First 20 | ForEach-Object {
            $age = if ($_.createdDateTime) { [Math]::Round(((Get-Date) - [datetime]$_.createdDateTime).TotalHours, 0) } else { 'unknown' }
            "$($_.title) — severity: $($_.severity) — age: $($age)h — source: $($_.serviceSource)"
        }

        $severity = if (($staleCritical | Where-Object { $_.severity -eq 'critical' }).Count -gt 0) { 'Critical' } else { 'High' }

        $Result.Findings += New-TiTCFinding `
            -Title "Unresolved High/Critical Security Alerts Older Than 48 Hours ($($staleCritical.Count) alerts)" `
            -Description "$($staleCritical.Count) high or critical severity security alerts have been open for more than 48 hours without resolution. Active critical alerts indicate ongoing or uncontained threats. Delayed response significantly increases the risk of a security incident escalating to a breach. Total open alerts across all severities: $($openAlerts.Count)." `
            -Severity $severity `
            -Domain Defender `
            -RiskWeight 9 `
            -Remediation "1. Immediately triage all high/critical alerts in Microsoft Defender portal (security.microsoft.com > Incidents & alerts > Alerts). 2. Investigate alerts for true positives and initiate incident response procedures. 3. Classify false positives and suppress recurring false positive alert rules. 4. Establish SLA targets: critical alerts within 4h, high within 24h." `
            -RemediationUrl 'https://learn.microsoft.com/en-us/microsoft-365/security/defender/investigate-alerts' `
            -ComplianceControls @('ISO27001:A.5.24', 'SOC2:CC7.2', 'NIST:IR-4') `
            -AffectedResources $affectedList `
            -Evidence @{
                TotalOpenAlerts     = $openAlerts.Count
                HighCriticalAlerts  = $criticalAlerts.Count
                StaleAlerts         = $staleAlerts.Count
                StaleCritical       = $staleCritical.Count
                BySeverity          = $alertsBySeverity
                ThresholdHours      = 48
            } `
            -EvidenceQuery "GET /security/alerts_v2?`$filter=status ne 'resolved'" `
            -DetectedBy $script:COMPONENT `
            -Tags @('Alerts', 'ThreatDetection', 'IncidentResponse')
    }
    elseif ($criticalAlerts.Count -gt 0) {
        $affectedList = $criticalAlerts | Select-Object -First 20 | ForEach-Object {
            "$($_.title) — severity: $($_.severity) — source: $($_.serviceSource)"
        }

        $Result.Findings += New-TiTCFinding `
            -Title "Open High/Critical Security Alerts Require Attention ($($criticalAlerts.Count) alerts)" `
            -Description "$($criticalAlerts.Count) high or critical severity security alerts are currently open. While these are within the 48-hour response window, they require immediate triage to prevent escalation. Total open alerts: $($openAlerts.Count)." `
            -Severity High `
            -Domain Defender `
            -RiskWeight 7 `
            -Remediation "Triage and investigate all high/critical alerts in Microsoft Defender portal. Classify as true positive (begin incident response) or false positive (suppress the rule). Target resolution within 24 hours for high, 4 hours for critical." `
            -RemediationUrl 'https://learn.microsoft.com/en-us/microsoft-365/security/defender/investigate-alerts' `
            -ComplianceControls @('ISO27001:A.5.24', 'SOC2:CC7.2', 'NIST:IR-4') `
            -AffectedResources $affectedList `
            -Evidence @{
                TotalOpenAlerts    = $openAlerts.Count
                HighCriticalAlerts = $criticalAlerts.Count
                BySeverity         = $alertsBySeverity
            } `
            -EvidenceQuery "GET /security/alerts_v2?`$filter=status ne 'resolved'" `
            -DetectedBy $script:COMPONENT `
            -Tags @('Alerts', 'ThreatDetection', 'IncidentResponse')
    }
}

# ============================================================================
# ASSESSOR: Active Security Incidents
# ============================================================================

function Test-TiTCIncidents {
    [CmdletBinding()]
    param(
        [hashtable]$Config,
        [TiTCCollectorResult]$Result
    )

    Write-TiTCLog "Checking active security incidents..." -Level Info -Component $script:COMPONENT

    $activeIncidents = @()
    try {
        $activeIncidents = (Invoke-TiTCGraphRequest `
            -Endpoint '/security/incidents' `
            -Select 'id,displayName,severity,status,createdDateTime,lastUpdateDateTime,classification,determination' `
            -Filter "status ne 'resolved'" `
            -AllPages `
            -Component $script:COMPONENT
        ).value
    }
    catch {
        Write-TiTCLog "Could not retrieve incidents: $_" -Level Warning -Component $script:COMPONENT
        return
    }

    $Result.ObjectsScanned += $activeIncidents.Count
    $Result.RawData['ActiveIncidents'] = $activeIncidents

    if ($activeIncidents.Count -eq 0) {
        Write-TiTCLog "No active security incidents found" -Level Info -Component $script:COMPONENT
        return
    }

    $highCriticalIncidents = $activeIncidents | Where-Object { $_.severity -in @('high', 'critical') }
    $incidentsBySeverity   = $activeIncidents | Group-Object severity | Select-Object Name, Count

    $severity = if (($activeIncidents | Where-Object { $_.severity -eq 'critical' }).Count -gt 0) { 'Critical' }
                elseif ($highCriticalIncidents.Count -gt 0) { 'High' }
                else { 'Medium' }

    $affectedList = $activeIncidents | Select-Object -First 20 | ForEach-Object {
        $age = if ($_.createdDateTime) { [Math]::Round(((Get-Date) - [datetime]$_.createdDateTime).TotalHours, 0) } else { 'unknown' }
        "$($_.displayName) — severity: $($_.severity) — status: $($_.status) — age: $($age)h"
    }

    $Result.Findings += New-TiTCFinding `
        -Title "Active Security Incidents Require Investigation ($($activeIncidents.Count) open)" `
        -Description "$($activeIncidents.Count) security incidents are currently active and unresolved in the tenant. Security incidents represent correlated groups of related alerts indicating a coordinated attack or threat campaign. $($highCriticalIncidents.Count) incidents are high or critical severity. Active incidents require immediate investigation and coordinated response." `
        -Severity $severity `
        -Domain Defender `
        -RiskWeight 9 `
        -Remediation "1. Access the incident queue in Microsoft Defender portal (security.microsoft.com > Incidents). 2. Assign incidents to security analysts for investigation. 3. Follow the incident investigation guide to determine scope, affected assets, and attacker techniques. 4. Initiate containment and eradication procedures for confirmed incidents." `
        -RemediationUrl 'https://learn.microsoft.com/en-us/microsoft-365/security/defender/incidents-overview' `
        -ComplianceControls @('ISO27001:A.5.24', 'NIST:IR-4') `
        -AffectedResources $affectedList `
        -Evidence @{
            TotalActiveIncidents = $activeIncidents.Count
            HighCritical         = $highCriticalIncidents.Count
            BySeverity           = $incidentsBySeverity
        } `
        -EvidenceQuery "GET /security/incidents?`$filter=status ne 'resolved'" `
        -DetectedBy $script:COMPONENT `
        -Tags @('Incidents', 'ThreatDetection')
}

# ============================================================================
# ASSESSOR: Defender for Endpoint Coverage
# ============================================================================

function Test-TiTCDefenderForEndpointCoverage {
    [CmdletBinding()]
    param(
        [hashtable]$Config,
        [TiTCCollectorResult]$Result
    )

    Write-TiTCLog "Checking Defender for Endpoint device onboarding coverage..." -Level Info -Component $script:COMPONENT

    # Get managed devices — check for Defender sensor health via managementAgent
    $managedDevices = @()
    try {
        $managedDevices = (Invoke-TiTCGraphRequest `
            -Endpoint '/deviceManagement/managedDevices' `
            -Select 'id,deviceName,operatingSystem,managementAgent,isSupervised,userPrincipalName' `
            -Filter "operatingSystem eq 'Windows'" `
            -AllPages `
            -Component $script:COMPONENT
        ).value
    }
    catch {
        Write-TiTCLog "Could not retrieve managed devices for Defender coverage check: $_" -Level Warning -Component $script:COMPONENT
        return
    }

    $Result.ObjectsScanned += $managedDevices.Count
    $Result.RawData['WindowsManagedDevices'] = $managedDevices

    if ($managedDevices.Count -eq 0) {
        Write-TiTCLog "No Windows managed devices found — skipping Defender coverage check" -Level Info -Component $script:COMPONENT
        return
    }

    # Devices with 'mdm' or 'easMdm' management agents should have Defender onboarded via Intune
    # Devices with 'configurationManagerClientMdm' or 'configurationManagerClient' are co-managed
    $mfgOnboardedAgents = @('mdm', 'easMdm', 'configurationManagerClientMdm', 'intuneClient')
    $onboardedDevices   = $managedDevices | Where-Object { $_.managementAgent -in $mfgOnboardedAgents }
    $notOnboarded       = $managedDevices | Where-Object { $_.managementAgent -notin $mfgOnboardedAgents }

    # Additional check via security alerts for device coverage
    $devicesWithAlerts = @()
    try {
        $recentAlerts = (Invoke-TiTCGraphRequest `
            -Endpoint '/security/alerts_v2' `
            -Select 'id,deviceDnsName' `
            -Filter "serviceSource eq 'microsoftDefenderForEndpoint'" `
            -Component $script:COMPONENT
        ).value

        $devicesWithAlerts = $recentAlerts | Where-Object { $_.deviceDnsName } |
            Select-Object -ExpandProperty deviceDnsName -Unique
    }
    catch {
        Write-TiTCLog "Could not cross-reference Defender alerts for device coverage: $_" -Level Debug -Component $script:COMPONENT
    }

    $Result.RawData['DefenderCoverage'] = @{
        TotalWindowsDevices = $managedDevices.Count
        LikelyOnboarded     = $onboardedDevices.Count
        PossiblyNotOnboarded= $notOnboarded.Count
        DevicesWithAlerts   = $devicesWithAlerts.Count
    }

    if ($notOnboarded.Count -gt 0) {
        $affectedList = $notOnboarded | Select-Object -First 30 | ForEach-Object {
            "$($_.deviceName) [agent: $($_.managementAgent)] — $($_.userPrincipalName)"
        }

        $Result.Findings += New-TiTCFinding `
            -Title "Windows Devices May Not Be Onboarded to Defender for Endpoint ($($notOnboarded.Count) devices)" `
            -Description "$($notOnboarded.Count) of $($managedDevices.Count) Windows managed devices have management agent types that suggest they may not be fully onboarded to Microsoft Defender for Endpoint. Devices not onboarded lack EDR (Endpoint Detection and Response) capabilities including advanced threat hunting, automated investigation, and device isolation." `
            -Severity High `
            -Domain Defender `
            -RiskWeight 8 `
            -Remediation "1. Onboard devices to Defender for Endpoint via Intune: Endpoint security > Endpoint detection and response > + Create policy (Windows 10, 11 and Server). 2. For co-managed devices, configure the Endpoint Protection workload in Configuration Manager. 3. Verify onboarding status in Defender portal: Settings > Endpoints > Device inventory." `
            -RemediationUrl 'https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/onboard-configure' `
            -ComplianceControls @('ISO27001:A.8.7', 'CIS:4.1.1', 'NIST:SI-3') `
            -AffectedResources $affectedList `
            -Evidence @{
                TotalWindowsDevices   = $managedDevices.Count
                LikelyOnboarded       = $onboardedDevices.Count
                PossiblyNotOnboarded  = $notOnboarded.Count
                DevicesReportingAlerts= $devicesWithAlerts.Count
            } `
            -EvidenceQuery "GET /deviceManagement/managedDevices?`$filter=operatingSystem eq 'Windows'" `
            -DetectedBy $script:COMPONENT `
            -Tags @('DefenderForEndpoint', 'EndpointSecurity', 'Onboarding')
    }
}

# ============================================================================
# ASSESSOR: Email Threat Protection Policies
# ============================================================================

function Test-TiTCEmailThreatPolicies {
    [CmdletBinding()]
    param(
        [hashtable]$Config,
        [TiTCCollectorResult]$Result
    )

    Write-TiTCLog "Checking email threat protection policy configuration..." -Level Info -Component $script:COMPONENT

    # Check preset security policies via beta API
    $presetPolicies = @()
    try {
        $presetPolicies = (Invoke-TiTCGraphRequest `
            -Endpoint '/security/collaboration/presetSecurityPolicies' `
            -Component $script:COMPONENT `
            -Beta
        ).value
    }
    catch {
        Write-TiTCLog "Preset security policies endpoint unavailable, trying alternative..." -Level Debug -Component $script:COMPONENT
    }

    # Alternative: check protection policies via identity/conditionalAccess or organization settings
    $hasStandardPreset = $false
    $hasStrictPreset   = $false
    $policyDetails     = @()

    if ($presetPolicies.Count -gt 0) {
        $Result.ObjectsScanned += $presetPolicies.Count
        $hasStandardPreset = $presetPolicies | Where-Object { $_.displayName -match 'standard' -and $_.state -eq 'enabled' }
        $hasStrictPreset   = $presetPolicies | Where-Object { $_.displayName -match 'strict'   -and $_.state -eq 'enabled' }
        $policyDetails     = $presetPolicies | ForEach-Object { "$($_.displayName): $($_.state)" }
    }
    else {
        # Fallback: attempt to detect via security alerts from Defender for Office 365
        try {
            $o365Alerts = (Invoke-TiTCGraphRequest `
                -Endpoint '/security/alerts_v2' `
                -Select 'id,serviceSource' `
                -Filter "serviceSource eq 'microsoftDefenderForOffice365'" `
                -Component $script:COMPONENT
            ).value

            # Presence of Defender for Office 365 alerts implies it is licensed and active
            if ($o365Alerts.Count -gt 0) {
                $hasStandardPreset = $true
                Write-TiTCLog "Defender for Office 365 alerts found — service appears active" -Level Debug -Component $script:COMPONENT
            }
        }
        catch {
            Write-TiTCLog "Could not check Defender for Office 365 alert activity: $_" -Level Debug -Component $script:COMPONENT
        }
    }

    $Result.RawData['EmailThreatPolicies'] = @{
        PresetPoliciesFound = $presetPolicies.Count
        HasStandardPreset   = [bool]$hasStandardPreset
        HasStrictPreset     = [bool]$hasStrictPreset
        PolicyDetails       = $policyDetails
    }

    if (-not $hasStandardPreset -and -not $hasStrictPreset) {
        $Result.Findings += New-TiTCFinding `
            -Title "No Defender for Office 365 Preset Security Policy Detected" `
            -Description "No Standard or Strict preset security policy for Defender for Office 365 was detected. Preset policies provide pre-configured, Microsoft-recommended settings for Safe Links, Safe Attachments, and anti-phishing protection. Without preset policies, email threat protection relies on default settings which offer only basic protection against phishing, malware, and spoofing attacks." `
            -Severity Medium `
            -Domain Defender `
            -RiskWeight 6 `
            -Remediation "Apply the Standard or Strict preset security policy in Microsoft Defender portal: Email & collaboration > Policies & rules > Threat policies > Preset security policies. The Standard preset is recommended for most organisations. Assign to all users as a minimum." `
            -RemediationUrl 'https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/preset-security-policies' `
            -ComplianceControls @('ISO27001:A.8.23', 'NIST:SI-8') `
            -AffectedResources @('All mailboxes — email threat protection at default level only') `
            -Evidence @{
                PresetPoliciesFound = $presetPolicies.Count
                HasStandardPreset   = [bool]$hasStandardPreset
                HasStrictPreset     = [bool]$hasStrictPreset
            } `
            -EvidenceQuery 'GET /security/collaboration/presetSecurityPolicies (beta)' `
            -DetectedBy $script:COMPONENT `
            -Tags @('DefenderForOffice365', 'EmailSecurity', 'PresetPolicies')
    }
}

# ============================================================================
# ASSESSOR: Attack Simulation Training
# ============================================================================

function Test-TiTCAttackSimulation {
    [CmdletBinding()]
    param(
        [hashtable]$Config,
        [TiTCCollectorResult]$Result
    )

    Write-TiTCLog "Checking attack simulation training activity..." -Level Info -Component $script:COMPONENT

    $simulations = @()
    try {
        $simulations = (Invoke-TiTCGraphRequest `
            -Endpoint '/security/attackSimulation/simulations' `
            -Select 'id,displayName,status,createdDateTime,launchDateTime,completionDateTime,attackType' `
            -AllPages `
            -Beta `
            -Component $script:COMPONENT
        ).value
    }
    catch {
        Write-TiTCLog "Could not retrieve attack simulation data (may require Attack Simulator license): $_" -Level Warning -Component $script:COMPONENT
        $Result.Warnings += "Attack Simulation check skipped — endpoint unavailable (requires Microsoft Defender for Office 365 Plan 2 or Microsoft 365 E5)"
        return
    }

    $Result.ObjectsScanned += $simulations.Count
    $Result.RawData['AttackSimulations'] = $simulations

    $cutoff90 = (Get-Date).AddDays(-90)
    $recentSimulations = $simulations | Where-Object {
        $_.launchDateTime -and ([datetime]$_.launchDateTime) -gt $cutoff90
    }

    if ($simulations.Count -eq 0 -or $recentSimulations.Count -eq 0) {
        $lastSimDate = if ($simulations.Count -gt 0) {
            $simulations | Sort-Object launchDateTime -Descending |
                Select-Object -First 1 -ExpandProperty launchDateTime
        } else { 'Never' }

        $Result.Findings += New-TiTCFinding `
            -Title "No Attack Simulation Training in the Last 90 Days" `
            -Description "No attack simulation training campaigns have been launched in the past 90 days (last simulation: $lastSimDate). Regular phishing simulations are a critical security awareness control. Without them, employees are not tested or trained to recognise phishing and social engineering attacks — the leading cause of initial access in breaches." `
            -Severity Medium `
            -Domain Defender `
            -RiskWeight 5 `
            -Remediation "Launch a phishing simulation in Microsoft Defender portal: Email & collaboration > Attack simulation training > + Launch simulation. Run at minimum one simulation per quarter. Follow up with training assignments for users who fail simulations. Consider automated campaigns for continuous awareness reinforcement." `
            -RemediationUrl 'https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/attack-simulation-training-get-started' `
            -ComplianceControls @('ISO27001:A.6.3', 'NIST:AT-2') `
            -AffectedResources @('All users — no recent phishing simulation training') `
            -Evidence @{
                TotalSimulations   = $simulations.Count
                RecentSimulations  = 0
                ThresholdDays      = 90
                LastSimulationDate = $lastSimDate
            } `
            -EvidenceQuery 'GET /security/attackSimulation/simulations (beta)' `
            -DetectedBy $script:COMPONENT `
            -Tags @('AttackSimulation', 'SecurityAwareness', 'Training')
    }
}

# ============================================================================
# ASSESSOR: Automated Investigation and Response
# ============================================================================

function Test-TiTCAutoInvestigation {
    [CmdletBinding()]
    param(
        [hashtable]$Config,
        [TiTCCollectorResult]$Result
    )

    Write-TiTCLog "Checking Automated Investigation and Response (AIR) configuration..." -Level Info -Component $script:COMPONENT

    # Check for automated investigation evidence via alert investigation states
    $automatedActions = @()
    try {
        # Look for alerts with automated investigation actions
        $alertsWithAIR = (Invoke-TiTCGraphRequest `
            -Endpoint '/security/alerts_v2' `
            -Select 'id,status,classification,determination,serviceSource' `
            -Filter "determination eq 'apt' or determination eq 'malware' or determination eq 'phishing'" `
            -Component $script:COMPONENT
        ).value
    }
    catch {
        Write-TiTCLog "Could not retrieve alert determination data: $_" -Level Debug -Component $script:COMPONENT
    }

    # Check for automated investigation records via beta
    $investigations = @()
    try {
        $investigations = (Invoke-TiTCGraphRequest `
            -Endpoint '/security/runHuntingQuery' `
            -Component $script:COMPONENT `
            -Beta
        ).value
    }
    catch {
        # Expected — this approach may not work without advanced hunting license
    }

    # Primary signal: check if Microsoft Defender XDR (formerly M365D) has auto-remediation configured
    # We infer from incidents having 'automated' investigation status
    $airEnabled = $false
    $airEvidence = @{}

    try {
        $incidentsWithAIR = (Invoke-TiTCGraphRequest `
            -Endpoint '/security/incidents' `
            -Select 'id,severity,status,determination' `
            -Filter "status eq 'resolved' and determination eq 'truePositive'" `
            -Component $script:COMPONENT
        ).value

        if ($incidentsWithAIR.Count -gt 0) {
            $airEnabled = $true
        }

        $airEvidence = @{
            AutoResolvedIncidents = $incidentsWithAIR.Count
            InferenceMethod       = 'Resolved true-positive incidents found'
        }
    }
    catch {
        Write-TiTCLog "Could not check auto-investigation incident data: $_" -Level Debug -Component $script:COMPONENT
        $airEvidence = @{ Error = "Could not definitively determine AIR status" }
    }

    $Result.ObjectsScanned += 1
    $Result.RawData['AutoInvestigation'] = $airEvidence

    if (-not $airEnabled) {
        $Result.Findings += New-TiTCFinding `
            -Title "Automated Investigation and Response (AIR) May Not Be Active" `
            -Description "No evidence of Automated Investigation and Response (AIR) activity was found. AIR automatically triages alerts, investigates threats, and can automatically remediate attacks without requiring manual analyst intervention. Without AIR enabled, security teams must manually investigate every alert, significantly increasing response time and analyst workload. This is especially critical outside business hours." `
            -Severity Low `
            -Domain Defender `
            -RiskWeight 4 `
            -Remediation "Enable Automated Investigation and Response in Microsoft Defender portal: Settings > Microsoft Defender XDR > Automated investigation. Set automation level to 'Full — remediate threats automatically' or 'Semi — require approval for core actions'. Verify AIR is configured per service: Defender for Endpoint (Settings > Endpoints > Advanced features > Automated Investigation) and Defender for Office 365." `
            -RemediationUrl 'https://learn.microsoft.com/en-us/microsoft-365/security/defender/m365d-configure-auto-investigation-response' `
            -ComplianceControls @('ISO27001:A.5.24', 'NIST:IR-4') `
            -AffectedResources @('Microsoft Defender XDR — automated response posture') `
            -Evidence $airEvidence `
            -EvidenceQuery 'GET /security/incidents (resolved true-positive inference)' `
            -DetectedBy $script:COMPONENT `
            -Tags @('AutomatedResponse', 'AIR', 'IncidentResponse')
    }
}

# ============================================================================
# MODULE EXPORT
# ============================================================================

Export-ModuleMember -Function @('Invoke-TiTCDefenderCollector')
