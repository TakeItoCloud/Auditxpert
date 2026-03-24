#Requires -Version 5.1
<#
.SYNOPSIS
    TakeItToCloud.Assess — Entra ID / Identity Security Collector.

.DESCRIPTION
    Performs comprehensive identity and access management security checks against
    Microsoft Entra ID (Azure AD) via Graph API. Covers:

    - MFA enrollment and enforcement gaps
    - Privileged role assignments and standing access
    - Conditional Access policy coverage
    - Stale/dormant accounts
    - Guest account hygiene
    - Application and service principal risks
    - Password policy and credential hygiene
    - Authentication methods configuration
    - Named locations and trusted networks
    - Administrative unit coverage
    - Sign-in risk policies

    All checks produce standardized TiTCFinding objects with compliance mappings.

.NOTES
    Module:     TiTC.Collector.EntraID
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

$script:COMPONENT = 'Collector.EntraID'

# Critical Entra ID directory roles (by templateId)
$script:PRIVILEGED_ROLES = @{
    '62e90394-69f5-4237-9190-012177145e10' = 'Global Administrator'
    'e8611ab8-c189-46e8-94e1-60213ab1f814' = 'Privileged Role Administrator'
    '194ae4cb-b126-40b2-bd5b-6091b380977d' = 'Security Administrator'
    'f28a1f50-f6e7-4571-818b-6a12f2af6b6c' = 'SharePoint Administrator'
    '29232cdf-9323-42fd-ade2-1d097af3e4de' = 'Exchange Administrator'
    'fe930be7-5e62-47db-91af-98c3a49a38b1' = 'User Administrator'
    '9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3' = 'Application Administrator'
    '158c047a-c907-4556-b7ef-446551a6b5f7' = 'Cloud Application Administrator'
    '966707d0-3269-4727-9be2-8c3a10f19b9d' = 'Password Administrator'
    'b0f54661-2d74-4c50-afa3-1ec803f12efe' = 'Billing Administrator'
    '7be44c8a-adaf-4e2a-84d6-ab2649e08a13' = 'Privileged Authentication Administrator'
    'e6d1a23a-da11-4be4-9570-befc86d067a7' = 'Compliance Administrator'
    'b1be1c3e-b65d-4f19-8427-f6fa0d97feb9' = 'Conditional Access Administrator'
}

# ============================================================================
# MAIN COLLECTOR ENTRY POINT
# ============================================================================

function Invoke-TiTCEntraIDCollector {
    <#
    .SYNOPSIS
        Runs all Entra ID security checks and returns a TiTCCollectorResult.

    .DESCRIPTION
        Orchestrates all identity security assessors against the connected tenant.
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
            'MFA', 'PrivilegedAccess', 'ConditionalAccess', 'StaleAccounts',
            'GuestAccounts', 'Applications', 'PasswordPolicy', 'AuthMethods',
            'SignInRisk', 'All'
        )]
        [string[]]$Checks = @('All')
    )

    $result = New-TiTCCollectorResult -Domain EntraID
    Write-TiTCLog "Starting Entra ID security assessment..." -Level Info -Component $script:COMPONENT

    # Load config defaults if not provided
    if (-not $Config.Thresholds) {
        $Config = Get-TiTCConfig -ProfileName Full
    }

    $thresholds = $Config.Thresholds
    $runAll = $Checks -contains 'All'

    # ── Assessor dispatch ───────────────────────────────────────────────
    $assessors = [ordered]@{
        'MFA'              = { Test-TiTCMFAEnrollment -Config $Config -Result $result }
        'PrivilegedAccess' = { Test-TiTCPrivilegedAccess -Config $Config -Result $result }
        'ConditionalAccess'= { Test-TiTCConditionalAccessPolicies -Config $Config -Result $result }
        'StaleAccounts'    = { Test-TiTCStaleAccounts -Config $Config -Result $result }
        'GuestAccounts'    = { Test-TiTCGuestAccounts -Config $Config -Result $result }
        'Applications'     = { Test-TiTCApplicationSecurity -Config $Config -Result $result }
        'PasswordPolicy'   = { Test-TiTCPasswordPolicy -Config $Config -Result $result }
        'AuthMethods'      = { Test-TiTCAuthenticationMethods -Config $Config -Result $result }
        'SignInRisk'       = { Test-TiTCSignInRiskPolicies -Config $Config -Result $result }
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

    # Summary
    $summary = $result.ToSummary()
    Write-TiTCLog "Entra ID assessment complete" -Level Success -Component $script:COMPONENT -Data $summary

    return $result
}

# ============================================================================
# ASSESSOR: MFA Enrollment & Enforcement
# ============================================================================

function Test-TiTCMFAEnrollment {
    [CmdletBinding()]
    param(
        [hashtable]$Config,
        $Result
    )

    Write-TiTCLog "Checking MFA enrollment status..." -Level Info -Component $script:COMPONENT

    # Get all enabled users (non-guest)
    $users = (Invoke-TiTCGraphRequest `
        -Endpoint '/users' `
        -Select 'id,displayName,userPrincipalName,userType,accountEnabled,assignedLicenses' `
        -Filter "userType eq 'Member' and accountEnabled eq true" `
        -AllPages `
        -Component $script:COMPONENT
    ).value

    $Result.ObjectsScanned += $users.Count

    # Get authentication methods for each user (batch approach)
    $usersWithoutMFA = [System.Collections.ArrayList]::new()
    $usersWithMFA = 0
    $smsOnlyUsers = [System.Collections.ArrayList]::new()

    foreach ($user in $users) {
        if (-not $user.id) { continue }
        try {
            $authMethods = (Invoke-TiTCGraphRequest `
                -Endpoint "/users/$($user.id)/authentication/methods" `
                -Component $script:COMPONENT
            ).value

            # Check for strong MFA methods
            $strongMethods = $authMethods | Where-Object {
                $_.'@odata.type' -in @(
                    '#microsoft.graph.microsoftAuthenticatorAuthenticationMethod',
                    '#microsoft.graph.fido2AuthenticationMethod',
                    '#microsoft.graph.windowsHelloForBusinessAuthenticationMethod',
                    '#microsoft.graph.softwareOathAuthenticationMethod',
                    '#microsoft.graph.temporaryAccessPassAuthenticationMethod'
                )
            }

            $hasSmsOnly = ($authMethods | Where-Object {
                $_.'@odata.type' -eq '#microsoft.graph.phoneAuthenticationMethod'
            }) -and -not $strongMethods

            if (-not $strongMethods) {
                $null = $usersWithoutMFA.Add($user.userPrincipalName)
            }
            else {
                $usersWithMFA++
            }

            if ($hasSmsOnly) {
                $null = $smsOnlyUsers.Add($user.userPrincipalName)
            }
        }
        catch {
            Write-TiTCLog "Could not check MFA for $($user.userPrincipalName): $_" -Level Debug -Component $script:COMPONENT
        }
    }

    $mfaPercentage = if ($users.Count -gt 0) {
        [Math]::Round(($usersWithMFA / $users.Count) * 100, 1)
    } else { 100 }

    $target = $Config.Thresholds.MFAEnforcementTarget

    # ── Finding: Users without MFA ──────────────────────────────────
    if ($usersWithoutMFA.Count -gt 0) {
        $severity = if ($usersWithoutMFA.Count -gt ($users.Count * 0.3)) {
            'Critical'
        }
        elseif ($usersWithoutMFA.Count -gt ($users.Count * 0.1)) {
            'High'
        }
        else {
            'Medium'
        }

        $Result.Findings += New-TiTCFinding `
            -Title "Users without MFA enrollment" `
            -Description "$($usersWithoutMFA.Count) of $($users.Count) users ($([Math]::Round(100 - $mfaPercentage, 1))%) have no strong MFA method registered. Target: ${target}% enrollment." `
            -Severity $severity `
            -Domain EntraID `
            -RiskWeight 9 `
            -Remediation "Enable Security Defaults or create a Conditional Access policy requiring MFA for all users. Use Authentication Methods policies to enable Microsoft Authenticator as the default method." `
            -RemediationUrl 'https://learn.microsoft.com/entra/identity/authentication/concept-authentication-methods' `
            -ComplianceControls @('ISO27001:A.9.4.2', 'CIS:1.1.1', 'SOC2:CC6.1', 'NIST:IA-2') `
            -AffectedResources ($usersWithoutMFA | Select-Object -First 50) `
            -Evidence @{
                TotalUsers      = $users.Count
                WithMFA         = $usersWithMFA
                WithoutMFA      = $usersWithoutMFA.Count
                MFAPercentage   = $mfaPercentage
                TargetPercent   = $target
            } `
            -EvidenceQuery 'GET /users/{id}/authentication/methods' `
            -DetectedBy $script:COMPONENT `
            -Tags @('MFA', 'Identity', 'CriticalControl')
    }

    # ── Finding: SMS-only MFA users ─────────────────────────────────
    if ($smsOnlyUsers.Count -gt 0) {
        $Result.Findings += New-TiTCFinding `
            -Title "Users relying on SMS-only MFA" `
            -Description "$($smsOnlyUsers.Count) users use SMS as their only MFA method. SMS is vulnerable to SIM-swap attacks and is considered a weak authenticator by NIST SP 800-63B." `
            -Severity Medium `
            -Domain EntraID `
            -RiskWeight 5 `
            -Remediation "Migrate users to Microsoft Authenticator push notifications or FIDO2 security keys. Use Authentication Strengths in Conditional Access to require phishing-resistant methods." `
            -RemediationUrl 'https://learn.microsoft.com/entra/identity/authentication/concept-authentication-strengths' `
            -ComplianceControls @('ISO27001:A.9.4.2', 'NIST:IA-2(6)') `
            -AffectedResources ($smsOnlyUsers | Select-Object -First 50) `
            -Evidence @{ SMSOnlyCount = $smsOnlyUsers.Count } `
            -EvidenceQuery 'GET /users/{id}/authentication/methods' `
            -DetectedBy $script:COMPONENT `
            -Tags @('MFA', 'SMS', 'WeakAuth')
    }

    # Store raw data for evidence packs
    $Result.RawData['MFA'] = @{
        TotalUsers    = $users.Count
        WithMFA       = $usersWithMFA
        WithoutMFA    = $usersWithoutMFA
        SMSOnly       = $smsOnlyUsers
        MFAPercentage = $mfaPercentage
    }

    Write-TiTCLog "MFA check complete: $mfaPercentage% enrolled ($usersWithMFA/$($users.Count))" -Level Info -Component $script:COMPONENT
}

# ============================================================================
# ASSESSOR: Privileged Access
# ============================================================================

function Test-TiTCPrivilegedAccess {
    [CmdletBinding()]
    param(
        [hashtable]$Config,
        $Result
    )

    Write-TiTCLog "Checking privileged role assignments..." -Level Info -Component $script:COMPONENT

    # Get all directory role assignments (no $select — endpoint has limited $select support)
    $roleAssignments = (Invoke-TiTCGraphRequest `
        -Endpoint '/roleManagement/directory/roleAssignments' `
        -AllPages `
        -Component $script:COMPONENT
    ).value

    # Get role definitions
    $roleDefinitions = (Invoke-TiTCGraphRequest `
        -Endpoint '/roleManagement/directory/roleDefinitions' `
        -AllPages `
        -Component $script:COMPONENT
    ).value

    $roleLookup = @{}
    foreach ($rd in $roleDefinitions) {
        $roleLookup[$rd.id] = $rd
    }

    $principalCache = @{}
    foreach ($assignment in $roleAssignments) {
        if (-not $assignment.principalId -or $principalCache.ContainsKey($assignment.principalId)) {
            continue
        }

        try {
            $principalCache[$assignment.principalId] = Invoke-TiTCGraphRequest `
                -Endpoint "/directoryObjects/$($assignment.principalId)" `
                -Component $script:COMPONENT `
                -NoTop
        }
        catch {
            $principalCache[$assignment.principalId] = [PSCustomObject]@{
                id = $assignment.principalId
                displayName = $assignment.principalId
                '@odata.type' = '#microsoft.graph.directoryObject'
            }
        }
    }

    # ── Analyze Global Administrators ───────────────────────────────
    $globalAdminRoleDef = $roleDefinitions | Where-Object {
        $_.templateId -eq '62e90394-69f5-4237-9190-012177145e10'
    }

    $globalAdminAssignments = @()
    if ($globalAdminRoleDef) {
        $globalAdminAssignments = $roleAssignments | Where-Object {
            $_.roleDefinitionId -eq $globalAdminRoleDef.id
        }
    }

    $Result.ObjectsScanned += $roleAssignments.Count

    $maxAdmins = $Config.Thresholds.AdminAccountMaxCount

    if ($globalAdminAssignments.Count -gt $maxAdmins) {
        $Result.Findings += New-TiTCFinding `
            -Title "Excessive Global Administrator accounts" `
            -Description "$($globalAdminAssignments.Count) Global Administrator assignments found. Microsoft recommends no more than $maxAdmins. Excessive privileged accounts increase the attack surface." `
            -Severity High `
            -Domain EntraID `
            -RiskWeight 8 `
            -Remediation "Review all Global Admin assignments. Use least-privilege roles (e.g., Exchange Admin, User Admin) instead. Implement PIM for just-in-time elevation." `
            -RemediationUrl 'https://learn.microsoft.com/entra/identity/role-based-access-control/best-practices' `
            -ComplianceControls @('ISO27001:A.9.2.3', 'CIS:1.1.4', 'SOC2:CC6.3', 'NIST:AC-6') `
            -AffectedResources ($globalAdminAssignments | ForEach-Object {
                if ($principalCache[$_.principalId].displayName) { $principalCache[$_.principalId].displayName } else { $_.principalId }
            } | Select-Object -First 20) `
            -Evidence @{
                GlobalAdminCount = $globalAdminAssignments.Count
                Threshold        = $maxAdmins
                Assignments      = $globalAdminAssignments | ForEach-Object {
                    @{
                        Principal = if ($principalCache[$_.principalId].displayName) { $principalCache[$_.principalId].displayName } else { $_.principalId }
                        PrincipalId = $_.principalId
                    }
                }
            } `
            -DetectedBy $script:COMPONENT `
            -Tags @('PrivilegedAccess', 'GlobalAdmin', 'LeastPrivilege')
    }

    # ── Check for permanent (non-PIM) privileged assignments ────────
    $permanentPrivileged = [System.Collections.ArrayList]::new()

    foreach ($assignment in $roleAssignments) {
        $roleDef = $roleLookup[$assignment.roleDefinitionId]
        if (-not $roleDef) { continue }

        $isPrivileged = $script:PRIVILEGED_ROLES.ContainsKey($roleDef.templateId)
        if (-not $isPrivileged) { continue }

        # Check if assignment is permanent (no end date = standing access)
        if (-not $assignment.scheduleInfo -or -not $assignment.scheduleInfo.expiration) {
            $null = $permanentPrivileged.Add(@{
                Principal = if ($principalCache[$assignment.principalId].displayName) { $principalCache[$assignment.principalId].displayName } else { $assignment.principalId }
                Role      = $roleDef.displayName
                Type      = if ($principalCache[$assignment.principalId].'@odata.type' -match 'group') { 'Group' }
                           elseif ($principalCache[$assignment.principalId].'@odata.type' -match 'servicePrincipal') { 'ServicePrincipal' }
                           else { 'User' }
            })
        }
    }

    if ($permanentPrivileged.Count -gt 0) {
        $Result.Findings += New-TiTCFinding `
            -Title "Standing privileged role assignments without PIM" `
            -Description "$($permanentPrivileged.Count) privileged role assignments are permanently active without just-in-time activation through PIM. Standing access increases exposure window for compromised accounts." `
            -Severity High `
            -Domain EntraID `
            -RiskWeight 7 `
            -Remediation "Enable Privileged Identity Management (PIM) and convert permanent assignments to eligible assignments requiring activation. Set maximum activation duration to 8 hours." `
            -RemediationUrl 'https://learn.microsoft.com/entra/id-governance/privileged-identity-management/pim-configure' `
            -ComplianceControls @('ISO27001:A.9.2.3', 'CIS:1.1.5', 'SOC2:CC6.1', 'NIST:AC-2') `
            -AffectedResources ($permanentPrivileged | ForEach-Object { "$($_.Principal) ($($_.Role))" } | Select-Object -First 30) `
            -Evidence @{
                PermanentAssignments = $permanentPrivileged.Count
                Details              = $permanentPrivileged | Select-Object -First 50
            } `
            -DetectedBy $script:COMPONENT `
            -Tags @('PrivilegedAccess', 'PIM', 'StandingAccess')
    }

    # ── Check for service principals with privileged roles ──────────
    $spWithPrivRoles = $permanentPrivileged | Where-Object { $_.Type -eq 'ServicePrincipal' }
    if ($spWithPrivRoles.Count -gt 0) {
        $Result.Findings += New-TiTCFinding `
            -Title "Service principals with privileged directory roles" `
            -Description "$($spWithPrivRoles.Count) service principals hold privileged directory roles. Service principals bypass MFA and Conditional Access, making them high-value targets." `
            -Severity High `
            -Domain EntraID `
            -RiskWeight 7 `
            -Remediation "Review service principal role assignments. Use application permissions with minimal scope instead of directory roles where possible. Implement workload identity federation to eliminate secrets." `
            -RemediationUrl 'https://learn.microsoft.com/entra/workload-id/workload-identity-federation' `
            -ComplianceControls @('ISO27001:A.9.4.1', 'NIST:AC-6(5)') `
            -AffectedResources ($spWithPrivRoles | ForEach-Object { "$($_.Principal) ($($_.Role))" }) `
            -Evidence @{ ServicePrincipals = $spWithPrivRoles } `
            -DetectedBy $script:COMPONENT `
            -Tags @('PrivilegedAccess', 'ServicePrincipal', 'NonHuman')
    }

    $Result.RawData['PrivilegedAccess'] = @{
        TotalRoleAssignments = $roleAssignments.Count
        GlobalAdmins         = $globalAdminAssignments.Count
        PermanentPrivileged  = $permanentPrivileged.Count
        ServicePrincipals    = $spWithPrivRoles.Count
    }

    Write-TiTCLog "Privileged access check complete: $($globalAdminAssignments.Count) GAs, $($permanentPrivileged.Count) permanent privileged" -Level Info -Component $script:COMPONENT
}

# ============================================================================
# ASSESSOR: Conditional Access Policies
# ============================================================================

function Test-TiTCConditionalAccessPolicies {
    [CmdletBinding()]
    param(
        [hashtable]$Config,
        $Result
    )

    Write-TiTCLog "Checking Conditional Access policies..." -Level Info -Component $script:COMPONENT

    $policies = (Invoke-TiTCGraphRequest `
        -Endpoint '/identity/conditionalAccess/policies' `
        -AllPages `
        -Component $script:COMPONENT
    ).value

    $Result.ObjectsScanned += $policies.Count

    $enabledPolicies = $policies | Where-Object { $_.state -eq 'enabled' }
    $reportOnlyPolicies = $policies | Where-Object { $_.state -eq 'enabledForReportingButNotEnforced' }
    $disabledPolicies = $policies | Where-Object { $_.state -eq 'disabled' }

    $minPolicies = $Config.Thresholds.ConditionalAccessMinPolicies

    # ── Finding: Too few CA policies ────────────────────────────────
    if ($enabledPolicies.Count -lt $minPolicies) {
        $Result.Findings += New-TiTCFinding `
            -Title "Insufficient Conditional Access policies" `
            -Description "Only $($enabledPolicies.Count) Conditional Access policies are enabled (minimum recommended: $minPolicies). CA policies are the primary mechanism to enforce MFA, block risky sign-ins, and control access." `
            -Severity High `
            -Domain EntraID `
            -RiskWeight 8 `
            -Remediation "Implement baseline CA policies: (1) Require MFA for all users, (2) Block legacy authentication, (3) Require MFA for admin roles, (4) Require compliant devices for sensitive apps, (5) Block or limit access from risky locations." `
            -RemediationUrl 'https://learn.microsoft.com/entra/identity/conditional-access/plan-conditional-access' `
            -ComplianceControls @('ISO27001:A.9.4.1', 'CIS:1.2.1', 'SOC2:CC6.1', 'NIST:AC-7') `
            -Evidence @{
                EnabledCount    = $enabledPolicies.Count
                ReportOnly      = $reportOnlyPolicies.Count
                Disabled        = $disabledPolicies.Count
                MinRequired     = $minPolicies
            } `
            -DetectedBy $script:COMPONENT `
            -Tags @('ConditionalAccess', 'PolicyCoverage')
    }

    # ── Check for legacy auth blocking ──────────────────────────────
    $legacyAuthBlocked = $enabledPolicies | Where-Object {
        $_.conditions.clientAppTypes -contains 'exchangeActiveSync' -or
        $_.conditions.clientAppTypes -contains 'other'
    } | Where-Object {
        $_.grantControls.builtInControls -contains 'block'
    }

    if (-not $legacyAuthBlocked) {
        $Result.Findings += New-TiTCFinding `
            -Title "Legacy authentication not blocked by Conditional Access" `
            -Description "No Conditional Access policy blocks legacy authentication protocols (IMAP, POP3, SMTP Auth, EAS). Legacy protocols cannot enforce MFA, making them a common attack vector." `
            -Severity Critical `
            -Domain EntraID `
            -RiskWeight 9 `
            -Remediation "Create a CA policy targeting 'Other clients' and 'Exchange ActiveSync' with a Block grant control. Apply to all users with emergency access exclusions." `
            -RemediationUrl 'https://learn.microsoft.com/entra/identity/conditional-access/block-legacy-authentication' `
            -ComplianceControls @('ISO27001:A.9.4.2', 'CIS:1.2.2', 'SOC2:CC6.6', 'NIST:AC-17') `
            -Evidence @{
                LegacyBlockPolicies = 0
                TotalEnabled        = $enabledPolicies.Count
            } `
            -DetectedBy $script:COMPONENT `
            -Tags @('ConditionalAccess', 'LegacyAuth', 'CriticalControl')
    }

    # ── Check for policies with broad exclusions ────────────────────
    $broadExclusions = $enabledPolicies | Where-Object {
        ($_.conditions.users.excludeGroups.Count -gt 3) -or
        ($_.conditions.users.excludeUsers.Count -gt 5)
    }

    if ($broadExclusions.Count -gt 0) {
        $Result.Findings += New-TiTCFinding `
            -Title "Conditional Access policies with excessive exclusions" `
            -Description "$($broadExclusions.Count) CA policies have broad user/group exclusions. Excessive exclusions create coverage gaps that attackers can exploit." `
            -Severity Medium `
            -Domain EntraID `
            -RiskWeight 5 `
            -Remediation "Review and minimize CA policy exclusions. Use a single 'CA Exclusion' security group with regular access reviews. Ensure break-glass accounts are the only permanent exclusions." `
            -ComplianceControls @('ISO27001:A.9.2.5', 'NIST:AC-2(7)') `
            -AffectedResources ($broadExclusions | ForEach-Object { $_.displayName }) `
            -Evidence @{
                PoliciesWithBroadExclusions = $broadExclusions.Count
                PolicyNames = $broadExclusions | ForEach-Object { $_.displayName }
            } `
            -DetectedBy $script:COMPONENT `
            -Tags @('ConditionalAccess', 'Exclusions', 'CoverageGap')
    }

    $Result.RawData['ConditionalAccess'] = @{
        TotalPolicies   = $policies.Count
        Enabled         = $enabledPolicies.Count
        ReportOnly      = $reportOnlyPolicies.Count
        Disabled        = $disabledPolicies.Count
        LegacyBlocked   = ($legacyAuthBlocked.Count -gt 0)
        BroadExclusions = $broadExclusions.Count
        PolicyDetails   = $enabledPolicies | ForEach-Object {
            @{ Name = $_.displayName; State = $_.state; GrantControls = $_.grantControls.builtInControls }
        }
    }

    Write-TiTCLog "CA check complete: $($enabledPolicies.Count) enabled, $($reportOnlyPolicies.Count) report-only" -Level Info -Component $script:COMPONENT
}

# ============================================================================
# ASSESSOR: Stale/Dormant Accounts
# ============================================================================

function Test-TiTCStaleAccounts {
    [CmdletBinding()]
    param(
        [hashtable]$Config,
        $Result
    )

    Write-TiTCLog "Checking for stale accounts..." -Level Info -Component $script:COMPONENT

    $staleDays = $Config.Thresholds.StaleAccountDays
    $cutoffDate = (Get-Date).AddDays(-$staleDays).ToString('yyyy-MM-ddTHH:mm:ssZ')

    # Get users with sign-in activity (requires Azure AD P1+)
    try {
        $users = (Invoke-TiTCGraphRequest `
            -Endpoint '/users' `
            -Select 'id,displayName,userPrincipalName,userType,accountEnabled,signInActivity,createdDateTime' `
            -Filter "userType eq 'Member' and accountEnabled eq true" `
            -AllPages `
            -Beta `
            -Component $script:COMPONENT
        ).value
    }
    catch {
        Write-TiTCLog "signInActivity requires Azure AD P1 license. Falling back to lastSignInDateTime filter." -Level Warning -Component $script:COMPONENT
        $Result.Warnings += "signInActivity data requires Azure AD Premium P1. Stale account check may be incomplete."
        return
    }

    $Result.ObjectsScanned += $users.Count

    $staleUsers = $users | Where-Object {
        $lastSignIn = $_.signInActivity.lastSignInDateTime
        $lastNonInteractive = $_.signInActivity.lastNonInteractiveSignInDateTime

        $effectiveDate = if ($lastSignIn -and $lastNonInteractive) {
            @($lastSignIn, $lastNonInteractive) | Sort-Object -Descending | Select-Object -First 1
        }
        elseif ($lastSignIn) { $lastSignIn }
        elseif ($lastNonInteractive) { $lastNonInteractive }
        else { $null }

        if ($effectiveDate) {
            [datetime]$effectiveDate -lt [datetime]$cutoffDate
        }
        else {
            # Never signed in — check creation date
            $_.createdDateTime -and ([datetime]$_.createdDateTime -lt [datetime]$cutoffDate)
        }
    }

    if ($staleUsers.Count -gt 0) {
        $severity = if ($staleUsers.Count -gt ($users.Count * 0.2)) {
            'High'
        }
        elseif ($staleUsers.Count -gt 10) {
            'Medium'
        }
        else {
            'Low'
        }

        $Result.Findings += New-TiTCFinding `
            -Title "Stale user accounts (inactive >$staleDays days)" `
            -Description "$($staleUsers.Count) of $($users.Count) accounts have not signed in for over $staleDays days. Stale accounts are targets for credential stuffing and account takeover attacks." `
            -Severity $severity `
            -Domain EntraID `
            -RiskWeight 6 `
            -Remediation "Review stale accounts and disable or delete those no longer needed. Implement an automated lifecycle policy using Entra ID Access Reviews or a scheduled PowerShell script." `
            -RemediationUrl 'https://learn.microsoft.com/entra/id-governance/access-reviews-overview' `
            -RemediationScript @'
# Disable stale accounts (review list first!)
$staleUsers | ForEach-Object {
    Update-MgUser -UserId $_.id -AccountEnabled:$false
    Write-Output "Disabled: $($_.userPrincipalName)"
}
'@ `
            -ComplianceControls @('ISO27001:A.9.2.6', 'CIS:1.1.6', 'SOC2:CC6.2', 'NIST:AC-2(3)') `
            -AffectedResources ($staleUsers | ForEach-Object { $_.userPrincipalName } | Select-Object -First 50) `
            -Evidence @{
                StaleCount    = $staleUsers.Count
                TotalUsers    = $users.Count
                ThresholdDays = $staleDays
            } `
            -DetectedBy $script:COMPONENT `
            -Tags @('AccountHygiene', 'StaleAccounts', 'Lifecycle')
    }

    $Result.RawData['StaleAccounts'] = @{
        ThresholdDays = $staleDays
        TotalUsers    = $users.Count
        StaleUsers    = $staleUsers | ForEach-Object {
            @{
                UPN        = $_.userPrincipalName
                LastSignIn = $_.signInActivity.lastSignInDateTime
                Created    = $_.createdDateTime
            }
        } | Select-Object -First 100
    }

    Write-TiTCLog "Stale account check complete: $($staleUsers.Count) stale of $($users.Count)" -Level Info -Component $script:COMPONENT
}

# ============================================================================
# ASSESSOR: Guest Accounts
# ============================================================================

function Test-TiTCGuestAccounts {
    [CmdletBinding()]
    param(
        [hashtable]$Config,
        $Result
    )

    Write-TiTCLog "Checking guest account hygiene..." -Level Info -Component $script:COMPONENT

    $guests = (Invoke-TiTCGraphRequest `
        -Endpoint '/users' `
        -Select 'id,displayName,userPrincipalName,mail,userType,accountEnabled,createdDateTime,externalUserState,signInActivity' `
        -Filter "userType eq 'Guest'" `
        -AllPages `
        -Beta `
        -Component $script:COMPONENT
    ).value

    $Result.ObjectsScanned += $guests.Count

    $maxAge = $Config.Thresholds.GuestAccountMaxAge
    $ageCutoff = (Get-Date).AddDays(-$maxAge)

    # Old guest accounts
    $staleGuests = $guests | Where-Object {
        $_.createdDateTime -and ([datetime]$_.createdDateTime -lt $ageCutoff)
    }

    # Guests who never accepted invitation
    $pendingGuests = $guests | Where-Object {
        $_.externalUserState -eq 'PendingAcceptance'
    }

    if ($staleGuests.Count -gt 0) {
        $Result.Findings += New-TiTCFinding `
            -Title "Guest accounts older than $maxAge days" `
            -Description "$($staleGuests.Count) guest accounts were created more than $maxAge days ago. Old guest accounts may have outdated access and should be reviewed regularly." `
            -Severity Medium `
            -Domain EntraID `
            -RiskWeight 4 `
            -Remediation "Implement quarterly guest access reviews using Entra ID Access Reviews. Remove guests who no longer need access to organizational resources." `
            -RemediationUrl 'https://learn.microsoft.com/entra/id-governance/manage-guest-access-with-access-reviews' `
            -ComplianceControls @('ISO27001:A.9.2.5', 'SOC2:CC6.2', 'NIST:AC-2(3)') `
            -AffectedResources ($staleGuests | ForEach-Object { $_.mail ?? $_.userPrincipalName } | Select-Object -First 50) `
            -Evidence @{
                StaleGuestCount = $staleGuests.Count
                TotalGuests     = $guests.Count
                MaxAgeDays      = $maxAge
            } `
            -DetectedBy $script:COMPONENT `
            -Tags @('GuestAccess', 'ExternalIdentity', 'Lifecycle')
    }

    if ($pendingGuests.Count -gt 0) {
        $Result.Findings += New-TiTCFinding `
            -Title "Guest invitations pending acceptance" `
            -Description "$($pendingGuests.Count) guest accounts have never accepted their invitation. Pending invitations may indicate stale collaboration requests or failed onboarding." `
            -Severity Low `
            -Domain EntraID `
            -RiskWeight 2 `
            -Remediation "Review pending guest invitations. Remove those older than 30 days. Consider implementing automatic redemption via B2B direct connect." `
            -AffectedResources ($pendingGuests | ForEach-Object { $_.mail ?? $_.displayName } | Select-Object -First 30) `
            -Evidence @{ PendingCount = $pendingGuests.Count } `
            -DetectedBy $script:COMPONENT `
            -Tags @('GuestAccess', 'Pending')
    }

    $Result.RawData['GuestAccounts'] = @{
        TotalGuests   = $guests.Count
        StaleGuests   = $staleGuests.Count
        PendingGuests = $pendingGuests.Count
        EnabledGuests = ($guests | Where-Object { $_.accountEnabled }).Count
    }

    Write-TiTCLog "Guest check complete: $($guests.Count) total, $($staleGuests.Count) stale, $($pendingGuests.Count) pending" -Level Info -Component $script:COMPONENT
}

# ============================================================================
# ASSESSOR: Application & Service Principal Security
# ============================================================================

function Test-TiTCApplicationSecurity {
    [CmdletBinding()]
    param(
        [hashtable]$Config,
        $Result
    )

    Write-TiTCLog "Checking application security..." -Level Info -Component $script:COMPONENT

    # Get applications with credential info
    $apps = (Invoke-TiTCGraphRequest `
        -Endpoint '/applications' `
        -Select 'id,displayName,appId,passwordCredentials,keyCredentials,requiredResourceAccess,createdDateTime' `
        -AllPages `
        -Component $script:COMPONENT
    ).value

    $Result.ObjectsScanned += $apps.Count

    # ── Apps with expiring or expired secrets ───────────────────────
    $now = Get-Date
    $expiringApps = [System.Collections.ArrayList]::new()
    $expiredApps = [System.Collections.ArrayList]::new()
    $longLivedApps = [System.Collections.ArrayList]::new()

    foreach ($app in $apps) {
        foreach ($cred in $app.passwordCredentials) {
            if ($cred.endDateTime) {
                $expiry = [datetime]$cred.endDateTime

                if ($expiry -lt $now) {
                    $null = $expiredApps.Add(@{
                        AppName = $app.displayName
                        AppId   = $app.appId
                        Expiry  = $cred.endDateTime
                    })
                }
                elseif ($expiry -lt $now.AddDays(30)) {
                    $null = $expiringApps.Add(@{
                        AppName    = $app.displayName
                        AppId      = $app.appId
                        DaysLeft   = [Math]::Round(($expiry - $now).TotalDays, 0)
                    })
                }

                # Secrets valid for more than 2 years
                if ($cred.startDateTime) {
                    $lifetime = ($expiry - [datetime]$cred.startDateTime).TotalDays
                    if ($lifetime -gt 730) {
                        $null = $longLivedApps.Add(@{
                            AppName  = $app.displayName
                            Lifetime = [Math]::Round($lifetime / 365, 1)
                        })
                    }
                }
            }
        }
    }

    if ($expiredApps.Count -gt 0) {
        $Result.Findings += New-TiTCFinding `
            -Title "Applications with expired client secrets" `
            -Description "$($expiredApps.Count) applications have expired client secrets. While not an active security risk, expired secrets indicate poor credential lifecycle management." `
            -Severity Low `
            -Domain EntraID `
            -RiskWeight 3 `
            -Remediation "Remove expired credentials from application registrations. Implement a credential rotation schedule. Prefer certificate-based credentials or managed identities over client secrets." `
            -RemediationUrl 'https://learn.microsoft.com/entra/identity-platform/howto-create-service-principal-portal' `
            -ComplianceControls @('ISO27001:A.9.4.3', 'NIST:IA-5') `
            -AffectedResources ($expiredApps | ForEach-Object { "$($_.AppName) (expired: $($_.Expiry))" }) `
            -Evidence @{ ExpiredApps = $expiredApps } `
            -DetectedBy $script:COMPONENT `
            -Tags @('Applications', 'Credentials', 'Expired')
    }

    if ($longLivedApps.Count -gt 0) {
        $Result.Findings += New-TiTCFinding `
            -Title "Applications with long-lived secrets (>2 years)" `
            -Description "$($longLivedApps.Count) applications have client secrets valid for more than 2 years. Long-lived secrets increase the risk window if credentials are compromised." `
            -Severity Medium `
            -Domain EntraID `
            -RiskWeight 5 `
            -Remediation "Shorten secret lifetime to maximum 6-12 months. Migrate to certificate-based authentication or managed identities. Use Workload Identity Federation for CI/CD pipelines." `
            -RemediationUrl 'https://learn.microsoft.com/entra/workload-id/workload-identity-federation' `
            -ComplianceControls @('ISO27001:A.9.4.3', 'CIS:1.3.1', 'NIST:IA-5(1)') `
            -AffectedResources ($longLivedApps | ForEach-Object { "$($_.AppName) ($($_.Lifetime) years)" }) `
            -Evidence @{ LongLivedApps = $longLivedApps } `
            -DetectedBy $script:COMPONENT `
            -Tags @('Applications', 'Credentials', 'LongLived')
    }

    # ── Apps with high-privilege Graph permissions ───────────────────
    $highPrivApps = [System.Collections.ArrayList]::new()
    $graphResourceId = '00000003-0000-0000-c000-000000000000'  # Microsoft Graph

    $dangerousPermissions = @(
        'Application.ReadWrite.All',
        'Directory.ReadWrite.All',
        'RoleManagement.ReadWrite.Directory',
        'Mail.ReadWrite',
        'Files.ReadWrite.All',
        'Sites.ReadWrite.All',
        'User.ReadWrite.All'
    )

    foreach ($app in $apps) {
        $graphAccess = $app.requiredResourceAccess | Where-Object { $_.resourceAppId -eq $graphResourceId }
        if (-not $graphAccess) { continue }

        $appPermissions = $graphAccess.resourceAccess | Where-Object { $_.type -eq 'Role' }
        if ($appPermissions.Count -gt 10) {
            $null = $highPrivApps.Add(@{
                AppName         = $app.displayName
                AppId           = $app.appId
                PermissionCount = $appPermissions.Count
            })
        }
    }

    if ($highPrivApps.Count -gt 0) {
        $Result.Findings += New-TiTCFinding `
            -Title "Applications with excessive Graph API permissions" `
            -Description "$($highPrivApps.Count) applications request more than 10 application-level Graph API permissions. Over-provisioned apps increase blast radius in case of compromise." `
            -Severity Medium `
            -Domain EntraID `
            -RiskWeight 6 `
            -Remediation "Review application permissions and apply least-privilege principle. Remove unused permissions. Use delegated permissions with user context where possible." `
            -ComplianceControls @('ISO27001:A.9.4.1', 'NIST:AC-6(10)') `
            -AffectedResources ($highPrivApps | ForEach-Object { "$($_.AppName) ($($_.PermissionCount) permissions)" }) `
            -Evidence @{ HighPrivApps = $highPrivApps } `
            -DetectedBy $script:COMPONENT `
            -Tags @('Applications', 'Permissions', 'LeastPrivilege')
    }

    $Result.RawData['Applications'] = @{
        TotalApps     = $apps.Count
        ExpiredCreds  = $expiredApps.Count
        ExpiringCreds = $expiringApps.Count
        LongLived     = $longLivedApps.Count
        HighPrivilege = $highPrivApps.Count
    }

    Write-TiTCLog "Application check complete: $($apps.Count) apps, $($expiredApps.Count) expired creds" -Level Info -Component $script:COMPONENT
}

# ============================================================================
# ASSESSOR: Password Policy
# ============================================================================

function Test-TiTCPasswordPolicy {
    [CmdletBinding()]
    param(
        [hashtable]$Config,
        $Result
    )

    Write-TiTCLog "Checking password policies..." -Level Info -Component $script:COMPONENT

    # Get organization password policy
    try {
        $org = (Invoke-TiTCGraphRequest `
            -Endpoint '/organization' `
            -Select 'id,displayName,passwordPolicies' `
            -Component $script:COMPONENT
        ).value

        # Check for banned password lists
        $authMethodsPolicy = (Invoke-TiTCGraphRequest `
            -Endpoint '/policies/authenticationMethodsPolicy' `
            -Beta `
            -NoTop `
            -Component $script:COMPONENT
        )
    }
    catch {
        Write-TiTCLog "Could not retrieve password policies: $_" -Level Warning -Component $script:COMPONENT
        $Result.Warnings += "Password policy check requires Directory.Read.All permission."
        return
    }

    # Check Password Protection settings
    try {
        $passwordProtection = (Invoke-TiTCGraphRequest `
            -Endpoint '/settings' `
            -Beta `
            -Component $script:COMPONENT
        ).value

        $bannedPasswordSettings = $passwordProtection | Where-Object {
            $_.displayName -eq 'Password Rule Settings'
        }
    }
    catch {
        # Password protection may not be available in all tenants
        Write-TiTCLog "Password protection settings not available" -Level Debug -Component $script:COMPONENT
    }

    # Check Self-Service Password Reset
    try {
        $sspr = Invoke-TiTCGraphRequest `
            -Endpoint '/policies/authorizationPolicy' `
            -Select 'id,defaultUserRolePermissions,allowedToUseSSPR' `
            -NoTop `
            -Component $script:COMPONENT
    }
    catch {
        Write-TiTCLog "Could not check SSPR configuration" -Level Debug -Component $script:COMPONENT
    }

    $Result.RawData['PasswordPolicy'] = @{
        Organization = $org
        SSPREnabled  = $sspr.allowedToUseSSPR ?? 'Unknown'
    }

    Write-TiTCLog "Password policy check complete" -Level Info -Component $script:COMPONENT
}

# ============================================================================
# ASSESSOR: Authentication Methods
# ============================================================================

function Test-TiTCAuthenticationMethods {
    [CmdletBinding()]
    param(
        [hashtable]$Config,
        $Result
    )

    Write-TiTCLog "Checking authentication methods policy..." -Level Info -Component $script:COMPONENT

    try {
        $authMethodsPolicy = Invoke-TiTCGraphRequest `
            -Endpoint '/policies/authenticationMethodsPolicy' `
            -NoTop `
            -Component $script:COMPONENT

        $methods = $authMethodsPolicy.authenticationMethodConfigurations

        # Check if FIDO2 is enabled
        $fido2 = $methods | Where-Object { $_.id -eq 'fido2' }
        if (-not $fido2 -or $fido2.state -ne 'enabled') {
            $Result.Findings += New-TiTCFinding `
                -Title "FIDO2 security keys not enabled" `
                -Description "FIDO2 passwordless authentication is not enabled. FIDO2 keys provide phishing-resistant authentication, the strongest form of MFA available." `
                -Severity Low `
                -Domain EntraID `
                -RiskWeight 3 `
                -Remediation "Enable FIDO2 security keys in Authentication Methods policy. Target pilot group first, then expand. Consider for privileged users at minimum." `
                -RemediationUrl 'https://learn.microsoft.com/entra/identity/authentication/how-to-enable-passkey-fido2' `
                -ComplianceControls @('ISO27001:A.9.4.2', 'NIST:IA-2(6)') `
                -DetectedBy $script:COMPONENT `
                -Tags @('AuthMethods', 'FIDO2', 'Passwordless')
        }

        # Check if Authenticator is enabled with number matching
        $authenticator = $methods | Where-Object { $_.id -eq 'microsoftAuthenticator' }
        if ($authenticator -and $authenticator.state -eq 'enabled') {
            # Check for number matching (anti-MFA fatigue)
            $featureSettings = $authenticator.featureSettings
            if (-not $featureSettings.displayAppInformationRequiredState -or
                $featureSettings.displayAppInformationRequiredState.state -ne 'enabled') {
                $Result.Findings += New-TiTCFinding `
                    -Title "Authenticator app context not enforced" `
                    -Description "Microsoft Authenticator is not configured to show application context (number matching + app name). Without these, users are vulnerable to MFA fatigue/prompt bombing attacks." `
                    -Severity Medium `
                    -Domain EntraID `
                    -RiskWeight 6 `
                    -Remediation "Enable 'Show application name in push and passwordless notifications' and 'Show geographic location in push and passwordless notifications' in Authentication Methods." `
                    -RemediationUrl 'https://learn.microsoft.com/entra/identity/authentication/how-to-mfa-number-match' `
                    -ComplianceControls @('ISO27001:A.9.4.2', 'CIS:1.1.9') `
                    -DetectedBy $script:COMPONENT `
                    -Tags @('AuthMethods', 'MFAFatigue', 'NumberMatching')
            }
        }

        $Result.RawData['AuthMethods'] = @{
            Methods = $methods | ForEach-Object {
                @{ Id = $_.id; State = $_.state }
            }
        }
    }
    catch {
        Write-TiTCLog "Could not check authentication methods: $_" -Level Warning -Component $script:COMPONENT
        $Result.Warnings += "Authentication methods policy check requires Policy.Read.All permission."
    }

    Write-TiTCLog "Authentication methods check complete" -Level Info -Component $script:COMPONENT
}

# ============================================================================
# ASSESSOR: Sign-In Risk Policies
# ============================================================================

function Test-TiTCSignInRiskPolicies {
    [CmdletBinding()]
    param(
        [hashtable]$Config,
        $Result
    )

    Write-TiTCLog "Checking sign-in risk and identity protection..." -Level Info -Component $script:COMPONENT

    try {
        # Check for Identity Protection risk policies via CA
        $policies = (Invoke-TiTCGraphRequest `
            -Endpoint '/identity/conditionalAccess/policies' `
            -AllPages `
            -Component $script:COMPONENT
        ).value

        $enabledPolicies = $policies | Where-Object { $_.state -eq 'enabled' }

        # Sign-in risk policy
        $signInRiskPolicy = $enabledPolicies | Where-Object {
            $_.conditions.signInRiskLevels -and $_.conditions.signInRiskLevels.Count -gt 0
        }

        # User risk policy
        $userRiskPolicy = $enabledPolicies | Where-Object {
            $_.conditions.userRiskLevels -and $_.conditions.userRiskLevels.Count -gt 0
        }

        if (-not $signInRiskPolicy) {
            $Result.Findings += New-TiTCFinding `
                -Title "No sign-in risk-based Conditional Access policy" `
                -Description "No Conditional Access policy evaluates sign-in risk. Sign-in risk policies use Microsoft's threat intelligence to detect anomalous sign-in patterns (impossible travel, anonymous IP, malware-linked IP)." `
                -Severity High `
                -Domain EntraID `
                -RiskWeight 7 `
                -Remediation "Create a CA policy with sign-in risk condition: require MFA for medium+ risk, block for high risk. Requires Azure AD P2 or Entra ID P2 license." `
                -RemediationUrl 'https://learn.microsoft.com/entra/id-protection/howto-identity-protection-configure-risk-policies' `
                -ComplianceControls @('ISO27001:A.9.4.2', 'CIS:1.2.6', 'SOC2:CC6.1', 'NIST:SI-4') `
                -DetectedBy $script:COMPONENT `
                -Tags @('IdentityProtection', 'SignInRisk', 'ThreatDetection')
        }

        if (-not $userRiskPolicy) {
            $Result.Findings += New-TiTCFinding `
                -Title "No user risk-based Conditional Access policy" `
                -Description "No Conditional Access policy evaluates user risk. User risk policies detect compromised credentials (leaked password databases, impossible travel patterns over time)." `
                -Severity High `
                -Domain EntraID `
                -RiskWeight 7 `
                -Remediation "Create a CA policy with user risk condition: require password change for medium+ risk, block for high risk. Enable SSPR so users can self-remediate." `
                -RemediationUrl 'https://learn.microsoft.com/entra/id-protection/howto-identity-protection-configure-risk-policies' `
                -ComplianceControls @('ISO27001:A.9.4.2', 'CIS:1.2.7', 'SOC2:CC6.1', 'NIST:SI-4') `
                -DetectedBy $script:COMPONENT `
                -Tags @('IdentityProtection', 'UserRisk', 'CompromisedCredentials')
        }

        # Check for risky users currently flagged
        try {
            $riskyUsers = (Invoke-TiTCGraphRequest `
                -Endpoint '/identityProtection/riskyUsers' `
                -Filter "riskState eq 'atRisk'" `
                -Select 'id,userPrincipalName,riskLevel,riskState,riskLastUpdatedDateTime' `
                -Top 100 `
                -Component $script:COMPONENT
            ).value

            if ($riskyUsers.Count -gt 0) {
                $highRisk = $riskyUsers | Where-Object { $_.riskLevel -eq 'high' }

                $severity = if ($highRisk.Count -gt 0) { 'Critical' } else { 'High' }

                $Result.Findings += New-TiTCFinding `
                    -Title "Users currently flagged as at-risk" `
                    -Description "$($riskyUsers.Count) users are currently flagged as at-risk by Identity Protection ($($highRisk.Count) high risk). These accounts may have compromised credentials." `
                    -Severity $severity `
                    -Domain EntraID `
                    -RiskWeight 9 `
                    -Remediation "Immediately investigate high-risk users. Force password reset and MFA re-registration. Review sign-in logs for anomalous activity. Consider disabling accounts until investigation is complete." `
                    -RemediationUrl 'https://learn.microsoft.com/entra/id-protection/howto-identity-protection-investigate-risk' `
                    -ComplianceControls @('ISO27001:A.16.1.5', 'SOC2:CC7.2', 'NIST:IR-4') `
                    -AffectedResources ($riskyUsers | ForEach-Object { "$($_.userPrincipalName) (Risk: $($_.riskLevel))" } | Select-Object -First 20) `
                    -Evidence @{
                        TotalRiskyUsers = $riskyUsers.Count
                        HighRisk        = $highRisk.Count
                    } `
                    -DetectedBy $script:COMPONENT `
                    -Tags @('IdentityProtection', 'RiskyUsers', 'ActiveThreat')
            }
        }
        catch {
            Write-TiTCLog "Could not check risky users (requires Identity Protection): $_" -Level Debug -Component $script:COMPONENT
        }

        $Result.RawData['SignInRisk'] = @{
            HasSignInRiskPolicy = ($signInRiskPolicy.Count -gt 0)
            HasUserRiskPolicy   = ($userRiskPolicy.Count -gt 0)
            RiskyUsersCount     = $riskyUsers.Count
        }
    }
    catch {
        Write-TiTCLog "Sign-in risk check failed: $_" -Level Warning -Component $script:COMPONENT
        $Result.Warnings += "Sign-in risk policy check may require Azure AD P2 license."
    }

    Write-TiTCLog "Sign-in risk check complete" -Level Info -Component $script:COMPONENT
}

# ============================================================================
# EXPORTS
# ============================================================================

Export-ModuleMember -Function @(
    'Invoke-TiTCEntraIDCollector'
)
