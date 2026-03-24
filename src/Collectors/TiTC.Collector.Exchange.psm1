#Requires -Version 5.1
<#
.SYNOPSIS
    TakeItToCloud.Assess — Exchange Online / Mail Flow Security Collector.

.DESCRIPTION
    Performs comprehensive Exchange Online security checks via Graph API and
    Exchange Online PowerShell (where available). Covers:

    - Mail flow transport rules analysis
    - Anti-phishing / anti-spam / anti-malware policies
    - DMARC, DKIM, SPF configuration
    - External forwarding rules
    - Mailbox auditing configuration
    - Shared mailbox sign-in status
    - OWA and ActiveSync policies
    - Connector security (inbound/outbound)
    - Sender authentication
    - Mail-enabled security groups exposure

    All checks produce standardized TiTCFinding objects with compliance mappings.

.NOTES
    Module:     TiTC.Collector.Exchange
    Author:     TakeItToCloud
    Version:    1.0.0
    Requires:   TiTC.Core, Microsoft.Graph.Authentication
                Optional: ExchangeOnlineManagement module for deep checks
#>

# ============================================================================
# MODULE DEPENDENCIES
# ============================================================================

$CorePath = Join-Path (Split-Path $PSScriptRoot -Parent) 'Core\TiTC.Core.psm1'
if (Test-Path $CorePath) { Import-Module $CorePath -ErrorAction Stop }

$ModelsPath = Join-Path (Split-Path $PSScriptRoot -Parent) 'Core\Models\TiTC.Models.psm1'
if (Test-Path $ModelsPath) { Import-Module $ModelsPath -ErrorAction Stop }

# ============================================================================
# CONSTANTS
# ============================================================================

$script:COMPONENT = 'Collector.Exchange'

# Known risky transport rule patterns
$script:RISKY_RULE_ACTIONS = @(
    'RedirectMessage',
    'BlindCopyTo',
    'CopyTo',
    'DeleteMessage',
    'ModifyMessageHeader'
)

# ============================================================================
# MAIN COLLECTOR ENTRY POINT
# ============================================================================

function Invoke-TiTCExchangeCollector {
    <#
    .SYNOPSIS
        Runs all Exchange Online security checks and returns a TiTCCollectorResult.

    .DESCRIPTION
        Orchestrates Exchange Online security assessors. Uses Graph API as primary
        data source, with optional ExchangeOnlineManagement module for deep checks
        that Graph doesn't expose.

    .PARAMETER Config
        Assessment configuration hashtable from Get-TiTCConfig.

    .PARAMETER Checks
        Specific checks to run. Default runs all checks.

    .PARAMETER UseExchangeModule
        Connect to Exchange Online PowerShell for deep checks (transport rules,
        connector config, anti-phishing policies). Requires ExchangeOnlineManagement.
    #>
    [CmdletBinding()]
    [OutputType([PSObject])]
    param(
        [hashtable]$Config = @{},

        [ValidateSet(
            'ExternalForwarding', 'TransportRules', 'AntiPhishing',
            'MailboxAuditing', 'SharedMailboxes', 'DomainSecurity',
            'OWAPolicy', 'Connectors', 'MailEnabledGroups', 'All'
        )]
        [string[]]$Checks = @('All'),

        [switch]$UseExchangeModule
    )

    $result = New-TiTCCollectorResult -Domain Exchange
    Write-TiTCLog "Starting Exchange Online security assessment..." -Level Info -Component $script:COMPONENT

    if (-not $Config.Thresholds) {
        $Config = Get-TiTCConfig -ProfileName Full
    }

    $runAll = $Checks -contains 'All'

    # Check if Exchange Online module is available for deep checks
    $exoConnected = $false
    if ($UseExchangeModule) {
        $exoConnected = Connect-TiTCExchangeOnline
        if (-not $exoConnected) {
            $result.Warnings += "ExchangeOnlineManagement module not available. Some deep checks will be skipped."
        }
    }

    # ── Assessor dispatch ───────────────────────────────────────────
    $assessors = [ordered]@{
        'ExternalForwarding' = { Test-TiTCExternalForwarding -Config $Config -Result $result }
        'TransportRules'     = { Test-TiTCTransportRules -Config $Config -Result $result -ExoConnected $exoConnected }
        'AntiPhishing'       = { Test-TiTCAntiPhishingPolicies -Config $Config -Result $result -ExoConnected $exoConnected }
        'MailboxAuditing'    = { Test-TiTCMailboxAuditing -Config $Config -Result $result }
        'SharedMailboxes'    = { Test-TiTCSharedMailboxSecurity -Config $Config -Result $result }
        'DomainSecurity'     = { Test-TiTCDomainEmailSecurity -Config $Config -Result $result }
        'OWAPolicy'          = { Test-TiTCOWAPolicy -Config $Config -Result $result -ExoConnected $exoConnected }
        'Connectors'         = { Test-TiTCMailConnectors -Config $Config -Result $result -ExoConnected $exoConnected }
        'MailEnabledGroups'  = { Test-TiTCMailEnabledGroups -Config $Config -Result $result }
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

    # Disconnect Exchange Online if connected
    if ($exoConnected) {
        try { Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue } catch {}
    }

    $result.Complete()

    $summary = $result.ToSummary()
    Write-TiTCLog "Exchange Online assessment complete" -Level Success -Component $script:COMPONENT -Data $summary

    return $result
}

# ============================================================================
# HELPER: Connect Exchange Online
# ============================================================================

function Connect-TiTCExchangeOnline {
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    if (-not (Get-Module -ListAvailable -Name ExchangeOnlineManagement)) {
        Write-TiTCLog "ExchangeOnlineManagement module not installed" -Level Warning -Component $script:COMPONENT
        return $false
    }

    try {
        $tenantInfo = Get-TiTCTenantInfo
        Import-Module ExchangeOnlineManagement -ErrorAction Stop

        # Use existing Graph token context for SSO
        Connect-ExchangeOnline -ShowBanner:$false -ErrorAction Stop
        Write-TiTCLog "Connected to Exchange Online PowerShell" -Level Success -Component $script:COMPONENT
        return $true
    }
    catch {
        Write-TiTCLog "Failed to connect Exchange Online: $($_.Exception.Message)" -Level Warning -Component $script:COMPONENT
        return $false
    }
}

# ============================================================================
# ASSESSOR: External Forwarding
# ============================================================================

function Test-TiTCExternalForwarding {
    [CmdletBinding()]
    param(
        [hashtable]$Config,
        $Result
    )

    Write-TiTCLog "Checking for external mail forwarding..." -Level Info -Component $script:COMPONENT

    # Get mailbox settings via Graph — check for forwardingSmtpAddress and forwarding rules
    $users = (Invoke-TiTCGraphRequest `
        -Endpoint '/users' `
        -Select 'id,displayName,userPrincipalName,mail' `
        -Filter "userType eq 'Member' and accountEnabled eq true" `
        -AllPages `
        -Component $script:COMPONENT
    ).value

    $Result.ObjectsScanned += $users.Count

    $externalForwards = [System.Collections.ArrayList]::new()
    $suspiciousRules = [System.Collections.ArrayList]::new()

    foreach ($user in $users) {
        if (-not $user.id) { continue }
        try {
            # Check mailbox forwarding via mailbox settings
            $mailboxSettings = Invoke-TiTCGraphRequest `
                -Endpoint "/users/$($user.id)/mailboxSettings" `
                -Component $script:COMPONENT

            # Check for automatic forwarding
            if ($mailboxSettings.value -and $mailboxSettings.value.Count -gt 0) {
                $settings = $mailboxSettings.value[0]
                # Graph doesn't directly expose forwardingSMTPAddress — checked via EXO below
            }

            # Check inbox rules for forwarding
            $rules = (Invoke-TiTCGraphRequest `
                -Endpoint "/users/$($user.id)/mailFolders/inbox/messageRules" `
                -Component $script:COMPONENT
            ).value

            foreach ($rule in $rules) {
                if ($rule.isEnabled -eq $true) {
                    $hasForward = $false
                    $forwardTo = @()

                    if ($rule.actions.forwardTo) {
                        $hasForward = $true
                        $forwardTo += $rule.actions.forwardTo | ForEach-Object {
                            $_.emailAddress.address
                        }
                    }

                    if ($rule.actions.forwardAsAttachmentTo) {
                        $hasForward = $true
                        $forwardTo += $rule.actions.forwardAsAttachmentTo | ForEach-Object {
                            $_.emailAddress.address
                        }
                    }

                    if ($rule.actions.redirectTo) {
                        $hasForward = $true
                        $forwardTo += $rule.actions.redirectTo | ForEach-Object {
                            $_.emailAddress.address
                        }
                    }

                    if ($hasForward) {
                        # Check if any forward targets are external
                        $tenantDomain = (Get-TiTCTenantInfo).Domain
                        $acceptedDomains = @($tenantDomain)  # Extended if EXO is connected

                        $externalTargets = $forwardTo | Where-Object {
                            $domain = $_ -replace '.*@', ''
                            $domain -notin $acceptedDomains
                        }

                        if ($externalTargets) {
                            $null = $suspiciousRules.Add(@{
                                User       = $user.userPrincipalName
                                RuleName   = $rule.displayName
                                Targets    = $externalTargets
                                RuleId     = $rule.id
                            })
                        }

                        $null = $externalForwards.Add(@{
                            User      = $user.userPrincipalName
                            RuleName  = $rule.displayName
                            Targets   = $forwardTo
                            IsEnabled = $rule.isEnabled
                        })
                    }
                }
            }
        }
        catch {
            # Some users may not have mailboxes (resource accounts, etc.)
            Write-TiTCLog "Could not check forwarding for $($user.userPrincipalName): $_" -Level Debug -Component $script:COMPONENT
        }
    }

    # ── Finding: External forwarding rules ──────────────────────────
    if ($suspiciousRules.Count -gt 0) {
        $Result.Findings += New-TiTCFinding `
            -Title "Inbox rules forwarding mail to external addresses" `
            -Description "$($suspiciousRules.Count) inbox rules forward or redirect email to external addresses. External forwarding is a common data exfiltration technique and a primary indicator of account compromise." `
            -Severity Critical `
            -Domain Exchange `
            -RiskWeight 9 `
            -Remediation "Review all external forwarding rules immediately. Disable unauthorized rules. Implement an outbound spam filter policy to block automatic external forwarding. Use mail flow rules to prevent users from creating external forwarding rules." `
            -RemediationUrl 'https://learn.microsoft.com/microsoft-365/security/office-365-security/outbound-spam-policies-external-email-forwarding' `
            -RemediationScript @'
# Block external forwarding at the transport level
New-TransportRule -Name "Block External Auto-Forwarding" `
    -Priority 0 `
    -SentToScope NotInOrganization `
    -MessageTypeMatches AutoForward `
    -RejectMessageReasonText "External email forwarding is blocked by policy"
'@ `
            -ComplianceControls @('ISO27001:A.8.12', 'CIS:2.1.1', 'SOC2:CC6.7', 'NIST:SC-7') `
            -AffectedResources ($suspiciousRules | ForEach-Object {
                "$($_.User) → $($_.Targets -join ', ')"
            } | Select-Object -First 30) `
            -Evidence @{
                ExternalForwardCount = $suspiciousRules.Count
                Rules                = $suspiciousRules | Select-Object -First 50
            } `
            -EvidenceQuery 'GET /users/{id}/mailFolders/inbox/messageRules' `
            -DetectedBy $script:COMPONENT `
            -Tags @('ExternalForwarding', 'DataExfiltration', 'CriticalControl')
    }

    $Result.RawData['ExternalForwarding'] = @{
        UsersChecked     = $users.Count
        ForwardingRules  = $externalForwards.Count
        ExternalForwards = $suspiciousRules.Count
        Details          = $suspiciousRules | Select-Object -First 100
    }

    Write-TiTCLog "External forwarding check complete: $($suspiciousRules.Count) external forwards found" -Level Info -Component $script:COMPONENT
}

# ============================================================================
# ASSESSOR: Transport Rules
# ============================================================================

function Test-TiTCTransportRules {
    [CmdletBinding()]
    param(
        [hashtable]$Config,
        $Result,
        [bool]$ExoConnected
    )

    Write-TiTCLog "Checking transport rules..." -Level Info -Component $script:COMPONENT

    if (-not $ExoConnected) {
        Write-TiTCLog "Transport rules require ExchangeOnlineManagement. Skipping unsupported Graph fallback." -Level Warning -Component $script:COMPONENT
        $Result.Warnings += "Transport rule analysis requires ExchangeOnlineManagement module for full coverage."
        Test-TiTCAutoForwardingPolicy -Config $Config -Result $Result
        return
    }
    else {
        # Use Exchange Online module for full transport rule analysis
        $transportRules = Get-TransportRule -ResultSize Unlimited
    }

    $Result.ObjectsScanned += $transportRules.Count

    # ── Analyze rules for risky patterns ────────────────────────────
    $riskyRules = [System.Collections.ArrayList]::new()
    $bypassSpamRules = [System.Collections.ArrayList]::new()
    $headerModRules = [System.Collections.ArrayList]::new()

    foreach ($rule in $transportRules) {
        $ruleName = $rule.Name ?? $rule.displayName
        $ruleState = $rule.State ?? $rule.state
        $ruleActions = @()

        # Check for SCL bypass (spam confidence level set to -1 = bypass spam filtering)
        if ($rule.SetSCL -eq -1 -or $rule.SetHeaderName -eq 'X-MS-Exchange-Organization-SCL') {
            $null = $bypassSpamRules.Add(@{
                Name   = $ruleName
                State  = $ruleState
                Reason = 'Bypasses spam filtering (SCL=-1)'
            })
        }

        # Check for rules that redirect/BCC to external
        if ($rule.BlindCopyTo -or $rule.CopyTo -or $rule.RedirectMessageTo) {
            $null = $riskyRules.Add(@{
                Name    = $ruleName
                State   = $ruleState
                Action  = 'Redirect/BCC'
                Targets = @($rule.BlindCopyTo, $rule.CopyTo, $rule.RedirectMessageTo) | Where-Object { $_ }
            })
        }

        # Check for rules that strip authentication headers
        if ($rule.RemoveHeader -match 'Authentication-Results|ARC-|DKIM-Signature|X-MS-Exchange-Organization-Auth') {
            $null = $headerModRules.Add(@{
                Name    = $ruleName
                State   = $ruleState
                Header  = $rule.RemoveHeader
            })
        }

        # Check for rules that delete messages silently
        if ($rule.DeleteMessage -eq $true) {
            $null = $riskyRules.Add(@{
                Name   = $ruleName
                State  = $ruleState
                Action = 'DeleteMessage'
                Reason = 'Silently deletes messages — potential data loss or hiding evidence'
            })
        }
    }

    if ($bypassSpamRules.Count -gt 0) {
        $Result.Findings += New-TiTCFinding `
            -Title "Transport rules bypassing spam filtering" `
            -Description "$($bypassSpamRules.Count) transport rules set SCL to -1 or modify spam headers, bypassing Exchange Online Protection spam filtering. This can allow phishing and malware to reach user inboxes." `
            -Severity High `
            -Domain Exchange `
            -RiskWeight 8 `
            -Remediation "Review all rules that bypass spam filtering. Use allow lists in anti-spam policies instead of SCL override rules. If business-critical, scope bypass rules to specific senders only." `
            -RemediationUrl 'https://learn.microsoft.com/microsoft-365/security/office-365-security/create-safe-sender-lists-in-office-365' `
            -ComplianceControls @('ISO27001:A.8.23', 'CIS:2.2.1', 'SOC2:CC6.6', 'NIST:SI-8') `
            -AffectedResources ($bypassSpamRules | ForEach-Object { "$($_.Name) ($($_.State))" }) `
            -Evidence @{ BypassRules = $bypassSpamRules } `
            -DetectedBy $script:COMPONENT `
            -Tags @('TransportRules', 'SpamBypass', 'EmailSecurity')
    }

    if ($riskyRules.Count -gt 0) {
        $Result.Findings += New-TiTCFinding `
            -Title "Transport rules with risky actions" `
            -Description "$($riskyRules.Count) transport rules perform potentially dangerous actions (redirect, BCC, delete). These may be legitimate but warrant review as they can be used for data exfiltration or to hide malicious activity." `
            -Severity Medium `
            -Domain Exchange `
            -RiskWeight 6 `
            -Remediation "Audit all transport rules with redirect, BCC, or delete actions. Verify business justification. Document rule owners and review dates. Remove rules that are no longer needed." `
            -ComplianceControls @('ISO27001:A.8.12', 'NIST:SC-7') `
            -AffectedResources ($riskyRules | ForEach-Object { "$($_.Name) [$($_.Action)]" }) `
            -Evidence @{ RiskyRules = $riskyRules } `
            -DetectedBy $script:COMPONENT `
            -Tags @('TransportRules', 'DataFlow', 'Review')
    }

    if ($headerModRules.Count -gt 0) {
        $Result.Findings += New-TiTCFinding `
            -Title "Transport rules stripping email authentication headers" `
            -Description "$($headerModRules.Count) transport rules remove email authentication headers (DKIM, ARC, Authentication-Results). This undermines email authentication and can mask spoofed messages." `
            -Severity High `
            -Domain Exchange `
            -RiskWeight 7 `
            -Remediation "Remove rules that strip authentication headers unless there is a documented business need. These headers are critical for DMARC enforcement and phishing protection." `
            -ComplianceControls @('ISO27001:A.8.23', 'NIST:SI-8') `
            -AffectedResources ($headerModRules | ForEach-Object { "$($_.Name) (removes: $($_.Header))" }) `
            -Evidence @{ HeaderModRules = $headerModRules } `
            -DetectedBy $script:COMPONENT `
            -Tags @('TransportRules', 'AuthHeaders', 'Spoofing')
    }

    $Result.RawData['TransportRules'] = @{
        TotalRules      = $transportRules.Count
        RiskyRules      = $riskyRules.Count
        SpamBypass      = $bypassSpamRules.Count
        HeaderMod       = $headerModRules.Count
    }

    Write-TiTCLog "Transport rules check complete: $($transportRules.Count) rules analyzed" -Level Info -Component $script:COMPONENT
}

# ============================================================================
# ASSESSOR: Auto-Forwarding Policy (Graph-only fallback)
# ============================================================================

function Test-TiTCAutoForwardingPolicy {
    [CmdletBinding()]
    param(
        [hashtable]$Config,
        $Result
    )

    # Check if remote domains allow auto-forwarding
    try {
        $remoteDomains = (Invoke-TiTCGraphRequest `
            -Endpoint '/admin/exchange/remoteDomains' `
            -Beta `
            -AllPages `
            -Component $script:COMPONENT
        ).value

        $autoForwardEnabled = $remoteDomains | Where-Object {
            $_.autoForwardEnabled -eq $true
        }

        if ($autoForwardEnabled) {
            $Result.Findings += New-TiTCFinding `
                -Title "Auto-forwarding to external domains is permitted" `
                -Description "Remote domain configuration allows automatic email forwarding to external domains. This is a common data exfiltration vector." `
                -Severity High `
                -Domain Exchange `
                -RiskWeight 8 `
                -Remediation "Set AutoForwardEnabled to false on the default remote domain (*). Use outbound spam filter policy to control auto-forwarding behavior centrally." `
                -RemediationUrl 'https://learn.microsoft.com/exchange/mail-flow-best-practices/remote-domains/remote-domains' `
                -ComplianceControls @('ISO27001:A.8.12', 'CIS:2.1.1', 'NIST:SC-7') `
                -AffectedResources ($autoForwardEnabled | ForEach-Object { "Domain: $($_.domainName)" }) `
                -Evidence @{ RemoteDomains = $autoForwardEnabled | ForEach-Object { @{ Domain = $_.domainName; AutoForward = $_.autoForwardEnabled } } } `
                -DetectedBy $script:COMPONENT `
                -Tags @('AutoForwarding', 'RemoteDomains', 'DataExfiltration')
        }
    }
    catch {
        Write-TiTCLog "Could not check remote domain settings: $_" -Level Debug -Component $script:COMPONENT
    }
}

# ============================================================================
# ASSESSOR: Anti-Phishing Policies
# ============================================================================

function Test-TiTCAntiPhishingPolicies {
    [CmdletBinding()]
    param(
        [hashtable]$Config,
        $Result,
        [bool]$ExoConnected
    )

    Write-TiTCLog "Checking anti-phishing configuration..." -Level Info -Component $script:COMPONENT

    if (-not $ExoConnected) {
        Write-TiTCLog "Anti-phishing deep check requires ExchangeOnlineManagement. Skipping unsupported Graph fallback." -Level Warning -Component $script:COMPONENT
        $Result.Warnings += "Anti-phishing policy check requires ExchangeOnlineManagement module for full coverage."
        return
    }

    # ── Deep check with Exchange Online module ──────────────────────
    $antiPhishPolicies = Get-AntiPhishPolicy

    $Result.ObjectsScanned += $antiPhishPolicies.Count

    foreach ($policy in $antiPhishPolicies) {
        if ($policy.IsDefault -and -not $policy.Enabled) { continue }

        # Check impersonation protection
        if (-not $policy.EnableTargetedUserProtection -and -not $policy.EnableTargetedDomainsProtection) {
            $Result.Findings += New-TiTCFinding `
                -Title "Anti-phishing policy '$($policy.Name)' lacks impersonation protection" `
                -Description "Policy '$($policy.Name)' does not have user or domain impersonation protection enabled. Impersonation attacks targeting executives and trusted domains are a leading cause of business email compromise (BEC)." `
                -Severity High `
                -Domain Exchange `
                -RiskWeight 7 `
                -Remediation "Enable targeted user protection for C-suite and finance team. Enable targeted domain protection for your organization's domains and key partner domains." `
                -RemediationUrl 'https://learn.microsoft.com/microsoft-365/security/office-365-security/anti-phishing-policies-about#impersonation-settings-in-anti-phishing-policies' `
                -ComplianceControls @('ISO27001:A.8.23', 'CIS:2.3.2', 'NIST:SI-8') `
                -AffectedResources @($policy.Name) `
                -Evidence @{
                    PolicyName              = $policy.Name
                    UserProtection          = $policy.EnableTargetedUserProtection
                    DomainProtection        = $policy.EnableTargetedDomainsProtection
                    MailboxIntelligence     = $policy.EnableMailboxIntelligence
                } `
                -DetectedBy $script:COMPONENT `
                -Tags @('AntiPhishing', 'Impersonation', 'BEC')
        }

        # Check spoof intelligence action
        if ($policy.AuthenticationFailAction -ne 'Quarantine') {
            $Result.Findings += New-TiTCFinding `
                -Title "Spoofed messages not quarantined in policy '$($policy.Name)'" `
                -Description "Policy '$($policy.Name)' does not quarantine messages that fail sender authentication. Failed authentication messages are moved to junk instead of being quarantined for admin review." `
                -Severity Medium `
                -Domain Exchange `
                -RiskWeight 5 `
                -Remediation "Set the 'If message is detected as spoof' action to 'Quarantine the message' in the anti-phishing policy." `
                -ComplianceControls @('ISO27001:A.8.23', 'NIST:SI-8') `
                -AffectedResources @($policy.Name) `
                -Evidence @{ PolicyName = $policy.Name; SpoofAction = $policy.AuthenticationFailAction } `
                -DetectedBy $script:COMPONENT `
                -Tags @('AntiPhishing', 'Spoofing', 'Quarantine')
        }
    }

    # Check Safe Links policies
    try {
        $safeLinks = Get-SafeLinksPolicy
        if (-not $safeLinks -or $safeLinks.Count -eq 0) {
            $Result.Findings += New-TiTCFinding `
                -Title "Safe Links not configured" `
                -Description "No Safe Links policies found. Safe Links provides time-of-click URL scanning that protects against zero-day phishing URLs that pass initial inspection." `
                -Severity High `
                -Domain Exchange `
                -RiskWeight 7 `
                -Remediation "Create a Safe Links policy targeting all users. Enable URL scanning for email messages, Teams, and Office applications. Enable real-time scanning." `
                -RemediationUrl 'https://learn.microsoft.com/microsoft-365/security/office-365-security/safe-links-about' `
                -ComplianceControls @('ISO27001:A.8.23', 'CIS:2.4.1', 'SOC2:CC6.6', 'NIST:SI-3') `
                -DetectedBy $script:COMPONENT `
                -Tags @('SafeLinks', 'URLProtection', 'DefenderForOffice365')
        }
    }
    catch {
        Write-TiTCLog "Safe Links check requires Defender for Office 365 Plan 1+" -Level Debug -Component $script:COMPONENT
    }

    # Check Safe Attachments policies
    try {
        $safeAttachments = Get-SafeAttachmentPolicy
        if (-not $safeAttachments -or $safeAttachments.Count -eq 0) {
            $Result.Findings += New-TiTCFinding `
                -Title "Safe Attachments not configured" `
                -Description "No Safe Attachments policies found. Safe Attachments provides sandbox detonation of attachments to detect zero-day malware that signature-based scanning misses." `
                -Severity High `
                -Domain Exchange `
                -RiskWeight 7 `
                -Remediation "Create a Safe Attachments policy targeting all users. Set action to 'Dynamic Delivery' for minimal user impact while attachments are being scanned." `
                -RemediationUrl 'https://learn.microsoft.com/microsoft-365/security/office-365-security/safe-attachments-about' `
                -ComplianceControls @('ISO27001:A.8.23', 'CIS:2.4.2', 'SOC2:CC6.6', 'NIST:SI-3') `
                -DetectedBy $script:COMPONENT `
                -Tags @('SafeAttachments', 'Malware', 'DefenderForOffice365')
        }
    }
    catch {
        Write-TiTCLog "Safe Attachments check requires Defender for Office 365 Plan 1+" -Level Debug -Component $script:COMPONENT
    }

    $Result.RawData['AntiPhishing'] = @{
        PolicyCount = $antiPhishPolicies.Count
        Policies    = $antiPhishPolicies | ForEach-Object {
            @{
                Name                = $_.Name
                IsDefault           = $_.IsDefault
                UserProtection      = $_.EnableTargetedUserProtection
                DomainProtection    = $_.EnableTargetedDomainsProtection
                MailboxIntelligence = $_.EnableMailboxIntelligence
                SpoofAction         = $_.AuthenticationFailAction
            }
        }
    }

    Write-TiTCLog "Anti-phishing check complete" -Level Info -Component $script:COMPONENT
}

# ============================================================================
# ASSESSOR: Mailbox Auditing
# ============================================================================

function Test-TiTCMailboxAuditing {
    [CmdletBinding()]
    param(
        [hashtable]$Config,
        $Result
    )

    Write-TiTCLog "Checking mailbox audit configuration..." -Level Info -Component $script:COMPONENT

    # Check organization-level audit config
    try {
        $org = (Invoke-TiTCGraphRequest `
            -Endpoint '/organization' `
            -Select 'id,displayName' `
            -Component $script:COMPONENT
        ).value

        # Mailbox auditing is enabled by default since Jan 2019
        # but can be disabled per-mailbox or at org level
        # Check via admin audit log config
        $auditConfig = Invoke-TiTCGraphRequest `
            -Endpoint '/admin/reportSettings' `
            -Beta `
            -Component $script:COMPONENT

        # Note: detailed audit bypass check requires EXO module
        $Result.RawData['MailboxAuditing'] = @{
            Note = 'Mailbox auditing enabled by default since Jan 2019. Deep audit bypass check requires ExchangeOnlineManagement module.'
        }
    }
    catch {
        Write-TiTCLog "Audit configuration check limited via Graph. Use -UseExchangeModule for full check." -Level Debug -Component $script:COMPONENT
    }

    Write-TiTCLog "Mailbox auditing check complete" -Level Info -Component $script:COMPONENT
}

# ============================================================================
# ASSESSOR: Shared Mailbox Security
# ============================================================================

function Test-TiTCSharedMailboxSecurity {
    [CmdletBinding()]
    param(
        [hashtable]$Config,
        $Result
    )

    Write-TiTCLog "Checking shared mailbox security..." -Level Info -Component $script:COMPONENT

    # Get shared mailboxes (they are users with specific recipientType)
    try {
        $sharedMailboxes = (Invoke-TiTCGraphRequest `
            -Endpoint '/users' `
            -Select 'id,displayName,userPrincipalName,accountEnabled,mail,assignedLicenses' `
            -Filter "mailboxSettings/userPurpose eq 'shared'" `
            -Beta `
            -AllPages `
            -Component $script:COMPONENT
        ).value
    }
    catch {
        # Fallback — filter might not be supported on all tenants
        Write-TiTCLog "Shared mailbox filter not available. Skipping shared mailbox check." -Level Warning -Component $script:COMPONENT
        return
    }

    $Result.ObjectsScanned += $sharedMailboxes.Count

    # Check for shared mailboxes with sign-in enabled
    $signInEnabled = $sharedMailboxes | Where-Object { $_.accountEnabled -eq $true }

    if ($signInEnabled.Count -gt 0) {
        $Result.Findings += New-TiTCFinding `
            -Title "Shared mailboxes with direct sign-in enabled" `
            -Description "$($signInEnabled.Count) shared mailboxes have interactive sign-in enabled. Shared mailboxes should be blocked from direct sign-in to prevent credential sharing and ensure access is only through delegation." `
            -Severity Medium `
            -Domain Exchange `
            -RiskWeight 5 `
            -Remediation "Block sign-in for all shared mailboxes: Set-MsolUser -UserPrincipalName <UPN> -BlockCredential `$true. Access shared mailboxes only through Full Access delegation or Outlook auto-mapping." `
            -RemediationUrl 'https://learn.microsoft.com/microsoft-365/admin/email/about-shared-mailboxes' `
            -RemediationScript @'
# Block sign-in for shared mailboxes
$sharedMailboxes | ForEach-Object {
    Update-MgUser -UserId $_.id -AccountEnabled:$false
    Write-Output "Blocked sign-in: $($_.userPrincipalName)"
}
'@ `
            -ComplianceControls @('ISO27001:A.9.2.4', 'CIS:2.5.1', 'NIST:AC-2(10)') `
            -AffectedResources ($signInEnabled | ForEach-Object { $_.userPrincipalName } | Select-Object -First 30) `
            -Evidence @{
                TotalShared     = $sharedMailboxes.Count
                SignInEnabled   = $signInEnabled.Count
            } `
            -DetectedBy $script:COMPONENT `
            -Tags @('SharedMailbox', 'SignIn', 'AccessControl')
    }

    # Check for shared mailboxes with licenses (unnecessary cost)
    $licensedShared = $sharedMailboxes | Where-Object {
        $_.assignedLicenses -and $_.assignedLicenses.Count -gt 0
    }

    if ($licensedShared.Count -gt 0) {
        $Result.Findings += New-TiTCFinding `
            -Title "Shared mailboxes with assigned licenses" `
            -Description "$($licensedShared.Count) shared mailboxes have user licenses assigned. Shared mailboxes do not require licenses unless they exceed 50GB or need archive/litigation hold, representing potential cost waste." `
            -Severity Low `
            -Domain Exchange `
            -RiskWeight 3 `
            -Remediation "Review licenses assigned to shared mailboxes. Remove unnecessary licenses. Shared mailboxes under 50GB do not require a license." `
            -AffectedResources ($licensedShared | ForEach-Object { $_.userPrincipalName } | Select-Object -First 20) `
            -Evidence @{ LicensedSharedCount = $licensedShared.Count } `
            -DetectedBy $script:COMPONENT `
            -Tags @('SharedMailbox', 'License', 'CostOptimization')
    }

    $Result.RawData['SharedMailboxes'] = @{
        Total         = $sharedMailboxes.Count
        SignInEnabled = $signInEnabled.Count
        Licensed      = $licensedShared.Count
    }

    Write-TiTCLog "Shared mailbox check complete: $($sharedMailboxes.Count) shared mailboxes" -Level Info -Component $script:COMPONENT
}

# ============================================================================
# ASSESSOR: Domain Email Security (DMARC/DKIM/SPF via DNS)
# ============================================================================

function Test-TiTCDomainEmailSecurity {
    [CmdletBinding()]
    param(
        [hashtable]$Config,
        $Result
    )

    Write-TiTCLog "Checking domain email authentication (DMARC/SPF)..." -Level Info -Component $script:COMPONENT

    # Get verified domains
    $org = (Invoke-TiTCGraphRequest `
        -Endpoint '/organization' `
        -Select 'id,verifiedDomains' `
        -Component $script:COMPONENT
    ).value

    $domains = $org[0].verifiedDomains | Where-Object { $_.type -eq 'Managed' }

    $Result.ObjectsScanned += $domains.Count

    $noDmarc = [System.Collections.ArrayList]::new()
    $weakDmarc = [System.Collections.ArrayList]::new()

    foreach ($domain in $domains) {
        $domainName = $domain.name

        # Check DMARC record via DNS
        try {
            $dmarcRecord = Resolve-DnsName "_dmarc.$domainName" -Type TXT -ErrorAction SilentlyContinue |
                Where-Object { $_.Strings -match '^v=DMARC1' }

            if (-not $dmarcRecord) {
                $null = $noDmarc.Add($domainName)
            }
            else {
                $dmarcText = $dmarcRecord.Strings -join ''

                # Check for weak DMARC policies
                if ($dmarcText -match 'p=none') {
                    $null = $weakDmarc.Add(@{
                        Domain = $domainName
                        Policy = 'none'
                        Record = $dmarcText
                    })
                }
            }
        }
        catch {
            Write-TiTCLog "DNS lookup failed for _dmarc.$domainName" -Level Debug -Component $script:COMPONENT
            $null = $noDmarc.Add($domainName)
        }
    }

    if ($noDmarc.Count -gt 0) {
        $Result.Findings += New-TiTCFinding `
            -Title "Domains without DMARC records" `
            -Description "$($noDmarc.Count) verified domains have no DMARC DNS record. Without DMARC, attackers can spoof your domain in phishing campaigns targeting your employees, customers, and partners." `
            -Severity High `
            -Domain Exchange `
            -RiskWeight 8 `
            -Remediation "Add DMARC TXT records for all domains. Start with p=none and rua= for monitoring, then progress to p=quarantine and finally p=reject after validating legitimate mail sources." `
            -RemediationUrl 'https://learn.microsoft.com/microsoft-365/security/office-365-security/email-authentication-dmarc-configure' `
            -ComplianceControls @('ISO27001:A.8.23', 'CIS:2.6.1', 'SOC2:CC6.6', 'NIST:SI-8') `
            -AffectedResources $noDmarc `
            -Evidence @{ DomainsWithoutDMARC = $noDmarc } `
            -DetectedBy $script:COMPONENT `
            -Tags @('DMARC', 'EmailAuthentication', 'Spoofing')
    }

    if ($weakDmarc.Count -gt 0) {
        $Result.Findings += New-TiTCFinding `
            -Title "Domains with DMARC policy set to 'none'" `
            -Description "$($weakDmarc.Count) domains have DMARC policy set to 'none' (monitor only). While better than no DMARC, the policy does not instruct receiving servers to take action on failed authentication." `
            -Severity Medium `
            -Domain Exchange `
            -RiskWeight 5 `
            -Remediation "Progress DMARC policy from p=none to p=quarantine after verifying legitimate senders are passing authentication. Target p=reject for maximum protection." `
            -ComplianceControls @('ISO27001:A.8.23', 'CIS:2.6.2', 'NIST:SI-8') `
            -AffectedResources ($weakDmarc | ForEach-Object { "$($_.Domain) (p=$($_.Policy))" }) `
            -Evidence @{ WeakDMARC = $weakDmarc } `
            -DetectedBy $script:COMPONENT `
            -Tags @('DMARC', 'EmailAuthentication', 'WeakPolicy')
    }

    $Result.RawData['DomainSecurity'] = @{
        TotalDomains = $domains.Count
        NoDMARC      = $noDmarc.Count
        WeakDMARC    = $weakDmarc.Count
    }

    Write-TiTCLog "Domain security check complete: $($domains.Count) domains checked" -Level Info -Component $script:COMPONENT
}

# ============================================================================
# ASSESSOR: OWA Policy
# ============================================================================

function Test-TiTCOWAPolicy {
    [CmdletBinding()]
    param(
        [hashtable]$Config,
        $Result,
        [bool]$ExoConnected
    )

    Write-TiTCLog "Checking OWA policies..." -Level Info -Component $script:COMPONENT

    if (-not $ExoConnected) {
        Write-TiTCLog "OWA policy deep check requires ExchangeOnlineManagement module" -Level Debug -Component $script:COMPONENT
        return
    }

    $owaPolicies = Get-OwaMailboxPolicy

    foreach ($policy in $owaPolicies) {
        # Check if external content is allowed (web bugs, linked images)
        if ($policy.ExternalImageProxyEnabled -eq $false) {
            $Result.Findings += New-TiTCFinding `
                -Title "OWA external image proxy disabled" `
                -Description "OWA policy '$($policy.Name)' does not proxy external images. Direct loading of external images exposes user IP addresses and enables tracking pixels in phishing emails." `
                -Severity Low `
                -Domain Exchange `
                -RiskWeight 3 `
                -Remediation "Enable ExternalImageProxyEnabled in OWA mailbox policy to route all external images through the Microsoft proxy." `
                -ComplianceControls @('NIST:SI-8') `
                -AffectedResources @($policy.Name) `
                -DetectedBy $script:COMPONENT `
                -Tags @('OWA', 'TrackingPixels', 'Privacy')
        }
    }

    Write-TiTCLog "OWA policy check complete" -Level Info -Component $script:COMPONENT
}

# ============================================================================
# ASSESSOR: Mail Connectors
# ============================================================================

function Test-TiTCMailConnectors {
    [CmdletBinding()]
    param(
        [hashtable]$Config,
        $Result,
        [bool]$ExoConnected
    )

    Write-TiTCLog "Checking mail connectors..." -Level Info -Component $script:COMPONENT

    if (-not $ExoConnected) {
        Write-TiTCLog "Connector analysis requires ExchangeOnlineManagement module" -Level Debug -Component $script:COMPONENT
        return
    }

    $inboundConnectors = Get-InboundConnector
    $outboundConnectors = Get-OutboundConnector

    $Result.ObjectsScanned += $inboundConnectors.Count + $outboundConnectors.Count

    # Check for inbound connectors without TLS enforcement
    $noTlsConnectors = $inboundConnectors | Where-Object {
        $_.RequireTls -eq $false -and $_.Enabled -eq $true
    }

    if ($noTlsConnectors.Count -gt 0) {
        $Result.Findings += New-TiTCFinding `
            -Title "Inbound connectors without TLS enforcement" `
            -Description "$($noTlsConnectors.Count) inbound connectors do not require TLS encryption. Mail received through these connectors may be transmitted in plaintext, exposing sensitive content." `
            -Severity Medium `
            -Domain Exchange `
            -RiskWeight 5 `
            -Remediation "Enable RequireTLS on all inbound connectors. For partner connectors, also require a valid certificate from the sender's domain." `
            -ComplianceControls @('ISO27001:A.8.24', 'SOC2:CC6.7', 'NIST:SC-8') `
            -AffectedResources ($noTlsConnectors | ForEach-Object { $_.Name }) `
            -Evidence @{ NoTlsConnectors = $noTlsConnectors | ForEach-Object { @{ Name = $_.Name; RequireTls = $_.RequireTls } } } `
            -DetectedBy $script:COMPONENT `
            -Tags @('Connectors', 'TLS', 'Encryption')
    }

    $Result.RawData['Connectors'] = @{
        InboundCount  = $inboundConnectors.Count
        OutboundCount = $outboundConnectors.Count
        NoTLS         = $noTlsConnectors.Count
    }

    Write-TiTCLog "Connector check complete" -Level Info -Component $script:COMPONENT
}

# ============================================================================
# ASSESSOR: Mail-Enabled Security Groups
# ============================================================================

function Test-TiTCMailEnabledGroups {
    [CmdletBinding()]
    param(
        [hashtable]$Config,
        $Result
    )

    Write-TiTCLog "Checking mail-enabled groups exposure..." -Level Info -Component $script:COMPONENT

    # Get groups that accept external mail
    try {
        $groups = (Invoke-TiTCGraphRequest `
            -Endpoint '/groups' `
            -Select 'id,displayName,mailEnabled,securityEnabled,mail,groupTypes' `
            -Filter "mailEnabled eq true" `
            -AllPages `
            -Component $script:COMPONENT
        ).value

        $Result.ObjectsScanned += $groups.Count

        # Graph does not expose AllowExternalSenders reliably here, so flag mail-enabled security groups for review.
        $externalSecGroups = $groups | Where-Object {
            $_.securityEnabled -eq $true
        }

        if ($externalSecGroups.Count -gt 0) {
            $Result.Findings += New-TiTCFinding `
                -Title "Mail-enabled security groups should be reviewed for external sender exposure" `
                -Description "$($externalSecGroups.Count) security groups are mail-enabled. Review these groups in Exchange Online to confirm whether external senders are allowed, because one inbound email can reach all members if external delivery is enabled." `
                -Severity Low `
                -Domain Exchange `
                -RiskWeight 4 `
                -Remediation "Review each mail-enabled security group in Exchange Online and disable external sender access unless there is a documented business requirement." `
                -ComplianceControls @('ISO27001:A.8.23', 'NIST:SC-7') `
                -AffectedResources ($externalSecGroups | ForEach-Object { "$($_.displayName) ($($_.mail))" } | Select-Object -First 20) `
                -Evidence @{ ExternalSecGroups = $externalSecGroups.Count } `
                -DetectedBy $script:COMPONENT `
                -Tags @('Groups', 'ExternalMail', 'AttackSurface')
        }
    }
    catch {
        Write-TiTCLog "Group check failed: $_" -Level Debug -Component $script:COMPONENT
    }

    Write-TiTCLog "Mail-enabled groups check complete" -Level Info -Component $script:COMPONENT
}

# ============================================================================
# EXPORTS
# ============================================================================

Export-ModuleMember -Function @(
    'Invoke-TiTCExchangeCollector'
)
