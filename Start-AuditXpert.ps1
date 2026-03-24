#Requires -Version 5.1
<#
.SYNOPSIS
    AuditXpert Interactive Launcher — Enterprise M365 Security Assessment

.DESCRIPTION
    Menu-driven interface for running M365 security assessments, managing app
    registrations, and configuring the AuditXpert platform. This is the primary
    entry point — users do not need to call orchestrators directly.

.NOTES
    Product:  AuditXpert by TakeItToCloud
    Author:   TakeItToCloud
    Version:  1.0.0
    Run:      .\Start-AuditXpert.ps1
#>

$ErrorActionPreference = 'Continue'
$scriptRoot = $PSScriptRoot

# ============================================================================
# BANNER & MENU
# ============================================================================

function Show-Banner {
    Clear-Host
    Write-Host ""
    Write-Host "  ╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "  ║                                                              ║" -ForegroundColor Cyan
    Write-Host "  ║             AuditXpert — M365 Security Assessment            ║" -ForegroundColor Cyan
    Write-Host "  ║                       by TakeItToCloud                       ║" -ForegroundColor Cyan
    Write-Host "  ║                                                              ║" -ForegroundColor Cyan
    Write-Host "  ╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""
}

function Show-MainMenu {
    Write-Host "  [1] Check prerequisites" -ForegroundColor White
    Write-Host "  [2] Run with interactive (delegated) auth" -ForegroundColor White
    Write-Host "  [3] Run with App + Certificate auth" -ForegroundColor White
    Write-Host "  [4] Create App Registration with Certificate" -ForegroundColor White
    Write-Host "  [5] Quit" -ForegroundColor Gray
    Write-Host ""
    $choice = Read-Host "  Select an option (1-5)"
    return $choice.Trim()
}

# ============================================================================
# OPTION 1: PREREQUISITES CHECK
# ============================================================================

function Test-Prerequisites {
    Write-Host ""
    Write-Host "  ═══ Prerequisites Check ═══" -ForegroundColor Cyan
    Write-Host ""

    # PowerShell version
    $psVer = $PSVersionTable.PSVersion.ToString()
    $psOk  = $PSVersionTable.PSVersion.Major -ge 5
    Write-Host ("  {0,-16}{1,-45}{2}" -f 'PowerShell:', $psVer, (if ($psOk) { '✓' } else { '✗' })) `
        -ForegroundColor (if ($psOk) { 'Green' } else { 'Red' })

    # Required and optional modules
    $modules = @(
        [PSCustomObject]@{ Name = 'Microsoft.Graph.Authentication'; Required = $true;  Purpose = 'Graph API connectivity' }
        [PSCustomObject]@{ Name = 'Microsoft.Graph.Applications';   Required = $false; Purpose = 'App registration automation (Option 4)' }
        [PSCustomObject]@{ Name = 'ExchangeOnlineManagement';       Required = $false; Purpose = 'Deep Exchange checks' }
        [PSCustomObject]@{ Name = 'Pester';                         Required = $false; Purpose = 'Running tests' }
    )

    $allRequiredMet = $true

    foreach ($mod in $modules) {
        $installed = Get-Module -ListAvailable -Name $mod.Name | Sort-Object Version -Descending | Select-Object -First 1
        if ($installed) {
            Write-Host ("  {0,-16}{1,-45}{2}" -f "$($mod.Name):", "v$($installed.Version)", '✓') -ForegroundColor Green
        } elseif ($mod.Required) {
            $allRequiredMet = $false
            Write-Host ("  {0,-16}{1,-45}{2}" -f "$($mod.Name):", 'Not installed (REQUIRED)', '✗') -ForegroundColor Red
            $install = Read-Host "  Install $($mod.Name) now? (Y/N)"
            if ($install -eq 'Y') {
                Write-Host "  Installing $($mod.Name)..." -ForegroundColor Cyan
                try {
                    Install-Module -Name $mod.Name -Scope CurrentUser -Force -AllowClobber
                    Write-Host "  $($mod.Name) installed." -ForegroundColor Green
                    $allRequiredMet = $true
                } catch {
                    Write-Host "  Install failed: $_" -ForegroundColor Red
                }
            }
        } else {
            Write-Host ("  {0,-16}{1,-45}{2}" -f "$($mod.Name):", "Not installed — $($mod.Purpose)", '⚠') -ForegroundColor Yellow
            $install = Read-Host "  Install $($mod.Name) now? (Y/N)"
            if ($install -eq 'Y') {
                Write-Host "  Installing $($mod.Name)..." -ForegroundColor Cyan
                try {
                    Install-Module -Name $mod.Name -Scope CurrentUser -Force -AllowClobber
                    Write-Host "  $($mod.Name) installed." -ForegroundColor Green
                } catch {
                    Write-Host "  Install failed: $_" -ForegroundColor Red
                }
            }
        }
    }

    # wkhtmltopdf
    $wk = Get-Command wkhtmltopdf -ErrorAction SilentlyContinue
    if ($wk) {
        Write-Host ("  {0,-16}{1,-45}{2}" -f 'wkhtmltopdf:', $wk.Source, '✓') -ForegroundColor Green
    } else {
        Write-Host ("  {0,-16}{1,-45}{2}" -f 'wkhtmltopdf:', 'Not found  (HTML reports still work — print to PDF from browser)', '⚠') -ForegroundColor Yellow
    }

    # AI API key
    $anthropicKey = $env:ANTHROPIC_API_KEY
    $openaiKey    = $env:OPENAI_API_KEY
    if ($anthropicKey) {
        Write-Host ("  {0,-16}{1,-45}{2}" -f 'AI API Key:', 'ANTHROPIC_API_KEY set', '✓') -ForegroundColor Green
    } elseif ($openaiKey) {
        Write-Host ("  {0,-16}{1,-45}{2}" -f 'AI API Key:', 'OPENAI_API_KEY set', '✓') -ForegroundColor Green
    } else {
        Write-Host ("  {0,-16}{1,-45}{2}" -f 'AI API Key:', 'Not set  (AI Explainer will prompt at runtime)', '⚠') -ForegroundColor Yellow
    }

    # Summary
    Write-Host ""
    if ($allRequiredMet) {
        Write-Host "  Status: All required prerequisites met ✓" -ForegroundColor Green
    } else {
        Write-Host "  Status: Required prerequisites are missing ✗" -ForegroundColor Red
    }

    Write-Host ""
    Read-Host "  Press Enter to return to menu"
}

# ============================================================================
# AI KEY HELPER
# ============================================================================

function Get-AIApiKey {
    $aiKey = if ($env:ANTHROPIC_API_KEY) { $env:ANTHROPIC_API_KEY } elseif ($env:OPENAI_API_KEY) { $env:OPENAI_API_KEY } else { $null }

    if (-not $aiKey) {
        Write-Host ""
        Write-Host "  AI Explainer requires an API key." -ForegroundColor Yellow
        Write-Host "  Get one at: https://console.anthropic.com/settings/keys" -ForegroundColor DarkGray
        Write-Host ""
        $aiKey = Read-Host "  Enter Anthropic API key (or press Enter to skip AI Explainer)"
        if ($aiKey) {
            $env:ANTHROPIC_API_KEY = $aiKey
        } else {
            $aiKey = $null
        }
    }

    return $aiKey
}

# ============================================================================
# PRE-FLIGHT VALIDATION
# ============================================================================

function Test-AuditXpertPreFlight {
    param(
        [string]$TenantId,
        [string]$AuthMethod,      # 'Interactive' or 'Certificate'
        [string]$ClientId,
        [string]$CertThumbprint
    )

    $ready = $true

    if (-not (Get-Module -ListAvailable 'Microsoft.Graph.Authentication')) {
        Write-Host "  ✗ Microsoft.Graph.Authentication not installed. Run Option 1 to install." -ForegroundColor Red
        $ready = $false
    }

    if (-not $TenantId) {
        Write-Host "  ✗ Tenant ID is required." -ForegroundColor Red
        $ready = $false
    }

    if ($AuthMethod -eq 'Certificate') {
        if (-not $ClientId) {
            Write-Host "  ✗ Client ID is required for certificate auth." -ForegroundColor Red
            $ready = $false
        }

        $cert = $null
        $cert = Get-ChildItem Cert:\CurrentUser\My -ErrorAction SilentlyContinue |
            Where-Object { $_.Thumbprint -eq $CertThumbprint }
        if (-not $cert) {
            $cert = Get-ChildItem Cert:\LocalMachine\My -ErrorAction SilentlyContinue |
                Where-Object { $_.Thumbprint -eq $CertThumbprint }
        }

        if (-not $cert) {
            Write-Host "  ✗ Certificate with thumbprint '$CertThumbprint' not found in local certificate store." -ForegroundColor Red
            Write-Host "  Check: Cert:\CurrentUser\My or Cert:\LocalMachine\My" -ForegroundColor Yellow
            Write-Host "  Run Option 4 to create a new App Registration and Certificate." -ForegroundColor Yellow
            $ready = $false
        } elseif ($cert.NotAfter -lt (Get-Date)) {
            Write-Host "  ✗ Certificate expired on $($cert.NotAfter.ToString('yyyy-MM-dd'))." -ForegroundColor Red
            $ready = $false
        } elseif ($cert.NotAfter -lt (Get-Date).AddDays(30)) {
            $daysLeft = [Math]::Round(($cert.NotAfter - (Get-Date)).TotalDays)
            Write-Host "  ⚠ Certificate expires in $daysLeft days ($($cert.NotAfter.ToString('yyyy-MM-dd')))." -ForegroundColor Yellow
        }
    }

    return $ready
}

# ============================================================================
# SAVED APP CONFIGURATIONS
# ============================================================================

function Get-SavedAppConfigs {
    $certDir = Join-Path $scriptRoot 'certs'
    $configs  = @(Get-ChildItem $certDir -Filter '*-config.json' -ErrorAction SilentlyContinue)
    return $configs
}

# ============================================================================
# ASSESSMENT SUB-MENU (shared by Options 2 and 3)
# ============================================================================

function Show-AssessmentSubMenu {
    param(
        [hashtable]$AuthParams   # Pre-built: must contain TenantId + auth credentials
    )

    # Collect tenant and output path
    if (-not $AuthParams.TenantId) {
        Write-Host ""
        $AuthParams.TenantId = Read-Host "  Tenant ID or domain"
        if (-not $AuthParams.TenantId) { return }
    }

    $defaultOutput = "C:\Reports\AuditXpert-$(Get-Date -Format 'yyyy-MM-dd')"
    Write-Host ""
    $outputInput = Read-Host "  Output path [$defaultOutput]"
    $outputPath  = if ($outputInput.Trim()) { $outputInput.Trim() } else { $defaultOutput }

    # Ensure output directory exists
    if (-not (Test-Path $outputPath)) {
        New-Item -ItemType Directory -Path $outputPath -Force | Out-Null
    }

    # AI key
    $aiKey = Get-AIApiKey

    # Sub-menu
    Write-Host ""
    Write-Host "  ═══ Select Assessment Type ═══" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  [1] Full Assessment (Snapshot + MSP Pack + AI Explainer)" -ForegroundColor White
    Write-Host "  [2] M365 Risk Snapshot only" -ForegroundColor White
    Write-Host "  [3] MSP Audit Pack only" -ForegroundColor White
    Write-Host "  [4] Back to main menu" -ForegroundColor DarkGray
    Write-Host ""
    $subChoice = Read-Host "  Select (1-4)"

    if ($subChoice -eq '4' -or -not $subChoice.Trim()) { return }

    # Build common params
    $commonParams = @{}
    foreach ($k in $AuthParams.Keys) { $commonParams[$k] = $AuthParams[$k] }
    $commonParams.Profile        = 'Full'
    $commonParams.OutputFormat   = 'HTML'
    $commonParams.IncludeEvidence = $true
    $commonParams.OutputPath     = $outputPath
    $commonParams.SkipBanner     = $true

    if ($aiKey) {
        $commonParams.IncludeAIExplainer = $true
    }

    # Pre-flight
    $authMethod = if ($AuthParams.ContainsKey('CertificateThumbprint')) { 'Certificate' } else { 'Interactive' }
    $certThumb  = if ($AuthParams.ContainsKey('CertificateThumbprint')) { $AuthParams.CertificateThumbprint } else { $null }
    $clientId   = if ($AuthParams.ContainsKey('ClientId')) { $AuthParams.ClientId } else { $null }

    Write-Host ""
    if (-not (Test-AuditXpertPreFlight -TenantId $AuthParams.TenantId -AuthMethod $authMethod -ClientId $clientId -CertThumbprint $certThumb)) {
        Write-Host ""
        Write-Host "  Pre-flight checks failed. Cannot proceed." -ForegroundColor Red
        Read-Host "  Press Enter to return to menu"
        return
    }

    $snapshotPath    = Join-Path $scriptRoot 'profiles\Invoke-M365Snapshot.ps1'
    $mspPackPath     = Join-Path $scriptRoot 'profiles\Invoke-MSPAuditPack.ps1'
    $assessmentStart = Get-Date

    switch ($subChoice.Trim()) {
        '1' {
            # Full: Snapshot then MSP Pack
            Write-Host ""
            Write-Host "  Running M365 Risk Snapshot..." -ForegroundColor Cyan
            $snapshotReport = & $snapshotPath @commonParams

            $mspName = Read-Host "`n  MSP Company Name [TakeItToCloud]"
            if (-not $mspName.Trim()) { $mspName = 'TakeItToCloud' }

            Write-Host ""
            Write-Host "  Running MSP Audit Pack..." -ForegroundColor Cyan
            $mspParams = @{}
            foreach ($k in $commonParams.Keys) { $mspParams[$k] = $commonParams[$k] }
            $mspParams.MSPCompanyName = $mspName
            $mspParams.AuditPacks     = @('ISO27001', 'CyberInsurance', 'SOC2Lite')
            & $mspPackPath @mspParams
        }
        '2' {
            Write-Host ""
            Write-Host "  Running M365 Risk Snapshot..." -ForegroundColor Cyan
            & $snapshotPath @commonParams
        }
        '3' {
            $mspName = Read-Host "  MSP Company Name [TakeItToCloud]"
            if (-not $mspName.Trim()) { $mspName = 'TakeItToCloud' }

            Write-Host ""
            Write-Host "  Running MSP Audit Pack..." -ForegroundColor Cyan
            $mspParams = @{}
            foreach ($k in $commonParams.Keys) { $mspParams[$k] = $commonParams[$k] }
            $mspParams.MSPCompanyName = $mspName
            $mspParams.AuditPacks     = @('ISO27001', 'CyberInsurance', 'SOC2Lite')
            & $mspPackPath @mspParams
        }
    }

    # Post-assessment summary
    $duration = [Math]::Round(((Get-Date) - $assessmentStart).TotalSeconds)
    $mins     = [Math]::Floor($duration / 60)
    $secs     = $duration % 60

    Write-Host ""
    Write-Host "  ═══ Assessment Complete ═══" -ForegroundColor Green
    Write-Host ""
    Write-Host "  Duration:   ${mins}m ${secs}s" -ForegroundColor White
    Write-Host "  Output:     $outputPath" -ForegroundColor White

    $reportHtmlPath = Join-Path $outputPath 'report\security-assessment-report.html'
    if (Test-Path $reportHtmlPath) {
        Write-Host ""
        $open = Read-Host "  Open report in browser? (Y/N)"
        if ($open.Trim().ToUpper() -eq 'Y') {
            Start-Process $reportHtmlPath
        }
    }

    Write-Host ""
    Read-Host "  Press Enter to return to menu"
}

# ============================================================================
# OPTION 2: INTERACTIVE AUTH
# ============================================================================

function Start-InteractiveAssessment {
    Write-Host ""
    Write-Host "  ═══ Interactive Auth ═══" -ForegroundColor Cyan
    Write-Host ""
    $tenantId = Read-Host "  Tenant ID or domain"
    if (-not $tenantId.Trim()) { return }

    $authParams = @{
        TenantId    = $tenantId.Trim()
        Interactive = $true
    }

    Show-AssessmentSubMenu -AuthParams $authParams
}

# ============================================================================
# OPTION 3: APP + CERTIFICATE AUTH
# ============================================================================

function Start-CertificateAssessment {
    Write-Host ""
    Write-Host "  ═══ App + Certificate Auth ═══" -ForegroundColor Cyan

    # Auto-detect saved configs
    $configs = @(Get-SavedAppConfigs)

    $tenantId   = $null
    $clientId   = $null
    $thumbprint = $null

    if ($configs.Count -gt 0) {
        Write-Host ""
        Write-Host "  Saved app configurations found:" -ForegroundColor Cyan
        for ($i = 0; $i -lt $configs.Count; $i++) {
            try {
                $data = Get-Content $configs[$i].FullName | ConvertFrom-Json
                Write-Host ("  [{0}] {1}  (App: {2}, Cert expires: {3})" -f ($i+1), $data.TenantId, $data.ClientId, $data.CertificateExpiry) -ForegroundColor White
            } catch {
                Write-Host "  [$($i+1)] $($configs[$i].Name) (could not parse)" -ForegroundColor DarkGray
            }
        }
        Write-Host "  [$($configs.Count + 1)] Enter credentials manually" -ForegroundColor DarkGray
        Write-Host ""
        $selection = Read-Host "  Select (1-$($configs.Count + 1))"

        $selNum = 0
        if ([int]::TryParse($selection.Trim(), [ref]$selNum) -and $selNum -ge 1 -and $selNum -le $configs.Count) {
            try {
                $selectedConfig = Get-Content $configs[$selNum - 1].FullName | ConvertFrom-Json
                $tenantId       = $selectedConfig.TenantId
                $clientId       = $selectedConfig.ClientId
                $thumbprint     = $selectedConfig.CertificateThumbprint

                # Validate cert
                $cert = Get-ChildItem Cert:\CurrentUser\My -ErrorAction SilentlyContinue |
                    Where-Object { $_.Thumbprint -eq $thumbprint }
                if (-not $cert) {
                    $cert = Get-ChildItem Cert:\LocalMachine\My -ErrorAction SilentlyContinue |
                        Where-Object { $_.Thumbprint -eq $thumbprint }
                }

                if (-not $cert) {
                    Write-Host ""
                    Write-Host "  ✗ Certificate not found in local store!" -ForegroundColor Red
                    Write-Host "  Import the PFX from: $($selectedConfig.PfxPath)" -ForegroundColor Yellow
                    Write-Host "  Command: Import-PfxCertificate -FilePath '$($selectedConfig.PfxPath)' -CertStoreLocation Cert:\CurrentUser\My" -ForegroundColor DarkGray
                    Write-Host ""
                    Read-Host "  Press Enter to return to menu"
                    return
                }

                Write-Host ""
                Write-Host "  Certificate found:" -ForegroundColor Green
                Write-Host "    Subject:    $($cert.Subject)" -ForegroundColor White
                Write-Host "    Thumbprint: $($cert.Thumbprint)" -ForegroundColor White
                Write-Host "    Expires:    $($cert.NotAfter.ToString('yyyy-MM-dd'))" -ForegroundColor White
                $storeDisplay = if ($cert.PSParentPath -match 'LocalMachine') { 'LocalMachine\My' } else { 'CurrentUser\My' }
                Write-Host "    Store:      $storeDisplay" -ForegroundColor White
                Write-Host ""
                $confirm = Read-Host "  Continue? (Y/N)"
                if ($confirm.Trim().ToUpper() -ne 'Y') { return }
            } catch {
                Write-Host "  Could not load saved config: $_" -ForegroundColor Red
                # Fall through to manual entry
            }
        }
    }

    # Manual entry (or fallback)
    if (-not $tenantId) {
        Write-Host ""
        $tenantId   = Read-Host "  Tenant ID or domain"
        if (-not $tenantId.Trim()) { return }
        $clientId   = Read-Host "  App (Client) ID"
        if (-not $clientId.Trim()) { return }
        $thumbprint = Read-Host "  Certificate thumbprint"
        if (-not $thumbprint.Trim()) { return }

        $tenantId   = $tenantId.Trim()
        $clientId   = $clientId.Trim()
        $thumbprint = $thumbprint.Trim()

        # Validate cert exists
        $cert = Get-ChildItem Cert:\CurrentUser\My -ErrorAction SilentlyContinue |
            Where-Object { $_.Thumbprint -eq $thumbprint }
        if (-not $cert) {
            $cert = Get-ChildItem Cert:\LocalMachine\My -ErrorAction SilentlyContinue |
                Where-Object { $_.Thumbprint -eq $thumbprint }
        }

        if (-not $cert) {
            Write-Host ""
            Write-Host "  ✗ Certificate with thumbprint '$thumbprint' not found!" -ForegroundColor Red
            Write-Host "  Check: Cert:\CurrentUser\My or Cert:\LocalMachine\My" -ForegroundColor Yellow
            Write-Host "  Run Option 4 to create a new App Registration and Certificate." -ForegroundColor Yellow
            Write-Host ""
            Read-Host "  Press Enter to return to menu"
            return
        }

        Write-Host ""
        Write-Host "  Certificate found:" -ForegroundColor Green
        Write-Host "    Subject:    $($cert.Subject)" -ForegroundColor White
        Write-Host "    Thumbprint: $($cert.Thumbprint)" -ForegroundColor White
        Write-Host "    Expires:    $($cert.NotAfter.ToString('yyyy-MM-dd'))" -ForegroundColor White
        $storeDisplay = if ($cert.PSParentPath -match 'LocalMachine') { 'LocalMachine\My' } else { 'CurrentUser\My' }
        Write-Host "    Store:      $storeDisplay" -ForegroundColor White
        Write-Host ""
        $confirm = Read-Host "  Continue? (Y/N)"
        if ($confirm.Trim().ToUpper() -ne 'Y') { return }
    }

    $authParams = @{
        TenantId               = $tenantId
        ClientId               = $clientId
        CertificateThumbprint  = $thumbprint
    }

    Show-AssessmentSubMenu -AuthParams $authParams
}

# ============================================================================
# OPTION 4: CREATE APP REGISTRATION WITH CERTIFICATE
# ============================================================================

function New-AuditXpertAppRegistration {
    param(
        [Parameter(Mandatory)][string]$TenantId,
        [string]$AppDisplayName    = 'AuditXpert Security Scanner',
        [int]$CertValidityYears    = 2,
        [string]$CertExportPath    = (Join-Path $scriptRoot 'certs')
    )

    # ── Step 1: Connect with admin permissions ─────────────────────────────
    Write-Host ""
    Write-Host "  Connecting to Microsoft Graph as admin..." -ForegroundColor Cyan
    Write-Host "  You need Global Administrator or Application Administrator role." -ForegroundColor DarkGray
    Write-Host ""

    try {
        Connect-MgGraph -TenantId $TenantId -Scopes @(
            'Application.ReadWrite.All',
            'AppRoleAssignment.ReadWrite.All',
            'Directory.ReadWrite.All'
        ) -NoWelcome -ErrorAction Stop
    } catch {
        Write-Host "  Failed to connect to Microsoft Graph: $_" -ForegroundColor Red
        Read-Host "  Press Enter to return to menu"
        return
    }

    $context = Get-MgContext
    if (-not $context) {
        Write-Host "  Failed to establish Graph context." -ForegroundColor Red
        Read-Host "  Press Enter to return to menu"
        return
    }
    Write-Host "  Connected as: $($context.Account)" -ForegroundColor Green

    # ── Step 2: Check for existing app ─────────────────────────────────────
    Write-Host ""
    Write-Host "  Checking for existing AuditXpert app registration..." -ForegroundColor Cyan

    $existingApp = Get-MgApplication -Filter "displayName eq '$AppDisplayName'" -ErrorAction SilentlyContinue
    $isUpdate    = $false
    $app         = $null

    if ($existingApp) {
        Write-Host "  Found existing app: $($existingApp.AppId)" -ForegroundColor Yellow
        $response = Read-Host "  Update permissions and rotate certificate? (Y/N)"
        if ($response.Trim().ToUpper() -ne 'Y') {
            Disconnect-MgGraph -ErrorAction SilentlyContinue
            return
        }
        $app      = $existingApp
        $isUpdate = $true
    }

    # ── Step 3: Define required permissions ───────────────────────────────
    $graphResourceId     = '00000003-0000-0000-c000-000000000000'
    $requiredPermissions = @(
        @{ Id = '7ab1d382-f21e-4acd-a863-ba3e13f7da61'; Type = 'Role' }  # Directory.Read.All
        @{ Id = '246dd0d5-5bd0-4def-940b-0421030a5b68'; Type = 'Role' }  # Policy.Read.All
        @{ Id = 'df021288-bdef-4463-88db-98f22de89214'; Type = 'Role' }  # User.Read.All
        @{ Id = '5b567255-7703-4780-807c-7be8301ae99b'; Type = 'Role' }  # Group.Read.All
        @{ Id = '9a5d68dd-52b0-4cc2-bd40-abcf44ac3a30'; Type = 'Role' }  # Application.Read.All
        @{ Id = '483bed4a-2ad3-4361-a73b-c83ccdbdc53c'; Type = 'Role' }  # RoleManagement.Read.Directory
        @{ Id = 'b0afded3-3588-46d8-8b3d-9842eff778da'; Type = 'Role' }  # AuditLog.Read.All
        @{ Id = '498476ce-e0fe-48b0-b801-37ba7e2685c6'; Type = 'Role' }  # Organization.Read.All
        @{ Id = '230c1aed-a721-4c5d-9cb4-a90514e508ef'; Type = 'Role' }  # Reports.Read.All
        @{ Id = 'dc377aa6-52d8-4e23-b271-b3b753e78c78'; Type = 'Role' }  # DeviceManagementConfiguration.Read.All
        @{ Id = '2f51be20-0bb4-4fed-bf7b-db946066c75e'; Type = 'Role' }  # DeviceManagementManagedDevices.Read.All
        @{ Id = 'bf394140-e372-4bf9-a898-299cfc7564e5'; Type = 'Role' }  # SecurityAlert.Read.All
        @{ Id = '45cc0394-e837-488b-a098-1918f48d186c'; Type = 'Role' }  # SecurityIncident.Read.All
        @{ Id = 'bf7b1a76-6e77-406b-998a-9b13d33dbb10'; Type = 'Role' }  # SecurityEvents.Read.All
        @{ Id = '6e472fd1-ad78-48da-a0f0-97ab2c6b769e'; Type = 'Role' }  # IdentityRiskEvent.Read.All
        @{ Id = 'dc5007c0-2d7d-4c42-879c-2dab87571379'; Type = 'Role' }  # IdentityRiskyUser.Read.All
        @{ Id = '570282fd-fa5c-430d-a7fd-fc8dc98a9dca'; Type = 'Role' }  # Mail.Read
        @{ Id = '40f97065-369a-49f4-947c-6a90f8a0eab1'; Type = 'Role' }  # MailboxSettings.Read
    )

    # ── Step 4: Create or update the app ──────────────────────────────────
    $resourceAccess = @{
        ResourceAppId  = $graphResourceId
        ResourceAccess = $requiredPermissions
    }

    if (-not $isUpdate) {
        Write-Host ""
        Write-Host "  Creating app registration: $AppDisplayName..." -ForegroundColor Cyan

        $appParams = @{
            DisplayName            = $AppDisplayName
            SignInAudience         = 'AzureADMyOrg'
            RequiredResourceAccess = @($resourceAccess)
            Notes                  = "Created by AuditXpert for automated M365 security assessments. Created on $(Get-Date -Format 'yyyy-MM-dd HH:mm')"
        }

        try {
            $app = New-MgApplication @appParams -ErrorAction Stop
            Write-Host "  App created: $($app.AppId)" -ForegroundColor Green

            $sp = New-MgServicePrincipal -AppId $app.AppId -ErrorAction Stop
            Write-Host "  Service principal created: $($sp.Id)" -ForegroundColor Green
        } catch {
            Write-Host "  Failed to create app registration: $_" -ForegroundColor Red
            Disconnect-MgGraph -ErrorAction SilentlyContinue
            Read-Host "  Press Enter to return to menu"
            return
        }
    } else {
        Write-Host ""
        Write-Host "  Updating app permissions..." -ForegroundColor Cyan
        Update-MgApplication -ApplicationId $app.Id -RequiredResourceAccess @($resourceAccess)
        $sp = Get-MgServicePrincipal -Filter "appId eq '$($app.AppId)'"
        Write-Host "  Permissions updated." -ForegroundColor Green
    }

    # ── Step 5: Generate self-signed certificate ───────────────────────────
    Write-Host ""
    Write-Host "  Generating self-signed certificate..." -ForegroundColor Cyan

    $tenantShort = ($TenantId -split '\.')[0]
    $certName    = "AuditXpert-$tenantShort"
    $certExpiry  = (Get-Date).AddYears($CertValidityYears)

    $certParams = @{
        Subject           = "CN=$certName"
        CertStoreLocation = 'Cert:\CurrentUser\My'
        NotAfter          = $certExpiry
        KeySpec           = 'Signature'
        KeyLength         = 2048
        KeyAlgorithm      = 'RSA'
        HashAlgorithm     = 'SHA256'
        FriendlyName      = "AuditXpert - $tenantShort - Expires $($certExpiry.ToString('yyyy-MM-dd'))"
    }

    try {
        $cert = New-SelfSignedCertificate @certParams -ErrorAction Stop
        Write-Host "  Certificate created: $($cert.Thumbprint)" -ForegroundColor Green
    } catch {
        Write-Host "  Failed to generate certificate: $_" -ForegroundColor Red
        Disconnect-MgGraph -ErrorAction SilentlyContinue
        Read-Host "  Press Enter to return to menu"
        return
    }

    # ── Step 6: Upload certificate to app registration ────────────────────
    Write-Host "  Uploading certificate to app registration..." -ForegroundColor Cyan

    $certBytes   = $cert.GetRawCertData()
    $keyCredential = @{
        DisplayName = $certName
        Type        = 'AsymmetricX509Cert'
        Usage       = 'Verify'
        Key         = $certBytes
        EndDateTime = $certExpiry
    }

    try {
        Update-MgApplication -ApplicationId $app.Id -KeyCredentials @($keyCredential) -ErrorAction Stop
        Write-Host "  Certificate uploaded to app." -ForegroundColor Green
    } catch {
        Write-Host "  Failed to upload certificate: $_" -ForegroundColor Red
    }

    # ── Step 7: Grant admin consent ────────────────────────────────────────
    Write-Host ""
    Write-Host "  Granting admin consent for all permissions..." -ForegroundColor Cyan

    $graphSp = Get-MgServicePrincipal -Filter "appId eq '$graphResourceId'"

    $granted = 0
    foreach ($perm in $requiredPermissions) {
        try {
            New-MgServicePrincipalAppRoleAssignment `
                -ServicePrincipalId $sp.Id `
                -PrincipalId        $sp.Id `
                -ResourceId         $graphSp.Id `
                -AppRoleId          $perm.Id `
                -ErrorAction SilentlyContinue | Out-Null
            $granted++
        } catch {
            # Permission may already be granted
        }
    }
    Write-Host "  Admin consent granted ($granted permissions)." -ForegroundColor Green

    # ── Step 8: Export certificate ─────────────────────────────────────────
    Write-Host ""
    Write-Host "  Exporting certificate..." -ForegroundColor Cyan

    if (-not (Test-Path $CertExportPath)) {
        New-Item -ItemType Directory -Path $CertExportPath -Force | Out-Null
    }

    # Export .cer (public key only)
    $cerPath = Join-Path $CertExportPath "$certName.cer"
    try {
        Export-Certificate -Cert $cert -FilePath $cerPath -Type CERT | Out-Null
        Write-Host "  Public cert:  $cerPath" -ForegroundColor DarkGray
    } catch {
        Write-Host "  Could not export .cer: $_" -ForegroundColor Yellow
    }

    # Export .pfx (private key)
    $pfxPassword = Read-Host "  Enter password for PFX export (private key)" -AsSecureString
    $pfxPath     = Join-Path $CertExportPath "$certName.pfx"
    try {
        Export-PfxCertificate -Cert $cert -FilePath $pfxPath -Password $pfxPassword | Out-Null
        Write-Host "  Private key:  $pfxPath  (KEEP THIS SECURE)" -ForegroundColor Yellow
    } catch {
        Write-Host "  Could not export .pfx: $_" -ForegroundColor Yellow
    }

    # ── Step 9: Save config file ───────────────────────────────────────────
    $configData = [ordered]@{
        TenantId              = $TenantId
        ClientId              = $app.AppId
        AppObjectId           = $app.Id
        ServicePrincipalId    = $sp.Id
        CertificateThumbprint = $cert.Thumbprint
        CertificateSubject    = $cert.Subject
        CertificateExpiry     = $certExpiry.ToString('yyyy-MM-dd')
        CertificatePath       = $cerPath
        PfxPath               = $pfxPath
        AppDisplayName        = $AppDisplayName
        CreatedAt             = (Get-Date -Format 'o')
        CreatedBy             = $context.Account
    }

    $configPath = Join-Path $CertExportPath "$certName-config.json"
    $configData | ConvertTo-Json | Set-Content $configPath -Encoding UTF8
    Write-Host "  Config saved: $configPath" -ForegroundColor DarkGray

    # ── Step 10: Summary ───────────────────────────────────────────────────
    $tidPad   = $TenantId.PadRight(39)
    $appPad   = $AppDisplayName.PadRight(39)
    $cidPad   = $app.AppId.PadRight(39)
    $thumbPad = $cert.Thumbprint.PadRight(39)
    $expPad   = $certExpiry.ToString('yyyy-MM-dd').PadRight(39)
    $cfgPad   = $configPath.PadRight(39)

    Write-Host ""
    Write-Host "  ┌─────────────────────────────────────────────────────────┐" -ForegroundColor Green
    Write-Host "  │         APP REGISTRATION COMPLETE                       │" -ForegroundColor Green
    Write-Host "  ├─────────────────────────────────────────────────────────┤" -ForegroundColor Green
    Write-Host "  │  Tenant:       $tidPad│" -ForegroundColor White
    Write-Host "  │  App Name:     $appPad│" -ForegroundColor White
    Write-Host "  │  Client ID:    $cidPad│" -ForegroundColor Cyan
    Write-Host "  │  Thumbprint:   $thumbPad│" -ForegroundColor Cyan
    Write-Host "  │  Cert Expires: $expPad│" -ForegroundColor White
    Write-Host "  │  Cert Store:   Cert:\CurrentUser\My                     │" -ForegroundColor White
    Write-Host "  │  Config File:  $cfgPad│" -ForegroundColor White
    Write-Host "  └─────────────────────────────────────────────────────────┘" -ForegroundColor Green
    Write-Host ""
    Write-Host "  To run an assessment with this app:" -ForegroundColor Yellow
    Write-Host "  .\Start-AuditXpert.ps1  (select Option 3)" -ForegroundColor White
    Write-Host ""
    Write-Host "  Or directly:" -ForegroundColor DarkGray
    Write-Host "  .\profiles\Invoke-M365Snapshot.ps1 ``" -ForegroundColor White
    Write-Host "      -TenantId '$TenantId' ``" -ForegroundColor White
    Write-Host "      -ClientId '$($app.AppId)' ``" -ForegroundColor White
    Write-Host "      -CertificateThumbprint '$($cert.Thumbprint)'" -ForegroundColor White
    Write-Host ""

    Disconnect-MgGraph -ErrorAction SilentlyContinue

    Read-Host "  Press Enter to return to menu"
    return $configData
}

function Invoke-Option4 {
    Write-Host ""
    Write-Host "  ═══ Create App Registration with Certificate ═══" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  This will:" -ForegroundColor White
    Write-Host "  1. Connect to Microsoft Graph (requires Global/Application Admin)" -ForegroundColor DarkGray
    Write-Host "  2. Create (or update) an app registration named 'AuditXpert Security Scanner'" -ForegroundColor DarkGray
    Write-Host "  3. Generate a self-signed certificate and upload it to the app" -ForegroundColor DarkGray
    Write-Host "  4. Grant admin consent for all required permissions" -ForegroundColor DarkGray
    Write-Host "  5. Export the certificate and save connection config" -ForegroundColor DarkGray
    Write-Host ""

    # Check Microsoft.Graph.Applications is available
    if (-not (Get-Module -ListAvailable 'Microsoft.Graph.Applications')) {
        Write-Host "  Microsoft.Graph.Applications module is required for this option." -ForegroundColor Red
        $install = Read-Host "  Install now? (Y/N)"
        if ($install.Trim().ToUpper() -eq 'Y') {
            Install-Module -Name 'Microsoft.Graph.Applications' -Scope CurrentUser -Force -AllowClobber
        } else {
            Read-Host "  Press Enter to return to menu"
            return
        }
    }

    Import-Module 'Microsoft.Graph.Applications' -ErrorAction SilentlyContinue

    $tenantId = Read-Host "  Tenant ID or domain"
    if (-not $tenantId.Trim()) { return }

    $appNameInput = Read-Host "  App display name [AuditXpert Security Scanner]"
    $appName = if ($appNameInput.Trim()) { $appNameInput.Trim() } else { 'AuditXpert Security Scanner' }

    New-AuditXpertAppRegistration -TenantId $tenantId.Trim() -AppDisplayName $appName
}

# ============================================================================
# MODULE BOOTSTRAP
# ============================================================================

# Import core modules (needed for Test-TiTCPrerequisites if called)
$modelsPath = Join-Path $scriptRoot 'src\Core\Models\TiTC.Models.psm1'
$corePath   = Join-Path $scriptRoot 'src\Core\TiTC.Core.psm1'

if (Test-Path $modelsPath) {
    Import-Module $modelsPath -Force -ErrorAction SilentlyContinue
}
if (Test-Path $corePath) {
    Import-Module $corePath -Force -ErrorAction SilentlyContinue
}

# ============================================================================
# MAIN LOOP
# ============================================================================

Show-Banner

$running = $true
while ($running) {
    $choice = Show-MainMenu

    switch ($choice) {
        '1' { Test-Prerequisites }
        '2' { Start-InteractiveAssessment }
        '3' { Start-CertificateAssessment }
        '4' { Invoke-Option4 }
        '5' {
            Write-Host ""
            Write-Host "  Goodbye." -ForegroundColor DarkGray
            Write-Host ""
            $running = $false
        }
        default {
            Write-Host ""
            Write-Host "  Invalid selection. Please enter 1-5." -ForegroundColor Red
            Write-Host ""
        }
    }

    # Reshow banner before each menu iteration (except exit)
    if ($running) {
        Write-Host ""
        Write-Host "  ─────────────────────────────────────────────────────────" -ForegroundColor DarkGray
        Write-Host ""
    }
}
