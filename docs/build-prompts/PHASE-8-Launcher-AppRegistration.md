# PHASE 8 — BUILD: Interactive Launcher, App Registration & Certificate Automation
# ══════════════════════════════════════════════════════════════════════════════════
# Feed this prompt to Claude in VS Code AFTER fixing all bugs from the previous session.
# This is the final enterprise-grade polish phase.
# Root: C:\Scripts\Assessment\AuditXpert
# ══════════════════════════════════════════════════════════════════════════════════

## CONTEXT
Read `AUDITXPERT-BUILD-SPEC.md` for full project context.
All modules are built. This phase adds an interactive launcher with a menu system,
automated Azure AD app registration with certificate authentication, and a 
pre-flight validation system that checks everything before running.

## CREATE 2 FILES

---

## FILE 1: Interactive Launcher
Path: `C:\Scripts\Assessment\AuditXpert\Start-AuditXpert.ps1`

This is the NEW primary entry point. Users run this instead of calling orchestrators directly.
It provides a menu-driven interface for all operations.

### Requirements

The script must:
- Work in PowerShell 5.1 and 7.x
- Use Write-Host with colors for the menu (not fancy TUI libraries)
- Handle invalid input gracefully
- Loop back to the menu after each operation completes
- Be the ONLY file users need to know about

### Main Menu

```
  ╔══════════════════════════════════════════════════════════════╗
  ║                                                              ║
  ║             AuditXpert — M365 Security Assessment            ║
  ║                       by TakeItToCloud                       ║
  ║                                                              ║
  ╚══════════════════════════════════════════════════════════════╝

  [1] Check prerequisites
  [2] Run with interactive (delegated) auth
  [3] Run with App + Certificate auth
  [4] Create App Registration with Certificate
  [5] Quit

  Select an option (1-5): _
```

### Option 1: Check Prerequisites

Call Test-TiTCPrerequisites (from Core module) or implement inline.
Check and report status of:

```powershell
# Required modules
$requiredModules = @(
    @{ Name = 'Microsoft.Graph.Authentication'; Required = $true; Purpose = 'Graph API connectivity' }
    @{ Name = 'Microsoft.Graph.Applications';   Required = $false; Purpose = 'App registration automation (Option 4)' }
    @{ Name = 'ExchangeOnlineManagement';       Required = $false; Purpose = 'Deep Exchange checks (transport rules, anti-phishing)' }
    @{ Name = 'Pester';                         Required = $false; Purpose = 'Running tests' }
)
```

For each module:
- If installed: show ✓ green with version
- If missing + required: show ✗ red, ask "Install now? (Y/N)"
- If missing + optional: show ⚠ yellow, ask "Install now? (Y/N)"

Also check:
- PowerShell version
- wkhtmltopdf availability
- ANTHROPIC_API_KEY / OPENAI_API_KEY in environment
- Existing AuditXpert app registrations in the tenant (if connected)

Print summary like:
```
  ═══ Prerequisites Check ═══

  PowerShell:     7.5.0                                    ✓
  Graph Auth:     Microsoft.Graph.Authentication v2.34.0   ✓
  Graph Apps:     Microsoft.Graph.Applications v2.34.0     ✓
  Exchange:       ExchangeOnlineManagement v3.6.0          ✓
  Pester:         Pester v5.6.1                            ✓
  wkhtmltopdf:    Not found                                ⚠ (HTML reports still work, print to PDF from browser)
  AI API Key:     ANTHROPIC_API_KEY set                    ✓

  Status: All required prerequisites met ✓
  
  Press Enter to return to menu...
```

### Option 2: Run with Interactive (Delegated) Auth

Shows sub-menu:
```
  ═══ Interactive Auth — Select Assessment Type ═══

  [1] Full Assessment (Snapshot + MSP Pack + AI Explainer)
  [2] M365 Risk Snapshot only
  [3] MSP Audit Pack only
  [4] Back to main menu

  Select (1-4): _
```

Before showing sub-menu, ask for:
```
  Tenant ID or domain: _
  Output path [C:\Reports\AuditXpert-2026-03-24]: _    ← show default, Enter to accept
```

For sub-options 1, 2, 3 — check if AI API key is available:
```powershell
$aiKey = $env:ANTHROPIC_API_KEY ?? $env:OPENAI_API_KEY
if (-not $aiKey) {
    Write-Host ""
    Write-Host "  AI Explainer requires an API key." -ForegroundColor Yellow
    Write-Host "  Get one at: https://console.anthropic.com/settings/keys" -ForegroundColor Gray
    Write-Host ""
    $aiKey = Read-Host "  Enter API key (or press Enter to skip AI Explainer)"
    if ($aiKey) {
        $env:ANTHROPIC_API_KEY = $aiKey
    }
}
```

Then run with these defaults:
```powershell
$commonParams = @{
    TenantId         = $tenantId
    Profile          = 'Full'
    OutputFormat      = 'HTML'
    IncludeEvidence  = $true
    OutputPath       = $outputPath
    SkipBanner       = $true   # We already showed our banner
}

# Add AI explainer if key available
if ($env:ANTHROPIC_API_KEY -or $env:OPENAI_API_KEY) {
    $commonParams.IncludeAIExplainer = $true
}
```

**Sub-option 1 (Full):** Run BOTH Invoke-M365Snapshot AND Invoke-MSPAuditPack sequentially.
The MSP Pack asks additionally: "MSP Company Name [TakeItToCloud]: _"

**Sub-option 2 (Snapshot only):** Run Invoke-M365Snapshot with $commonParams

**Sub-option 3 (MSP Pack only):** Run Invoke-MSPAuditPack with $commonParams + MSP branding

After completion, show:
```
  ═══ Assessment Complete ═══

  Risk Score:     63/100 (D)
  Findings:       16 total (2 critical, 5 high)
  Duration:       4m 32s
  
  Reports saved to: C:\Reports\AuditXpert-2026-03-24\
  
  Open report in browser? (Y/N): _
```

If Y, run: `Start-Process $reportHtmlPath`

### Option 3: Run with App + Certificate Auth

Shows sub-menu (same as Option 2), but first asks for app credentials:
```
  ═══ App + Certificate Auth ═══

  Tenant ID or domain: _
  App (Client) ID: _
  Certificate thumbprint: _
```

Then validate the certificate exists locally:
```powershell
$cert = Get-ChildItem Cert:\CurrentUser\My | Where-Object { $_.Thumbprint -eq $thumbprint }
if (-not $cert) {
    $cert = Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.Thumbprint -eq $thumbprint }
}
if (-not $cert) {
    Write-Host "  Certificate with thumbprint $thumbprint not found!" -ForegroundColor Red
    Write-Host "  Check: Cert:\CurrentUser\My or Cert:\LocalMachine\My" -ForegroundColor Yellow
    Write-Host "  Run Option 4 to create a new App + Certificate." -ForegroundColor Yellow
    # Return to menu
}
```

If cert found, show confirmation:
```
  Certificate found:
    Subject:    CN=AuditXpert-CaannesITConsulting
    Thumbprint: A1B2C3D4...
    Expires:    2028-03-24
    Store:      CurrentUser\My
  
  Continue? (Y/N): _
```

Then run with `-ClientId` and `-CertificateThumbprint` params.

### Option 4: Create App Registration with Certificate

This is the automation engine. It:
1. Connects to Graph with admin consent (interactive, one-time)
2. Checks if an AuditXpert app already exists
3. Creates the app if not, or updates permissions if it does
4. Generates a self-signed certificate
5. Uploads the certificate to the app
6. Grants admin consent for all permissions
7. Exports the certificate
8. Shows all the info needed to run assessments

```powershell
function New-AuditXpertAppRegistration {
    param(
        [Parameter(Mandatory)][string]$TenantId,
        [string]$AppDisplayName = 'AuditXpert Security Scanner',
        [int]$CertValidityYears = 2,
        [string]$CertExportPath = 'C:\Scripts\Assessment\AuditXpert\certs'
    )

    # ── Step 1: Connect with admin permissions ──────────────────────
    Write-Host "`n  Connecting to Microsoft Graph as admin..." -ForegroundColor Cyan
    Write-Host "  You need Global Administrator or Application Administrator role." -ForegroundColor Gray
    
    # Needs these scopes to create apps:
    Connect-MgGraph -TenantId $TenantId -Scopes @(
        'Application.ReadWrite.All',
        'AppRoleAssignment.ReadWrite.All',
        'Directory.ReadWrite.All'
    ) -NoWelcome

    $context = Get-MgContext
    if (-not $context) { throw "Failed to connect" }
    Write-Host "  Connected as: $($context.Account)" -ForegroundColor Green

    # ── Step 2: Check for existing app ──────────────────────────────
    Write-Host "`n  Checking for existing AuditXpert app registration..." -ForegroundColor Cyan
    
    $existingApp = Get-MgApplication -Filter "displayName eq '$AppDisplayName'" -ErrorAction SilentlyContinue
    
    if ($existingApp) {
        Write-Host "  Found existing app: $($existingApp.AppId)" -ForegroundColor Yellow
        $response = Read-Host "  Update permissions and rotate certificate? (Y/N)"
        if ($response -ne 'Y') { return }
        $app = $existingApp
        $isUpdate = $true
    } else {
        $isUpdate = $false
    }

    # ── Step 3: Define required permissions ─────────────────────────
    # Microsoft Graph App ID: 00000003-0000-0000-c000-000000000000
    $graphResourceId = '00000003-0000-0000-c000-000000000000'
    
    # All required Application permissions with their GUIDs
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

    # ── Step 4: Create or update the app ────────────────────────────
    $resourceAccess = @{
        ResourceAppId  = $graphResourceId
        ResourceAccess = $requiredPermissions
    }

    if (-not $isUpdate) {
        Write-Host "`n  Creating app registration: $AppDisplayName..." -ForegroundColor Cyan
        
        $appParams = @{
            DisplayName            = $AppDisplayName
            SignInAudience         = 'AzureADMyOrg'
            RequiredResourceAccess = @($resourceAccess)
            Notes                  = "Created by AuditXpert for automated M365 security assessments. Created on $(Get-Date -Format 'yyyy-MM-dd HH:mm')"
        }
        
        $app = New-MgApplication @appParams
        Write-Host "  App created: $($app.AppId)" -ForegroundColor Green

        # Create service principal
        $sp = New-MgServicePrincipal -AppId $app.AppId
        Write-Host "  Service principal created: $($sp.Id)" -ForegroundColor Green
    } else {
        Write-Host "`n  Updating app permissions..." -ForegroundColor Cyan
        Update-MgApplication -ApplicationId $app.Id -RequiredResourceAccess @($resourceAccess)
        $sp = Get-MgServicePrincipal -Filter "appId eq '$($app.AppId)'"
        Write-Host "  Permissions updated" -ForegroundColor Green
    }

    # ── Step 5: Generate self-signed certificate ────────────────────
    Write-Host "`n  Generating self-signed certificate..." -ForegroundColor Cyan
    
    $tenantShort = ($TenantId -split '\.')[0]
    $certName = "AuditXpert-$tenantShort"
    $certExpiry = (Get-Date).AddYears($CertValidityYears)
    
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
    
    $cert = New-SelfSignedCertificate @certParams
    Write-Host "  Certificate created: $($cert.Thumbprint)" -ForegroundColor Green

    # ── Step 6: Upload certificate to app registration ──────────────
    Write-Host "  Uploading certificate to app registration..." -ForegroundColor Cyan
    
    $certBytes = $cert.GetRawCertData()
    $certBase64 = [System.Convert]::ToBase64String($certBytes)
    
    $keyCredential = @{
        DisplayName = $certName
        Type        = 'AsymmetricX509Cert'
        Usage       = 'Verify'
        Key         = $certBytes
        EndDateTime = $certExpiry
    }
    
    Update-MgApplication -ApplicationId $app.Id -KeyCredentials @($keyCredential)
    Write-Host "  Certificate uploaded to app" -ForegroundColor Green

    # ── Step 7: Grant admin consent ─────────────────────────────────
    Write-Host "`n  Granting admin consent for all permissions..." -ForegroundColor Cyan
    
    # Get the Microsoft Graph service principal
    $graphSp = Get-MgServicePrincipal -Filter "appId eq '$graphResourceId'"
    
    foreach ($perm in $requiredPermissions) {
        try {
            New-MgServicePrincipalAppRoleAssignment `
                -ServicePrincipalId $sp.Id `
                -PrincipalId $sp.Id `
                -ResourceId $graphSp.Id `
                -AppRoleId $perm.Id `
                -ErrorAction SilentlyContinue | Out-Null
        } catch {
            # Permission may already be granted — ignore
        }
    }
    Write-Host "  Admin consent granted for all permissions" -ForegroundColor Green

    # ── Step 8: Export certificate ──────────────────────────────────
    Write-Host "`n  Exporting certificate..." -ForegroundColor Cyan
    
    if (-not (Test-Path $CertExportPath)) {
        New-Item -ItemType Directory -Path $CertExportPath -Force | Out-Null
    }
    
    # Export .cer (public key only — safe to share)
    $cerPath = Join-Path $CertExportPath "$certName.cer"
    Export-Certificate -Cert $cert -FilePath $cerPath -Type CERT | Out-Null
    Write-Host "  Public cert:  $cerPath" -ForegroundColor Gray
    
    # Export .pfx (private key — KEEP SECURE)
    $pfxPassword = Read-Host "  Enter password for PFX export (private key)" -AsSecureString
    $pfxPath = Join-Path $CertExportPath "$certName.pfx"
    Export-PfxCertificate -Cert $cert -FilePath $pfxPath -Password $pfxPassword | Out-Null
    Write-Host "  Private key:  $pfxPath (KEEP THIS SECURE)" -ForegroundColor Yellow

    # ── Step 9: Save config file ────────────────────────────────────
    $configData = @{
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
    $configData | ConvertTo-Json | Set-Content $configPath
    Write-Host "  Config saved: $configPath" -ForegroundColor Gray

    # ── Step 10: Display summary ────────────────────────────────────
    Write-Host ""
    Write-Host "  ┌─────────────────────────────────────────────────────────┐" -ForegroundColor Green
    Write-Host "  │         APP REGISTRATION COMPLETE                       │" -ForegroundColor Green
    Write-Host "  ├─────────────────────────────────────────────────────────┤" -ForegroundColor Green
    Write-Host "  │  Tenant:       $($TenantId.PadRight(39))│" -ForegroundColor White
    Write-Host "  │  App Name:     $($AppDisplayName.PadRight(39))│" -ForegroundColor White
    Write-Host "  │  Client ID:    $($app.AppId.PadRight(39))│" -ForegroundColor Cyan
    Write-Host "  │  Thumbprint:   $($cert.Thumbprint.PadRight(39))│" -ForegroundColor Cyan
    Write-Host "  │  Cert Expires: $($certExpiry.ToString('yyyy-MM-dd').PadRight(39))│" -ForegroundColor White
    Write-Host "  │  Cert Store:   Cert:\CurrentUser\My                     │" -ForegroundColor White
    Write-Host "  │  Config File:  $($configPath.PadRight(39))│" -ForegroundColor White
    Write-Host "  └─────────────────────────────────────────────────────────┘" -ForegroundColor Green
    Write-Host ""
    Write-Host "  To run an assessment with this app:" -ForegroundColor Yellow
    Write-Host "  .\profiles\Invoke-M365Snapshot.ps1 ``" -ForegroundColor White
    Write-Host "      -TenantId '$TenantId' ``" -ForegroundColor White
    Write-Host "      -ClientId '$($app.AppId)' ``" -ForegroundColor White
    Write-Host "      -CertificateThumbprint '$($cert.Thumbprint)'" -ForegroundColor White
    Write-Host ""

    # Disconnect admin session
    Disconnect-MgGraph -ErrorAction SilentlyContinue

    return $configData
}
```

### Option 3 Enhancement: Auto-detect saved app configs

When Option 3 is selected, before asking for credentials, check for saved configs:
```powershell
$certDir = Join-Path $PSScriptRoot 'certs'
$configs = Get-ChildItem $certDir -Filter '*-config.json' -ErrorAction SilentlyContinue

if ($configs) {
    Write-Host "`n  Saved app configurations found:" -ForegroundColor Cyan
    $i = 0
    foreach ($cfg in $configs) {
        $i++
        $data = Get-Content $cfg.FullName | ConvertFrom-Json
        Write-Host "  [$i] $($data.TenantId) (App: $($data.ClientId), Cert expires: $($data.CertificateExpiry))" -ForegroundColor White
    }
    Write-Host "  [$($i+1)] Enter credentials manually" -ForegroundColor Gray
    
    $selection = Read-Host "`n  Select (1-$($i+1))"
    
    if ($selection -le $configs.Count) {
        $selectedConfig = Get-Content $configs[$selection - 1].FullName | ConvertFrom-Json
        $tenantId = $selectedConfig.TenantId
        $clientId = $selectedConfig.ClientId
        $thumbprint = $selectedConfig.CertificateThumbprint
        
        # Validate cert still exists locally
        $cert = Get-ChildItem Cert:\CurrentUser\My | Where-Object { $_.Thumbprint -eq $thumbprint }
        if (-not $cert) {
            Write-Host "  Certificate not found in local store!" -ForegroundColor Red
            Write-Host "  Import the PFX from: $($selectedConfig.PfxPath)" -ForegroundColor Yellow
            # Show import instructions...
        }
    }
}
```

### Pre-Flight Validation (runs before ANY assessment)

Before launching any assessment (Option 2 or 3), run a quick pre-flight:
```powershell
function Test-AuditXpertPreFlight {
    param(
        [string]$TenantId,
        [string]$AuthMethod,     # 'Interactive' or 'Certificate'
        [string]$ClientId,
        [string]$CertThumbprint
    )

    $ready = $true

    # Check Graph module
    if (-not (Get-Module -ListAvailable 'Microsoft.Graph.Authentication')) {
        Write-Host "  ✗ Microsoft.Graph.Authentication not installed" -ForegroundColor Red
        $ready = $false
    }

    # Check cert exists (if cert auth)
    if ($AuthMethod -eq 'Certificate') {
        $cert = Get-ChildItem Cert:\CurrentUser\My -ErrorAction SilentlyContinue | 
            Where-Object { $_.Thumbprint -eq $CertThumbprint }
        if (-not $cert) {
            Write-Host "  ✗ Certificate $CertThumbprint not found" -ForegroundColor Red
            $ready = $false
        } elseif ($cert.NotAfter -lt (Get-Date)) {
            Write-Host "  ✗ Certificate expired on $($cert.NotAfter.ToString('yyyy-MM-dd'))" -ForegroundColor Red
            $ready = $false
        } elseif ($cert.NotAfter -lt (Get-Date).AddDays(30)) {
            Write-Host "  ⚠ Certificate expires in $([Math]::Round(($cert.NotAfter - (Get-Date)).TotalDays)) days" -ForegroundColor Yellow
        }
    }

    # Check output path writable
    # Check AI key if explainer enabled

    return $ready
}
```

### Full Script Structure

```powershell
#Requires -Version 5.1
<#
.SYNOPSIS
    AuditXpert Interactive Launcher — Enterprise M365 Security Assessment
.DESCRIPTION
    Menu-driven interface for running security assessments, managing app
    registrations, and configuring the AuditXpert platform.
.NOTES
    Author: TakeItToCloud
    Run:    .\Start-AuditXpert.ps1
#>

$ErrorActionPreference = 'Continue'
$scriptRoot = $PSScriptRoot

# Import core modules
Import-Module (Join-Path $scriptRoot 'src\Core\Models\TiTC.Models.psm1') -Force
Import-Module (Join-Path $scriptRoot 'src\Core\TiTC.Core.psm1') -Force

function Show-MainMenu { ... }
function Show-Banner { ... }
function Test-Prerequisites { ... }           # Option 1
function Start-InteractiveAssessment { ... }  # Option 2
function Start-CertificateAssessment { ... }  # Option 3
function New-AuditXpertAppRegistration { ... }# Option 4
function Show-AssessmentSubMenu { ... }       # Sub-menu for options 2/3
function Invoke-FullAssessment { ... }        # Runs Snapshot + MSP Pack
function Invoke-SnapshotOnly { ... }          # Runs Snapshot only
function Invoke-MSPPackOnly { ... }           # Runs MSP Pack only
function Test-AuditXpertPreFlight { ... }     # Pre-flight validation
function Get-AIApiKey { ... }                 # Prompt for AI key
function Get-SavedAppConfigs { ... }          # Load saved cert configs

# Main loop
Show-Banner
do {
    $choice = Show-MainMenu
    switch ($choice) {
        '1' { Test-Prerequisites }
        '2' { Start-InteractiveAssessment }
        '3' { Start-CertificateAssessment }
        '4' { New-AuditXpertAppRegistration }
        '5' { break }
    }
} while ($choice -ne '5')
```

### Assessment Sub-Menu (shared by Option 2 and 3)

```powershell
function Show-AssessmentSubMenu {
    param(
        [hashtable]$AuthParams    # Pre-built auth params (TenantId + either Interactive or Cert)
    )

    # Ask for tenant and output path
    if (-not $AuthParams.TenantId) {
        $AuthParams.TenantId = Read-Host "`n  Tenant ID or domain"
    }
    
    $defaultOutput = "C:\Reports\AuditXpert-$(Get-Date -Format 'yyyy-MM-dd')"
    $outputInput = Read-Host "  Output path [$defaultOutput]"
    $outputPath = if ($outputInput) { $outputInput } else { $defaultOutput }

    # Get AI key
    $aiKey = Get-AIApiKey

    Write-Host ""
    Write-Host "  ═══ Select Assessment Type ═══" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  [1] Full Assessment (Snapshot + MSP Pack + AI Explainer)" -ForegroundColor White
    Write-Host "  [2] M365 Risk Snapshot only" -ForegroundColor White
    Write-Host "  [3] MSP Audit Pack only" -ForegroundColor White
    Write-Host "  [4] Back to main menu" -ForegroundColor Gray
    Write-Host ""
    $subChoice = Read-Host "  Select (1-4)"

    # Build common params
    $commonParams = $AuthParams.Clone()
    $commonParams.Profile = 'Full'
    $commonParams.OutputFormat = 'HTML'
    $commonParams.IncludeEvidence = $true
    $commonParams.OutputPath = $outputPath
    $commonParams.SkipBanner = $true

    if ($aiKey) {
        $commonParams.IncludeAIExplainer = $true
    }

    switch ($subChoice) {
        '1' {
            # Full: run Snapshot then MSP Pack
            Write-Host "`n  Running M365 Risk Snapshot..." -ForegroundColor Cyan
            $snapshotReport = & (Join-Path $scriptRoot 'profiles\Invoke-M365Snapshot.ps1') @commonParams

            $mspName = Read-Host "`n  MSP Company Name [TakeItToCloud]"
            if (-not $mspName) { $mspName = 'TakeItToCloud' }

            Write-Host "`n  Running MSP Audit Pack..." -ForegroundColor Cyan
            $mspParams = $commonParams.Clone()
            $mspParams.MSPCompanyName = $mspName
            $mspParams.AuditPacks = @('ISO27001', 'CyberInsurance', 'SOC2Lite')
            & (Join-Path $scriptRoot 'profiles\Invoke-MSPAuditPack.ps1') @mspParams
        }
        '2' {
            Write-Host "`n  Running M365 Risk Snapshot..." -ForegroundColor Cyan
            & (Join-Path $scriptRoot 'profiles\Invoke-M365Snapshot.ps1') @commonParams
        }
        '3' {
            $mspName = Read-Host "  MSP Company Name [TakeItToCloud]"
            if (-not $mspName) { $mspName = 'TakeItToCloud' }

            Write-Host "`n  Running MSP Audit Pack..." -ForegroundColor Cyan
            $mspParams = $commonParams.Clone()
            $mspParams.MSPCompanyName = $mspName
            $mspParams.AuditPacks = @('ISO27001', 'CyberInsurance', 'SOC2Lite')
            & (Join-Path $scriptRoot 'profiles\Invoke-MSPAuditPack.ps1') @mspParams
        }
        '4' { return }
    }

    # Post-assessment: offer to open report
    $reportPath = Join-Path $outputPath 'report\security-assessment-report.html'
    if (Test-Path $reportPath) {
        $open = Read-Host "`n  Open report in browser? (Y/N)"
        if ($open -eq 'Y') { Start-Process $reportPath }
    }
}
```

---

## FILE 2: Update TiTC.Core.psm1 — add interactive auth scopes fix

Add the missing scopes to the Interactive auth scope list in Connect-TiTCGraph.
Find the $connectParams.Scopes array in the 'Interactive' switch case and add:

```powershell
'IdentityRiskEvent.Read.All',
'IdentityRiskyUser.Read.All',
'SecurityAlert.Read.All',
'SecurityIncident.Read.All',
'SecurityEvents.Read.All',
'DeviceManagementConfiguration.Read.All',
'DeviceManagementManagedDevices.Read.All'
```

These were missing and caused the 403 errors in the Defender and SignInRisk collectors.

---

## ALSO CREATE

### Folder: `C:\Scripts\Assessment\AuditXpert\certs\`
Create with a `.gitignore` inside:
```
# Never commit certificates or private keys
*.pfx
*.cer
*.pem
*-config.json
!.gitignore
```

### Update .gitignore in project root:
Add:
```
# Certificates (NEVER commit)
certs/*.pfx
certs/*.cer  
certs/*.pem
certs/*-config.json
```

---

## VALIDATION

After building Start-AuditXpert.ps1:
1. Run `.\Start-AuditXpert.ps1` — verify menu displays correctly
2. Select Option 1 — verify prerequisites check works
3. Select Option 5 — verify clean exit
4. Verify the script has no parse errors:
   ```powershell
   $errors = $null
   [System.Management.Automation.Language.Parser]::ParseFile(
       'C:\Scripts\Assessment\AuditXpert\Start-AuditXpert.ps1',
       [ref]$null, [ref]$errors)
   $errors | Format-List
   ```
