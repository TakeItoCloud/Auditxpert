@{
    RootModule        = 'TiTC.Core.psm1'
    ModuleVersion     = '1.0.0'
    GUID              = 'a1b2c3d4-e5f6-7890-abcd-ef1234567890'
    Author            = 'TakeItToCloud'
    CompanyName       = 'TakeItToCloud'
    Copyright         = '(c) 2026 TakeItToCloud. All rights reserved.'
    Description       = 'Core infrastructure for AuditXpert M365 Security Assessment Platform. Provides Graph API authentication, request wrapper, logging, and configuration management.'
    PowerShellVersion = '5.1'
    RequiredModules   = @('Microsoft.Graph.Authentication')
    FunctionsToExport = @(
        'Connect-TiTCGraph',
        'Disconnect-TiTCGraph',
        'Test-TiTCConnection',
        'Invoke-TiTCGraphRequest',
        'Get-TiTCConfig',
        'Write-TiTCLog',
        'Initialize-TiTCLogging',
        'Export-TiTCLog',
        'Get-TiTCState',
        'Get-TiTCTenantInfo',
        'Merge-TiTCHashtable'
    )
    CmdletsToExport   = @()
    AliasesToExport   = @()
    PrivateData       = @{
        PSData = @{
            Tags        = @('Microsoft365', 'Security', 'Assessment', 'AuditXpert', 'TakeItToCloud', 'GraphAPI')
            ProjectUri  = 'https://github.com/TakeItToCloud/AuditXpert'
            LicenseUri  = 'https://github.com/TakeItToCloud/AuditXpert/blob/main/LICENSE'
            ReleaseNotes= 'v1.0.0 — Initial release'
        }
    }
}
