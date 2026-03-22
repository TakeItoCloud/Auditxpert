@{
    RootModule        = 'TiTC.Collector.EntraID.psm1'
    ModuleVersion     = '1.0.0'
    GUID              = 'c3d4e5f6-a7b8-9012-cdef-123456789012'
    Author            = 'TakeItToCloud'
    CompanyName       = 'TakeItToCloud'
    Copyright         = '(c) 2026 TakeItToCloud. All rights reserved.'
    Description       = 'Entra ID / Azure AD identity security collector for AuditXpert. Performs 19 checks across MFA, privileged access, Conditional Access, stale accounts, guest accounts, applications, password policy, auth methods, and sign-in risk.'
    PowerShellVersion = '5.1'
    RequiredModules   = @()
    FunctionsToExport = @('Invoke-TiTCEntraIDCollector')
    CmdletsToExport   = @()
    AliasesToExport   = @()
    PrivateData       = @{
        PSData = @{
            Tags       = @('Microsoft365', 'Security', 'EntraID', 'AzureAD', 'Identity', 'AuditXpert')
            ProjectUri = 'https://github.com/TakeItToCloud/AuditXpert'
        }
    }
}
