@{
    RootModule        = 'TiTC.Models.psm1'
    ModuleVersion     = '1.0.0'
    GUID              = 'b2c3d4e5-f6a7-8901-bcde-f12345678901'
    Author            = 'TakeItToCloud'
    CompanyName       = 'TakeItToCloud'
    Copyright         = '(c) 2026 TakeItToCloud. All rights reserved.'
    Description       = 'Data models and factory functions for AuditXpert. Defines TiTCFinding, TiTCCollectorResult, TiTCRiskScore, TiTCAssessmentReport, and TiTCLicenseWaste.'
    PowerShellVersion = '5.1'
    RequiredModules   = @()
    FunctionsToExport = @(
        'New-TiTCFinding',
        'New-TiTCCollectorResult'
    )
    CmdletsToExport   = @()
    AliasesToExport   = @()
    PrivateData       = @{
        PSData = @{
            Tags       = @('Microsoft365', 'Security', 'Assessment', 'AuditXpert', 'Models')
            ProjectUri = 'https://github.com/TakeItToCloud/AuditXpert'
        }
    }
}
