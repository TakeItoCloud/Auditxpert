@{
    RootModule        = 'TiTC.Output.Evidence.psm1'
    ModuleVersion     = '1.0.0'
    GUID              = 'd0e1f2a3-b4c5-6789-defa-890123456789'
    Author            = 'TakeItToCloud'
    CompanyName       = 'TakeItToCloud'
    Copyright         = '(c) 2026 TakeItToCloud. All rights reserved.'
    Description       = 'Compliance evidence pack generator for AuditXpert. Maps assessment findings to compliance framework controls and generates structured evidence folders for auditor delivery. Supports ISO 27001, SOC 2, Cyber Insurance, CIS Controls, and Internal Risk frameworks.'
    PowerShellVersion = '5.1'
    RequiredModules   = @()
    FunctionsToExport = @('Export-TiTCEvidencePack')
    CmdletsToExport   = @()
    AliasesToExport   = @()
    PrivateData       = @{
        PSData = @{
            Tags       = @('Microsoft365', 'Security', 'Compliance', 'Evidence', 'ISO27001', 'SOC2', 'AuditXpert')
            ProjectUri = 'https://github.com/TakeItToCloud/AuditXpert'
        }
    }
}
