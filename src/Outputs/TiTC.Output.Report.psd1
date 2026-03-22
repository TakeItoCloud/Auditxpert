@{
    RootModule        = 'TiTC.Output.Report.psm1'
    ModuleVersion     = '1.0.0'
    GUID              = 'c9d0e1f2-a3b4-5678-cdef-789012345678'
    Author            = 'TakeItToCloud'
    CompanyName       = 'TakeItToCloud'
    Copyright         = '(c) 2026 TakeItToCloud. All rights reserved.'
    Description       = 'HTML/PDF report generator for AuditXpert. Produces professional branded single-page HTML reports from assessment data. Supports optional PDF conversion via wkhtmltopdf.'
    PowerShellVersion = '5.1'
    RequiredModules   = @()
    FunctionsToExport = @('Export-TiTCReport')
    CmdletsToExport   = @()
    AliasesToExport   = @()
    PrivateData       = @{
        PSData = @{
            Tags       = @('Microsoft365', 'Security', 'Reporting', 'PDF', 'HTML', 'AuditXpert')
            ProjectUri = 'https://github.com/TakeItToCloud/AuditXpert'
        }
    }
}
