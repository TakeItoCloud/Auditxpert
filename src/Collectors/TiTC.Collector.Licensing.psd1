@{
    RootModule        = 'TiTC.Collector.Licensing.psm1'
    ModuleVersion     = '1.0.0'
    GUID              = 'a7b8c9d0-e1f2-3456-abcd-567890123456'
    Author            = 'TakeItToCloud'
    CompanyName       = 'TakeItToCloud'
    Copyright         = '(c) 2026 TakeItToCloud. All rights reserved.'
    Description       = 'License and cost waste collector for AuditXpert. Performs 7 checks covering license inventory, unused licenses (EUR waste calculation), duplicate assignments, over-provisioned users, trial subscriptions, unlicensed users, and waste summary.'
    PowerShellVersion = '5.1'
    RequiredModules   = @()
    FunctionsToExport = @('Invoke-TiTCLicensingCollector')
    CmdletsToExport   = @()
    AliasesToExport   = @()
    PrivateData       = @{
        PSData = @{
            Tags       = @('Microsoft365', 'Licensing', 'CostOptimization', 'LicenseWaste', 'AuditXpert')
            ProjectUri = 'https://github.com/TakeItToCloud/AuditXpert'
        }
    }
}
