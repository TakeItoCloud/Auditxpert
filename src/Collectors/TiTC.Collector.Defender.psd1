@{
    RootModule        = 'TiTC.Collector.Defender.psm1'
    ModuleVersion     = '1.0.0'
    GUID              = 'f6a7b8c9-d0e1-2345-fabc-456789012345'
    Author            = 'TakeItToCloud'
    CompanyName       = 'TakeItToCloud'
    Copyright         = '(c) 2026 TakeItToCloud. All rights reserved.'
    Description       = 'Microsoft Defender security collector for AuditXpert. Performs 7 checks across Secure Score, security alerts, incidents, Defender for Endpoint coverage, email threat policies, attack simulation, and automated investigation.'
    PowerShellVersion = '5.1'
    RequiredModules   = @()
    FunctionsToExport = @('Invoke-TiTCDefenderCollector')
    CmdletsToExport   = @()
    AliasesToExport   = @()
    PrivateData       = @{
        PSData = @{
            Tags       = @('Microsoft365', 'Security', 'Defender', 'SecureScore', 'AuditXpert')
            ProjectUri = 'https://github.com/TakeItToCloud/AuditXpert'
        }
    }
}
