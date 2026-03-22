@{
    RootModule        = 'TiTC.Collector.Intune.psm1'
    ModuleVersion     = '1.0.0'
    GUID              = 'e5f6a7b8-c9d0-1234-efab-345678901234'
    Author            = 'TakeItToCloud'
    CompanyName       = 'TakeItToCloud'
    Copyright         = '(c) 2026 TakeItToCloud. All rights reserved.'
    Description       = 'Intune / Endpoint security collector for AuditXpert. Performs 8 checks across device compliance, compliance policies, encryption, OS update compliance, stale devices, app protection (MAM), security baselines, and device configuration profiles.'
    PowerShellVersion = '5.1'
    RequiredModules   = @()
    FunctionsToExport = @('Invoke-TiTCIntuneCollector')
    CmdletsToExport   = @()
    AliasesToExport   = @()
    PrivateData       = @{
        PSData = @{
            Tags       = @('Microsoft365', 'Security', 'Intune', 'EndpointSecurity', 'MDM', 'AuditXpert')
            ProjectUri = 'https://github.com/TakeItToCloud/AuditXpert'
        }
    }
}
