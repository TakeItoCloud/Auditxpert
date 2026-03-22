@{
    RootModule        = 'TiTC.Collector.Exchange.psm1'
    ModuleVersion     = '1.0.0'
    GUID              = 'd4e5f6a7-b8c9-0123-defa-234567890123'
    Author            = 'TakeItToCloud'
    CompanyName       = 'TakeItToCloud'
    Copyright         = '(c) 2026 TakeItToCloud. All rights reserved.'
    Description       = 'Exchange Online mail security collector for AuditXpert. Performs 15 checks across external forwarding, transport rules, anti-phishing, mailbox auditing, shared mailboxes, domain security, OWA policies, connectors, and mail-enabled groups.'
    PowerShellVersion = '5.1'
    RequiredModules   = @()
    FunctionsToExport = @('Invoke-TiTCExchangeCollector')
    CmdletsToExport   = @()
    AliasesToExport   = @()
    PrivateData       = @{
        PSData = @{
            Tags       = @('Microsoft365', 'Security', 'Exchange', 'Email', 'AuditXpert')
            ProjectUri = 'https://github.com/TakeItToCloud/AuditXpert'
        }
    }
}
