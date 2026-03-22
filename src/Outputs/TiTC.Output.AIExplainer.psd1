@{
    RootModule        = 'TiTC.Output.AIExplainer.psm1'
    ModuleVersion     = '1.0.0'
    GUID              = 'e1f2a3b4-c5d6-7890-efab-901234567890'
    Author            = 'TakeItToCloud'
    CompanyName       = 'TakeItToCloud'
    Copyright         = '(c) 2026 TakeItToCloud. All rights reserved.'
    Description       = 'AI-powered plain-English finding explainer for AuditXpert. Enriches security findings with business-language explanations, impact statements, and priority ratings using Claude (Anthropic) or OpenAI APIs.'
    PowerShellVersion = '5.1'
    RequiredModules   = @()
    FunctionsToExport = @('Invoke-TiTCAIExplainer')
    CmdletsToExport   = @()
    AliasesToExport   = @()
    PrivateData       = @{
        PSData = @{
            Tags       = @('Microsoft365', 'Security', 'AI', 'Claude', 'OpenAI', 'AuditXpert')
            ProjectUri = 'https://github.com/TakeItToCloud/AuditXpert'
        }
    }
}
