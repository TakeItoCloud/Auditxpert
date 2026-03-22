@{
    RootModule        = 'TiTC.Analyzer.Risk.psm1'
    ModuleVersion     = '1.0.0'
    GUID              = 'b8c9d0e1-f2a3-4567-bcde-678901234567'
    Author            = 'TakeItToCloud'
    CompanyName       = 'TakeItToCloud'
    Copyright         = '(c) 2026 TakeItToCloud. All rights reserved.'
    Description       = 'Risk scoring and analysis engine for AuditXpert. Provides composite scoring, category scoring, remediation prioritization, quick wins identification, compliance gap analysis, and executive narrative generation.'
    PowerShellVersion = '5.1'
    RequiredModules   = @()
    FunctionsToExport = @('Invoke-TiTCRiskAnalysis')
    CmdletsToExport   = @()
    AliasesToExport   = @()
    PrivateData       = @{
        PSData = @{
            Tags       = @('Microsoft365', 'Security', 'RiskScoring', 'Compliance', 'AuditXpert')
            ProjectUri = 'https://github.com/TakeItToCloud/AuditXpert'
        }
    }
}
