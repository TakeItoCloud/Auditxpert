#Requires -Version 5.1
<#
.SYNOPSIS
    Focused regression tests for AuditXpert entry points and export contracts.
#>

BeforeAll {
    $ProjectRoot = Split-Path $PSScriptRoot -Parent

    $LauncherScript = Join-Path $ProjectRoot 'Start-AuditXpert.ps1'
    $SnapshotScript = Join-Path $ProjectRoot 'profiles\Invoke-M365Snapshot.ps1'
    $MspScript = Join-Path $ProjectRoot 'profiles\Invoke-MSPAuditPack.ps1'

    Import-Module (Join-Path $ProjectRoot 'src\Core\Models\TiTC.Models.psm1') -Force
    Import-Module (Join-Path $ProjectRoot 'src\Core\TiTC.Core.psm1') -Force
    Import-Module (Join-Path $ProjectRoot 'src\Outputs\TiTC.Output.AIExplainer.psm1') -Force
    Import-Module (Join-Path $ProjectRoot 'src\Outputs\TiTC.Output.Report.psm1') -Force
    Import-Module (Join-Path $ProjectRoot 'src\Outputs\TiTC.Output.Evidence.psm1') -Force

    function Get-ValidateSetValues {
        param(
            [Parameter(Mandatory)]
            [System.Management.Automation.CommandInfo]$Command,

            [Parameter(Mandatory)]
            [string]$ParameterName
        )

        return @(
            $Command.Parameters[$ParameterName].Attributes |
                Where-Object { $_ -is [System.Management.Automation.ValidateSetAttribute] } |
                Select-Object -ExpandProperty ValidValues
        )
    }

    function Get-FullExpansionFrameworks {
        param(
            [Parameter(Mandatory)]
            [string]$ScriptPath
        )

        $lines = Get-Content -Path $ScriptPath
        $startIndex = -1
        for ($i = 0; $i -lt $lines.Count; $i++) {
            if ($lines[$i] -match '^\$frameworksToRun\s*=\s*if\s*\(\$AuditPacks\s*-contains\s*''Full''\)\s*\{') {
                $startIndex = $i
                break
            }
        }

        if ($startIndex -lt 0) {
            throw "Could not locate Full framework expansion in $ScriptPath"
        }

        $blockLines = @()
        for ($i = $startIndex + 1; $i -lt $lines.Count; $i++) {
            if ($lines[$i] -match '^\}\s*else') { break }
            $blockLines += $lines[$i]
        }

        return @([regex]::Matches(($blockLines -join "`n"), "'([^']+)'") | ForEach-Object { $_.Groups[1].Value })
    }
}

Describe 'Start-AuditXpert launcher safety' {
    It 'parses cleanly' {
        { [void][scriptblock]::Create((Get-Content -Path $LauncherScript -Raw)) } | Should -Not -Throw
    }

    It 'Test-Prerequisites runs without inline if-expression errors' {
        $tokens = $null
        $errors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($LauncherScript, [ref]$tokens, [ref]$errors)
        $functionAst = $ast.Find(
            { param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Test-Prerequisites' },
            $true
        )

        $functionAst | Should -Not -BeNullOrEmpty
        . ([scriptblock]::Create($functionAst.Extent.Text))

        Mock Write-Host {}
        Mock Read-Host { '' }
        Mock Get-Module { [PSCustomObject]@{ Version = [version]'5.7.1' } }
        Mock Get-Command { [PSCustomObject]@{ Source = 'C:\Tools\wkhtmltopdf.exe' } }

        { Test-Prerequisites } | Should -Not -Throw
    }

    It 'does not contain inline if-blocks in format expression positions' {
        $content = Get-Content -Path $LauncherScript -Raw
        $content | Should -Not -Match '-f[^\r\n]*\(\s*if\s*\('
    }

    It 'captures a session OpenAI key explicitly for the current launcher run' {
        $tokens = $null
        $errors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($LauncherScript, [ref]$tokens, [ref]$errors)
        $secureReaderAst = $ast.Find(
            { param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Read-AuditXpertSecureText' },
            $true
        )
        $aiPromptAst = $ast.Find(
            { param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Get-AIApiKey' },
            $true
        )

        . ([scriptblock]::Create($secureReaderAst.Extent.Text))
        . ([scriptblock]::Create($aiPromptAst.Extent.Text))

        $previousAnthropic = $env:ANTHROPIC_API_KEY
        $previousOpenAI = $env:OPENAI_API_KEY
        $env:ANTHROPIC_API_KEY = ''
        $env:OPENAI_API_KEY = ''

        try {
            Mock Write-Host {}
            Mock Read-Host {
                param($Prompt)
                if ($Prompt -like '  Select AI configuration*') { return '2' }
                throw "Unexpected prompt: $Prompt"
            }
            Mock Read-AuditXpertSecureText { 'session-openai-key' }

            $aiSettings = Get-AIApiKey

            $aiSettings.Enabled | Should -BeTrue
            $aiSettings.Provider | Should -Be 'OpenAI'
            $aiSettings.ApiKey | Should -Be 'session-openai-key'
            $aiSettings.Status | Should -Be 'AI: OpenAI key loaded for this session'
        }
        finally {
            $env:ANTHROPIC_API_KEY = $previousAnthropic
            $env:OPENAI_API_KEY = $previousOpenAI
        }
    }

    It 'can intentionally disable AI from the launcher prompt' {
        $tokens = $null
        $errors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($LauncherScript, [ref]$tokens, [ref]$errors)
        $secureReaderAst = $ast.Find(
            { param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Read-AuditXpertSecureText' },
            $true
        )
        $aiPromptAst = $ast.Find(
            { param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Get-AIApiKey' },
            $true
        )

        . ([scriptblock]::Create($secureReaderAst.Extent.Text))
        . ([scriptblock]::Create($aiPromptAst.Extent.Text))

        Mock Write-Host {}
        Mock Read-Host { '4' }
        Mock Read-AuditXpertSecureText { throw 'Should not prompt for a key when AI is skipped.' }

        $aiSettings = Get-AIApiKey

        $aiSettings.Enabled | Should -BeFalse
        $aiSettings.ApiKey | Should -BeNullOrEmpty
        $aiSettings.Status | Should -Be 'AI: disabled'
    }

    It 'uses the selected environment AI key and passes provider and key through to snapshot launch params' {
        $tokens = $null
        $errors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($LauncherScript, [ref]$tokens, [ref]$errors)
        $aiPromptAst = $ast.Find(
            { param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Get-AIApiKey' },
            $true
        )
        $snapshotParamsAst = $ast.Find(
            { param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'New-SnapshotLaunchParams' },
            $true
        )

        . ([scriptblock]::Create($aiPromptAst.Extent.Text))
        . ([scriptblock]::Create($snapshotParamsAst.Extent.Text))

        $previousAnthropic = $env:ANTHROPIC_API_KEY
        $previousOpenAI = $env:OPENAI_API_KEY
        $env:ANTHROPIC_API_KEY = 'anthropic-env-key'
        $env:OPENAI_API_KEY = ''

        try {
            Mock Write-Host {}
            Mock Read-Host {
                param($Prompt)
                if ($Prompt -like '  Select AI configuration*') { return '1' }
                throw "Unexpected prompt: $Prompt"
            }

            $aiSettings = Get-AIApiKey
            $launchParams = New-SnapshotLaunchParams -AuthParams @{ TenantId = 'contoso.onmicrosoft.com' } -OutputPath 'C:\Reports\Test' -IncludeAIExplainer $aiSettings.Enabled -AIApiKey $aiSettings.ApiKey -AIProvider $aiSettings.Provider

            $aiSettings.Provider | Should -Be 'Claude'
            $aiSettings.ApiKey | Should -Be 'anthropic-env-key'
            $aiSettings.Status | Should -Be 'AI: Claude key loaded from environment'
            $launchParams.IncludeAIExplainer | Should -BeTrue
            $launchParams.AIProvider | Should -Be 'Claude'
            $launchParams.AIApiKey | Should -Be 'anthropic-env-key'
        }
        finally {
            $env:ANTHROPIC_API_KEY = $previousAnthropic
            $env:OPENAI_API_KEY = $previousOpenAI
        }
    }

    It 'builds snapshot launch params using only declared snapshot parameters' {
        $tokens = $null
        $errors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($LauncherScript, [ref]$tokens, [ref]$errors)
        $functionAst = $ast.Find(
            { param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'New-SnapshotLaunchParams' },
            $true
        )

        $functionAst | Should -Not -BeNullOrEmpty
        . ([scriptblock]::Create($functionAst.Extent.Text))

        $snapshotParameters = (Get-Command $SnapshotScript).Parameters.Keys
        $interactiveArgs = @{
            AuthParams = @{ TenantId = 'contoso.onmicrosoft.com' }
            OutputPath = 'C:\Reports\Test'
            IncludeAIExplainer = $false
            AIApiKey = $null
            AIProvider = $null
        }
        $interactiveParams = New-SnapshotLaunchParams @interactiveArgs
        $certArgs = @{
            AuthParams = @{
                TenantId = 'contoso.onmicrosoft.com'
                ClientId = '11111111-1111-1111-1111-111111111111'
                CertificateThumbprint = 'ABCDEF1234567890'
            }
            OutputPath = 'C:\Reports\Test'
            IncludeAIExplainer = $true
            AIApiKey = 'session-key'
            AIProvider = 'Claude'
        }
        $certParams = New-SnapshotLaunchParams @certArgs

        @($interactiveParams.Keys | Where-Object { $_ -notin $snapshotParameters }).Count | Should -Be 0
        @($certParams.Keys | Where-Object { $_ -notin $snapshotParameters }).Count | Should -Be 0
        $interactiveParams.ContainsKey('Interactive') | Should -BeFalse
        $interactiveParams.ContainsKey('ClientId') | Should -BeFalse
        $interactiveParams.ContainsKey('CertificateThumbprint') | Should -BeFalse
        $certParams.OutputFormat | Should -Be 'HTML'
        $certParams.AIApiKey | Should -Be 'session-key'
        $certParams.AIProvider | Should -Be 'Claude'
    }

    It 'builds MSP launch params using only declared MSP parameters' {
        $tokens = $null
        $errors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($LauncherScript, [ref]$tokens, [ref]$errors)
        $functionAst = $ast.Find(
            { param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'New-MSPLaunchParams' },
            $true
        )

        $functionAst | Should -Not -BeNullOrEmpty
        . ([scriptblock]::Create($functionAst.Extent.Text))

        $mspParameters = (Get-Command $MspScript).Parameters.Keys
        $interactiveArgs = @{
            AuthParams = @{ TenantId = 'contoso.onmicrosoft.com' }
            OutputPath = 'C:\Reports\Test'
            IncludeAIExplainer = $false
            MSPCompanyName = 'TakeItToCloud'
            AIApiKey = $null
            AIProvider = $null
        }
        $interactiveParams = New-MSPLaunchParams @interactiveArgs
        $certArgs = @{
            AuthParams = @{
                TenantId = 'contoso.onmicrosoft.com'
                ClientId = '11111111-1111-1111-1111-111111111111'
                CertificateThumbprint = 'ABCDEF1234567890'
            }
            OutputPath = 'C:\Reports\Test'
            IncludeAIExplainer = $true
            MSPCompanyName = 'TakeItToCloud'
            AIApiKey = 'session-key'
            AIProvider = 'OpenAI'
        }
        $certParams = New-MSPLaunchParams @certArgs

        @($interactiveParams.Keys | Where-Object { $_ -notin $mspParameters }).Count | Should -Be 0
        @($certParams.Keys | Where-Object { $_ -notin $mspParameters }).Count | Should -Be 0
        $interactiveParams.ContainsKey('ReportFormat') | Should -BeTrue
        $interactiveParams.ContainsKey('OutputFormat') | Should -BeFalse
        $interactiveParams.ContainsKey('Profile') | Should -BeFalse
        $interactiveParams.ContainsKey('IncludeEvidence') | Should -BeFalse
        $interactiveParams.ContainsKey('SkipBanner') | Should -BeFalse
        $certParams.ReportFormat | Should -Be 'HTML'
        $certParams.AIApiKey | Should -Be 'session-key'
        $certParams.AIProvider | Should -Be 'OpenAI'
    }

    It 'builds full assessment launch params that are valid for both snapshot and MSP targets' {
        $tokens = $null
        $errors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($LauncherScript, [ref]$tokens, [ref]$errors)
        $snapshotAst = $ast.Find(
            { param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'New-SnapshotLaunchParams' },
            $true
        )
        $mspAst = $ast.Find(
            { param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'New-MSPLaunchParams' },
            $true
        )

        . ([scriptblock]::Create($snapshotAst.Extent.Text))
        . ([scriptblock]::Create($mspAst.Extent.Text))

        $authParams = @{
            TenantId = 'contoso.onmicrosoft.com'
            ClientId = '11111111-1111-1111-1111-111111111111'
            CertificateThumbprint = 'ABCDEF1234567890'
        }

        $snapshotParams = New-SnapshotLaunchParams -AuthParams $authParams -OutputPath 'C:\Reports\Test' -IncludeAIExplainer $true -AIApiKey 'session-key' -AIProvider 'Claude'
        $mspParams = New-MSPLaunchParams -AuthParams $authParams -OutputPath 'C:\Reports\Test' -IncludeAIExplainer $true -MSPCompanyName 'TakeItToCloud' -AIApiKey 'session-key' -AIProvider 'Claude'
        $snapshotSupported = (Get-Command $SnapshotScript).Parameters.Keys
        $mspSupported = (Get-Command $MspScript).Parameters.Keys

        @($snapshotParams.Keys | Where-Object { $_ -notin $snapshotSupported }).Count | Should -Be 0
        @($mspParams.Keys | Where-Object { $_ -notin $mspSupported }).Count | Should -Be 0
    }

    It 'builds cert auth launch params using only parameters supported by each target' {
        $tokens = $null
        $errors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($LauncherScript, [ref]$tokens, [ref]$errors)
        $snapshotAst = $ast.Find(
            { param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'New-SnapshotLaunchParams' },
            $true
        )
        $mspAst = $ast.Find(
            { param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'New-MSPLaunchParams' },
            $true
        )

        . ([scriptblock]::Create($snapshotAst.Extent.Text))
        . ([scriptblock]::Create($mspAst.Extent.Text))

        $authParams = @{
            TenantId = 'contoso.onmicrosoft.com'
            ClientId = '11111111-1111-1111-1111-111111111111'
            CertificateThumbprint = 'ABCDEF1234567890'
        }

        $snapshotParams = New-SnapshotLaunchParams -AuthParams $authParams -OutputPath 'C:\Reports\Test' -IncludeAIExplainer $false -AIApiKey $null -AIProvider $null
        $mspParams = New-MSPLaunchParams -AuthParams $authParams -OutputPath 'C:\Reports\Test' -IncludeAIExplainer $false -MSPCompanyName 'TakeItToCloud' -AIApiKey $null -AIProvider $null

        $snapshotParams.ContainsKey('ClientId') | Should -BeTrue
        $snapshotParams.ContainsKey('CertificateThumbprint') | Should -BeTrue
        $snapshotParams.ContainsKey('ClientSecret') | Should -BeFalse
        $mspParams.ContainsKey('ClientId') | Should -BeTrue
        $mspParams.ContainsKey('CertificateThumbprint') | Should -BeTrue
        $mspParams.ContainsKey('ClientSecret') | Should -BeFalse
    }

    It 'builds app auth launch params using only parameters supported by each target' {
        $tokens = $null
        $errors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($LauncherScript, [ref]$tokens, [ref]$errors)
        $snapshotAst = $ast.Find(
            { param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'New-SnapshotLaunchParams' },
            $true
        )
        $mspAst = $ast.Find(
            { param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'New-MSPLaunchParams' },
            $true
        )

        . ([scriptblock]::Create($snapshotAst.Extent.Text))
        . ([scriptblock]::Create($mspAst.Extent.Text))

        $authParams = @{
            TenantId = 'contoso.onmicrosoft.com'
            ClientId = '11111111-1111-1111-1111-111111111111'
            ClientSecret = 'test-secret'
        }

        $snapshotParams = New-SnapshotLaunchParams -AuthParams $authParams -OutputPath 'C:\Reports\Test' -IncludeAIExplainer $false -AIApiKey $null -AIProvider $null
        $mspParams = New-MSPLaunchParams -AuthParams $authParams -OutputPath 'C:\Reports\Test' -IncludeAIExplainer $false -MSPCompanyName 'TakeItToCloud' -AIApiKey $null -AIProvider $null

        $snapshotParams.ContainsKey('ClientId') | Should -BeTrue
        $snapshotParams.ContainsKey('ClientSecret') | Should -BeTrue
        $snapshotParams.ContainsKey('CertificateThumbprint') | Should -BeFalse
        $mspParams.ContainsKey('ClientId') | Should -BeTrue
        $mspParams.ContainsKey('ClientSecret') | Should -BeTrue
        $mspParams.ContainsKey('CertificateThumbprint') | Should -BeFalse
    }
}

Describe 'Snapshot auth parameter contract' {
    BeforeAll {
        $snapshotCommand = Get-Command $SnapshotScript
        $snapshotCertSet = $snapshotCommand.ParameterSets | Where-Object Name -eq 'CertAuth'
    }

    It 'declares ClientId in the CertAuth parameter set' {
        $snapshotCertSet.Parameters.Name | Should -Contain 'ClientId'
    }

    It 'requires ClientId in the CertAuth parameter set' {
        ($snapshotCertSet.Parameters | Where-Object Name -eq 'ClientId').IsMandatory | Should -BeTrue
    }

    It 'requires CertificateThumbprint in the CertAuth parameter set' {
        ($snapshotCertSet.Parameters | Where-Object Name -eq 'CertificateThumbprint').IsMandatory | Should -BeTrue
    }

    It 'keeps AppAuth and CertAuth parameter sets distinct' {
        $snapshotCommand.ParameterSets.Name | Should -Contain 'AppAuth'
        $snapshotCommand.ParameterSets.Name | Should -Contain 'CertAuth'
        $snapshotCommand.ParameterSets.Name | Should -Contain 'Interactive'
    }

    It 'maps OutputFormat All to the dual-artifact report format without inline if-expression arguments' {
        $content = Get-Content -Path $SnapshotScript -Raw
        $content.Contains("`$reportFormat = if (`$OutputFormat -eq 'All') { 'Both' } else { `$OutputFormat }") | Should -BeTrue
        $content | Should -Match '-CompanyName\s+\$reportCompanyName'
        $content | Should -Not -Match '-CompanyName\s+\(if\s*\('
    }

    It 'declares AI provider and API key parameters for launcher pass-through' {
        $snapshotCommand.Parameters.Keys | Should -Contain 'AIApiKey'
        $snapshotCommand.Parameters.Keys | Should -Contain 'AIProvider'
        (Get-ValidateSetValues -Command $snapshotCommand -ParameterName 'AIProvider') | Should -Contain 'Auto'
    }
}

Describe 'MSP auth and framework contracts' {
    BeforeAll {
        $mspCommand = Get-Command $MspScript
        $mspCertSet = $mspCommand.ParameterSets | Where-Object Name -eq 'CertAuth'
        $auditPackValidateSet = Get-ValidateSetValues -Command $mspCommand -ParameterName 'AuditPacks'
        $fullExpansionFrameworks = Get-FullExpansionFrameworks -ScriptPath $MspScript
    }

    It 'declares ClientId in the CertAuth parameter set' {
        $mspCertSet.Parameters.Name | Should -Contain 'ClientId'
    }

    It 'requires ClientId in the CertAuth parameter set' {
        ($mspCertSet.Parameters | Where-Object Name -eq 'ClientId').IsMandatory | Should -BeTrue
    }

    It 'includes CISControls in the AuditPacks ValidateSet' {
        $auditPackValidateSet | Should -Contain 'CISControls'
    }

    It 'keeps the Full framework expansion aligned with the explicit AuditPacks ValidateSet' {
        $explicitFrameworks = @($auditPackValidateSet | Where-Object { $_ -ne 'Full' } | Sort-Object)
        @($fullExpansionFrameworks | Sort-Object) | Should -Be $explicitFrameworks
    }

    It 'passes ReportFormat through to Export-TiTCReport without coercing Both to PDF' {
        $content = Get-Content -Path $MspScript -Raw
        $content | Should -Match '-Format\s+\$ReportFormat'
        $content | Should -Not -Match "Both'\)\s*\{\s*'PDF'"
    }

    It 'declares AI provider and API key parameters for launcher pass-through' {
        $mspCommand.Parameters.Keys | Should -Contain 'AIApiKey'
        $mspCommand.Parameters.Keys | Should -Contain 'AIProvider'
        (Get-ValidateSetValues -Command $mspCommand -ParameterName 'AIProvider') | Should -Contain 'Auto'
    }
}

Describe 'AI explainer provider resolution' {
    It 'supports Auto provider and resolves to Claude when ANTHROPIC_API_KEY is available' {
        $previousAnthropic = $env:ANTHROPIC_API_KEY
        $previousOpenAI = $env:OPENAI_API_KEY
        $env:ANTHROPIC_API_KEY = 'anthropic-test-key'
        $env:OPENAI_API_KEY = ''

        try {
            InModuleScope 'TiTC.Output.AIExplainer' {
                Mock Write-TiTCLog {}
                Mock Build-TiTCAIPrompt { 'prompt' }
                Mock Invoke-TiTCAIRequest { '{"risk":"R","impact":"I","priority":3}' }
                Mock Parse-TiTCAIResponse { @{ Risk = 'R'; Impact = 'I'; Priority = 3 } }

                $finding = [pscustomobject]@{
                    Title = 'Test finding'
                    Severity = 'High'
                    AIExplanation = $null
                    AIBusinessImpact = $null
                    AIPriority = $null
                }

                $result = Invoke-TiTCAIExplainer -Findings @($finding) -Provider Auto -MaxFindings 1
                $result.Count | Should -Be 1
                Should -Invoke Invoke-TiTCAIRequest -Times 1 -ParameterFilter { $Provider -eq 'Claude' -and $ApiKey -eq 'anthropic-test-key' }
            }
        }
        finally {
            $env:ANTHROPIC_API_KEY = $previousAnthropic
            $env:OPENAI_API_KEY = $previousOpenAI
        }
    }

    It 'throws a precise error when Claude is selected without ANTHROPIC_API_KEY' {
        $previousAnthropic = $env:ANTHROPIC_API_KEY
        $env:ANTHROPIC_API_KEY = ''

        try {
            InModuleScope 'TiTC.Output.AIExplainer' {
                Mock Write-TiTCLog {}

                {
                    Invoke-TiTCAIExplainer -Findings @([pscustomobject]@{ Title = 'Test'; Severity = 'High' }) -Provider Claude -MaxFindings 1
                } | Should -Throw "*requires API key 'ANTHROPIC_API_KEY'*"
            }
        }
        finally {
            $env:ANTHROPIC_API_KEY = $previousAnthropic
        }
    }
}

Describe 'Export-TiTCReport report format behavior' {
    It 'returns both artifact paths when Format Both is requested and wkhtmltopdf is available' {
        $outputBase = Join-Path $TestDrive 'security-assessment-report'

        function global:wkhtmltopdf {
            param([Parameter(ValueFromRemainingArguments = $true)][object[]]$RemainingArgs)
            $pdfPath = $RemainingArgs[-1]
            Set-Content -Path $pdfPath -Value 'pdf-bytes' -Encoding UTF8
        }

        try {
            InModuleScope 'TiTC.Output.Report' -Parameters @{ OutputBase = $outputBase } {
                param($OutputBase)

                Mock Build-TiTCReportHTML { '<html><body>report</body></html>' }
                Mock Write-TiTCLog {}

                $result = Export-TiTCReport -AssessmentData @{ Report = @{}; RiskAnalysis = @{}; ExecutiveSummary = @{} } `
                    -OutputPath $OutputBase `
                    -Format Both

                $result.HtmlPath | Should -Be "$OutputBase.html"
                $result.PdfPath | Should -Be "$OutputBase.pdf"
                Test-Path $result.HtmlPath | Should -BeTrue
                Test-Path $result.PdfPath | Should -BeTrue
            }
        }
        finally {
            Remove-Item function:\wkhtmltopdf -ErrorAction SilentlyContinue
        }
    }

    It 'fails fast for Format Both when wkhtmltopdf is unavailable' {
        Remove-Item function:\wkhtmltopdf -ErrorAction SilentlyContinue
        $outputBase = Join-Path $TestDrive 'report-no-pdf'

        InModuleScope 'TiTC.Output.Report' -Parameters @{ OutputBase = $outputBase } {
            param($OutputBase)

            Mock Build-TiTCReportHTML { '<html><body>report</body></html>' }
            Mock Write-TiTCLog {}

            {
                Export-TiTCReport -AssessmentData @{ Report = @{}; RiskAnalysis = @{}; ExecutiveSummary = @{} } `
                    -OutputPath $OutputBase `
                    -Format Both
            } | Should -Throw "*requires wkhtmltopdf*"
        }
    }
}

Describe 'Evidence export framework validation' {
    BeforeAll {
        $evidenceCommand = Get-Command Export-TiTCEvidencePack
        $evidenceValidateSet = Get-ValidateSetValues -Command $evidenceCommand -ParameterName 'Frameworks'
    }

    It 'accepts the documented sentinel and explicit framework names' {
        $evidenceValidateSet | Should -Contain 'All'
        $evidenceValidateSet | Should -Contain 'ISO27001'
        $evidenceValidateSet | Should -Contain 'SOC2Lite'
        $evidenceValidateSet | Should -Contain 'CyberInsurance'
        $evidenceValidateSet | Should -Contain 'CISControls'
        $evidenceValidateSet | Should -Contain 'InternalRisk'
    }

    It 'rejects unsupported framework names at parameter binding time' {
        {
            Export-TiTCEvidencePack -Report ([PSCustomObject]@{}) -OutputPath $TestDrive -Frameworks 'NotAFramework'
        } | Should -Throw
    }

    It 'uses resolved framework variables in orchestration instead of a literal All sentinel' {
        $snapshotContent = Get-Content -Path $SnapshotScript -Raw
        $mspContent = Get-Content -Path $MspScript -Raw

        $snapshotContent | Should -Match '-Frameworks\s+\$evidenceFrameworks'
        $snapshotContent | Should -Not -Match "-Frameworks\s+@\('All'\)"
        $mspContent | Should -Match '-Frameworks\s+\$frameworksToRun'
    }
}
