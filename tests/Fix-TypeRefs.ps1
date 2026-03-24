# Bulk-remove [TiTC*] type references from all non-Models source files
# Applies Rules A-E as per spec

$root  = 'C:\Scripts\Assessment\AuditXpert'
$scope = @(
    'src\Analyzers\TiTC.Analyzer.Risk.psm1'
    'src\Collectors\TiTC.Collector.Defender.psm1'
    'src\Collectors\TiTC.Collector.EntraID.psm1'
    'src\Collectors\TiTC.Collector.Exchange.psm1'
    'src\Collectors\TiTC.Collector.Intune.psm1'
    'src\Collectors\TiTC.Collector.Licensing.psm1'
    'src\Outputs\TiTC.Output.Report.psm1'
    'src\Outputs\TiTC.Output.Evidence.psm1'
    'src\Outputs\TiTC.Output.AIExplainer.psm1'
    'src\Core\TiTC.Core.psm1'
    'profiles\Invoke-M365Snapshot.ps1'
    'profiles\Invoke-MSPAuditPack.ps1'
    'profiles\Invoke-AuditExplainer.ps1'
)

$replacements = [ordered]@{
    # Rule B: OutputType attributes
    '\[OutputType\(\[TiTCCollectorResult\]\)\]'      = '[OutputType([PSObject])]'
    '\[OutputType\(\[TiTCFinding\]\)\]'              = '[OutputType([PSObject])]'
    '\[OutputType\(\[TiTCAssessmentReport\]\)\]'     = '[OutputType([PSObject])]'
    '\[OutputType\(\[TiTCRiskScore\]\)\]'            = '[OutputType([PSObject])]'
    '\[OutputType\(\[TiTCLicenseWaste\]\)\]'         = '[OutputType([PSObject])]'

    # Rule C: ::new() → factory functions
    '\[TiTCRiskScore\]::new\(\)'                     = 'New-TiTCRiskScore'
    '\[TiTCLicenseWaste\]::new\(\)'                  = 'New-TiTCLicenseWaste'
    '\[TiTCAssessmentReport\]::new\(\)'              = 'New-TiTCAssessmentReport'
    '\[TiTCFinding\]::new\(\)'                       = 'New-TiTCFinding'

    # Rule E: Enum references → string literals
    '\[TiTCSeverity\]::Critical'                     = "'Critical'"
    '\[TiTCSeverity\]::High'                         = "'High'"
    '\[TiTCSeverity\]::Medium'                       = "'Medium'"
    '\[TiTCSeverity\]::Low'                          = "'Low'"
    '\[TiTCSeverity\]::Info'                         = "'Info'"
    '\[TiTCCollectorStatus\]::PartialSuccess'        = "'PartialSuccess'"
    '\[TiTCCollectorStatus\]::Success'               = "'Success'"
    '\[TiTCCollectorStatus\]::Failed'                = "'Failed'"
    '\[TiTCFindingStatus\]::Open'                    = "'Open'"
    '\[TiTCFindingStatus\]::Closed'                  = "'Closed'"
    '\[TiTCFindingStatus\]::Accepted'                = "'Accepted'"
    '\[TiTCDomain\]::EntraID'                        = "'EntraID'"
    '\[TiTCDomain\]::Exchange'                       = "'Exchange'"
    '\[TiTCDomain\]::Intune'                         = "'Intune'"
    '\[TiTCDomain\]::Defender'                       = "'Defender'"
    '\[TiTCDomain\]::Licensing'                      = "'Licensing'"

    # Rule A: Parameter type annotations (must come AFTER ::new() replacements)
    # Typed array params
    '\[TiTCCollectorResult\[\]\](\s*\$)'             = '$1'
    '\[TiTCFinding\[\]\](\s*\$)'                     = '$1'
    # Typed single-object params
    '\[TiTCCollectorResult\](\s*\$)'                 = '$1'
    '\[TiTCFinding\](\s*\$)'                         = '$1'
    '\[TiTCRiskScore\](\s*\$)'                       = '$1'
    '\[TiTCAssessmentReport\](\s*\$)'                = '$1'
    '\[TiTCLicenseWaste\](\s*\$)'                    = '$1'
    # Enum params (replace with [string])
    '\[TiTCSeverity\](\s*\$)'                        = '[string]$1'
    '\[TiTCDomain\](\s*\$)'                          = '[string]$1'
    '\[TiTCComplianceFramework\](\s*\$)'             = '[string]$1'
    '\[TiTCFindingStatus\](\s*\$)'                   = '[string]$1'
    '\[TiTCCollectorStatus\](\s*\$)'                 = '[string]$1'
}

$totalChanged = 0
foreach ($rel in $scope) {
    $path = Join-Path $root $rel
    if (-not (Test-Path $path)) { Write-Host "SKIP (not found): $rel" -ForegroundColor DarkGray; continue }

    $content = Get-Content $path -Raw
    $updated = $content

    foreach ($pattern in $replacements.Keys) {
        $replacement = $replacements[$pattern]
        $updated = [regex]::Replace($updated, $pattern, $replacement)
    }

    if ($updated -ne $content) {
        Set-Content $path $updated -NoNewline
        Write-Host "Fixed: $rel" -ForegroundColor Green
        $totalChanged++
    } else {
        Write-Host "Clean: $rel" -ForegroundColor DarkGray
    }
}

Write-Host ""
Write-Host "Done. $totalChanged files modified." -ForegroundColor Cyan

# Verify: count remaining [TiTC references outside Models
Write-Host ""
Write-Host "Remaining [TiTC references in non-Models files:" -ForegroundColor Yellow
Get-ChildItem $root -Recurse -Include '*.psm1','*.ps1' |
    Where-Object { $_.FullName -notmatch '\\TiTC\.Models|\\tests\\' } |
    Select-String -Pattern '\[TiTC' |
    ForEach-Object { Write-Host "  $($_.Filename):$($_.LineNumber)  $($_.Line.Trim())" -ForegroundColor Red }
