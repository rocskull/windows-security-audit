<#
.SYNOPSIS
    Exports Windows configuration audit results to HTML, CSV, JSON, and Excel.

.DESCRIPTION
    Provides dependency-free report generation for framework result objects.
    Reports are written locally and no JavaScript libraries, web assets, or
    system configuration changes are used.
#>

Set-StrictMode -Version Latest

$script:ResultProperties = @(
    'ControlID', 'BenchmarkName', 'BenchmarkVersion', 'BenchmarkFile', 'Profile',
    'Category', 'SubCategory', 'Title', 'Expected', 'Actual', 'Status',
    'Severity', 'Evidence', 'Remediation', 'Reference', 'Timestamp',
    'ComputerName', 'User'
)
$script:DefaultReportsDirectory = Join-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -ChildPath 'Reports'

function Get-ReportValue {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)] [psobject]$Result,
        [Parameter(Mandatory = $true)] [string]$Name
    )

    $property = $Result.PSObject.Properties[$Name]
    if ($null -eq $property -or $null -eq $property.Value) {
        return ''
    }

    if ($property.Value -is [datetime]) {
        return $property.Value.ToString('o')
    }

    return [string]$property.Value
}

function ConvertTo-HtmlEncoded {
    [CmdletBinding()]
    param ([AllowNull()][object]$Value)

    return [System.Net.WebUtility]::HtmlEncode([string]$Value)
}

function Get-ReportStatus {
    [CmdletBinding()]
    param ([Parameter(Mandatory = $true)] [psobject]$Result)

    return (Get-ReportValue -Result $Result -Name 'Status').Trim().ToUpperInvariant()
}

function Get-AuditReportSummary {
    [CmdletBinding()]
    param ([Parameter()] [object[]]$Results)

    $allResults = @($Results | Where-Object { $null -ne $_ })
    $statusCounts = [ordered]@{
        'PASS'           = 0
        'FAIL'           = 0
        'WARNING'        = 0
        'NOT APPLICABLE' = 0
    }

    foreach ($result in $allResults) {
        $status = Get-ReportStatus -Result $result
        if ($statusCounts.Contains($status)) {
            $statusCounts[$status]++
        }
    }

    $scoredCount = $statusCounts['PASS'] + $statusCounts['FAIL']
    $compliancePercent = if ($scoredCount -gt 0) {
        [Math]::Round((100 * $statusCounts['PASS'] / $scoredCount), 2)
    }
    else {
        0
    }

    $categoryBreakdown = foreach ($group in ($allResults | Group-Object -Property { Get-ReportValue -Result $_ -Name 'Category' } | Sort-Object Name)) {
        $categoryResults = @($group.Group)
        $pass = @($categoryResults | Where-Object { (Get-ReportStatus -Result $_) -eq 'PASS' }).Count
        $fail = @($categoryResults | Where-Object { (Get-ReportStatus -Result $_) -eq 'FAIL' }).Count
        $warning = @($categoryResults | Where-Object { (Get-ReportStatus -Result $_) -eq 'WARNING' }).Count
        $notApplicable = @($categoryResults | Where-Object { (Get-ReportStatus -Result $_) -eq 'NOT APPLICABLE' }).Count
        $categoryScored = $pass + $fail
        [pscustomobject]@{
            Category          = if ([string]::IsNullOrWhiteSpace($group.Name)) { 'Uncategorized' } else { $group.Name }
            Total             = $categoryResults.Count
            Pass              = $pass
            Fail              = $fail
            Warning           = $warning
            NotApplicable     = $notApplicable
            CompliancePercent = if ($categoryScored -gt 0) { [Math]::Round((100 * $pass / $categoryScored), 2) } else { 0 }
        }
    }

    $criticalFindings = @($allResults | Where-Object {
        (Get-ReportStatus -Result $_) -eq 'FAIL' -and (Get-ReportValue -Result $_ -Name 'Severity').Trim().ToUpperInvariant() -eq 'CRITICAL'
    })

    return [pscustomobject]@{
        GeneratedAt       = Get-Date
        Total             = $allResults.Count
        Pass              = $statusCounts['PASS']
        Fail              = $statusCounts['FAIL']
        Warning           = $statusCounts['WARNING']
        NotApplicable     = $statusCounts['NOT APPLICABLE']
        CompliancePercent = $compliancePercent
        CriticalFindings  = $criticalFindings
        CategoryBreakdown = @($categoryBreakdown)
    }
}

function Get-ReportBenchmarks {
    <#
    .SYNOPSIS
        Returns the unique benchmark name, version, and definition tuples.
    #>
    [CmdletBinding()]
    param ([Parameter()] [object[]]$Results)

    $seen = @{}
    foreach ($result in @($Results | Where-Object { $null -ne $_ })) {
        $definition = Get-ReportValue -Result $result -Name 'BenchmarkFile'
        $name = Get-ReportValue -Result $result -Name 'BenchmarkName'
        $version = Get-ReportValue -Result $result -Name 'BenchmarkVersion'
        $key = '{0}|{1}|{2}' -f $definition, $name, $version
        if ($seen.ContainsKey($key)) { continue }
        $seen[$key] = $true
        [pscustomobject][ordered]@{
            Name       = $name
            Version    = $version
            Definition = $definition
        }
    }
}

function Resolve-ReportOutputPath {
    [CmdletBinding()]
    param (
        [Parameter()] [string]$OutputDirectory,
        [Parameter(Mandatory = $true)] [string]$Extension,
        [Parameter()] [string]$Path
    )

    if (-not [string]::IsNullOrWhiteSpace($Path)) {
        $parent = Split-Path -Path $Path -Parent
        if (-not [string]::IsNullOrWhiteSpace($parent) -and -not (Test-Path -LiteralPath $parent -PathType Container)) {
            New-Item -ItemType Directory -Path $parent -Force | Out-Null
        }
        return $Path
    }

    if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
        $OutputDirectory = $script:DefaultReportsDirectory
    }
    if (-not (Test-Path -LiteralPath $OutputDirectory -PathType Container)) {
        New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
    }

    return (Join-Path -Path $OutputDirectory -ChildPath ('CISAuditReport_{0}.{1}' -f (Get-Date -Format 'yyyyMMdd_HHmmss'), $Extension))
}

function Get-ReportRows {
    [CmdletBinding()]
    param ([Parameter()] [object[]]$Results)

    foreach ($result in @($Results | Where-Object { $null -ne $_ })) {
        $row = [ordered]@{}
        foreach ($propertyName in $script:ResultProperties) {
        $row[$propertyName] = Get-ReportValue -Result $result -Name $propertyName
        }
        [pscustomobject]$row
    }
}

function Get-StatusCssClass {
    [CmdletBinding()]
    param ([Parameter(Mandatory = $true)] [string]$Status)

    return ('status-{0}' -f ($Status.ToLowerInvariant().Replace(' ', '-')))
}

function ConvertTo-HtmlTableRows {
    [CmdletBinding()]
    param (
        [Parameter()] [object[]]$Results,
        [Parameter(Mandatory = $true)] [string[]]$Properties
    )

    $builder = New-Object System.Text.StringBuilder
    foreach ($result in @($Results | Where-Object { $null -ne $_ })) {
        [void]$builder.Append('<tr>')
        foreach ($propertyName in $Properties) {
            $value = Get-ReportValue -Result $result -Name $propertyName
            if ($propertyName -eq 'Status') {
                $cssClass = Get-StatusCssClass -Status $value
                [void]$builder.AppendFormat('<td><span class="status {0}">{1}</span></td>', $cssClass, (ConvertTo-HtmlEncoded $value))
            }
            else {
                [void]$builder.AppendFormat('<td>{0}</td>', (ConvertTo-HtmlEncoded $value))
            }
        }
        [void]$builder.Append('</tr>')
    }
    return $builder.ToString()
}

function Generate-HTMLReport {
    <#
    .SYNOPSIS
        Creates a modern, self-contained HTML audit report.

    .PARAMETER Results
        Collection of CIS result objects.

    .PARAMETER OutputDirectory
        Directory for the generated report. Defaults to the project's Reports folder.

    .PARAMETER Path
        Optional explicit HTML output path.

    .OUTPUTS
        System.IO.FileInfo
    #>
    [CmdletBinding()]
    param (
        [Parameter()] [object[]]$Results,
        [Parameter()] [string]$OutputDirectory,
        [Parameter()] [string]$Path
    )

    $reportPath = Resolve-ReportOutputPath -OutputDirectory $OutputDirectory -Extension 'html' -Path $Path
    $summary = Get-AuditReportSummary -Results $Results
    $allResults = @($Results | Where-Object { $null -ne $_ })

    $categoryRows = foreach ($category in $summary.CategoryBreakdown) {
        '<tr><td>{0}</td><td>{1}</td><td>{2}</td><td>{3}</td><td>{4}</td><td>{5}</td><td>{6:N2}%</td></tr>' -f (ConvertTo-HtmlEncoded $category.Category), $category.Total, $category.Pass, $category.Fail, $category.Warning, $category.NotApplicable, $category.CompliancePercent
    }
    if (@($categoryRows).Count -eq 0) {
        $categoryRows = '<tr><td colspan="7" class="empty">No audit results were supplied.</td></tr>'
    }

    $criticalRows = ConvertTo-HtmlTableRows -Results $summary.CriticalFindings -Properties @('ControlID', 'Category', 'Title', 'Actual', 'Remediation')
    if ([string]::IsNullOrWhiteSpace($criticalRows)) {
        $criticalRows = '<tr><td colspan="5" class="empty">No critical failed findings.</td></tr>'
    }
    $failedRows = ConvertTo-HtmlTableRows -Results @($allResults | Where-Object { (Get-ReportStatus $_) -eq 'FAIL' }) -Properties @('ControlID','Category','Title','Severity','Actual')
    if ([string]::IsNullOrWhiteSpace($failedRows)) { $failedRows = '<tr><td colspan="5" class="empty">No failed controls.</td></tr>' }
    $remediationRows = ConvertTo-HtmlTableRows -Results @($allResults | Where-Object { (Get-ReportStatus $_) -in @('FAIL','WARNING') }) -Properties @('ControlID','Category','Title','Status','Severity','Remediation')
    if ([string]::IsNullOrWhiteSpace($remediationRows)) { $remediationRows = '<tr><td colspan="6" class="empty">No remediation actions are required.</td></tr>' }
    $first = @($allResults | Select-Object -First 1); $machine = if($first.Count){Get-ReportValue $first[0] 'ComputerName'}else{$env:COMPUTERNAME}; $user = if($first.Count){Get-ReportValue $first[0] 'User'}else{$env:USERNAME}
    $benchmarks = @(Get-ReportBenchmarks -Results $allResults)
    $benchmarkName = if($benchmarks.Count){@($benchmarks | ForEach-Object Name) -join '; '}else{'Unavailable'}
    $benchmarkVersion = if($benchmarks.Count){@($benchmarks | ForEach-Object Version) -join '; '}else{'Unavailable'}
    $benchmarkFile = if($benchmarks.Count){@($benchmarks | ForEach-Object Definition) -join '; '}else{'Unavailable'}
    try { $identity=[Security.Principal.WindowsIdentity]::GetCurrent(); $executionMode=if((New-Object Security.Principal.WindowsPrincipal($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){'Administrator'}else{'Standard User'} } catch { $executionMode='Standard User' }
    try { $computerSystem=Get-CimInstance Win32_ComputerSystem -ErrorAction Stop; $domain=if($computerSystem.PartOfDomain){$computerSystem.Domain}else{'Workgroup'} } catch { $domain='Unavailable' }
    try { $os=Get-CimInstance Win32_OperatingSystem -ErrorAction Stop; $windows='{0} ({1}) Build {2}' -f $os.Caption,$os.Version,$os.BuildNumber } catch { try { $cv=Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction Stop; $productName=[string]$cv.ProductName;if([int]$cv.CurrentBuildNumber -ge 22000){$productName=$productName -replace 'Windows 10','Windows 11'};$windows='{0} (10.0.{1}) Build {1}' -f $productName,$cv.CurrentBuildNumber } catch { $windows='Unavailable' } }
    try { $av=@(Get-CimInstance -Namespace root\SecurityCenter2 -Class AntiVirusProduct -ErrorAction Stop|ForEach-Object displayName)-join '; ';if(!$av){$av='None detected'} } catch { $av='Unavailable' }
    $machineRows='<tr><th>CIS Benchmark</th><td>{0}</td></tr><tr><th>Benchmark Version</th><td>{1}</td></tr><tr><th>Benchmark Definition</th><td>{2}</td></tr><tr><th>Execution Mode</th><td>{3}</td></tr><tr><th>Computer Name / Hostname</th><td>{4}</td></tr><tr><th>Domain</th><td>{5}</td></tr><tr><th>Audit User</th><td>{6}</td></tr><tr><th>Windows Version</th><td>{7}</td></tr><tr><th>PowerShell Version</th><td>{8}</td></tr><tr><th>Execution Policy</th><td>{9}</td></tr><tr><th>Installed Antivirus</th><td>{10}</td></tr><tr><th>Export Time</th><td>{11}</td></tr>' -f (ConvertTo-HtmlEncoded $benchmarkName),(ConvertTo-HtmlEncoded $benchmarkVersion),(ConvertTo-HtmlEncoded $benchmarkFile),(ConvertTo-HtmlEncoded $executionMode),(ConvertTo-HtmlEncoded $machine),(ConvertTo-HtmlEncoded $domain),(ConvertTo-HtmlEncoded $user),(ConvertTo-HtmlEncoded $windows),(ConvertTo-HtmlEncoded $PSVersionTable.PSVersion),(ConvertTo-HtmlEncoded (Get-ExecutionPolicy)),(ConvertTo-HtmlEncoded $av),(ConvertTo-HtmlEncoded $summary.GeneratedAt.ToString('yyyy-MM-dd HH:mm:ss K'))
    function Get-Posture { param([string]$Pattern) $x=@($allResults|Where-Object{(Get-ReportValue $_ 'Category') -match $Pattern});if(!$x.Count){return 'No related findings.'};'{0} PASS, {1} FAIL, {2} total' -f @($x|Where-Object{(Get-ReportStatus $_)-eq'PASS'}).Count,@($x|Where-Object{(Get-ReportStatus $_)-eq'FAIL'}).Count,$x.Count }
    $bitlocker=Get-Posture 'BitLocker';$defender=Get-Posture 'Defender|ASR|SmartScreen';$firewall=Get-Posture 'Firewall';$admins=@($allResults|Where-Object{(Get-ReportValue $_ 'Title') -eq 'Members of Local Administrators'}|ForEach-Object{Get-ReportValue $_ 'Actual'})-join '; ';if(!$admins){$admins='No finding returned.'}

    $findingRows = ConvertTo-HtmlTableRows -Results $allResults -Properties @('ControlID', 'Category', 'SubCategory', 'Title', 'Status', 'Severity', 'Expected', 'Actual', 'Evidence', 'Remediation', 'Reference')
    if ([string]::IsNullOrWhiteSpace($findingRows)) {
        $findingRows = '<tr><td colspan="11" class="empty">No audit results were supplied.</td></tr>'
    }

    $html = @"
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Windows CIS Configuration Assessment</title>
<style>
:root { --ink:#132238; --muted:#637083; --surface:#ffffff; --canvas:#f3f6fa; --line:#dfe6ef; --blue:#2364aa; --green:#12715b; --red:#bd3e3e; --amber:#a76500; --slate:#5d6775; }
* { box-sizing:border-box; } body { margin:0; background:var(--canvas); color:var(--ink); font-family:Segoe UI,Arial,sans-serif; font-size:14px; line-height:1.45; }
.hero { background:linear-gradient(125deg,#12253d,#2364aa); color:#fff; padding:42px max(28px,calc((100vw - 1320px)/2)); } .hero h1 { margin:0 0 6px; font-size:30px; } .hero p { margin:0; color:#dceaff; }
.container { max-width:1320px; margin:0 auto; padding:28px; } .section { background:var(--surface); border:1px solid var(--line); border-radius:12px; box-shadow:0 4px 18px rgba(19,34,56,.05); margin-bottom:24px; overflow:hidden; }
.section h2 { font-size:18px; margin:0; padding:18px 20px; border-bottom:1px solid var(--line); } .section-body { padding:20px; }
.cards { display:grid; grid-template-columns:repeat(6,minmax(130px,1fr)); gap:14px; } .card { background:#fff; border:1px solid var(--line); border-radius:10px; padding:16px; } .card .label { color:var(--muted); font-size:12px; text-transform:uppercase; letter-spacing:.06em; } .card .value { margin-top:5px; font-size:28px; font-weight:700; } .card.compliance { background:#eff7f5; border-color:#c8e5dc; } .card.pass .value { color:var(--green); } .card.fail .value { color:var(--red); } .card.warning .value { color:var(--amber); }
.table-wrap { overflow-x:auto; } table { width:100%; border-collapse:collapse; min-width:720px; } th { background:#f7f9fc; color:#4c5b70; font-size:11px; letter-spacing:.05em; text-align:left; text-transform:uppercase; } th,td { padding:11px 12px; border-bottom:1px solid var(--line); vertical-align:top; } tr:last-child td { border-bottom:0; } tr:hover td { background:#fbfcfe; }
.status { display:inline-block; padding:3px 8px; border-radius:999px; font-size:11px; font-weight:700; white-space:nowrap; } .status-pass { background:#dff3ec; color:#0d684f; } .status-fail { background:#fbe4e4; color:#a52e2e; } .status-warning { background:#fff0d5; color:#875400; } .status-not-applicable { background:#e9edf2; color:#536171; }
.empty { color:var(--muted); font-style:italic; text-align:center; padding:24px; } .footer { color:var(--muted); font-size:12px; padding:0 0 28px; } @media (max-width:900px) { .cards { grid-template-columns:repeat(2,1fr); } .hero { padding:32px 24px; } .container { padding:20px; } }
</style>
</head>
<body>
<header class="hero"><h1>Windows CIS Configuration Assessment</h1><p>$(ConvertTo-HtmlEncoded $benchmarkName) | version(s) $(ConvertTo-HtmlEncoded $benchmarkVersion) | $($summary.Total) automated controls</p></header>
<main class="container">
<section class="section"><h2>Executive Summary</h2><div class="section-body"><div class="cards">
<div class="card compliance"><div class="label">Compliance</div><div class="value">$($summary.CompliancePercent.ToString('N2'))%</div></div>
<div class="card pass"><div class="label">Pass</div><div class="value">$($summary.Pass)</div></div>
<div class="card fail"><div class="label">Fail</div><div class="value">$($summary.Fail)</div></div>
<div class="card warning"><div class="label">Warning</div><div class="value">$($summary.Warning)</div></div>
<div class="card"><div class="label">Not Applicable</div><div class="value">$($summary.NotApplicable)</div></div>
<div class="card"><div class="label">Critical Failures</div><div class="value">$($summary.CriticalFindings.Count)</div></div>
</div></div></section>
<section class="section"><h2>Machine Information and Security Posture</h2><div class="section-body"><div class="table-wrap"><table><tbody>$machineRows</tbody></table></div><p><strong>BitLocker Summary:</strong> $(ConvertTo-HtmlEncoded $bitlocker)</p><p><strong>Defender Summary:</strong> $(ConvertTo-HtmlEncoded $defender)</p><p><strong>Firewall Summary:</strong> $(ConvertTo-HtmlEncoded $firewall)</p><p><strong>Local Administrators:</strong> $(ConvertTo-HtmlEncoded $admins)</p></div></section>
<section class="section"><h2>Severity Distribution</h2><div class="section-body"><div class="cards"><div class="card"><div class="label">Critical</div><div class="value">$(@($allResults|Where-Object{(Get-ReportValue $_ 'Severity') -eq 'Critical'}).Count)</div></div><div class="card"><div class="label">High</div><div class="value">$(@($allResults|Where-Object{(Get-ReportValue $_ 'Severity') -eq 'High'}).Count)</div></div><div class="card"><div class="label">Medium</div><div class="value">$(@($allResults|Where-Object{(Get-ReportValue $_ 'Severity') -eq 'Medium'}).Count)</div></div><div class="card"><div class="label">Low</div><div class="value">$(@($allResults|Where-Object{(Get-ReportValue $_ 'Severity') -eq 'Low'}).Count)</div></div><div class="card"><div class="label">Informational</div><div class="value">$(@($allResults|Where-Object{(Get-ReportValue $_ 'Severity') -eq 'Informational'}).Count)</div></div></div></div></section>
<section class="section"><h2>Critical Findings</h2><div class="table-wrap"><table><thead><tr><th>Control ID</th><th>Category</th><th>Title</th><th>Actual</th><th>Remediation</th></tr></thead><tbody>$criticalRows</tbody></table></div></section>
<section class="section"><h2>Failed Controls</h2><div class="table-wrap"><table><thead><tr><th>Control ID</th><th>Category</th><th>Title</th><th>Severity</th><th>Actual</th></tr></thead><tbody>$failedRows</tbody></table></div></section>
<section class="section"><h2>Category Breakdown</h2><div class="table-wrap"><table><thead><tr><th>Category</th><th>Total</th><th>Pass</th><th>Fail</th><th>Warning</th><th>Not Applicable</th><th>Compliance</th></tr></thead><tbody>$($categoryRows -join [Environment]::NewLine)</tbody></table></div></section>
<section class="section"><h2>All Findings</h2><div class="table-wrap"><table><thead><tr><th>Control ID</th><th>Category</th><th>Subcategory</th><th>Title</th><th>Status</th><th>Severity</th><th>Expected</th><th>Actual</th><th>Evidence</th><th>Remediation</th><th>Reference</th></tr></thead><tbody>$findingRows</tbody></table></div></section>
<section class="section"><h2>Remediation Table</h2><div class="table-wrap"><table><thead><tr><th>Control ID</th><th>Category</th><th>Title</th><th>Status</th><th>Severity</th><th>Remediation</th></tr></thead><tbody>$remediationRows</tbody></table></div></section>
</main>
<footer class="container footer">Compliance is calculated as PASS / (PASS + FAIL). WARNING and NOT APPLICABLE findings are displayed separately.</footer>
</body></html>
"@
    Set-Content -LiteralPath $reportPath -Value $html -Encoding UTF8
    return Get-Item -LiteralPath $reportPath
}

function Generate-CSVReport {
    <#
    .SYNOPSIS
        Creates a CSV export of all audit result objects.
    #>
    [CmdletBinding()]
    param (
        [Parameter()] [object[]]$Results,
        [Parameter()] [string]$OutputDirectory,
        [Parameter()] [string]$Path
    )

    $reportPath = Resolve-ReportOutputPath -OutputDirectory $OutputDirectory -Extension 'csv' -Path $Path
    $rows = @(Get-ReportRows -Results $Results)
    if ($rows.Count -eq 0) {
        Set-Content -LiteralPath $reportPath -Value ($script:ResultProperties -join ',') -Encoding UTF8
    }
    else {
        $rows | Export-Csv -LiteralPath $reportPath -NoTypeInformation -Encoding UTF8
    }
    return Get-Item -LiteralPath $reportPath
}

function Generate-JSONReport {
    <#
    .SYNOPSIS
        Creates a JSON audit report containing summary metadata and results.
    #>
    [CmdletBinding()]
    param (
        [Parameter()] [object[]]$Results,
        [Parameter()] [string]$OutputDirectory,
        [Parameter()] [string]$Path
    )

    $reportPath = Resolve-ReportOutputPath -OutputDirectory $OutputDirectory -Extension 'json' -Path $Path
    $summary = Get-AuditReportSummary -Results $Results
    $benchmarks = @(Get-ReportBenchmarks -Results $Results)
    $benchmark = if ($benchmarks.Count -gt 0) { $benchmarks[0] } else { $null }
    $report = [ordered]@{
        GeneratedAt = $summary.GeneratedAt
        Benchmark   = $benchmark
        Benchmarks  = $benchmarks
        Summary     = [ordered]@{
            Total             = $summary.Total
            Pass              = $summary.Pass
            Fail              = $summary.Fail
            Warning           = $summary.Warning
            NotApplicable     = $summary.NotApplicable
            CompliancePercent = $summary.CompliancePercent
        }
        CategoryBreakdown = $summary.CategoryBreakdown
        CriticalFindings  = $summary.CriticalFindings
        Results           = @(Get-ReportRows -Results $Results)
    }
    Set-Content -LiteralPath $reportPath -Value ($report | ConvertTo-Json -Depth 10) -Encoding UTF8
    return Get-Item -LiteralPath $reportPath
}

function ConvertTo-ExcelColumnName {
    [CmdletBinding()]
    param ([Parameter(Mandatory = $true)] [int]$Number)

    $columnName = ''
    while ($Number -gt 0) {
        $remainder = ($Number - 1) % 26
        $columnName = ([char](65 + $remainder)).ToString() + $columnName
        $Number = [Math]::Floor(($Number - 1) / 26)
    }
    return $columnName
}

function New-ExcelCell {
    [CmdletBinding()]
    param (
        [Parameter()] [AllowNull()] [object]$Value,
        [Parameter()] [int]$Style = 0,
        [Parameter()] [switch]$Numeric
    )

    return [pscustomobject]@{ Value = $Value; Style = $Style; Numeric = [bool]$Numeric }
}

function ConvertTo-ExcelCellXml {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)] [int]$Row,
        [Parameter(Mandatory = $true)] [int]$Column,
        [Parameter(Mandatory = $true)] [psobject]$Cell
    )

    $reference = '{0}{1}' -f (ConvertTo-ExcelColumnName -Number $Column), $Row
    $styleAttribute = if ($Cell.Style -gt 0) { ' s="{0}"' -f $Cell.Style } else { '' }
    if ($Cell.Numeric) {
        $numericValue = [Convert]::ToString($Cell.Value, [Globalization.CultureInfo]::InvariantCulture)
        return '<c r="{0}"{1}><v>{2}</v></c>' -f $reference, $styleAttribute, $numericValue
    }

    $encodedValue = [Security.SecurityElement]::Escape([string]$Cell.Value)
    return '<c r="{0}"{1} t="inlineStr"><is><t xml:space="preserve">{2}</t></is></c>' -f $reference, $styleAttribute, $encodedValue
}

function New-ExcelWorksheetXml {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)] [object[]]$Rows,
        [Parameter()] [int]$FreezeRows = 1,
        [Parameter()] [int]$AutoFilterRow = 0
    )

    $builder = New-Object System.Text.StringBuilder
    $maximumColumns = 1
    foreach ($rowValue in $Rows) {
        $maximumColumns = [Math]::Max($maximumColumns, @($rowValue).Count)
    }
    $lastColumn = ConvertTo-ExcelColumnName -Number $maximumColumns
    $lastRow = [Math]::Max(1, $Rows.Count)
    $widths = @(14, 42, 14, 30, 28, 30, 30, 60, 34, 34, 18, 14, 65, 75, 42, 24, 18, 22)
    [void]$builder.Append('<?xml version="1.0" encoding="UTF-8" standalone="yes"?><worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">')
    [void]$builder.AppendFormat('<dimension ref="A1:{0}{1}"/>', $lastColumn, $lastRow)
    [void]$builder.AppendFormat('<sheetViews><sheetView workbookViewId="0"><pane ySplit="{0}" topLeftCell="A{1}" activePane="bottomLeft" state="frozen"/></sheetView></sheetViews>', $FreezeRows, ($FreezeRows + 1))
    [void]$builder.Append('<cols>')
    for ($columnIndex = 1; $columnIndex -le $maximumColumns; $columnIndex++) {
        $width = if ($columnIndex -le $widths.Count) { $widths[$columnIndex - 1] } else { 22 }
        [void]$builder.AppendFormat('<col min="{0}" max="{0}" width="{1}" customWidth="1"/>', $columnIndex, $width)
    }
    [void]$builder.Append('</cols><sheetData>')
    for ($rowIndex = 0; $rowIndex -lt $Rows.Count; $rowIndex++) {
        $rowNumber = $rowIndex + 1
        [void]$builder.AppendFormat('<row r="{0}">', $rowNumber)
        $row = @($Rows[$rowIndex])
        for ($columnIndex = 0; $columnIndex -lt $row.Count; $columnIndex++) {
            $cell = $row[$columnIndex]
            if ($null -ne $cell) {
                [void]$builder.Append((ConvertTo-ExcelCellXml -Row $rowNumber -Column ($columnIndex + 1) -Cell $cell))
            }
        }
        [void]$builder.Append('</row>')
    }
    [void]$builder.Append('</sheetData>')
    if ($AutoFilterRow -gt 0 -and $lastRow -ge $AutoFilterRow) {
        [void]$builder.AppendFormat('<autoFilter ref="A{0}:{1}{2}"/>', $AutoFilterRow, $lastColumn, $lastRow)
    }
    [void]$builder.Append('</worksheet>')
    return $builder.ToString()
}

function Add-OpenXmlZipEntry {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)] [System.IO.Compression.ZipArchive]$Archive,
        [Parameter(Mandatory = $true)] [string]$Name,
        [Parameter(Mandatory = $true)] [string]$Content
    )

    $entry = $Archive.CreateEntry($Name)
    $writer = New-Object System.IO.StreamWriter($entry.Open(), (New-Object System.Text.UTF8Encoding($false)))
    try {
        $writer.Write($Content)
    }
    finally {
        $writer.Dispose()
    }
}

function Generate-ExcelReport {
    <#
    .SYNOPSIS
        Creates a native Excel .xlsx audit report without requiring Excel.

    .DESCRIPTION
        Writes a standards-based Open XML workbook with Summary and Findings
        worksheets. The Summary worksheet includes compliance, status totals,
        category breakdown, and critical findings.
    #>
    [CmdletBinding()]
    param (
        [Parameter()] [object[]]$Results,
        [Parameter()] [string]$OutputDirectory,
        [Parameter()] [string]$Path
    )

    $reportPath = Resolve-ReportOutputPath -OutputDirectory $OutputDirectory -Extension 'xlsx' -Path $Path
    $summary = Get-AuditReportSummary -Results $Results
    $findings = @(Get-ReportRows -Results $Results)

    $summaryRows = @()
    $summaryRows += ,@((New-ExcelCell -Value 'Windows CIS Configuration Assessment' -Style 1))
    $summaryRows += ,@((New-ExcelCell -Value ('Generated: {0}' -f $summary.GeneratedAt.ToString('yyyy-MM-dd HH:mm:ss K'))))
    if ($findings.Count -gt 0) {
        $summaryRows += ,@((New-ExcelCell -Value 'Selected Benchmarks' -Style 1))
        $summaryRows += ,@('CIS Benchmark', 'Version', 'Definition' | ForEach-Object { New-ExcelCell -Value $_ -Style 2 })
        foreach ($benchmark in @(Get-ReportBenchmarks -Results $findings)) {
            $summaryRows += ,@(
                (New-ExcelCell -Value $benchmark.Name),
                (New-ExcelCell -Value $benchmark.Version),
                (New-ExcelCell -Value $benchmark.Definition)
            )
        }
    }
    $summaryRows += ,@()
    $summaryRows += ,@((New-ExcelCell -Value 'Summary Dashboard' -Style 1))
    $summaryRows += ,@((New-ExcelCell -Value 'Metric' -Style 2), (New-ExcelCell -Value 'Value' -Style 2))
    $summaryRows += ,@((New-ExcelCell -Value 'Compliance %'), (New-ExcelCell -Value ($summary.CompliancePercent / 100) -Style 3 -Numeric))
    $summaryRows += ,@((New-ExcelCell -Value 'PASS'), (New-ExcelCell -Value $summary.Pass -Numeric))
    $summaryRows += ,@((New-ExcelCell -Value 'FAIL'), (New-ExcelCell -Value $summary.Fail -Numeric))
    $summaryRows += ,@((New-ExcelCell -Value 'WARNING'), (New-ExcelCell -Value $summary.Warning -Numeric))
    $summaryRows += ,@((New-ExcelCell -Value 'NOT APPLICABLE'), (New-ExcelCell -Value $summary.NotApplicable -Numeric))
    $summaryRows += ,@()
    $summaryRows += ,@((New-ExcelCell -Value 'Category Breakdown' -Style 1))
    $summaryRows += ,@('Category', 'Total', 'Pass', 'Fail', 'Warning', 'Not Applicable', 'Compliance %' | ForEach-Object { New-ExcelCell -Value $_ -Style 2 })
    foreach ($category in $summary.CategoryBreakdown) {
        $summaryRows += ,@(
            (New-ExcelCell -Value $category.Category), (New-ExcelCell -Value $category.Total -Numeric), (New-ExcelCell -Value $category.Pass -Numeric),
            (New-ExcelCell -Value $category.Fail -Numeric), (New-ExcelCell -Value $category.Warning -Numeric), (New-ExcelCell -Value $category.NotApplicable -Numeric),
            (New-ExcelCell -Value ($category.CompliancePercent / 100) -Style 3 -Numeric)
        )
    }
    $summaryRows += ,@()
    $summaryRows += ,@((New-ExcelCell -Value 'Critical Findings' -Style 1))
    $summaryRows += ,@('ControlID', 'Category', 'Title', 'Actual', 'Remediation' | ForEach-Object { New-ExcelCell -Value $_ -Style 2 })
    foreach ($finding in $summary.CriticalFindings) {
        $summaryRows += ,@('ControlID', 'Category', 'Title', 'Actual', 'Remediation' | ForEach-Object { New-ExcelCell -Value (Get-ReportValue -Result $finding -Name $_) })
    }

    $findingsRows = @()
    $findingsRows += ,@((New-ExcelCell -Value 'All Audit Findings' -Style 1))
    $findingsRows += ,@()
    $findingsRows += ,@($script:ResultProperties | ForEach-Object { New-ExcelCell -Value $_ -Style 2 })
    foreach ($finding in $findings) {
        $findingsRows += ,@($script:ResultProperties | ForEach-Object { New-ExcelCell -Value (Get-ReportValue -Result $finding -Name $_) })
    }

    Add-Type -AssemblyName System.IO.Compression -ErrorAction Stop
    Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction Stop
    $fileStream = New-Object System.IO.FileStream($reportPath, [System.IO.FileMode]::Create, [System.IO.FileAccess]::Write)
    $archive = New-Object System.IO.Compression.ZipArchive($fileStream, [System.IO.Compression.ZipArchiveMode]::Create, $false)
    try {
        Add-OpenXmlZipEntry -Archive $archive -Name '[Content_Types].xml' -Content '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/><Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/><Override PartName="/xl/worksheets/sheet2.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/><Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/></Types>'
        Add-OpenXmlZipEntry -Archive $archive -Name '_rels/.rels' -Content '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/></Relationships>'
        Add-OpenXmlZipEntry -Archive $archive -Name 'xl/workbook.xml' -Content '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets><sheet name="Summary" sheetId="1" r:id="rId1"/><sheet name="Findings" sheetId="2" r:id="rId2"/></sheets></workbook>'
        Add-OpenXmlZipEntry -Archive $archive -Name 'xl/_rels/workbook.xml.rels' -Content '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/><Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet2.xml"/><Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/></Relationships>'
        Add-OpenXmlZipEntry -Archive $archive -Name 'xl/styles.xml' -Content '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><fonts count="3"><font><sz val="11"/><name val="Calibri"/></font><font><b/><color rgb="FFFFFFFF"/><sz val="11"/><name val="Calibri"/></font><font><b/><color rgb="FFFFFFFF"/><sz val="16"/><name val="Calibri"/></font></fonts><fills count="3"><fill><patternFill patternType="none"/></fill><fill><patternFill patternType="gray125"/></fill><fill><patternFill patternType="solid"><fgColor rgb="FF2364AA"/><bgColor indexed="64"/></patternFill></fill></fills><borders count="1"><border><left/><right/><top/><bottom/><diagonal/></border></borders><cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs><cellXfs count="4"><xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/><xf numFmtId="0" fontId="2" fillId="2" borderId="0" xfId="0"/><xf numFmtId="0" fontId="1" fillId="2" borderId="0" xfId="0"/><xf numFmtId="10" fontId="0" fillId="0" borderId="0" xfId="0" applyNumberFormat="1"/></cellXfs></styleSheet>'
        Add-OpenXmlZipEntry -Archive $archive -Name 'xl/worksheets/sheet1.xml' -Content (New-ExcelWorksheetXml -Rows $summaryRows -FreezeRows 1)
        Add-OpenXmlZipEntry -Archive $archive -Name 'xl/worksheets/sheet2.xml' -Content (New-ExcelWorksheetXml -Rows $findingsRows -FreezeRows 3 -AutoFilterRow 3)
    }
    finally {
        $archive.Dispose()
        $fileStream.Dispose()
    }

    return Get-Item -LiteralPath $reportPath
}

Export-ModuleMember -Function Generate-HTMLReport, Generate-CSVReport, Generate-JSONReport, Generate-ExcelReport
