<#
.SYNOPSIS
    Runs a data-driven CIS configuration assessment on supported Windows releases.

.DESCRIPTION
    Detects the local Windows workstation or server release, role, and join mode;
    selects the newest compatible benchmark definition and variant; executes
    every automated control; and exports HTML, Excel, CSV, and JSON reports. The
    framework is read-only and never changes Windows configuration.

.PARAMETER ConfigurationFile
    Path to the framework configuration JSON file.

.PARAMETER OutputPath
    Base directory for the timestamped assessment output folder. When omitted,
    the script prompts interactively and defaults to C:\Reports.

.PARAMETER BenchmarkPath
    Optional explicit benchmark definition. Compatibility with the detected
    operating system is validated before execution.

.PARAMETER BenchmarkVariant
    Auto chooses Enterprise or Standalone on workstations and Standard or
    Standalone on servers. Use STIG to explicitly select a STIG benchmark.

.PARAMETER IncludeDefenderBenchmark
    Adds the installed Microsoft Defender Antivirus supplemental benchmark to
    the operating-system assessment.

.PARAMETER ListBenchmarks
    Lists installed benchmark definitions and exits.

.PARAMETER ListModules
    Lists framework modules and exits. Retained for compatibility with earlier
    releases of this tool.

.PARAMETER PassThru
    Returns every finding to the pipeline after report generation.

.EXAMPLE
    .\Invoke-CISAudit.ps1 -OutputPath C:\Reports

.EXAMPLE
    .\Invoke-CISAudit.ps1 -BenchmarkPath .\Benchmarks\CIS_Windows11_5.1.0.json

.NOTES
    Compatible with Windows PowerShell 5.1 and PowerShell 7 on Windows.
#>
[CmdletBinding()]
param (
    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$ConfigurationFile = 'Configuration.json',

    [Parameter()]
    [Alias('O')]
    [string]$OutputPath,

    [Parameter()]
    [string]$BenchmarkPath,

    [Parameter()]
    [ValidateSet('Auto', 'Enterprise', 'Standalone', 'Standard', 'STIG', 'General')]
    [string]$BenchmarkVariant = 'Auto',

    [Parameter()]
    [switch]$IncludeDefenderBenchmark,

    [Parameter()]
    [switch]$ListBenchmarks,

    [Parameter()]
    [switch]$ListModules,

    [Parameter()]
    [switch]$PassThru
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$script:LogFile = $null

function Write-AuditLog {
    <#
    .SYNOPSIS
        Writes a timestamped framework log entry.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)] [string]$Message,
        [Parameter()] [ValidateSet('INFO', 'WARNING', 'ERROR')] [string]$Level = 'INFO'
    )

    $entry = '[{0}] [{1}] {2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff'), $Level, $Message
    if ($script:LogFile) {
        try {
            Add-Content -LiteralPath $script:LogFile -Value $entry -Encoding UTF8
        }
        catch {
            Write-Warning "Unable to write to the audit log: $($_.Exception.Message)"
        }
    }
    Write-Host $entry
}

function New-AuditOutputDirectory {
    <#
    .SYNOPSIS
        Creates a unique timestamped report directory.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param ([Parameter()] [string]$RequestedDirectory)

    $candidate = $RequestedDirectory
    if ([string]::IsNullOrWhiteSpace($candidate)) {
        $candidate = Read-Host 'Enter output directory (Press Enter for default C:\Reports)'
    }
    if ([string]::IsNullOrWhiteSpace($candidate)) {
        $candidate = 'C:\Reports'
    }

    $baseDirectory = [IO.Path]::GetFullPath($candidate.Trim())
    if (Test-Path -LiteralPath $baseDirectory -PathType Leaf) {
        throw "Output path exists as a file: $baseDirectory"
    }
    if (-not (Test-Path -LiteralPath $baseDirectory -PathType Container)) {
        New-Item -ItemType Directory -Path $baseDirectory -Force -ErrorAction Stop | Out-Null
    }

    $folderName = Get-Date -Format 'yyyy-MM-dd_HHmmss'
    $runDirectory = Join-Path -Path $baseDirectory -ChildPath $folderName
    $suffix = 1
    while (Test-Path -LiteralPath $runDirectory) {
        $runDirectory = Join-Path -Path $baseDirectory -ChildPath ('{0}_{1}' -f $folderName, $suffix)
        $suffix++
    }
    New-Item -ItemType Directory -Path $runDirectory -ErrorAction Stop | Out-Null
    return $runDirectory
}

function Export-CISAuditReports {
    <#
    .SYNOPSIS
        Generates all configured report formats.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)] [object[]]$Results,
        [Parameter(Mandatory = $true)] [string]$OutputDirectory,
        [Parameter(Mandatory = $true)] [string[]]$Formats
    )

    $reportModule = Join-Path -Path $PSScriptRoot -ChildPath 'Modules\ReportGenerator.psm1'
    Import-Module -Name $reportModule -Force -DisableNameChecking -ErrorAction Stop
    foreach ($format in $Formats) {
        $report = switch ($format.Trim().ToUpperInvariant()) {
            'HTML'  { Generate-HTMLReport -Results $Results -OutputDirectory $OutputDirectory; break }
            'EXCEL' { Generate-ExcelReport -Results $Results -OutputDirectory $OutputDirectory; break }
            'CSV'   { Generate-CSVReport -Results $Results -OutputDirectory $OutputDirectory; break }
            'JSON'  { Generate-JSONReport -Results $Results -OutputDirectory $OutputDirectory; break }
            default { throw "Unsupported report format '$format'." }
        }
        Write-AuditLog -Message "Generated $($format.ToUpperInvariant()) report: $($report.FullName)"
    }
}

try {
    if (-not [IO.Path]::IsPathRooted($ConfigurationFile)) {
        $ConfigurationFile = Join-Path -Path $PSScriptRoot -ChildPath $ConfigurationFile
    }
    if (-not (Test-Path -LiteralPath $ConfigurationFile -PathType Leaf)) {
        throw "Configuration file does not exist: $ConfigurationFile"
    }
    $configuration = Get-Content -LiteralPath $ConfigurationFile -Raw | ConvertFrom-Json
    foreach ($required in @('ModulesFolder', 'BenchmarksFolder', 'ReportFormats')) {
        if ($null -eq $configuration.PSObject.Properties[$required]) {
            throw "Configuration file is missing required property '$required'."
        }
    }

    $modulesDirectory = Join-Path -Path $PSScriptRoot -ChildPath ([string]$configuration.ModulesFolder)
    $benchmarksDirectory = Join-Path -Path $PSScriptRoot -ChildPath ([string]$configuration.BenchmarksFolder)
    $platformModule = Join-Path -Path $modulesDirectory -ChildPath 'Platform.psm1'
    $engineModule = Join-Path -Path $modulesDirectory -ChildPath 'BenchmarkEngine.psm1'
    Import-Module -Name $platformModule -Force -DisableNameChecking -ErrorAction Stop

    if ($ListModules) {
        Get-ChildItem -LiteralPath $modulesDirectory -Filter '*.psm1' -File |
            Sort-Object Name | Select-Object Name, FullName
        return
    }
    if ($ListBenchmarks) {
        Get-CISBenchmarkCatalog -BenchmarksDirectory $benchmarksDirectory |
            Select-Object Name, Version, Variant, Product, ProductType, BuildMinimum, BuildMaximum, Archived, Supplemental, AutomatedControlCount, Path
        return
    }

    $outputDirectory = New-AuditOutputDirectory -RequestedDirectory $OutputPath
    $script:LogFile = Join-Path -Path $outputDirectory -ChildPath ('CISAudit_{0}.log' -f (Get-Date -Format 'yyyyMMdd_HHmmss'))
    Write-AuditLog -Message "Assessment output directory: $outputDirectory"

    $platform = Get-WindowsPlatform
    Write-AuditLog -Message ("Detected {0}: {1}, version {2}, build {3}, architecture {4}, join mode {5}, server role {6}." -f $platform.Product, $platform.Caption, $platform.Version, $platform.BuildNumber, $platform.Architecture, $platform.JoinMode, $platform.ServerRole)

    $selection = Select-CISBenchmark -Platform $platform -BenchmarksDirectory $benchmarksDirectory -BenchmarkPath $BenchmarkPath -BenchmarkVariant $BenchmarkVariant
    $selections = @($selection)
    $includeDefender = [bool]$IncludeDefenderBenchmark
    if (-not $includeDefender -and $null -ne $configuration.PSObject.Properties['IncludeDefenderBenchmark']) {
        $includeDefender = [bool]$configuration.IncludeDefenderBenchmark
    }
    if ($includeDefender) {
        $selections += Select-CISSupplementalBenchmark -BenchmarksDirectory $benchmarksDirectory -BenchmarkId 'CIS_Microsoft_Defender_Antivirus'
    }
    Import-Module -Name $engineModule -Force -DisableNameChecking -ErrorAction Stop

    try {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($identity)
        if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
            Write-AuditLog -Level WARNING -Message 'PowerShell is not elevated. Access-denied observations are reported as WARNING; run as Administrator for a complete assessment.'
        }
    }
    catch {
        Write-AuditLog -Level WARNING -Message "Unable to determine elevation state: $($_.Exception.Message)"
    }

    $start = Get-Date
    $results = @()
    foreach ($selectedBenchmark in $selections) {
        $benchmark = Import-CISBenchmark -Path $selectedBenchmark.Path
        Write-AuditLog -Message ("Selected benchmark: {0} v{1}, variant {2} ({3} automated controls) from {4}." -f $benchmark.Benchmark.Name, $benchmark.Benchmark.Version, $benchmark.Benchmark.Variant, $benchmark.Benchmark.AutomatedControlCount, $selectedBenchmark.Path)
        $benchmarkResults = @(Invoke-CISBenchmark -BenchmarkDocument $benchmark -BenchmarkPath $selectedBenchmark.Path -Platform $platform)
        if ($benchmarkResults.Count -ne [int]$benchmark.Benchmark.AutomatedControlCount) {
            throw "Execution returned $($benchmarkResults.Count) results for $($benchmark.Benchmark.AutomatedControlCount) controls in '$($benchmark.Benchmark.Name)'."
        }
        $results += $benchmarkResults
    }

    Export-CISAuditReports -Results $results -OutputDirectory $outputDirectory -Formats @($configuration.ReportFormats)
    $elapsed = (Get-Date) - $start
    $statusText = ($results | Group-Object Status | Sort-Object Name | ForEach-Object { '{0}={1}' -f $_.Name, $_.Count }) -join ', '
    Write-AuditLog -Message "Assessment completed in $elapsed. $statusText"
    Write-Host "Reports and log: $outputDirectory" -ForegroundColor Green
    if ($PassThru) {
        return $results
    }
}
catch {
    if ($script:LogFile) {
        Write-AuditLog -Level ERROR -Message $_.Exception.Message
    }
    Write-Error -Message "CIS assessment failed: $($_.Exception.Message)"
    throw
}
