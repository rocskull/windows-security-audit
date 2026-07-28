<#
.SYNOPSIS
    Runs the Windows Security Configuration Review Framework.

.DESCRIPTION
    Discovers every PowerShell module file (*.psm1) in the configured Modules
    directory, imports each module, invokes its Invoke-Audit entry point, and
    collects its custom-object results. The framework is audit-only; it does
    not implement or modify any Windows configuration checks.

    Module contract:
    Audit modules must expose an Invoke-Audit function. Invoke-Audit must return
    one or more [pscustomobject] values. Shared modules, such as Result.psm1,
    are imported for use by audit modules but are not executed as checks.
    Module-specific audit logic is deliberately outside this framework.

.PARAMETER ConfigurationFile
    Path to the framework JSON configuration file.

.PARAMETER ListModules
    Lists discovered module files without importing or executing them.

.EXAMPLE
    .\Invoke-CISAudit.ps1

.EXAMPLE
    .\Invoke-CISAudit.ps1 -ListModules

.NOTES
    Compatible with Windows PowerShell 5.1 and PowerShell 7.
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
    [switch]$ListModules
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:AuditContext = $null
$global:CISAuditOutputDirectory = $null

function Get-AuditOutputDirectory {
    <#
    .SYNOPSIS
        Prompts for, validates, and creates the timestamped output folder.
    #>
    [CmdletBinding()]
    param ([string]$RequestedDirectory)

    $defaultDirectory = 'C:\Reports'
    while ($true) {
        $candidate = $RequestedDirectory
        if ([string]::IsNullOrWhiteSpace($candidate)) {
            $candidate = Read-Host 'Enter output directory (Press Enter for default C:\Reports)'
        }
        if ([string]::IsNullOrWhiteSpace($candidate)) { $candidate = $defaultDirectory }

        try {
            $baseDirectory = [System.IO.Path]::GetFullPath($candidate.Trim())
            if (Test-Path -LiteralPath $baseDirectory -PathType Leaf) {
                throw "The path exists but is a file: $baseDirectory"
            }
            if (-not (Test-Path -LiteralPath $baseDirectory -PathType Container)) {
                New-Item -ItemType Directory -Path $baseDirectory -Force -ErrorAction Stop | Out-Null
            }

            $timestampFolder = Get-Date -Format 'yyyy-MM-dd_HHmmss'
            $runDirectory = Join-Path -Path $baseDirectory -ChildPath $timestampFolder
            $suffix = 1
            while (Test-Path -LiteralPath $runDirectory) {
                $runDirectory = Join-Path -Path $baseDirectory -ChildPath ('{0}_{1}' -f $timestampFolder, $suffix)
                $suffix++
            }
            New-Item -ItemType Directory -Path $runDirectory -ErrorAction Stop | Out-Null
            $global:CISAuditOutputDirectory = $runDirectory
            return $runDirectory
        }
        catch {
            Write-Host ('Unable to create output folder: {0}' -f $_.Exception.Message) -ForegroundColor Red
            $RequestedDirectory = $null
        }
    }
}

function Write-Log {
    <#
    .SYNOPSIS
        Writes a timestamped entry to the audit log and console.

    .PARAMETER Message
        Text to include in the log entry.

    .PARAMETER Level
        Severity level for the log entry.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Message,

        [Parameter()]
        [ValidateSet('DEBUG', 'INFO', 'WARNING', 'ERROR')]
        [string]$Level = 'INFO'
    )

    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff'
    $entry = '[{0}] [{1}] {2}' -f $timestamp, $Level, $Message

    if ($script:AuditContext -and $script:AuditContext.LogFile) {
        try {
            Add-Content -LiteralPath $script:AuditContext.LogFile -Value $entry -Encoding UTF8 -ErrorAction Stop
        }
        catch {
            Write-Warning ('Unable to write to audit log: {0}' -f $_.Exception.Message)
        }
    }

    Write-Host $entry
}

function Write-DebugLog {
    <#
    .SYNOPSIS
        Writes a debug entry to the audit log and PowerShell debug stream.

    .PARAMETER Message
        Text to include in the debug entry.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Message
    )

    Write-Log -Message $Message -Level 'DEBUG'
    Write-Debug -Message $Message
}

function Start-Audit {
    <#
    .SYNOPSIS
        Initializes audit context and logging.

    .PARAMETER LogDirectory
        Directory where the framework should create its log file.

    .OUTPUTS
        System.Collections.Specialized.OrderedDictionary
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$LogDirectory
    )

    if (-not (Test-Path -LiteralPath $LogDirectory -PathType Container)) {
        New-Item -ItemType Directory -Path $LogDirectory -Force | Out-Null
    }

    $startTime = Get-Date
    $logName = 'CISAudit_{0}.log' -f $startTime.ToString('yyyyMMdd_HHmmss')
    $script:AuditContext = [ordered]@{
        StartTime = $startTime
        LogFile   = Join-Path -Path $LogDirectory -ChildPath $logName
        OutputDirectory = $LogDirectory
    }

    Write-Log -Message ('Audit started. PowerShell version: {0}' -f $PSVersionTable.PSVersion)
    return $script:AuditContext
}

function Finish-Audit {
    <#
    .SYNOPSIS
        Records audit completion details and clears the console progress bar.

    .PARAMETER ResultCount
        Number of valid audit result objects collected.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [int]$ResultCount
    )

    $endTime = Get-Date
    $elapsed = $endTime - $script:AuditContext.StartTime
    Write-Progress -Id 1 -Activity 'Executing audit modules' -Completed
    Write-Log -Message ('Audit finished. End time: {0}; elapsed: {1}; results: {2}' -f $endTime.ToString('o'), $elapsed, $ResultCount)
}

function Invoke-ReportGenerator {
    <#
    .SYNOPSIS
        Generates configured audit reports.

    .DESCRIPTION
        Imports the ReportGenerator module and generates the requested HTML,
        CSV, JSON, and Excel reports from the supplied audit results.

    .PARAMETER Results
        Audit result objects collected by the framework.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [System.Collections.IEnumerable]$Results,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$OutputDirectory,

        [Parameter(Mandatory = $true)]
        [string[]]$ReportFormats
    )

    $reportModulePath = Join-Path -Path $PSScriptRoot -ChildPath 'Modules\ReportGenerator.psm1'
    if (-not (Test-Path -LiteralPath $reportModulePath -PathType Leaf)) {
        throw "ReportGenerator module does not exist: $reportModulePath"
    }

    Import-Module -Name $reportModulePath -Force -DisableNameChecking -ErrorAction Stop
    $reportResults = @($Results | ForEach-Object { $_ })

    foreach ($reportFormat in $ReportFormats) {
        $normalizedFormat = $reportFormat.Trim().ToUpperInvariant()
        switch ($normalizedFormat) {
            'HTML'  { $report = Generate-HTMLReport -Results $reportResults -OutputDirectory $OutputDirectory }
            'CSV'   { $report = Generate-CSVReport -Results $reportResults -OutputDirectory $OutputDirectory }
            'JSON'  { $report = Generate-JSONReport -Results $reportResults -OutputDirectory $OutputDirectory }
            'EXCEL' { $report = Generate-ExcelReport -Results $reportResults -OutputDirectory $OutputDirectory }
            default  { throw "Unsupported report format in Configuration.json: $reportFormat" }
        }
        Write-Log -Message ('Report generated: {0}' -f $report.FullName)
    }
}

function Get-AuditModules {
    <#
    .SYNOPSIS
        Finds audit modules in the configured modules directory.

    .PARAMETER ModulesDirectory
        Directory containing module files.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$ModulesDirectory
    )

    if (-not (Test-Path -LiteralPath $ModulesDirectory -PathType Container)) {
        throw "Modules directory does not exist: $ModulesDirectory"
    }

    $supportModules = @('Result.psm1', 'ReportGenerator.psm1', 'Common.psm1', 'SecurityAuditUtilities.psm1')
    @(Get-ChildItem -LiteralPath $ModulesDirectory -Filter '*.psm1' -File -Recurse |
        Where-Object { $_.Name -notin $supportModules } |
        Sort-Object -Property FullName)
}

try {
    if (-not [System.IO.Path]::IsPathRooted($ConfigurationFile)) {
        $ConfigurationFile = Join-Path -Path $PSScriptRoot -ChildPath $ConfigurationFile
    }

    if (-not (Test-Path -LiteralPath $ConfigurationFile -PathType Leaf)) {
        throw "Configuration file does not exist: $ConfigurationFile"
    }

    $configuration = Get-Content -LiteralPath $ConfigurationFile -Raw | ConvertFrom-Json
    if ([string]::IsNullOrWhiteSpace($configuration.ModulesFolder) -or [string]::IsNullOrWhiteSpace($configuration.LogFolder)) {
        throw 'Configuration.json must define ModulesFolder and LogFolder.'
    }

    $modulesDirectory = Join-Path -Path $PSScriptRoot -ChildPath $configuration.ModulesFolder
    $auditModules = @(Get-AuditModules -ModulesDirectory $modulesDirectory)

    if ($ListModules) {
        $auditModules | Select-Object -Property Name, FullName
        return
    }

    $runOutputDirectory = Get-AuditOutputDirectory -RequestedDirectory $OutputPath
    Start-Audit -LogDirectory $runOutputDirectory | Out-Null
    Write-Host ('Output Folder:' + [Environment]::NewLine + $runOutputDirectory)
    Write-Log -Message ('Output folder: {0}' -f $runOutputDirectory)
    Write-Log -Message ('Discovered {0} module(s).' -f $auditModules.Count)

    $results = New-Object 'System.Collections.Generic.List[object]'
    $moduleCount = $auditModules.Count
    $moduleIndex = 0

    foreach ($moduleFile in $auditModules) {
        $moduleIndex++
        $percentComplete = [Math]::Floor(($moduleIndex / [Math]::Max($moduleCount, 1)) * 100)
        Write-Progress -Id 1 -Activity 'Executing audit modules' -Status ('{0} ({1} of {2})' -f $moduleFile.Name, $moduleIndex, $moduleCount) -PercentComplete $percentComplete

        $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
        try {
            Write-Log -Message ('Importing module: {0}' -f $moduleFile.Name)
            $importedModule = Import-Module -Name $moduleFile.FullName -PassThru -Force -DisableNameChecking

            $auditCommand = & $importedModule {
                $ErrorActionPreference = 'Stop'
                Get-Command -Name 'Invoke-Audit' -CommandType Function -ErrorAction SilentlyContinue
            }

            if (-not $auditCommand) {
                $stopwatch.Stop()
                Write-DebugLog -Message ('Support module imported and not executed: {0}; execution time: {1}' -f $moduleFile.Name, $stopwatch.Elapsed)
                continue
            }

            $moduleResults = & $importedModule {
                param($Command)
                $ErrorActionPreference = 'Stop'
                & $Command
            } $auditCommand

            foreach ($moduleResult in @($moduleResults)) {
                if ($null -eq $moduleResult) {
                    continue
                }

                if ($moduleResult -isnot [System.Management.Automation.PSCustomObject]) {
                    throw ('Module returned an invalid result type: {0}. Only [pscustomobject] is allowed.' -f $moduleResult.GetType().FullName)
                }

                $results.Add($moduleResult)
            }

            $stopwatch.Stop()
            Write-Log -Message ('Module completed: {0}; execution time: {1}' -f $moduleFile.Name, $stopwatch.Elapsed)
        }
        catch {
            $stopwatch.Stop()
            Write-Log -Message ('Module error: {0}; execution time: {1}; error: {2}' -f $moduleFile.Name, $stopwatch.Elapsed, $_.Exception.Message) -Level 'ERROR'
        }
    }

    Invoke-ReportGenerator -Results $results -OutputDirectory $global:CISAuditOutputDirectory -ReportFormats @($configuration.ReportFormats)
    Finish-Audit -ResultCount $results.Count
    return $results
}
catch {
    if ($script:AuditContext) {
        Write-Log -Message ('Framework error: {0}' -f $_.Exception.Message) -Level 'ERROR'
    }
    else {
        Write-Error -Message ('Framework initialization failed: {0}' -f $_.Exception.Message)
    }

    throw
}
