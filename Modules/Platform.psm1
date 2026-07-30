<#
.SYNOPSIS
    Detects the local Windows platform and selects a compatible CIS benchmark.

.DESCRIPTION
    This module contains read-only platform discovery and benchmark selection
    helpers. Benchmark compatibility is defined inside each benchmark JSON
    document, keeping operating-system selection separate from audit logic.
#>

Set-StrictMode -Version Latest

function Get-WindowsPlatform {
    <#
    .SYNOPSIS
        Returns normalized information about the local Windows installation.

    .DESCRIPTION
        Uses Win32_OperatingSystem and Win32_ComputerSystem to determine the
        caption, version, build, product type, architecture, and domain state.
        Product and server release names are normalized by build number.
        DomainRole is also normalized so benchmark controls can express
        Domain Controller and Member Server applicability as data.

    .OUTPUTS
        System.Management.Automation.PSCustomObject
    #>
    [CmdletBinding()]
    [OutputType([System.Management.Automation.PSCustomObject])]
    param ()

    if ($env:OS -ne 'Windows_NT') {
        throw 'This assessment framework can only run on Microsoft Windows.'
    }

    $operatingSystem = $null
    $computerSystem = $null
    try { $operatingSystem = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop } catch { }
    try { $computerSystem = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop } catch { }

    if ($null -ne $operatingSystem) {
        $caption = [string]$operatingSystem.Caption
        $version = [string]$operatingSystem.Version
        $buildNumber = [int]$operatingSystem.BuildNumber
        $architecture = [string]$operatingSystem.OSArchitecture
        $productType = [int]$operatingSystem.ProductType
    }
    else {
        try {
            $currentVersion = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction Stop
            $caption = [string]$currentVersion.ProductName
            $buildNumber = [int]$currentVersion.CurrentBuildNumber
            $version = if ($currentVersion.CurrentMajorVersionNumber) {
                '{0}.{1}.{2}' -f $currentVersion.CurrentMajorVersionNumber, $currentVersion.CurrentMinorVersionNumber, $buildNumber
            }
            else {
                [string]$currentVersion.CurrentVersion
            }
            $architecture = [string]$env:PROCESSOR_ARCHITECTURE
            $productType = if ($caption -match 'Server') { 3 } else { 1 }
        }
        catch {
            throw "Unable to detect Windows through CIM or the CurrentVersion registry key: $($_.Exception.Message)"
        }
    }
    $isServer = $productType -ne 1
    $product = if ($isServer) {
        switch ($buildNumber) {
            { $_ -ge 26100 } { 'Windows Server 2025'; break }
            { $_ -ge 20348 } { 'Windows Server 2022'; break }
            { $_ -ge 17763 } { 'Windows Server 2019'; break }
            { $_ -ge 14393 } { 'Windows Server 2016'; break }
            9600 { 'Windows Server 2012 R2'; break }
            { $_ -ge 6000 -and $_ -le 6002 } { 'Windows Server 2008'; break }
            3790 { 'Windows Server 2003'; break }
            default { 'Unsupported Windows Server' }
        }
    }
    else {
        switch ($buildNumber) {
            { $_ -ge 22000 } { 'Windows 11'; break }
            { $_ -ge 10240 } { 'Windows 10'; break }
            9600 { 'Windows 8.1'; break }
            9200 { 'Windows 8'; break }
            { $_ -ge 7600 -and $_ -le 7601 } { 'Windows 7'; break }
            2600 { 'Windows XP'; break }
            default { 'Unsupported Windows Workstation' }
        }
    }
    if ($product -eq 'Windows 11' -and $caption -match 'Windows 10') {
        $caption = $caption -replace 'Windows 10', 'Windows 11'
    }

    $domainJoined = if ($null -ne $computerSystem) { [bool]$computerSystem.PartOfDomain } else { $false }
    $entraJoined = $false
    if (-not $isServer) {
        try {
            $dsregcmd = Get-Command -Name 'dsregcmd.exe' -ErrorAction Stop
            $joinStatus = @(& $dsregcmd.Source /status 2>$null) -join [Environment]::NewLine
            $entraJoined = $joinStatus -match '(?im)^\s*AzureAdJoined\s*:\s*YES\s*$'
        }
        catch { }
    }
    $rawDomainRole = if ($null -ne $computerSystem -and $null -ne $computerSystem.DomainRole) {
        [int]$computerSystem.DomainRole
    }
    elseif ($isServer -and $productType -eq 2) {
        4
    }
    elseif ($isServer -and $domainJoined) {
        3
    }
    else {
        0
    }
    $serverRole = if (-not $isServer) {
        'NotServer'
    }
    elseif ($rawDomainRole -in 4, 5) {
        'DomainController'
    }
    elseif ($rawDomainRole -in 2, 3) {
        'MemberServer'
    }
    else {
        'StandaloneServer'
    }
    $joinMode = if ($isServer) {
        if ($serverRole -eq 'StandaloneServer') { 'Standalone' } else { 'Standard' }
    }
    elseif ($domainJoined -or $entraJoined) {
        'Enterprise'
    }
    else {
        'Standalone'
    }

    [pscustomobject][ordered]@{
        Product         = $product
        Caption         = $caption
        Version         = $version
        BuildNumber     = $buildNumber
        Architecture    = $architecture
        ProductType     = if ($isServer) { 'Server' } else { 'Workstation' }
        DomainJoined    = $domainJoined
        EntraJoined     = $entraJoined
        Domain          = if ($null -ne $computerSystem -and $domainJoined) { [string]$computerSystem.Domain } else { 'Workgroup' }
        DomainRole      = $rawDomainRole
        ServerRole      = $serverRole
        JoinMode        = $joinMode
        ComputerName    = if ($null -ne $computerSystem) { [string]$computerSystem.Name } else { [string]$env:COMPUTERNAME }
    }
}

function Test-BenchmarkCompatibility {
    <#
    .SYNOPSIS
        Tests whether benchmark metadata applies to a detected platform.

    .PARAMETER Benchmark
        Benchmark metadata object from a benchmark JSON file.

    .PARAMETER Platform
        Platform object returned by Get-WindowsPlatform.

    .OUTPUTS
        System.Boolean
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param (
        [Parameter(Mandatory = $true)]
        [psobject]$Benchmark,

        [Parameter(Mandatory = $true)]
        [psobject]$Platform,

        [Parameter()]
        [switch]$AllowSupplemental
    )

    if ($null -eq $Benchmark.Platform) {
        return $false
    }
    $isSupplemental = $null -ne $Benchmark.PSObject.Properties['Supplemental'] -and [bool]$Benchmark.Supplemental
    if ($isSupplemental) {
        return [bool]$AllowSupplemental
    }
    if ([string]$Benchmark.Platform.Product -ne [string]$Platform.Product) {
        return $false
    }
    if ($Benchmark.Platform.ProductType -and [string]$Benchmark.Platform.ProductType -ne [string]$Platform.ProductType) {
        return $false
    }
    if ($null -ne $Benchmark.Platform.BuildMinimum -and $Platform.BuildNumber -lt [int]$Benchmark.Platform.BuildMinimum) {
        return $false
    }
    if ($null -ne $Benchmark.Platform.BuildMaximum -and $Platform.BuildNumber -gt [int]$Benchmark.Platform.BuildMaximum) {
        return $false
    }
    return $true
}

function Get-CISBenchmarkCatalog {
    <#
    .SYNOPSIS
        Reads benchmark metadata from all versioned JSON files in a directory.

    .PARAMETER BenchmarksDirectory
        Directory containing CIS_*.json benchmark definition files.

    .OUTPUTS
        System.Management.Automation.PSCustomObject
    #>
    [CmdletBinding()]
    [OutputType([System.Management.Automation.PSCustomObject])]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$BenchmarksDirectory
    )

    if (-not (Test-Path -LiteralPath $BenchmarksDirectory -PathType Container)) {
        throw "Benchmarks directory does not exist: $BenchmarksDirectory"
    }

    $catalogPath = Join-Path -Path $BenchmarksDirectory -ChildPath 'BenchmarkCatalog.json'
    if (Test-Path -LiteralPath $catalogPath -PathType Leaf) {
        try {
            $index = Get-Content -LiteralPath $catalogPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
            $entries = @($index.Benchmarks)
            $definitionFiles = @(Get-ChildItem -LiteralPath $BenchmarksDirectory -Filter 'CIS_*.json' -File)
            $catalogIsCurrent = $entries.Count -eq $definitionFiles.Count
            if ($catalogIsCurrent) {
                foreach ($entry in $entries) {
                    $definitionPath = Join-Path -Path $BenchmarksDirectory -ChildPath ([string]$entry.FileName)
                    if (-not (Test-Path -LiteralPath $definitionPath -PathType Leaf) -or
                        $null -eq $entry.PSObject.Properties['Sha256']) {
                        $catalogIsCurrent = $false
                        break
                    }
                    $actualHash = (Get-FileHash -LiteralPath $definitionPath -Algorithm SHA256 -ErrorAction Stop).Hash
                    if (-not $actualHash.Equals([string]$entry.Sha256, [StringComparison]::OrdinalIgnoreCase)) {
                        $catalogIsCurrent = $false
                        break
                    }
                }
            }
            if (-not $catalogIsCurrent) {
                Write-Warning "Benchmark catalog index '$catalogPath' is stale; discovering metadata from the definition files."
                throw 'StaleBenchmarkCatalog'
            }
            foreach ($entry in $entries) {
                $definitionPath = Join-Path -Path $BenchmarksDirectory -ChildPath ([string]$entry.FileName)
                [pscustomobject][ordered]@{
                    Path                  = $definitionPath
                    Name                  = [string]$entry.Name
                    Version               = [string]$entry.Version
                    Variant               = [string]$entry.Variant
                    Product               = [string]$entry.Platform.Product
                    ProductType           = [string]$entry.Platform.ProductType
                    BuildMinimum          = $entry.Platform.BuildMinimum
                    BuildMaximum          = $entry.Platform.BuildMaximum
                    Archived              = [bool]$entry.Archived
                    Supplemental          = [bool]$entry.Supplemental
                    AutomatedControlCount = [int]$entry.AutomatedControlCount
                    Metadata              = $entry
                }
            }
            return
        }
        catch {
            if ($_.Exception.Message -ne 'StaleBenchmarkCatalog') {
                Write-Warning "Benchmark catalog index '$catalogPath' is invalid; falling back to definition discovery. $($_.Exception.Message)"
            }
        }
    }

    foreach ($file in (Get-ChildItem -LiteralPath $BenchmarksDirectory -Filter 'CIS_*.json' -File | Sort-Object Name)) {
        try {
            $document = Get-Content -LiteralPath $file.FullName -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
            if ($null -eq $document.Benchmark) {
                continue
            }
            [pscustomobject][ordered]@{
                Path                  = $file.FullName
                Name                  = [string]$document.Benchmark.Name
                Version               = [string]$document.Benchmark.Version
                Variant               = [string]$document.Benchmark.Variant
                Product               = [string]$document.Benchmark.Platform.Product
                ProductType           = [string]$document.Benchmark.Platform.ProductType
                BuildMinimum          = $document.Benchmark.Platform.BuildMinimum
                BuildMaximum          = $document.Benchmark.Platform.BuildMaximum
                Archived              = [bool]$document.Benchmark.Archived
                Supplemental          = [bool]$document.Benchmark.Supplemental
                AutomatedControlCount = [int]$document.Benchmark.AutomatedControlCount
                Metadata              = $document.Benchmark
            }
        }
        catch {
            Write-Warning "Skipping invalid benchmark file '$($file.FullName)': $($_.Exception.Message)"
        }
    }
}

function Select-CISBenchmark {
    <#
    .SYNOPSIS
        Selects the newest compatible benchmark definition.

    .DESCRIPTION
        When an explicit benchmark path is provided, compatibility is still
        checked to prevent accidental assessment against the wrong operating
        system. Otherwise, all compatible definitions are ordered by semantic
        version and the newest definition is selected.

    .PARAMETER Platform
        Platform object returned by Get-WindowsPlatform.

    .PARAMETER BenchmarksDirectory
        Directory containing versioned benchmark definitions.

    .PARAMETER BenchmarkPath
        Optional explicit benchmark JSON path.

    .PARAMETER BenchmarkVariant
        Auto chooses Enterprise/Standalone for workstations and
        Standard/Standalone for servers. STIG must be selected explicitly.

    .OUTPUTS
        System.Management.Automation.PSCustomObject
    #>
    [CmdletBinding()]
    [OutputType([System.Management.Automation.PSCustomObject])]
    param (
        [Parameter(Mandatory = $true)]
        [psobject]$Platform,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$BenchmarksDirectory,

        [Parameter()]
        [string]$BenchmarkPath,

        [Parameter()]
        [ValidateSet('Auto', 'Enterprise', 'Standalone', 'Standard', 'STIG', 'General')]
        [string]$BenchmarkVariant = 'Auto'
    )

    if (-not [string]::IsNullOrWhiteSpace($BenchmarkPath)) {
        if (-not [System.IO.Path]::IsPathRooted($BenchmarkPath)) {
            $BenchmarkPath = Join-Path -Path $BenchmarksDirectory -ChildPath $BenchmarkPath
        }
        if (-not (Test-Path -LiteralPath $BenchmarkPath -PathType Leaf)) {
            throw "The requested benchmark file does not exist: $BenchmarkPath"
        }
        $document = Get-Content -LiteralPath $BenchmarkPath -Raw | ConvertFrom-Json
        if (-not (Test-BenchmarkCompatibility -Benchmark $document.Benchmark -Platform $Platform)) {
            throw "Benchmark '$BenchmarkPath' is not compatible with $($Platform.Product) build $($Platform.BuildNumber)."
        }
        if ([bool]$document.Benchmark.Supplemental) {
            throw "Benchmark '$BenchmarkPath' is supplemental and cannot be used as the operating-system benchmark."
        }
        return [pscustomobject]@{ Path = (Resolve-Path -LiteralPath $BenchmarkPath).Path; Document = $document }
    }

    $compatible = @(Get-CISBenchmarkCatalog -BenchmarksDirectory $BenchmarksDirectory | Where-Object {
        -not $_.Supplemental -and (Test-BenchmarkCompatibility -Benchmark $_.Metadata -Platform $Platform)
    })
    $desiredVariant = if ($BenchmarkVariant -ne 'Auto') {
        $BenchmarkVariant
    }
    elseif ([string]$Platform.JoinMode) {
        [string]$Platform.JoinMode
    }
    else {
        'General'
    }
    $variantMatches = @($compatible | Where-Object { $_.Variant -eq $desiredVariant })
    if ($variantMatches.Count -eq 0 -and $BenchmarkVariant -eq 'Auto') {
        $variantMatches = @($compatible | Where-Object { $_.Variant -eq 'General' })
    }
    $compatible = $variantMatches
    if ($compatible.Count -eq 0) {
        throw "No compatible '$desiredVariant' CIS benchmark definition was found for $($Platform.Product) build $($Platform.BuildNumber). Use -ListBenchmarks to review installed variants."
    }

    $selected = $compatible | Sort-Object -Property @{ Expression = {
        try { [version]$_.Version } catch { [version]'0.0.0' }
    }; Descending = $true } | Select-Object -First 1
    $document = Get-Content -LiteralPath $selected.Path -Raw | ConvertFrom-Json
    return [pscustomobject]@{ Path = $selected.Path; Document = $document }
}

function Select-CISSupplementalBenchmark {
    <#
    .SYNOPSIS
        Selects the newest installed version of a supplemental benchmark.

    .PARAMETER BenchmarksDirectory
        Directory containing versioned benchmark definitions.

    .PARAMETER BenchmarkId
        Stable benchmark metadata ID, such as CIS_Microsoft_Defender_Antivirus.
    #>
    [CmdletBinding()]
    [OutputType([System.Management.Automation.PSCustomObject])]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$BenchmarksDirectory,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$BenchmarkId
    )

    $matches = @(Get-CISBenchmarkCatalog -BenchmarksDirectory $BenchmarksDirectory | Where-Object {
        $_.Supplemental -and [string]$_.Metadata.Id -eq $BenchmarkId
    })
    if ($matches.Count -eq 0) {
        throw "Supplemental benchmark '$BenchmarkId' is not installed."
    }
    $selected = $matches | Sort-Object -Property @{ Expression = {
        try { [version]$_.Version } catch { [version]'0.0.0' }
    }; Descending = $true } | Select-Object -First 1
    $document = Get-Content -LiteralPath $selected.Path -Raw | ConvertFrom-Json
    return [pscustomobject]@{ Path = $selected.Path; Document = $document }
}

Export-ModuleMember -Function Get-WindowsPlatform, Get-CISBenchmarkCatalog, Select-CISBenchmark, Select-CISSupplementalBenchmark, Test-BenchmarkCompatibility
