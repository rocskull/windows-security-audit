<#
.SYNOPSIS
    Provides JSON-driven registry evaluation functions for the audit framework.

.DESCRIPTION
    Reads registry setting definitions from JSON and evaluates them without
    changing the system. Every finding produced by the public test functions is
    created through New-CISResult.
#>

Set-StrictMode -Version Latest

$resultModulePath = Join-Path -Path $PSScriptRoot -ChildPath 'Result.psm1'
Import-Module -Name $resultModulePath -Force -ErrorAction Stop
Import-Module -Name (Join-Path $PSScriptRoot 'Common.psm1') -Force -ErrorAction Stop
$script:RegistryChecksPath = Join-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -ChildPath 'Benchmarks\RegistryChecks.json'

function ConvertTo-RegistryDisplayValue {
    <#
    .SYNOPSIS
        Converts a registry value to a display-safe string.
    #>
    [CmdletBinding()]
    param (
        [Parameter()]
        [AllowNull()]
        [object]$Value
    )

    if ($null -eq $Value) {
        return '<null>'
    }

    if ($Value -is [string]) {
        return $Value
    }

    if ($Value -is [System.Collections.IEnumerable]) {
        return ($Value | ConvertTo-Json -Compress -Depth 10)
    }

    return [string]$Value
}

function Get-RegistryValue {
    <#
    .SYNOPSIS
        Retrieves a registry value without changing the registry.

    .DESCRIPTION
        Returns a PSCustomObject that identifies whether a registry value exists,
        its current value, and any read error. It does not write to the console.

    .PARAMETER RegistryPath
        Registry provider path, for example HKLM:\Software\Example.

    .PARAMETER ValueName
        Name of the registry value to retrieve.

    .OUTPUTS
        System.Management.Automation.PSCustomObject
    #>
    [CmdletBinding()]
    [OutputType([System.Management.Automation.PSCustomObject])]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$RegistryPath,

        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$ValueName
    )

    try {
        if (-not (Test-Path -LiteralPath $RegistryPath)) {
            return [pscustomobject][ordered]@{
                RegistryPath = $RegistryPath
                ValueName    = $ValueName
                Exists       = $false
                Value        = $null
                Error        = $null
            }
        }

        $properties = Get-ItemProperty -LiteralPath $RegistryPath -ErrorAction Stop
        $property = $properties.PSObject.Properties[$ValueName]

        if ($null -eq $property) {
            return [pscustomobject][ordered]@{
                RegistryPath = $RegistryPath
                ValueName    = $ValueName
                Exists       = $false
                Value        = $null
                Error        = $null
            }
        }

        return [pscustomobject][ordered]@{
            RegistryPath = $RegistryPath
            ValueName    = $ValueName
            Exists       = $true
            Value        = $property.Value
            Error        = $null
        }
    }
    catch {
        return [pscustomobject][ordered]@{
            RegistryPath = $RegistryPath
            ValueName    = $ValueName
            Exists       = $false
            Value        = $null
            Error        = $_.Exception.Message
        }
    }
}

function Resolve-RegistryProviderPath {
    <#
    .SYNOPSIS
        Converts a benchmark registry hive and relative key path to a provider path.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$RegistryHive,

        [Parameter(Mandatory = $true)]
        [string]$RegistryPath
    )

    $hiveKey = $RegistryHive.Trim().TrimEnd(':').ToUpperInvariant()
    $hiveMap = @{
        'HKLM'               = 'HKLM:'
        'HKEY_LOCAL_MACHINE' = 'HKLM:'
        'HKCU'               = 'HKCU:'
        'HKEY_CURRENT_USER'  = 'HKCU:'
        'HKCR'               = 'HKCR:'
        'HKEY_CLASSES_ROOT'  = 'HKCR:'
        'HKU'                = 'HKU:'
        'HKEY_USERS'         = 'HKU:'
        'HKCC'               = 'HKCC:'
        'HKEY_CURRENT_CONFIG'= 'HKCC:'
    }

    if (-not $hiveMap.ContainsKey($hiveKey)) {
        throw "Unsupported RegistryHive '$RegistryHive'. Use a supported Windows registry hive such as HKLM or HKCU."
    }

    $relativePath = $RegistryPath.Trim().TrimStart('\\')
    if ($relativePath -match '^(HKLM|HKCU|HKCR|HKU|HKCC|HKEY_)') {
        throw 'RegistryPath must be relative to RegistryHive; do not include a hive in RegistryPath.'
    }

    return ('{0}\{1}' -f $hiveMap[$hiveKey], $relativePath)
}

function Get-RequiredRegistrySettingProperty {
    <#
    .SYNOPSIS
        Obtains a required property from a JSON registry setting definition.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [psobject]$Setting,

        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    $property = $Setting.PSObject.Properties[$Name]
    if ($null -eq $property -or $null -eq $property.Value -or [string]::IsNullOrWhiteSpace([string]$property.Value)) {
        throw "Registry setting is missing required property '$Name'."
    }

    return $property.Value
}

function New-RegistryFinding {
    <#
    .SYNOPSIS
        Creates a framework-compliant registry finding.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)] [psobject]$Setting,
        [Parameter(Mandatory = $true)] [string]$Expected,
        [Parameter(Mandatory = $true)] [string]$Actual,
        [Parameter(Mandatory = $true)] [ValidateSet('PASS', 'FAIL', 'WARNING', 'NOT APPLICABLE')] [string]$Status,
        [Parameter(Mandatory = $true)] [string]$Evidence
    )

    return New-CISResult `
        -ControlID (Get-RequiredRegistrySettingProperty -Setting $Setting -Name 'ControlID') `
        -Category (Get-RequiredRegistrySettingProperty -Setting $Setting -Name 'Category') `
        -SubCategory (Get-RequiredRegistrySettingProperty -Setting $Setting -Name 'SubCategory') `
        -Title (Get-RequiredRegistrySettingProperty -Setting $Setting -Name 'Title') `
        -Expected $Expected `
        -Actual $Actual `
        -Status $Status `
        -Severity (Get-RequiredRegistrySettingProperty -Setting $Setting -Name 'Severity') `
        -Evidence $Evidence `
        -Remediation (Get-RequiredRegistrySettingProperty -Setting $Setting -Name 'Remediation') `
        -Reference (Get-RequiredRegistrySettingProperty -Setting $Setting -Name 'Reference')
}

function Test-RegistrySetting {
    <#
    .SYNOPSIS
        Evaluates one JSON registry setting definition.

    .DESCRIPTION
        Reads the RegistryHive, RegistryPath, ValueName, Comparison, Expected,
        and required
        result metadata from a setting object. It performs a read-only registry
        evaluation and returns one New-CISResult PSCustomObject.

    .PARAMETER Setting
        A setting object deserialized from the JSON configuration file.

    .OUTPUTS
        System.Management.Automation.PSCustomObject
    #>
    [CmdletBinding()]
    [OutputType([System.Management.Automation.PSCustomObject])]
    param (
        [Parameter(Mandatory = $true)]
        [psobject]$Setting
    )

    $registryHive = Get-RequiredRegistrySettingProperty -Setting $Setting -Name 'RegistryHive'
    $registryPath = Resolve-RegistryProviderPath -RegistryHive $registryHive -RegistryPath (Get-RequiredRegistrySettingProperty -Setting $Setting -Name 'RegistryPath')
    $valueName = Get-RequiredRegistrySettingProperty -Setting $Setting -Name 'ValueName'
    $operator = Get-RequiredRegistrySettingProperty -Setting $Setting -Name 'Comparison'
    $supportedOperators = @('Equals', 'NotEquals', 'GreaterThan', 'LessThan', 'Exists', 'NotExists', 'Boolean')

    if ($supportedOperators -notcontains $operator) {
        throw "Unsupported registry comparison operator '$operator'."
    }

    if ($operator -notin @('Exists', 'NotExists')) {
        $expectedValue = Get-RequiredRegistrySettingProperty -Setting $Setting -Name 'Expected'
    }
    else {
        $expectedValue = $null
    }

    $registryValue = Get-RegistryValue -RegistryPath $registryPath -ValueName $valueName
    $locationEvidence = 'Registry path: {0}; value name: {1}.' -f $registryPath, $valueName

    if (-not [string]::IsNullOrWhiteSpace($registryValue.Error)) {
        return New-RegistryFinding -Setting $Setting -Expected (ConvertTo-RegistryDisplayValue $expectedValue) -Actual '<unavailable>' -Status WARNING -Evidence ('{0} Read error: {1}' -f $locationEvidence, $registryValue.Error)
    }

    $actualDisplay = if ($registryValue.Exists) { ConvertTo-RegistryDisplayValue $registryValue.Value } else { '<not found>' }
    $expectedDisplay = ConvertTo-RegistryDisplayValue $expectedValue
    $status = 'FAIL'

    switch ($operator) {
        'Exists' {
            $expectedDisplay = 'Registry value exists'
            $status = if ($registryValue.Exists) { 'PASS' } else { 'FAIL' }
        }
        'NotExists' {
            $expectedDisplay = 'Registry value does not exist'
            $status = if (-not $registryValue.Exists) { 'PASS' } else { 'FAIL' }
        }
        'Equals' {
            if ($registryValue.Exists -and $actualDisplay -eq $expectedDisplay) { $status = 'PASS' }
        }
        'NotEquals' {
            if ($registryValue.Exists -and $actualDisplay -ne $expectedDisplay) { $status = 'PASS' }
        }
        'GreaterThan' {
            try {
                if ($registryValue.Exists -and ([Convert]::ToDecimal($registryValue.Value, [Globalization.CultureInfo]::InvariantCulture) -gt [Convert]::ToDecimal($expectedValue, [Globalization.CultureInfo]::InvariantCulture))) { $status = 'PASS' }
            }
            catch {
                return New-RegistryFinding -Setting $Setting -Expected $expectedDisplay -Actual $actualDisplay -Status WARNING -Evidence ('{0} Numeric comparison failed: {1}' -f $locationEvidence, $_.Exception.Message)
            }
        }
        'LessThan' {
            try {
                if ($registryValue.Exists -and ([Convert]::ToDecimal($registryValue.Value, [Globalization.CultureInfo]::InvariantCulture) -lt [Convert]::ToDecimal($expectedValue, [Globalization.CultureInfo]::InvariantCulture))) { $status = 'PASS' }
            }
            catch {
                return New-RegistryFinding -Setting $Setting -Expected $expectedDisplay -Actual $actualDisplay -Status WARNING -Evidence ('{0} Numeric comparison failed: {1}' -f $locationEvidence, $_.Exception.Message)
            }
        }
        'Boolean' {
            try {
                $actualBoolean = [Convert]::ToBoolean($registryValue.Value, [Globalization.CultureInfo]::InvariantCulture)
                $expectedBoolean = [Convert]::ToBoolean($expectedValue, [Globalization.CultureInfo]::InvariantCulture)
                $expectedDisplay = $expectedBoolean.ToString()
                if ($registryValue.Exists -and $actualBoolean -eq $expectedBoolean) { $status = 'PASS' }
            }
            catch {
                return New-RegistryFinding -Setting $Setting -Expected $expectedDisplay -Actual $actualDisplay -Status WARNING -Evidence ('{0} Boolean comparison failed: {1}' -f $locationEvidence, $_.Exception.Message)
            }
        }
    }

    return New-RegistryFinding -Setting $Setting -Expected $expectedDisplay -Actual $actualDisplay -Status $status -Evidence ('{0} Observed value: {1}.' -f $locationEvidence, $actualDisplay)
}

function Test-RegistryCollection {
    <#
    .SYNOPSIS
        Evaluates every registry setting in a JSON configuration file.

    .DESCRIPTION
        The JSON document must contain a Checks array, or it can be a root
        array of setting definitions. Each definition is passed to
        Test-RegistrySetting. No registry values are hardcoded in this module.

    .PARAMETER ConfigurationPath
        Path to the JSON file containing registry setting definitions. If omitted,
        the module loads Benchmarks\RegistryChecks.json.

    .OUTPUTS
        System.Management.Automation.PSCustomObject
    #>
    [CmdletBinding()]
    [OutputType([System.Management.Automation.PSCustomObject])]
    param (
        [string]$ConfigurationPath
    )

    if ([string]::IsNullOrWhiteSpace($ConfigurationPath)) {
        $ConfigurationPath = $script:RegistryChecksPath
    }

    if (-not (Test-Path -LiteralPath $ConfigurationPath -PathType Leaf)) {
        throw "Registry settings file does not exist: $ConfigurationPath"
    }

    try {
        $configuration = Get-Content -LiteralPath $ConfigurationPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
    }
    catch {
        throw "Unable to parse registry settings file '$ConfigurationPath': $($_.Exception.Message)"
    }

    if ($configuration -is [System.Array]) {
        $settings = $configuration
    }
    elseif ($null -ne $configuration.PSObject.Properties['Checks']) {
        if ($null -eq $configuration.Checks) {
            $settings = @()
        }
        else {
            $settings = @($configuration.Checks)
        }
    }
    else {
        throw "Registry settings file '$ConfigurationPath' must contain a Checks array."
    }

    foreach ($setting in $settings) {
        Test-RegistrySetting -Setting $setting
    }
}

function Invoke-Audit {
    <#
    .SYNOPSIS
        Runs every registry check in the default RegistryChecks.json file.

    .DESCRIPTION
        This is the Registry module's framework entry point. It delegates to
        Test-RegistryCollection, which loads and evaluates every JSON check.

    .OUTPUTS
        System.Management.Automation.PSCustomObject
    #>
    [CmdletBinding()]
    [OutputType([System.Management.Automation.PSCustomObject])]
    param ()

    Test-RegistryCollection
}

Export-ModuleMember -Function Get-RegistryValue, Test-RegistrySetting, Test-RegistryCollection
