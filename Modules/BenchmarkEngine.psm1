<#
.SYNOPSIS
    Executes data-driven CIS benchmark controls.

.DESCRIPTION
    The benchmark engine loads validated JSON definitions and dispatches each
    automated control to a reusable, read-only check provider. Supported
    providers cover registry values, registry data collections, local security
    policy, user rights, advanced audit policy, installed products, and built-in
    account names. No CIS values or control identifiers are hard-coded in the
    execution logic.
#>

Set-StrictMode -Version Latest
Import-Module (Join-Path -Path $PSScriptRoot -ChildPath 'Result.psm1') -Force -ErrorAction Stop

$script:SecurityPolicyCache = $null
$script:AuditPolicyCache = $null
$script:SupportedCheckTypes = @(
    'Registry', 'RegistryAll', 'RegistryValueData', 'SecurityPolicy',
    'UserRight', 'AuditPolicy', 'BuiltinAccountName', 'InstalledProduct'
)

function Import-CISBenchmark {
    <#
    .SYNOPSIS
        Loads and validates a versioned benchmark JSON document.

    .PARAMETER Path
        Path to a benchmark definition file.

    .OUTPUTS
        System.Management.Automation.PSCustomObject
    #>
    [CmdletBinding()]
    [OutputType([System.Management.Automation.PSCustomObject])]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Path
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Benchmark definition does not exist: $Path"
    }
    try {
        $document = Get-Content -LiteralPath $Path -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
    }
    catch {
        throw "Unable to parse benchmark definition '$Path': $($_.Exception.Message)"
    }

    foreach ($property in @('SchemaVersion', 'Benchmark', 'Controls')) {
        if ($null -eq $document.PSObject.Properties[$property]) {
            throw "Benchmark definition '$Path' is missing required property '$property'."
        }
    }
    foreach ($property in @('Name', 'Version', 'Platform', 'AutomatedControlCount')) {
        if ($null -eq $document.Benchmark.PSObject.Properties[$property]) {
            throw "Benchmark metadata in '$Path' is missing required property '$property'."
        }
    }

    $controls = @($document.Controls)
    $declaredControlCount = [int]$document.Benchmark.PSObject.Properties['AutomatedControlCount'].Value
    if ($controls.Count -ne $declaredControlCount) {
        throw "Benchmark '$Path' declares $($document.Benchmark.AutomatedControlCount) automated controls but contains $($controls.Count)."
    }
    $duplicateIds = @($controls | Group-Object -Property Id | Where-Object { $_.Count -gt 1 })
    if ($duplicateIds.Count -gt 0) {
        throw "Benchmark '$Path' contains duplicate control IDs: $($duplicateIds.Name -join ', ')."
    }

    foreach ($control in $controls) {
        foreach ($property in @('Id', 'Title', 'Category', 'Severity', 'ExpectedValue', 'Check', 'Remediation')) {
            if ($null -eq $control.PSObject.Properties[$property]) {
                throw "Control '$($control.Id)' is missing required property '$property'."
            }
        }
        if (-not $control.Automated) {
            throw "Control '$($control.Id)' is not marked Automated and must not be present in an automated definition."
        }
        if ($script:SupportedCheckTypes -notcontains [string]$control.Check.Type) {
            throw "Control '$($control.Id)' uses unsupported check type '$($control.Check.Type)'."
        }
    }

    return $document
}

function ConvertTo-CISDecimal {
    <#
    .SYNOPSIS
        Converts registry or policy values to decimal for ordered comparisons.
    #>
    [CmdletBinding()]
    [OutputType([decimal])]
    param ([Parameter(Mandatory = $true)] [object]$Value)

    if ($Value -is [string] -and $Value -match '^0x[0-9a-f]+$') {
        return [Convert]::ToInt64($Value.Substring(2), 16)
    }
    return [Convert]::ToDecimal($Value, [Globalization.CultureInfo]::InvariantCulture)
}

function ConvertTo-CISDisplayValue {
    <#
    .SYNOPSIS
        Converts scalar and array values into stable report text.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param ([AllowNull()] [object]$Value)

    if ($null -eq $Value) {
        return '<null>'
    }
    if ($Value -is [System.Array]) {
        return (@($Value) | ForEach-Object { [string]$_ }) -join '; '
    }
    if ($Value -is [bool]) {
        return $Value.ToString()
    }
    return [string]$Value
}

function Test-CISValue {
    <#
    .SYNOPSIS
        Applies a benchmark comparison operator to an observed value.

    .PARAMETER Actual
        Observed value.

    .PARAMETER Operator
        Comparison operator from the benchmark definition.

    .PARAMETER Expected
        Expected scalar or collection.

    .OUTPUTS
        System.Boolean
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param (
        [AllowNull()] [object]$Actual,
        [Parameter(Mandatory = $true)] [string]$Operator,
        [AllowNull()] [object]$Expected
    )

    switch ($Operator) {
        'Equals' {
            return ([string]$Actual).Trim().Equals(([string]$Expected).Trim(), [StringComparison]::OrdinalIgnoreCase)
        }
        'NotEquals' {
            return -not ([string]$Actual).Trim().Equals(([string]$Expected).Trim(), [StringComparison]::OrdinalIgnoreCase)
        }
        'GreaterThanOrEqual' {
            return (ConvertTo-CISDecimal $Actual) -ge (ConvertTo-CISDecimal $Expected)
        }
        'LessThanOrEqual' {
            return (ConvertTo-CISDecimal $Actual) -le (ConvertTo-CISDecimal $Expected)
        }
        'Between' {
            $bounds = @($Expected)
            if ($bounds.Count -ne 2) { throw 'Between requires exactly two expected bounds.' }
            $number = ConvertTo-CISDecimal $Actual
            return $number -ge (ConvertTo-CISDecimal $bounds[0]) -and $number -le (ConvertTo-CISDecimal $bounds[1])
        }
        'In' {
            foreach ($candidate in @($Expected)) {
                if (Test-CISValue -Actual $Actual -Operator Equals -Expected $candidate) { return $true }
            }
            return $false
        }
        'Empty' {
            if ($null -eq $Actual) { return $true }
            if ($Actual -is [System.Array]) { return @($Actual | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) }).Count -eq 0 }
            return [string]::IsNullOrWhiteSpace([string]$Actual)
        }
        'NotEmpty' {
            return -not (Test-CISValue -Actual $Actual -Operator Empty -Expected $null)
        }
        'ContainsAll' {
            $actualText = (ConvertTo-CISDisplayValue $Actual).ToUpperInvariant()
            foreach ($required in @($Expected)) {
                if ($actualText.IndexOf(([string]$required).Trim().ToUpperInvariant(), [StringComparison]::Ordinal) -lt 0) {
                    return $false
                }
            }
            return $true
        }
        'ExactSet' {
            $actualItems = @(@($Actual) | ForEach-Object { ([string]$_).Trim().ToUpperInvariant() } |
                Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Sort-Object -Unique)
            $expectedItems = @(@($Expected) | ForEach-Object { ([string]$_).Trim().ToUpperInvariant() } |
                Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Sort-Object -Unique)
            if ($actualItems.Count -ne $expectedItems.Count) {
                return $false
            }
            return @($expectedItems | Where-Object { $actualItems -notcontains $_ }).Count -eq 0
        }
        'EmptyOrContainsAll' {
            if (Test-CISValue -Actual $Actual -Operator Empty -Expected $null) {
                return $true
            }
            return Test-CISValue -Actual $Actual -Operator ContainsAll -Expected $Expected
        }
        default {
            throw "Unsupported comparison operator '$Operator'."
        }
    }
}

function Get-CISRegistryObservation {
    <#
    .SYNOPSIS
        Reads one registry value while distinguishing missing data from errors.
    #>
    [CmdletBinding()]
    [OutputType([System.Management.Automation.PSCustomObject])]
    param (
        [Parameter(Mandatory = $true)] [string]$Path,
        [Parameter(Mandatory = $true)] [string]$ValueName
    )

    $Path = Resolve-CISRegistryProviderPath -Path $Path
    try {
        if (-not (Test-Path -LiteralPath $Path -PathType Container)) {
            return [pscustomobject]@{ Exists = $false; Value = $null; Error = $null }
        }
        $item = Get-ItemProperty -LiteralPath $Path -ErrorAction Stop
        $property = $item.PSObject.Properties[$ValueName]
        if ($null -eq $property) {
            return [pscustomobject]@{ Exists = $false; Value = $null; Error = $null }
        }
        return [pscustomobject]@{ Exists = $true; Value = $property.Value; Error = $null }
    }
    catch {
        return [pscustomobject]@{ Exists = $false; Value = $null; Error = $_.Exception.Message }
    }
}

function Resolve-CISRegistryProviderPath {
    <#
    .SYNOPSIS
        Converts benchmark hive notation and user placeholders to provider paths.

    .DESCRIPTION
        CIS user-policy audit text represents the current user as
        HKU\[USER SID]. The framework resolves that placeholder to HKCU so the
        finding describes the account that launched the assessment. Hives that
        do not have default PowerShell drives are converted to Registry::
        provider paths.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param ([Parameter(Mandatory = $true)] [string]$Path)

    $resolved = $Path
    $resolved = $resolved -replace '^HKU:\\\[(?:USER\s*SID|USERSID)\]', 'HKCU:'
    $resolved = $resolved -replace '^HKU:\\', 'Registry::HKEY_USERS\'
    $resolved = $resolved -replace '^HKCR:\\', 'Registry::HKEY_CLASSES_ROOT\'
    $resolved = $resolved -replace '^HKCC:\\', 'Registry::HKEY_CURRENT_CONFIG\'
    return $resolved
}

function Test-CISRegistryCondition {
    <#
    .SYNOPSIS
        Evaluates one registry condition from a benchmark definition.
    #>
    [CmdletBinding()]
    [OutputType([System.Management.Automation.PSCustomObject])]
    param ([Parameter(Mandatory = $true)] [psobject]$Condition)

    $resolvedPath = Resolve-CISRegistryProviderPath -Path ([string]$Condition.Path)
    $observation = Get-CISRegistryObservation -Path $resolvedPath -ValueName ([string]$Condition.ValueName)
    $location = '{0}::{1}' -f $resolvedPath, $Condition.ValueName
    if (-not [string]::IsNullOrWhiteSpace([string]$observation.Error)) {
        return [pscustomobject]@{
            Status = 'WARNING'; Actual = '<unavailable>'
            Evidence = "Registry read failed at $location. $($observation.Error)"
        }
    }

    $operator = [string]$Condition.Operator
    if ($operator -eq 'NotExists') {
        $passed = -not $observation.Exists
        return [pscustomobject]@{
            Status = if ($passed) { 'PASS' } else { 'FAIL' }
            Actual = if ($observation.Exists) { ConvertTo-CISDisplayValue $observation.Value } else { '<not present>' }
            Evidence = "Registry value $location exists=$($observation.Exists)."
        }
    }
    if (-not $observation.Exists) {
        return [pscustomobject]@{
            Status = 'FAIL'; Actual = '<not present>'
            Evidence = "Required registry value $location was not found."
        }
    }

    try {
        $passed = Test-CISValue -Actual $observation.Value -Operator $operator -Expected $Condition.Expected
        return [pscustomobject]@{
            Status = if ($passed) { 'PASS' } else { 'FAIL' }
            Actual = ConvertTo-CISDisplayValue $observation.Value
            Evidence = "Registry value $location was $(ConvertTo-CISDisplayValue $observation.Value)."
        }
    }
    catch {
        return [pscustomobject]@{
            Status = 'WARNING'; Actual = ConvertTo-CISDisplayValue $observation.Value
            Evidence = "Registry comparison failed at $location. $($_.Exception.Message)"
        }
    }
}

function Test-CISRegistryValueData {
    <#
    .SYNOPSIS
        Compares all data values below one registry key.

    .DESCRIPTION
        Some CIS list policies use arbitrary numeric registry value names. This
        provider intentionally compares the value data and does not depend on
        those generated names.
    #>
    [CmdletBinding()]
    [OutputType([System.Management.Automation.PSCustomObject])]
    param ([Parameter(Mandatory = $true)] [psobject]$Check)

    $path = Resolve-CISRegistryProviderPath -Path ([string]$Check.Path)
    try {
        if (-not (Test-Path -LiteralPath $path -PathType Container)) {
            return [pscustomobject]@{
                Status = 'FAIL'; Actual = '<not present>'
                Evidence = "Required registry key $path was not found."
            }
        }
        $item = Get-ItemProperty -LiteralPath $path -ErrorAction Stop
        $providerProperties = @('PSPath', 'PSParentPath', 'PSChildName', 'PSDrive', 'PSProvider')
        $values = @($item.PSObject.Properties |
            Where-Object { $providerProperties -notcontains $_.Name } |
            ForEach-Object { $_.Value })
        $passed = Test-CISValue -Actual $values -Operator ([string]$Check.Operator) -Expected $Check.Expected
        return [pscustomobject]@{
            Status = if ($passed) { 'PASS' } else { 'FAIL' }
            Actual = ConvertTo-CISDisplayValue $values
            Evidence = "Registry key $path returned $($values.Count) policy data value(s)."
        }
    }
    catch {
        return [pscustomobject]@{
            Status = 'WARNING'; Actual = '<unavailable>'
            Evidence = "Registry data enumeration failed at $path. $($_.Exception.Message)"
        }
    }
}

function Get-CISSecurityPolicy {
    <#
    .SYNOPSIS
        Exports and caches the local security policy through secedit.exe.
    #>
    [CmdletBinding()]
    [OutputType([System.Management.Automation.PSCustomObject])]
    param ()

    if ($null -ne $script:SecurityPolicyCache) {
        return $script:SecurityPolicyCache
    }
    $secedit = Get-Command -Name 'secedit.exe' -ErrorAction SilentlyContinue
    if ($null -eq $secedit) {
        $script:SecurityPolicyCache = [pscustomobject]@{ Available = $false; Data = @{}; Error = 'secedit.exe is unavailable.' }
        return $script:SecurityPolicyCache
    }

    $temporaryPath = [IO.Path]::ChangeExtension([IO.Path]::GetTempFileName(), '.inf')
    try {
        $output = & $secedit.Source /export /cfg $temporaryPath /quiet 2>&1
        if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $temporaryPath -PathType Leaf)) {
            throw "secedit.exe exited with code $LASTEXITCODE. $($output -join ' ')"
        }
        $data = @{}
        $section = ''
        foreach ($line in (Get-Content -LiteralPath $temporaryPath -ErrorAction Stop)) {
            if ($line -match '^\s*\[(.+)\]\s*$') {
                $section = $Matches[1].Trim()
                continue
            }
            if ($line -match '^\s*([^;][^=]*?)\s*=\s*(.*)$') {
                $data['{0}|{1}' -f $section, $Matches[1].Trim()] = $Matches[2].Trim()
            }
        }
        $script:SecurityPolicyCache = [pscustomobject]@{ Available = $true; Data = $data; Error = $null }
    }
    catch {
        $script:SecurityPolicyCache = [pscustomobject]@{ Available = $false; Data = @{}; Error = $_.Exception.Message }
    }
    finally {
        if (Test-Path -LiteralPath $temporaryPath) {
            Remove-Item -LiteralPath $temporaryPath -Force -ErrorAction SilentlyContinue
        }
    }
    return $script:SecurityPolicyCache
}

function ConvertTo-CISPrincipalToken {
    <#
    .SYNOPSIS
        Normalizes account names and SIDs for user-right comparisons.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param ([Parameter(Mandatory = $true)] [string]$Value)

    $token = $Value.Trim().TrimStart('*')
    $known = @{
        'ADMINISTRATORS' = 'S-1-5-32-544'
        'USERS' = 'S-1-5-32-545'
        'GUESTS' = 'S-1-5-32-546'
        'LOCAL ACCOUNT' = 'S-1-5-113'
        'LOCAL SERVICE' = 'S-1-5-19'
        'NETWORK SERVICE' = 'S-1-5-20'
        'SERVICE' = 'S-1-5-6'
        'WINDOW MANAGER\WINDOW MANAGER GROUP' = 'S-1-5-90-0'
        'AUTHENTICATED USERS' = 'S-1-5-11'
        'ENTERPRISE DOMAIN CONTROLLERS' = 'S-1-5-9'
        'LOCAL ACCOUNT AND MEMBER OF ADMINISTRATORS GROUP' = 'S-1-5-114'
        'NT VIRTUAL MACHINE\VIRTUAL MACHINES' = 'S-1-5-83-0'
    }
    $upper = $token.ToUpperInvariant()
    if ($known.ContainsKey($upper)) {
        return $known[$upper]
    }
    if ($token -match '^S-\d-(?:\d+-)+\d+$') {
        return $token.ToUpperInvariant()
    }
    try {
        return ([Security.Principal.NTAccount]$token).Translate([Security.Principal.SecurityIdentifier]).Value.ToUpperInvariant()
    }
    catch {
        return $upper
    }
}

function Test-CISUserRight {
    <#
    .SYNOPSIS
        Compares one exported user-right assignment with the benchmark set.
    #>
    [CmdletBinding()]
    [OutputType([System.Management.Automation.PSCustomObject])]
    param ([Parameter(Mandatory = $true)] [psobject]$Check)

    $policy = Get-CISSecurityPolicy
    if (-not $policy.Available) {
        return [pscustomobject]@{ Status = 'WARNING'; Actual = '<unavailable>'; Evidence = "Local security policy export failed. $($policy.Error)" }
    }
    $lookupKey = 'Privilege Rights|{0}' -f $Check.Key
    $raw = if ($policy.Data.ContainsKey($lookupKey)) { [string]$policy.Data[$lookupKey] } else { '' }
    $actualTokens = @($raw -split ',' | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | ForEach-Object { ConvertTo-CISPrincipalToken $_ } | Sort-Object -Unique)
    $expectedTokens = @(@($Check.Expected) | ForEach-Object { ConvertTo-CISPrincipalToken ([string]$_) } | Sort-Object -Unique)
    $missing = @($expectedTokens | Where-Object { $actualTokens -notcontains $_ })
    $extra = @($actualTokens | Where-Object { $expectedTokens -notcontains $_ })
    $passed = switch ([string]$Check.Operator) {
        'ContainsAll' { $missing.Count -eq 0; break }
        'SubsetOf' { $extra.Count -eq 0; break }
        default { $missing.Count -eq 0 -and $extra.Count -eq 0 }
    }
    [pscustomobject]@{
        Status = if ($passed) { 'PASS' } else { 'FAIL' }
        Actual = if ($actualTokens.Count -eq 0) { 'No One' } else { $actualTokens -join '; ' }
        Evidence = "secedit Privilege Rights::$($Check.Key). Raw='$raw'; missing='$($missing -join ', ')'; extra='$($extra -join ', ')'."
    }
}

function Test-CISSecurityPolicy {
    <#
    .SYNOPSIS
        Compares one local security policy value with its definition.
    #>
    [CmdletBinding()]
    [OutputType([System.Management.Automation.PSCustomObject])]
    param ([Parameter(Mandatory = $true)] [psobject]$Check)

    $policy = Get-CISSecurityPolicy
    if (-not $policy.Available) {
        return [pscustomobject]@{ Status = 'WARNING'; Actual = '<unavailable>'; Evidence = "Local security policy export failed. $($policy.Error)" }
    }
    $lookupKey = '{0}|{1}' -f $Check.Section, $Check.Key
    if (-not $policy.Data.ContainsKey($lookupKey)) {
        return [pscustomobject]@{ Status = 'FAIL'; Actual = '<not present>'; Evidence = "secedit did not return $lookupKey." }
    }
    $actual = $policy.Data[$lookupKey]
    try {
        $passed = Test-CISValue -Actual $actual -Operator ([string]$Check.Operator) -Expected $Check.Expected
        return [pscustomobject]@{
            Status = if ($passed) { 'PASS' } else { 'FAIL' }
            Actual = ConvertTo-CISDisplayValue $actual
            Evidence = "secedit $lookupKey was $(ConvertTo-CISDisplayValue $actual)."
        }
    }
    catch {
        return [pscustomobject]@{ Status = 'WARNING'; Actual = ConvertTo-CISDisplayValue $actual; Evidence = "Security policy comparison failed for $lookupKey. $($_.Exception.Message)" }
    }
}

function Get-CISAuditPolicy {
    <#
    .SYNOPSIS
        Reads and caches advanced audit policy in CSV form.
    #>
    [CmdletBinding()]
    [OutputType([System.Management.Automation.PSCustomObject])]
    param ()

    if ($null -ne $script:AuditPolicyCache) {
        return $script:AuditPolicyCache
    }
    $auditpol = Get-Command -Name 'auditpol.exe' -ErrorAction SilentlyContinue
    if ($null -eq $auditpol) {
        $script:AuditPolicyCache = [pscustomobject]@{ Available = $false; Data = @{}; Error = 'auditpol.exe is unavailable.' }
        return $script:AuditPolicyCache
    }
    try {
        $raw = @(& $auditpol.Source /get /category:* /r 2>&1)
        if ($LASTEXITCODE -ne 0) {
            throw "auditpol.exe exited with code $LASTEXITCODE. $($raw -join ' ')"
        }
        $rows = @(($raw -join [Environment]::NewLine) | ConvertFrom-Csv)
        $data = @{}
        foreach ($row in $rows) {
            $names = @($row.PSObject.Properties.Name)
            $subcategoryProperty = $names | Where-Object { $_ -match '^Subcategory$' } | Select-Object -First 1
            $settingProperty = $names | Where-Object { $_ -match 'Inclusion Setting' } | Select-Object -First 1
            $valueProperty = $names | Where-Object { $_ -match 'Setting Value' } | Select-Object -First 1
            if (-not $subcategoryProperty) { continue }
            $subcategory = [string]$row.$subcategoryProperty
            $data[$subcategory] = [pscustomobject]@{
                Setting = if ($settingProperty) { [string]$row.$settingProperty } else { '' }
                Value = if ($valueProperty) { [string]$row.$valueProperty } else { '' }
            }
        }
        if ($data.Count -eq 0) {
            throw 'auditpol.exe returned no parseable subcategory rows. A localized CSV header may require a definition update.'
        }
        $script:AuditPolicyCache = [pscustomobject]@{ Available = $true; Data = $data; Error = $null }
    }
    catch {
        $script:AuditPolicyCache = [pscustomobject]@{ Available = $false; Data = @{}; Error = $_.Exception.Message }
    }
    return $script:AuditPolicyCache
}

function Test-CISAuditPolicy {
    <#
    .SYNOPSIS
        Evaluates one advanced audit policy subcategory.
    #>
    [CmdletBinding()]
    [OutputType([System.Management.Automation.PSCustomObject])]
    param ([Parameter(Mandatory = $true)] [psobject]$Check)

    $policy = Get-CISAuditPolicy
    if (-not $policy.Available) {
        return [pscustomobject]@{ Status = 'WARNING'; Actual = '<unavailable>'; Evidence = "Advanced audit policy read failed. $($policy.Error)" }
    }
    if (-not $policy.Data.ContainsKey([string]$Check.Subcategory)) {
        return [pscustomobject]@{ Status = 'WARNING'; Actual = '<not returned>'; Evidence = "auditpol.exe did not return subcategory '$($Check.Subcategory)'." }
    }
    $row = $policy.Data[[string]$Check.Subcategory]
    $actualFlags = @()
    $numericValue = 0
    if ([int]::TryParse([string]$row.Value, [ref]$numericValue)) {
        if (($numericValue -band 1) -eq 1) { $actualFlags += 'Success' }
        if (($numericValue -band 2) -eq 2) { $actualFlags += 'Failure' }
    }
    else {
        if ($row.Setting -match 'Success') { $actualFlags += 'Success' }
        if ($row.Setting -match 'Failure') { $actualFlags += 'Failure' }
    }
    $operator = if ($null -ne $Check.PSObject.Properties['Operator']) {
        [string]$Check.Operator
    }
    else {
        'ContainsAll'
    }
    $passed = Test-CISValue -Actual $actualFlags -Operator $operator -Expected $Check.Expected
    [pscustomobject]@{
        Status = if ($passed) { 'PASS' } else { 'FAIL' }
        Actual = if ($actualFlags.Count -gt 0) { $actualFlags -join ' and ' } else { 'No Auditing' }
        Evidence = "auditpol subcategory '$($Check.Subcategory)' returned '$($row.Setting)' (value '$($row.Value)'); comparison=$operator."
    }
}

function Test-CISBuiltinAccountName {
    <#
    .SYNOPSIS
        Checks whether a built-in local account has its default name.
    #>
    [CmdletBinding()]
    [OutputType([System.Management.Automation.PSCustomObject])]
    param ([Parameter(Mandatory = $true)] [psobject]$Check)

    try {
        $suffix = '-{0}' -f [int]$Check.Rid
        $account = Get-CimInstance -ClassName Win32_UserAccount -Filter 'LocalAccount=True' -ErrorAction Stop |
            Where-Object { [string]$_.SID -like "*$suffix" } | Select-Object -First 1
        if ($null -eq $account) {
            return [pscustomobject]@{ Status = 'WARNING'; Actual = '<not found>'; Evidence = "No local account with RID $($Check.Rid) was returned." }
        }
        $passed = Test-CISValue -Actual ([string]$account.Name) -Operator ([string]$Check.Operator) -Expected $Check.Expected
        return [pscustomobject]@{
            Status = if ($passed) { 'PASS' } else { 'FAIL' }
            Actual = [string]$account.Name
            Evidence = "Built-in account SID $($account.SID) is named '$($account.Name)'."
        }
    }
    catch {
        return [pscustomobject]@{ Status = 'WARNING'; Actual = '<unavailable>'; Evidence = "Built-in account query failed. $($_.Exception.Message)" }
    }
}

function Test-CISInstalledProduct {
    <#
    .SYNOPSIS
        Checks installed-product registry entries by name and minimum version.
    #>
    [CmdletBinding()]
    [OutputType([System.Management.Automation.PSCustomObject])]
    param ([Parameter(Mandatory = $true)] [psobject]$Check)

    $uninstallPaths = @(
        'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
        'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
    )
    try {
        $products = foreach ($path in $uninstallPaths) {
            if (-not (Test-Path -LiteralPath $path -PathType Container)) { continue }
            Get-ChildItem -LiteralPath $path -ErrorAction Stop | ForEach-Object {
                Get-ItemProperty -LiteralPath $_.PSPath -ErrorAction SilentlyContinue
            } | Where-Object { $_.DisplayName -match [string]$Check.NamePattern }
        }
        $matching = @($products)
        if ($matching.Count -eq 0) {
            return [pscustomobject]@{
                Status = 'FAIL'; Actual = '<not installed>'
                Evidence = "No installed product matched '$($Check.NamePattern)'."
            }
        }
        $minimum = [version]([string]$Check.MinimumVersion)
        $compliant = @($matching | Where-Object {
            try { [version]([string]$_.DisplayVersion) -ge $minimum } catch { $false }
        })
        $display = @($matching | ForEach-Object { '{0} {1}' -f $_.DisplayName, $_.DisplayVersion }) -join '; '
        return [pscustomobject]@{
            Status = if ($compliant.Count -gt 0) { 'PASS' } else { 'FAIL' }
            Actual = $display
            Evidence = "Installed-product inventory found: $display. Minimum version is $minimum."
        }
    }
    catch {
        return [pscustomobject]@{
            Status = 'WARNING'; Actual = '<unavailable>'
            Evidence = "Installed-product inventory failed. $($_.Exception.Message)"
        }
    }
}

function Invoke-CISControl {
    <#
    .SYNOPSIS
        Executes one control and returns a standardized CIS result.

    .PARAMETER Control
        Control definition from a benchmark JSON document.

    .PARAMETER Benchmark
        Benchmark metadata object.

    .PARAMETER BenchmarkFile
        File name of the selected benchmark definition.

    .OUTPUTS
        System.Management.Automation.PSCustomObject
    #>
    [CmdletBinding()]
    [OutputType([System.Management.Automation.PSCustomObject])]
    param (
        [Parameter(Mandatory = $true)] [psobject]$Control,
        [Parameter(Mandatory = $true)] [psobject]$Benchmark,
        [Parameter(Mandatory = $true)] [string]$BenchmarkFile,
        [Parameter()] [AllowNull()] [psobject]$Platform
    )

    $applicableRoles = @(if ($null -ne $Control.PSObject.Properties['AppliesToServerRoles']) {
        @($Control.AppliesToServerRoles)
    })
    if ($applicableRoles.Count -gt 0 -and $null -ne $Platform -and
        $applicableRoles -notcontains [string]$Platform.ServerRole) {
        $observation = [pscustomobject]@{
            Status = 'NOT APPLICABLE'
            Actual = '<not applicable>'
            Evidence = "Control applies to server role(s) '$($applicableRoles -join ', ')'; detected role is '$($Platform.ServerRole)'."
        }
    }
    else {
      try {
        switch ([string]$Control.Check.Type) {
            'Registry' {
                $observation = Test-CISRegistryCondition -Condition $Control.Check
            }
            'RegistryAll' {
                $conditionResults = @($Control.Check.Conditions | ForEach-Object { Test-CISRegistryCondition -Condition $_ })
                $status = if (@($conditionResults | Where-Object Status -eq 'WARNING').Count -gt 0) {
                    'WARNING'
                }
                elseif (@($conditionResults | Where-Object Status -eq 'FAIL').Count -gt 0) {
                    'FAIL'
                }
                else {
                    'PASS'
                }
                $observation = [pscustomobject]@{
                    Status = $status
                    Actual = ($conditionResults.Actual -join ' | ')
                    Evidence = ($conditionResults.Evidence -join ' ')
                }
            }
            'RegistryValueData' {
                $observation = Test-CISRegistryValueData -Check $Control.Check
            }
            'SecurityPolicy' {
                $observation = Test-CISSecurityPolicy -Check $Control.Check
            }
            'UserRight' {
                $observation = Test-CISUserRight -Check $Control.Check
            }
            'AuditPolicy' {
                $observation = Test-CISAuditPolicy -Check $Control.Check
            }
            'BuiltinAccountName' {
                $observation = Test-CISBuiltinAccountName -Check $Control.Check
            }
            'InstalledProduct' {
                $observation = Test-CISInstalledProduct -Check $Control.Check
            }
            default {
                throw "Unsupported check type '$($Control.Check.Type)'."
            }
        }
      }
      catch {
          $observation = [pscustomobject]@{
              Status = 'WARNING'
              Actual = '<unavailable>'
              Evidence = "Unexpected check error: $($_.Exception.Message)"
          }
        }
    }

    New-CISResult `
        -ControlID ([string]$Control.Id) `
        -Category ([string]$Control.Category) `
        -SubCategory ([string]$Control.SubCategory) `
        -Title ([string]$Control.Title) `
        -Expected ([string]$Control.ExpectedValue) `
        -Actual ([string]$observation.Actual) `
        -Status ([string]$observation.Status) `
        -Severity ([string]$Control.Severity) `
        -Evidence ([string]$observation.Evidence) `
        -Remediation ([string]$Control.Remediation) `
        -Reference ([string]$Control.Reference) `
        -BenchmarkName ([string]$Benchmark.Name) `
        -BenchmarkVersion ([string]$Benchmark.Version) `
        -BenchmarkFile $BenchmarkFile `
        -Profile ([string]$Control.Profile)
}

function Invoke-CISBenchmark {
    <#
    .SYNOPSIS
        Executes every automated control in a benchmark document.

    .PARAMETER BenchmarkDocument
        Validated benchmark document returned by Import-CISBenchmark.

    .PARAMETER BenchmarkPath
        Source path used for report provenance.

    .OUTPUTS
        System.Management.Automation.PSCustomObject
    #>
    [CmdletBinding()]
    [OutputType([System.Management.Automation.PSCustomObject])]
    param (
        [Parameter(Mandatory = $true)] [psobject]$BenchmarkDocument,
        [Parameter(Mandatory = $true)] [string]$BenchmarkPath,
        [Parameter()] [AllowNull()] [psobject]$Platform
    )

    $controls = @($BenchmarkDocument.Controls)
    for ($index = 0; $index -lt $controls.Count; $index++) {
        $control = $controls[$index]
        $percent = [Math]::Floor((($index + 1) / [Math]::Max(1, $controls.Count)) * 100)
        Write-Progress -Id 1 -Activity 'Executing CIS benchmark' -Status "$($control.Id) ($($index + 1) of $($controls.Count))" -PercentComplete $percent
        Invoke-CISControl -Control $control -Benchmark $BenchmarkDocument.Benchmark -BenchmarkFile (Split-Path -Path $BenchmarkPath -Leaf) -Platform $Platform
    }
    Write-Progress -Id 1 -Activity 'Executing CIS benchmark' -Completed
}

Export-ModuleMember -Function Import-CISBenchmark, Invoke-CISBenchmark, Invoke-CISControl, Test-CISValue
