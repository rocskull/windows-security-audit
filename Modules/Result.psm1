<#
.SYNOPSIS
    Provides the standard result schema for Windows security configuration findings.

.DESCRIPTION
    This module exposes New-CISResult, the single constructor that audit modules
    should use when returning findings to the framework. The function writes no
    console output and returns only one PSCustomObject for each finding.
#>

Set-StrictMode -Version Latest

function New-CISResult {
    <#
    .SYNOPSIS
        Creates a standardized CIS audit finding.

    .DESCRIPTION
        Returns one ordered PSCustomObject using the framework's required result
        schema. This function performs no audit checks and writes no console output.

    .PARAMETER ControlID
        Unique identifier of the benchmark control.

    .PARAMETER Category
        Top-level benchmark category.

    .PARAMETER SubCategory
        Benchmark subcategory.

    .PARAMETER Title
        Human-readable control title.

    .PARAMETER Expected
        Expected secure configuration value or condition.

    .PARAMETER Actual
        Observed configuration value or condition.

    .PARAMETER Status
        Finding status: PASS, FAIL, WARNING, or NOT APPLICABLE.

    .PARAMETER Severity
        Severity assigned to the finding.

    .PARAMETER Evidence
        Evidence supporting the finding.

    .PARAMETER Remediation
        Recommended remediation guidance.

    .PARAMETER Reference
        Benchmark, policy, or documentation reference.

    .PARAMETER Timestamp
        Time at which the finding was created. Defaults to the current local time.

    .PARAMETER ComputerName
        Name of the audited computer. Defaults to the local computer name.

    .PARAMETER User
        Identity running the audit. Defaults to the current user name.

    .OUTPUTS
        System.Management.Automation.PSCustomObject

    .EXAMPLE
        New-CISResult -ControlID '1.1.1' -Category 'Account Policies' `
            -SubCategory 'Password Policy' -Title 'Example finding' `
            -Expected 'Enabled' -Actual 'Enabled' -Status PASS -Severity Medium `
            -Evidence 'Example evidence' -Remediation 'No action required.' `
            -Reference 'CIS Benchmark'
    #>
    [CmdletBinding()]
    [OutputType([System.Management.Automation.PSCustomObject])]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$ControlID,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Category,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$SubCategory,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Title,

        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$Expected,

        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$Actual,

        [Parameter(Mandatory = $true)]
        [ValidateSet('PASS', 'FAIL', 'WARNING', 'NOT APPLICABLE', 'NOT EXECUTED')]
        [string]$Status,

        [Parameter(Mandatory = $true)]
        [ValidateSet('Critical', 'High', 'Medium', 'Low', 'Informational', 'Info')]
        [string]$Severity,

        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$Evidence,

        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$Remediation,

        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$Reference,

        [Parameter()]
        [datetime]$Timestamp = (Get-Date),

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$ComputerName = $env:COMPUTERNAME,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$User = $env:USERNAME
    )

    [pscustomobject][ordered]@{
        ControlID    = $ControlID
        Category     = $Category
        SubCategory  = $SubCategory
        Title        = $Title
        Expected     = $Expected
        Actual       = $Actual
        Status       = $Status
        Severity     = if ($Severity -eq 'Info') { 'Informational' } else { $Severity }
        Evidence     = $Evidence
        Remediation  = $Remediation
        Reference    = $Reference
        Timestamp    = $Timestamp
        ComputerName = $ComputerName
        User         = $User
    }
}

Export-ModuleMember -Function New-CISResult
