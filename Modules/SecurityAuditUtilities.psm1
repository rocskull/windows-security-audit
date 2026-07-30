Set-StrictMode -Version Latest
Import-Module (Join-Path $PSScriptRoot 'Common.psm1') -Force -ErrorAction Stop
Import-Module (Join-Path $PSScriptRoot 'Result.psm1') -Force -ErrorAction Stop
function Get-CISRegistryValue { param([string]$Path,[string]$Name) Common\Get-CISRegistryValue -Path $Path -Name $Name }
function New-CISAuditFinding { param([string]$ControlID,[string]$Category,[string]$SubCategory,[string]$Title,[string]$Expected,[string]$Actual,[ValidateSet('PASS','FAIL','WARNING','NOT APPLICABLE')][string]$Status,[ValidateSet('Critical','High','Medium','Low','Informational')][string]$Severity,[string]$Evidence,[string]$Remediation) New-CISResult -ControlID $ControlID -Category $Category -SubCategory $SubCategory -Title $Title -Expected $Expected -Actual $Actual -Status $Status -Severity $Severity -Evidence $Evidence -Remediation $Remediation -Reference 'Windows security configuration review' }
function Test-CISBool { param([object]$Value) if($null -eq $Value){'WARNING'}elseif($Value -eq 1 -or $Value -eq $true){'PASS'}else{'FAIL'} }
Export-ModuleMember -Function Get-CISRegistryValue,New-CISAuditFinding,Test-CISBool
<#
.SYNOPSIS
    Provides compatibility helpers for legacy audit modules.
.DESCRIPTION
    Retained for framework v1 modules. New CIS checks use BenchmarkEngine.psm1
    and Result.psm1 directly.
#>
