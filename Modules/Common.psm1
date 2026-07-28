<#
.SYNOPSIS
    Shared read-only helpers for Windows security audit modules.
#>
Set-StrictMode -Version Latest
Import-Module (Join-Path $PSScriptRoot 'Result.psm1') -Force -ErrorAction Stop

function Test-IsAdministrator {
    [CmdletBinding()]
    [OutputType([bool])]
    param()
    try {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($identity)
        return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    catch { return $false }
}
function Get-CISRegistryValue { param([string]$Path,[string]$Name) try { Get-ItemPropertyValue -LiteralPath $Path -Name $Name -ErrorAction Stop } catch { $null } }
function Get-CISCimInstance { param([string]$ClassName,[string]$Namespace='root\cimv2',[string]$Filter) try { if($Filter){@(Get-CimInstance -ClassName $ClassName -Namespace $Namespace -Filter $Filter -ErrorAction Stop)}else{@(Get-CimInstance -ClassName $ClassName -Namespace $Namespace -ErrorAction Stop)} } catch { @() } }
function Get-CISServiceStatus { param([string]$Name) try { (Get-Service -Name $Name -ErrorAction Stop).Status.ToString() } catch { $null } }
function Get-CISFileSignature { param([string]$Path) if(-not(Test-Path -LiteralPath $Path -PathType Leaf)){return $null};try{(Get-AuthenticodeSignature -LiteralPath $Path -ErrorAction Stop).Status.ToString()}catch{'Unknown'} }
function Get-CISEventLog { param([string]$LogName) try { Get-WinEvent -ListLog $LogName -ErrorAction Stop } catch { $null } }
function Test-CISCapability {
    param([string]$Command,[string]$Module,[string]$RegistryPath,[switch]$RequireAdministrator,[switch]$DomainJoined)
    if($RequireAdministrator -and -not(Test-IsAdministrator)){return [pscustomobject]@{Available=$false;Status='NOT EXECUTED';Evidence='Administrator privileges required.'}}
    if($Command -and -not(Get-Command -Name $Command -ErrorAction SilentlyContinue)){return [pscustomobject]@{Available=$false;Status='NOT APPLICABLE';Evidence="Required command '$Command' is unavailable."}}
    if($Module -and -not(Get-Module -ListAvailable -Name $Module)){return [pscustomobject]@{Available=$false;Status='NOT APPLICABLE';Evidence="Required module '$Module' is unavailable."}}
    if($RegistryPath -and -not(Test-Path -LiteralPath $RegistryPath)){return [pscustomobject]@{Available=$false;Status='NOT APPLICABLE';Evidence="Required feature or policy path '$RegistryPath' is unavailable."}}
    if($DomainJoined){$cs=Get-CISCimInstance Win32_ComputerSystem;if(!$cs.Count -or -not $cs[0].PartOfDomain){return [pscustomobject]@{Available=$false;Status='NOT APPLICABLE';Evidence='The computer is not domain joined.'}}}
    [pscustomobject]@{Available=$true;Status='PASS';Evidence='Prerequisites met.'}
}
function Invoke-CISSafely { param([scriptblock]$ScriptBlock) try { & $ScriptBlock } catch { [pscustomobject]@{Succeeded=$false;Error=$_.Exception.Message} } }
function Write-CISLog { param([string]$Message,[ValidateSet('Debug','Info','Warning','Error')][string]$Level='Info') Write-Verbose -Message ('[{0}] {1}' -f $Level,$Message) }
function New-CISPrerequisiteResult { param([string]$ControlID,[string]$Category,[string]$Title,[string]$Status,[string]$Evidence) New-CISResult -ControlID $ControlID -Category $Category -SubCategory 'Prerequisite' -Title $Title -Expected 'Required audit capability is available.' -Actual 'Unavailable' -Status $Status -Severity Informational -Evidence $Evidence -Remediation $(if($Status -eq 'NOT EXECUTED'){'Run PowerShell as Administrator.'}else{'Install or enable the required Windows feature, module, or policy provider.'}) -Reference 'Audit framework capability detection' }
Export-ModuleMember -Function Test-IsAdministrator,Get-CISRegistryValue,Get-CISCimInstance,Get-CISServiceStatus,Get-CISFileSignature,Get-CISEventLog,Test-CISCapability,Invoke-CISSafely,Write-CISLog,New-CISPrerequisiteResult
