Set-StrictMode -Version Latest
Import-Module (Join-Path $PSScriptRoot 'SecurityAuditUtilities.psm1') -Force -ErrorAction Stop
function Invoke-Audit {[CmdletBinding()][OutputType([pscustomobject])]param();$p='HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard';$checks=@(@('CG-001','Credential Guard Enabled',$p,'EnableVirtualizationBasedSecurity'),@('CG-002','LSA Isolation','HKLM:\SYSTEM\CurrentControlSet\Control\Lsa','RunAsPPL'),@('CG-003','Virtualization Support',$p,'RequirePlatformSecurityFeatures'),@('CG-004','UEFI Lock',$p,'Locked'),@('CG-005','Secure Boot','HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State','UEFISecureBootEnabled'),@('CG-006','TPM','HKLM:\SYSTEM\CurrentControlSet\Services\TPM','Start'));foreach($c in $checks){$v=Get-CISRegistryValue $c[2] $c[3];New-CISAuditFinding $c[0] 'Credential Guard' 'Credential Protection' $c[1] 'Enabled or available.' ([string]$v) $(if($null -eq $v){'WARNING'}else{'PASS'}) High "$($c[3])=$v" 'Enable Credential Guard prerequisites and verify firmware support.'}}
Export-ModuleMember -Function Invoke-Audit
<#
.SYNOPSIS
    Provides legacy Credential Guard review checks.
.DESCRIPTION
    Retained for compatibility with framework v1. The v2 CIS entry point uses
    versioned benchmark controls instead of this hard-coded module.
#>
