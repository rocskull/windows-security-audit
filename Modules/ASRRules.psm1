Set-StrictMode -Version Latest
Import-Module (Join-Path $PSScriptRoot 'SecurityAuditUtilities.psm1') -Force -ErrorAction Stop
function Invoke-Audit {[CmdletBinding()][OutputType([pscustomobject])]param();try{$p=Get-MpPreference -ErrorAction Stop;$ids=@($p.AttackSurfaceReductionRules_Ids);$actions=@($p.AttackSurfaceReductionRules_Actions)}catch{$ids=@();$actions=@()};$names=@{'56a863a9-875e-4185-98a7-b882c64b5ce5'='Vulnerable signed drivers';'d4f940ab-401b-4efc-aadc-ad5f3c50688a'='Office child processes';'3b576869-a4ec-4529-8536-b80a7769e899'='Office creates executables';'be9ba2d9-53ea-4cdc-84e5-9b1eeee46550'='Executable content from email';'01443614-cd74-433a-b99e-2ecdc07bfc25'='PSExec and WMI child processes';'5beb7efe-fd9a-4556-801d-275e5ffc04cc'='Obfuscated scripts'};$n=0;foreach($guid in $names.Keys){$n++;$idx=[array]::IndexOf($ids,$guid);$action=if($idx -ge 0){[int]$actions[$idx]}else{0};$mode=@{0='Disabled';1='Block Mode';2='Audit Mode';6='Warn Mode'}[$action];New-CISAuditFinding ('ASR-{0:d3}' -f $n) 'Defender ASR' 'Attack Surface Reduction' $names[$guid] 'Rule is configured and reviewed.' ("GUID=$guid; Enabled=$($action -ne 0); Mode=$mode; Audit Mode=$($action -eq 2); Block Mode=$($action -eq 1); Warn Mode=$($action -eq 6); Disabled=$($action -eq 0)") $(if($idx -lt 0){'WARNING'}else{'PASS'}) High ("Rule Name=$($names[$guid]); GUID=$guid; Action=$action") 'Configure the ASR rule in block, audit, or warn mode as appropriate.'}}
Export-ModuleMember -Function Invoke-Audit
<#
.SYNOPSIS
    Provides legacy Microsoft Defender Attack Surface Reduction review checks.
.DESCRIPTION
    Retained for compatibility with framework v1. The v2 CIS entry point does
    not execute this module; CIS controls are defined in benchmark JSON files.
#>
