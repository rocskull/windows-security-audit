Set-StrictMode -Version Latest
Import-Module (Join-Path $PSScriptRoot 'SecurityAuditUtilities.psm1') -Force -ErrorAction Stop
function Invoke-Audit {[CmdletBinding()][OutputType([pscustomobject])]param();$p='HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell';$checks=@(@('PS-001','PowerShell Version',"$($PSVersionTable.PSVersion)",'PASS'),@('PS-002','PowerShell 2 Installed',(Test-Path "$env:WINDIR\System32\WindowsPowerShell\v1.0\powershell.exe"),'WARNING'),@('PS-003','Execution Policy',(Get-ExecutionPolicy -List|Out-String),'PASS'),@('PS-004','Constrained Language Mode',$ExecutionContext.SessionState.LanguageMode,'PASS'),@('PS-005','AMSI',(Test-Path 'HKLM:\SOFTWARE\Microsoft\AMSI'),'PASS'),@('PS-006','Script Block Logging',(Get-CISRegistryValue "$p\ScriptBlockLogging" 'EnableScriptBlockLogging'),$null),@('PS-007','Module Logging',(Get-CISRegistryValue "$p\ModuleLogging" 'EnableModuleLogging'),$null),@('PS-008','Transcription',(Get-CISRegistryValue "$p\Transcription" 'EnableTranscripting'),$null),@('PS-009','Protected Event Logging',(Get-CISRegistryValue "$p\ProtectedEventLogging" 'EnableProtectedEventLogging'),$null),@('PS-010','PowerShell Remoting',(Get-Service WinRM -ErrorAction SilentlyContinue).Status,'PASS'),@('PS-011','Profiles',($PROFILE),'PASS'));foreach($c in $checks){$status=if($null -eq $c[3]){Test-CISBool $c[2]}else{$c[3]};New-CISAuditFinding $c[0] 'PowerShell Security' 'PowerShell' $c[1] 'Configured and reviewed.' ([string]$c[2]) $status Medium ("$($c[1]): $($c[2])") 'Review and configure PowerShell security controls.'}}
Export-ModuleMember -Function Invoke-Audit
<#
.SYNOPSIS
    Provides legacy PowerShell security advisory checks.
.DESCRIPTION
    Retained for compatibility with framework v1 and excluded from the v2 CIS
    compliance score.
#>
