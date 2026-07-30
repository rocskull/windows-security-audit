Set-StrictMode -Version Latest
Import-Module (Join-Path $PSScriptRoot 'Result.psm1') -Force -ErrorAction Stop
Import-Module (Join-Path $PSScriptRoot 'Common.psm1') -Force -ErrorAction Stop

function New-FirewallResult {
    param([string]$ControlID,[string]$Title,[string]$Expected,[string]$Actual,[ValidateSet('PASS','FAIL','WARNING','NOT APPLICABLE')][string]$Status,[ValidateSet('Critical','High','Medium','Low','Informational')][string]$Severity,[string]$Evidence,[string]$Remediation)
    New-CISResult -ControlID $ControlID -Category 'Firewall' -SubCategory 'Microsoft Defender Firewall' -Title $Title -Expected $Expected -Actual $Actual -Status $Status -Severity $Severity -Evidence $Evidence -Remediation $Remediation -Reference 'CIS Microsoft Windows 10/11 Benchmark - Windows Defender Firewall'
}

function Invoke-Audit {
    [CmdletBinding()]
    [OutputType([System.Management.Automation.PSCustomObject])]
    param()
    try { $profiles = @(Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop) }
    catch {
        foreach ($check in @('Domain Firewall Enabled','Private Firewall Enabled','Public Firewall Enabled','Inbound Policy','Outbound Policy','Firewall Logging','Firewall Notifications')) {
            New-FirewallResult -ControlID ('FW-{0:d3}' -f (1 + [array]::IndexOf(@('Domain Firewall Enabled','Private Firewall Enabled','Public Firewall Enabled','Inbound Policy','Outbound Policy','Firewall Logging','Firewall Notifications'), $check))) -Title $check -Expected 'Firewall policy is available.' -Actual 'Unavailable' -Status WARNING -Severity High -Evidence $_.Exception.Message -Remediation 'Verify Microsoft Defender Firewall management components are available.'
        }
        New-FirewallResult -ControlID 'FW-008' -Title 'Firewall Service Running' -Expected 'MpsSvc is running.' -Actual 'Unavailable' -Status WARNING -Severity High -Evidence $_.Exception.Message -Remediation 'Verify the Windows Defender Firewall service.'
        return
    }
    $profileMap = @{ Domain = 'Domain Firewall Enabled'; Private = 'Private Firewall Enabled'; Public = 'Public Firewall Enabled' }
    $index = 0
    foreach ($profileName in @('Domain','Private','Public')) {
        $index++
        $profile = @($profiles | Where-Object Name -eq $profileName | Select-Object -First 1)
        $actual = if ($profile.Count -eq 0) { 'Profile unavailable' } elseif ($profile[0].Enabled) { 'Enabled' } else { 'Disabled' }
        New-FirewallResult -ControlID ('FW-{0:d3}' -f $index) -Title $profileMap[$profileName] -Expected 'Enabled' -Actual $actual -Status $(if ($profile.Count -eq 0) {'WARNING'} elseif ($profile[0].Enabled) {'PASS'} else {'FAIL'}) -Severity High -Evidence ('Profile: {0}; Enabled: {1}.' -f $profileName, $(if($profile.Count){$profile[0].Enabled}else{'<unavailable>'})) -Remediation ('Enable the {0} firewall profile.' -f $profileName)
    }
    $inbound = @($profiles | ForEach-Object { '{0}={1}' -f $_.Name,$_.DefaultInboundAction })
    New-FirewallResult -ControlID 'FW-004' -Title 'Inbound Policy' -Expected 'Block for every firewall profile' -Actual ($inbound -join '; ') -Status $(if ($profiles.Count -eq 3 -and @($profiles | Where-Object { $_.DefaultInboundAction -ne 'Block' }).Count -eq 0) {'PASS'} else {'FAIL'}) -Severity High -Evidence ('DefaultInboundAction values: {0}.' -f ($inbound -join '; ')) -Remediation 'Set the default inbound action to Block for Domain, Private, and Public profiles.'
    $outbound = @($profiles | ForEach-Object { '{0}={1}' -f $_.Name,$_.DefaultOutboundAction })
    New-FirewallResult -ControlID 'FW-005' -Title 'Outbound Policy' -Expected 'Allow or a documented restrictive policy for every profile' -Actual ($outbound -join '; ') -Status $(if ($profiles.Count -eq 3 -and @($profiles | Where-Object { $_.DefaultOutboundAction -notin @('Allow','Block') }).Count -eq 0) {'PASS'} else {'WARNING'}) -Severity Medium -Evidence ('DefaultOutboundAction values: {0}.' -f ($outbound -join '; ')) -Remediation 'Review default outbound actions and document any restrictive policy.'
    $logging = @($profiles | ForEach-Object { '{0}: LogBlocked={1}, LogAllowed={2}, Size={3}' -f $_.Name,$_.LogBlocked,$_.LogAllowed,$_.LogMaxSizeKilobytes })
    New-FirewallResult -ControlID 'FW-006' -Title 'Firewall Logging' -Expected 'Dropped-packet logging enabled with a log size of at least 16,384 KB for every profile' -Actual ($logging -join '; ') -Status $(if ($profiles.Count -eq 3 -and @($profiles | Where-Object { -not $_.LogBlocked -or $_.LogMaxSizeKilobytes -lt 16384 }).Count -eq 0) {'PASS'} else {'FAIL'}) -Severity Medium -Evidence ($logging -join '; ') -Remediation 'Enable dropped-packet logging and set each firewall log size to at least 16,384 KB.'
    try { $service = Get-Service -Name MpsSvc -ErrorAction Stop; $serviceActual = $service.Status.ToString(); $serviceStatus = if($service.Status -eq 'Running'){'PASS'}else{'FAIL'}; $serviceEvidence = "MpsSvc status: $serviceActual." } catch { $serviceActual='Unavailable';$serviceStatus='WARNING';$serviceEvidence=$_.Exception.Message }
    New-FirewallResult -ControlID 'FW-008' -Title 'Firewall Service Running' -Expected 'Running' -Actual $serviceActual -Status $serviceStatus -Severity High -Evidence $serviceEvidence -Remediation 'Set the Windows Defender Firewall (MpsSvc) service to start automatically and run it.'
    $notifications = @($profiles | ForEach-Object { '{0}={1}' -f $_.Name,$_.NotifyOnListen })
    New-FirewallResult -ControlID 'FW-007' -Title 'Firewall Notifications' -Expected 'Notifications enabled for every profile' -Actual ($notifications -join '; ') -Status $(if ($profiles.Count -eq 3 -and @($profiles | Where-Object { -not $_.NotifyOnListen }).Count -eq 0) {'PASS'} else {'FAIL'}) -Severity Low -Evidence ('NotifyOnListen: {0}.' -f ($notifications -join '; ')) -Remediation 'Enable firewall notifications for blocked inbound connections.'
}
Export-ModuleMember -Function Invoke-Audit
<#
.SYNOPSIS
    Provides legacy Microsoft Defender Firewall review checks.
.DESCRIPTION
    Retained for compatibility with framework v1. The v2 CIS entry point reads
    firewall requirements from the selected benchmark definition.
#>
