<#
.SYNOPSIS
    Audits local Windows account and group configuration.

.DESCRIPTION
    Implements read-only account checks for the Windows Security Configuration
    Review Framework. Findings are returned as New-CISResult PSCustomObjects.
    The module does not write to the console or modify any local accounts.
#>

Set-StrictMode -Version Latest

$resultModulePath = Join-Path -Path $PSScriptRoot -ChildPath 'Result.psm1'
Import-Module -Name $resultModulePath -Force -ErrorAction Stop
Import-Module -Name (Join-Path $PSScriptRoot 'Common.psm1') -Force -ErrorAction Stop

function New-AccountsResult {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)] [string]$ControlID,
        [Parameter(Mandatory = $true)] [string]$SubCategory,
        [Parameter(Mandatory = $true)] [string]$Title,
        [Parameter(Mandatory = $true)] [string]$Expected,
        [Parameter(Mandatory = $true)] [string]$Actual,
        [Parameter(Mandatory = $true)] [ValidateSet('PASS', 'FAIL', 'WARNING', 'NOT APPLICABLE')] [string]$Status,
        [Parameter(Mandatory = $true)] [ValidateSet('Critical', 'High', 'Medium', 'Low', 'Informational')] [string]$Severity,
        [Parameter(Mandatory = $true)] [string]$Evidence,
        [Parameter(Mandatory = $true)] [string]$Remediation,
        [Parameter(Mandatory = $true)] [string]$Reference
    )

    return New-CISResult -ControlID $ControlID -Category 'Accounts' -SubCategory $SubCategory -Title $Title -Expected $Expected -Actual $Actual -Status $Status -Severity $Severity -Evidence $Evidence -Remediation $Remediation -Reference $Reference
}

function Get-AccountsAuditConfiguration {
    [CmdletBinding()]
    param ()

    $configurationPath = Join-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -ChildPath 'Configuration.json'
    $configuration = [pscustomobject]@{
        AllowedLocalAdministrators = @()
        LastLogonWarningDays       = 90
    }

    if (-not (Test-Path -LiteralPath $configurationPath -PathType Leaf)) {
        return $configuration
    }

    try {
        $jsonConfiguration = Get-Content -LiteralPath $configurationPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
        if ($null -ne $jsonConfiguration.PSObject.Properties['Accounts']) {
            $accounts = $jsonConfiguration.Accounts
            if ($null -ne $accounts.PSObject.Properties['AllowedLocalAdministrators'] -and $null -ne $accounts.AllowedLocalAdministrators) {
                $configuration.AllowedLocalAdministrators = @($accounts.AllowedLocalAdministrators)
            }
            if ($null -ne $accounts.PSObject.Properties['LastLogonWarningDays']) {
                $days = 0
                if ([int]::TryParse([string]$accounts.LastLogonWarningDays, [ref]$days) -and $days -gt 0) {
                    $configuration.LastLogonWarningDays = $days
                }
            }
        }
    }
    catch {
        # Default, conservative configuration is used if the optional section cannot be read.
    }

    return $configuration
}

function Get-LocalAccountInventory {
    [CmdletBinding()]
    param ()

    try {
        return @(Get-CimInstance -ClassName Win32_UserAccount -Filter 'LocalAccount = TRUE' -ErrorAction Stop)
    }
    catch {
        $getLocalUser = Get-Command -Name Get-LocalUser -ErrorAction SilentlyContinue
        if ($null -eq $getLocalUser) {
            throw "Unable to retrieve local accounts: $($_.Exception.Message)"
        }

        try {
            return @(Get-LocalUser -ErrorAction Stop | ForEach-Object {
                [pscustomobject]@{
                    Name              = $_.Name
                    Domain            = $env:COMPUTERNAME
                    SID               = [string]$_.SID
                    Disabled          = -not $_.Enabled
                    Lockout           = $null
                    PasswordExpires   = ($null -ne $_.PasswordExpires)
                    PasswordRequired  = $_.PasswordRequired
                    LastLogon         = $_.LastLogon
                    InventoryProvider = 'LocalAccounts'
                }
            })
        }
        catch {
            throw "Unable to retrieve local accounts through CIM or LocalAccounts: $($_.Exception.Message)"
        }
    }
}

function Get-AccountDisplayName {
    [CmdletBinding()]
    param ([Parameter(Mandatory = $true)] [psobject]$Account)

    $domainProperty = $Account.PSObject.Properties['Domain']
    $domain = if ($null -eq $domainProperty) { '' } else { [string]$domainProperty.Value }
    if ([string]::IsNullOrWhiteSpace($domain)) {
        return [string]$Account.Name
    }
    return ('{0}\{1}' -f $domain, $Account.Name)
}

function ConvertTo-LastLogonDate {
    [CmdletBinding()]
    param ([Parameter()] [AllowNull()] [object]$Value)

    if ($null -eq $Value) {
        return $null
    }
    if ($Value -is [datetime]) {
        return [datetime]$Value
    }
    try {
        return [datetime]$Value
    }
    catch {
        return $null
    }
}

function Get-LocalGroupMembers {
    [CmdletBinding()]
    param ([Parameter(Mandatory = $true)] [psobject]$Group)

    if ($Group.PSObject.Properties['InventoryProvider'] -and $Group.InventoryProvider -eq 'LocalAccounts') {
        try {
            return @(Get-LocalGroupMember -SID $Group.SID -ErrorAction Stop)
        }
        catch {
            throw "Unable to retrieve members of local group '$($Group.Name)': $($_.Exception.Message)"
        }
    }

    try {
        # The inventory object is normalized to a PSCustomObject, so retain and
        # use its original CIM instance for the association query.
        if ($Group.PSObject.Properties['CimInstance'] -and $null -ne $Group.CimInstance) {
            return @(Get-CimAssociatedInstance -InputObject $Group.CimInstance -Association Win32_GroupUser -ErrorAction Stop)
        }
        throw "No CIM instance is available for local group '$($Group.Name)'."
    }
    catch {
        try {
            return @(Get-LocalGroupMember -SID $Group.SID -ErrorAction Stop)
        }
        catch {
            throw "Unable to retrieve members of local group '$($Group.Name)': $($_.Exception.Message)"
        }
    }
}

function Get-LocalGroupInventory {
    [CmdletBinding()]
    param ()

    try {
        return @(Get-CimInstance -ClassName Win32_Group -Filter 'LocalAccount = TRUE' -ErrorAction Stop | ForEach-Object {
            [pscustomobject]@{
                Name              = $_.Name
                SID               = [string]$_.SID
                InventoryProvider = 'CIM'
                CimInstance       = $_
            }
        })
    }
    catch {
        $getLocalGroup = Get-Command -Name Get-LocalGroup -ErrorAction SilentlyContinue
        if ($null -eq $getLocalGroup) {
            throw "Unable to retrieve local groups: $($_.Exception.Message)"
        }
        try {
            return @(Get-LocalGroup -ErrorAction Stop | ForEach-Object {
                [pscustomobject]@{
                    Name              = $_.Name
                    SID               = [string]$_.SID
                    InventoryProvider = 'LocalAccounts'
                }
            })
        }
        catch {
            throw "Unable to retrieve local groups through CIM or LocalAccounts: $($_.Exception.Message)"
        }
    }
}

function Test-AllowedLocalAdministrator {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)] [psobject]$Account,
        [Parameter()] [string[]]$AllowedAdministrators
    )

    $candidates = @((Get-AccountDisplayName -Account $Account), [string]$Account.Name, [string]$Account.SID)
    foreach ($allowed in @($AllowedAdministrators)) {
        foreach ($candidate in $candidates) {
            if (-not [string]::IsNullOrWhiteSpace($allowed) -and $allowed.Equals($candidate, [System.StringComparison]::OrdinalIgnoreCase)) {
                return $true
            }
        }
    }
    return $false
}

function Invoke-Audit {
    <#
    .SYNOPSIS
        Performs read-only local account and group security checks.

    .DESCRIPTION
        Audits built-in accounts, account state and password properties, local
        Administrator membership, empty local groups, and stale last-logon
        records. Returns New-CISResult PSCustomObjects only.

    .OUTPUTS
        System.Management.Automation.PSCustomObject
    #>
    [CmdletBinding()]
    [OutputType([System.Management.Automation.PSCustomObject])]
    param ()

    $reference = 'Windows Security Configuration Review Framework - Accounts Baseline'
    $configuration = Get-AccountsAuditConfiguration

    try {
        $accounts = Get-LocalAccountInventory
    }
    catch {
        New-AccountsResult -ControlID 'ACCT-001' -SubCategory 'Account Discovery' -Title 'Local account inventory' -Expected 'Local accounts can be enumerated.' -Actual 'Inventory unavailable.' -Status WARNING -Severity High -Evidence $_.Exception.Message -Remediation 'Verify local WMI/CIM access and run the audit with sufficient read permissions.' -Reference $reference
        return
    }

    # 1. Built-in Administrator Account
    $administrator = @($accounts | Where-Object { $_.SID -match '-500$' } | Select-Object -First 1)
    if ($administrator.Count -eq 0) {
        New-AccountsResult -ControlID 'ACCT-001' -SubCategory 'Built-in Accounts' -Title 'Built-in Administrator Account' -Expected 'Built-in Administrator account is disabled.' -Actual 'Built-in Administrator account was not found.' -Status WARNING -Severity High -Evidence 'No local account with a SID ending in -500 was returned by Win32_UserAccount.' -Remediation 'Verify that the built-in Administrator account is present and disabled, or document a supported exception.' -Reference $reference
    }
    else {
        $administratorState = if ($administrator[0].Disabled) { 'Disabled' } else { 'Enabled' }
        New-AccountsResult -ControlID 'ACCT-001' -SubCategory 'Built-in Accounts' -Title 'Built-in Administrator Account' -Expected 'Disabled' -Actual $administratorState -Status $(if ($administrator[0].Disabled) { 'PASS' } else { 'FAIL' }) -Severity High -Evidence ('Account: {0}; SID: {1}; Disabled: {2}.' -f (Get-AccountDisplayName $administrator[0]), $administrator[0].SID, $administrator[0].Disabled) -Remediation 'Disable the built-in Administrator account unless a documented operational exception requires it.' -Reference $reference
    }

    # 2. Guest Account
    $guest = @($accounts | Where-Object { $_.SID -match '-501$' } | Select-Object -First 1)
    if ($guest.Count -eq 0) {
        New-AccountsResult -ControlID 'ACCT-002' -SubCategory 'Built-in Accounts' -Title 'Guest Account' -Expected 'Guest account is disabled.' -Actual 'Guest account was not found.' -Status WARNING -Severity High -Evidence 'No local account with a SID ending in -501 was returned by Win32_UserAccount.' -Remediation 'Verify that the Guest account is present and disabled, or document a supported exception.' -Reference $reference
    }
    else {
        $guestState = if ($guest[0].Disabled) { 'Disabled' } else { 'Enabled' }
        New-AccountsResult -ControlID 'ACCT-002' -SubCategory 'Built-in Accounts' -Title 'Guest Account' -Expected 'Disabled' -Actual $guestState -Status $(if ($guest[0].Disabled) { 'PASS' } else { 'FAIL' }) -Severity High -Evidence ('Account: {0}; SID: {1}; Disabled: {2}.' -f (Get-AccountDisplayName $guest[0]), $guest[0].SID, $guest[0].Disabled) -Remediation 'Disable the Guest account.' -Reference $reference
    }

    # 3. Disabled Accounts
    $disabledAccounts = @($accounts | Where-Object { $_.Disabled })
    $disabledNames = @($disabledAccounts | ForEach-Object { Get-AccountDisplayName $_ })
    New-AccountsResult -ControlID 'ACCT-003' -SubCategory 'Account Status' -Title 'Disabled Accounts' -Expected 'Disabled accounts are documented and reviewed.' -Actual $(if ($disabledNames.Count -eq 0) { 'No disabled local accounts found.' } else { $disabledNames -join '; ' }) -Status $(if ($disabledNames.Count -eq 0) { 'PASS' } else { 'WARNING' }) -Severity Low -Evidence ('Disabled local account count: {0}.' -f $disabledNames.Count) -Remediation 'Review disabled accounts periodically; remove accounts that are no longer required and document retained accounts.' -Reference $reference

    # 4. Locked Accounts
    $lockoutStatusUnknown = @($accounts | Where-Object { $null -eq $_.Lockout }).Count -gt 0
    $lockedAccounts = @($accounts | Where-Object { $_.Lockout })
    $lockedNames = @($lockedAccounts | ForEach-Object { Get-AccountDisplayName $_ })
    New-AccountsResult -ControlID 'ACCT-004' -SubCategory 'Account Status' -Title 'Locked Accounts' -Expected 'No local accounts are locked.' -Actual $(if ($lockoutStatusUnknown) { 'Lockout status is unavailable through the LocalAccounts fallback.' } elseif ($lockedNames.Count -eq 0) { 'No locked local accounts found.' } else { $lockedNames -join '; ' }) -Status $(if ($lockoutStatusUnknown) { 'WARNING' } elseif ($lockedNames.Count -eq 0) { 'PASS' } else { 'FAIL' }) -Severity High -Evidence ('Locked local account count: {0}; lockout status available: {1}.' -f $lockedNames.Count, (-not $lockoutStatusUnknown)) -Remediation 'Investigate locked accounts for possible password attacks or stale credentials, then unlock only verified accounts.' -Reference $reference

    # 5. Password Never Expires
    $activeAccounts = @($accounts | Where-Object { -not $_.Disabled })
    $neverExpireAccounts = @($activeAccounts | Where-Object { -not $_.PasswordExpires })
    $neverExpireNames = @($neverExpireAccounts | ForEach-Object { Get-AccountDisplayName $_ })
    New-AccountsResult -ControlID 'ACCT-005' -SubCategory 'Password Policy' -Title 'Password Never Expires' -Expected 'Enabled local accounts have password expiration enabled.' -Actual $(if ($neverExpireNames.Count -eq 0) { 'No enabled local accounts have non-expiring passwords.' } else { $neverExpireNames -join '; ' }) -Status $(if ($neverExpireNames.Count -eq 0) { 'PASS' } else { 'FAIL' }) -Severity High -Evidence ('Enabled accounts with PasswordExpires=False: {0}.' -f $neverExpireNames.Count) -Remediation 'Enable password expiration for affected local accounts or document approved service-account exceptions.' -Reference $reference

    # 6. Users without Password Required
    $noPasswordRequired = @($activeAccounts | Where-Object { -not $_.PasswordRequired })
    $noPasswordRequiredNames = @($noPasswordRequired | ForEach-Object { Get-AccountDisplayName $_ })
    New-AccountsResult -ControlID 'ACCT-006' -SubCategory 'Password Policy' -Title 'Users without Password Required' -Expected 'Enabled local accounts require a password.' -Actual $(if ($noPasswordRequiredNames.Count -eq 0) { 'All enabled local accounts require passwords.' } else { $noPasswordRequiredNames -join '; ' }) -Status $(if ($noPasswordRequiredNames.Count -eq 0) { 'PASS' } else { 'FAIL' }) -Severity High -Evidence ('Enabled accounts with PasswordRequired=False: {0}.' -f $noPasswordRequiredNames.Count) -Remediation 'Require passwords for affected accounts or disable accounts that are not required.' -Reference $reference

    # 7. Members of Local Administrators
    try {
        $localGroups = Get-LocalGroupInventory
    }
    catch {
        $localGroups = @()
    }
    $administratorsGroup = @($localGroups | Where-Object { $_.SID -eq 'S-1-5-32-544' } | Select-Object -First 1)
    $administratorMembers = @()
    if ($administratorsGroup.Count -eq 0) {
        New-AccountsResult -ControlID 'ACCT-007' -SubCategory 'Privileged Groups' -Title 'Members of Local Administrators' -Expected 'Local Administrators group membership is available for review.' -Actual 'Local Administrators group was not found.' -Status WARNING -Severity High -Evidence 'No local Win32_Group object with SID S-1-5-32-544 was found.' -Remediation 'Verify local group enumeration and review the local Administrators group.' -Reference $reference
    }
    else {
        try {
            $administratorMembers = Get-LocalGroupMembers -Group $administratorsGroup[0]
            $administratorMemberNames = @($administratorMembers | ForEach-Object { Get-AccountDisplayName $_ })
            New-AccountsResult -ControlID 'ACCT-007' -SubCategory 'Privileged Groups' -Title 'Members of Local Administrators' -Expected 'Local Administrators membership is reviewed.' -Actual $(if ($administratorMemberNames.Count -eq 0) { 'No members found.' } else { $administratorMemberNames -join '; ' }) -Status PASS -Severity High -Evidence ('Local Administrators group SID: S-1-5-32-544; member count: {0}.' -f $administratorMemberNames.Count) -Remediation 'Review privileged membership regularly and remove accounts that do not require local administrative access.' -Reference $reference
        }
        catch {
            New-AccountsResult -ControlID 'ACCT-007' -SubCategory 'Privileged Groups' -Title 'Members of Local Administrators' -Expected 'Local Administrators group membership is available for review.' -Actual 'Membership enumeration failed.' -Status WARNING -Severity High -Evidence $_.Exception.Message -Remediation 'Verify local WMI/CIM access and review local Administrators membership manually.' -Reference $reference
        }
    }

    # 8. Empty Local Groups
    if ($localGroups.Count -eq 0) {
        New-AccountsResult -ControlID 'ACCT-008' -SubCategory 'Local Groups' -Title 'Empty Local Groups' -Expected 'Local groups are available for review.' -Actual 'No local groups were enumerated.' -Status WARNING -Severity Low -Evidence 'Win32_Group returned no local groups.' -Remediation 'Verify local group enumeration and review local group configuration manually.' -Reference $reference
    }
    else {
        $emptyGroupNames = New-Object 'System.Collections.Generic.List[string]'
        $groupReadErrors = New-Object 'System.Collections.Generic.List[string]'
        foreach ($localGroup in $localGroups) {
            try {
                if ((Get-LocalGroupMembers -Group $localGroup).Count -eq 0) {
                    $emptyGroupNames.Add([string]$localGroup.Name)
                }
            }
            catch {
                $groupReadErrors.Add([string]$localGroup.Name)
            }
        }
        $emptyGroupStatus = if ($groupReadErrors.Count -gt 0) { 'WARNING' } elseif ($emptyGroupNames.Count -gt 0) { 'WARNING' } else { 'PASS' }
        New-AccountsResult -ControlID 'ACCT-008' -SubCategory 'Local Groups' -Title 'Empty Local Groups' -Expected 'Empty local groups are documented and reviewed.' -Actual $(if ($emptyGroupNames.Count -eq 0) { 'No empty local groups found.' } else { $emptyGroupNames -join '; ' }) -Status $emptyGroupStatus -Severity Low -Evidence ('Empty group count: {0}; groups not enumerated: {1}.' -f $emptyGroupNames.Count, $(if ($groupReadErrors.Count -eq 0) { 'None' } else { $groupReadErrors -join '; ' })) -Remediation 'Review empty groups and remove groups that are no longer required; investigate groups that could not be enumerated.' -Reference $reference
    }

    # 9. Unexpected Local Administrators
    if ($administratorsGroup.Count -gt 0 -and $administratorMembers.Count -gt 0) {
        if ($configuration.AllowedLocalAdministrators.Count -eq 0) {
            New-AccountsResult -ControlID 'ACCT-009' -SubCategory 'Privileged Groups' -Title 'Unexpected Local Administrators' -Expected 'A configured allowlist defines permitted local Administrators members.' -Actual 'No AllowedLocalAdministrators entries are configured.' -Status WARNING -Severity Critical -Evidence ('Observed members: {0}.' -f (@($administratorMembers | ForEach-Object { Get-AccountDisplayName $_ }) -join '; ')) -Remediation 'Populate Configuration.json Accounts.AllowedLocalAdministrators with approved account names, domain-qualified names, or SIDs.' -Reference $reference
        }
        else {
            $unexpectedAdministrators = @($administratorMembers | Where-Object { -not (Test-AllowedLocalAdministrator -Account $_ -AllowedAdministrators $configuration.AllowedLocalAdministrators) })
            $unexpectedNames = @($unexpectedAdministrators | ForEach-Object { Get-AccountDisplayName $_ })
            New-AccountsResult -ControlID 'ACCT-009' -SubCategory 'Privileged Groups' -Title 'Unexpected Local Administrators' -Expected ($configuration.AllowedLocalAdministrators -join '; ') -Actual $(if ($unexpectedNames.Count -eq 0) { 'No unexpected local Administrators members found.' } else { $unexpectedNames -join '; ' }) -Status $(if ($unexpectedNames.Count -eq 0) { 'PASS' } else { 'FAIL' }) -Severity Critical -Evidence ('Configured allowlist entries: {0}; unexpected member count: {1}.' -f $configuration.AllowedLocalAdministrators.Count, $unexpectedNames.Count) -Remediation 'Remove unapproved local Administrators members or add documented, approved identities to the allowlist.' -Reference $reference
        }
    }
    elseif ($administratorsGroup.Count -gt 0) {
        New-AccountsResult -ControlID 'ACCT-009' -SubCategory 'Privileged Groups' -Title 'Unexpected Local Administrators' -Expected 'A configured allowlist defines permitted local Administrators members.' -Actual 'No local Administrators members were available for comparison.' -Status WARNING -Severity Critical -Evidence 'The local Administrators group is empty or membership enumeration was unavailable.' -Remediation 'Verify local Administrators membership and configure an approved allowlist.' -Reference $reference
    }

    # 10. Last Logon Time
    $cutoff = (Get-Date).AddDays(-1 * $configuration.LastLogonWarningDays)
    $staleAccounts = New-Object 'System.Collections.Generic.List[string]'
    foreach ($account in $activeAccounts) {
        $lastLogon = ConvertTo-LastLogonDate -Value $account.LastLogon
        if ($null -eq $lastLogon -or $lastLogon -lt $cutoff) {
            $lastLogonText = if ($null -eq $lastLogon) { 'Never or unavailable' } else { $lastLogon.ToString('yyyy-MM-dd HH:mm:ss') }
            $staleAccounts.Add(('{0} ({1})' -f (Get-AccountDisplayName $account), $lastLogonText))
        }
    }
    New-AccountsResult -ControlID 'ACCT-010' -SubCategory 'Account Activity' -Title 'Last Logon Time' -Expected ('Enabled local accounts have logged on within the last {0} days or are documented.' -f $configuration.LastLogonWarningDays) -Actual $(if ($staleAccounts.Count -eq 0) { 'No stale enabled local accounts found.' } else { $staleAccounts -join '; ' }) -Status $(if ($staleAccounts.Count -eq 0) { 'PASS' } else { 'WARNING' }) -Severity Medium -Evidence ('Review cutoff: {0}; stale or never-used enabled account count: {1}.' -f $cutoff.ToString('yyyy-MM-dd HH:mm:ss'), $staleAccounts.Count) -Remediation 'Disable, remove, or document enabled accounts that have not logged on within the review period.' -Reference $reference
}

Export-ModuleMember -Function Invoke-Audit
