<#
.SYNOPSIS
    Audits the local Windows password and account-lockout policy.

.DESCRIPTION
    Exports the local security policy's System Access area with secedit and
    evaluates the exported values against the framework baseline. The export
    is read-only with respect to system configuration and its temporary file is
    removed before the function returns. Findings are returned as
    New-CISResult objects; this module does not write to the console.
#>

Set-StrictMode -Version Latest

$resultModulePath = Join-Path -Path $PSScriptRoot -ChildPath 'Result.psm1'
Import-Module -Name $resultModulePath -Force -ErrorAction Stop
Import-Module -Name (Join-Path $PSScriptRoot 'Common.psm1') -Force -ErrorAction Stop

function New-PasswordPolicyResult {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)] [string]$ControlID,
        [Parameter(Mandatory = $true)] [string]$Title,
        [Parameter(Mandatory = $true)] [string]$Expected,
        [Parameter(Mandatory = $true)] [string]$Actual,
        [Parameter(Mandatory = $true)] [ValidateSet('PASS', 'FAIL', 'WARNING')] [string]$Status,
        [Parameter(Mandatory = $true)] [ValidateSet('Critical', 'High', 'Medium', 'Low', 'Informational')] [string]$Severity,
        [Parameter(Mandatory = $true)] [string]$Evidence,
        [Parameter(Mandatory = $true)] [string]$Remediation
    )

    return New-CISResult -ControlID $ControlID -Category 'Password Policy' -SubCategory 'Local Security Policy' -Title $Title -Expected $Expected -Actual $Actual -Status $Status -Severity $Severity -Evidence $Evidence -Remediation $Remediation -Reference 'CIS Microsoft Windows 10/11 Benchmark - Account Policies'
}

function Get-LocalSystemAccessPolicy {
    <#
    .SYNOPSIS
        Reads the System Access section of the effective local security policy.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param ()

    $seceditPath = Join-Path -Path $env:SystemRoot -ChildPath 'System32\secedit.exe'
    if (-not (Test-Path -LiteralPath $seceditPath -PathType Leaf)) {
        throw "Local Security Policy export tool was not found: $seceditPath"
    }

    $exportPath = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath ('CISPasswordPolicy_{0}.inf' -f [guid]::NewGuid().ToString('N'))
    try {
        # secedit /export reads the effective security policy; it does not apply
        # or change any setting. Suppress its native status messages so this
        # module's only output is audit result objects.
        & $seceditPath /export /cfg $exportPath /areas SECURITYPOLICY 2>$null | Out-Null
        if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $exportPath -PathType Leaf)) {
            throw "secedit export failed with exit code $LASTEXITCODE."
        }

        $policy = @{}
        $section = ''
        foreach ($line in Get-Content -LiteralPath $exportPath -ErrorAction Stop) {
            $trimmedLine = $line.Trim()
            if ($trimmedLine -match '^\[(?<Section>[^\]]+)\]$') {
                $section = $matches['Section']
                continue
            }

            if ($section -eq 'System Access' -and $trimmedLine -match '^(?<Key>[^=]+?)\s*=\s*(?<Value>.*)$') {
                $policy[$matches['Key'].Trim()] = $matches['Value'].Trim()
            }
        }

        if ($policy.Count -eq 0) {
            throw 'The exported local security policy did not contain a System Access section.'
        }

        return $policy
    }
    finally {
        if (Test-Path -LiteralPath $exportPath -PathType Leaf) {
            Remove-Item -LiteralPath $exportPath -Force -ErrorAction SilentlyContinue
        }
    }
}

function Get-PolicyInteger {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)] [hashtable]$Policy,
        [Parameter(Mandatory = $true)] [string]$Key
    )

    if (-not $Policy.ContainsKey($Key)) {
        return $null
    }

    $number = 0
    if (-not [int]::TryParse([string]$Policy[$Key], [ref]$number)) {
        return $null
    }

    return $number
}

function Invoke-Audit {
    <#
    .SYNOPSIS
        Performs read-only local password and lockout policy checks.

    .OUTPUTS
        System.Management.Automation.PSCustomObject
    #>
    [CmdletBinding()]
    [OutputType([System.Management.Automation.PSCustomObject])]
    param ()

    try {
        $policy = Get-LocalSystemAccessPolicy
    }
    catch {
        $message = $_.Exception.Message
        foreach ($check in @(
            @{ ID = 'PASS-001'; Title = 'Minimum Password Length' },
            @{ ID = 'PASS-002'; Title = 'Maximum Password Age' },
            @{ ID = 'PASS-003'; Title = 'Minimum Password Age' },
            @{ ID = 'PASS-004'; Title = 'Password Complexity' },
            @{ ID = 'PASS-005'; Title = 'Password History' },
            @{ ID = 'PASS-006'; Title = 'Lockout Threshold' },
            @{ ID = 'PASS-007'; Title = 'Lockout Duration' },
            @{ ID = 'PASS-008'; Title = 'Reset Lockout Counter' }
        )) {
            New-PasswordPolicyResult -ControlID $check.ID -Title $check.Title -Expected 'Local security policy value is available for assessment.' -Actual 'Unavailable' -Status WARNING -Severity High -Evidence $message -Remediation 'Verify access to the local security policy and rerun the audit.'
        }
        return
    }

    $minimumPasswordLength = Get-PolicyInteger -Policy $policy -Key 'MinimumPasswordLength'
    New-PasswordPolicyResult -ControlID 'PASS-001' -Title 'Minimum Password Length' -Expected '14 or more characters' -Actual $(if ($null -eq $minimumPasswordLength) { 'Unavailable' } else { "$minimumPasswordLength characters" }) -Status $(if ($null -eq $minimumPasswordLength) { 'WARNING' } elseif ($minimumPasswordLength -ge 14) { 'PASS' } else { 'FAIL' }) -Severity High -Evidence ('System Access\MinimumPasswordLength = {0}.' -f $(if ($null -eq $minimumPasswordLength) { '<unavailable>' } else { $minimumPasswordLength })) -Remediation 'Set the minimum password length to at least 14 characters.'

    $maximumPasswordAge = Get-PolicyInteger -Policy $policy -Key 'MaximumPasswordAge'
    New-PasswordPolicyResult -ControlID 'PASS-002' -Title 'Maximum Password Age' -Expected '1 to 365 days' -Actual $(if ($null -eq $maximumPasswordAge) { 'Unavailable' } elseif ($maximumPasswordAge -eq 0) { 'Never expires (0 days)' } else { "$maximumPasswordAge days" }) -Status $(if ($null -eq $maximumPasswordAge) { 'WARNING' } elseif ($maximumPasswordAge -ge 1 -and $maximumPasswordAge -le 365) { 'PASS' } else { 'FAIL' }) -Severity Medium -Evidence ('System Access\MaximumPasswordAge = {0}.' -f $(if ($null -eq $maximumPasswordAge) { '<unavailable>' } else { $maximumPasswordAge })) -Remediation 'Set the maximum password age to 365 days or fewer, and do not configure passwords to never expire.'

    $minimumPasswordAge = Get-PolicyInteger -Policy $policy -Key 'MinimumPasswordAge'
    New-PasswordPolicyResult -ControlID 'PASS-003' -Title 'Minimum Password Age' -Expected '1 or more days' -Actual $(if ($null -eq $minimumPasswordAge) { 'Unavailable' } else { "$minimumPasswordAge days" }) -Status $(if ($null -eq $minimumPasswordAge) { 'WARNING' } elseif ($minimumPasswordAge -ge 1) { 'PASS' } else { 'FAIL' }) -Severity Medium -Evidence ('System Access\MinimumPasswordAge = {0}.' -f $(if ($null -eq $minimumPasswordAge) { '<unavailable>' } else { $minimumPasswordAge })) -Remediation 'Set the minimum password age to at least 1 day.'

    $passwordComplexity = Get-PolicyInteger -Policy $policy -Key 'PasswordComplexity'
    New-PasswordPolicyResult -ControlID 'PASS-004' -Title 'Password Complexity' -Expected 'Enabled' -Actual $(if ($null -eq $passwordComplexity) { 'Unavailable' } elseif ($passwordComplexity -eq 1) { 'Enabled' } else { 'Disabled' }) -Status $(if ($null -eq $passwordComplexity) { 'WARNING' } elseif ($passwordComplexity -eq 1) { 'PASS' } else { 'FAIL' }) -Severity High -Evidence ('System Access\PasswordComplexity = {0}.' -f $(if ($null -eq $passwordComplexity) { '<unavailable>' } else { $passwordComplexity })) -Remediation 'Enable the policy requiring passwords to meet complexity requirements.'

    $passwordHistory = Get-PolicyInteger -Policy $policy -Key 'PasswordHistorySize'
    New-PasswordPolicyResult -ControlID 'PASS-005' -Title 'Password History' -Expected '24 or more remembered passwords' -Actual $(if ($null -eq $passwordHistory) { 'Unavailable' } else { "$passwordHistory remembered passwords" }) -Status $(if ($null -eq $passwordHistory) { 'WARNING' } elseif ($passwordHistory -ge 24) { 'PASS' } else { 'FAIL' }) -Severity Medium -Evidence ('System Access\PasswordHistorySize = {0}.' -f $(if ($null -eq $passwordHistory) { '<unavailable>' } else { $passwordHistory })) -Remediation 'Set Enforce password history to at least 24 remembered passwords.'

    $lockoutThreshold = Get-PolicyInteger -Policy $policy -Key 'LockoutBadCount'
    New-PasswordPolicyResult -ControlID 'PASS-006' -Title 'Lockout Threshold' -Expected '1 to 10 invalid logon attempts' -Actual $(if ($null -eq $lockoutThreshold) { 'Unavailable' } elseif ($lockoutThreshold -eq 0) { 'Disabled (0 attempts)' } else { "$lockoutThreshold invalid attempts" }) -Status $(if ($null -eq $lockoutThreshold) { 'WARNING' } elseif ($lockoutThreshold -ge 1 -and $lockoutThreshold -le 10) { 'PASS' } else { 'FAIL' }) -Severity High -Evidence ('System Access\LockoutBadCount = {0}.' -f $(if ($null -eq $lockoutThreshold) { '<unavailable>' } else { $lockoutThreshold })) -Remediation 'Set the account lockout threshold to 10 or fewer invalid logon attempts, and do not disable lockout.'

    $lockoutDuration = Get-PolicyInteger -Policy $policy -Key 'LockoutDuration'
    New-PasswordPolicyResult -ControlID 'PASS-007' -Title 'Lockout Duration' -Expected '15 or more minutes' -Actual $(if ($null -eq $lockoutDuration) { 'Unavailable' } elseif ($lockoutDuration -eq 0) { 'Administrator unlock required (0 minutes)' } else { "$lockoutDuration minutes" }) -Status $(if ($null -eq $lockoutDuration) { 'WARNING' } elseif ($lockoutDuration -ge 15) { 'PASS' } else { 'FAIL' }) -Severity Medium -Evidence ('System Access\LockoutDuration = {0}.' -f $(if ($null -eq $lockoutDuration) { '<unavailable>' } else { $lockoutDuration })) -Remediation 'Set the account lockout duration to at least 15 minutes.'

    $resetLockoutCounter = Get-PolicyInteger -Policy $policy -Key 'ResetLockoutCount'
    New-PasswordPolicyResult -ControlID 'PASS-008' -Title 'Reset Lockout Counter' -Expected '15 or more minutes' -Actual $(if ($null -eq $resetLockoutCounter) { 'Unavailable' } else { "$resetLockoutCounter minutes" }) -Status $(if ($null -eq $resetLockoutCounter) { 'WARNING' } elseif ($resetLockoutCounter -ge 15) { 'PASS' } else { 'FAIL' }) -Severity Medium -Evidence ('System Access\ResetLockoutCount = {0}.' -f $(if ($null -eq $resetLockoutCounter) { '<unavailable>' } else { $resetLockoutCounter })) -Remediation 'Set the reset account lockout counter after interval to at least 15 minutes.'
}

Export-ModuleMember -Function Invoke-Audit
