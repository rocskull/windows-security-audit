<#
.SYNOPSIS
    Audits local Windows startup-program persistence locations.

.DESCRIPTION
    Reads startup registry keys, startup folders, Winlogon values, and Explorer
    startup approval metadata. It does not create, modify, enable, disable, or
    execute startup entries. All findings are New-CISResult objects.
#>

Set-StrictMode -Version Latest
Import-Module (Join-Path $PSScriptRoot 'Result.psm1') -Force -ErrorAction Stop

function New-StartupResult {
    param(
        [string]$ControlID,[string]$Title,[string]$Expected,[string]$Actual,
        [ValidateSet('PASS','FAIL','WARNING','NOT APPLICABLE')][string]$Status,
        [ValidateSet('Critical','High','Medium','Low','Informational')][string]$Severity,
        [string]$Evidence,[string]$Remediation
    )
    New-CISResult -ControlID $ControlID -Category 'Startup Programs' -SubCategory 'Startup Persistence' -Title $Title -Expected $Expected -Actual $Actual -Status $Status -Severity $Severity -Evidence $Evidence -Remediation $Remediation -Reference 'Windows startup persistence security review'
}

function Get-RegistryStartupEntries {
    param([string]$Path,[string]$Source)
    try {
        $key = Get-Item -LiteralPath $Path -ErrorAction Stop
        foreach ($name in $key.GetValueNames()) {
            [pscustomobject]@{
                Source  = $Source
                Location = $Path
                Name    = if ([string]::IsNullOrEmpty($name)) { '(Default)' } else { $name }
                Command = [string]$key.GetValue($name, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
            }
        }
    }
    catch { }
}

function Get-ShortcutCommand {
    param([string]$Path)
    if ($Path -notmatch '(?i)\.lnk$') { return $Path }
    try {
        $shell = New-Object -ComObject WScript.Shell
        $shortcut = $shell.CreateShortcut($Path)
        $command = ('"{0}" {1}' -f $shortcut.TargetPath,$shortcut.Arguments).Trim()
        [void][Runtime.InteropServices.Marshal]::ReleaseComObject($shortcut)
        [void][Runtime.InteropServices.Marshal]::ReleaseComObject($shell)
        return $command
    }
    catch { return $Path }
}

function Get-StartupFolderEntries {
    param([string]$Path,[string]$Source)
    if (-not (Test-Path -LiteralPath $Path -PathType Container)) { return }
    try {
        foreach ($item in @(Get-ChildItem -LiteralPath $Path -Force -File -ErrorAction Stop)) {
            [pscustomobject]@{
                Source   = $Source
                Location = $Path
                Name     = $item.Name
                Command  = Get-ShortcutCommand -Path $item.FullName
            }
        }
    }
    catch { }
}

function Get-ExecutablePath {
    param([string]$Command)
    $expanded = [Environment]::ExpandEnvironmentVariables($Command).Trim()
    if ($expanded -match '^\s*"(?<Path>[^"]+\.exe)"') { return $matches['Path'] }
    if ($expanded -match '^\s*(?<Path>[^\s]+\.exe)(?=\s|$)') { return $matches['Path'] }
    return $null
}

function Get-StartupSignatureStatus {
    param([string]$Command)
    $executable = Get-ExecutablePath -Command $Command
    if ([string]::IsNullOrWhiteSpace($executable) -or -not (Test-Path -LiteralPath $executable -PathType Leaf)) { return $null }
    try { return (Get-AuthenticodeSignature -LiteralPath $executable -ErrorAction Stop).Status.ToString() }
    catch { return 'Unknown' }
}

function Test-StartupPattern {
    param([string]$Command,[ValidateSet('Temp','AppData','Downloads','Network','PowerShell','CMD')]$Type)
    $expanded = [Environment]::ExpandEnvironmentVariables($Command)
    switch ($Type) {
        'Temp'       { return $expanded -match '(?i)(^|[\\/])(?:temp|tmp)(?:[\\/]|$)' }
        'AppData'    { return $expanded -match '(?i)(^|[\\/])(?:appdata|localappdata)(?:[\\/]|$)' }
        'Downloads'  { return $expanded -match '(?i)(^|[\\/])downloads(?:[\\/]|$)' }
        'Network'    { return $expanded -match '(?i)^\s*\\\\|(^|\s)(?:https?|ftp)://' }
        'PowerShell' { return $expanded -match '(?i)(powershell|pwsh)(\.exe)?' }
        'CMD'        { return $expanded -match '(?i)(^|[\\/])cmd(\.exe)?(\s|$)' }
    }
}

function Add-StartupRiskFindings {
    param([Parameter(Mandatory = $true)][psobject]$Entry,[Parameter(Mandatory = $true)][string]$Evidence)
    $identity = '{0}: {1}' -f $Entry.Source,$Entry.Name
    $riskChecks = @(
        @{ ID='START-010'; Title='Startup Entry Executes from Temp'; Type='Temp'; Severity='High'; Expected='Startup commands do not execute from temporary locations.'; Remediation='Move the file to a protected location and investigate its origin.' },
        @{ ID='START-011'; Title='Startup Entry Executes from AppData'; Type='AppData'; Severity='Medium'; Expected='Startup commands do not execute from AppData unless explicitly approved.'; Remediation='Validate the application, signature, and AppData persistence entry.' },
        @{ ID='START-012'; Title='Startup Entry Executes from Downloads'; Type='Downloads'; Severity='High'; Expected='Startup commands do not execute files from Downloads.'; Remediation='Remove the persistence entry and investigate the downloaded file.' },
        @{ ID='START-013'; Title='Startup Entry Executes from a Network Path'; Type='Network'; Severity='High'; Expected='Startup commands do not execute from network or URL paths.'; Remediation='Use a protected local, signed executable and review the remote source.' },
        @{ ID='START-014'; Title='Startup Entry Executes PowerShell'; Type='PowerShell'; Severity='Medium'; Expected='PowerShell startup execution is authorized and constrained.'; Remediation='Review the command, script source, signing, and PowerShell security controls.' },
        @{ ID='START-015'; Title='Startup Entry Executes CMD'; Type='CMD'; Severity='Low'; Expected='CMD startup execution is authorized.'; Remediation='Review the command interpreter invocation and referenced scripts.' }
    )
    foreach ($risk in $riskChecks) {
        if (Test-StartupPattern -Command $Entry.Command -Type $risk.Type) {
            New-StartupResult -ControlID $risk.ID -Title $risk.Title -Expected $risk.Expected -Actual $identity -Status WARNING -Severity $risk.Severity -Evidence $Evidence -Remediation $risk.Remediation
        }
    }
    $signatureStatus = Get-StartupSignatureStatus -Command $Entry.Command
    if ($signatureStatus -in @('NotSigned','HashMismatch','NotTrusted')) {
        New-StartupResult -ControlID 'START-009' -Title 'Startup Entry Executes Unsigned Executable' -Expected 'Startup executable is signed and trusted.' -Actual $identity -Status WARNING -Severity High -Evidence ('Signature status: {0}. {1}' -f $signatureStatus,$Evidence) -Remediation 'Replace the startup executable with a signed trusted version or document and monitor an approved exception.'
    }
}

function Invoke-Audit {
    [CmdletBinding()]
    [OutputType([System.Management.Automation.PSCustomObject])]
    param()

    $entries = @()
    $entries += @(Get-RegistryStartupEntries -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' -Source 'HKLM Run')
    $entries += @(Get-RegistryStartupEntries -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' -Source 'HKCU Run')
    $entries += @(Get-RegistryStartupEntries -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce' -Source 'HKLM RunOnce')
    $entries += @(Get-RegistryStartupEntries -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce' -Source 'HKCU RunOnce')
    $entries += @(Get-StartupFolderEntries -Path (Join-Path $env:APPDATA 'Microsoft\Windows\Start Menu\Programs\Startup') -Source 'Startup Folder')
    $entries += @(Get-StartupFolderEntries -Path (Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\StartUp') -Source 'Common Startup Folder')
    $entries += @(Get-RegistryStartupEntries -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Source 'Winlogon' | Where-Object { $_.Name -in @('Shell','Userinit') })
    $entries += @(Get-RegistryStartupEntries -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run' -Source 'Explorer Startup')
    $entries += @(Get-RegistryStartupEntries -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run32' -Source 'Explorer Startup')
    $entries += @(Get-RegistryStartupEntries -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run' -Source 'Explorer Startup')

    if ($entries.Count -eq 0) {
        New-StartupResult -ControlID 'START-001' -Title 'Startup Program Inventory' -Expected 'Startup locations are available for review.' -Actual 'No startup entries found or access was unavailable.' -Status WARNING -Severity Low -Evidence 'No registry or startup-folder entries were enumerated.' -Remediation 'Verify access to startup registry locations and startup folders.'
        return
    }

    foreach ($entry in $entries) {
        $controlId = switch ($entry.Source) {
            'HKLM Run'           { 'START-001' }
            'HKCU Run'           { 'START-002' }
            { $_ -like '*RunOnce' } { 'START-003' }
            'Startup Folder'     { 'START-004' }
            'Common Startup Folder' { 'START-005' }
            'Winlogon'           { if ($entry.Name -eq 'Shell') { 'START-006' } else { 'START-007' } }
            'Explorer Startup'   { 'START-008' }
            default               { 'START-001' }
        }
        $evidence = 'Source: {0}; Location: {1}; Value or File Name: {2}; Command: {3}; Executable Path: {4}.' -f $entry.Source,$entry.Location,$entry.Name,$entry.Command,(Get-ExecutablePath -Command $entry.Command)
        New-StartupResult -ControlID $controlId -Title ('Startup Entry: {0}' -f $entry.Source) -Expected 'Startup entry is authorized and executes from a trusted location.' -Actual ('{0}: {1}' -f $entry.Name,$entry.Command) -Status PASS -Severity Informational -Evidence $evidence -Remediation 'Review the startup entry and remove it if it is not authorized.'
        Add-StartupRiskFindings -Entry $entry -Evidence $evidence
    }
}

Export-ModuleMember -Function Invoke-Audit
