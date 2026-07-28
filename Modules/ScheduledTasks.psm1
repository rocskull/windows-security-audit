<#
.SYNOPSIS
    Audits local scheduled tasks and potentially unsafe task execution.

.DESCRIPTION
    Enumerates scheduled tasks through the built-in ScheduledTasks module. It
    reads task XML only to collect metadata and does not create, modify, run,
    disable, or delete any task. Results are emitted exclusively as
    New-CISResult objects.
#>

Set-StrictMode -Version Latest
Import-Module (Join-Path $PSScriptRoot 'Result.psm1') -Force -ErrorAction Stop
Import-Module (Join-Path $PSScriptRoot 'Common.psm1') -Force -ErrorAction Stop

function New-ScheduledTaskResult {
    param(
        [string]$ControlID,[string]$Title,[string]$Expected,[string]$Actual,
        [ValidateSet('PASS','FAIL','WARNING','NOT APPLICABLE')][string]$Status,
        [ValidateSet('Critical','High','Medium','Low','Informational')][string]$Severity,
        [string]$Evidence,[string]$Remediation
    )
    New-CISResult -ControlID $ControlID -Category 'Scheduled Tasks' -SubCategory 'Task Configuration' -Title $Title -Expected $Expected -Actual $Actual -Status $Status -Severity $Severity -Evidence $Evidence -Remediation $Remediation -Reference 'Windows Task Scheduler security review'
}

function ConvertTo-TaskText {
    param([object]$Value)
    if ($null -eq $Value) { return '<none>' }
    $text = [string]$Value
    if ([string]::IsNullOrWhiteSpace($text)) { return '<none>' }
    return $text
}

function Get-TaskDetails {
    param([Parameter(Mandatory = $true)][object]$Task)

    $xml = $null
    try {
        $taskXml = Export-ScheduledTask -TaskName $Task.TaskName -TaskPath $Task.TaskPath -ErrorAction Stop
        $xml = [xml]($taskXml -join [Environment]::NewLine)
    }
    catch {
        # Get-ScheduledTask still exposes most useful detail when XML access is
        # restricted (for example, for an operating-system task).
    }

    $author = '<unavailable>'
    $principal = '<unavailable>'
    $runAsUser = '<unavailable>'
    $hidden = $false
    $triggerText = '<unavailable>'
    $actionText = '<unavailable>'
    $executePaths = @()
    $arguments = @()

    if ($null -ne $xml -and $null -ne $xml.Task) {
        $author = ConvertTo-TaskText $xml.Task.RegistrationInfo.Author
        $principalNode = $xml.Task.Principals.Principal | Select-Object -First 1
        if ($null -ne $principalNode) {
            $runAsUser = ConvertTo-TaskText $(if ($principalNode.UserId) { $principalNode.UserId } else { $principalNode.GroupId })
            $principal = 'UserOrGroup={0}; RunLevel={1}; LogonType={2}' -f $runAsUser,(ConvertTo-TaskText $principalNode.RunLevel),(ConvertTo-TaskText $principalNode.LogonType)
        }
        $hidden = [string]$xml.Task.Settings.Hidden -eq 'true'
        $triggers = @($xml.Task.Triggers.ChildNodes | Where-Object { $_.NodeType -eq [System.Xml.XmlNodeType]::Element })
        if ($triggers.Count -gt 0) {
            $triggerText = @($triggers | ForEach-Object { '{0}: Start={1}; Enabled={2}' -f $_.LocalName,(ConvertTo-TaskText $_.StartBoundary),(ConvertTo-TaskText $_.Enabled) }) -join ' | '
        }
        $actions = @($xml.Task.Actions.ChildNodes | Where-Object { $_.NodeType -eq [System.Xml.XmlNodeType]::Element })
        if ($actions.Count -gt 0) {
            $actionText = @($actions | ForEach-Object {
                if ($_.LocalName -eq 'Exec') {
                    $command = ConvertTo-TaskText $_.Command
                    $args = ConvertTo-TaskText $_.Arguments
                    $executePaths += $command
                    $arguments += $args
                    'Exec: Command={0}; Arguments={1}; WorkingDirectory={2}' -f $command,$args,(ConvertTo-TaskText $_.WorkingDirectory)
                }
                else {
                    '{0}: {1}' -f $_.LocalName,$_.InnerText
                }
            }) -join ' | '
        }
    }
    else {
        $runAsUser = ConvertTo-TaskText $Task.Principal.UserId
        $principal = 'UserOrGroup={0}; RunLevel={1}; LogonType={2}' -f $runAsUser,(ConvertTo-TaskText $Task.Principal.RunLevel),(ConvertTo-TaskText $Task.Principal.LogonType)
        $hidden = [bool]$Task.Settings.Hidden
        $triggerText = @($Task.Triggers | ForEach-Object { $_.ToString() }) -join ' | '
        $actionText = @($Task.Actions | ForEach-Object {
            $command = ConvertTo-TaskText $_.Execute
            $args = ConvertTo-TaskText $_.Arguments
            $executePaths += $command
            $arguments += $args
            'Exec: Command={0}; Arguments={1}' -f $command,$args
        }) -join ' | '
    }

    [pscustomobject]@{
        TaskName     = ConvertTo-TaskText $Task.TaskName
        TaskPath     = ConvertTo-TaskText $Task.TaskPath
        Author       = $author
        State        = ConvertTo-TaskText $Task.State
        Principal    = $principal
        RunAsUser    = $runAsUser
        Trigger      = $triggerText
        Action       = $actionText
        ExecutePaths = @($executePaths)
        Arguments    = @($arguments)
        Hidden       = $hidden
        XmlAvailable = ($null -ne $xml)
    }
}

function Test-TaskPathInWritableLocation {
    param([string]$Text)
    $expanded = [Environment]::ExpandEnvironmentVariables($Text)
    return $expanded -match '(?i)(^|[\\/])(?:temp|tmp|appdata|localappdata)(?:[\\/]|$)'
}

function Test-TaskScriptInvocation {
    param([string]$ExecutePath,[string]$Arguments)
    $combined = '{0} {1}' -f $ExecutePath,$Arguments
    return $combined -match '(?i)(\.ps1|\.psm1|\.bat|\.cmd|\.vbs|\.js|\.wsf)(?=(\s|"|''|$))'
}

function Get-TaskSignatureStatus {
    param([string]$ExecutePath)
    $expandedPath = [Environment]::ExpandEnvironmentVariables($ExecutePath.Trim('"'))
    if ($expandedPath -notmatch '(?i)\.exe$' -or -not (Test-Path -LiteralPath $expandedPath -PathType Leaf)) {
        return $null
    }
    try { return (Get-AuthenticodeSignature -LiteralPath $expandedPath -ErrorAction Stop).Status.ToString() }
    catch { return 'Unknown' }
}

function Invoke-Audit {
    [CmdletBinding()]
    [OutputType([System.Management.Automation.PSCustomObject])]
    param()

    try { $tasks = @(Get-ScheduledTask -ErrorAction Stop) }
    catch {
        New-ScheduledTaskResult -ControlID 'TASK-001' -Title 'Scheduled Task Inventory' -Expected 'Scheduled tasks can be enumerated.' -Actual 'Unavailable' -Status WARNING -Severity High -Evidence $_.Exception.Message -Remediation 'Verify the ScheduledTasks module and required read permissions.'
        return
    }

    foreach ($task in $tasks) {
        $details = Get-TaskDetails -Task $task
        $taskIdentity = '{0}{1}' -f $details.TaskPath,$details.TaskName
        $evidence = 'Task Name: {0}; Task Path: {1}; Author: {2}; State: {3}; Principal: {4}; Run As User: {5}; Trigger: {6}; Action: {7}; Execute Path: {8}; Command Line Arguments: {9}; Hidden: {10}; XML Available: {11}.' -f $details.TaskName,$details.TaskPath,$details.Author,$details.State,$details.Principal,$details.RunAsUser,$details.Trigger,$details.Action,($details.ExecutePaths -join ' | '),($details.Arguments -join ' | '),$details.Hidden,$details.XmlAvailable
        New-ScheduledTaskResult -ControlID 'TASK-001' -Title 'Scheduled Task Inventory' -Expected 'Task configuration is inventoried and reviewed.' -Actual $taskIdentity -Status PASS -Severity Informational -Evidence $evidence -Remediation 'Review the task owner, principal, trigger, and action; remove tasks that are no longer authorized.'

        $runsAsSystem = $details.RunAsUser -match '(?i)(^SYSTEM$|S-1-5-18|NT AUTHORITY\\SYSTEM)'
        $runsAsAdministrator = $details.RunAsUser -match '(?i)(administrator|S-1-5-32-544)' -or $details.Principal -match '(?i)RunLevel=HighestAvailable'
        $runsPowerShell = @($details.ExecutePaths + $details.Arguments | Where-Object { $_ -match '(?i)(powershell|pwsh)(\.exe)?' }).Count -gt 0
        $runsCmd = @($details.ExecutePaths + $details.Arguments | Where-Object { $_ -match '(?i)(^|[\\/])cmd(\.exe)?(\s|$)' }).Count -gt 0
        $runsWScript = @($details.ExecutePaths + $details.Arguments | Where-Object { $_ -match '(?i)(^|[\\/])wscript(\.exe)?(\s|$)' }).Count -gt 0
        $runsCScript = @($details.ExecutePaths + $details.Arguments | Where-Object { $_ -match '(?i)(^|[\\/])cscript(\.exe)?(\s|$)' }).Count -gt 0
        $writableExecution = @($details.ExecutePaths + $details.Arguments | Where-Object { Test-TaskPathInWritableLocation ([string]$_) }).Count -gt 0
        $scriptFromWritableLocation = $writableExecution -and @($details.ExecutePaths | ForEach-Object { Test-TaskScriptInvocation $_ ($details.Arguments -join ' ') } | Where-Object { $_ }).Count -gt 0

        if ($runsAsSystem) { New-ScheduledTaskResult -ControlID 'TASK-002' -Title 'Task Runs as SYSTEM' -Expected 'SYSTEM task is authorized and does not run untrusted content.' -Actual $taskIdentity -Status WARNING -Severity Low -Evidence $evidence -Remediation 'Validate the business purpose and execution paths of the SYSTEM task.' }
        if ($runsAsAdministrator) { New-ScheduledTaskResult -ControlID 'TASK-003' -Title 'Task Runs as Administrator' -Expected 'Elevated task is authorized and uses least privilege.' -Actual $taskIdentity -Status WARNING -Severity Low -Evidence $evidence -Remediation 'Validate the elevated task and use a lower-privileged principal where possible.' }
        if ($runsPowerShell) { New-ScheduledTaskResult -ControlID 'TASK-004' -Title 'Task Executes PowerShell' -Expected 'PowerShell task execution is authorized and constrained.' -Actual $taskIdentity -Status WARNING -Severity Medium -Evidence $evidence -Remediation 'Review the PowerShell command, script source, signing, and execution-policy controls.' }
        if ($runsCmd) { New-ScheduledTaskResult -ControlID 'TASK-005' -Title 'Task Executes CMD' -Expected 'CMD task execution is authorized.' -Actual $taskIdentity -Status WARNING -Severity Low -Evidence $evidence -Remediation 'Review the command interpreter invocation and referenced scripts.' }
        if ($runsWScript) { New-ScheduledTaskResult -ControlID 'TASK-006' -Title 'Task Executes WScript' -Expected 'WScript task execution is authorized.' -Actual $taskIdentity -Status WARNING -Severity Low -Evidence $evidence -Remediation 'Review the script host invocation and referenced script.' }
        if ($runsCScript) { New-ScheduledTaskResult -ControlID 'TASK-007' -Title 'Task Executes CScript' -Expected 'CScript task execution is authorized.' -Actual $taskIdentity -Status WARNING -Severity Low -Evidence $evidence -Remediation 'Review the script host invocation and referenced script.' }
        if ($writableExecution) { New-ScheduledTaskResult -ControlID 'TASK-008' -Title 'Task Executes from Temp or AppData' -Expected 'Task actions do not execute files from user-writable temporary or application-data locations.' -Actual $taskIdentity -Status WARNING -Severity Low -Evidence $evidence -Remediation 'Move the executable or script to a protected location and validate its integrity.' }
        if ($runsAsSystem -and $scriptFromWritableLocation) { New-ScheduledTaskResult -ControlID 'TASK-009' -Title 'SYSTEM Task Launching Script from Writable Location' -Expected 'SYSTEM tasks do not launch scripts from Temp or AppData.' -Actual $taskIdentity -Status FAIL -Severity Critical -Evidence $evidence -Remediation 'Immediately move the script to a protected location, validate its integrity, and review for compromise.' }
        foreach ($executePath in $details.ExecutePaths) {
            $signatureStatus = Get-TaskSignatureStatus -ExecutePath $executePath
            if ($signatureStatus -in @('NotSigned','HashMismatch','NotTrusted')) {
                New-ScheduledTaskResult -ControlID 'TASK-010' -Title 'Task Executes Unsigned Executable' -Expected 'Executable actions are signed and trusted.' -Actual ('{0}: {1}' -f $taskIdentity,$executePath) -Status WARNING -Severity Low -Evidence ('Signature status: {0}. {1}' -f $signatureStatus,$evidence) -Remediation 'Replace the executable with a signed, trusted version or document and monitor an approved exception.'
            }
        }
        if ($details.Hidden) { New-ScheduledTaskResult -ControlID 'TASK-011' -Title 'Hidden Scheduled Task' -Expected 'Scheduled tasks are visible unless a documented exception exists.' -Actual $taskIdentity -Status WARNING -Severity High -Evidence $evidence -Remediation 'Review the hidden task for authorization and make it visible unless a documented exception requires concealment.' }
    }
}

Export-ModuleMember -Function Invoke-Audit
