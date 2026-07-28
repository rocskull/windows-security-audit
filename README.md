# Windows Configuration Review Framework

A modular, read-only PowerShell framework for reviewing Windows security configuration. It gathers evidence, returns structured findings, and generates HTML, CSV, JSON, and Excel reports. It does not change Windows configuration.

This tool performs read-only Windows security checks aligned with CIS Benchmark guidance and provides remediation recommendations. It is intended to support security reviews and does not replace a formal CIS compliance assessment.

## Quick start

1. Open PowerShell in this project directory.
2. For the fullest set of checks, open PowerShell **as Administrator**.
3. Run:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Invoke-CISAudit.ps1
```

Reports and execution logs are written to the selected timestamped run folder. The execution-policy bypass is scoped to this one process; it does not change the device execution policy.

## Choosing an output folder

At the start of an interactive audit, enter an output directory when prompted:

```text
Enter output directory (Press Enter for default C:\Reports):
```

Press Enter to use `C:\Reports`, or enter another absolute or relative path. The framework validates and creates the selected base folder when necessary. It then creates one timestamped subfolder, for example `C:\Reports\2026-07-28_221530`, and writes the HTML, CSV, JSON, Excel reports and audit log there.

The full run folder is displayed before checks begin. If the path is invalid or cannot be created, the framework explains the error and prompts again.

To avoid the prompt, pass `-OutputPath`. It accepts local paths, UNC paths, and relative paths:

```powershell
.\Invoke-CISAudit.ps1 -OutputPath 'D:\Client Reviews'
.\Invoke-CISAudit.ps1 -O 'D:\Client Reviews'
.\Invoke-CISAudit.ps1 -OutputPath '\\Server01\Audits'
.\Invoke-CISAudit.ps1 -OutputPath '.\Reports'
```

When `-OutputPath` (or its short alias `-O`) is omitted, the script prompts for a location and uses `C:\Reports` when Enter is pressed.

To list discovered modules without running them:

```powershell
.\Invoke-CISAudit.ps1 -ListModules
```

To use another configuration file:

```powershell
.\Invoke-CISAudit.ps1 -ConfigurationFile .\Configuration.json
```

## Execution modes and result status

The report records whether the audit ran as a Standard User or Administrator, as well as hostname, domain, Windows version, PowerShell version, and execution policy.

- `PASS` — the control meets its expectation.
- `FAIL` — the control does not meet its expectation.
- `WARNING` — an advisory, incomplete assessment, or a setting requiring review.
- `NOT APPLICABLE` — the feature is not installed or does not apply to this device.
- `NOT EXECUTED` — the check could not run, for example because elevation is required.

Run as Administrator to avoid permission-related `WARNING` or `NOT EXECUTED` results for BitLocker, audit policy, security policy, service, and protected event-log checks.

## Features

- Modular architecture using PowerShell modules
- Audit-only mode (no system changes)
- PASS / FAIL / WARNING / NOT APPLICABLE outcomes
- Export reports to HTML, CSV, JSON, and Excel
- Detailed logging and evidence collection
- Remediation recommendations
- Designed for PowerShell 5.1 and PowerShell 7 compatibility

## Project Structure

- `Invoke-CISAudit.ps1` - main entry point
- `Modules/` - future audit modules and shared framework components
- `Reports/` - generated report output (kept out of source control except its placeholder)
- `Logs/` - execution logs (kept out of source control except its placeholder)
- `Benchmarks/` - benchmark definitions and references
- `Configuration.json` - configuration and audit preferences

## Intended Result Contract

Future checks will return one of the following statuses:

- `PASS` — the configuration meets the benchmark requirement.
- `FAIL` — the configuration does not meet the benchmark requirement.
- `WARNING` — the result needs review or could not be conclusively assessed.
- `NOT APPLICABLE` — the requirement does not apply to the audited system.

Each result is intended to include benchmark metadata, severity, collected evidence, and an actionable remediation recommendation. Checks must remain read-only.

## Running the Scaffold

```powershell
.\Invoke-CISAudit.ps1
```

The command initializes framework logging and module discovery, but creates no
reports and performs no audit checks until audit modules are added.

## Module Contract

The core framework imports every `.psm1` file below `Modules/`. Audit modules
must define an `Invoke-Audit` function and return one or more `[pscustomobject]`
result objects. Support modules, such as `Result.psm1`, are imported but not
executed as checks. The framework records module errors and execution time,
then continues with the remaining modules. No audit modules are included in
this project yet.

## Registry Definition Format

`Modules/Registry.psm1` evaluates registry settings from JSON; it contains no
hardcoded controls. It automatically loads
`Benchmarks/RegistryChecks.json`. Each entry in its `Checks` array must include
`ControlID`, `Category`, `SubCategory`, `Title`, `RegistryHive`,
`RegistryPath`, `ValueName`, `Comparison`, `Expected`, `Severity`, `Reference`,
and `Remediation`. `RegistryPath` is relative to `RegistryHive`; for example,
use `HKLM` and `SOFTWARE\Example`. `Expected` is not used by the `Exists` and
`NotExists` comparisons.

## Next Steps

1. Add audit module definitions to `Modules/`
2. Implement configuration loading and report export logic in `Invoke-CISAudit.ps1`
3. Add read-only checks for Windows configuration items
