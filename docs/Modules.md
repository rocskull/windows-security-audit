# Module reference

## Platform.psm1

`Get-WindowsPlatform`

Returns normalized operating-system, build, product type, architecture, and
domain information. It distinguishes workstation/server releases by build,
detects Active Directory and Entra join state, and normalizes server roles as
DomainController, MemberServer, or StandaloneServer.

`Get-CISBenchmarkCatalog`

Reads the compact `BenchmarkCatalog.json` index without executing checks. If
the index is unavailable or its SHA-256 hashes show that a definition changed,
it discovers metadata from versioned `CIS_*.json` files.

`Test-BenchmarkCompatibility`

Compares detected product type and build with benchmark platform metadata.

`Select-CISBenchmark`

Validates an explicit definition or selects the newest compatible semantic
version and variant. Auto selection distinguishes Enterprise/Standalone
workstations and Standard/Standalone servers; STIG is explicit.

`Select-CISSupplementalBenchmark`

Selects the newest installed supplemental definition, currently used for the
Microsoft Defender Antivirus benchmark.

## BenchmarkEngine.psm1

`Import-CISBenchmark`

Parses and validates a benchmark definition.

`Invoke-CISBenchmark`

Executes every control, displays progress, and returns one result per control.

`Invoke-CISControl`

Dispatches a control to its generic provider and converts provider output to
the standard result schema. Provider exceptions become `WARNING` findings so
the report retains a complete control inventory. Server-role mismatches become
`NOT APPLICABLE`.

`Test-CISValue`

Implements shared scalar, range, exact-set, and containment comparisons.

The module caches `secedit` and `auditpol` output once per assessment to avoid
running expensive system commands for each control.

Supported providers are Registry, RegistryAll, RegistryValueData,
SecurityPolicy, UserRight, AuditPolicy, BuiltinAccountName, and
InstalledProduct.

## Result.psm1

`New-CISResult`

Creates the ordered finding object used by every report. Valid statuses are
`PASS`, `FAIL`, `WARNING`, and `NOT APPLICABLE`.

## ReportGenerator.psm1

`Generate-HTMLReport`

Creates a responsive, self-contained HTML report with benchmark identity,
machine information, summary metrics, failed controls, category breakdown,
all findings, and remediation actions. Multiple selected benchmark versions
are listed when a supplemental definition is included.

`Generate-ExcelReport`

Creates a dependency-free Open XML workbook with Summary and Findings sheets,
column sizing, frozen headings, and filtering.

`Generate-CSVReport`

Exports one flat row per control, including benchmark and evidence metadata.

`Generate-JSONReport`

Exports benchmark identity, summary totals, category breakdown, critical
findings, and the complete result array. `Benchmarks` preserves all selected
versions while `Benchmark` retains the primary definition for compatibility.

## Legacy modules

Earlier releases included topic modules such as `Firewall.psm1` and
`Defender.psm1` with hard-coded advisory checks. They remain for compatibility
but are not imported by the v3 entry point. CIS-scored execution is exclusively
driven by the selected benchmark definition.

| Module | Legacy purpose |
|---|---|
| `Accounts.psm1` | Local account and local-group inventory |
| `ASRRules.psm1` | Defender Attack Surface Reduction review |
| `AuditPolicy.psm1` | Hard-coded advanced audit policy review |
| `BitLocker.psm1` | BitLocker volume review |
| `BrowserSecurity.psm1` | Browser enterprise-policy advisories |
| `Common.psm1` | Shared v1 helpers |
| `CredentialGuard.psm1` | Credential Guard prerequisites |
| `Defender.psm1` | Defender Antivirus posture |
| `DefenderForEndpoint.psm1` | Defender for Endpoint health |
| `DeviceGuard.psm1` | Device Guard and VBS posture |
| `EventLogs.psm1` | Event-log configuration |
| `ExploitProtection.psm1` | Process-mitigation advisories |
| `Firewall.psm1` | Firewall profile checks |
| `LSAProtection.psm1` | LSA protection checks |
| `PasswordPolicy.psm1` | Hard-coded password policy |
| `PowerShellSecurity.psm1` | PowerShell security advisories |
| `RDP.psm1` | Remote Desktop security |
| `Registry.psm1` | v1 registry-definition evaluator |
| `ScheduledTasks.psm1` | Scheduled-task persistence review |
| `SecurityAuditUtilities.psm1` | v1 result and registry helpers |
| `SecurityPolicy.psm1` | Hard-coded local security options |
| `Services.psm1` | Service-hardening advisories |
| `SmartScreen.psm1` | SmartScreen policy review |
| `SMB.psm1` | SMB configuration |
| `StartupPrograms.psm1` | Startup persistence review |
| `TLS.psm1` | Schannel protocol review |
| `WindowsUpdate.psm1` | Windows Update advisories |
| `WinRM.psm1` | Windows Remote Management advisories |
