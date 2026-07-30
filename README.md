# Windows CIS Configuration Assessment Framework

A read-only, modular PowerShell framework that detects the local Windows
release, join mode, and server role; selects a versioned CIS benchmark
definition; executes its automated controls; and creates HTML, Excel, CSV, and
JSON reports.

Benchmark values live in JSON, not PowerShell. Updating assessment content
therefore means replacing a definition and its catalog entry rather than
rewriting the audit engine.

## Included definitions

| Target and variant | CIS version | Automated checks |
|---|---:|---:|
| Windows 11 Enterprise | 5.1.0 | 533 |
| Windows 11 Stand-alone | 5.0.0 | 486 |
| Windows 10 Enterprise | 4.0.0 | 488 |
| Windows 10 Stand-alone | 4.0.0 | 448 |
| Windows 10 Enterprise Release 1703 (archive) | 1.3.0 | 406 inferred |
| Windows 8.1 Workstation (archive) | 2.4.0 | 365 inferred |
| Windows 8 (archive) | 1.0.0 | 327 |
| Windows 7 Workstation (archive) | 3.2.0 | 343 inferred |
| Windows XP (archive) | 3.1.0 | 156 |
| Windows Server 2025 | 2.1.0 | 426 |
| Windows Server 2022 | 5.1.0 | 406 |
| Windows Server 2022 Stand-alone | 2.0.0 | 340 |
| Windows Server 2022 STIG | 2.0.0 | 462 |
| Windows Server 2019 | 5.0.0 | 398 |
| Windows Server 2019 Stand-alone | 3.0.0 | 363 |
| Windows Server 2019 STIG | 3.0.0 | 450 |
| Windows Server 2016 | 4.0.0 | 420 |
| Windows Server 2016 STIG | 3.0.0 | 443 |
| Windows Server 2012 R2 (archive) | 3.0.0 | 361 |
| Windows Server 2008 non-R2 (archive) | 3.3.0 | 316 |
| Windows Server 2003 (archive) | 3.1.0 | 119 |
| Microsoft Defender Antivirus supplemental benchmark | 1.0.0 | 59 |

The 22 definitions contain 8,115 automated checks in total. The modern and
imported PDFs explicitly label Automated/Manual recommendations; generated
counts match those labels exactly. The Windows 7, Windows 8.1, and Windows 10
1703 PDFs use older Scored/Not Scored terminology. For those three files, the
framework includes every recommendation with a deterministic registry, policy,
account, audit, or installed-product test. Organization-defined assignments
without a prescribed expected value are listed in
`Benchmarks/generation-unresolved.json` and are not assigned invented values.

The requested Windows 11 Enterprise v3.0.0 PDF was not supplied. The framework
uses the attached v5.1.0 PDF. A validated v3.0.0 JSON can be added without an
engine change.

## Requirements and archived-runtime limits

- Windows PowerShell 5.1 or PowerShell 7; PowerShell 7 is preferred.
- Administrator elevation is strongly recommended.
- `secedit.exe` and `auditpol.exe` are required for policy controls.

Local execution is supported where PowerShell 5.1 or 7 is available: Windows 7
SP1, Windows 8.1, Windows 10, Windows 11, and Windows Server 2012 R2 through
Server 2025. Definitions are included for XP, Windows 8, Server 2003, and
Server 2008 non-R2 because their PDFs were supplied, but those operating systems
cannot host this PowerShell 5.1 framework. They remain usable as versioned
definition/reference artifacts.

Unreadable evidence returns `WARNING`; the framework never silently converts
access-denied or provider errors into configuration failures.

## Quick start

Run from an elevated PowerShell window:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass `
  -File .\Invoke-CISAudit.ps1 `
  -OutputPath C:\Reports
```

The timestamped output folder contains HTML, XLSX, CSV, JSON, and log files.
When `-OutputPath` is omitted, the script prompts and defaults to `C:\Reports`.

List the complete catalog:

```powershell
.\Invoke-CISAudit.ps1 -ListBenchmarks
```

Run the applicable STIG variant:

```powershell
.\Invoke-CISAudit.ps1 -BenchmarkVariant STIG -OutputPath C:\Reports
```

Add the Defender Antivirus benchmark to the OS assessment:

```powershell
.\Invoke-CISAudit.ps1 -IncludeDefenderBenchmark -OutputPath C:\Reports
```

Use an explicit definition:

```powershell
.\Invoke-CISAudit.ps1 `
  -BenchmarkPath .\Benchmarks\CIS_Server2022_Standalone_2.0.0.json `
  -OutputPath C:\Reports
```

## Automatic selection

The platform module uses product type and build number to distinguish:

- Windows 11: build 22000 or newer
- Windows 10: builds 10240-21999
- Windows 8.1: build 9600
- Windows 8: build 9200
- Windows 7: builds 7600-7601
- Server 2025: builds 26100-29999
- Server 2022: build 20348
- Server 2019: build 17763
- Server 2016: build 14393
- Server 2012 R2: build 9600 with server product type
- Server 2008 non-R2: builds 6000-6002

`-BenchmarkVariant Auto` applies these rules:

- Active Directory or Entra-joined workstation: `Enterprise`
- Workgroup workstation: `Standalone`, falling back to `General` for archived
  benchmarks without separate variants
- Domain Controller or domain Member Server: `Standard`
- Workgroup server: `Standalone`
- STIG: explicit `-BenchmarkVariant STIG`

Controls labeled DC-only or MS-only in a shared server benchmark are preserved
and reported as `NOT APPLICABLE` on the other role.

## Results and reports

Statuses are `PASS`, `FAIL`, `WARNING`, and `NOT APPLICABLE`. Compliance is
calculated as `PASS / (PASS + FAIL)`; warnings and not-applicable findings are
reported separately.

Every finding contains the control ID/title, category, severity, CIS profile,
expected and actual values, evidence, remediation, benchmark name/version/file,
timestamp, computer, and audit user. When Defender is included, HTML, Excel,
and JSON list both selected benchmark versions; CSV includes benchmark identity
on every row.

## Architecture

```text
windows-security-audit/
|-- Invoke-CISAudit.ps1
|-- Configuration.json
|-- Benchmarks/
|   |-- BenchmarkCatalog.json
|   |-- CIS_Windows11_5.1.0.json
|   |-- CIS_Server2025_2.1.0.json
|   `-- ...
|-- Modules/
|   |-- Platform.psm1
|   |-- BenchmarkEngine.psm1
|   |-- Result.psm1
|   `-- ReportGenerator.psm1
|-- Tools/
|   `-- Build-BenchmarkDefinitions.py
`-- docs/
    |-- BenchmarkDefinitionSchema.md
    `-- Modules.md
```

Legacy topic modules remain for compatibility and reference, but the entry
point executes only definition-driven controls so advisory checks cannot alter
the CIS compliance score.

## Updating definitions

1. Add or replace the versioned JSON definition.
2. Ensure `Variant`, product type, and build range are correct.
3. Include every automated recommendation and set the exact
   `AutomatedControlCount`.
4. Run `-ListBenchmarks`, then validate and test the selected definition.

The catalog stores SHA-256 hashes. If a JSON file is added or replaced without
updating the catalog, the framework detects the mismatch and discovers metadata
directly from the definitions, so no PowerShell change is required. Rebuilding
the catalog with the maintainer generator restores the faster indexed startup
path.

The engine rejects missing fields, duplicate IDs, unsupported providers, and
declared-count mismatches before evidence collection. See
[`docs/BenchmarkDefinitionSchema.md`](docs/BenchmarkDefinitionSchema.md).

All providers are read-only. This framework supports configuration assessment
and evidence collection; it does not constitute CIS certification or replace
organizational risk analysis.
