# Benchmark definition schema

Benchmark definitions are versioned JSON documents stored separately from the
PowerShell engine. `Benchmarks/BenchmarkCatalog.json` is a compact metadata
index used during platform selection; the selected full definition is then
loaded and validated.

## Benchmark document

```json
{
  "SchemaVersion": "2.1",
  "Benchmark": {
    "Id": "CIS_Server2022",
    "Name": "CIS Microsoft Windows Server 2022 Benchmark",
    "Version": "5.1.0",
    "Variant": "Standard",
    "Platform": {
      "Product": "Windows Server 2022",
      "ProductType": "Server",
      "BuildMinimum": 20348,
      "BuildMaximum": 20348
    },
    "SourceDocument": "CIS_Microsoft_Windows_Server_2022_Benchmark_v5.1.0.pdf",
    "Archived": false,
    "Supplemental": false,
    "AutomationSelection": "CISAutomatedRecommendations",
    "AutomatedControlCount": 406
  },
  "Controls": []
}
```

Supported variants are `Enterprise`, `Standalone`, `Standard`, `STIG`,
`General`, and `Supplemental`. Build limits are inclusive. Supplemental
definitions are never selected as the operating-system benchmark.

`AutomationSelection` is `CISAutomatedRecommendations` when the source uses
Automated/Manual labels. Older source documents may use
`InferredMachineReadableAuditProcedure`; those controls also include an
`AutomationBasis` explanation.

## Control document

```json
{
  "Id": "2.2.5",
  "Title": "Ensure 'Add workstations to domain' is set to 'Administrators' (DC only)",
  "Category": "Local Policies",
  "SubCategory": "User Rights and Security Options",
  "Severity": "High",
  "Profile": "Level 1 (L1)",
  "Automated": true,
  "ExpectedValue": "Administrators",
  "AppliesToServerRoles": ["DomainController"],
  "Check": {
    "Type": "UserRight",
    "Key": "SeMachineAccountPrivilege",
    "Operator": "ExactSet",
    "Expected": ["Administrators"]
  },
  "Remediation": "Configure the CIS-prescribed Group Policy setting.",
  "Reference": "CIS Microsoft Windows Server 2022 Benchmark v5.1.0, control 2.2.5"
}
```

`AppliesToServerRoles` is optional. Valid values are `DomainController`,
`MemberServer`, and `StandaloneServer`. A role mismatch returns a complete
`NOT APPLICABLE` finding rather than suppressing the control.

Severity is assessment-prioritization metadata because Windows CIS profiles do
not assign conventional vulnerability severities to every recommendation.
Level 1 is mapped to High and Level 2-only to Medium.

## Comparison operators

Providers may use:

- `Equals` and `NotEquals`
- `GreaterThanOrEqual` and `LessThanOrEqual`
- `Between` with two inclusive bounds
- `In` with accepted scalar values
- `Empty`, `NotEmpty`, and `NotExists`
- `ContainsAll`
- `ExactSet`
- `EmptyOrContainsAll`
- `SubsetOf` for user-right assignments

## Check providers

### Registry

Reads one registry value.

```json
{
  "Type": "Registry",
  "Path": "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Personalization",
  "ValueName": "NoLockScreenCamera",
  "Operator": "Equals",
  "Expected": 1,
  "ValueType": "DWORD"
}
```

### RegistryAll

Contains a `Conditions` array of Registry condition objects. Every condition
must pass. A provider warning takes precedence over failure so unreadable
evidence is never represented as a configuration mismatch.

### RegistryValueData

Compares all data values below a key when Windows generates arbitrary numeric
value names for list policies.

```json
{
  "Type": "RegistryValueData",
  "Path": "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\DeviceInstall\\Restrictions\\DenyDeviceClasses",
  "Operator": "ContainsAll",
  "Expected": ["{d48179be-ec20-11d1-b6b8-00c04fa372a7}"]
}
```

### SecurityPolicy

Reads a key from the cached `secedit.exe` export.

```json
{
  "Type": "SecurityPolicy",
  "Section": "System Access",
  "Key": "MinimumPasswordLength",
  "Operator": "GreaterThanOrEqual",
  "Expected": 14
}
```

Legacy basic audit policy uses the same provider with section `Event Audit`.

### UserRight

Reads `Privilege Rights` from the `secedit.exe` export and normalizes
well-known names and SIDs.

```json
{
  "Type": "UserRight",
  "Key": "SeDebugPrivilege",
  "Operator": "ExactSet",
  "Expected": ["Administrators"]
}
```

### AuditPolicy

Reads an advanced audit subcategory through `auditpol.exe`.

```json
{
  "Type": "AuditPolicy",
  "Subcategory": "Logon",
  "Operator": "ContainsAll",
  "Expected": ["Success", "Failure"]
}
```

Use `ExactSet` when additional Success/Failure flags are not allowed.

### BuiltinAccountName

Finds a built-in local account by RID and compares its current name. RID 500 is
the built-in administrator and RID 501 the built-in guest.

### InstalledProduct

Reads the 32-bit and 64-bit uninstall registry inventories.

```json
{
  "Type": "InstalledProduct",
  "NamePattern": "^EMET",
  "MinimumVersion": "5.52"
}
```

## Catalog index

`BenchmarkCatalog.json` contains the same benchmark metadata plus `FileName`
and a SHA-256 hash. The index avoids parsing every full definition during
startup. If it is absent, invalid, or stale after a definition is replaced, the
platform module falls back to definition discovery. Replacing benchmark JSON
therefore never requires a PowerShell logic change.

## Validation

Before execution, the engine verifies:

- root schema, benchmark metadata, and controls are present;
- `AutomatedControlCount` equals the control array length;
- every control ID is unique;
- every included control is marked automated;
- required result/remediation fields exist; and
- every provider type is supported.

Invalid definitions stop before evidence collection and report generation.
