"""Build versioned CIS benchmark JSON definitions from extracted CIS PDF text.

This is a maintainer utility, not part of the runtime assessment path. It parses
recommendation metadata, reuses verified check mappings where titles are
unchanged, and derives registry/security-policy checks from each recommendation's
Audit section. Generated definitions are validated by the PowerShell runtime
before they can be selected.

The source documents remain authoritative. Review CIS licensing terms before
redistributing source text or generated derivative benchmark content.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable


MODERN_HEADER = re.compile(
    r"(?m)^(?P<id>\d+(?:\.\d+)+)\s+"
    r"(?:\((?:L1|L2|NG)\)\s+)?"
    r"(?P<title>(?:Ensure|Configure|Disable|Enable|Set|Turn off|Allow|Prohibit|"
    r"Audit|Prevent|Do not|Block|Specify|MSS:|Windows Firewall:)"
    r"[^\n]*(?:\n(?!Profile Applicability:)[^\n]*){0,6}?)\s+"
    r"\((?P<mode>Automated|Manual)\)\s*\n\s*Profile Applicability:",
    re.IGNORECASE,
)
LEGACY_HEADER = re.compile(
    r"(?m)^(?P<id>\d+(?:\.\d+)+)\s+"
    r"(?:\((?:L1|L2|NG)\)\s+)?"
    r"(?P<title>(?:Ensure|Configure|Disable|Enable|Set|Turn off|Allow|Prohibit|"
    r"Audit|Prevent|Do not|Block|Specify|MSS:|Windows Firewall:)"
    r"[^\n]*(?:\n(?!Profile Applicability:)[^\n]*){0,6}?)\s+"
    r"\((?P<mode>Scored|Not Scored)\)\s*\n\s*Profile Applicability:",
    re.IGNORECASE,
)
PAGE_MARKER = re.compile(r"\n\f?\n?=== PDF PAGE \d+ ===\n", re.IGNORECASE)
CHAR_TRANSLATION = str.maketrans(
    {
        "\ufffd": "'",
        "“": '"',
        "”": '"',
        "’": "'",
        "‘": "'",
        "\u00a0": " ",
    }
)
MOJIBAKE_REPLACEMENTS = {
    "â€™": "'",
    "â€œ": '"',
    "â€\u009d": '"',
    "â€¢": "-",
}


@dataclass(frozen=True)
class BenchmarkSpec:
    source: str
    output: str
    benchmark_id: str
    name: str
    version: str
    product: str
    product_type: str
    build_minimum: int | None
    build_maximum: int | None
    variant: str
    archived: bool = False
    supplemental: bool = False
    legacy_automation_inference: bool = False


SPECS = (
    BenchmarkSpec(
        "CIS_Microsoft_Defender_Antivirus_Benchmark_v1.0.0.txt",
        "CIS_Microsoft_Defender_Antivirus_1.0.0.json",
        "CIS_Microsoft_Defender_Antivirus",
        "CIS Microsoft Defender Antivirus Benchmark",
        "1.0.0",
        "Microsoft Defender Antivirus",
        "Supplemental",
        None,
        None,
        "Supplemental",
        supplemental=True,
    ),
    BenchmarkSpec(
        "CIS_Microsoft_Windows_10_Enterprise_Benchmark_v4.0.0.txt",
        "CIS_Windows10_4.0.0.json",
        "CIS_Windows10_Enterprise",
        "CIS Microsoft Windows 10 Enterprise Benchmark",
        "4.0.0",
        "Windows 10",
        "Workstation",
        10240,
        21999,
        "Enterprise",
    ),
    BenchmarkSpec(
        "CIS_Microsoft_Windows_10_Enterprise_Release_1703_Benchmark_v1.3.0.txt",
        "CIS_Windows10_Enterprise_1703_1.3.0.json",
        "CIS_Windows10_Enterprise_1703",
        "CIS Microsoft Windows 10 Enterprise Release 1703 Benchmark",
        "1.3.0",
        "Windows 10",
        "Workstation",
        15063,
        15063,
        "Enterprise",
        archived=True,
        legacy_automation_inference=True,
    ),
    BenchmarkSpec(
        "CIS_Microsoft_Windows_10_Stand-alone_Benchmark_v4.0.0.txt",
        "CIS_Windows10_Standalone_4.0.0.json",
        "CIS_Windows10_Standalone",
        "CIS Microsoft Windows 10 Stand-alone Benchmark",
        "4.0.0",
        "Windows 10",
        "Workstation",
        10240,
        21999,
        "Standalone",
    ),
    BenchmarkSpec(
        "CIS_Microsoft_Windows_11_Enterprise_Benchmark_v5.1.0.txt",
        "CIS_Windows11_5.1.0.json",
        "CIS_Windows11_Enterprise",
        "CIS Microsoft Windows 11 Enterprise Benchmark",
        "5.1.0",
        "Windows 11",
        "Workstation",
        22000,
        None,
        "Enterprise",
    ),
    BenchmarkSpec(
        "CIS_Microsoft_Windows_11_Stand-alone_Benchmark_v5.0.0.txt",
        "CIS_Windows11_Standalone_5.0.0.json",
        "CIS_Windows11_Standalone",
        "CIS Microsoft Windows 11 Stand-alone Benchmark",
        "5.0.0",
        "Windows 11",
        "Workstation",
        22000,
        None,
        "Standalone",
    ),
    BenchmarkSpec(
        "CIS_Microsoft_Windows_7_Workstation_Benchmark_v3.2.0_ARCHIVE.txt",
        "CIS_Windows7_Workstation_3.2.0_ARCHIVE.json",
        "CIS_Windows7_Workstation",
        "CIS Microsoft Windows 7 Workstation Benchmark",
        "3.2.0",
        "Windows 7",
        "Workstation",
        7600,
        7601,
        "General",
        archived=True,
        legacy_automation_inference=True,
    ),
    BenchmarkSpec(
        "CIS_Microsoft_Windows_8.1_Workstation_Benchmark_v2.4.0_ARCHIVE.txt",
        "CIS_Windows8.1_Workstation_2.4.0_ARCHIVE.json",
        "CIS_Windows8.1_Workstation",
        "CIS Microsoft Windows 8.1 Workstation Benchmark",
        "2.4.0",
        "Windows 8.1",
        "Workstation",
        9600,
        9600,
        "General",
        archived=True,
        legacy_automation_inference=True,
    ),
    BenchmarkSpec(
        "CIS_Microsoft_Windows_8_Benchmark__imported__v1.0.0_ARCHIVE.txt",
        "CIS_Windows8_1.0.0_ARCHIVE.json",
        "CIS_Windows8",
        "CIS Microsoft Windows 8 Benchmark",
        "1.0.0",
        "Windows 8",
        "Workstation",
        9200,
        9200,
        "General",
        archived=True,
    ),
    BenchmarkSpec(
        "CIS_Microsoft_Windows_Server_2003_Benchmark__imported__v3.1.0_ARCHIVE.txt",
        "CIS_Server2003_3.1.0_ARCHIVE.json",
        "CIS_Server2003",
        "CIS Microsoft Windows Server 2003 Benchmark",
        "3.1.0",
        "Windows Server 2003",
        "Server",
        3790,
        3790,
        "Standard",
        archived=True,
    ),
    BenchmarkSpec(
        "CIS_Microsoft_Windows_Server_2008_(non-R2)_Benchmark_v3.3.0_ARCHIVE.txt",
        "CIS_Server2008_3.3.0_ARCHIVE.json",
        "CIS_Server2008",
        "CIS Microsoft Windows Server 2008 (non-R2) Benchmark",
        "3.3.0",
        "Windows Server 2008",
        "Server",
        6000,
        6002,
        "Standard",
        archived=True,
    ),
    BenchmarkSpec(
        "CIS_Microsoft_Windows_Server_2012_R2_Benchmark_v3.0.0_ARCHIVE.txt",
        "CIS_Server2012R2_3.0.0_ARCHIVE.json",
        "CIS_Server2012R2",
        "CIS Microsoft Windows Server 2012 R2 Benchmark",
        "3.0.0",
        "Windows Server 2012 R2",
        "Server",
        9600,
        9600,
        "Standard",
        archived=True,
    ),
    BenchmarkSpec(
        "CIS_Microsoft_Windows_Server_2016_Benchmark_v4.0.0.txt",
        "CIS_Server2016_4.0.0.json",
        "CIS_Server2016",
        "CIS Microsoft Windows Server 2016 Benchmark",
        "4.0.0",
        "Windows Server 2016",
        "Server",
        14393,
        14393,
        "Standard",
    ),
    BenchmarkSpec(
        "CIS_Microsoft_Windows_Server_2016_STIG_Benchmark_v3.0.0.txt",
        "CIS_Server2016_STIG_3.0.0.json",
        "CIS_Server2016_STIG",
        "CIS Microsoft Windows Server 2016 STIG Benchmark",
        "3.0.0",
        "Windows Server 2016",
        "Server",
        14393,
        14393,
        "STIG",
    ),
    BenchmarkSpec(
        "CIS_Microsoft_Windows_Server_2019_Benchmark_v5.0.0.txt",
        "CIS_Server2019_5.0.0.json",
        "CIS_Server2019",
        "CIS Microsoft Windows Server 2019 Benchmark",
        "5.0.0",
        "Windows Server 2019",
        "Server",
        17763,
        17763,
        "Standard",
    ),
    BenchmarkSpec(
        "CIS_Microsoft_Windows_Server_2019_Stand-alone_v3.0.0.txt",
        "CIS_Server2019_Standalone_3.0.0.json",
        "CIS_Server2019_Standalone",
        "CIS Microsoft Windows Server 2019 Stand-alone Benchmark",
        "3.0.0",
        "Windows Server 2019",
        "Server",
        17763,
        17763,
        "Standalone",
    ),
    BenchmarkSpec(
        "CIS_Microsoft_Windows_Server_2019_STIG_Benchmark_v3.0.0.txt",
        "CIS_Server2019_STIG_3.0.0.json",
        "CIS_Server2019_STIG",
        "CIS Microsoft Windows Server 2019 STIG Benchmark",
        "3.0.0",
        "Windows Server 2019",
        "Server",
        17763,
        17763,
        "STIG",
    ),
    BenchmarkSpec(
        "CIS_Microsoft_Windows_Server_2022_Benchmark_v5.1.0.txt",
        "CIS_Server2022_5.1.0.json",
        "CIS_Server2022",
        "CIS Microsoft Windows Server 2022 Benchmark",
        "5.1.0",
        "Windows Server 2022",
        "Server",
        20348,
        20348,
        "Standard",
    ),
    BenchmarkSpec(
        "CIS_Microsoft_Windows_Server_2022_Stand-alone_Benchmark_v2.0.0.txt",
        "CIS_Server2022_Standalone_2.0.0.json",
        "CIS_Server2022_Standalone",
        "CIS Microsoft Windows Server 2022 Stand-alone Benchmark",
        "2.0.0",
        "Windows Server 2022",
        "Server",
        20348,
        20348,
        "Standalone",
    ),
    BenchmarkSpec(
        "CIS_Microsoft_Windows_Server_2022_STIG_Benchmark_v2.0.0.txt",
        "CIS_Server2022_STIG_2.0.0.json",
        "CIS_Server2022_STIG",
        "CIS Microsoft Windows Server 2022 STIG Benchmark",
        "2.0.0",
        "Windows Server 2022",
        "Server",
        20348,
        20348,
        "STIG",
    ),
    BenchmarkSpec(
        "CIS_Microsoft_Windows_Server_2025_Benchmark_v2.1.0.txt",
        "CIS_Server2025_2.1.0.json",
        "CIS_Server2025",
        "CIS Microsoft Windows Server 2025 Benchmark",
        "2.1.0",
        "Windows Server 2025",
        "Server",
        26100,
        29999,
        "Standard",
    ),
    BenchmarkSpec(
        "CIS_Microsoft_Windows_XP_Benchmark__imported__v3.1.0_ARCHIVE.txt",
        "CIS_WindowsXP_3.1.0_ARCHIVE.json",
        "CIS_WindowsXP",
        "CIS Microsoft Windows XP Benchmark",
        "3.1.0",
        "Windows XP",
        "Workstation",
        2600,
        2600,
        "General",
        archived=True,
    ),
)

USER_RIGHT_KEYS = {
    "access this computer from the network": "SeNetworkLogonRight",
    "act as part of the operating system": "SeTcbPrivilege",
    "add workstations to domain": "SeMachineAccountPrivilege",
    "adjust memory quotas for a process": "SeIncreaseQuotaPrivilege",
    "allow log on locally": "SeInteractiveLogonRight",
    "allow log on through remote desktop services": "SeRemoteInteractiveLogonRight",
    "allow log on through terminal services": "SeRemoteInteractiveLogonRight",
    "back up files and directories": "SeBackupPrivilege",
    "bypass traverse checking": "SeChangeNotifyPrivilege",
    "change the system time": "SeSystemtimePrivilege",
    "change the time zone": "SeTimeZonePrivilege",
    "create a pagefile": "SeCreatePagefilePrivilege",
    "create a token object": "SeCreateTokenPrivilege",
    "create global objects": "SeCreateGlobalPrivilege",
    "create permanent shared objects": "SeCreatePermanentPrivilege",
    "create symbolic links": "SeCreateSymbolicLinkPrivilege",
    "debug programs": "SeDebugPrivilege",
    "deny access to this computer from the network": "SeDenyNetworkLogonRight",
    "deny log on as a batch job": "SeDenyBatchLogonRight",
    "deny log on as a service": "SeDenyServiceLogonRight",
    "deny log on locally": "SeDenyInteractiveLogonRight",
    "deny log on through remote desktop services": "SeDenyRemoteInteractiveLogonRight",
    "deny log on through terminal services": "SeDenyRemoteInteractiveLogonRight",
    "enable computer and user accounts to be trusted for delegation": "SeEnableDelegationPrivilege",
    "force shutdown from a remote system": "SeRemoteShutdownPrivilege",
    "generate security audits": "SeAuditPrivilege",
    "impersonate a client after authentication": "SeImpersonatePrivilege",
    "increase scheduling priority": "SeIncreaseBasePriorityPrivilege",
    "increase a process working set": "SeIncreaseWorkingSetPrivilege",
    "load and unload device drivers": "SeLoadDriverPrivilege",
    "lock pages in memory": "SeLockMemoryPrivilege",
    "log on as a batch job": "SeBatchLogonRight",
    "log on as a service": "SeServiceLogonRight",
    "manage auditing and security log": "SeSecurityPrivilege",
    "modify firmware environment values": "SeSystemEnvironmentPrivilege",
    "perform volume maintenance tasks": "SeManageVolumePrivilege",
    "profile single process": "SeProfileSingleProcessPrivilege",
    "profile system performance": "SeSystemProfilePrivilege",
    "remove computer from docking station": "SeUndockPrivilege",
    "replace a process level token": "SeAssignPrimaryTokenPrivilege",
    "restore files and directories": "SeRestorePrivilege",
    "shut down the system": "SeShutdownPrivilege",
    "synchronize directory service data": "SeSyncAgentPrivilege",
    "take ownership of files or other objects": "SeTakeOwnershipPrivilege",
}

CLASSIC_AUDIT_KEYS = {
    "audit system events": "AuditSystemEvents",
    "audit logon events": "AuditLogonEvents",
    "audit object access": "AuditObjectAccess",
    "audit privilege use": "AuditPrivilegeUse",
    "audit policy change": "AuditPolicyChange",
    "audit account management": "AuditAccountManage",
    "audit process tracking": "AuditProcessTracking",
    "audit directory service access": "AuditDSAccess",
    "audit account logon events": "AuditAccountLogon",
}


def clean_text(value: str) -> str:
    value = PAGE_MARKER.sub(" ", value)
    value = re.sub(r"===\s*PDF(?:\s*PAGE\s*\d+)?\s*===", " ", value, flags=re.IGNORECASE)
    value = value.translate(CHAR_TRANSLATION)
    for source, replacement in MOJIBAKE_REPLACEMENTS.items():
        value = value.replace(source, replacement)
    value = re.sub(r"\bPage\s+\d+\b", " ", value, flags=re.IGNORECASE)
    value = re.sub(
        r"(?i)\b([0-9a-f]{8})-\s*([0-9a-f]{4})-\s*([0-9a-f]{4})-\s*"
        r"([0-9a-f]{4})-\s*([0-9a-f]{12})\b",
        r"\1-\2-\3-\4-\5",
        value,
    )
    return re.sub(r"\s+", " ", value).strip()


def normalized(value: str) -> str:
    return clean_text(value).lower().replace('"', "'")


def canonical_setting(title: str) -> str:
    title = clean_text(title)
    match = re.search(
        r"^(?:Ensure|Set|Configure)\s+'(?P<setting>.+?)'\s+"
        r"(?:is set to|to include|to)\s+",
        title,
        re.IGNORECASE,
    )
    if match:
        return normalized(match.group("setting"))
    match = re.search(r"^Ensure\s+'(?P<setting>.+?)'\s+or higher is installed", title, re.I)
    return normalized(match.group("setting")) if match else normalized(title)


def field(block: str, start: str, ends: Iterable[str]) -> str:
    end_pattern = "|".join(re.escape(item) for item in ends)
    match = re.search(
        rf"(?is)\n{re.escape(start)}:\s*(.*?)(?=\n(?:{end_pattern}):|\Z)",
        block,
    )
    return match.group(1).strip() if match else ""


def extract_expected_value(title: str, block: str) -> str:
    description = clean_text(field(block, "Description", ("Rationale", "Impact", "Audit", "Remediation")))
    match = re.search(
        r"The recommended state for this setting is:\s*(.+?)(?:\.\s|$)",
        description,
        re.IGNORECASE,
    )
    if match:
        return clean_text(match.group(1)).strip("'\"")
    match = re.search(
        r"(?:is set to|to include|to)\s+'(.+?)'(?:\s+\([^)]*only\))?(?:\s*$|\s+or higher|\s+or fewer)",
        clean_text(title),
        re.IGNORECASE,
    )
    if match:
        expected = clean_text(match.group(1))
        lower = clean_text(title).lower()
        if " or higher" in lower and "or higher" not in expected.lower():
            expected += " or higher"
        return expected
    return clean_text(title)


def profile_and_roles(title: str, block: str) -> tuple[str, list[str] | None]:
    profile_text = clean_text(field(block, "Profile Applicability", ("Description",)))
    levels = []
    if re.search(r"\bLevel 1\b|\(L1\)", profile_text, re.I):
        levels.append("Level 1 (L1)")
    if re.search(r"\bLevel 2\b|\(L2\)", profile_text, re.I):
        levels.append("Level 2 (L2)")
    if re.search(r"\bNext Generation\b|\(NG\)", profile_text, re.I):
        levels.append("Next Generation (NG)")
    profile = ", ".join(levels) if levels else profile_text[:200]
    lowered = clean_text(title).lower()
    if re.search(r"\((?:stig\s+)?dc\s+only\)", lowered, re.I):
        return profile, ["DomainController"]
    if re.search(r"\((?:stig\s+)?ms\s+only\)", lowered, re.I):
        return profile, ["MemberServer"]
    return profile, None


def category(control_id: str, supplemental: bool) -> tuple[str, str]:
    if supplemental:
        return "Microsoft Defender Antivirus", "Defender Security Policy"
    major = control_id.split(".")[0]
    categories = {
        "1": ("Account Policies", "Password and Account Lockout Policy"),
        "2": ("Local Policies", "User Rights and Security Options"),
        "5": ("System Services", "Service Configuration"),
        "9": ("Windows Defender Firewall", "Firewall Profiles"),
        "17": ("Advanced Audit Policy", "Audit Policy Configuration"),
        "18": ("Administrative Templates (Computer)", "Computer Configuration Policies"),
        "19": ("Administrative Templates (User)", "User Configuration Policies"),
        "20": ("Additional STIG Controls", "STIG Requirements"),
    }
    return categories.get(major, ("Windows Security Configuration", "Operating System Security"))


def parse_numeric_expectation(text: str) -> tuple[str, Any] | None:
    lower = clean_text(text).lower()
    numbers = [int(item) for item in re.findall(r"(?<![a-z0-9])\d+(?![a-z0-9])", lower)]
    if not numbers:
        return None
    if ("or fewer" in lower or "or less" in lower or "or lower" in lower) and "not 0" in lower:
        return "Between", [1, numbers[0]]
    if "or fewer" in lower or "or less" in lower or "or lower" in lower:
        return "LessThanOrEqual", numbers[0]
    if "or more" in lower or "or higher" in lower or "or greater" in lower:
        return "GreaterThanOrEqual", numbers[0]
    if len(numbers) > 1 and re.search(r"\bor\b|,", lower):
        return "In", list(dict.fromkeys(numbers))
    return "Equals", numbers[0]


def extract_registry_locations(audit_raw: str) -> list[tuple[str, str, str]]:
    normalized_audit = audit_raw.translate(CHAR_TRANSLATION)
    for source, replacement in MOJIBAKE_REPLACEMENTS.items():
        normalized_audit = normalized_audit.replace(source, replacement)
    lines = normalized_audit.splitlines()
    locations: list[tuple[str, str, str]] = []
    hive_pattern = re.compile(
        r"(HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKEY_USERS|HKEY_USER|"
        r"HKLM|HKCU|HKU)(?::)?\\",
        re.IGNORECASE,
    )
    for index, line in enumerate(lines):
        match = hive_pattern.search(line)
        if not match:
            continue
        pieces = [line[match.start():].strip()]
        cursor = index + 1
        while cursor < len(lines):
            continuation = lines[cursor].strip()
            if not continuation:
                break
            if continuation.startswith(("===", "Note:", "Remediation:", "Default Value:", "References:")):
                break
            if re.match(r"^Page\s+\d+", continuation, re.I):
                break
            if hive_pattern.search(continuation):
                break
            # Registry paths and value names are occasionally split mid-word.
            if len(continuation) < 80 and not continuation.endswith("."):
                pieces.append(continuation)
                cursor += 1
                continue
            break
        location = "".join(pieces)
        location = re.sub(r"\s+Page\s+\d+.*$", "", location, flags=re.I)
        split_at = location.rfind(":")
        hive_colon = location.upper().find("HK")
        if split_at <= hive_colon + 4:
            final_slash = location.rfind("\\")
            if final_slash <= hive_colon + 4:
                continue
            raw_path = location[:final_slash]
            value_name = location[final_slash + 1 :].strip().rstrip(".")
        else:
            raw_path = location[:split_at]
            value_name = location[split_at + 1 :].strip().rstrip(".")
        hive_match = hive_pattern.match(raw_path)
        if not hive_match or not value_name:
            continue
        hive = hive_match.group(1).upper()
        suffix = raw_path[hive_match.end() - 1 :]
        hive_map = {
            "HKEY_LOCAL_MACHINE": "HKLM:",
            "HKLM": "HKLM:",
            "HKEY_CURRENT_USER": "HKCU:",
            "HKCU": "HKCU:",
            "HKEY_USERS": r"HKU:",
            "HKU": r"HKU:",
            "HKEY_USER": "HKCU:",
        }
        path = hive_map[hive] + suffix
        before = "\n".join(lines[max(0, index - 8) : index])
        locations.append((path, value_name, before))
    deduped = []
    seen = set()
    for item in locations:
        key = (item[0].lower(), item[1].lower())
        if key not in seen:
            seen.add(key)
            deduped.append(item)
    return deduped


def parse_registry_expected(context: str, title: str) -> tuple[str, Any, str | None]:
    text = clean_text(context)
    match = re.search(
        r"REG_(?P<type>DWORD|QWORD|SZ|MULTI_SZ|EXPAND_SZ)\s+value\s+of\s+"
        r"(?P<value>.+?)(?:\.\s|$)",
        text,
        re.IGNORECASE,
    )
    value_type = match.group("type").upper() if match else None
    phrase = clean_text(match.group("value")) if match else extract_expected_value(title, "")
    lower = phrase.lower()
    if "does not exist" in lower or "not present" in lower:
        return "NotExists", None, value_type
    if value_type == "MULTI_SZ":
        if "blank" in lower and "browser" in lower:
            return "EmptyOrContainsAll", ["BROWSER"], value_type
        if "blank" in lower or "none" == lower.strip():
            return "Empty", None, value_type
        values = [item.strip().strip("'\"") for item in re.split(r",|\bor\b", phrase, flags=re.I)]
        values = [item for item in values if item and not item.lower().startswith(("when ", "i.e."))]
        return "ExactSet", values, value_type
    numeric = parse_numeric_expectation(phrase)
    if numeric:
        return numeric[0], numeric[1], value_type
    if "enabled" == lower.strip():
        return "Equals", 1, value_type
    if "disabled" == lower.strip():
        return "Equals", 0, value_type
    value = phrase.strip().strip("'\"")
    if "," in value and "=" in value:
        fragments = [item.strip() for item in value.split(",") if item.strip()]
        return "ContainsAll", fragments, value_type
    return "Equals", value, value_type


def registry_check(audit_raw: str, title: str) -> dict[str, Any] | None:
    locations = extract_registry_locations(audit_raw)
    if not locations:
        return None
    conditions = []
    for path, value_name, context in locations:
        operator, expected, value_type = parse_registry_expected(context, title)
        condition: dict[str, Any] = {
            "Path": path,
            "ValueName": value_name,
            "Operator": operator,
            "Expected": expected,
        }
        if value_type:
            condition["ValueType"] = value_type
        conditions.append(condition)
    if len(conditions) == 1:
        return {"Type": "Registry", **conditions[0]}
    return {"Type": "RegistryAll", "Conditions": conditions}


def expected_principals(title: str) -> tuple[str, list[str]]:
    cleaned = clean_text(title)
    match = re.search(r"(?:is set to|to include|to)\s+'(.+?)'(?:\s+\([^)]*only\))?(?:\s*$)", cleaned, re.I)
    phrase = match.group(1) if match else ""
    if phrase.lower() == "no one":
        return "ExactSet", []
    operator = "ContainsAll" if re.search(r"\bto include\b", cleaned, re.I) else "ExactSet"
    principals = [item.strip() for item in phrase.split(",") if item.strip()]
    return operator, principals


def audit_policy_check(title: str) -> dict[str, Any] | None:
    cleaned = clean_text(title)
    match = re.search(r"'Audit (?P<name>.+?)'\s+is set to", cleaned, re.I)
    if match:
        name = match.group("name")
    else:
        match = re.search(r"'Audit Policy:\s*(?:.+?:\s*)?(?P<name>[^']+)'\s+to", cleaned, re.I)
        if not match:
            return None
        name = match.group("name")
    lower = cleaned.lower()
    expected = []
    if "success" in lower:
        expected.append("Success")
    if "failure" in lower:
        expected.append("Failure")
    operator = "ContainsAll" if "to include" in lower else "ExactSet"
    return {"Type": "AuditPolicy", "Subcategory": name, "Operator": operator, "Expected": expected}


def classic_audit_policy_check(title: str) -> dict[str, Any] | None:
    setting = canonical_setting(title)
    key = CLASSIC_AUDIT_KEYS.get(setting)
    if not key:
        return None
    lower = clean_text(title).lower()
    value = 0
    if "success" in lower:
        value += 1
    if "failure" in lower:
        value += 2
    return {
        "Type": "SecurityPolicy",
        "Section": "Event Audit",
        "Key": key,
        "Operator": "Equals",
        "Expected": value,
    }


def security_policy_expectation(check: dict[str, Any], title: str) -> dict[str, Any]:
    result = copy.deepcopy(check)
    expected_text = extract_expected_value(title, "")
    numeric = parse_numeric_expectation(expected_text)
    if numeric:
        result["Operator"], result["Expected"] = numeric
    elif "enabled" in expected_text.lower():
        result["Operator"], result["Expected"] = "Equals", 1
    elif "disabled" in expected_text.lower():
        result["Operator"], result["Expected"] = "Equals", 0
    return result


def build_known_maps(output_directory: Path) -> tuple[dict[str, dict[str, Any]], dict[str, list[dict[str, Any]]]]:
    by_title: dict[str, dict[str, Any]] = {}
    by_setting: dict[str, list[dict[str, Any]]] = {}
    for path in output_directory.glob("*.json"):
        try:
            document = json.loads(path.read_text(encoding="utf-8-sig"))
        except (OSError, json.JSONDecodeError):
            continue
        for control in document.get("Controls", []):
            by_title[normalized(control["Title"])] = copy.deepcopy(control)
            by_setting.setdefault(canonical_setting(control["Title"]), []).append(copy.deepcopy(control))
    return by_title, by_setting


def choose_canonical_check(control_id: str, title: str, candidates: list[dict[str, Any]]) -> dict[str, Any] | None:
    if not candidates:
        return None
    preferred_type = None
    if control_id.startswith("2.2."):
        preferred_type = "UserRight"
    elif control_id.startswith("17."):
        preferred_type = "AuditPolicy"
    elif control_id.startswith("1."):
        preferred_type = "SecurityPolicy"
    for candidate in candidates:
        check = candidate.get("Check", {})
        if preferred_type and check.get("Type") != preferred_type:
            continue
        if check.get("Type") == "UserRight":
            operator, expected = expected_principals(title)
            return {"Type": "UserRight", "Key": check["Key"], "Operator": operator, "Expected": expected}
        if check.get("Type") == "AuditPolicy":
            return audit_policy_check(title) or copy.deepcopy(check)
        if check.get("Type") == "SecurityPolicy":
            return security_policy_expectation(check, title)
        return copy.deepcopy(check)
    # Imported/legacy benchmark numbering does not use the modern section
    # layout, so a canonical setting match is more reliable than its ID.
    if preferred_type:
        return choose_canonical_check("", title, candidates)
    return None


def parse_recommendations(text: str, legacy_inference: bool) -> list[tuple[re.Match[str], str, str]]:
    header = LEGACY_HEADER if legacy_inference else MODERN_HEADER
    matches = list(header.finditer(text))
    recommendations = []
    for index, match in enumerate(matches):
        mode = match.group("mode").lower()
        if not legacy_inference and mode != "automated":
            continue
        end = matches[index + 1].start() if index + 1 < len(matches) else len(text)
        recommendations.append((match, text[match.start() : end], mode))
    return recommendations


def derive_check(
    control_id: str,
    title: str,
    audit_raw: str,
    by_title: dict[str, dict[str, Any]],
    by_setting: dict[str, list[dict[str, Any]]],
) -> dict[str, Any] | None:
    exact = by_title.get(normalized(title))
    if exact:
        exact_check = copy.deepcopy(exact["Check"])
        if (
            exact_check.get("Type") == "Registry"
            and exact_check.get("ValueName") == "<numeric value>"
        ):
            values = re.findall(r"\{[0-9a-f-]{36}\}", str(exact_check.get("Expected", "")), re.I)
            return {
                "Type": "RegistryValueData",
                "Path": exact_check["Path"],
                "Operator": "ContainsAll",
                "Expected": values,
            }
        return exact_check
    setting = canonical_setting(title)
    if control_id.startswith("17.") or setting.startswith("audit policy:"):
        check = audit_policy_check(title)
        if check:
            return check
    check = classic_audit_policy_check(title)
    if check:
        return check
    if setting in USER_RIGHT_KEYS:
        operator, expected = expected_principals(title)
        if expected or re.search(r"\bNo One\b", title, re.I):
            return {
                "Type": "UserRight",
                "Key": USER_RIGHT_KEYS[setting],
                "Operator": operator,
                "Expected": expected,
            }
    check = registry_check(audit_raw, title)
    if check:
        return check
    candidates = by_setting.get(canonical_setting(title), [])
    check = choose_canonical_check(control_id, title, candidates)
    if check:
        return check
    if re.search(r"\bEMET\s+5\.52\b.*installed", title, re.I):
        return {
            "Type": "InstalledProduct",
            "NamePattern": "^EMET",
            "MinimumVersion": "5.52",
        }
    if setting == "accounts: administrator account status":
        return {
            "Type": "SecurityPolicy",
            "Section": "System Access",
            "Key": "EnableAdminAccount",
            "Operator": "Equals",
            "Expected": 0 if "disabled" in title.lower() else 1,
        }
    if setting == "accounts: guest account status":
        return {
            "Type": "SecurityPolicy",
            "Section": "System Access",
            "Key": "EnableGuestAccount",
            "Operator": "Equals",
            "Expected": 0 if "disabled" in title.lower() else 1,
        }
    if setting == "network security: force logoff when logon hours expire":
        return {
            "Type": "SecurityPolicy",
            "Section": "System Access",
            "Key": "ForceLogoffWhenHourExpire",
            "Operator": "Equals",
            "Expected": 1 if "enabled" in title.lower() else 0,
        }
    if setting == "netbios node type":
        return {
            "Type": "Registry",
            "Path": r"HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters",
            "ValueName": "NodeType",
            "Operator": "Equals",
            "Expected": 2,
            "ValueType": "DWORD",
        }
    event_log_match = re.match(r"maximum (application|security|system) log size", setting)
    if event_log_match:
        log_name = event_log_match.group(1).title()
        numeric = parse_numeric_expectation(title)
        if numeric:
            size_kib = int(numeric[1] if not isinstance(numeric[1], list) else numeric[1][0])
            return {
                "Type": "Registry",
                "Path": rf"HKLM:\SYSTEM\CurrentControlSet\Services\Eventlog\{log_name}",
                "ValueName": "MaxSize",
                "Operator": "GreaterThanOrEqual",
                "Expected": size_kib * 1024,
                "ValueType": "DWORD",
            }
    retention_match = re.match(r"retention method for (application|security|system) log", setting)
    if retention_match:
        log_name = retention_match.group(1).title()
        return {
            "Type": "Registry",
            "Path": rf"HKLM:\SYSTEM\CurrentControlSet\Services\Eventlog\{log_name}",
            "ValueName": "Retention",
            "Operator": "Equals",
            "Expected": 0,
            "ValueType": "DWORD",
        }
    guest_log_match = re.match(r"prevent local guests group from accessing (application|security|system) log", setting)
    if guest_log_match:
        log_name = guest_log_match.group(1).title()
        return {
            "Type": "Registry",
            "Path": rf"HKLM:\SYSTEM\CurrentControlSet\Services\Eventlog\{log_name}",
            "ValueName": "RestrictGuestAccess",
            "Operator": "Equals",
            "Expected": 1,
            "ValueType": "DWORD",
        }
    return None


def build_definition(
    spec: BenchmarkSpec,
    text_path: Path,
    by_title: dict[str, dict[str, Any]],
    by_setting: dict[str, list[dict[str, Any]]],
) -> tuple[dict[str, Any], list[dict[str, str]]]:
    text = text_path.read_text(encoding="utf-8-sig")
    controls = []
    unresolved = []
    for match, block, source_mode in parse_recommendations(text, spec.legacy_automation_inference):
        control_id = match.group("id")
        title = clean_text(match.group("title"))
        audit_raw = field(block, "Audit", ("Remediation", "Default Value", "References"))
        check = derive_check(control_id, title, audit_raw, by_title, by_setting)
        if not check:
            unresolved.append({"Id": control_id, "Title": title, "Reason": "No supported machine-readable check could be derived."})
            continue
        profile, roles = profile_and_roles(title, block)
        control_category, subcategory = category(control_id, spec.supplemental)
        severity = "Medium" if "Level 2" in profile else "High"
        remediation = clean_text(field(block, "Remediation", ("Default Value", "References", "CIS Controls")))
        expected = extract_expected_value(title, block)
        control: dict[str, Any] = {
            "Id": control_id,
            "Title": title,
            "Category": control_category,
            "SubCategory": subcategory,
            "Severity": severity,
            "Profile": profile,
            "Automated": True,
            "ExpectedValue": expected,
            "Check": check,
            "Remediation": remediation or f"Apply the CIS-prescribed configuration for control {control_id}.",
            "Reference": f"{spec.name} v{spec.version}, control {control_id}",
        }
        if roles:
            control["AppliesToServerRoles"] = roles
        if spec.legacy_automation_inference:
            control["AutomationBasis"] = (
                f"Machine-readable assessment inferred from the legacy '{source_mode.title()}' audit procedure."
            )
        controls.append(control)
    metadata: dict[str, Any] = {
        "Id": spec.benchmark_id,
        "Name": spec.name,
        "Version": spec.version,
        "Variant": spec.variant,
        "Platform": {
            "Product": spec.product,
            "ProductType": spec.product_type,
            "BuildMinimum": spec.build_minimum,
            "BuildMaximum": spec.build_maximum,
        },
        "SourceDocument": spec.source.replace(".txt", ".pdf"),
        "Archived": spec.archived,
        "Supplemental": spec.supplemental,
        "AutomationSelection": (
            "InferredMachineReadableAuditProcedure"
            if spec.legacy_automation_inference
            else "CISAutomatedRecommendations"
        ),
        "AutomatedControlCount": len(controls),
    }
    return {"SchemaVersion": "2.1", "Benchmark": metadata, "Controls": controls}, unresolved


def validate_definition(document: dict[str, Any], spec: BenchmarkSpec) -> None:
    controls = document["Controls"]
    ids = [item["Id"] for item in controls]
    if len(ids) != len(set(ids)):
        duplicates = sorted({item for item in ids if ids.count(item) > 1})
        raise ValueError(f"{spec.output}: duplicate control IDs: {duplicates}")
    if not controls:
        raise ValueError(f"{spec.output}: no automated controls were generated")
    for control in controls:
        if not control["Remediation"]:
            raise ValueError(f"{spec.output}: {control['Id']} has empty remediation")
        check = control["Check"]
        if check["Type"] in {"Registry", "RegistryAll"}:
            conditions = check.get("Conditions", [check])
            for condition in conditions:
                if "\n" in condition["Path"] or "\n" in condition["ValueName"]:
                    raise ValueError(f"{spec.output}: {control['Id']} contains a split registry location")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--text-directory", type=Path, required=True)
    parser.add_argument("--output-directory", type=Path, required=True)
    parser.add_argument("--strict", action="store_true", help="Fail when any parsed recommendation has no check.")
    args = parser.parse_args()
    args.output_directory.mkdir(parents=True, exist_ok=True)
    by_title, by_setting = build_known_maps(args.output_directory)
    all_unresolved: dict[str, list[dict[str, str]]] = {}
    generated = []
    catalog_entries = []
    for spec in SPECS:
        text_path = args.text_directory / spec.source
        if not text_path.exists():
            raise FileNotFoundError(text_path)
        document, unresolved = build_definition(spec, text_path, by_title, by_setting)
        validate_definition(document, spec)
        output_path = args.output_directory / spec.output
        output_path.write_text(json.dumps(document, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        generated.append((spec.output, len(document["Controls"]), len(unresolved)))
        catalog_entries.append(
            {
                "FileName": spec.output,
                "Sha256": hashlib.sha256(output_path.read_bytes()).hexdigest(),
                **copy.deepcopy(document["Benchmark"]),
            }
        )
        if unresolved:
            all_unresolved[spec.output] = unresolved
        # Newly generated mappings improve coverage for older benchmarks.
        for control in document["Controls"]:
            by_title[normalized(control["Title"])] = copy.deepcopy(control)
            by_setting.setdefault(canonical_setting(control["Title"]), []).append(copy.deepcopy(control))
    unresolved_path = args.output_directory / "generation-unresolved.json"
    unresolved_path.write_text(json.dumps(all_unresolved, indent=2) + "\n", encoding="utf-8")
    catalog_path = args.output_directory / "BenchmarkCatalog.json"
    catalog_path.write_text(
        json.dumps(
            {
                "SchemaVersion": "1.0",
                "GeneratedBy": Path(__file__).name,
                "Benchmarks": catalog_entries,
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    for filename, count, unresolved_count in generated:
        print(f"{filename}: {count} checks, {unresolved_count} unresolved")
    if args.strict and all_unresolved:
        print(f"Unresolved recommendations were written to {unresolved_path}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
