"""Windows audit policy checks via auditpol and registry inspection."""

import csv
import io
import platform

from core.result import CheckResult
from core.platform_utils import safe_run, read_file_safe, file_exists, is_elevated, check_process_running

try:
    import winreg
except ImportError:
    winreg = None


def _is_windows():
    return platform.system() == "Windows"


def _parse_auditpol_csv(raw_output):
    """Parse auditpol /get /category:* /r CSV output.

    Returns a dict mapping subcategory name (stripped) -> inclusion setting string.
    """
    result = {}
    reader = csv.DictReader(io.StringIO(raw_output))
    for row in reader:
        subcat = row.get("Subcategory", "").strip()
        setting = row.get("Inclusion Setting", "").strip()
        if subcat:
            result[subcat] = setting
    return result


def _get_audit_policies():
    """Run auditpol and return parsed dict, or (None, error_msg)."""
    rc, out, err = safe_run(["auditpol", "/get", "/category:*", "/r"], timeout=15)
    if rc != 0:
        return None, err or "auditpol command failed"
    policies = _parse_auditpol_csv(out)
    if not policies:
        return None, "No audit policies parsed from auditpol output"
    return policies, out


def _has_success(setting):
    return setting in ("Success", "Success and Failure")


def _has_failure(setting):
    return setting in ("Failure", "Success and Failure")


def _has_success_and_failure(setting):
    return setting == "Success and Failure"


def _check_credential_validation(policies, raw_output):
    """WIN-AUDIT-001: Credential Validation auditing (Success AND Failure)."""
    check_id = "WIN-AUDIT-001"
    title_base = "Credential Validation Auditing"
    subcat = "Credential Validation"
    setting = policies.get(subcat, "Not Found")
    evidence = {"subcategory": subcat, "setting": setting, "raw_auditpol": raw_output[:500]}

    if _has_success_and_failure(setting):
        return CheckResult(
            check_id=check_id,
            title="{} - Properly Configured".format(title_base),
            severity="PASS",
            detail="Credential Validation is auditing both Success and Failure events.",
            remediation="No action required.",
            category="config",
            platform="windows",
            evidence=evidence,
            mitre_techniques=["T1110", "T1078"],
        )

    return CheckResult(
        check_id=check_id,
        title="{} - Insufficient".format(title_base),
        severity="FAIL",
        detail="Credential Validation is set to '{}'. Both Success and Failure are required "
               "to detect brute-force attacks and credential abuse.".format(setting),
        remediation="auditpol /set /subcategory:\"Credential Validation\" /success:enable /failure:enable",
        category="config",
        platform="windows",
        evidence=evidence,
        mitre_techniques=["T1110", "T1078"],
    )


def _check_kerberos(policies, raw_output):
    """WIN-AUDIT-002: Kerberos Authentication Service and Service Ticket Operations."""
    check_id = "WIN-AUDIT-002"
    title_base = "Kerberos Auditing"
    subcats = {
        "Kerberos Authentication Service": policies.get("Kerberos Authentication Service", "Not Found"),
        "Kerberos Service Ticket Operations": policies.get("Kerberos Service Ticket Operations", "Not Found"),
    }
    evidence = {"subcategories": subcats, "raw_auditpol": raw_output[:500]}

    all_ok = all(_has_success_and_failure(v) for v in subcats.values())
    if all_ok:
        return CheckResult(
            check_id=check_id,
            title="{} - Properly Configured".format(title_base),
            severity="PASS",
            detail="Both Kerberos subcategories audit Success and Failure.",
            remediation="No action required.",
            category="config",
            platform="windows",
            evidence=evidence,
            mitre_techniques=["T1558.003", "T1550.003"],
        )

    issues = []
    remediation_cmds = []
    for name, val in subcats.items():
        if not _has_success_and_failure(val):
            issues.append("{}: '{}'".format(name, val))
            remediation_cmds.append(
                'auditpol /set /subcategory:"{}" /success:enable /failure:enable'.format(name)
            )

    return CheckResult(
        check_id=check_id,
        title="{} - Insufficient".format(title_base),
        severity="FAIL",
        detail="Kerberos auditing gaps: {}. Required for Kerberoasting and "
               "pass-the-ticket detection.".format("; ".join(issues)),
        remediation="\n".join(remediation_cmds),
        category="config",
        platform="windows",
        evidence=evidence,
        mitre_techniques=["T1558.003", "T1550.003"],
    )


def _check_logon_logoff(policies, raw_output):
    """WIN-AUDIT-003: Logon/Logoff event auditing."""
    check_id = "WIN-AUDIT-003"
    title_base = "Logon/Logoff Auditing"

    subcats_config = {
        "Logon": {"require_success": True, "require_failure": True, "fail_level": "FAIL"},
        "Logoff": {"require_success": True, "require_failure": False, "fail_level": "WARN"},
        "Account Lockout": {"require_success": False, "require_failure": True, "fail_level": "FAIL"},
        "Special Logon": {"require_success": True, "require_failure": False, "fail_level": "WARN"},
    }

    evidence = {}
    issues = []
    worst_severity = "PASS"
    remediation_cmds = []

    for subcat, config in subcats_config.items():
        setting = policies.get(subcat, "Not Found")
        evidence[subcat] = setting

        ok = True
        if config["require_success"] and not _has_success(setting):
            ok = False
        if config["require_failure"] and not _has_failure(setting):
            ok = False

        if not ok:
            issues.append("{}: '{}'".format(subcat, setting))
            suc = "/success:enable" if config["require_success"] else ""
            fail = "/failure:enable" if config["require_failure"] else ""
            remediation_cmds.append(
                'auditpol /set /subcategory:"{}" {} {}'.format(subcat, suc, fail).strip()
            )
            level = config["fail_level"]
            if level == "FAIL":
                worst_severity = "FAIL"
            elif level == "WARN" and worst_severity != "FAIL":
                worst_severity = "WARN"

    if not issues:
        return CheckResult(
            check_id=check_id,
            title="{} - Properly Configured".format(title_base),
            severity="PASS",
            detail="All Logon/Logoff subcategories are properly audited.",
            remediation="No action required.",
            category="config",
            platform="windows",
            evidence=evidence,
        )

    return CheckResult(
        check_id=check_id,
        title="{} - Gaps Detected".format(title_base),
        severity=worst_severity,
        detail="Logon/Logoff auditing gaps: {}".format("; ".join(issues)),
        remediation="\n".join(remediation_cmds),
        category="config",
        platform="windows",
        evidence=evidence,
    )


def _check_process_creation(policies, raw_output):
    """WIN-AUDIT-004: Process Creation auditing and command-line logging."""
    check_id = "WIN-AUDIT-004"
    title_base = "Process Creation Auditing"
    subcat = "Process Creation"
    setting = policies.get(subcat, "Not Found")
    evidence = {"subcategory": subcat, "setting": setting}

    results = []

    # Check auditpol setting
    if _has_success(setting):
        severity = "PASS"
        detail = "Process Creation auditing is enabled (Success)."
    else:
        severity = "FAIL"
        detail = "Process Creation auditing is set to '{}'. This is critical for detecting " \
                 "process execution and malware.".format(setting)

    # Check registry for command-line logging
    cmdline_enabled = None
    if winreg is not None:
        try:
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
            )
            val, _ = winreg.QueryValueEx(key, "ProcessCreationIncludeCmdLine_Enabled")
            winreg.CloseKey(key)
            cmdline_enabled = val
        except (OSError, FileNotFoundError, WindowsError if _is_windows() else Exception):
            cmdline_enabled = None
    evidence["ProcessCreationIncludeCmdLine_Enabled"] = cmdline_enabled

    remediation_parts = []
    if severity == "FAIL":
        remediation_parts.append(
            'auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable'
        )

    if cmdline_enabled != 1:
        if severity == "PASS":
            severity = "WARN"
        detail += " Command-line logging is NOT enabled in the registry."
        remediation_parts.append(
            'reg add "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Audit" '
            '/v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f'
        )
    else:
        detail += " Command-line logging is enabled."

    if not remediation_parts:
        remediation_parts.append("No action required.")

    return CheckResult(
        check_id=check_id,
        title="{} - {}".format(title_base, severity),
        severity=severity,
        detail=detail,
        remediation="\n".join(remediation_parts),
        category="config",
        platform="windows",
        evidence=evidence,
        mitre_techniques=["T1059", "T1055", "T1036"],
    )


def _check_account_management(policies, raw_output):
    """WIN-AUDIT-005: Account Management subcategories (S+F for all)."""
    check_id = "WIN-AUDIT-005"
    title_base = "Account Management Auditing"

    subcats = [
        "User Account Management",
        "Computer Account Management",
        "Security Group Management",
        "Distribution Group Management",
        "Other Account Management Events",
    ]

    evidence = {}
    issues = []
    remediation_cmds = []

    for subcat in subcats:
        setting = policies.get(subcat, "Not Found")
        evidence[subcat] = setting
        if not _has_success_and_failure(setting):
            issues.append("{}: '{}'".format(subcat, setting))
            remediation_cmds.append(
                'auditpol /set /subcategory:"{}" /success:enable /failure:enable'.format(subcat)
            )

    if not issues:
        return CheckResult(
            check_id=check_id,
            title="{} - Properly Configured".format(title_base),
            severity="PASS",
            detail="All Account Management subcategories audit Success and Failure.",
            remediation="No action required.",
            category="config",
            platform="windows",
            evidence=evidence,
            mitre_techniques=["T1136", "T1098", "T1078"],
        )

    return CheckResult(
        check_id=check_id,
        title="{} - Gaps Detected".format(title_base),
        severity="FAIL",
        detail="Account Management auditing gaps: {}".format("; ".join(issues)),
        remediation="\n".join(remediation_cmds),
        category="config",
        platform="windows",
        evidence=evidence,
        mitre_techniques=["T1136", "T1098", "T1078"],
    )


def _check_policy_change(policies, raw_output):
    """WIN-AUDIT-006: Policy Change subcategories (Success required for all)."""
    check_id = "WIN-AUDIT-006"
    title_base = "Policy Change Auditing"

    subcats = [
        "Audit Policy Change",
        "Authentication Policy Change",
        "Authorization Policy Change",
        "MPSSVC Rule-Level Policy Change",
        "Filtering Platform Policy Change",
        "Other Policy Change Events",
    ]

    evidence = {}
    issues = []
    remediation_cmds = []

    for subcat in subcats:
        setting = policies.get(subcat, "Not Found")
        evidence[subcat] = setting
        if not _has_success(setting):
            issues.append("{}: '{}'".format(subcat, setting))
            remediation_cmds.append(
                'auditpol /set /subcategory:"{}" /success:enable'.format(subcat)
            )

    if not issues:
        return CheckResult(
            check_id=check_id,
            title="{} - Properly Configured".format(title_base),
            severity="PASS",
            detail="All Policy Change subcategories audit at least Success events.",
            remediation="No action required.",
            category="config",
            platform="windows",
            evidence=evidence,
            mitre_techniques=["T1562.002"],
        )

    return CheckResult(
        check_id=check_id,
        title="{} - Gaps Detected".format(title_base),
        severity="FAIL",
        detail="Policy Change auditing gaps (attackers can modify audit policy "
               "to hide tracks): {}".format("; ".join(issues)),
        remediation="\n".join(remediation_cmds),
        category="config",
        platform="windows",
        evidence=evidence,
        mitre_techniques=["T1562.002"],
    )


def _check_privilege_use(policies, raw_output):
    """WIN-AUDIT-007: Privilege Use auditing."""
    check_id = "WIN-AUDIT-007"
    title_base = "Privilege Use Auditing"

    sensitive = policies.get("Sensitive Privilege Use", "Not Found")
    non_sensitive = policies.get("Non Sensitive Privilege Use", "Not Found")
    evidence = {
        "Sensitive Privilege Use": sensitive,
        "Non Sensitive Privilege Use": non_sensitive,
    }

    issues = []
    remediation_cmds = []
    worst = "PASS"

    if not _has_success_and_failure(sensitive):
        issues.append("Sensitive Privilege Use: '{}'".format(sensitive))
        remediation_cmds.append(
            'auditpol /set /subcategory:"Sensitive Privilege Use" /success:enable /failure:enable'
        )
        worst = "FAIL"

    if not _has_success(non_sensitive):
        issues.append("Non Sensitive Privilege Use: '{}' (recommended)".format(non_sensitive))
        remediation_cmds.append(
            'auditpol /set /subcategory:"Non Sensitive Privilege Use" /success:enable'
        )
        if worst != "FAIL":
            worst = "WARN"

    if not issues:
        return CheckResult(
            check_id=check_id,
            title="{} - Properly Configured".format(title_base),
            severity="PASS",
            detail="Privilege Use subcategories are properly audited.",
            remediation="No action required.",
            category="config",
            platform="windows",
            evidence=evidence,
            mitre_techniques=["T1078.003", "T1134"],
        )

    return CheckResult(
        check_id=check_id,
        title="{} - Gaps Detected".format(title_base),
        severity=worst,
        detail="Privilege Use auditing gaps: {}".format("; ".join(issues)),
        remediation="\n".join(remediation_cmds),
        category="config",
        platform="windows",
        evidence=evidence,
        mitre_techniques=["T1078.003", "T1134"],
    )


def _check_object_access(policies, raw_output):
    """WIN-AUDIT-008: Object Access auditing (File System, Registry, SAM)."""
    check_id = "WIN-AUDIT-008"
    title_base = "Object Access Auditing"

    subcats = ["File System", "Registry", "SAM"]
    evidence = {}
    issues = []
    remediation_cmds = []

    for subcat in subcats:
        setting = policies.get(subcat, "Not Found")
        evidence[subcat] = setting
        if not _has_success(setting):
            issues.append("{}: '{}'".format(subcat, setting))
            remediation_cmds.append(
                'auditpol /set /subcategory:"{}" /success:enable /failure:enable'.format(subcat)
            )

    note = ("Note: Object Access auditing also requires SACLs (System Access Control Lists) "
            "to be configured on the specific objects you want to monitor. Without SACLs, "
            "enabling the audit policy alone will not generate events.")

    if not issues:
        return CheckResult(
            check_id=check_id,
            title="{} - Enabled".format(title_base),
            severity="PASS",
            detail="Object Access subcategories (File System, Registry, SAM) are audited. {}".format(note),
            remediation="Ensure SACLs are configured on sensitive objects.",
            category="config",
            platform="windows",
            evidence=evidence,
        )

    return CheckResult(
        check_id=check_id,
        title="{} - Not Fully Enabled".format(title_base),
        severity="WARN",
        detail="Object Access auditing gaps: {}. {}".format("; ".join(issues), note),
        remediation="\n".join(remediation_cmds) + "\n\n" + note,
        category="config",
        platform="windows",
        evidence=evidence,
    )


def _check_system_events(policies, raw_output):
    """WIN-AUDIT-009: System events auditing."""
    check_id = "WIN-AUDIT-009"
    title_base = "System Events Auditing"

    subcats = [
        "Security System Extension",
        "System Integrity",
        "Security State Change",
    ]

    evidence = {}
    issues = []
    remediation_cmds = []

    for subcat in subcats:
        setting = policies.get(subcat, "Not Found")
        evidence[subcat] = setting
        if not _has_success_and_failure(setting):
            issues.append("{}: '{}'".format(subcat, setting))
            remediation_cmds.append(
                'auditpol /set /subcategory:"{}" /success:enable /failure:enable'.format(subcat)
            )

    if not issues:
        return CheckResult(
            check_id=check_id,
            title="{} - Properly Configured".format(title_base),
            severity="PASS",
            detail="System event subcategories are auditing Success and Failure.",
            remediation="No action required.",
            category="config",
            platform="windows",
            evidence=evidence,
        )

    return CheckResult(
        check_id=check_id,
        title="{} - Gaps Detected".format(title_base),
        severity="FAIL",
        detail="System event auditing gaps: {}".format("; ".join(issues)),
        remediation="\n".join(remediation_cmds),
        category="config",
        platform="windows",
        evidence=evidence,
    )


def _check_detailed_tracking(policies, raw_output):
    """WIN-AUDIT-010: Detailed Tracking - Process Termination and DPAPI Activity."""
    check_id = "WIN-AUDIT-010"
    title_base = "Detailed Tracking Auditing"

    subcats_config = {
        "Process Termination": {"level": "WARN"},
        "DPAPI Activity": {"level": "WARN"},
    }

    evidence = {}
    issues = []
    remediation_cmds = []
    worst = "PASS"

    for subcat, config in subcats_config.items():
        setting = policies.get(subcat, "Not Found")
        evidence[subcat] = setting
        if not _has_success(setting):
            issues.append("{}: '{}'".format(subcat, setting))
            remediation_cmds.append(
                'auditpol /set /subcategory:"{}" /success:enable'.format(subcat)
            )
            if worst != "FAIL":
                worst = config["level"]

    if not issues:
        return CheckResult(
            check_id=check_id,
            title="{} - Properly Configured".format(title_base),
            severity="PASS",
            detail="Process Termination and DPAPI Activity are being audited.",
            remediation="No action required.",
            category="config",
            platform="windows",
            evidence=evidence,
        )

    return CheckResult(
        check_id=check_id,
        title="{} - Recommended Additions".format(title_base),
        severity=worst,
        detail="Detailed Tracking gaps (recommended for forensic completeness): {}".format(
            "; ".join(issues)),
        remediation="\n".join(remediation_cmds),
        category="config",
        platform="windows",
        evidence=evidence,
    )


def run_checks():
    """Return all Windows audit policy checks."""
    if not _is_windows():
        return []

    if not is_elevated():
        return [CheckResult(
            check_id="WIN-AUDIT-001",
            title="Audit Policy Checks - Elevation Required",
            severity="SKIP",
            detail="Audit policy checks require administrator privileges.",
            remediation="Re-run this tool as Administrator.",
            category="config",
            platform="windows",
            evidence={},
        )]

    policies, raw_output = _get_audit_policies()
    if policies is None:
        return [CheckResult(
            check_id="WIN-AUDIT-001",
            title="Audit Policy - Cannot Retrieve",
            severity="SKIP",
            detail="Failed to retrieve audit policies: {}".format(raw_output),
            remediation="Ensure auditpol.exe is available and you are running as Administrator.",
            category="config",
            platform="windows",
            evidence={"error": raw_output},
        )]

    return [
        _check_credential_validation(policies, raw_output),
        _check_kerberos(policies, raw_output),
        _check_logon_logoff(policies, raw_output),
        _check_process_creation(policies, raw_output),
        _check_account_management(policies, raw_output),
        _check_policy_change(policies, raw_output),
        _check_privilege_use(policies, raw_output),
        _check_object_access(policies, raw_output),
        _check_system_events(policies, raw_output),
        _check_detailed_tracking(policies, raw_output),
    ]
