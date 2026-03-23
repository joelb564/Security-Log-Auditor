"""macOS BSM (OpenBSM) audit checks: auditd status, audit_control config, log files."""

import glob
import os
import time
import re

from core.result import CheckResult
from core.platform_utils import (
    safe_run, read_file_safe, file_exists, is_elevated,
    check_process_running, get_os,
)


def _get_macos_version():
    """Return macOS major version as int, or None if detection fails."""
    rc, out, _ = safe_run(["sw_vers", "-productVersion"])
    if rc != 0 or not out.strip():
        return None, out.strip()
    version_str = out.strip()
    try:
        major = int(version_str.split(".")[0])
        return major, version_str
    except (ValueError, IndexError):
        return None, version_str


def _check_auditd_running():
    """MAC-BSM-001: Is auditd running?"""
    evidence = {}

    major_version, version_str = _get_macos_version()
    evidence["macos_version"] = version_str
    evidence["macos_major"] = major_version

    auditd_running = check_process_running("auditd")
    evidence["auditd_running"] = auditd_running

    is_ventura_plus = major_version is not None and major_version >= 13

    if is_ventura_plus:
        # On Ventura+, OpenBSM is deprecated
        detail = (
            "macOS {} detected (Ventura or later). OpenBSM/auditd is deprecated. "
            "Apple recommends the Endpoint Security Framework (ESF) for audit "
            "event collection. EDR agents such as CrowdStrike Falcon, SentinelOne, "
            "and Microsoft Defender for Endpoint use ESF natively."
        ).format(version_str)

        if auditd_running:
            detail += " auditd is still running (legacy mode)."

        return CheckResult(
            check_id="MAC-BSM-001",
            title="OpenBSM deprecated on macOS {}".format(version_str),
            severity="INFO",
            detail=detail,
            remediation=(
                "Migrate from OpenBSM to Endpoint Security Framework-based tooling. "
                "Deploy an ESF-aware EDR agent (CrowdStrike, SentinelOne, MDE) or "
                "use osquery with its ESF-based process_events table. "
                "See: https://developer.apple.com/documentation/endpointsecurity"
            ),
            category="service",
            platform="macos",
            evidence=evidence,
            mitre_techniques=["T1562.002"],
        )

    # Pre-Ventura: auditd should be running
    if auditd_running:
        return CheckResult(
            check_id="MAC-BSM-001",
            title="auditd is running",
            severity="PASS",
            detail="auditd process is active on macOS {}.".format(version_str),
            remediation="No action required.",
            category="service",
            platform="macos",
            evidence=evidence,
            mitre_techniques=["T1562.002"],
        )

    return CheckResult(
        check_id="MAC-BSM-001",
        title="auditd is not running",
        severity="WARN",
        detail=(
            "auditd is not running on macOS {}. BSM audit events are not "
            "being collected. On pre-Ventura macOS, auditd provides kernel-level "
            "audit logging via OpenBSM."
        ).format(version_str),
        remediation=(
            "Enable and start auditd:\n"
            "  sudo launchctl load -w /System/Library/LaunchDaemons/com.apple.auditd.plist\n"
            "Verify with: sudo praudit -l /dev/auditpipe"
        ),
        category="service",
        platform="macos",
        evidence=evidence,
        mitre_techniques=["T1562.002"],
    )


def _check_audit_control():
    """MAC-BSM-002: audit_control configuration analysis."""
    evidence = {}
    config_path = "/etc/security/audit_control"

    content = read_file_safe(config_path)
    evidence["config_path"] = config_path

    if content is None:
        return CheckResult(
            check_id="MAC-BSM-002",
            title="audit_control not readable",
            severity="WARN",
            detail="Cannot read {}. This file defines BSM audit policy flags.".format(config_path),
            remediation=(
                "Ensure {} exists and is readable. Default macOS installs "
                "include this file. Re-create from backup or reinstall macOS "
                "security components."
            ).format(config_path),
            category="config",
            platform="macos",
            evidence=evidence,
            mitre_techniques=["T1562.002"],
        )

    evidence["config_content"] = content[:1000]

    # Parse key:value pairs (audit_control uses colon separators)
    config = {}
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if ":" in line:
            key, _, value = line.partition(":")
            config[key.strip()] = value.strip()

    evidence["parsed_config"] = config

    # Check flags
    flags_str = config.get("flags", "")
    flags = [f.strip() for f in flags_str.split(",") if f.strip()]
    evidence["flags"] = flags

    required_flags = {"lo", "aa"}
    recommended_flags = {"ex", "pc", "fw"}
    all_desired = {"lo", "aa", "ex", "pc", "fw", "fd"}

    results = []

    missing_required = required_flags - set(flags)
    missing_recommended = recommended_flags - set(flags)

    if missing_required:
        results.append(CheckResult(
            check_id="MAC-BSM-002",
            title="audit_control missing critical flags",
            severity="FAIL",
            detail=(
                "audit_control flags field is '{}'. Missing critical flags: {}. "
                "'lo' covers login/logout events; 'aa' covers authentication/authorization. "
                "Without these, core security events are not audited."
            ).format(flags_str, ", ".join(sorted(missing_required))),
            remediation=(
                "Edit {} and add missing flags:\n"
                "  flags:lo,aa,ex,pc,fw,fd\n"
                "Then restart auditd: sudo audit -s\n\n"
                "Flag reference: lo=login/logout, aa=auth, ex=exec, "
                "pc=process, fw=file-write, fd=file-delete"
            ).format(config_path),
            category="config",
            platform="macos",
            evidence=evidence,
            mitre_techniques=["T1562.002", "T1078"],
        ))
    elif missing_recommended:
        for flag in sorted(missing_recommended):
            flag_desc = {"ex": "exec (process execution)", "pc": "process (fork/exit)",
                         "fw": "file-write"}.get(flag, flag)
            results.append(CheckResult(
                check_id="MAC-BSM-002",
                title="audit_control missing recommended flag: {}".format(flag),
                severity="WARN",
                detail=(
                    "audit_control flags field is '{}'. Missing recommended flag '{}' ({}). "
                    "This reduces visibility into relevant security events."
                ).format(flags_str, flag, flag_desc),
                remediation=(
                    "Add '{}' to the flags line in {}:\n"
                    "  flags:{},{}\n"
                    "Then restart auditd: sudo audit -s"
                ).format(flag, config_path, flags_str, flag),
                category="config",
                platform="macos",
                evidence=evidence,
                mitre_techniques=["T1562.002"],
            ))
    else:
        results.append(CheckResult(
            check_id="MAC-BSM-002",
            title="audit_control flags configured",
            severity="PASS",
            detail="audit_control flags '{}' include all recommended flags.".format(flags_str),
            remediation="No action required.",
            category="config",
            platform="macos",
            evidence=evidence,
            mitre_techniques=["T1562.002"],
        ))

    # Check minfree
    minfree = config.get("minfree", "")
    evidence["minfree"] = minfree
    if minfree:
        try:
            minfree_val = int(minfree)
            if minfree_val < 5:
                results.append(CheckResult(
                    check_id="MAC-BSM-002",
                    title="audit_control minfree is low ({}%)".format(minfree_val),
                    severity="WARN",
                    detail=(
                        "minfree is set to {}%. When free disk space drops below this "
                        "threshold, audit may stop logging. A value of at least 20% is "
                        "recommended."
                    ).format(minfree_val),
                    remediation=(
                        "Increase minfree in {}:\n"
                        "  minfree:20\n"
                        "Then reload: sudo audit -s"
                    ).format(config_path),
                    category="config",
                    platform="macos",
                    evidence=evidence,
                    mitre_techniques=["T1562.002"],
                ))
        except ValueError:
            pass

    # Check filesz
    filesz = config.get("filesz", "")
    evidence["filesz"] = filesz
    if filesz:
        try:
            filesz_val = int(filesz.replace("B", "").replace("M", "").replace("K", ""))
            evidence["filesz_parsed"] = filesz_val
        except ValueError:
            pass

    if not results:
        results.append(CheckResult(
            check_id="MAC-BSM-002",
            title="audit_control configuration reviewed",
            severity="PASS",
            detail="audit_control configuration at {} appears adequate.".format(config_path),
            remediation="No action required.",
            category="config",
            platform="macos",
            evidence=evidence,
            mitre_techniques=["T1562.002"],
        ))

    return results


def _check_audit_logs():
    """MAC-BSM-003: Audit log location and recent files."""
    evidence = {}
    audit_dir = "/var/audit"

    if not file_exists(audit_dir):
        return CheckResult(
            check_id="MAC-BSM-003",
            title="Audit log directory not found",
            severity="WARN",
            detail=(
                "{} does not exist. BSM audit logs are normally stored here."
            ).format(audit_dir),
            remediation=(
                "Verify auditd configuration. The audit log directory is set in "
                "/etc/security/audit_control via the 'dir' directive. "
                "Ensure auditd is enabled: sudo launchctl load -w "
                "/System/Library/LaunchDaemons/com.apple.auditd.plist"
            ),
            category="service",
            platform="macos",
            evidence=evidence,
            mitre_techniques=["T1070.002"],
        )

    # List audit log files
    try:
        log_files = sorted(glob.glob(os.path.join(audit_dir, "*")))
    except PermissionError:
        log_files = []

    evidence["audit_dir"] = audit_dir
    evidence["log_file_count"] = len(log_files)

    if not log_files:
        return CheckResult(
            check_id="MAC-BSM-003",
            title="No audit log files in {}".format(audit_dir),
            severity="WARN",
            detail="The audit directory exists but contains no log files.",
            remediation=(
                "Verify auditd is running and generating events:\n"
                "  sudo audit -s\n"
                "  ls -la /var/audit/\n"
                "  sudo praudit -l /dev/auditpipe"
            ),
            category="service",
            platform="macos",
            evidence=evidence,
            mitre_techniques=["T1070.002"],
        )

    # Check modification times
    now = time.time()
    one_hour_ago = now - 3600
    recent_files = []
    for f in log_files:
        try:
            mtime = os.path.getmtime(f)
            if mtime >= one_hour_ago:
                recent_files.append(os.path.basename(f))
        except (OSError, PermissionError):
            continue

    evidence["recent_files"] = recent_files
    evidence["total_files"] = [os.path.basename(f) for f in log_files[-10:]]

    if not recent_files:
        return CheckResult(
            check_id="MAC-BSM-003",
            title="No recently modified audit log files",
            severity="WARN",
            detail=(
                "Found {} audit log file(s) in {} but none modified in the last hour. "
                "Audit logging may have stalled or been disabled."
            ).format(len(log_files), audit_dir),
            remediation=(
                "Check auditd status and restart if needed:\n"
                "  sudo audit -s\n"
                "  sudo praudit -l /dev/auditpipe\n"
                "If no events appear, verify audit_control flags are set."
            ),
            category="service",
            platform="macos",
            evidence=evidence,
            mitre_techniques=["T1070.002"],
        )

    return CheckResult(
        check_id="MAC-BSM-003",
        title="Audit logs are current",
        severity="PASS",
        detail=(
            "{} audit log file(s) in {}, {} modified within the last hour."
        ).format(len(log_files), audit_dir, len(recent_files)),
        remediation="No action required.",
        category="service",
        platform="macos",
        evidence=evidence,
        mitre_techniques=["T1070.002"],
    )


def run_checks():
    """Return all macOS BSM audit checks. Returns empty list on non-macOS."""
    if get_os() != "macos":
        return []

    results = []
    results.append(_check_auditd_running())

    # _check_audit_control may return a list or single result
    control_result = _check_audit_control()
    if isinstance(control_result, list):
        results.extend(control_result)
    else:
        results.append(control_result)

    results.append(_check_audit_logs())
    return results
