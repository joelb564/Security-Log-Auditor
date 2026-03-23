"""Orchestrates checks, collects results into a Report."""

import platform
from datetime import datetime, timezone

from core.result import CheckResult, Report
from core.platform_utils import get_os, get_hostname, get_os_info, is_elevated
from core.suppression import load_suppressions, apply_suppressions


def run_all_checks(category_filter=None, severity_filter=None):
    """Run all applicable checks for the current platform and return a Report."""
    current_os = get_os()
    elevated = is_elevated()
    results = []

    # Platform-specific checks
    if current_os == "linux":
        results.extend(_run_linux_checks(category_filter))
    elif current_os == "windows":
        results.extend(_run_windows_checks(category_filter))
    elif current_os == "macos":
        results.extend(_run_macos_checks(category_filter))

    # Determine if any shipper was detected
    shipper_detected = any(
        r.severity == "PASS" and "shipper" in r.check_id.lower()
        for r in results
    )

    # Common checks (all platforms)
    if category_filter is None or category_filter in ("edr", "coverage"):
        results.extend(_run_common_checks(results, shipper_detected, category_filter))

    # Apply severity filter
    if severity_filter:
        severity_order = {"FAIL": 0, "WARN": 1, "INFO": 2, "PASS": 3, "SKIP": 4}
        threshold = severity_order.get(severity_filter, 4)
        results = [r for r in results if severity_order.get(r.severity, 4) <= threshold]

    report = Report(
        hostname=get_hostname(),
        os_info=get_os_info(),
        timestamp=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        is_elevated=elevated,
        results=results,
    )
    # Apply suppressions from .audit-suppress file
    suppressed_ids = load_suppressions()
    apply_suppressions(report.results, suppressed_ids)

    report.calculate_summary()
    report.calculate_health_score()
    return report


def _should_run(category_filter, *categories):
    if category_filter is None:
        return True
    return category_filter in categories


def _run_linux_checks(category_filter):
    results = []
    try:
        if _should_run(category_filter, "service"):
            from checks.linux.auditd_service import run_checks
            results.extend(run_checks())
    except Exception as e:
        results.append(_error_result("LINUX-AUDITD-ERR", "auditd_service module error", str(e), "linux"))

    try:
        if _should_run(category_filter, "config"):
            from checks.linux.auditd_config import run_checks
            results.extend(run_checks())
    except Exception as e:
        results.append(_error_result("LINUX-CONFIG-ERR", "auditd_config module error", str(e), "linux"))

    try:
        if _should_run(category_filter, "rules"):
            from checks.linux.auditd_rules import run_checks
            results.extend(run_checks())
    except Exception as e:
        results.append(_error_result("LINUX-RULES-ERR", "auditd_rules module error", str(e), "linux"))

    try:
        if _should_run(category_filter, "forwarding"):
            from checks.linux.syslog_forwarding import run_checks
            results.extend(run_checks())
    except Exception as e:
        results.append(_error_result("LINUX-SYSLOG-ERR", "syslog_forwarding module error", str(e), "linux"))

    try:
        if _should_run(category_filter, "config"):
            from checks.linux.journald import run_checks
            results.extend(run_checks())
    except Exception as e:
        results.append(_error_result("LINUX-JOURNALD-ERR", "journald module error", str(e), "linux"))

    try:
        if _should_run(category_filter, "config"):
            from checks.linux.auth_logs import run_checks
            results.extend(run_checks())
    except Exception as e:
        results.append(_error_result("LINUX-AUTH-ERR", "auth_logs module error", str(e), "linux"))

    try:
        if _should_run(category_filter, "forwarding"):
            from checks.linux.log_shipper import run_checks
            results.extend(run_checks())
    except Exception as e:
        results.append(_error_result("LINUX-SHIPPER-ERR", "log_shipper module error", str(e), "linux"))

    try:
        if _should_run(category_filter, "noise"):
            from checks.linux.noise_analysis import run_checks
            results.extend(run_checks())
    except Exception as e:
        results.append(_error_result("LINUX-NOISE-ERR", "noise_analysis module error", str(e), "linux"))

    try:
        if _should_run(category_filter, "config"):
            from checks.linux.log_retention import run_checks
            results.extend(run_checks())
    except Exception as e:
        results.append(_error_result("LINUX-RETENTION-ERR", "log_retention module error", str(e), "linux"))

    try:
        if _should_run(category_filter, "config"):
            from checks.linux.selinux_logging import run_checks
            results.extend(run_checks())
    except Exception as e:
        results.append(_error_result("LINUX-SELINUX-ERR", "selinux_logging module error", str(e), "linux"))

    try:
        if _should_run(category_filter, "config"):
            from checks.linux.ntp_logging import run_checks
            results.extend(run_checks())
    except Exception as e:
        results.append(_error_result("LINUX-NTP-ERR", "ntp_logging module error", str(e), "linux"))

    try:
        if _should_run(category_filter, "config"):
            from checks.linux.firewall_logging import run_checks
            results.extend(run_checks())
    except Exception as e:
        results.append(_error_result("LINUX-FW-ERR", "firewall_logging module error", str(e), "linux"))

    try:
        if _should_run(category_filter, "service"):
            from checks.linux.fim_detection import run_checks
            results.extend(run_checks())
    except Exception as e:
        results.append(_error_result("LINUX-FIM-ERR", "fim_detection module error", str(e), "linux"))

    return results


def _run_windows_checks(category_filter):
    results = []
    try:
        if _should_run(category_filter, "config"):
            from checks.windows.audit_policy import run_checks
            results.extend(run_checks())
    except Exception as e:
        results.append(_error_result("WIN-AUDIT-ERR", "audit_policy module error", str(e), "windows"))

    try:
        if _should_run(category_filter, "config"):
            from checks.windows.event_log_config import run_checks
            results.extend(run_checks())
    except Exception as e:
        results.append(_error_result("WIN-EVTLOG-ERR", "event_log_config module error", str(e), "windows"))

    try:
        if _should_run(category_filter, "config"):
            from checks.windows.powershell_logging import run_checks
            results.extend(run_checks())
    except Exception as e:
        results.append(_error_result("WIN-PS-ERR", "powershell_logging module error", str(e), "windows"))

    try:
        if _should_run(category_filter, "service"):
            from checks.windows.sysmon import run_checks
            results.extend(run_checks())
    except Exception as e:
        results.append(_error_result("WIN-SYSMON-ERR", "sysmon module error", str(e), "windows"))

    try:
        if _should_run(category_filter, "forwarding"):
            from checks.windows.log_shipper import run_checks
            results.extend(run_checks())
    except Exception as e:
        results.append(_error_result("WIN-SHIPPER-ERR", "log_shipper module error", str(e), "windows"))

    try:
        if _should_run(category_filter, "noise"):
            from checks.windows.noise_analysis import run_checks
            results.extend(run_checks())
    except Exception as e:
        results.append(_error_result("WIN-NOISE-ERR", "noise_analysis module error", str(e), "windows"))

    return results


def _run_macos_checks(category_filter):
    results = []
    try:
        if _should_run(category_filter, "config"):
            from checks.macos.bsm_audit import run_checks
            results.extend(run_checks())
    except Exception as e:
        results.append(_error_result("MAC-BSM-ERR", "bsm_audit module error", str(e), "macos"))

    try:
        if _should_run(category_filter, "config"):
            from checks.macos.uls import run_checks
            results.extend(run_checks())
    except Exception as e:
        results.append(_error_result("MAC-ULS-ERR", "uls module error", str(e), "macos"))

    try:
        if _should_run(category_filter, "forwarding"):
            from checks.macos.log_shipper import run_checks
            results.extend(run_checks())
    except Exception as e:
        results.append(_error_result("MAC-SHIPPER-ERR", "log_shipper module error", str(e), "macos"))

    try:
        if _should_run(category_filter, "noise"):
            from checks.macos.noise_analysis import run_checks
            results.extend(run_checks())
    except Exception as e:
        results.append(_error_result("MAC-NOISE-ERR", "noise_analysis module error", str(e), "macos"))

    return results


def _run_common_checks(all_results, shipper_detected, category_filter):
    results = []
    try:
        if _should_run(category_filter, "edr"):
            from common.edr_detection import run_checks
            results.extend(run_checks(shipper_detected=shipper_detected))
    except Exception as e:
        results.append(_error_result("ALL-EDR-ERR", "edr_detection module error", str(e), "all"))

    try:
        if _should_run(category_filter, "coverage"):
            from common.coverage_matrix import run_checks
            combined = all_results + results
            results.extend(run_checks(combined))
    except Exception as e:
        results.append(_error_result("ALL-COV-ERR", "coverage_matrix module error", str(e), "all"))

    return results


def _error_result(check_id, title, error, plat):
    return CheckResult(
        check_id=check_id,
        title=title,
        severity="SKIP",
        detail="Module failed to execute: {}".format(error),
        remediation="Check that all module dependencies are available.",
        category="service",
        platform=plat,
        evidence={"error": error},
    )


def list_all_checks():
    """Return a list of (check_id, title, platform) tuples for all known checks."""
    checks = []
    # Linux checks
    checks.extend([
        ("LINUX-AUDITD-001", "auditd installed", "linux"),
        ("LINUX-AUDITD-002", "auditd service running", "linux"),
        ("LINUX-AUDITD-003", "auditd enabled at boot", "linux"),
        ("LINUX-AUDITD-013", "Kernel audit subsystem status", "linux"),
        ("LINUX-AUDITD-004", "Audit backlog buffer size", "linux"),
        ("LINUX-AUDITD-005", "disk_full_action configuration", "linux"),
        ("LINUX-AUDITD-006", "Log rotation configuration", "linux"),
        ("LINUX-AUDITD-007", "Immutable mode (-e 2)", "linux"),
        ("LINUX-AUDITD-008", "log_format ENRICHED", "linux"),
        ("LINUX-AUDITD-009", "space_left early warning", "linux"),
        ("LINUX-AUDITD-010", "max_log_file_action", "linux"),
        ("LINUX-AUDITD-011", "name_format hostname embedding", "linux"),
        ("LINUX-AUDITD-012", "freq flush frequency", "linux"),
        ("LINUX-AUDITD-014", "Audit log file permissions", "linux"),
        ("LINUX-RULES-001", "execve syscall monitoring", "linux"),
        ("LINUX-RULES-002", "Privileged command monitoring", "linux"),
        ("LINUX-RULES-003", "Critical file watches", "linux"),
        ("LINUX-RULES-004", "Cron monitoring", "linux"),
        ("LINUX-RULES-005", "Module load/unload monitoring", "linux"),
        ("LINUX-RULES-006", "Network configuration changes", "linux"),
        ("LINUX-RULES-007", "Time change monitoring", "linux"),
        ("LINUX-RULES-008", "User/group management syscalls", "linux"),
        ("LINUX-RULES-009", "Rule key coverage", "linux"),
        ("LINUX-RULES-010", "Architecture coverage consistency", "linux"),
        ("LINUX-RULES-011", "LD_PRELOAD file watches", "linux"),
        ("LINUX-RULES-012", "ptrace syscall monitoring", "linux"),
        ("LINUX-RULES-013", "mount/umount syscall monitoring", "linux"),
        ("LINUX-RULES-014", "Permission change syscalls", "linux"),
        ("LINUX-RULES-015", "File deletion syscalls", "linux"),
        ("LINUX-RULES-016", "Execution from temp directories", "linux"),
        ("LINUX-SYSLOG-001", "rsyslog/syslog-ng service", "linux"),
        ("LINUX-SYSLOG-002", "Remote forwarding configured", "linux"),
        ("LINUX-SYSLOG-003", "auth/security facility forwarding", "linux"),
        ("LINUX-SYSLOG-004", "TLS encryption on forwarding", "linux"),
        ("LINUX-SYSLOG-005", "Queue/buffer configuration", "linux"),
        ("LINUX-SYSLOG-006", "Forwarding health check", "linux"),
        ("LINUX-JOURNALD-001", "Persistent storage enabled", "linux"),
        ("LINUX-JOURNALD-002", "ForwardToSyslog", "linux"),
        ("LINUX-JOURNALD-003", "Journal size limits", "linux"),
        ("LINUX-JOURNALD-004", "Rate limiting configuration", "linux"),
        ("LINUX-JOURNALD-005", "Forward sealing (Seal)", "linux"),
        ("LINUX-AUTH-001", "Auth log file health", "linux"),
        ("LINUX-AUTH-002", "SSH logging level", "linux"),
        ("LINUX-AUTH-003", "Failed auth log presence", "linux"),
        ("LINUX-AUTH-004", "sshd_config drop-in overrides", "linux"),
        ("LINUX-AUTH-005", "wtmp/btmp/lastlog health", "linux"),
        ("LINUX-AUTH-006", "login.defs logging settings", "linux"),
        ("LINUX-SHIPPER-001", "Splunk Universal Forwarder (Linux)", "linux"),
        ("LINUX-SHIPPER-002", "Filebeat / Elastic Agent", "linux"),
        ("LINUX-SHIPPER-003", "Any shipper detected (Linux)", "linux"),
        ("LINUX-SHIPPER-006", "NXLog detection and config", "linux"),
        ("LINUX-SHIPPER-004", "Shipper connection health", "linux"),
        ("LINUX-SHIPPER-005", "Critical log input coverage", "linux"),
        ("LINUX-NOISE-001", "auid=unset filter on execve", "linux"),
        ("LINUX-NOISE-002", "Broad /tmp watches", "linux"),
        ("LINUX-NOISE-003", "System process execve noise", "linux"),
        ("LINUX-NOISE-004", "Duplicate syslog/auditd forwarding", "linux"),
        ("LINUX-NOISE-005", "aureport summary statistics", "linux"),
        ("LINUX-NOISE-006", "High-volume event type detection", "linux"),
        ("LINUX-RETENTION-001", "Combined log retention estimate", "linux"),
        ("LINUX-SELINUX-001", "SELinux audit logging status", "linux"),
        ("LINUX-NTP-001", "Time synchronization health", "linux"),
        ("LINUX-FW-001", "Firewall logging configuration", "linux"),
        ("LINUX-FIM-001", "File Integrity Monitoring presence", "linux"),
    ])
    # Windows checks
    checks.extend([
        ("WIN-AUDIT-001", "Credential Validation audit policy", "windows"),
        ("WIN-AUDIT-002", "Kerberos Authentication audit policy", "windows"),
        ("WIN-AUDIT-003", "Logon/Logoff audit policy", "windows"),
        ("WIN-AUDIT-004", "Process Creation audit policy", "windows"),
        ("WIN-AUDIT-005", "Account Management audit policy", "windows"),
        ("WIN-AUDIT-006", "Policy Change audit policy", "windows"),
        ("WIN-AUDIT-007", "Privilege Use audit policy", "windows"),
        ("WIN-AUDIT-008", "Object Access audit policy", "windows"),
        ("WIN-AUDIT-009", "System events audit policy", "windows"),
        ("WIN-AUDIT-010", "Detailed Tracking audit policy", "windows"),
        ("WIN-EVTLOG-001", "Security log maximum size", "windows"),
        ("WIN-EVTLOG-002", "Security log retention policy", "windows"),
        ("WIN-EVTLOG-003", "PowerShell Operational log size", "windows"),
        ("WIN-EVTLOG-004", "Key channels enabled", "windows"),
        ("WIN-EVTLOG-005", "Log fill rate estimation", "windows"),
        ("WIN-PS-001", "PowerShell Script Block Logging", "windows"),
        ("WIN-PS-002", "PowerShell Module Logging", "windows"),
        ("WIN-PS-003", "PowerShell Transcription", "windows"),
        ("WIN-PS-004", "PowerShell v2 presence", "windows"),
        ("WIN-SYSMON-001", "Sysmon installed", "windows"),
        ("WIN-SYSMON-002", "Sysmon configuration quality", "windows"),
        ("WIN-SYSMON-003", "Sysmon log channel size", "windows"),
        ("WIN-SHIPPER-001", "Splunk Universal Forwarder (Windows)", "windows"),
        ("WIN-SHIPPER-002", "Winlogbeat", "windows"),
        ("WIN-SHIPPER-003", "Any shipper detected (Windows)", "windows"),
        ("WIN-NOISE-001", "4634 Logoff filtering", "windows"),
        ("WIN-NOISE-002", "4658/4690 Handle events", "windows"),
        ("WIN-NOISE-003", "5156/5158 WFP connection events", "windows"),
        ("WIN-NOISE-004", "4703 Token right adjusted", "windows"),
    ])
    # macOS checks
    checks.extend([
        ("MAC-BSM-001", "auditd running (macOS)", "macos"),
        ("MAC-BSM-002", "audit_control configuration", "macos"),
        ("MAC-BSM-003", "Audit log location and size", "macos"),
        ("MAC-ULS-001", "Unified logging system operational", "macos"),
        ("MAC-ULS-002", "Security-relevant ULS subsystems", "macos"),
        ("MAC-ULS-003", "osquery presence and configuration", "macos"),
        ("MAC-SHIPPER-001", "Splunk Universal Forwarder (macOS)", "macos"),
        ("MAC-SHIPPER-002", "Filebeat (macOS)", "macos"),
        ("MAC-NOISE-001", "ULS volume assessment", "macos"),
    ])
    # Common checks
    checks.extend([
        ("ALL-EDR-001", "EDR presence", "all"),
        ("ALL-EDR-002", "S1 Cloud Funnel gap analysis", "all"),
        ("ALL-EDR-003", "MDE audit policy dependency", "windows"),
        ("ALL-EDR-004", "EDR detected but no SIEM forwarder", "all"),
        ("ALL-COVERAGE-*", "MITRE ATT&CK coverage matrix (12 tactics)", "all"),
    ])
    return checks
