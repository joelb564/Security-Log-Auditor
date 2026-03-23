"""Windows Event Log configuration checks via wevtutil."""

import platform
import re

from core.result import CheckResult
from core.platform_utils import safe_run, read_file_safe, file_exists, is_elevated, check_process_running


def _is_windows():
    return platform.system() == "Windows"


def _parse_wevtutil_output(output):
    """Parse wevtutil gl output into a dict of key-value pairs.

    wevtutil gl outputs lines like:
      name: Security
      enabled: true
      type: Admin
      maxSize: 20971520
      retention: false
    """
    result = {}
    for line in output.splitlines():
        line = line.strip()
        if ":" in line:
            key, _, value = line.partition(":")
            result[key.strip().lower()] = value.strip()
    return result


def _get_log_config(channel):
    """Get event log configuration for a channel. Returns (config_dict, raw_output) or (None, error)."""
    rc, out, err = safe_run(["wevtutil", "gl", channel], timeout=10)
    if rc != 0:
        return None, err or "wevtutil gl failed for {}".format(channel)
    config = _parse_wevtutil_output(out)
    return config, out


def _bytes_to_mb(byte_val):
    """Convert bytes to megabytes."""
    try:
        return int(byte_val) / (1024 * 1024)
    except (ValueError, TypeError):
        return 0


def _check_security_log_size():
    """WIN-EVTLOG-001: Security log maximum size."""
    check_id = "WIN-EVTLOG-001"
    title_base = "Security Log Maximum Size"

    config, raw = _get_log_config("Security")
    if config is None:
        return CheckResult(
            check_id=check_id,
            title="{} - Cannot Check".format(title_base),
            severity="SKIP",
            detail="Could not retrieve Security log config: {}".format(raw),
            remediation="Ensure wevtutil is available and you are running as Administrator.",
            category="config",
            platform="windows",
            evidence={"error": raw},
        )

    max_size_bytes = config.get("maxsize", "0")
    max_size_mb = _bytes_to_mb(max_size_bytes)
    evidence = {"maxsize_bytes": max_size_bytes, "maxsize_mb": max_size_mb, "raw_config": raw}

    if max_size_mb >= 1024:
        return CheckResult(
            check_id=check_id,
            title="{} - Adequate ({:.0f} MB)".format(title_base, max_size_mb),
            severity="PASS",
            detail="Security log max size is {:.0f} MB (>= 1 GB recommended).".format(max_size_mb),
            remediation="No action required.",
            category="config",
            platform="windows",
            evidence=evidence,
        )

    if max_size_mb >= 256:
        return CheckResult(
            check_id=check_id,
            title="{} - Below Recommended ({:.0f} MB)".format(title_base, max_size_mb),
            severity="WARN",
            detail="Security log max size is {:.0f} MB. Recommended minimum is 1 GB "
                   "for adequate retention.".format(max_size_mb),
            remediation='wevtutil sl Security /ms:1073741824\n\n'
                        'Or via Group Policy:\n'
                        '  Computer Configuration > Administrative Templates > '
                        'Windows Components > Event Log Service > Security > '
                        'Specify the maximum log file size (KB) = 1048576',
            category="config",
            platform="windows",
            evidence=evidence,
        )

    return CheckResult(
        check_id=check_id,
        title="{} - Too Small ({:.0f} MB)".format(title_base, max_size_mb),
        severity="FAIL",
        detail="Security log max size is only {:.0f} MB. This is critically small and "
               "events will be overwritten rapidly. Minimum 256 MB required, 1 GB recommended.".format(max_size_mb),
        remediation='wevtutil sl Security /ms:1073741824\n\n'
                    'Or via Group Policy:\n'
                    '  Computer Configuration > Administrative Templates > '
                    'Windows Components > Event Log Service > Security > '
                    '  Specify the maximum log file size (KB) = 1048576',
        category="config",
        platform="windows",
        evidence=evidence,
    )


def _check_security_log_retention():
    """WIN-EVTLOG-002: Security log retention policy."""
    check_id = "WIN-EVTLOG-002"
    title_base = "Security Log Retention Policy"

    config, raw = _get_log_config("Security")
    if config is None:
        return CheckResult(
            check_id=check_id,
            title="{} - Cannot Check".format(title_base),
            severity="SKIP",
            detail="Could not retrieve Security log config: {}".format(raw),
            remediation="Ensure wevtutil is available and you are running as Administrator.",
            category="config",
            platform="windows",
            evidence={"error": raw},
        )

    retention = config.get("retention", "unknown")
    evidence = {"retention": retention, "raw_config": raw}

    # retention: false means overwrite-as-needed (circular), true means do-not-overwrite
    if retention.lower() == "false":
        return CheckResult(
            check_id=check_id,
            title="{} - Overwrite Mode".format(title_base),
            severity="WARN",
            detail="Security log is set to overwrite events as needed (retention=false). "
                   "Old events will be lost when the log is full. Ensure log size is "
                   "adequate and logs are forwarded to a SIEM.",
            remediation="If not forwarding logs, consider enabling retention:\n"
                        "  wevtutil sl Security /rt:true\n\n"
                        "Better approach: ensure log forwarding is active and increase log size:\n"
                        "  wevtutil sl Security /ms:1073741824",
            category="config",
            platform="windows",
            evidence=evidence,
        )

    return CheckResult(
        check_id=check_id,
        title="{} - Retention Enabled".format(title_base),
        severity="PASS",
        detail="Security log retention is enabled. Events will not be overwritten.",
        remediation="No action required. Note: if the log fills up with retention=true, "
                    "new events may be dropped. Ensure log forwarding and adequate size.",
        category="config",
        platform="windows",
        evidence=evidence,
    )


def _check_powershell_log_size():
    """WIN-EVTLOG-003: PowerShell Operational log size."""
    check_id = "WIN-EVTLOG-003"
    title_base = "PowerShell Operational Log Size"
    channel = "Microsoft-Windows-PowerShell/Operational"

    config, raw = _get_log_config(channel)
    if config is None:
        return CheckResult(
            check_id=check_id,
            title="{} - Cannot Check".format(title_base),
            severity="SKIP",
            detail="Could not retrieve PowerShell Operational log config: {}".format(raw),
            remediation="Ensure the PowerShell Operational log channel exists.",
            category="config",
            platform="windows",
            evidence={"error": raw},
        )

    max_size_bytes = config.get("maxsize", "0")
    max_size_mb = _bytes_to_mb(max_size_bytes)
    evidence = {"channel": channel, "maxsize_bytes": max_size_bytes, "maxsize_mb": max_size_mb,
                "raw_config": raw}

    if max_size_mb >= 100:
        return CheckResult(
            check_id=check_id,
            title="{} - Adequate ({:.0f} MB)".format(title_base, max_size_mb),
            severity="PASS",
            detail="PowerShell Operational log is {:.0f} MB (>= 100 MB).".format(max_size_mb),
            remediation="No action required.",
            category="config",
            platform="windows",
            evidence=evidence,
        )

    return CheckResult(
        check_id=check_id,
        title="{} - Too Small ({:.0f} MB)".format(title_base, max_size_mb),
        severity="WARN",
        detail="PowerShell Operational log is only {:.0f} MB. With Script Block Logging enabled, "
               "this fills quickly. Recommend at least 100 MB.".format(max_size_mb),
        remediation='wevtutil sl "Microsoft-Windows-PowerShell/Operational" /ms:104857600',
        category="config",
        platform="windows",
        evidence=evidence,
    )


def _check_key_channels_enabled():
    """WIN-EVTLOG-004: Key event log channels are enabled."""
    check_id = "WIN-EVTLOG-004"
    title_base = "Key Event Log Channels"

    channels = [
        "Security",
        "System",
        "Application",
        "Microsoft-Windows-PowerShell/Operational",
        "Microsoft-Windows-Sysmon/Operational",
        "Microsoft-Windows-WMI-Activity/Operational",
        "Microsoft-Windows-TaskScheduler/Operational",
        "Microsoft-Windows-Windows Defender/Operational",
    ]

    evidence = {}
    enabled = []
    disabled = []
    not_found = []

    for channel in channels:
        config, raw = _get_log_config(channel)
        if config is None:
            not_found.append(channel)
            evidence[channel] = "not found"
        else:
            is_enabled = config.get("enabled", "false").lower() == "true"
            evidence[channel] = "enabled" if is_enabled else "disabled"
            if is_enabled:
                enabled.append(channel)
            else:
                disabled.append(channel)

    remediation_cmds = []
    for ch in disabled:
        remediation_cmds.append('wevtutil sl "{}" /e:true'.format(ch))

    if not disabled:
        severity = "PASS"
        detail = "All available key channels are enabled ({} of {} found and enabled).".format(
            len(enabled), len(channels))
        if not_found:
            detail += " Not installed: {}".format(", ".join(not_found))
        remediation = "No action required."
    else:
        severity = "WARN"
        detail = "Disabled channels: {}".format(", ".join(disabled))
        if not_found:
            detail += ". Not installed: {}".format(", ".join(not_found))
        remediation = "\n".join(remediation_cmds)

    return CheckResult(
        check_id=check_id,
        title="{} - {}".format(title_base, severity),
        severity=severity,
        detail=detail,
        remediation=remediation,
        category="config",
        platform="windows",
        evidence=evidence,
    )


def _check_log_fill_rate():
    """WIN-EVTLOG-005: Security log fill rate estimation."""
    check_id = "WIN-EVTLOG-005"
    title_base = "Security Log Fill Rate"

    # Get current log info
    config, raw = _get_log_config("Security")
    if config is None:
        return CheckResult(
            check_id=check_id,
            title="{} - Cannot Check".format(title_base),
            severity="SKIP",
            detail="Could not retrieve Security log config.",
            remediation="Ensure wevtutil is available.",
            category="config",
            platform="windows",
            evidence={"error": raw},
        )

    max_size_bytes = config.get("maxsize", "0")
    evidence = {"maxsize_bytes": max_size_bytes, "raw_config": raw}

    # Use wevtutil to get log file size info
    rc, out, err = safe_run(["wevtutil", "gli", "Security"], timeout=10)
    if rc != 0:
        return CheckResult(
            check_id=check_id,
            title="{} - Cannot Estimate".format(title_base),
            severity="INFO",
            detail="Could not retrieve Security log info for fill rate estimation.",
            remediation="No action required.",
            category="config",
            platform="windows",
            evidence=evidence,
        )

    gli_data = _parse_wevtutil_output(out)
    evidence["gli_output"] = out

    # Try to extract number of records and file size
    num_records = gli_data.get("numberoflogrecords", "unknown")
    file_size = gli_data.get("filesize", "0")
    evidence["number_of_records"] = num_records
    evidence["current_filesize"] = file_size

    try:
        current_mb = int(file_size) / (1024 * 1024)
        max_mb = _bytes_to_mb(max_size_bytes)
        fill_pct = (current_mb / max_mb * 100) if max_mb > 0 else 0
        evidence["fill_percentage"] = "{:.1f}%".format(fill_pct)
    except (ValueError, TypeError, ZeroDivisionError):
        fill_pct = 0

    if fill_pct > 90:
        severity = "WARN"
        detail = "Security log is {:.1f}% full ({} records). Log may wrap soon, " \
                 "potentially losing events.".format(fill_pct, num_records)
        remediation = "Increase log size: wevtutil sl Security /ms:1073741824\n" \
                      "Or archive and clear: wevtutil cl Security /bu:Security_backup.evtx"
    elif fill_pct > 75:
        severity = "INFO"
        detail = "Security log is {:.1f}% full ({} records).".format(fill_pct, num_records)
        remediation = "Monitor log fill rate. Consider increasing log size if fill rate is high."
    else:
        severity = "PASS"
        detail = "Security log is {:.1f}% full ({} records). Adequate headroom.".format(
            fill_pct, num_records)
        remediation = "No action required."

    return CheckResult(
        check_id=check_id,
        title="{} - {:.0f}% Full".format(title_base, fill_pct),
        severity=severity,
        detail=detail,
        remediation=remediation,
        category="config",
        platform="windows",
        evidence=evidence,
    )


def run_checks():
    """Return all Windows event log configuration checks."""
    if not _is_windows():
        return []

    if not is_elevated():
        return [CheckResult(
            check_id="WIN-EVTLOG-001",
            title="Event Log Config Checks - Elevation Required",
            severity="SKIP",
            detail="Event log configuration checks require administrator privileges.",
            remediation="Re-run this tool as Administrator.",
            category="config",
            platform="windows",
            evidence={},
        )]

    return [
        _check_security_log_size(),
        _check_security_log_retention(),
        _check_powershell_log_size(),
        _check_key_channels_enabled(),
        _check_log_fill_rate(),
    ]
