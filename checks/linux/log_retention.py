"""Log retention estimation checks: auditd, journald, syslog, auth log capacity."""

import glob
import os
import re
import time

from core.result import CheckResult
from core.platform_utils import (
    safe_run, read_file_safe, file_exists, is_elevated,
    parse_config_file, get_file_mtime,
)


def _parse_size_to_mb(size_str):
    """Parse a size string like '500M', '1G', '50K' to megabytes."""
    if not size_str:
        return None
    size_str = size_str.strip()
    match = re.match(r'^(\d+(?:\.\d+)?)\s*([KMGTP]?)B?$', size_str, re.IGNORECASE)
    if not match:
        # Try plain number (bytes)
        try:
            return float(size_str) / (1024 * 1024)
        except ValueError:
            return None

    value = float(match.group(1))
    unit = match.group(2).upper()
    multipliers = {"": 1.0 / (1024 * 1024), "K": 1.0 / 1024, "M": 1.0, "G": 1024.0, "T": 1024 * 1024.0}
    return value * multipliers.get(unit, 1.0)


def _get_dir_size_mb(path):
    """Get total size of a directory in MB."""
    rc, out, _ = safe_run(["du", "-sm", path], timeout=10)
    if rc == 0 and out.strip():
        try:
            return float(out.strip().split()[0])
        except (ValueError, IndexError):
            pass
    return None


def _get_oldest_file_age_days(directory, pattern="*"):
    """Get the age in days of the oldest file matching pattern in directory."""
    oldest_mtime = None
    matched = glob.glob(os.path.join(directory, pattern))
    for fpath in matched:
        mtime = get_file_mtime(fpath)
        if mtime is not None:
            if oldest_mtime is None or mtime < oldest_mtime:
                oldest_mtime = mtime
    if oldest_mtime is not None:
        age_seconds = time.time() - oldest_mtime
        return max(age_seconds / 86400.0, 0.01)  # Avoid division by zero
    return None


def _check_combined_retention():
    """LINUX-RETENTION-001: Combined log retention estimate."""
    evidence = {}
    total_capacity_mb = 0.0
    total_current_size_mb = 0.0
    daily_rate_mb = None
    components = {}

    # --- Auditd ---
    auditd_conf = parse_config_file("/etc/audit/auditd.conf")
    audit_num_logs = 5  # default
    audit_max_file = 8  # default in MB
    try:
        audit_num_logs = int(auditd_conf.get("num_logs", "5"))
    except ValueError:
        pass
    try:
        audit_max_file = int(auditd_conf.get("max_log_file", "8"))
    except ValueError:
        pass

    audit_capacity_mb = audit_num_logs * audit_max_file
    total_capacity_mb += audit_capacity_mb
    components["auditd"] = {
        "num_logs": audit_num_logs,
        "max_log_file_mb": audit_max_file,
        "capacity_mb": audit_capacity_mb,
    }

    audit_dir = "/var/log/audit"
    if file_exists(audit_dir):
        audit_size = _get_dir_size_mb(audit_dir)
        if audit_size is not None:
            total_current_size_mb += audit_size
            components["auditd"]["current_size_mb"] = round(audit_size, 1)

        audit_age_days = _get_oldest_file_age_days(audit_dir, "audit.log*")
        if audit_age_days is not None:
            components["auditd"]["oldest_file_age_days"] = round(audit_age_days, 1)

    # --- Journald ---
    journald_conf = parse_config_file("/etc/systemd/journald.conf")
    # Also check drop-ins
    for dropin in sorted(glob.glob("/etc/systemd/journald.conf.d/*.conf")):
        override = parse_config_file(dropin)
        journald_conf.update(override)

    journal_max_use = journald_conf.get("SystemMaxUse", "")
    journal_capacity_mb = _parse_size_to_mb(journal_max_use)
    if journal_capacity_mb is None:
        # Default is ~10% of filesystem or 4G, use conservative estimate
        journal_capacity_mb = 500.0  # reasonable default assumption

    total_capacity_mb += journal_capacity_mb
    components["journald"] = {
        "SystemMaxUse": journal_max_use or "not set (using default)",
        "capacity_mb": round(journal_capacity_mb, 1),
    }

    journal_dir = "/var/log/journal"
    if file_exists(journal_dir):
        journal_size = _get_dir_size_mb(journal_dir)
        if journal_size is not None:
            total_current_size_mb += journal_size
            components["journald"]["current_size_mb"] = round(journal_size, 1)

    # --- Syslog ---
    syslog_path = None
    for candidate in ["/var/log/syslog", "/var/log/messages"]:
        if file_exists(candidate):
            syslog_path = candidate
            break

    if syslog_path:
        try:
            syslog_size_mb = os.path.getsize(syslog_path) / (1024 * 1024)
            total_current_size_mb += syslog_size_mb
            components["syslog"] = {
                "path": syslog_path,
                "current_size_mb": round(syslog_size_mb, 1),
            }
        except OSError:
            components["syslog"] = {"path": syslog_path, "current_size_mb": None}

        # Check logrotate config
        for lr_path in sorted(glob.glob("/etc/logrotate.d/*")):
            content = read_file_safe(lr_path)
            if content and ("syslog" in content.lower() or "messages" in content.lower()):
                rotate_match = re.search(r'rotate\s+(\d+)', content)
                frequency = "unknown"
                for freq in ["daily", "weekly", "monthly"]:
                    if freq in content:
                        frequency = freq
                        break
                rotate_count = int(rotate_match.group(1)) if rotate_match else None
                components["syslog"]["logrotate_rotate"] = rotate_count
                components["syslog"]["logrotate_frequency"] = frequency
                if rotate_count and syslog_size_mb:
                    syslog_capacity = syslog_size_mb * (rotate_count + 1)
                    total_capacity_mb += syslog_capacity
                    components["syslog"]["capacity_mb"] = round(syslog_capacity, 1)
                break

    # --- Auth log ---
    auth_path = None
    for candidate in ["/var/log/auth.log", "/var/log/secure"]:
        if file_exists(candidate):
            auth_path = candidate
            break

    if auth_path:
        try:
            auth_size_mb = os.path.getsize(auth_path) / (1024 * 1024)
            total_current_size_mb += auth_size_mb
            components["auth"] = {
                "path": auth_path,
                "current_size_mb": round(auth_size_mb, 1),
            }
        except OSError:
            components["auth"] = {"path": auth_path, "current_size_mb": None}

        for lr_path in sorted(glob.glob("/etc/logrotate.d/*")):
            content = read_file_safe(lr_path)
            if content and (
                "auth.log" in content or "secure" in content
            ):
                rotate_match = re.search(r'rotate\s+(\d+)', content)
                frequency = "unknown"
                for freq in ["daily", "weekly", "monthly"]:
                    if freq in content:
                        frequency = freq
                        break
                rotate_count = int(rotate_match.group(1)) if rotate_match else None
                components["auth"]["logrotate_rotate"] = rotate_count
                components["auth"]["logrotate_frequency"] = frequency
                if rotate_count and auth_size_mb:
                    auth_capacity = auth_size_mb * (rotate_count + 1)
                    total_capacity_mb += auth_capacity
                    components["auth"]["capacity_mb"] = round(auth_capacity, 1)
                break

    # --- Calculate estimated retention ---
    evidence["components"] = components
    evidence["total_capacity_mb"] = round(total_capacity_mb, 1)
    evidence["total_current_size_mb"] = round(total_current_size_mb, 1)

    # Estimate daily generation rate
    # Use the oldest audit log age if available
    audit_age = components.get("auditd", {}).get("oldest_file_age_days")
    if audit_age and total_current_size_mb > 0:
        daily_rate_mb = total_current_size_mb / audit_age
    elif total_current_size_mb > 0:
        # Fallback: assume current data represents about 7 days
        daily_rate_mb = total_current_size_mb / 7.0

    evidence["daily_rate_mb"] = round(daily_rate_mb, 2) if daily_rate_mb else None

    estimated_days = None
    if daily_rate_mb and daily_rate_mb > 0 and total_capacity_mb > 0:
        estimated_days = total_capacity_mb / daily_rate_mb
    evidence["estimated_retention_days"] = round(estimated_days, 1) if estimated_days else None

    if estimated_days is None:
        return CheckResult(
            check_id="LINUX-RETENTION-001",
            title="Unable to estimate log retention",
            severity="INFO",
            detail=(
                "This check estimates how many days of forensic history you have "
                "before the oldest events are overwritten. Log retention is the time "
                "window available for incident investigation -- if a breach is "
                "discovered 14 days after initial compromise but your logs only cover "
                "7 days, the earliest (and most critical) evidence of how the "
                "attacker got in is already gone. Industry best practice is 90 days "
                "minimum; many compliance frameworks require 1 year. This calculation "
                "combines auditd log rotation capacity, journald size limits, and "
                "syslog rotation settings to give you a realistic estimate. "
                "Insufficient data was available to calculate a retention estimate."
            ),
            remediation=(
                "Ensure auditd is running and generating logs so that retention "
                "can be estimated. Check that /var/log/audit/ exists and contains "
                "audit log files."
            ),
            category="config",
            platform="linux",
            evidence=evidence,
            mitre_techniques=["T1070.002"],
        )

    if estimated_days < 7:
        severity = "FAIL"
        title = "Log retention critically low ({:.0f} days estimated)".format(estimated_days)
        remediation_extra = (
            "Immediate actions to increase retention:\n"
            "  - Auditd: increase num_logs and max_log_file in /etc/audit/auditd.conf\n"
            "    Example: num_logs = 20, max_log_file = 50 (gives ~1GB capacity)\n"
            "  - Journald: set SystemMaxUse=2G in /etc/systemd/journald.conf\n"
            "  - Syslog: increase 'rotate' count in /etc/logrotate.d/ configs\n"
            "  - Consider compressed log rotation to maximize disk usage\n"
            "  - Forward logs to a centralized SIEM with longer retention"
        )
    elif estimated_days < 30:
        severity = "WARN"
        title = "Log retention below 30 days ({:.0f} days estimated)".format(estimated_days)
        remediation_extra = (
            "To increase retention towards the 30-90 day target:\n"
            "  - Auditd: increase num_logs in /etc/audit/auditd.conf (e.g., num_logs = 30)\n"
            "  - Journald: increase SystemMaxUse in /etc/systemd/journald.conf\n"
            "  - Syslog: increase 'rotate' count in logrotate configuration\n"
            "  - Forward logs to a centralized SIEM with longer retention"
        )
    else:
        severity = "PASS"
        title = "Log retention adequate ({:.0f} days estimated)".format(estimated_days)
        remediation_extra = (
            "No action required. For compliance with frameworks requiring 1 year "
            "retention, ensure logs are also forwarded to a centralized SIEM or "
            "archive with long-term storage."
        )

    return CheckResult(
        check_id="LINUX-RETENTION-001",
        title=title,
        severity=severity,
        detail=(
            "This check estimates how many days of forensic history you have "
            "before the oldest events are overwritten. Log retention is the time "
            "window available for incident investigation -- if a breach is "
            "discovered 14 days after initial compromise but your logs only cover "
            "7 days, the earliest (and most critical) evidence of how the "
            "attacker got in is already gone. Industry best practice is 90 days "
            "minimum; many compliance frameworks require 1 year. This calculation "
            "combines auditd log rotation capacity, journald size limits, and "
            "syslog rotation settings to give you a realistic estimate. "
            "Estimated retention: {:.0f} days based on {:.1f} MB/day generation "
            "rate and {:.0f} MB total configured capacity."
        ).format(estimated_days, daily_rate_mb, total_capacity_mb),
        remediation=remediation_extra,
        category="config",
        platform="linux",
        evidence=evidence,
        mitre_techniques=["T1070.002"],
    )


def run_checks():
    """Return all log retention checks."""
    return [
        _check_combined_retention(),
    ]
