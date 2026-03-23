"""Auditd configuration checks: backlog, disk actions, rotation, immutable mode."""

import glob
import os
import re
import stat

from core.result import CheckResult
from core.platform_utils import (
    safe_run, read_file_safe, file_exists, is_elevated,
    get_package_manager, parse_config_file, get_file_mtime,
    check_process_running, get_linux_distro,
)
from checks.linux.utils import read_all_rules


def _read_all_rules():
    """Read all audit rule lines from rules.d and audit.rules."""
    lines, _ = read_all_rules()
    return lines


def _check_backlog_buffer():
    """LINUX-AUDITD-004: Is the audit backlog buffer adequate?"""
    evidence = {}
    lines = _read_all_rules()
    backlog_value = None

    for line in lines:
        match = re.search(r'-b\s+(\d+)', line)
        if match:
            backlog_value = int(match.group(1))

    evidence["backlog_value"] = backlog_value
    evidence["rule_files_checked"] = glob.glob("/etc/audit/rules.d/*.rules") + (
        ["/etc/audit/audit.rules"] if file_exists("/etc/audit/audit.rules") else []
    )

    if backlog_value is None:
        return CheckResult(
            check_id="LINUX-AUDITD-004",
            title="Audit backlog buffer not configured",
            severity="FAIL",
            detail="The audit backlog buffer is a kernel-space queue that temporarily holds audit "
                   "events before the auditd daemon reads and writes them to disk. When the system "
                   "generates audit events faster than auditd can process them (e.g., during a burst "
                   "of process executions or file accesses), events queue up in this buffer. No -b "
                   "(backlog buffer) directive was found in any audit rules file. The kernel default "
                   "is typically just 64 entries, which is far too small for any production workload. "
                   "At this size, even routine system activity like a package update or service restart "
                   "can overflow the buffer, causing audit events to be silently dropped -- meaning "
                   "security-relevant actions will go unrecorded with no warning.",
            remediation="Add a backlog buffer directive to your base audit rules file. This sets the "
                        "kernel queue size to 16384 entries, which provides adequate headroom for most "
                        "production systems:\n"
                        "  -b 16384\n"
                        "Add this to /etc/audit/rules.d/00-base.rules, then reload the rules:\n"
                        "  sudo augenrules --load\n"
                        "The augenrules command merges all files in rules.d/ into the active rule set. "
                        "If you experience 'audit: backlog limit exceeded' messages in dmesg on very "
                        "busy systems, increase this value further (32768 or higher).",
            category="config",
            platform="linux",
            evidence=evidence,
            mitre_techniques=["T1562.001"],
        )

    if backlog_value < 8192:
        return CheckResult(
            check_id="LINUX-AUDITD-004",
            title="Audit backlog buffer too small",
            severity="FAIL",
            detail="The audit backlog buffer is a kernel-space queue that temporarily holds audit "
                   "events before the auditd daemon reads and writes them to disk. The current buffer "
                   "size is {} entries (minimum recommended: 8192). When the system generates events "
                   "faster than auditd can write them -- such as during service restarts, batch jobs, "
                   "or a burst of network connections -- a small buffer will overflow. Overflowed events "
                   "are silently dropped by the kernel, creating gaps in the audit trail. An attacker "
                   "could deliberately generate a flood of benign events to overflow the buffer and "
                   "hide their malicious actions in the resulting gaps.".format(backlog_value),
            remediation="Increase the backlog buffer to at least 16384 entries. Edit the -b value in "
                        "your audit rules (typically in /etc/audit/rules.d/00-base.rules):\n"
                        "  -b 16384\n"
                        "Then reload the rules into the kernel:\n"
                        "  sudo augenrules --load\n"
                        "This change takes effect immediately without restarting auditd. The buffer "
                        "consumes a small amount of kernel memory (roughly 16KB per 1000 entries), "
                        "so even large values have negligible memory impact on modern systems.",
            category="config",
            platform="linux",
            evidence=evidence,
            mitre_techniques=["T1562.001"],
        )

    if backlog_value < 16384:
        return CheckResult(
            check_id="LINUX-AUDITD-004",
            title="Audit backlog buffer adequate but could be larger",
            severity="WARN",
            detail="The audit backlog buffer is a kernel-space queue that temporarily holds audit "
                   "events before the auditd daemon reads and writes them to disk. The current buffer "
                   "size is {} entries, which is adequate for light workloads but may not handle peak "
                   "bursts on busy systems. A value of 16384 or higher is recommended for servers "
                   "running multiple services, handling high request volumes, or with extensive audit "
                   "rule sets. If the buffer overflows, audit events are silently dropped by the "
                   "kernel, creating invisible gaps in the security record.".format(backlog_value),
            remediation="Consider increasing to 16384 entries for better headroom during event bursts. "
                        "Edit the -b value in your audit rules:\n"
                        "  -b 16384\n"
                        "Then reload:\n"
                        "  sudo augenrules --load\n"
                        "This is a low-risk change -- the additional kernel memory usage is negligible "
                        "(a few extra kilobytes), and there are no performance downsides to a larger buffer.",
            category="config",
            platform="linux",
            evidence=evidence,
            mitre_techniques=["T1562.001"],
        )

    return CheckResult(
        check_id="LINUX-AUDITD-004",
        title="Audit backlog buffer adequate",
        severity="PASS",
        detail="The audit backlog buffer is a kernel-space queue that temporarily holds audit events "
               "before the auditd daemon reads and writes them to disk. The current buffer is set to "
               "{} entries (>= 16384), which provides sufficient headroom to handle event bursts from "
               "service restarts, batch jobs, or high-activity periods without silently dropping "
               "events.".format(backlog_value),
        remediation="No action required.",
        category="config",
        platform="linux",
        evidence=evidence,
        mitre_techniques=["T1562.001"],
    )


def _check_disk_full_action():
    """LINUX-AUDITD-005: What is the disk_full_action?"""
    evidence = {}
    conf_path = "/etc/audit/auditd.conf"
    config = parse_config_file(conf_path)

    disk_full = config.get("disk_full_action", "").upper()
    admin_space = config.get("admin_space_left_action", "").upper()
    evidence["disk_full_action"] = disk_full or "not set"
    evidence["admin_space_left_action"] = admin_space or "not set"
    evidence["config_file"] = conf_path

    if not disk_full and not admin_space:
        if not file_exists(conf_path):
            return CheckResult(
                check_id="LINUX-AUDITD-005",
                title="Auditd config file not found",
                severity="FAIL",
                detail="The disk_full_action and admin_space_left_action settings control what auditd "
                       "does when disk space runs out -- this is a critical security decision because an "
                       "attacker can deliberately fill a disk to stop audit logging. Cannot read {} -- "
                       "auditd may not be installed or the configuration file is missing.".format(conf_path),
                remediation="Install auditd and ensure {} exists. The installer creates this file with "
                            "default settings. Without it, auditd cannot run and no audit events will "
                            "be recorded.".format(conf_path),
                category="config",
                platform="linux",
                evidence=evidence,
                mitre_techniques=["T1562.001"],
            )

    dangerous = {"IGNORE"}
    cautious = {"SUSPEND"}
    safe_actions = {"SYSLOG", "ROTATE", "SINGLE", "HALT", "EXEC", "EMAIL"}

    issues = []
    severity = "PASS"

    for label, value in [("disk_full_action", disk_full), ("admin_space_left_action", admin_space)]:
        if value in dangerous:
            issues.append(
                "{} is set to IGNORE -- this is the worst possible setting. When the disk is full, "
                "audit events will be silently discarded with no notification. An attacker who fills "
                "the disk (or waits for it to fill naturally) gets a complete audit blind spot while "
                "the system continues running normally.".format(label))
            severity = "FAIL"
        elif value in cautious:
            issues.append(
                "{} is set to SUSPEND -- when disk space runs out, auditd will stop writing audit "
                "events but the system will continue running. This is better than IGNORE (at least "
                "the suspension is logged), but an attacker who can fill the disk can blind the audit "
                "system while keeping the system operational for further exploitation.".format(label))
            if severity != "FAIL":
                severity = "WARN"
        elif value and value not in safe_actions:
            issues.append("{} is set to '{}' (unknown action -- cannot verify this is safe).".format(label, value))
            if severity != "FAIL":
                severity = "WARN"

    if severity == "PASS":
        return CheckResult(
            check_id="LINUX-AUDITD-005",
            title="Disk full actions are safe",
            severity="PASS",
            detail="The disk_full_action and admin_space_left_action settings control what auditd does "
                   "when disk space runs low or runs out. This matters because an attacker can deliberately "
                   "fill the audit partition to stop logging. Currently: disk_full_action={}, "
                   "admin_space_left_action={}. Both are set to acceptable values that will either alert "
                   "administrators, rotate logs, or halt the system rather than silently dropping audit "
                   "events.".format(disk_full or "default", admin_space or "default"),
            remediation="No action required.",
            category="config",
            platform="linux",
            evidence=evidence,
            mitre_techniques=["T1562.001"],
        )

    return CheckResult(
        check_id="LINUX-AUDITD-005",
        title="Disk full action configuration concern",
        severity=severity,
        detail=" ".join(issues) + " For context, the available options represent a trade-off matrix: "
               "IGNORE silently drops events (worst -- attacker wins); SUSPEND stops logging but the "
               "system keeps running (attacker can fill disk to blind audit); SINGLE drops to single-user "
               "mode (protective but disruptive); HALT shuts down the system entirely (most secure for "
               "audit integrity but creates a denial-of-service risk if an attacker can trigger it); "
               "SYSLOG/EMAIL alert administrators while continuing to attempt logging.",
        remediation="Edit {} and set these values to protect audit integrity:\n"
                    "  disk_full_action = HALT\n"
                    "  admin_space_left_action = SINGLE\n"
                    "Then restart auditd:\n"
                    "  sudo systemctl restart auditd\n"
                    "HALT ensures the system stops if audit logging cannot continue, preventing "
                    "unaudited activity. admin_space_left_action = SINGLE drops to single-user mode "
                    "as an early warning before the disk is completely full, giving administrators a "
                    "chance to free space. Trade-off: HALT means an attacker who fills the disk causes "
                    "a system shutdown (denial of service). For systems where uptime is more critical "
                    "than audit completeness, consider SYSLOG or EXEC (to trigger an alert script) "
                    "instead.".format(conf_path),
        category="config",
        platform="linux",
        evidence=evidence,
        mitre_techniques=["T1562.001"],
    )


def _check_log_rotation():
    """LINUX-AUDITD-006: Is log rotation configured sensibly?"""
    evidence = {}
    conf_path = "/etc/audit/auditd.conf"
    config = parse_config_file(conf_path)

    num_logs_str = config.get("num_logs", "")
    max_log_file_str = config.get("max_log_file", "")
    evidence["num_logs"] = num_logs_str or "not set"
    evidence["max_log_file"] = max_log_file_str or "not set"

    if not file_exists(conf_path):
        return CheckResult(
            check_id="LINUX-AUDITD-006",
            title="Auditd config not found for rotation check",
            severity="FAIL",
            detail="Audit log rotation controls how much historical audit data is retained on disk. "
                   "auditd rotates logs by keeping a fixed number of log files (num_logs), each up to "
                   "a maximum size (max_log_file MB). When all files are full, the oldest is overwritten. "
                   "Cannot read {} -- the configuration file is missing.".format(conf_path),
            remediation="Install auditd and configure log rotation. Without a configuration file, audit "
                        "logging cannot function:\n"
                        "  Install auditd, then edit {} and set:\n"
                        "  num_logs = 10\n"
                        "  max_log_file = 100\n"
                        "This gives you 1 GB of audit history.".format(conf_path),
            category="config",
            platform="linux",
            evidence=evidence,
            mitre_techniques=["T1562.001"],
        )

    try:
        num_logs = int(num_logs_str) if num_logs_str else 5
        max_log_file = int(max_log_file_str) if max_log_file_str else 8
    except ValueError:
        return CheckResult(
            check_id="LINUX-AUDITD-006",
            title="Cannot parse log rotation settings",
            severity="WARN",
            detail="Audit log rotation controls how much historical audit data is retained. "
                   "The num_logs and max_log_file settings should be integers, but found: "
                   "num_logs='{}', max_log_file='{}'. With non-integer values, auditd may fall "
                   "back to defaults or fail to rotate logs correctly, potentially leading to "
                   "unbounded log growth or premature log loss.".format(
                num_logs_str, max_log_file_str),
            remediation="Set proper integer values in {}:\n"
                        "  num_logs = 10\n"
                        "  max_log_file = 100\n"
                        "num_logs is the number of rotated log files to keep. max_log_file is the "
                        "maximum size in megabytes before auditd rotates to the next file. Together, "
                        "these give you num_logs x max_log_file MB of total audit history.".format(conf_path),
            category="config",
            platform="linux",
            evidence=evidence,
            mitre_techniques=["T1562.001"],
        )

    total_mb = num_logs * max_log_file
    evidence["total_mb"] = total_mb

    if total_mb < 100:
        return CheckResult(
            check_id="LINUX-AUDITD-006",
            title="Audit log retention critically low",
            severity="FAIL",
            detail="Audit log rotation determines how much forensic history you retain. auditd keeps "
                   "{} rotated log files, each up to {} MB, for a total retention of {} MB. This is "
                   "critically low -- a moderately active system can generate 5-20 MB of audit data per "
                   "hour, which means you may have as little as {} to {} hours of forensic history before "
                   "the oldest evidence is permanently overwritten. In a real incident, investigators "
                   "often need days or weeks of historical data to trace an attacker's initial access "
                   "vector and lateral movement. With only {} MB, evidence of the original compromise "
                   "will likely be gone by the time the breach is discovered.".format(
                       num_logs, max_log_file, total_mb,
                       max(1, total_mb // 20), max(1, total_mb // 5),
                       total_mb),
            remediation="Increase log retention in {}. These settings control how many log files "
                        "auditd keeps (num_logs) and the maximum size of each file in MB "
                        "(max_log_file):\n"
                        "  num_logs = 10\n"
                        "  max_log_file = 100\n"
                        "This gives you 1000 MB (1 GB) of total retention. Then restart auditd:\n"
                        "  sudo systemctl restart auditd\n"
                        "For systems with ample disk space, consider even larger values. Also consider "
                        "forwarding audit logs to a remote SIEM or log server using audispd, so that "
                        "even if local logs rotate out, a remote copy is preserved.".format(conf_path),
            category="config",
            platform="linux",
            evidence=evidence,
            mitre_techniques=["T1562.001"],
        )

    if total_mb < 500:
        return CheckResult(
            check_id="LINUX-AUDITD-006",
            title="Audit log retention is low",
            severity="WARN",
            detail="Audit log rotation determines how much forensic history you retain. auditd keeps "
                   "{} rotated log files, each up to {} MB, for a total retention of {} MB. While not "
                   "critically low, this provides limited forensic runway -- at a typical rate of 5-20 MB "
                   "per hour on a moderately active system, you have roughly {} to {} hours of audit "
                   "history before the oldest data is overwritten. A recommended minimum of 500 MB "
                   "provides at least a day or two of coverage, giving incident responders a reasonable "
                   "window to begin an investigation.".format(
                       num_logs, max_log_file, total_mb,
                       max(1, total_mb // 20), max(1, total_mb // 5)),
            remediation="Increase retention in {} by raising num_logs (number of rotated files) or "
                        "max_log_file (max size per file in MB):\n"
                        "  num_logs = 10\n"
                        "  max_log_file = 100\n"
                        "This gives 1000 MB total. Then restart:\n"
                        "  sudo systemctl restart auditd\n"
                        "Trade-off: more retention uses more disk space. On a dedicated /var/log/audit "
                        "partition, ensure you have sufficient free space. For long-term retention, "
                        "forward logs to a remote SIEM rather than relying solely on local rotation.".format(conf_path),
            category="config",
            platform="linux",
            evidence=evidence,
            mitre_techniques=["T1562.001"],
        )

    return CheckResult(
        check_id="LINUX-AUDITD-006",
        title="Audit log retention adequate",
        severity="PASS",
        detail="Audit log rotation determines how much forensic history you retain. auditd is "
               "configured to keep {} rotated log files, each up to {} MB, for a total retention of "
               "{} MB. This provides a reasonable forensic window -- at a typical rate of 5-20 MB per "
               "hour on a moderately active system, you have roughly {} to {} hours of audit history "
               "available for incident investigation before the oldest entries are "
               "overwritten.".format(
                   num_logs, max_log_file, total_mb,
                   max(1, total_mb // 20), max(1, total_mb // 5)),
        remediation="No action required.",
        category="config",
        platform="linux",
        evidence=evidence,
        mitre_techniques=["T1562.001"],
    )


def _check_immutable_mode():
    """LINUX-AUDITD-007: Is immutable mode enabled?"""
    evidence = {}
    lines = _read_all_rules()
    evidence["total_rule_lines"] = len(lines)

    # Check for -e 2 at the end of rules
    has_immutable = False
    for line in reversed(lines):
        stripped = line.strip()
        if re.match(r'^-e\s+2$', stripped):
            has_immutable = True
            break
        # If we hit another -e or -a/-w rule, the -e 2 isn't at the end
        if stripped.startswith("-e ") or stripped.startswith("-a") or stripped.startswith("-w"):
            break

    evidence["immutable_found"] = has_immutable

    if has_immutable:
        return CheckResult(
            check_id="LINUX-AUDITD-007",
            title="Immutable mode enabled",
            severity="PASS",
            detail="Immutable mode (-e 2) locks the audit rule configuration in kernel memory, "
                   "preventing any changes to audit rules until the system is rebooted -- even by "
                   "root. This is a critical defense because the first action a sophisticated attacker "
                   "typically takes after gaining root access is to disable or modify audit logging to "
                   "cover their tracks. With immutable mode active, the audit rules are confirmed locked "
                   "and cannot be altered, disabled, or deleted at runtime. An attacker would need to "
                   "reboot the system to change the rules, which itself is a highly visible event.",
            remediation="No action required.",
            category="config",
            platform="linux",
            evidence=evidence,
            mitre_techniques=["T1562.001"],
        )

    return CheckResult(
        check_id="LINUX-AUDITD-007",
        title="Immutable mode not enabled",
        severity="WARN",
        detail="Immutable mode (-e 2) locks the audit rule configuration in kernel memory, "
               "preventing any changes to audit rules until the system is rebooted -- even by root. "
               "No '-e 2' directive was found at the end of the audit rules. Without immutable mode, "
               "an attacker who gains root access can silently delete or modify audit rules at runtime "
               "using auditctl. This is a well-known post-exploitation technique: after gaining "
               "privileged access, attackers disable audit logging first, then perform their malicious "
               "actions with no record. With immutable mode, the attacker would need to reboot the "
               "system to change audit rules, which is far more disruptive and detectable.",
        remediation="Add the immutable flag as the LAST line of your audit rules. It must be last "
                    "because once the kernel processes '-e 2', it ignores all subsequent rule changes. "
                    "Create or edit /etc/audit/rules.d/99-finalize.rules:\n"
                    "  -e 2\n"
                    "Then reload the rules:\n"
                    "  sudo augenrules --load\n"
                    "Caveat: after immutable mode is active, you CANNOT change audit rules without "
                    "rebooting. This means if you need to add or modify rules, you must edit the "
                    "rules files, then reboot the system for changes to take effect. This is an "
                    "intentional trade-off: the inconvenience of requiring a reboot to change rules "
                    "is the same property that prevents an attacker from changing them at runtime.",
        category="config",
        platform="linux",
        evidence=evidence,
        mitre_techniques=["T1562.001"],
    )


def _check_log_format():
    """LINUX-AUDITD-008: Is log_format set to ENRICHED?"""
    evidence = {}
    conf_path = "/etc/audit/auditd.conf"
    config = parse_config_file(conf_path)

    log_format = config.get("log_format", "").upper()
    evidence["log_format"] = log_format or "not set"
    evidence["config_file"] = conf_path

    if not file_exists(conf_path):
        return CheckResult(
            check_id="LINUX-AUDITD-008",
            title="Auditd config not found for log_format check",
            severity="FAIL",
            detail="The log_format setting controls how auditd writes audit records to disk. "
                   "Cannot read {} -- auditd may not be installed or the configuration file "
                   "is missing.".format(conf_path),
            remediation="Install auditd and ensure {} exists. Then set:\n"
                        "  log_format = ENRICHED\n"
                        "in the configuration file.".format(conf_path),
            category="config",
            platform="linux",
            evidence=evidence,
            mitre_techniques=["T1562.001"],
        )

    if log_format == "ENRICHED":
        return CheckResult(
            check_id="LINUX-AUDITD-008",
            title="Audit log format set to ENRICHED",
            severity="PASS",
            detail="The log_format setting controls how auditd writes audit records to disk. "
                   "ENRICHED format resolves UIDs to usernames, GIDs to group names, syscall "
                   "numbers to syscall names, architecture codes to architecture names, and "
                   "socket addresses to human-readable form -- all directly within each audit "
                   "record at write time. This is currently set to ENRICHED, which is the "
                   "recommended configuration for forensic analysis and SIEM ingestion.",
            remediation="No action required.",
            category="config",
            platform="linux",
            evidence=evidence,
            mitre_techniques=["T1562.001"],
        )

    return CheckResult(
        check_id="LINUX-AUDITD-008",
        title="Audit log format not set to ENRICHED",
        severity="WARN",
        detail="The log_format setting controls how auditd writes audit records to disk. "
               "Currently set to '{}' (default is RAW). Without ENRICHED format, audit logs "
               "contain only numeric identifiers -- uid=1001, gid=1001, syscall=59 -- and "
               "analysts must cross-reference /etc/passwd, /etc/group, and syscall tables to "
               "interpret each record. This is more than an inconvenience: if a user account is "
               "deleted after an incident (whether by the attacker covering tracks or by routine "
               "account cleanup), the UID-to-username mapping is lost forever and you cannot "
               "attribute the activity to a specific person. ENRICHED format resolves these "
               "mappings at write time, embedding 'auid=jsmith' directly in the log record "
               "so the information is preserved regardless of later account changes.".format(
                   log_format or "not set"),
        remediation="Edit {} and set:\n"
                    "  log_format = ENRICHED\n"
                    "Then restart auditd:\n"
                    "  sudo systemctl restart auditd\n"
                    "ENRICHED logs are slightly larger than RAW logs due to the additional "
                    "text fields, but the forensic value far outweighs the marginal storage "
                    "cost. Note: ENRICHED format was introduced in audit 2.6.4 -- verify your "
                    "auditd version supports it.".format(conf_path),
        category="config",
        platform="linux",
        evidence=evidence,
        mitre_techniques=["T1562.001"],
    )


def _check_space_left():
    """LINUX-AUDITD-009: Are space_left and space_left_action configured?"""
    evidence = {}
    conf_path = "/etc/audit/auditd.conf"
    config = parse_config_file(conf_path)

    space_left_str = config.get("space_left", "")
    space_left_action = config.get("space_left_action", "").upper()
    evidence["space_left"] = space_left_str or "not set"
    evidence["space_left_action"] = space_left_action or "not set"
    evidence["config_file"] = conf_path

    if not file_exists(conf_path):
        return CheckResult(
            check_id="LINUX-AUDITD-009",
            title="Auditd config not found for space_left check",
            severity="FAIL",
            detail="The space_left and space_left_action settings provide an early warning "
                   "system when audit log disk space is running low. Cannot read {} -- auditd "
                   "may not be installed or the configuration file is missing.".format(conf_path),
            remediation="Install auditd and ensure {} exists. Then set:\n"
                        "  space_left = 75\n"
                        "  space_left_action = SYSLOG\n"
                        "in the configuration file.".format(conf_path),
            category="config",
            platform="linux",
            evidence=evidence,
            mitre_techniques=["T1562.001"],
        )

    # Check space_left_action first for FAIL conditions
    if space_left_action == "IGNORE":
        return CheckResult(
            check_id="LINUX-AUDITD-009",
            title="space_left_action set to IGNORE",
            severity="FAIL",
            detail="The space_left and space_left_action settings are an early warning system "
                   "that fires BEFORE disk_full_action. Think of space_left as a low-fuel warning "
                   "light vs the engine actually stopping -- it gives you time to react (rotate logs, "
                   "add disk space, investigate why logs are filling up) before the more drastic "
                   "disk_full_action kicks in. Currently space_left_action is set to IGNORE, which "
                   "completely disables this early warning. When the audit partition reaches the "
                   "space_left threshold, nothing happens -- no alert, no log entry, no action. "
                   "You will get no advance notice before disk_full_action triggers, eliminating "
                   "your window to intervene and prevent audit data loss.",
            remediation="Edit {} and set:\n"
                        "  space_left = 75\n"
                        "  space_left_action = SYSLOG\n"
                        "Then restart auditd:\n"
                        "  sudo systemctl restart auditd\n"
                        "SYSLOG sends a warning to the system log when available disk space drops "
                        "below the space_left threshold (in MB). For more active alerting, use "
                        "EMAIL (requires email configuration in auditd.conf) or EXEC (runs a "
                        "custom script that can trigger PagerDuty, Slack, etc.).".format(conf_path),
            category="config",
            platform="linux",
            evidence=evidence,
            mitre_techniques=["T1562.001"],
        )

    if space_left_action == "SUSPEND":
        return CheckResult(
            check_id="LINUX-AUDITD-009",
            title="space_left_action set to SUSPEND",
            severity="WARN",
            detail="The space_left and space_left_action settings are an early warning system "
                   "that fires BEFORE disk_full_action. Think of space_left as a low-fuel warning "
                   "light vs the engine actually stopping -- it gives you time to react (rotate logs, "
                   "add disk space, investigate why logs are filling up) before the more drastic "
                   "disk_full_action kicks in. Currently space_left_action is set to SUSPEND, which "
                   "means auditd will stop writing audit events when the threshold is reached. While "
                   "better than IGNORE (the suspension is at least logged), this causes audit logging "
                   "to halt prematurely. The purpose of space_left is to be an early warning, not to "
                   "stop logging -- that is disk_full_action's job. Using SUSPEND here means you lose "
                   "your early warning window entirely.",
            remediation="Edit {} and set:\n"
                        "  space_left = 75\n"
                        "  space_left_action = SYSLOG\n"
                        "Then restart auditd:\n"
                        "  sudo systemctl restart auditd\n"
                        "SYSLOG sends a warning to the system log, giving administrators time to "
                        "take corrective action (free disk space, rotate logs, add storage) before "
                        "the more drastic disk_full_action triggers. For active alerting, consider "
                        "EMAIL or EXEC instead.".format(conf_path),
            category="config",
            platform="linux",
            evidence=evidence,
            mitre_techniques=["T1562.001"],
        )

    # Check space_left value
    try:
        space_left = int(space_left_str) if space_left_str else None
    except ValueError:
        space_left = None

    if space_left is None:
        return CheckResult(
            check_id="LINUX-AUDITD-009",
            title="space_left threshold not configured",
            severity="WARN",
            detail="The space_left setting defines a disk space threshold (in MB) that acts as an "
                   "early warning system before disk_full_action triggers. Think of it as a low-fuel "
                   "warning light vs the engine actually stopping -- it gives you time to react "
                   "(rotate logs, add disk space, investigate why logs are filling up) before the "
                   "more drastic disk_full_action kicks in. The space_left value is not set or not "
                   "parseable. Without a properly configured threshold, the early warning system "
                   "cannot function and you will have no advance notice before the disk fills up.",
            remediation="Edit {} and set:\n"
                        "  space_left = 75\n"
                        "  space_left_action = SYSLOG\n"
                        "Then restart auditd:\n"
                        "  sudo systemctl restart auditd\n"
                        "The value 75 means auditd will trigger the space_left_action when only "
                        "75 MB of free space remains on the audit log partition. Adjust this based "
                        "on your log volume -- higher values give more reaction time.".format(conf_path),
            category="config",
            platform="linux",
            evidence=evidence,
            mitre_techniques=["T1562.001"],
        )

    if space_left < 75:
        return CheckResult(
            check_id="LINUX-AUDITD-009",
            title="space_left threshold too low",
            severity="WARN",
            detail="The space_left setting defines a disk space threshold (in MB) that acts as an "
                   "early warning system before disk_full_action triggers. Think of it as a low-fuel "
                   "warning light vs the engine actually stopping -- it gives you time to react "
                   "(rotate logs, add disk space, investigate why logs are filling up) before the "
                   "more drastic disk_full_action kicks in. Currently set to {} MB (recommended "
                   "minimum: 75 MB). At {} MB, a busy system generating 5-20 MB of audit data per "
                   "hour may have only minutes between this early warning and the disk_full_action "
                   "firing, leaving almost no time to intervene.".format(space_left, space_left),
            remediation="Edit {} and increase the threshold:\n"
                        "  space_left = 75\n"
                        "Then restart auditd:\n"
                        "  sudo systemctl restart auditd\n"
                        "75 MB provides at least a few hours of buffer on most systems. For high-volume "
                        "audit environments, consider setting this even higher (150-250 MB) to give "
                        "your team more time to respond.".format(conf_path),
            category="config",
            platform="linux",
            evidence=evidence,
            mitre_techniques=["T1562.001"],
        )

    return CheckResult(
        check_id="LINUX-AUDITD-009",
        title="space_left and space_left_action properly configured",
        severity="PASS",
        detail="The space_left and space_left_action settings provide an early warning system that "
               "fires BEFORE disk_full_action. Think of space_left as a low-fuel warning light vs "
               "the engine actually stopping -- it gives you time to react before the more drastic "
               "disk_full_action kicks in. Currently space_left={} MB and space_left_action={}. "
               "This configuration will alert when available disk space drops below the threshold, "
               "giving administrators time to take corrective action.".format(
                   space_left, space_left_action or "default"),
        remediation="No action required.",
        category="config",
        platform="linux",
        evidence=evidence,
        mitre_techniques=["T1562.001"],
    )


def _check_max_log_file_action():
    """LINUX-AUDITD-010: Is max_log_file_action configured safely?"""
    evidence = {}
    conf_path = "/etc/audit/auditd.conf"
    config = parse_config_file(conf_path)

    action = config.get("max_log_file_action", "").upper()
    evidence["max_log_file_action"] = action or "not set"
    evidence["config_file"] = conf_path

    if not file_exists(conf_path):
        return CheckResult(
            check_id="LINUX-AUDITD-010",
            title="Auditd config not found for max_log_file_action check",
            severity="FAIL",
            detail="The max_log_file_action setting controls what auditd does when an individual "
                   "audit log file reaches the size limit set by max_log_file. Cannot read {} -- "
                   "auditd may not be installed or the configuration file is missing.".format(conf_path),
            remediation="Install auditd and ensure {} exists. Then set:\n"
                        "  max_log_file_action = ROTATE\n"
                        "in the configuration file.".format(conf_path),
            category="config",
            platform="linux",
            evidence=evidence,
            mitre_techniques=["T1562.001"],
        )

    if action == "IGNORE":
        return CheckResult(
            check_id="LINUX-AUDITD-010",
            title="max_log_file_action set to IGNORE",
            severity="FAIL",
            detail="The max_log_file_action setting controls what auditd does when an individual "
                   "audit log file reaches the size limit defined by max_log_file. Currently set "
                   "to IGNORE, which means auditd will continue writing to the same log file "
                   "indefinitely, completely disregarding the max_log_file size limit. The log file "
                   "will grow without bound until the partition runs out of space. This defeats the "
                   "purpose of having a max_log_file setting at all and can lead to a full disk, "
                   "which may trigger disk_full_action and potentially halt the system or cause "
                   "audit events to be lost. The available actions are: IGNORE (file grows unbounded "
                   "-- dangerous), SYSLOG (logs a warning but keeps writing to the same file), "
                   "SUSPEND (stops logging entirely -- dangerous), ROTATE (moves to the next log "
                   "file in the rotation), KEEP_LOGS (same as ROTATE but prevents overwriting older "
                   "files by incrementing the log file number indefinitely).",
            remediation="Edit {} and set:\n"
                        "  max_log_file_action = ROTATE\n"
                        "Then restart auditd:\n"
                        "  sudo systemctl restart auditd\n"
                        "ROTATE is the most common and practical choice: when a log file reaches "
                        "max_log_file MB, auditd rotates to the next file in the pool (controlled "
                        "by num_logs). KEEP_LOGS is an alternative that never overwrites old files "
                        "but requires manual cleanup or external log management.".format(conf_path),
            category="config",
            platform="linux",
            evidence=evidence,
            mitre_techniques=["T1562.001"],
        )

    if action == "SUSPEND":
        return CheckResult(
            check_id="LINUX-AUDITD-010",
            title="max_log_file_action set to SUSPEND",
            severity="WARN",
            detail="The max_log_file_action setting controls what auditd does when an individual "
                   "audit log file reaches the size limit defined by max_log_file. Currently set "
                   "to SUSPEND, which means auditd will silently stop writing audit events once "
                   "the log file reaches its size limit. The system continues running normally but "
                   "with no audit trail -- a complete blind spot. This is particularly dangerous "
                   "because there is no obvious indication that logging has stopped; administrators "
                   "may assume the system is being audited when it is not. An attacker who knows "
                   "the max_log_file size could deliberately generate audit events to fill the log "
                   "faster, triggering the suspension sooner. The available actions are: IGNORE "
                   "(file grows unbounded), SYSLOG (logs a warning but keeps writing), SUSPEND "
                   "(stops logging -- current setting), ROTATE (moves to next file in rotation -- "
                   "recommended), KEEP_LOGS (like ROTATE but never overwrites).",
            remediation="Edit {} and set:\n"
                        "  max_log_file_action = ROTATE\n"
                        "Then restart auditd:\n"
                        "  sudo systemctl restart auditd\n"
                        "ROTATE seamlessly moves to the next log file when the current one reaches "
                        "max_log_file MB, ensuring continuous logging. Combined with num_logs, this "
                        "creates a rolling window of audit history.".format(conf_path),
            category="config",
            platform="linux",
            evidence=evidence,
            mitre_techniques=["T1562.001"],
        )

    if action in ("ROTATE", "KEEP_LOGS"):
        return CheckResult(
            check_id="LINUX-AUDITD-010",
            title="max_log_file_action properly configured",
            severity="PASS",
            detail="The max_log_file_action setting controls what auditd does when an individual "
                   "audit log file reaches the size limit defined by max_log_file. Currently set "
                   "to {}, which is a safe configuration. {} ensures continuous audit logging by "
                   "moving to the next log file when the current one reaches its size limit. The "
                   "available actions are: IGNORE (file grows unbounded -- dangerous), SYSLOG "
                   "(logs a warning but keeps writing), SUSPEND (stops logging -- dangerous), "
                   "ROTATE (moves to next file in rotation), KEEP_LOGS (like ROTATE but never "
                   "overwrites older files).".format(
                       action,
                       "ROTATE cycles through a fixed pool of log files (controlled by num_logs), "
                       "overwriting the oldest when all slots are used"
                       if action == "ROTATE" else
                       "KEEP_LOGS increments the log file number indefinitely, preserving all "
                       "historical files but requiring manual cleanup or external log management"),
            remediation="No action required.",
            category="config",
            platform="linux",
            evidence=evidence,
            mitre_techniques=["T1562.001"],
        )

    # Unknown or SYSLOG or not set -- mild warning
    return CheckResult(
        check_id="LINUX-AUDITD-010",
        title="max_log_file_action may need attention",
        severity="WARN",
        detail="The max_log_file_action setting controls what auditd does when an individual "
               "audit log file reaches the size limit defined by max_log_file. Currently set "
               "to '{}'. The recommended values are ROTATE (moves to the next log file in the "
               "rotation pool) or KEEP_LOGS (never overwrites older files). The available "
               "actions are: IGNORE (file grows unbounded -- dangerous), SYSLOG (logs a warning "
               "but keeps writing to the same file), SUSPEND (stops logging -- dangerous), "
               "ROTATE (moves to next file -- recommended), KEEP_LOGS (like ROTATE but never "
               "overwrites).".format(action or "not set"),
        remediation="Edit {} and set:\n"
                    "  max_log_file_action = ROTATE\n"
                    "Then restart auditd:\n"
                    "  sudo systemctl restart auditd\n"
                    "ROTATE is the most practical choice for most environments. It creates a "
                    "rolling window of audit history using a fixed number of log files "
                    "(controlled by num_logs).".format(conf_path),
        category="config",
        platform="linux",
        evidence=evidence,
        mitre_techniques=["T1562.001"],
    )


def _check_name_format():
    """LINUX-AUDITD-011: Is name_format configured for host identification?"""
    evidence = {}
    conf_path = "/etc/audit/auditd.conf"
    config = parse_config_file(conf_path)

    name_format = config.get("name_format", "").upper()
    evidence["name_format"] = name_format or "not set"
    evidence["config_file"] = conf_path

    if not file_exists(conf_path):
        return CheckResult(
            check_id="LINUX-AUDITD-011",
            title="Auditd config not found for name_format check",
            severity="FAIL",
            detail="The name_format setting controls whether the hostname is embedded in each "
                   "audit record. Cannot read {} -- auditd may not be installed or the "
                   "configuration file is missing.".format(conf_path),
            remediation="Install auditd and ensure {} exists. Then set:\n"
                        "  name_format = HOSTNAME\n"
                        "in the configuration file.".format(conf_path),
            category="config",
            platform="linux",
            evidence=evidence,
            mitre_techniques=["T1562.001"],
        )

    if name_format in ("HOSTNAME", "FQD", "USER"):
        return CheckResult(
            check_id="LINUX-AUDITD-011",
            title="Audit name_format properly configured",
            severity="PASS",
            detail="The name_format setting controls whether the hostname is embedded in each "
                   "audit record via the 'node=' field. Currently set to {}, which means each "
                   "audit record will include the host identity. This is essential when multiple "
                   "hosts forward audit logs to a single SIEM or central log server -- without "
                   "a hostname in each record, events from different systems become indistinguishable. "
                   "The available options are: NONE (no hostname -- problematic for centralized "
                   "logging), HOSTNAME (short hostname), FQD (fully qualified domain name -- best "
                   "for environments with multiple domains), USER (a custom name set via the "
                   "'name' directive in auditd.conf).".format(name_format),
            remediation="No action required.",
            category="config",
            platform="linux",
            evidence=evidence,
            mitre_techniques=["T1562.001"],
        )

    return CheckResult(
        check_id="LINUX-AUDITD-011",
        title="Audit name_format not configured for host identification",
        severity="WARN",
        detail="The name_format setting controls whether the hostname is embedded in each "
               "audit record via the 'node=' field. Currently set to '{}'. When name_format is "
               "NONE or not set, audit records do not include the originating hostname. This is "
               "not a problem if audit logs stay on the local machine, but it becomes a critical "
               "issue when multiple hosts forward audit logs to a single SIEM or central log "
               "server. Without hostnames, records from different systems are indistinguishable "
               "-- you cannot tell whether a suspicious login event came from the web server, "
               "the database server, or the jump host. This is especially important if your "
               "SIEM ingests raw audit logs rather than going through a log shipper (like "
               "auditbeat or rsyslog) that adds host metadata. The available options are: NONE "
               "(no hostname), HOSTNAME (short hostname -- recommended), FQD (fully qualified "
               "domain name -- best for multi-domain environments), USER (custom name set via "
               "the 'name' directive).".format(name_format or "not set"),
        remediation="Edit {} and set:\n"
                    "  name_format = HOSTNAME\n"
                    "Then restart auditd:\n"
                    "  sudo systemctl restart auditd\n"
                    "Use HOSTNAME for most environments. Use FQD if you have multiple domains "
                    "or subdomains and need to distinguish hosts across them. Use USER and set "
                    "the 'name' directive if you need a custom identifier (e.g., for containers "
                    "or cloud instances where hostnames are auto-generated and not meaningful).".format(conf_path),
        category="config",
        platform="linux",
        evidence=evidence,
        mitre_techniques=["T1562.001"],
    )


def _check_flush_frequency():
    """LINUX-AUDITD-012: Is the flush frequency (freq) configured?"""
    evidence = {}
    conf_path = "/etc/audit/auditd.conf"
    config = parse_config_file(conf_path)

    freq_str = config.get("freq", "")
    evidence["freq"] = freq_str or "not set"
    evidence["config_file"] = conf_path

    if not file_exists(conf_path):
        return CheckResult(
            check_id="LINUX-AUDITD-012",
            title="Auditd config not found for freq check",
            severity="FAIL",
            detail="The freq setting controls how many audit records auditd buffers in memory "
                   "before writing them to disk. Cannot read {} -- auditd may not be installed "
                   "or the configuration file is missing.".format(conf_path),
            remediation="Install auditd and ensure {} exists. Then set:\n"
                        "  freq = 20\n"
                        "in the configuration file.".format(conf_path),
            category="config",
            platform="linux",
            evidence=evidence,
            mitre_techniques=["T1562.001"],
        )

    try:
        freq = int(freq_str) if freq_str else 0
    except ValueError:
        freq = 0

    if freq <= 0:
        return CheckResult(
            check_id="LINUX-AUDITD-012",
            title="Audit flush frequency not configured",
            severity="WARN",
            detail="The freq setting controls how many audit records auditd buffers in memory "
                   "before flushing (writing) them to disk. Currently set to '{}' (default is 0, "
                   "meaning no periodic flush). With freq=0, auditd only flushes when its internal "
                   "buffer is full, which can mean hundreds or thousands of events sitting in memory "
                   "at any given time. If the system crashes, loses power, or the auditd process is "
                   "killed (e.g., by an attacker using kill -9), all buffered events are permanently "
                   "lost with no way to recover them. This creates a forensic gap at the most "
                   "critical moment -- the events immediately preceding a crash or attack are often "
                   "the most important for understanding what happened, and those are exactly the "
                   "events most likely to be lost.".format(freq_str or "0"),
            remediation="Edit {} and set:\n"
                        "  freq = 20\n"
                        "Then restart auditd:\n"
                        "  sudo systemctl restart auditd\n"
                        "Setting freq=20 means auditd flushes to disk every 20 events, limiting "
                        "potential data loss to at most 20 records in a crash scenario. This is a "
                        "good balance between data safety and performance. Lower values (e.g., 1) "
                        "flush after every single event for maximum safety but add disk I/O overhead. "
                        "Higher values reduce I/O but increase the window of potential data loss. "
                        "Note: this setting only applies when flush is set to INCREMENTAL or "
                        "INCREMENTAL_ASYNC in auditd.conf.".format(conf_path),
            category="config",
            platform="linux",
            evidence=evidence,
            mitre_techniques=["T1562.001"],
        )

    return CheckResult(
        check_id="LINUX-AUDITD-012",
        title="Audit flush frequency configured",
        severity="PASS",
        detail="The freq setting controls how many audit records auditd buffers in memory before "
               "flushing (writing) them to disk. Currently set to {}, meaning auditd writes "
               "buffered events to disk every {} records. This limits potential data loss in a "
               "crash or power failure to at most {} events. Without periodic flushing (freq=0), "
               "auditd only writes when its internal buffer is full, which could mean losing "
               "hundreds of events if the system goes down unexpectedly.".format(
                   freq, freq, freq),
        remediation="No action required.",
        category="config",
        platform="linux",
        evidence=evidence,
        mitre_techniques=["T1562.001"],
    )


def _check_audit_log_permissions():
    """LINUX-AUDITD-014: Audit log file permissions."""
    evidence = {}
    audit_dir = "/var/log/audit"
    audit_log = "/var/log/audit/audit.log"
    issues = []

    base_detail = (
        "Audit logs contain sensitive security data including every command executed, every file "
        "accessed, every authentication attempt, and every privilege escalation. If the audit log "
        "directory or files are world-readable, any unprivileged user on the system can read this "
        "data -- including usernames, IP addresses, process arguments (which may contain passwords "
        "passed on command lines), and patterns of administrator activity. An attacker with any "
        "local account could use this to plan privilege escalation by studying administrator habits "
        "and scheduled tasks."
    )

    # Check if the audit directory exists
    if not os.path.isdir(audit_dir):
        return CheckResult(
            check_id="LINUX-AUDITD-014",
            title="Audit log directory not found",
            severity="SKIP",
            detail="{} The directory {} does not exist on this system, which typically means "
                   "auditd is not installed or has never been run. Cannot check log file "
                   "permissions without the directory present.".format(base_detail, audit_dir),
            remediation="Install and start auditd to create the audit log directory.",
            category="config",
            platform="linux",
            evidence={"audit_dir": audit_dir, "exists": False},
            mitre_techniques=["T1005"],
        )

    # Check directory permissions
    try:
        dir_stat = os.stat(audit_dir)
        dir_mode = stat.S_IMODE(dir_stat.st_mode)
        dir_owner = dir_stat.st_uid
        evidence["dir_mode"] = oct(dir_mode)
        evidence["dir_owner_uid"] = dir_owner

        if dir_owner != 0:
            issues.append("directory {} is owned by UID {} (should be root/0)".format(
                audit_dir, dir_owner))

        if dir_mode & stat.S_IROTH or dir_mode & stat.S_IXOTH:
            issues.append("directory {} is world-readable (mode {})".format(
                audit_dir, oct(dir_mode)))
    except OSError as e:
        evidence["dir_stat_error"] = str(e)
        issues.append("could not stat directory {}: {}".format(audit_dir, e))

    # Check audit.log permissions
    try:
        if os.path.isfile(audit_log):
            file_stat = os.stat(audit_log)
            file_mode = stat.S_IMODE(file_stat.st_mode)
            file_owner = file_stat.st_uid
            evidence["file_mode"] = oct(file_mode)
            evidence["file_owner_uid"] = file_owner

            if file_owner != 0:
                issues.append("file {} is owned by UID {} (should be root/0)".format(
                    audit_log, file_owner))

            if file_mode & stat.S_IROTH:
                issues.append("file {} is world-readable (mode {})".format(
                    audit_log, oct(file_mode)))
        else:
            evidence["audit_log_exists"] = False
    except OSError as e:
        evidence["file_stat_error"] = str(e)
        issues.append("could not stat file {}: {}".format(audit_log, e))

    evidence["issues"] = issues

    if issues:
        return CheckResult(
            check_id="LINUX-AUDITD-014",
            title="Audit log permissions too open",
            severity="WARN",
            detail="{} The following permission issues were found: {}. Overly permissive "
                   "audit log access allows any local user to read detailed security telemetry, "
                   "which an attacker can use for reconnaissance and privilege escalation "
                   "planning.".format(base_detail, "; ".join(issues)),
            remediation="Restrict permissions on the audit log directory and files:\n"
                        "  chmod 700 /var/log/audit && chmod 600 /var/log/audit/*\n"
                        "This ensures only root can access the audit logs. The directory mode 700 "
                        "prevents non-root users from listing or entering the directory. The file "
                        "mode 600 prevents non-root users from reading the log contents. If your "
                        "SIEM agent runs as a non-root user, use mode 750/640 and add that user "
                        "to the root group or create a dedicated audit group.",
            category="config",
            platform="linux",
            evidence=evidence,
            mitre_techniques=["T1005"],
        )

    return CheckResult(
        check_id="LINUX-AUDITD-014",
        title="Audit log permissions restrictive",
        severity="PASS",
        detail="{} The audit log directory {} and log file permissions are appropriately "
               "restrictive. Directory mode is {} and owned by UID {}. Only authorized users "
               "can access the audit trail, preventing unprivileged users from reading sensitive "
               "security event data.".format(
                   base_detail,
                   audit_dir,
                   evidence.get("dir_mode", "unknown"),
                   evidence.get("dir_owner_uid", "unknown")),
        remediation="No action required.",
        category="config",
        platform="linux",
        evidence=evidence,
        mitre_techniques=["T1005"],
    )


def run_checks():
    """Return all auditd configuration checks."""
    return [
        _check_backlog_buffer(),
        _check_disk_full_action(),
        _check_log_rotation(),
        _check_immutable_mode(),
        _check_log_format(),
        _check_space_left(),
        _check_max_log_file_action(),
        _check_name_format(),
        _check_flush_frequency(),
        _check_audit_log_permissions(),
    ]
