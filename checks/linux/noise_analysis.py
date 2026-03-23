"""Noise analysis checks: auid filters, broad watches, volume, duplicate forwarding."""

import glob
import re

from core.result import CheckResult
from core.platform_utils import (
    safe_run, read_file_safe, file_exists, is_elevated,
    get_package_manager, parse_config_file, get_file_mtime,
    check_process_running, get_linux_distro,
)


def _read_all_rules():
    """Read and combine all audit rule lines."""
    lines = []
    rule_files = sorted(glob.glob("/etc/audit/rules.d/*.rules"))
    if file_exists("/etc/audit/audit.rules"):
        rule_files.append("/etc/audit/audit.rules")
    for rf in rule_files:
        content = read_file_safe(rf)
        if content:
            for line in content.splitlines():
                stripped = line.strip()
                if stripped and not stripped.startswith("#"):
                    lines.append(stripped)
    return lines


def _check_auid_unset_filter():
    """LINUX-NOISE-001: auid=unset filter on execve rules."""
    evidence = {}
    lines = _read_all_rules()

    execve_rules = [l for l in lines if re.search(r'-S\s+execve', l)]
    evidence["total_execve_rules"] = len(execve_rules)

    if not execve_rules:
        return CheckResult(
            check_id="LINUX-NOISE-001",
            title="No execve rules to analyze for auid filter",
            severity="INFO",
            detail=(
                "The Audit User ID (auid) is a special Linux audit field that records the "
                "original login user ID -- the UID of the human who initially authenticated "
                "to the system. Unlike the effective UID which changes with su/sudo, auid "
                "persists across privilege transitions, so you can always trace an action "
                "back to the person who logged in. No execve syscall rules were found in the "
                "audit configuration, so auid filtering cannot be assessed."
            ),
            remediation="See LINUX-RULES-001 for adding execve monitoring.",
            category="noise",
            platform="linux",
            evidence=evidence,
            mitre_techniques=["T1059"],
        )

    # Check for auid!=unset or auid!=-1 or auid!=4294967295
    filtered_rules = []
    unfiltered_rules = []
    for rule in execve_rules:
        if re.search(r'auid!=(?:unset|-1|4294967295)', rule) or \
           re.search(r'auid>=\d+', rule):
            filtered_rules.append(rule)
        else:
            unfiltered_rules.append(rule)

    evidence["filtered_rules"] = filtered_rules
    evidence["unfiltered_rules"] = unfiltered_rules

    if not unfiltered_rules:
        return CheckResult(
            check_id="LINUX-NOISE-001",
            title="Execve rules have auid filter",
            severity="PASS",
            detail=(
                "The Audit User ID (auid) is a special Linux audit field that records the "
                "original login user ID -- the UID of the human who initially authenticated "
                "to the system. When auid is 'unset' (shown as 4294967295 or -1), it means "
                "the process was never associated with a human login session -- it was spawned "
                "by a system daemon, kernel thread, or boot-time service. All {} execve rules "
                "include an auid filter (auid!=unset or auid>=1000), which correctly excludes "
                "these system-generated process executions. This dramatically reduces audit "
                "noise while preserving visibility into commands run by actual users, which "
                "is critical for keeping SIEM ingestion costs manageable and alert quality high."
            ).format(len(execve_rules)),
            remediation="No action required.",
            category="noise",
            platform="linux",
            evidence=evidence,
            mitre_techniques=["T1059"],
        )

    return CheckResult(
        check_id="LINUX-NOISE-001",
        title="Execve rules missing auid filter",
        severity="WARN",
        detail=(
            "The Audit User ID (auid) is a special Linux audit field that records the "
            "original login user ID -- the UID of the human who initially authenticated "
            "to the system. When auid is 'unset' (4294967295 or -1), the process was spawned "
            "by a system daemon, kernel thread, or boot-time service with no human login "
            "session. {} of {} execve rules lack the auid!=unset filter, which means they "
            "capture every process execution on the system -- including routine activity from "
            "cron jobs, systemd service managers, package managers, and monitoring agents. "
            "These system-generated events are noise: they have no investigative value for "
            "detecting human attacker activity but can generate thousands of events per hour, "
            "inflating SIEM ingestion costs and drowning real alerts in false positives."
        ).format(len(unfiltered_rules), len(execve_rules)),
        remediation=(
            "Add an auid filter to each execve rule to exclude system daemon activity. The "
            "'auid>=1000' filter limits capture to UIDs in the human user range, and "
            "'auid!=unset' excludes processes with no login session. Example:\n"
            "  -a always,exit -F arch=b64 -S execve -F auid>=1000 -F auid!=unset -k exec\n"
            "Unfiltered rules that need updating:\n  " + "\n  ".join(unfiltered_rules[:3]) +
            "\nThen reload: sudo augenrules --load"
        ),
        category="noise",
        platform="linux",
        evidence=evidence,
        mitre_techniques=["T1059"],
    )


def _check_broad_tmp_watches():
    """LINUX-NOISE-002: Broad /tmp watches."""
    evidence = {}
    lines = _read_all_rules()

    tmp_watches = [l for l in lines if re.search(r'-w\s+/tmp\b', l)]
    var_tmp_watches = [l for l in lines if re.search(r'-w\s+/var/tmp\b', l)]
    dev_shm_watches = [l for l in lines if re.search(r'-w\s+/dev/shm\b', l)]

    evidence["tmp_watches"] = tmp_watches
    evidence["var_tmp_watches"] = var_tmp_watches
    evidence["dev_shm_watches"] = dev_shm_watches

    broad_watches = tmp_watches + var_tmp_watches + dev_shm_watches

    if not broad_watches:
        return CheckResult(
            check_id="LINUX-NOISE-002",
            title="No broad temporary directory watches",
            severity="PASS",
            detail=(
                "Temporary directories like /tmp, /var/tmp, and /dev/shm are among the "
                "noisiest locations to monitor with audit watches. Applications constantly "
                "create, modify, and delete temporary files in these directories -- a single "
                "web request might create multiple temp files, and build tools or package "
                "managers can generate thousands of file operations in minutes. No file "
                "watches were found on these directories, which avoids this major source "
                "of audit noise."
            ),
            remediation="No action required.",
            category="noise",
            platform="linux",
            evidence=evidence,
            mitre_techniques=["T1059"],
        )

    # Check if watches have execution-only permissions (less noisy)
    noisy_watches = []
    for rule in broad_watches:
        # -p wa or -p rwxa are noisy; -p x is less so
        perm_match = re.search(r'-p\s+(\S+)', rule)
        if perm_match:
            perms = perm_match.group(1)
            if 'w' in perms or 'a' in perms:
                noisy_watches.append(rule)
        else:
            # Default is all perms
            noisy_watches.append(rule)

    evidence["noisy_watches"] = noisy_watches

    if noisy_watches:
        return CheckResult(
            check_id="LINUX-NOISE-002",
            title="Broad temporary directory watches detected",
            severity="WARN",
            detail=(
                "Temporary directories like /tmp, /var/tmp, and /dev/shm are among the "
                "noisiest locations to monitor with audit watches. Applications constantly "
                "create, modify, and delete temporary files -- a single apt-get install can "
                "trigger hundreds of write events in /tmp, web servers create session temp "
                "files for every request, and build tools generate massive I/O in these "
                "directories. {} watch rule(s) were found monitoring write or attribute "
                "changes on these paths, which will generate extreme audit volume. This "
                "noise floods your SIEM with low-value events, increases storage costs, and "
                "makes it harder to spot genuine malicious activity like an attacker staging "
                "tools in /tmp."
            ).format(len(noisy_watches)),
            remediation=(
                "Remove or narrow these overly broad rules:\n  "
                + "\n  ".join(noisy_watches[:3]) +
                "\nInstead of watching all file operations in /tmp, monitor only for "
                "execution of files from temporary directories. An attacker who drops a "
                "binary in /tmp and executes it is the real threat -- not the thousands of "
                "normal temp file writes. A targeted alternative:\n"
                "  -a always,exit -F dir=/tmp -F perm=x -F auid>=1000 -F auid!=unset -k tmp_exec\n"
                "This watches only for execute permission events from human users, cutting "
                "noise by orders of magnitude while catching the actual attack pattern.\n"
                "Then reload: sudo augenrules --load"
            ),
            category="noise",
            platform="linux",
            evidence=evidence,
            mitre_techniques=["T1059"],
        )

    return CheckResult(
        check_id="LINUX-NOISE-002",
        title="Temporary directory watches are narrow",
        severity="PASS",
        detail=(
            "Temporary directories like /tmp, /var/tmp, and /dev/shm are among the noisiest "
            "locations to monitor with audit watches. Watches exist on these directories but "
            "they are configured with narrow permissions (execution-only), which avoids the "
            "massive volume of write and attribute-change events from normal application "
            "activity while still detecting the key threat: execution of attacker-dropped "
            "binaries from temp directories."
        ),
        remediation="No action required.",
        category="noise",
        platform="linux",
        evidence=evidence,
        mitre_techniques=["T1059"],
    )


def _check_system_process_volume():
    """LINUX-NOISE-003: Known system process execve volume."""
    evidence = {}

    if not is_elevated():
        return CheckResult(
            check_id="LINUX-NOISE-003",
            title="Cannot assess audit log volume (not elevated)",
            severity="SKIP",
            detail="Root privileges required to read audit logs.",
            remediation="Re-run with sudo for audit log volume analysis.",
            category="noise",
            platform="linux",
            evidence=evidence,
            mitre_techniques=[],
        )

    # Check recent audit log for volume analysis
    audit_log = "/var/log/audit/audit.log"
    if not file_exists(audit_log):
        return CheckResult(
            check_id="LINUX-NOISE-003",
            title="Audit log not found for volume analysis",
            severity="INFO",
            detail="No audit log at {} to analyze event volume.".format(audit_log),
            remediation="Ensure auditd is installed and running.",
            category="noise",
            platform="linux",
            evidence=evidence,
            mitre_techniques=[],
        )

    # Count EXECVE events and check for system-process noise
    rc, out, _ = safe_run(["wc", "-l", audit_log], timeout=15)
    total_lines = 0
    if rc == 0:
        try:
            total_lines = int(out.strip().split()[0])
        except (ValueError, IndexError):
            pass
    evidence["total_audit_lines"] = total_lines

    # Count EXECVE syscalls
    rc, out, _ = safe_run(["grep", "-c", "type=EXECVE", audit_log], timeout=15)
    execve_count = 0
    if rc == 0:
        try:
            execve_count = int(out.strip())
        except ValueError:
            pass
    evidence["execve_events"] = execve_count

    # Check for known noisy system processes (auid=unset means system)
    rc, out, _ = safe_run(["grep", "-c", "auid=4294967295", audit_log], timeout=15)
    unset_auid_count = 0
    if rc == 0:
        try:
            unset_auid_count = int(out.strip())
        except ValueError:
            pass
    evidence["unset_auid_events"] = unset_auid_count

    if total_lines == 0:
        return CheckResult(
            check_id="LINUX-NOISE-003",
            title="Audit log empty",
            severity="INFO",
            detail="Audit log is empty -- no volume analysis possible.",
            remediation="Ensure auditd is running and rules are loaded.",
            category="noise",
            platform="linux",
            evidence=evidence,
            mitre_techniques=[],
        )

    noise_ratio = unset_auid_count / total_lines if total_lines > 0 else 0
    evidence["noise_ratio"] = round(noise_ratio, 3)

    if noise_ratio > 0.5:
        return CheckResult(
            check_id="LINUX-NOISE-003",
            title="High system process noise in audit log",
            severity="WARN",
            detail=(
                "The audit log volume is dominated by system process activity. {:.0f}% of "
                "audit events ({}/{}) have auid=4294967295 (unset), meaning they were "
                "generated by system daemons and kernel threads that were never associated "
                "with a human login session. This happens when audit rules lack auid filters "
                "and capture everything -- routine system activity like cron running scheduled "
                "tasks, package managers checking for updates (a single apt-get update can "
                "generate thousands of execve events), monitoring agents polling system "
                "state, and systemd managing services. All of this creates audit records "
                "with no security investigation value, but each record still consumes SIEM "
                "ingestion capacity, storage, and processing resources."
            ).format(noise_ratio * 100, unset_auid_count, total_lines),
            remediation=(
                "Reduce system process noise by adding auid filters to your audit rules. "
                "The 'auid>=1000' filter restricts capture to human user UIDs, and "
                "'auid!=unset' excludes processes with no login session:\n"
                "  -a always,exit -F arch=b64 -S execve -F auid>=1000 -F auid!=unset -k exec\n"
                "Remove or refine rules that lack auid filtering. The trade-off is that you "
                "will not audit commands run by system services (UID < 1000), but these are "
                "almost never useful for security investigations.\n"
                "Then reload: sudo augenrules --load"
            ),
            category="noise",
            platform="linux",
            evidence=evidence,
            mitre_techniques=[],
        )

    if noise_ratio > 0.25:
        return CheckResult(
            check_id="LINUX-NOISE-003",
            title="Moderate system process noise in audit log",
            severity="INFO",
            detail=(
                "{:.0f}% of audit events have auid=4294967295 (unset), indicating they come "
                "from system daemons and kernel threads rather than human user sessions. Some "
                "system process noise is normal and unavoidable (e.g., audit infrastructure "
                "events), but this moderate level suggests some rules may be capturing more "
                "system activity than necessary. Each unnecessary event consumes SIEM "
                "ingestion capacity and can dilute alert quality."
            ).format(noise_ratio * 100),
            remediation=(
                "Review your audit rules for opportunities to add auid>=1000 and "
                "auid!=unset filters where they are missing. Focus on execve and file-watch "
                "rules, which tend to generate the highest volume of system process events."
            ),
            category="noise",
            platform="linux",
            evidence=evidence,
            mitre_techniques=[],
        )

    return CheckResult(
        check_id="LINUX-NOISE-003",
        title="Audit log noise level acceptable",
        severity="PASS",
        detail=(
            "Only {:.0f}% of audit events have auid=4294967295 (unset), meaning the vast "
            "majority of captured events are associated with human user sessions. This "
            "indicates that audit rules are well-tuned with appropriate auid filters, "
            "keeping system daemon noise low and ensuring that SIEM ingestion is focused "
            "on security-relevant human activity."
        ).format(noise_ratio * 100),
        remediation="No action required.",
        category="noise",
        platform="linux",
        evidence=evidence,
        mitre_techniques=[],
    )


def _check_duplicate_forwarding():
    """LINUX-NOISE-004: Syslog/auth log duplicate forwarding."""
    evidence = {}

    # Check if both journald ForwardToSyslog and rsyslog imjournal are active
    journald_conf = parse_config_file("/etc/systemd/journald.conf")
    # Also check drop-ins
    for dropin in sorted(glob.glob("/etc/systemd/journald.conf.d/*.conf")):
        override = parse_config_file(dropin)
        journald_conf.update(override)

    fwd_to_syslog = journald_conf.get("ForwardToSyslog", "").lower()
    evidence["ForwardToSyslog"] = fwd_to_syslog or "not set"

    # Check rsyslog for imjournal (reads from journal) and imuxsock (reads syslog socket)
    rsyslog_configs = {}
    main_conf = read_file_safe("/etc/rsyslog.conf")
    if main_conf:
        rsyslog_configs["/etc/rsyslog.conf"] = main_conf
    for f in sorted(glob.glob("/etc/rsyslog.d/*.conf")):
        content = read_file_safe(f)
        if content:
            rsyslog_configs[f] = content

    has_imjournal = False
    has_imuxsock = False
    for path, content in rsyslog_configs.items():
        if re.search(r'(?:module|load).*imjournal', content):
            has_imjournal = True
        if re.search(r'(?:module|load).*imuxsock', content):
            has_imuxsock = True

    evidence["rsyslog_imjournal"] = has_imjournal
    evidence["rsyslog_imuxsock"] = has_imuxsock

    # Duplicate scenario: ForwardToSyslog=yes AND imjournal loaded
    # This means journal -> syslog socket -> rsyslog AND journal -> imjournal -> rsyslog
    if fwd_to_syslog == "yes" and has_imjournal:
        return CheckResult(
            check_id="LINUX-NOISE-004",
            title="Potential duplicate log forwarding detected",
            severity="WARN",
            detail=(
                "Duplicate log forwarding occurs when the same event reaches your SIEM "
                "through multiple paths, doubling ingestion volume and cost with zero "
                "additional security value. On this system, journald ForwardToSyslog=yes "
                "AND rsyslog's imjournal module is loaded. This creates two parallel paths "
                "for the same events: (1) journald writes events to the /dev/log syslog "
                "socket, where rsyslog's imuxsock module picks them up, and (2) rsyslog's "
                "imjournal module reads the same events directly from the journal API. The "
                "result is that every journal event arrives at rsyslog twice, and if rsyslog "
                "forwards to a SIEM, you pay for double the ingestion with no additional "
                "detection capability."
            ),
            remediation=(
                "Choose one forwarding method and disable the other:\n\n"
                "Option A - Use imjournal only (recommended for modern systems):\n"
                "  imjournal reads directly from the journal, preserving structured metadata.\n"
                "  Set ForwardToSyslog=no in /etc/systemd/journald.conf\n"
                "  sudo systemctl restart systemd-journald\n\n"
                "Option B - Use ForwardToSyslog only (simpler, but loses journal metadata):\n"
                "  Comment out or remove the imjournal module load in rsyslog config.\n"
                "  sudo systemctl restart rsyslog\n\n"
                "Either option eliminates the duplicate events while maintaining full "
                "log forwarding coverage."
            ),
            category="noise",
            platform="linux",
            evidence=evidence,
            mitre_techniques=[],
        )

    # Check for multiple remote forwarding of auth logs
    auth_forward_count = 0
    for path, content in rsyslog_configs.items():
        for line in content.splitlines():
            line = line.strip()
            if line.startswith("#") or not line:
                continue
            if re.search(r'(auth|authpriv)\.\*?\s+@@?', line):
                auth_forward_count += 1
            # Wildcard forwarding also includes auth
            if re.search(r'\*\.\*\s+@@?', line):
                auth_forward_count += 1

    evidence["auth_forward_rules"] = auth_forward_count

    if auth_forward_count > 1:
        return CheckResult(
            check_id="LINUX-NOISE-004",
            title="Multiple auth log forwarding rules",
            severity="WARN",
            detail=(
                "Duplicate log forwarding occurs when the same event reaches your SIEM "
                "through multiple paths, increasing ingestion volume and cost with no "
                "additional security value. Found {} rsyslog rules that forward "
                "auth/authpriv events to remote targets. This typically happens when both "
                "a specific 'auth,authpriv.* @@server' rule and a wildcard '*.* @@server' "
                "rule exist -- the wildcard already includes auth events, so the specific "
                "rule causes each PAM authentication event, SSH login, and sudo command to "
                "be sent twice. If your SIEM charges per event or per GB ingested, this "
                "duplication directly increases your costs with no improvement in detection "
                "coverage."
            ).format(auth_forward_count),
            remediation=(
                "Audit your rsyslog forwarding rules and consolidate them. Identify which "
                "rules overlap:\n"
                "  grep -rn 'auth' /etc/rsyslog.conf /etc/rsyslog.d/\n"
                "  grep -rn '\\*\\.\\*.*@@' /etc/rsyslog.conf /etc/rsyslog.d/\n"
                "If you have a '*.* @@server' wildcard rule, it already forwards auth "
                "events -- remove any separate 'auth,authpriv.* @@server' rules that "
                "point to the same destination. Alternatively, if you want auth events "
                "to go to a specific server, remove auth from the wildcard by using "
                "facility filters."
            ),
            category="noise",
            platform="linux",
            evidence=evidence,
            mitre_techniques=[],
        )

    return CheckResult(
        check_id="LINUX-NOISE-004",
        title="No duplicate log forwarding detected",
        severity="PASS",
        detail=(
            "Duplicate log forwarding occurs when the same event reaches a SIEM through "
            "multiple paths, wasting ingestion capacity and budget. No duplicate forwarding "
            "patterns were detected -- journald and rsyslog are not creating parallel paths "
            "for the same events, and auth log forwarding rules do not overlap. This means "
            "your SIEM receives one copy of each event, keeping ingestion costs efficient."
        ),
        remediation="No action required.",
        category="noise",
        platform="linux",
        evidence=evidence,
        mitre_techniques=[],
    )


def _check_aureport_summary():
    """LINUX-NOISE-005: aureport summary statistics."""
    evidence = {}

    if not is_elevated():
        return CheckResult(
            check_id="LINUX-NOISE-005",
            title="Cannot run aureport (not elevated)",
            severity="SKIP",
            detail="Root privileges required to run aureport.",
            remediation="Re-run with sudo for aureport summary analysis.",
            category="noise",
            platform="linux",
            evidence=evidence,
            mitre_techniques=["T1562.001"],
        )

    rc, out, err = safe_run(["aureport", "--summary"], timeout=15)

    if rc != 0 or not out.strip():
        return CheckResult(
            check_id="LINUX-NOISE-005",
            title="aureport not available or failed",
            severity="INFO",
            detail=(
                "aureport is auditd's built-in log summarization tool. The --summary "
                "output shows the total number of audit events and breaks them down "
                "by type (syscall events, file access events, authentication events, "
                "etc.). This gives you a real baseline for understanding your audit "
                "log composition -- whether you are generating mostly useful security "
                "telemetry or mostly noise. Use this data to tune audit rules: if 80% "
                "of events are PATH records from package manager activity, you know "
                "where to add exclusion rules. aureport could not be executed on this "
                "system (it may not be installed or auditd may not be running)."
            ),
            remediation=(
                "Ensure auditd is installed and running. aureport is typically "
                "included in the audit or audit-libs package."
            ),
            category="noise",
            platform="linux",
            evidence={"error": err.strip()},
            mitre_techniques=["T1562.001"],
        )

    # Parse aureport --summary output
    # Typical output has a header then lines like:
    # Range of time in logs: ... - ...
    # Selected time for report: ...
    # Number of changes in configuration: N
    # Number of changes to accounts, groups, or roles: N
    # ...
    summary_lines = []
    total_events = None
    for line in out.strip().splitlines():
        line = line.strip()
        if not line or line.startswith("="):
            continue
        summary_lines.append(line)
        if "Number of" in line:
            parts = line.rsplit(":", 1)
            if len(parts) == 2:
                try:
                    count = int(parts[1].strip())
                    if total_events is None:
                        total_events = 0
                    total_events += count
                except ValueError:
                    pass

    evidence["aureport_output"] = "\n".join(summary_lines[:20])
    evidence["total_events_parsed"] = total_events

    return CheckResult(
        check_id="LINUX-NOISE-005",
        title="aureport summary collected",
        severity="INFO",
        detail=(
            "aureport is auditd's built-in log summarization tool. The --summary "
            "output shows the total number of audit events and breaks them down "
            "by type (syscall events, file access events, authentication events, "
            "etc.). This gives you a real baseline for understanding your audit "
            "log composition -- whether you are generating mostly useful security "
            "telemetry or mostly noise. Use this data to tune audit rules: if 80% "
            "of events are PATH records from package manager activity, you know "
            "where to add exclusion rules."
        ),
        remediation=(
            "Review the aureport summary to understand your audit log composition. "
            "Focus on which event categories dominate and whether those categories "
            "provide security value for your detection use cases."
        ),
        category="noise",
        platform="linux",
        evidence=evidence,
        mitre_techniques=["T1562.001"],
    )


def _check_high_volume_event_types():
    """LINUX-NOISE-006: High-volume event type detection."""
    evidence = {}

    if not is_elevated():
        return CheckResult(
            check_id="LINUX-NOISE-006",
            title="Cannot analyze event types (not elevated)",
            severity="SKIP",
            detail="Root privileges required to read audit logs.",
            remediation="Re-run with sudo for event type volume analysis.",
            category="noise",
            platform="linux",
            evidence=evidence,
            mitre_techniques=["T1562.001"],
        )

    audit_log = "/var/log/audit/audit.log"
    if not file_exists(audit_log):
        return CheckResult(
            check_id="LINUX-NOISE-006",
            title="Audit log not found for event type analysis",
            severity="SKIP",
            detail="No audit log at {} to analyze.".format(audit_log),
            remediation="Ensure auditd is installed and running.",
            category="noise",
            platform="linux",
            evidence=evidence,
            mitre_techniques=["T1562.001"],
        )

    rc, out, _ = safe_run(["tail", "-10000", audit_log], timeout=15)
    if rc != 0 or not out.strip():
        return CheckResult(
            check_id="LINUX-NOISE-006",
            title="Could not read audit log for event type analysis",
            severity="SKIP",
            detail="Failed to read the last 10000 lines of {}.".format(audit_log),
            remediation="Ensure the audit log is readable with current privileges.",
            category="noise",
            platform="linux",
            evidence=evidence,
            mitre_techniques=["T1562.001"],
        )

    # Count type= occurrences
    type_counts = {}
    total_events = 0
    for line in out.splitlines():
        match = re.search(r'type=(\S+)', line)
        if match:
            event_type = match.group(1)
            type_counts[event_type] = type_counts.get(event_type, 0) + 1
            total_events += 1

    evidence["total_events_sampled"] = total_events
    evidence["type_counts"] = dict(sorted(
        type_counts.items(), key=lambda x: x[1], reverse=True
    )[:15])

    if total_events == 0:
        return CheckResult(
            check_id="LINUX-NOISE-006",
            title="No typed events found in audit log sample",
            severity="INFO",
            detail="No type= fields found in the last 10000 lines of the audit log.",
            remediation="Ensure auditd rules are loaded and generating events.",
            category="noise",
            platform="linux",
            evidence=evidence,
            mitre_techniques=["T1562.001"],
        )

    # Find dominant types
    dominant_types = []
    for event_type, count in type_counts.items():
        ratio = count / total_events
        if ratio > 0.60:
            dominant_types.append((event_type, count, ratio))

    evidence["dominant_types"] = [
        {"type": t, "count": c, "ratio": round(r, 3)}
        for t, c, r in dominant_types
    ]

    if dominant_types:
        dominant_detail = ", ".join(
            "{} ({:.0f}%, {} events)".format(t, r * 100, c)
            for t, c, r in dominant_types
        )
        noise_note = ""
        for t, c, r in dominant_types:
            if t in ("PATH", "CWD"):
                noise_note = (
                    " PATH and CWD are common noise generators -- every syscall "
                    "audit event generates multiple PATH and CWD records as "
                    "supplementary data."
                )
                break

        return CheckResult(
            check_id="LINUX-NOISE-006",
            title="Dominant event type(s) detected in audit log",
            severity="WARN",
            detail=(
                "Every auditd syscall event generates multiple supplementary records: "
                "a SYSCALL record, one or more PATH records (for each file involved), "
                "a CWD record (current working directory), and a PROCTITLE record "
                "(process command line). On a system with broad syscall rules, PATH "
                "records alone can make up 50-70% of all audit events. While these "
                "supplementary records provide forensic context, they also inflate log "
                "volume significantly. If a single event type dominates your audit log, "
                "it indicates that either your rules are too broad (monitoring syscalls "
                "that happen millions of times per day) or you need SIEM-side filtering "
                "to discard the noise. Dominant type(s): {}.{}"
            ).format(dominant_detail, noise_note),
            remediation=(
                "Review and narrow your audit rules to reduce the dominant event type "
                "volume. Options:\n"
                "  - Add exclusion rules for known-noisy processes (package managers, "
                "monitoring agents)\n"
                "  - Use auid filters to exclude system daemon activity\n"
                "  - Configure SIEM-side filtering to drop low-value supplementary "
                "records (CWD, PROCTITLE) while keeping SYSCALL and PATH\n"
                "  - Narrow broad syscall rules to specific programs or directories\n"
                "Then reload: sudo augenrules --load"
            ),
            category="noise",
            platform="linux",
            evidence=evidence,
            mitre_techniques=["T1562.001"],
        )

    return CheckResult(
        check_id="LINUX-NOISE-006",
        title="Audit event type distribution is balanced",
        severity="PASS",
        detail=(
            "Every auditd syscall event generates multiple supplementary records: "
            "a SYSCALL record, one or more PATH records (for each file involved), "
            "a CWD record (current working directory), and a PROCTITLE record "
            "(process command line). On a system with broad syscall rules, PATH "
            "records alone can make up 50-70% of all audit events. While these "
            "supplementary records provide forensic context, they also inflate log "
            "volume significantly. If a single event type dominates your audit log, "
            "it indicates that either your rules are too broad or you need SIEM-side "
            "filtering to discard the noise. No single event type exceeds 60% of "
            "the sampled events, indicating a healthy distribution."
        ),
        remediation="No action required.",
        category="noise",
        platform="linux",
        evidence=evidence,
        mitre_techniques=["T1562.001"],
    )


def run_checks():
    """Return all noise analysis checks."""
    return [
        _check_auid_unset_filter(),
        _check_broad_tmp_watches(),
        _check_system_process_volume(),
        _check_duplicate_forwarding(),
        _check_aureport_summary(),
        _check_high_volume_event_types(),
    ]
