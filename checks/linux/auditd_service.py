"""Auditd service checks: installation, running state, and boot enablement."""

import glob

from core.result import CheckResult
from core.platform_utils import (
    safe_run, read_file_safe, file_exists, is_elevated,
    get_package_manager, parse_config_file, get_file_mtime,
    check_process_running, get_linux_distro,
)


def _check_auditd_installed():
    """LINUX-AUDITD-001: Is auditd installed?"""
    pm = get_package_manager()
    distro = get_linux_distro()
    evidence = {}

    # Try 'which auditd' first
    rc, out, _ = safe_run(["which", "auditd"])
    evidence["which_auditd"] = out.strip() if rc == 0 else "not found"

    if rc == 0:
        return CheckResult(
            check_id="LINUX-AUDITD-001",
            title="Auditd installed",
            severity="PASS",
            detail="auditd is the Linux Audit Framework daemon -- it hooks into the kernel to record "
                   "security-relevant events such as process execution, file access, permission changes, "
                   "and network connections. The auditd binary was found at {}. With auditd installed, "
                   "the system is capable of generating a detailed audit trail for incident response "
                   "and compliance purposes.".format(out.strip()),
            remediation="No action required.",
            category="service",
            platform="linux",
            evidence=evidence,
            mitre_techniques=["T1562.001"],
        )

    # Check via package manager
    if pm in ("apt-get",):
        rc_pkg, out_pkg, _ = safe_run(["dpkg", "-l", "auditd"])
        evidence["dpkg"] = out_pkg.strip()
        if rc_pkg == 0 and "ii" in out_pkg:
            return CheckResult(
                check_id="LINUX-AUDITD-001",
                title="Auditd installed",
                severity="PASS",
                detail="auditd is the Linux Audit Framework daemon -- it hooks into the kernel to record "
                       "security-relevant events such as process execution, file access, permission changes, "
                       "and network connections. The auditd package is installed (confirmed via dpkg). "
                       "With auditd installed, the system is capable of generating a detailed audit trail "
                       "for incident response and compliance purposes.",
                remediation="No action required.",
                category="service",
                platform="linux",
                evidence=evidence,
                mitre_techniques=["T1562.001"],
            )
    elif pm in ("dnf", "yum"):
        rc_pkg, out_pkg, _ = safe_run(["rpm", "-q", "audit"])
        evidence["rpm"] = out_pkg.strip()
        if rc_pkg == 0:
            return CheckResult(
                check_id="LINUX-AUDITD-001",
                title="Auditd installed",
                severity="PASS",
                detail="auditd is the Linux Audit Framework daemon -- it hooks into the kernel to record "
                       "security-relevant events such as process execution, file access, permission changes, "
                       "and network connections. The audit package is installed (confirmed via rpm). "
                       "With auditd installed, the system is capable of generating a detailed audit trail "
                       "for incident response and compliance purposes.",
                remediation="No action required.",
                category="service",
                platform="linux",
                evidence=evidence,
                mitre_techniques=["T1562.001"],
            )

    # Not found - build distro-specific install command
    install_cmds = {
        "apt-get": "sudo apt-get install -y auditd audispd-plugins",
        "dnf": "sudo dnf install -y audit",
        "yum": "sudo yum install -y audit",
        "zypper": "sudo zypper install -y audit",
        "pacman": "sudo pacman -S audit",
    }
    install_cmd = install_cmds.get(pm, "Install the audit/auditd package for your distribution.")

    return CheckResult(
        check_id="LINUX-AUDITD-001",
        title="Auditd not installed",
        severity="FAIL",
        detail="auditd is the Linux Audit Framework daemon -- it hooks into the kernel to record "
               "security-relevant events such as process execution (execve), file access, permission changes, "
               "user authentication, and network connections. The auditd binary was not found and the package "
               "was not detected via {}. Without auditd, the system has no kernel-level audit trail. This means "
               "if an attacker gains access, there will be no record of what commands they ran, what files they "
               "accessed, or how they escalated privileges -- making incident response and forensics extremely "
               "difficult.".format(pm),
        remediation="Install auditd using your package manager. This installs the daemon and its rule-loading "
                    "utilities:\n  {}\nThe audispd-plugins package (on Debian/Ubuntu) adds dispatcher plugins "
                    "for forwarding audit events to remote SIEM systems.".format(install_cmd),
        category="service",
        platform="linux",
        evidence=evidence,
        mitre_techniques=["T1562.001"],
    )


def _check_auditd_running():
    """LINUX-AUDITD-002: Is auditd service running?"""
    evidence = {}

    # systemctl check
    rc, out, err = safe_run(["systemctl", "is-active", "auditd"])
    evidence["systemctl_is_active"] = out.strip()

    if rc == 0 and out.strip() == "active":
        return CheckResult(
            check_id="LINUX-AUDITD-002",
            title="Auditd service running",
            severity="PASS",
            detail="The auditd daemon is the userspace process that reads audit events from the kernel's "
                   "audit subsystem and writes them to log files on disk. systemctl confirms auditd is "
                   "currently active and processing events. While auditd is running, all configured audit "
                   "rules are being enforced and security events are being recorded to the audit log "
                   "(typically /var/log/audit/audit.log).",
            remediation="No action required.",
            category="service",
            platform="linux",
            evidence=evidence,
            mitre_techniques=["T1562.001"],
        )

    # Fallback: service command
    rc2, out2, _ = safe_run(["service", "auditd", "status"])
    evidence["service_status"] = out2.strip()
    if rc2 == 0 and "running" in out2.lower():
        return CheckResult(
            check_id="LINUX-AUDITD-002",
            title="Auditd service running",
            severity="PASS",
            detail="The auditd daemon is the userspace process that reads audit events from the kernel's "
                   "audit subsystem and writes them to log files on disk. The init-style service command "
                   "confirms auditd is currently running and processing events. All configured audit rules "
                   "are being enforced and security events are being recorded.",
            remediation="No action required.",
            category="service",
            platform="linux",
            evidence=evidence,
            mitre_techniques=["T1562.001"],
        )

    # Fallback: process check
    if check_process_running("auditd"):
        evidence["process_running"] = True
        return CheckResult(
            check_id="LINUX-AUDITD-002",
            title="Auditd process running",
            severity="PASS",
            detail="The auditd daemon is the userspace process that reads audit events from the kernel's "
                   "audit subsystem and writes them to log files on disk. An auditd process was detected "
                   "via pgrep, confirming the daemon is active. Note: the process is running, but systemctl "
                   "did not report it as active, which may indicate it was started manually rather than "
                   "through the service manager.",
            remediation="No action required.",
            category="service",
            platform="linux",
            evidence=evidence,
            mitre_techniques=["T1562.001"],
        )

    return CheckResult(
        check_id="LINUX-AUDITD-002",
        title="Auditd service not running",
        severity="FAIL",
        detail="The auditd daemon is the userspace process that reads audit events from the kernel's "
               "audit subsystem and writes them to log files on disk. auditd is not currently running, "
               "which means no kernel audit events are being collected. This includes process execution "
               "tracking (who ran what commands), file access monitoring (who read or modified sensitive "
               "files), privilege escalation events (use of sudo, su, or setuid), user authentication "
               "events, and network connection attempts. Without these records, an active intrusion "
               "could go completely undetected, and post-incident forensics would have no audit trail "
               "to reconstruct the attacker's actions.",
        remediation="Start auditd immediately and enable it for future boots:\n"
                    "  sudo systemctl start auditd && sudo systemctl enable auditd\n"
                    "'start' launches the daemon right now so events begin recording immediately. "
                    "'enable' creates the systemd symlink so auditd starts automatically on every boot.",
        category="service",
        platform="linux",
        evidence=evidence,
        mitre_techniques=["T1562.001"],
    )


def _check_auditd_enabled():
    """LINUX-AUDITD-003: Is auditd enabled at boot?"""
    evidence = {}

    rc, out, _ = safe_run(["systemctl", "is-enabled", "auditd"])
    evidence["systemctl_is_enabled"] = out.strip()

    if rc == 0 and out.strip() == "enabled":
        return CheckResult(
            check_id="LINUX-AUDITD-003",
            title="Auditd enabled at boot",
            severity="PASS",
            detail="A service being 'enabled at boot' means systemd will automatically start it during "
                   "the system startup sequence, without any manual intervention. auditd is confirmed "
                   "enabled, so audit logging will begin recording events as soon as the system boots. "
                   "This eliminates the dangerous gap between system startup and when an administrator "
                   "might manually start the service.",
            remediation="No action required.",
            category="service",
            platform="linux",
            evidence=evidence,
            mitre_techniques=["T1562.001"],
        )

    return CheckResult(
        check_id="LINUX-AUDITD-003",
        title="Auditd not enabled at boot",
        severity="WARN",
        detail="A service being 'enabled at boot' means systemd will automatically start it during "
               "the system startup sequence. auditd is not enabled (systemctl reports '{}'). This "
               "creates a critical blind spot: after every reboot, the system will run without audit "
               "logging until someone manually starts auditd. An attacker who can trigger a reboot "
               "(or simply wait for a maintenance window) gets a window of completely unmonitored "
               "activity. Any commands executed, files accessed, or privilege escalations during "
               "this gap will leave no audit trail.".format(out.strip()),
        remediation="Enable auditd to start automatically at boot:\n"
                    "  sudo systemctl enable auditd\n"
                    "This creates a symlink in the systemd boot targets so auditd launches during "
                    "system initialization. The service will start early in the boot process, "
                    "minimizing the window before audit events are captured. Note: this does not "
                    "start auditd right now -- if it is not currently running, also run "
                    "'sudo systemctl start auditd'.",
        category="service",
        platform="linux",
        evidence=evidence,
        mitre_techniques=["T1562.001"],
    )


def _check_kernel_audit_status():
    """LINUX-AUDITD-013: Kernel audit subsystem status."""
    evidence = {}

    if not is_elevated():
        return CheckResult(
            check_id="LINUX-AUDITD-013",
            title="Kernel audit status (skipped -- not root)",
            severity="SKIP",
            detail="The auditctl -s command queries the kernel audit subsystem directly to confirm "
                   "whether audit events are actually being generated. This command requires root "
                   "privileges to read the kernel audit state. Re-run this tool with sudo or as root "
                   "to perform this check.",
            remediation="Re-run with elevated privileges: sudo security-log-auditor",
            category="service",
            platform="linux",
            evidence={"reason": "auditctl requires root"},
            mitre_techniques=["T1562.001"],
        )

    rc, out, err = safe_run(["auditctl", "-s"])
    evidence["auditctl_s_rc"] = rc
    evidence["auditctl_s_output"] = out.strip()

    if rc != 0:
        return CheckResult(
            check_id="LINUX-AUDITD-013",
            title="Kernel audit status unavailable",
            severity="SKIP",
            detail="The auditctl -s command failed (return code {}). This may indicate that auditd "
                   "is not installed or the audit kernel module is not loaded. The auditd daemon is "
                   "the userspace process that writes events to disk, but the kernel audit subsystem "
                   "is the actual source of events. Without being able to query the kernel, we cannot "
                   "confirm whether audit events are being generated.".format(rc),
            remediation="Ensure auditd is installed and the audit kernel subsystem is available. "
                        "Install auditd with your package manager, then run: sudo auditctl -s",
            category="service",
            platform="linux",
            evidence=evidence,
            mitre_techniques=["T1562.001"],
        )

    # Parse key fields from auditctl -s output
    fields = {}
    for line in out.strip().splitlines():
        parts = line.strip().split(None, 1)
        if len(parts) == 2:
            key = parts[0].rstrip("=").strip()
            val = parts[1].strip()
            fields[key] = val
        elif "=" in line:
            key, _, val = line.partition("=")
            fields[key.strip()] = val.strip()

    evidence["parsed_fields"] = fields

    enabled_str = fields.get("enabled", "")
    lost_str = fields.get("lost", "0")
    failure_str = fields.get("failure", "")
    backlog_limit_str = fields.get("backlog_limit", "")
    backlog_str = fields.get("backlog", "")

    try:
        enabled = int(enabled_str)
    except (ValueError, TypeError):
        enabled = -1

    try:
        lost = int(lost_str)
    except (ValueError, TypeError):
        lost = 0

    evidence["enabled"] = enabled
    evidence["lost"] = lost
    evidence["failure"] = failure_str
    evidence["backlog_limit"] = backlog_limit_str
    evidence["backlog"] = backlog_str

    base_detail = (
        "The auditd daemon is the userspace process that writes events to disk, but the kernel "
        "audit subsystem is the actual source of events. It is possible for auditd to be running "
        "while the kernel audit subsystem is disabled (enabled=0) -- in this case auditd is running "
        "but receiving zero events. The auditctl -s command queries the kernel directly to confirm "
        "events are being generated. The lost counter shows how many events were permanently dropped "
        "because the kernel's backlog buffer overflowed before auditd could read them -- each lost "
        "event is a gap in your security record that cannot be recovered."
    )

    if enabled == 0:
        return CheckResult(
            check_id="LINUX-AUDITD-013",
            title="Kernel audit subsystem DISABLED",
            severity="FAIL",
            detail="{} The kernel audit subsystem reports enabled=0, meaning the kernel is not "
                   "generating any audit events. Even if the auditd daemon is running, it is receiving "
                   "nothing. No process execution, file access, authentication, or privilege escalation "
                   "events are being captured. This is a complete audit blindspot -- an attacker could "
                   "perform any action on this system with zero audit trail.".format(base_detail),
            remediation="Enable the kernel audit subsystem immediately:\n"
                        "  sudo auditctl -e 1\n"
                        "This tells the kernel to begin generating audit events. To make this persistent "
                        "across reboots, ensure your audit rules files contain '-e 1' (but not '-e 2' "
                        "unless you want immutable mode). Also verify auditd is running:\n"
                        "  sudo systemctl status auditd",
            category="service",
            platform="linux",
            evidence=evidence,
            mitre_techniques=["T1562.001"],
        )

    if lost > 0:
        return CheckResult(
            check_id="LINUX-AUDITD-013",
            title="Kernel audit events lost ({} dropped)".format(lost),
            severity="WARN",
            detail="{} The kernel reports enabled={} ({}), so auditing is active. However, the lost "
                   "counter is {} -- this means {} audit events were permanently dropped because the "
                   "kernel's backlog buffer overflowed before auditd could read them. Each lost event "
                   "is an unrecoverable gap in your security record. The current backlog_limit is {} "
                   "and the current backlog is {}. Events are typically lost during bursts of high "
                   "system activity when auditd cannot drain the kernel buffer fast enough.".format(
                       base_detail,
                       enabled,
                       "auditing active" if enabled == 1 else "immutable/locked",
                       lost, lost,
                       backlog_limit_str or "unknown",
                       backlog_str or "unknown"),
            remediation="Increase the backlog buffer to reduce future event loss:\n"
                        "  sudo auditctl -b 8192\n"
                        "To make this persistent, add to your audit rules:\n"
                        "  -b 8192\n"
                        "The lost counter resets on reboot. To clear it without rebooting, restart "
                        "auditd:\n"
                        "  sudo service auditd restart\n"
                        "Note: the {} events already lost cannot be recovered.".format(lost),
            category="service",
            platform="linux",
            evidence=evidence,
            mitre_techniques=["T1562.001"],
        )

    return CheckResult(
        check_id="LINUX-AUDITD-013",
        title="Kernel audit subsystem active",
        severity="PASS",
        detail="{} The kernel reports enabled={} ({}), confirming audit events are being generated "
               "and delivered to the auditd daemon. The lost counter is 0, meaning no events have "
               "been dropped due to backlog overflow. The failure mode is {} and the backlog_limit "
               "is {}.".format(
                   base_detail,
                   enabled,
                   "auditing active" if enabled == 1 else "immutable/locked",
                   failure_str or "unknown",
                   backlog_limit_str or "unknown"),
        remediation="No action required.",
        category="service",
        platform="linux",
        evidence=evidence,
        mitre_techniques=["T1562.001"],
    )


def run_checks():
    """Return all auditd service checks."""
    return [
        _check_auditd_installed(),
        _check_auditd_running(),
        _check_auditd_enabled(),
        _check_kernel_audit_status(),
    ]
