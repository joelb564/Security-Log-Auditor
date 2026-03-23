"""Auditd rules checks: coverage for critical syscalls, files, and events."""

import glob
import re

from core.result import CheckResult
from core.platform_utils import (
    safe_run, read_file_safe, file_exists, is_elevated,
    get_package_manager, parse_config_file, get_file_mtime,
    check_process_running, get_linux_distro,
)


def _read_all_rules():
    """Read and combine all audit rule lines from rules.d and audit.rules."""
    lines = []
    sources = {}
    rule_files = sorted(glob.glob("/etc/audit/rules.d/*.rules"))
    if file_exists("/etc/audit/audit.rules"):
        rule_files.append("/etc/audit/audit.rules")
    for rf in rule_files:
        content = read_file_safe(rf)
        if content:
            file_lines = []
            for line in content.splitlines():
                stripped = line.strip()
                if stripped and not stripped.startswith("#"):
                    file_lines.append(stripped)
                    lines.append(stripped)
            if file_lines:
                sources[rf] = file_lines
    return lines, sources


def _rules_contain(lines, pattern):
    """Check if any rule line matches a regex pattern."""
    compiled = re.compile(pattern)
    return any(compiled.search(line) for line in lines)


def _find_matching_rules(lines, pattern):
    """Return all rule lines matching a regex pattern."""
    compiled = re.compile(pattern)
    return [line for line in lines if compiled.search(line)]


def _check_execve_monitoring(lines):
    """LINUX-RULES-001: execve syscall monitoring (b64 and b32, auid filter)."""
    evidence = {}

    b64_execve = _find_matching_rules(lines, r'-a\s+.*arch=b64.*-S\s+execve')
    b32_execve = _find_matching_rules(lines, r'-a\s+.*arch=b32.*-S\s+execve')
    auid_filter = _find_matching_rules(lines, r'-S\s+execve.*auid[!><=]')

    evidence["b64_execve_rules"] = b64_execve
    evidence["b32_execve_rules"] = b32_execve
    evidence["auid_filtered_rules"] = auid_filter

    has_b64 = len(b64_execve) > 0
    has_b32 = len(b32_execve) > 0

    if has_b64 and has_b32:
        return CheckResult(
            check_id="LINUX-RULES-001",
            title="Execve syscall monitoring present",
            severity="PASS",
            detail=(
                "The execve syscall is invoked every time a new process is launched on the system, "
                "making it the single most important syscall for command-line auditing. "
                "Monitoring is correctly configured for both 64-bit ({} rules) and 32-bit ({} rules) "
                "syscall tables. This means every command execution -- whether from interactive shells, "
                "scripts, or cron jobs -- will be recorded, and attackers cannot evade logging by "
                "compiling 32-bit binaries."
            ).format(len(b64_execve), len(b32_execve)),
            remediation="No action required.",
            category="rules",
            platform="linux",
            evidence=evidence,
            mitre_techniques=["T1059"],
        )

    missing = []
    if not has_b64:
        missing.append("b64")
    if not has_b32:
        missing.append("b32")

    severity = "WARN" if (has_b64 or has_b32) else "FAIL"

    missing_arch_explanation = []
    if "b64" in missing:
        missing_arch_explanation.append(
            "b64 (64-bit) -- the default execution mode on modern Linux; most processes use this syscall table"
        )
    if "b32" in missing:
        missing_arch_explanation.append(
            "b32 (32-bit) -- Linux can still execute 32-bit binaries, which use a completely separate "
            "syscall table; attackers deliberately compile 32-bit tools to bypass 64-bit-only monitoring"
        )

    return CheckResult(
        check_id="LINUX-RULES-001",
        title="Execve syscall monitoring incomplete",
        severity=severity,
        detail=(
            "The execve syscall is the kernel entry point called every time any process is launched "
            "on the system -- it is the foundation of command-line auditing. "
            "Monitoring is missing for the following architecture(s): {}. "
            "Linux maintains separate syscall tables for 32-bit and 64-bit execution modes. "
            "Without coverage for both, an attacker can compile a 32-bit binary (gcc -m32) to "
            "execute commands that completely bypass your audit logging. "
            "The auid (audit UID) filter tracks the original login user across sudo/su chains, "
            "so you can always trace activity back to who actually logged in, not just which "
            "service account ran the command."
        ).format("; ".join(missing_arch_explanation)),
        remediation=(
            "Add the following rules to /etc/audit/rules.d/10-execve.rules:\n"
            "  -a always,exit -F arch=b64 -S execve -F auid>=1000 -F auid!=unset -k exec\n"
            "  -a always,exit -F arch=b32 -S execve -F auid>=1000 -F auid!=unset -k exec\n"
            "What these rules do:\n"
            "  - '-a always,exit' means log on every syscall exit (captures both success and failure)\n"
            "  - '-F arch=b64/b32' targets the specific syscall table for that architecture\n"
            "  - '-S execve' monitors the process execution syscall\n"
            "  - '-F auid>=1000' only logs executions by human users (UIDs 1000+), reducing noise from system services\n"
            "  - '-F auid!=unset' excludes processes with no login context (e.g., early boot daemons)\n"
            "  - '-k exec' tags each event with the key 'exec' for easy searching with ausearch -k exec\n"
            "Trade-off: execve logging on busy systems can generate significant log volume. "
            "The auid>=1000 filter helps, but consider your disk and log rotation capacity.\n"
            "Then reload: sudo augenrules --load"
        ),
        category="rules",
        platform="linux",
        evidence=evidence,
        mitre_techniques=["T1059"],
    )


def _check_privileged_commands(lines):
    """LINUX-RULES-002: Privileged command monitoring."""
    evidence = {}
    priv_cmds = ["/usr/bin/sudo", "/usr/bin/su", "/usr/bin/passwd", "/usr/bin/chsh",
                 "/usr/bin/chfn", "/usr/bin/newgrp", "/usr/sbin/usermod",
                 "/usr/sbin/useradd", "/usr/sbin/userdel", "/usr/sbin/groupadd",
                 "/usr/sbin/groupmod", "/usr/sbin/groupdel", "/usr/bin/pkexec"]

    monitored = []
    missing = []

    for cmd in priv_cmds:
        pattern = re.escape(cmd)
        if _rules_contain(lines, pattern):
            monitored.append(cmd)
        else:
            # Also check short name
            short = cmd.split("/")[-1]
            if _rules_contain(lines, r'-w\s+.*' + re.escape(short)) or \
               _rules_contain(lines, re.escape(cmd)):
                monitored.append(cmd)
            else:
                missing.append(cmd)

    evidence["monitored"] = monitored
    evidence["missing"] = missing

    if not missing:
        return CheckResult(
            check_id="LINUX-RULES-002",
            title="Privileged command monitoring complete",
            severity="PASS",
            detail=(
                "Privileged commands are setuid/setgid binaries that execute with elevated permissions "
                "regardless of which user invokes them, making them prime targets for abuse and privilege "
                "escalation. All {} critical privileged commands are being monitored. This provides "
                "visibility into authentication changes (passwd, su, sudo), user/group management "
                "(useradd, userdel, usermod, groupadd, groupmod, groupdel), identity switching (newgrp), "
                "and policy-based privilege escalation (pkexec)."
            ).format(len(priv_cmds)),
            remediation="No action required.",
            category="rules",
            platform="linux",
            evidence=evidence,
            mitre_techniques=["T1548.003", "T1078"],
        )

    severity = "FAIL" if len(missing) > len(priv_cmds) // 2 else "WARN"

    # Build explanatory descriptions for each missing command
    cmd_explanations = {
        "sudo": "sudo -- allows running commands as root; abuse grants full system control",
        "su": "su -- switches to another user account; used to pivot between compromised accounts",
        "passwd": "passwd -- changes user passwords; an attacker can lock out legitimate users or set known passwords for persistence",
        "chsh": "chsh -- changes a user's login shell; an attacker can set it to a malicious binary that executes on every login",
        "chfn": "chfn -- changes user GECOS information; on some systems this can be abused to inject data into /etc/passwd",
        "newgrp": "newgrp -- changes the current group ID; can be used to gain access to files restricted to specific groups",
        "usermod": "usermod -- modifies user accounts; can add users to privileged groups like sudo or docker",
        "useradd": "useradd -- creates new user accounts; attackers create backdoor accounts for persistent access",
        "userdel": "userdel -- deletes user accounts; used to cover tracks or cause denial of service",
        "groupadd": "groupadd -- creates new groups; can be used to establish new permission boundaries",
        "groupmod": "groupmod -- modifies groups; can alter which users have access to group-owned resources",
        "groupdel": "groupdel -- deletes groups; disrupts access controls that depend on group membership",
        "pkexec": "pkexec -- PolicyKit privilege escalation; CVE-2021-4034 (PwnKit) exploited this for trivial root access",
    }

    missing_short = [m.split("/")[-1] for m in missing]
    missing_details = []
    for m in missing:
        short = m.split("/")[-1]
        if short in cmd_explanations:
            missing_details.append(cmd_explanations[short])
        else:
            missing_details.append(short)

    remediation_lines = [
        "Add the following rules to /etc/audit/rules.d/20-privileged.rules.\n"
        "Each rule monitors a setuid binary -- these are programs that run with the file owner's "
        "permissions (usually root) regardless of who executes them. Monitoring them detects "
        "privilege escalation attempts, unauthorized account changes, and lateral movement:"
    ]
    for cmd in missing[:5]:
        short = cmd.split("/")[-1]
        remediation_lines.append("  -a always,exit -F path={} -F perm=x -F auid>=1000 -F auid!=unset -k privileged".format(cmd))
    if len(missing) > 5:
        remediation_lines.append("  # ... and {} more commands".format(len(missing) - 5))
    remediation_lines.append(
        "The '-F perm=x' filter triggers only on execution (not reads), "
        "and '-F auid>=1000' limits logging to human users.\n"
        "Then reload: sudo augenrules --load"
    )

    return CheckResult(
        check_id="LINUX-RULES-002",
        title="Privileged command monitoring incomplete",
        severity=severity,
        detail=(
            "Privileged (setuid/setgid) commands are binaries that run with elevated permissions "
            "regardless of who invokes them -- they are the primary mechanism for privilege escalation "
            "on Linux. {} of {} privileged commands are not being monitored. "
            "Without audit rules on these binaries, an attacker who gains initial access as a low-privilege "
            "user can escalate to root or modify accounts without leaving an audit trail.\n"
            "Unmonitored commands:\n  {}"
        ).format(len(missing), len(priv_cmds), "\n  ".join(missing_details)),
        remediation="\n".join(remediation_lines),
        category="rules",
        platform="linux",
        evidence=evidence,
        mitre_techniques=["T1548.003", "T1078"],
    )


def _check_critical_file_watches(lines):
    """LINUX-RULES-003: Critical file watches."""
    evidence = {}
    critical_files = [
        "/etc/passwd", "/etc/shadow", "/etc/group", "/etc/gshadow",
        "/etc/sudoers", "/etc/sudoers.d/", "/etc/ssh/sshd_config",
        "/etc/audit/auditd.conf", "/etc/audit/rules.d/",
        "/var/log/auth.log", "/var/log/secure",
        "/bin/bash", "/bin/sh",
        "/etc/pam.d/", "/etc/systemd/system/",
    ]

    monitored = []
    missing = []

    for path in critical_files:
        escaped = re.escape(path.rstrip("/"))
        if _rules_contain(lines, r'-w\s+' + escaped):
            monitored.append(path)
        else:
            missing.append(path)

    # /var/log/auth.log and /var/log/secure are distro-specific -- only flag if both missing
    auth_log_covered = "/var/log/auth.log" in monitored or "/var/log/secure" in monitored
    if auth_log_covered:
        missing = [m for m in missing if m not in ("/var/log/auth.log", "/var/log/secure")]

    evidence["monitored"] = monitored
    evidence["missing"] = missing

    if not missing:
        return CheckResult(
            check_id="LINUX-RULES-003",
            title="Critical file watches in place",
            severity="PASS",
            detail=(
                "File watches (the -w flag in audit rules) monitor reads, writes, attribute changes, "
                "and executions on specific files or directories. All critical system files and "
                "directories are being monitored. This provides visibility into account manipulation "
                "(passwd/shadow/group), privilege escalation configuration (sudoers), remote access "
                "settings (sshd_config), audit tamper attempts (auditd.conf, rules.d), "
                "authentication logs, and shell execution."
            ),
            remediation="No action required.",
            category="rules",
            platform="linux",
            evidence=evidence,
            mitre_techniques=["T1222", "T1098"],
        )

    severity = "FAIL" if len(missing) > 3 else "WARN"

    # Build explanations for each missing file
    file_explanations = {
        "/etc/passwd": "/etc/passwd -- contains all user account definitions (username, UID, home directory, login shell); "
                       "an attacker modifying this can create backdoor accounts or change a user's shell to something malicious",
        "/etc/shadow": "/etc/shadow -- stores hashed passwords for all users; "
                       "reading it enables offline password cracking, writing it lets an attacker set known passwords",
        "/etc/group": "/etc/group -- defines group memberships; "
                      "adding a user to the 'sudo' or 'docker' group silently grants them elevated privileges",
        "/etc/gshadow": "/etc/gshadow -- stores group passwords and admin lists; "
                        "rarely used but modification can grant group-level access",
        "/etc/sudoers": "/etc/sudoers -- controls who can run commands as root via sudo; "
                        "a single line like 'attacker ALL=(ALL) NOPASSWD:ALL' grants full root access",
        "/etc/sudoers.d/": "/etc/sudoers.d/ -- drop-in directory for sudo rules; "
                           "attackers prefer dropping files here because it is less conspicuous than editing sudoers directly",
        "/etc/ssh/sshd_config": "/etc/ssh/sshd_config -- SSH server configuration; "
                                "an attacker can enable root login, weaken ciphers, or add authorized keys directives",
        "/etc/audit/auditd.conf": "/etc/audit/auditd.conf -- auditd daemon configuration; "
                                  "modifying this can reduce log sizes, disable logging, or redirect logs to /dev/null",
        "/etc/audit/rules.d/": "/etc/audit/rules.d/ -- audit rule definitions; "
                               "an attacker's first move after gaining root is often to delete or weaken audit rules to cover their tracks",
        "/var/log/auth.log": "/var/log/auth.log -- Debian/Ubuntu authentication log; "
                             "records all login attempts, sudo usage, and SSH sessions",
        "/var/log/secure": "/var/log/secure -- RHEL/CentOS authentication log; "
                           "equivalent to auth.log on Red Hat-based distributions",
        "/bin/bash": "/bin/bash -- the default interactive shell; "
                     "if replaced with a trojanized binary, every user session executes attacker code",
        "/bin/sh": "/bin/sh -- the POSIX shell used by most system scripts; "
                   "replacing it compromises every shell script and subprocess on the system",
    }

    missing_details = []
    for m in missing:
        if m in file_explanations:
            missing_details.append(file_explanations[m])
        else:
            missing_details.append(m)

    remediation_lines = [
        "Add the following file watches to /etc/audit/rules.d/30-critical-files.rules.\n"
        "File watches use '-p wa' (write + attribute change) to log any modification. "
        "Each '-k' tag provides a searchable label so you can quickly query related events "
        "with 'ausearch -k <keyname>':"
    ]
    for path in missing:
        perm = "wa"
        key = path.strip("/").replace("/", "_")
        if path.endswith("/"):
            remediation_lines.append("  -w {} -p {} -k {}".format(path, perm, key))
        else:
            remediation_lines.append("  -w {} -p {} -k {}".format(path, perm, key))
    remediation_lines.append(
        "Trade-off: watching directories like /etc/audit/rules.d/ generates events for every "
        "file created, modified, or deleted within them, which is the desired behavior for "
        "security-critical directories but can be noisy for high-churn paths.\n"
        "Then reload: sudo augenrules --load"
    )

    return CheckResult(
        check_id="LINUX-RULES-003",
        title="Critical file watches incomplete",
        severity=severity,
        detail=(
            "File watches are audit rules that monitor specific files or directories for reads, writes, "
            "and attribute changes. These critical system files form the backbone of authentication, "
            "authorization, and system integrity -- any unauthorized modification typically indicates "
            "active compromise or persistence installation. "
            "{} critical files/directories are not being monitored:\n  {}"
        ).format(len(missing), "\n  ".join(missing_details)),
        remediation="\n".join(remediation_lines),
        category="rules",
        platform="linux",
        evidence=evidence,
        mitre_techniques=["T1222", "T1098"],
    )


def _check_cron_monitoring(lines):
    """LINUX-RULES-004: Cron monitoring."""
    evidence = {}
    cron_paths = ["/etc/crontab", "/etc/cron.d/", "/var/spool/cron/",
                  "/etc/cron.daily/", "/etc/cron.hourly/",
                  "/etc/cron.weekly/", "/etc/cron.monthly/"]

    monitored = []
    missing = []
    for path in cron_paths:
        escaped = re.escape(path.rstrip("/"))
        if _rules_contain(lines, escaped):
            monitored.append(path)
        else:
            missing.append(path)

    evidence["monitored"] = monitored
    evidence["missing"] = missing

    if not missing:
        return CheckResult(
            check_id="LINUX-RULES-004",
            title="Cron monitoring complete",
            severity="PASS",
            detail=(
                "Cron is the Linux task scheduler, and it is one of the most commonly abused persistence "
                "mechanisms in real-world attacks (MITRE ATT&CK T1053.003 - Scheduled Task/Job: Cron). "
                "All cron-related paths are being monitored. This provides visibility into attackers "
                "dropping scheduled tasks that survive reboots, execute at predictable intervals, "
                "or run with elevated privileges. Monitoring covers the system-wide crontab, "
                "per-user cron spools, the drop-in directory, and all periodic execution directories."
            ),
            remediation="No action required.",
            category="rules",
            platform="linux",
            evidence=evidence,
            mitre_techniques=["T1053.003"],
        )

    severity = "WARN" if monitored else "FAIL"

    cron_explanations = {
        "/etc/crontab": "/etc/crontab -- the system-wide cron schedule; entries here run as root by default",
        "/etc/cron.d/": "/etc/cron.d/ -- drop-in directory for package and admin cron jobs; "
                        "attackers place files here because they blend in with legitimate system cron jobs",
        "/var/spool/cron/": "/var/spool/cron/ -- per-user crontab storage (created via 'crontab -e'); "
                            "each user's scheduled tasks live here, including those of compromised accounts",
        "/etc/cron.daily/": "/etc/cron.daily/ -- scripts run once per day; "
                            "a backdoor here executes reliably with minimal visibility",
        "/etc/cron.hourly/": "/etc/cron.hourly/ -- scripts run every hour; "
                             "provides rapid re-execution for persistence or C2 beaconing",
        "/etc/cron.weekly/": "/etc/cron.weekly/ -- scripts run once per week; "
                             "rarely inspected, making it a good hiding spot for long-term persistence",
        "/etc/cron.monthly/": "/etc/cron.monthly/ -- scripts run once per month; "
                              "almost never manually reviewed, ideal for stealthy backdoors",
    }

    missing_details = []
    for m in missing:
        if m in cron_explanations:
            missing_details.append(cron_explanations[m])
        else:
            missing_details.append(m)

    remediation_lines = [
        "Add the following watches to /etc/audit/rules.d/40-cron.rules.\n"
        "Cron is one of the top persistence mechanisms attackers use (MITRE T1053.003). "
        "By dropping a script or crontab entry, an attacker ensures their payload survives "
        "reboots, runs on a schedule, and often executes as root. Monitoring these paths "
        "lets you detect persistence installation in near real-time:"
    ]
    for path in missing:
        remediation_lines.append("  -w {} -p wa -k cron".format(path))
    remediation_lines.append(
        "The '-p wa' permission filter logs writes and attribute changes. "
        "Using the same '-k cron' key across all rules lets you search all cron-related "
        "activity with a single 'ausearch -k cron' command.\n"
        "Then reload: sudo augenrules --load"
    )

    return CheckResult(
        check_id="LINUX-RULES-004",
        title="Cron monitoring incomplete",
        severity=severity,
        detail=(
            "Cron is the Linux task scheduler and one of the most frequently abused persistence "
            "mechanisms in real-world attacks (MITRE ATT&CK T1053.003). Attackers drop scheduled "
            "tasks to survive reboots, maintain command-and-control callbacks, or periodically "
            "re-infect cleaned systems. {} of {} cron paths are not being monitored, meaning an "
            "attacker could install persistent scheduled tasks in these locations without generating "
            "any audit events:\n  {}"
        ).format(len(missing), len(cron_paths), "\n  ".join(missing_details)),
        remediation="\n".join(remediation_lines),
        category="rules",
        platform="linux",
        evidence=evidence,
        mitre_techniques=["T1053.003"],
    )


def _check_module_monitoring(lines):
    """LINUX-RULES-005: Module load/unload monitoring."""
    evidence = {}
    syscalls = ["init_module", "finit_module", "delete_module"]
    found = {}
    missing = []

    for sc in syscalls:
        matches = _find_matching_rules(lines, r'-S\s+' + sc)
        if matches:
            found[sc] = matches
        else:
            missing.append(sc)

    evidence["found_syscalls"] = found
    evidence["missing_syscalls"] = missing

    if not missing:
        return CheckResult(
            check_id="LINUX-RULES-005",
            title="Kernel module monitoring present",
            severity="PASS",
            detail=(
                "Kernel modules are loadable code that runs with full kernel-level privileges -- "
                "the highest privilege level on a Linux system, even above root. "
                "All module load/unload syscalls are being monitored: {}. "
                "This provides visibility into legitimate driver loading as well as rootkit "
                "installation attempts. Rootkits like Diamorphine, Reptile, and Adore-Ng use "
                "init_module or finit_module to load malicious kernel code that can hide processes, "
                "files, and network connections from userspace tools."
            ).format(", ".join(syscalls)),
            remediation="No action required.",
            category="rules",
            platform="linux",
            evidence=evidence,
            mitre_techniques=["T1547.006"],
        )

    syscall_explanations = {
        "init_module": "init_module -- the original syscall for loading a kernel module from a memory buffer; "
                       "used by older versions of insmod and by some rootkit loaders",
        "finit_module": "finit_module -- the newer file-descriptor-based module loading syscall (Linux 3.8+); "
                        "this is what modern insmod/modprobe actually calls, so missing this is the bigger gap",
        "delete_module": "delete_module -- unloads a kernel module; attackers use this to remove their rootkit "
                         "module after it has hooked kernel functions, or to unload legitimate security modules",
    }

    missing_details = []
    for m in missing:
        if m in syscall_explanations:
            missing_details.append(syscall_explanations[m])
        else:
            missing_details.append(m)

    return CheckResult(
        check_id="LINUX-RULES-005",
        title="Kernel module monitoring incomplete",
        severity="FAIL",
        detail=(
            "Kernel modules are loadable code that executes with full kernel privileges -- the highest "
            "privilege level on a Linux system, above even root userspace processes. "
            "The init_module and finit_module syscalls load kernel modules (drivers, filesystem handlers, "
            "and potentially rootkits), while delete_module unloads them. This is exactly how kernel "
            "rootkits like Diamorphine and Reptile work: they compile a malicious .ko file and load it "
            "via these syscalls, gaining the ability to hide processes, files, network connections, and "
            "even other kernel modules from all userspace tools including ps, ls, and netstat.\n"
            "Missing monitoring for:\n  {}"
        ).format("\n  ".join(missing_details)),
        remediation=(
            "Add the following rules to /etc/audit/rules.d/50-modules.rules:\n"
            "  -a always,exit -F arch=b64 -S init_module,finit_module,delete_module -k modules\n"
            "  -a always,exit -F arch=b32 -S init_module,finit_module,delete_module -k modules\n"
            "What these rules do:\n"
            "  - init_module: logs the legacy syscall for loading a module from a memory buffer\n"
            "  - finit_module: logs the modern syscall (Linux 3.8+) for loading a module from a file descriptor\n"
            "  - delete_module: logs module unloading, which can indicate an attacker removing evidence\n"
            "Both b64 and b32 variants are needed because module loading can technically be invoked "
            "from 32-bit code. On a properly configured production server, module loading should be "
            "rare after boot, so these rules generate minimal log volume.\n"
            "Then reload: sudo augenrules --load"
        ),
        category="rules",
        platform="linux",
        evidence=evidence,
        mitre_techniques=["T1547.006"],
    )


def _check_network_monitoring(lines):
    """LINUX-RULES-006: Network configuration changes."""
    evidence = {}
    net_files = ["/etc/hosts", "/etc/hostname", "/etc/resolv.conf",
                 "/etc/sysconfig/network", "/etc/network/"]
    net_syscalls = ["sethostname", "setdomainname"]

    file_monitored = []
    file_missing = []
    for path in net_files:
        escaped = re.escape(path.rstrip("/"))
        if _rules_contain(lines, escaped):
            file_monitored.append(path)
        else:
            file_missing.append(path)

    syscall_found = []
    syscall_missing = []
    for sc in net_syscalls:
        if _rules_contain(lines, r'-S\s+' + sc):
            syscall_found.append(sc)
        else:
            syscall_missing.append(sc)

    evidence["file_monitored"] = file_monitored
    evidence["file_missing"] = file_missing
    evidence["syscall_found"] = syscall_found
    evidence["syscall_missing"] = syscall_missing

    all_ok = not file_missing and not syscall_missing

    if all_ok:
        return CheckResult(
            check_id="LINUX-RULES-006",
            title="Network configuration monitoring complete",
            severity="PASS",
            detail=(
                "Network configuration files and syscalls control how the system resolves hostnames, "
                "routes DNS queries, and identifies itself on the network. All relevant files and "
                "syscalls are being monitored. This detects attacks such as DNS hijacking (modifying "
                "resolv.conf to redirect queries to attacker-controlled servers), traffic redirection "
                "(adding entries to /etc/hosts to reroute connections), and hostname changes that can "
                "break log correlation across your SIEM."
            ),
            remediation="No action required.",
            category="rules",
            platform="linux",
            evidence=evidence,
            mitre_techniques=["T1565.002"],
        )

    severity = "WARN" if (file_monitored or syscall_found) else "FAIL"

    file_explanations = {
        "/etc/hosts": "/etc/hosts -- static hostname-to-IP mappings that override DNS; an attacker can "
                      "redirect traffic (e.g., point your update server to a malicious IP) or block "
                      "security tool communications by routing them to 127.0.0.1",
        "/etc/hostname": "/etc/hostname -- the system's hostname; changing it can break log correlation "
                         "in centralized logging (your SIEM may treat events from the new hostname as a different host)",
        "/etc/resolv.conf": "/etc/resolv.conf -- DNS resolver configuration; an attacker changing the nameserver "
                            "directive can redirect ALL DNS queries to an attacker-controlled DNS server, enabling "
                            "man-in-the-middle attacks on every network connection",
        "/etc/sysconfig/network": "/etc/sysconfig/network -- RHEL/CentOS network configuration; changes here "
                                  "can modify routing, hostname, and gateway settings that persist across reboots",
        "/etc/network/": "/etc/network/ -- Debian/Ubuntu network configuration directory; modifications can "
                         "alter interfaces, routes, and DNS settings",
    }

    syscall_explanations = {
        "sethostname": "sethostname -- syscall that changes the system hostname at runtime; can break "
                       "log correlation and SIEM host identity",
        "setdomainname": "setdomainname -- syscall that changes the NIS/YP domain name; can affect "
                         "authentication in environments using NIS",
    }

    detail_parts = []
    if file_missing:
        file_details = []
        for f in file_missing:
            if f in file_explanations:
                file_details.append(file_explanations[f])
            else:
                file_details.append(f)
        detail_parts.append("Unmonitored files:\n  " + "\n  ".join(file_details))
    if syscall_missing:
        sc_details = []
        for s in syscall_missing:
            if s in syscall_explanations:
                sc_details.append(syscall_explanations[s])
            else:
                sc_details.append(s)
        detail_parts.append("Unmonitored syscalls:\n  " + "\n  ".join(sc_details))

    remediation_lines = [
        "Add the following rules to /etc/audit/rules.d/60-network.rules.\n"
        "Network configuration controls how the system resolves names and identifies itself. "
        "Unauthorized changes can redirect traffic, hijack DNS, or break log correlation:"
    ]
    if syscall_missing:
        remediation_lines.append(
            "  -a always,exit -F arch=b64 -S {} -k network_changes".format(",".join(net_syscalls)))
        remediation_lines.append(
            "  -a always,exit -F arch=b32 -S {} -k network_changes".format(",".join(net_syscalls)))
        remediation_lines.append(
            "  # sethostname/setdomainname are syscalls that change the system's identity at runtime")
    for path in file_missing:
        remediation_lines.append("  -w {} -p wa -k network_changes".format(path))
    remediation_lines.append(
        "Trade-off: on systems using DHCP or NetworkManager, resolv.conf and hostname may be "
        "updated automatically, generating expected events. You may want to tune your alerting "
        "to account for these legitimate changes.\n"
        "Then reload: sudo augenrules --load"
    )

    return CheckResult(
        check_id="LINUX-RULES-006",
        title="Network configuration monitoring incomplete",
        severity=severity,
        detail=(
            "Network configuration files and syscalls determine how the system resolves hostnames, "
            "directs DNS queries, and identifies itself on the network. Without monitoring, an "
            "attacker can silently redirect traffic, hijack DNS resolution, or change the system's "
            "hostname to disrupt log correlation in centralized logging systems.\n"
            "{}"
        ).format("\n".join(detail_parts)),
        remediation="\n".join(remediation_lines),
        category="rules",
        platform="linux",
        evidence=evidence,
        mitre_techniques=["T1565.002"],
    )


def _check_time_monitoring(lines):
    """LINUX-RULES-007: Time change monitoring."""
    evidence = {}
    time_syscalls = ["adjtimex", "settimeofday", "clock_settime"]
    time_files = ["/etc/localtime"]

    syscall_found = []
    syscall_missing = []
    for sc in time_syscalls:
        if _rules_contain(lines, r'-S\s+' + sc):
            syscall_found.append(sc)
        else:
            syscall_missing.append(sc)

    file_found = []
    file_missing = []
    for f in time_files:
        if _rules_contain(lines, re.escape(f)):
            file_found.append(f)
        else:
            file_missing.append(f)

    evidence["syscall_found"] = syscall_found
    evidence["syscall_missing"] = syscall_missing
    evidence["file_found"] = file_found
    evidence["file_missing"] = file_missing

    if not syscall_missing and not file_missing:
        return CheckResult(
            check_id="LINUX-RULES-007",
            title="Time change monitoring complete",
            severity="PASS",
            detail=(
                "System time is a critical component of security logging -- every audit event, log "
                "entry, and SIEM correlation depends on accurate timestamps. All time-related syscalls "
                "(adjtimex, settimeofday, clock_settime) and the timezone file (/etc/localtime) are "
                "being monitored. This detects attempts to manipulate timestamps to evade forensic "
                "analysis, break Kerberos authentication (which is time-sensitive), or shift malicious "
                "activity outside of SIEM detection windows."
            ),
            remediation="No action required.",
            category="rules",
            platform="linux",
            evidence=evidence,
            mitre_techniques=["T1070.006"],
        )

    severity = "WARN" if syscall_found else "FAIL"

    syscall_explanations = {
        "adjtimex": "adjtimex -- adjusts the kernel clock parameters; can be used for subtle time drift "
                    "that gradually shifts timestamps without a sudden obvious jump",
        "settimeofday": "settimeofday -- sets the system clock to an absolute value; allows an attacker "
                        "to jump the clock forward or backward to place their actions outside SIEM correlation windows",
        "clock_settime": "clock_settime -- the POSIX interface for setting clocks; the most commonly used "
                         "syscall for time changes on modern Linux systems",
    }

    file_explanations = {
        "/etc/localtime": "/etc/localtime -- the system timezone definition; changing the timezone shifts "
                          "how timestamps appear in logs without changing the actual UTC time, which can "
                          "confuse analysts correlating events across systems",
    }

    detail_parts = []
    if syscall_missing:
        sc_details = []
        for s in syscall_missing:
            if s in syscall_explanations:
                sc_details.append(syscall_explanations[s])
            else:
                sc_details.append(s)
        detail_parts.append("Unmonitored syscalls:\n  " + "\n  ".join(sc_details))
    if file_missing:
        f_details = []
        for f in file_missing:
            if f in file_explanations:
                f_details.append(file_explanations[f])
            else:
                f_details.append(f)
        detail_parts.append("Unmonitored files:\n  " + "\n  ".join(f_details))

    remediation_lines = [
        "Add the following rules to /etc/audit/rules.d/70-time.rules.\n"
        "Accurate system time is foundational to security operations. Attackers manipulate time to "
        "make their actions fall outside SIEM correlation windows, invalidate time-sensitive "
        "authentication (Kerberos tickets typically have a 5-minute tolerance), or confuse "
        "forensic timelines during incident response:"
    ]
    if syscall_missing:
        remediation_lines.append(
            "  -a always,exit -F arch=b64 -S {} -k time_change".format(",".join(time_syscalls)))
        remediation_lines.append(
            "  -a always,exit -F arch=b32 -S {} -k time_change".format(",".join(time_syscalls)))
        remediation_lines.append(
            "  # adjtimex adjusts clock drift, settimeofday/clock_settime set absolute time values")
    for f in file_missing:
        remediation_lines.append("  -w {} -p wa -k time_change".format(f))
    remediation_lines.append(
        "Trade-off: NTP (ntpd/chronyd) legitimately calls adjtimex to synchronize time. "
        "You should expect regular adjtimex events from your NTP service -- alert on "
        "settimeofday/clock_settime from non-NTP processes instead.\n"
        "Then reload: sudo augenrules --load"
    )

    return CheckResult(
        check_id="LINUX-RULES-007",
        title="Time change monitoring incomplete",
        severity=severity,
        detail=(
            "System time underpins every aspect of security logging and forensics. Every audit event, "
            "syslog entry, and SIEM correlation rule depends on accurate, consistent timestamps. "
            "Attackers change system time to make their activity fall outside detection windows, to "
            "invalidate Kerberos tickets (which require clocks to be within 5 minutes), or to confuse "
            "forensic timelines during incident response (MITRE ATT&CK T1070.006 - Timestomp).\n"
            "{}"
        ).format("\n".join(detail_parts)),
        remediation="\n".join(remediation_lines),
        category="rules",
        platform="linux",
        evidence=evidence,
        mitre_techniques=["T1070.006"],
    )


def _check_user_group_monitoring(lines):
    """LINUX-RULES-008: User/group management syscalls."""
    evidence = {}
    # Files that track user/group changes
    identity_files = ["/etc/passwd", "/etc/shadow", "/etc/group", "/etc/gshadow",
                      "/etc/security/opasswd"]
    # Relevant syscalls for direct user/group manipulation
    identity_syscalls = ["setuid", "setgid", "setreuid", "setregid",
                         "setresuid", "setresgid"]

    file_found = []
    file_missing = []
    for f in identity_files:
        if _rules_contain(lines, re.escape(f)):
            file_found.append(f)
        else:
            file_missing.append(f)

    syscall_found = []
    syscall_missing = []
    for sc in identity_syscalls:
        if _rules_contain(lines, r'-S\s+' + sc):
            syscall_found.append(sc)
        else:
            syscall_missing.append(sc)

    evidence["file_found"] = file_found
    evidence["file_missing"] = file_missing
    evidence["syscall_found"] = syscall_found
    evidence["syscall_missing"] = syscall_missing

    # Focus on file watches as primary indicator
    if not file_missing:
        return CheckResult(
            check_id="LINUX-RULES-008",
            title="User/group management monitoring adequate",
            severity="PASS",
            detail=(
                "Identity files are the database that defines who exists on the system, what their "
                "credentials are, and which groups they belong to. All critical identity files are "
                "being monitored: /etc/passwd (user accounts), /etc/shadow (password hashes), "
                "/etc/group (group memberships), /etc/gshadow (group passwords), and "
                "/etc/security/opasswd (password history). Syscall coverage for privilege-switching "
                "calls (setuid, setgid, and variants): {}/{}. This detects account creation, "
                "password changes, group membership modifications, and privilege escalation attempts."
            ).format(len(syscall_found), len(identity_syscalls)),
            remediation="No action required.",
            category="rules",
            platform="linux",
            evidence=evidence,
            mitre_techniques=["T1098", "T1136"],
        )

    severity = "FAIL" if len(file_missing) > 2 else "WARN"

    file_explanations = {
        "/etc/passwd": "/etc/passwd -- the user account database; each line defines a username, UID, "
                       "home directory, and login shell. Unauthorized additions mean backdoor accounts.",
        "/etc/shadow": "/etc/shadow -- contains password hashes (only readable by root); reading enables "
                       "offline cracking, writing allows setting known passwords for any account.",
        "/etc/group": "/etc/group -- defines group memberships; adding a user to groups like 'sudo', "
                      "'docker', or 'adm' silently escalates their privileges.",
        "/etc/gshadow": "/etc/gshadow -- group password and administrator information; rarely used "
                        "but modification can grant group-level administrative access.",
        "/etc/security/opasswd": "/etc/security/opasswd -- stores previous password hashes for password "
                                 "history enforcement (pam_pwhistory); reading reveals historical passwords "
                                 "that users may reuse on other systems.",
    }

    missing_details = []
    for m in file_missing:
        if m in file_explanations:
            missing_details.append(file_explanations[m])
        else:
            missing_details.append(m)

    remediation_lines = [
        "Add the following file watches to /etc/audit/rules.d/80-identity.rules.\n"
        "These files collectively define every user account, password, and group membership "
        "on the system. Monitoring them detects account creation (T1136), credential "
        "manipulation (T1098), and privilege escalation via group membership changes:"
    ]
    for f in file_missing:
        remediation_lines.append("  -w {} -p wa -k identity".format(f))
    remediation_lines.append(
        "The '-k identity' key groups all user/group management events together, "
        "so you can search all identity changes with 'ausearch -k identity'.\n"
        "Then reload: sudo augenrules --load"
    )

    return CheckResult(
        check_id="LINUX-RULES-008",
        title="User/group management monitoring incomplete",
        severity=severity,
        detail=(
            "Identity files are the core database defining every user account, password hash, and "
            "group membership on the system. Any unauthorized modification to these files typically "
            "indicates active compromise: an attacker creating backdoor accounts (T1136), changing "
            "passwords for persistence (T1098), or adding themselves to privileged groups for "
            "escalation. The following identity files are not being monitored:\n  {}"
        ).format("\n  ".join(missing_details)),
        remediation="\n".join(remediation_lines),
        category="rules",
        platform="linux",
        evidence=evidence,
        mitre_techniques=["T1098", "T1136"],
    )


def _check_rule_key_coverage(lines):
    """LINUX-RULES-009: Rule key coverage (check for -k tags)."""
    evidence = {}

    # Only count actionable rules (-a and -w), not control lines (-b, -e, -D, etc.)
    actionable_rules = [l for l in lines if l.startswith("-a ") or l.startswith("-w ")]
    rules_with_key = [l for l in actionable_rules if re.search(r'\s-k\s+\S+', l)]
    rules_without_key = [l for l in actionable_rules if not re.search(r'\s-k\s+\S+', l)]

    evidence["total_actionable_rules"] = len(actionable_rules)
    evidence["rules_with_key"] = len(rules_with_key)
    evidence["rules_without_key_samples"] = rules_without_key[:5]

    if not actionable_rules:
        return CheckResult(
            check_id="LINUX-RULES-009",
            title="No audit rules found for key analysis",
            severity="FAIL",
            detail=(
                "Audit rule keys (-k tags) are labels you attach to rules so you can quickly search "
                "and filter audit events by category. No actionable audit rules (-a or -w) were found "
                "at all, which means the system has no active audit monitoring. Without any audit rules, "
                "there is no visibility into process execution, file access, privilege escalation, or "
                "any other security-relevant activity."
            ),
            remediation=(
                "Configure audit rules first. See the other LINUX-RULES checks for specific "
                "recommendations on what to monitor (process execution, privileged commands, "
                "critical files, cron, kernel modules, network configuration, and time changes)."
            ),
            category="rules",
            platform="linux",
            evidence=evidence,
            mitre_techniques=["T1562.001"],
        )

    pct = (len(rules_with_key) / len(actionable_rules)) * 100

    if pct == 100:
        return CheckResult(
            check_id="LINUX-RULES-009",
            title="All rules have key tags",
            severity="PASS",
            detail=(
                "Audit rule keys (the -k flag) are labels that categorize audit events, functioning "
                "like tags in a logging system. All {} actionable rules have -k tags assigned. "
                "This means you can efficiently search audit logs by category -- for example, "
                "'ausearch -k exec' finds all process execution events, 'ausearch -k identity' finds "
                "all user/group changes, and 'ausearch -k modules' finds all kernel module operations. "
                "Without keys, you would need to search by raw syscall numbers or file paths, which is "
                "error-prone and slow during incident response."
            ).format(len(actionable_rules)),
            remediation="No action required.",
            category="rules",
            platform="linux",
            evidence=evidence,
            mitre_techniques=[],
        )

    severity = "WARN" if pct >= 50 else "FAIL"
    return CheckResult(
        check_id="LINUX-RULES-009",
        title="Some rules missing key tags",
        severity=severity,
        detail=(
            "Audit rule keys (-k tags) are labels that categorize audit events for efficient searching "
            "and filtering -- they work like tags in a logging system. When you search audit logs with "
            "'ausearch -k exec', the key lets you instantly find all process execution events instead of "
            "sifting through raw syscall numbers. Currently, {:.0f}% of rules have -k tags ({}/{} "
            "actionable rules). Rules without keys generate events that are difficult to categorize "
            "during incident response, especially under time pressure when you need to quickly answer "
            "questions like 'show me all file permission changes in the last hour.'"
        ).format(pct, len(rules_with_key), len(actionable_rules)),
        remediation=(
            "Add -k <descriptive_key> to each rule that is missing a key tag. Use consistent, "
            "meaningful names that describe the category of activity being monitored. Good key names "
            "include: exec (process execution), identity (user/group changes), privileged (setuid "
            "binaries), modules (kernel module operations), network_changes, time_change, cron.\n"
            "Examples of rules currently without keys:\n  "
            + "\n  ".join(rules_without_key[:3])
        ),
        category="rules",
        platform="linux",
        evidence=evidence,
        mitre_techniques=[],
    )


def _check_arch_coverage(lines):
    """LINUX-RULES-010: Architecture coverage consistency."""
    evidence = {}

    b64_rules = _find_matching_rules(lines, r'arch=b64')
    b32_rules = _find_matching_rules(lines, r'arch=b32')

    evidence["b64_count"] = len(b64_rules)
    evidence["b32_count"] = len(b32_rules)

    if not b64_rules and not b32_rules:
        # No architecture-specific rules at all
        return CheckResult(
            check_id="LINUX-RULES-010",
            title="No architecture-specific syscall rules",
            severity="INFO",
            detail=(
                "Architecture-specific rules use '-F arch=b64' or '-F arch=b32' to target the "
                "64-bit or 32-bit syscall tables respectively. No such rules were found. "
                "This is expected if only file watches (-w rules) are being used, since file watches "
                "do not need architecture qualifiers -- they monitor filesystem operations regardless "
                "of whether the process is 32-bit or 64-bit. However, if you intend to monitor "
                "syscalls like execve, init_module, or sethostname, you will need architecture-specific "
                "rules for both b64 and b32."
            ),
            remediation=(
                "If syscall monitoring is intended, add rules with both -F arch=b64 and -F arch=b32. "
                "Linux maintains completely separate syscall tables for each architecture, and the "
                "syscall numbers are different between them (e.g., execve is syscall 59 on x86_64 "
                "but syscall 11 on i386). Each architecture needs its own rule."
            ),
            category="rules",
            platform="linux",
            evidence=evidence,
            mitre_techniques=[],
        )

    if b64_rules and not b32_rules:
        return CheckResult(
            check_id="LINUX-RULES-010",
            title="Missing b32 architecture rules",
            severity="WARN",
            detail=(
                "Modern Linux runs in 64-bit mode but can still execute 32-bit (i386) binaries through "
                "a compatibility layer. Each architecture has a completely separate syscall table with "
                "different syscall numbers. Found {} b64 (64-bit) rules but no b32 (32-bit) rules. "
                "This is a significant gap because an attacker can trivially compile a 32-bit binary "
                "(gcc -m32 exploit.c -o exploit) that makes the same syscalls using the 32-bit table, "
                "completely bypassing all of your 64-bit-only monitoring. This is a well-known evasion "
                "technique -- for example, a 32-bit execve call to run commands would be invisible "
                "to your audit rules."
            ).format(len(b64_rules)),
            remediation=(
                "For each b64 syscall rule, create a matching b32 rule. The rule syntax is identical "
                "except for changing arch=b64 to arch=b32. Example:\n"
                "  -a always,exit -F arch=b32 -S execve -F auid>=1000 -F auid!=unset -k exec\n"
                "You can typically duplicate your entire b64 rule set and change the arch field. "
                "The b32 rules will have minimal performance impact on systems that do not run "
                "32-bit binaries, because the rules only trigger when a 32-bit syscall actually occurs.\n"
                "Then reload: sudo augenrules --load"
            ),
            category="rules",
            platform="linux",
            evidence=evidence,
            mitre_techniques=["T1059"],
        )

    if b32_rules and not b64_rules:
        return CheckResult(
            check_id="LINUX-RULES-010",
            title="Missing b64 architecture rules",
            severity="WARN",
            detail=(
                "Linux uses separate syscall tables for 64-bit (b64) and 32-bit (b32) execution modes. "
                "Found {} b32 rules but no b64 rules. On a 64-bit system, virtually all normal process "
                "execution uses the b64 syscall table, so missing b64 rules means the vast majority of "
                "system activity -- including all standard command execution, file operations, and network "
                "calls -- is completely unmonitored. This is the more critical gap compared to missing "
                "b32 rules."
            ).format(len(b32_rules)),
            remediation=(
                "For each b32 syscall rule, add a matching b64 rule. On a 64-bit system, b64 rules "
                "are the primary monitoring layer since nearly all processes use the 64-bit syscall table.\n"
                "Then reload: sudo augenrules --load"
            ),
            category="rules",
            platform="linux",
            evidence=evidence,
            mitre_techniques=["T1059"],
        )

    # Both present -- check balance
    ratio = min(len(b64_rules), len(b32_rules)) / max(len(b64_rules), len(b32_rules))
    evidence["ratio"] = round(ratio, 2)

    if ratio < 0.5:
        return CheckResult(
            check_id="LINUX-RULES-010",
            title="Architecture rule coverage imbalanced",
            severity="WARN",
            detail=(
                "Linux maintains separate syscall tables for 64-bit (b64) and 32-bit (b32) architectures, "
                "and each needs its own audit rules. Currently there are {} b64 rules and {} b32 rules "
                "(ratio: {:.0f}%). Ideally, every syscall rule should have both a b64 and b32 variant, "
                "resulting in a 1:1 ratio. A significant imbalance suggests some syscalls are only being "
                "monitored for one architecture, leaving the other open to evasion. An attacker who "
                "identifies the gap can use the unmonitored architecture to bypass logging."
            ).format(len(b64_rules), len(b32_rules), ratio * 100),
            remediation=(
                "Ensure each syscall rule has both an arch=b64 and arch=b32 version. Review your "
                "rules with: auditctl -l | grep arch= | sort\n"
                "Look for syscalls that appear in only one architecture and add the missing counterpart. "
                "The performance overhead of matching b32/b64 rules is negligible.\n"
                "Then reload: sudo augenrules --load"
            ),
            category="rules",
            platform="linux",
            evidence=evidence,
            mitre_techniques=["T1059"],
        )

    return CheckResult(
        check_id="LINUX-RULES-010",
        title="Architecture coverage consistent",
        severity="PASS",
        detail=(
            "Linux uses separate syscall tables for 64-bit (b64) and 32-bit (b32) execution, and audit "
            "rules must target each table independently. The current configuration has {} b64 rules and "
            "{} b32 rules, which indicates balanced coverage across both architectures. This prevents "
            "attackers from evading monitoring by compiling and running 32-bit binaries on the 64-bit system."
        ).format(len(b64_rules), len(b32_rules)),
        remediation="No action required.",
        category="rules",
        platform="linux",
        evidence=evidence,
        mitre_techniques=["T1059"],
    )


def _check_ld_preload_watches(lines):
    """LINUX-RULES-011: LD_PRELOAD file watches."""
    evidence = {}

    watched_paths = {
        "/etc/ld.so.preload": False,
        "/etc/ld.so.conf": False,
        "/etc/ld.so.conf.d/": False,
    }

    for path in watched_paths:
        escaped = re.escape(path.rstrip("/"))
        if _rules_contain(lines, r'-w\s+' + escaped):
            watched_paths[path] = True

    evidence["watched"] = [p for p, v in watched_paths.items() if v]
    evidence["missing"] = [p for p, v in watched_paths.items() if not v]

    if all(watched_paths.values()):
        return CheckResult(
            check_id="LINUX-RULES-011",
            title="LD_PRELOAD and library config watches in place",
            severity="PASS",
            detail=(
                "The dynamic linker configuration files control how shared libraries are loaded into "
                "every process on the system. All critical library configuration paths are being "
                "monitored: /etc/ld.so.preload (forces a shared library to load before all others in "
                "every process), /etc/ld.so.conf (defines library search paths), and /etc/ld.so.conf.d/ "
                "(drop-in directory for additional library search paths). This provides visibility into "
                "attacks that hijack the dynamic linker to inject malicious code system-wide."
            ),
            remediation="No action required.",
            category="rules",
            platform="linux",
            evidence=evidence,
            mitre_techniques=["T1574.006"],
        )

    # /etc/ld.so.preload is the highest priority -- FAIL if missing
    if not watched_paths["/etc/ld.so.preload"]:
        severity = "FAIL"
    else:
        severity = "WARN"

    path_explanations = {
        "/etc/ld.so.preload": (
            "/etc/ld.so.preload -- forces the dynamic linker (ld.so) to load a specified shared library "
            "before ALL others in EVERY process on the system. An attacker who writes to this file can "
            "intercept any library function (such as PAM authentication functions to steal credentials, "
            "or libc functions to hide processes and files) system-wide with a single file modification. "
            "This is the highest-priority path because it provides complete, silent code injection into "
            "every running and future process"
        ),
        "/etc/ld.so.conf": (
            "/etc/ld.so.conf -- defines the library search path for the dynamic linker. Modifying this "
            "file can cause the system to load attacker-controlled shared libraries from a malicious "
            "directory instead of the legitimate system libraries"
        ),
        "/etc/ld.so.conf.d/": (
            "/etc/ld.so.conf.d/ -- drop-in directory for additional library search path definitions. "
            "An attacker can drop a new configuration file here to prepend a malicious library path, "
            "which is less conspicuous than editing ld.so.conf directly"
        ),
    }

    missing = evidence["missing"]
    missing_details = []
    for m in missing:
        if m in path_explanations:
            missing_details.append(path_explanations[m])
        else:
            missing_details.append(m)

    remediation_lines = [
        "Add the following watches to /etc/audit/rules.d/30-lib-config.rules.\n"
        "These files control the dynamic linker, which is responsible for loading shared libraries "
        "into every process. Hijacking the linker is one of the most powerful persistence and "
        "code injection techniques available because it affects every process system-wide:"
    ]
    for path in missing:
        remediation_lines.append("  -w {} -p wa -k lib_config".format(path))
    remediation_lines.append(
        "The '-p wa' permission filter logs writes and attribute changes. "
        "On a properly configured production server, these files should rarely change -- "
        "any modification outside of package management is highly suspicious.\n"
        "Then reload: sudo augenrules --load"
    )

    return CheckResult(
        check_id="LINUX-RULES-011",
        title="LD_PRELOAD and library config watches incomplete",
        severity=severity,
        detail=(
            "The dynamic linker configuration files control how shared libraries are loaded into "
            "every process on the system. ld.so.preload forces the dynamic linker to load a specified "
            "shared library before all others -- an attacker who writes to this file can intercept any "
            "library function (like PAM authentication) system-wide. ld.so.conf and ld.so.conf.d/ "
            "control the library search path -- modifying these can cause the system to load "
            "attacker-controlled libraries instead of legitimate ones.\n"
            "Unmonitored paths:\n  {}"
        ).format("\n  ".join(missing_details)),
        remediation="\n".join(remediation_lines),
        category="rules",
        platform="linux",
        evidence=evidence,
        mitre_techniques=["T1574.006"],
    )


def _check_ptrace_monitoring(lines):
    """LINUX-RULES-012: ptrace syscall monitoring."""
    evidence = {}

    ptrace_rules = _find_matching_rules(lines, r'-S\s+ptrace')
    evidence["ptrace_rules"] = ptrace_rules

    if ptrace_rules:
        # Check for the more targeted a0=0x4 rule
        targeted_rules = _find_matching_rules(lines, r'-S\s+ptrace.*a0=0x4')
        evidence["targeted_rules"] = targeted_rules
        broad_rules = [r for r in ptrace_rules if r not in targeted_rules]
        evidence["broad_rules"] = broad_rules

        detail_parts = [
            "The ptrace syscall allows one process to observe and control another -- it is the "
            "mechanism behind debuggers like gdb and strace. Monitoring is configured with {} rule(s).".format(
                len(ptrace_rules))
        ]
        if targeted_rules:
            detail_parts.append(
                "Targeted PTRACE_POKETEXT (a0=0x4) rules are present, which specifically catch the "
                "most dangerous operation: writing to another process's memory."
            )
        if broad_rules:
            detail_parts.append(
                "Broad ptrace monitoring rules are present, capturing all ptrace activity including "
                "process attachment, memory reads, and register manipulation."
            )

        return CheckResult(
            check_id="LINUX-RULES-012",
            title="Ptrace syscall monitoring present",
            severity="PASS",
            detail=" ".join(detail_parts),
            remediation="No action required.",
            category="rules",
            platform="linux",
            evidence=evidence,
            mitre_techniques=["T1055.008"],
        )

    return CheckResult(
        check_id="LINUX-RULES-012",
        title="Ptrace syscall monitoring not configured",
        severity="WARN",
        detail=(
            "ptrace is the system call that allows one process to observe and control another -- it is "
            "the mechanism behind debuggers like gdb and strace. Attackers use ptrace to inject code "
            "into running processes (e.g., injecting into an SSH agent to steal keys, or into a web "
            "server to intercept credentials in memory). Process injection via ptrace is a well-known "
            "post-exploitation technique (MITRE T1055.008 - Ptrace System Calls) that leaves zero log "
            "entries without this audit rule. No ptrace monitoring rules were found."
        ),
        remediation=(
            "Add the following rules to /etc/audit/rules.d/50-ptrace.rules:\n"
            "  -a always,exit -F arch=b64 -S ptrace -F a0=0x4 -k process_injection\n"
            "  -a always,exit -F arch=b64 -S ptrace -k ptrace_activity\n"
            "What these rules do:\n"
            "  - The first rule filters on a0=0x4 (PTRACE_POKETEXT), which catches the most dangerous "
            "operation -- writing to another process's memory. This is how code injection works: the "
            "attacker writes shellcode or modified instructions directly into a target process.\n"
            "  - The second rule catches all ptrace activity (attach, peek, poke, getregs, etc.) for "
            "broader visibility into debugging and process manipulation.\n"
            "Trade-off: the targeted a0=0x4 rule catches the most dangerous operation (writing to "
            "another process's memory) while reducing noise from legitimate debugger usage. The broader "
            "rule catches all ptrace activity but is noisier -- on development systems, you may want "
            "only the targeted rule to avoid flooding logs with legitimate debugging.\n"
            "Then reload: sudo augenrules --load"
        ),
        category="rules",
        platform="linux",
        evidence=evidence,
        mitre_techniques=["T1055.008"],
    )


def _check_mount_monitoring(lines):
    """LINUX-RULES-013: mount/umount syscall monitoring."""
    evidence = {}

    mount_rules = _find_matching_rules(lines, r'-S\s+mount')
    umount_rules = _find_matching_rules(lines, r'-S\s+umount2')

    evidence["mount_rules"] = mount_rules
    evidence["umount_rules"] = umount_rules

    missing = []
    if not mount_rules:
        missing.append("mount")
    if not umount_rules:
        missing.append("umount2")

    if not missing:
        return CheckResult(
            check_id="LINUX-RULES-013",
            title="Mount/umount syscall monitoring present",
            severity="PASS",
            detail=(
                "The mount and umount2 syscalls control filesystem attachment and detachment. "
                "Both syscalls are being monitored ({} mount rule(s), {} umount2 rule(s)). "
                "This provides visibility into USB device mounts, remote filesystem attachment "
                "(NFS/CIFS shares), overlay filesystem creation, and potential container escape "
                "techniques that manipulate mount namespaces."
            ).format(len(mount_rules), len(umount_rules)),
            remediation="No action required.",
            category="rules",
            platform="linux",
            evidence=evidence,
            mitre_techniques=["T1052.001"],
        )

    syscall_explanations = {
        "mount": "mount -- attaches filesystems including USB devices, remote NFS/CIFS shares, and "
                 "overlay filesystems; also involved in some container escape techniques that manipulate "
                 "mount namespaces",
        "umount2": "umount2 -- detaches filesystems; an attacker may unmount security-relevant filesystems "
                   "or use mount/unmount sequences to manipulate overlay filesystems for file hiding",
    }

    missing_details = []
    for m in missing:
        if m in syscall_explanations:
            missing_details.append(syscall_explanations[m])
        else:
            missing_details.append(m)

    return CheckResult(
        check_id="LINUX-RULES-013",
        title="Mount/umount syscall monitoring incomplete",
        severity="WARN",
        detail=(
            "The mount and umount2 syscalls control filesystem attachment and detachment. Without "
            "monitoring, an attacker can mount USB devices, remote NFS/CIFS shares, or overlay "
            "filesystems to hide files -- all with no audit record. The mount syscall is also "
            "involved in some container escape techniques that manipulate mount namespaces to "
            "break out of containerized environments.\n"
            "Missing monitoring for:\n  {}"
        ).format("\n  ".join(missing_details)),
        remediation=(
            "Add the following rules to /etc/audit/rules.d/50-mount.rules:\n"
            "  -a always,exit -F arch=b64 -S mount,umount2 -F auid>=1000 -F auid!=unset -k mount_activity\n"
            "  -a always,exit -F arch=b32 -S mount,umount2 -F auid>=1000 -F auid!=unset -k mount_activity\n"
            "What these rules do:\n"
            "  - '-S mount,umount2' monitors both filesystem attach and detach operations\n"
            "  - '-F auid>=1000' limits to human users (reduces noise from system automounts)\n"
            "  - '-F auid!=unset' excludes processes with no login session context\n"
            "Trade-off: systems with autofs, systemd automounts, or removable media policies may "
            "generate legitimate mount events. The auid filter helps by excluding system-initiated "
            "mounts, but you may need to tune alerting for environments with frequent user mounts.\n"
            "Then reload: sudo augenrules --load"
        ),
        category="rules",
        platform="linux",
        evidence=evidence,
        mitre_techniques=["T1052.001"],
    )


def _check_permission_change_monitoring(lines):
    """LINUX-RULES-014: Permission change syscall monitoring (chmod/chown family)."""
    evidence = {}

    chmod_syscalls = ["chmod", "fchmod", "fchmodat"]
    chown_syscalls = ["chown", "fchown", "fchownat", "lchown"]
    all_syscalls = chmod_syscalls + chown_syscalls

    chmod_found = []
    chmod_missing = []
    for sc in chmod_syscalls:
        # Use word boundary to avoid matching fchmod when searching for chmod
        if _rules_contain(lines, r'-S\s+(?:[\w,]*,)?' + sc + r'(?:,|\s|$)'):
            chmod_found.append(sc)
        else:
            chmod_missing.append(sc)

    chown_found = []
    chown_missing = []
    for sc in chown_syscalls:
        if _rules_contain(lines, r'-S\s+(?:[\w,]*,)?' + sc + r'(?:,|\s|$)'):
            chown_found.append(sc)
        else:
            chown_missing.append(sc)

    evidence["chmod_found"] = chmod_found
    evidence["chmod_missing"] = chmod_missing
    evidence["chown_found"] = chown_found
    evidence["chown_missing"] = chown_missing

    all_found = chmod_found + chown_found
    all_missing = chmod_missing + chown_missing

    if not all_missing:
        return CheckResult(
            check_id="LINUX-RULES-014",
            title="Permission change syscall monitoring present",
            severity="PASS",
            detail=(
                "The chmod/fchmod/fchmodat and chown/fchown/fchownat/lchown syscall families control "
                "file permissions and ownership. All {} permission-related syscalls are being monitored. "
                "This detects an attacker making a binary SUID (chmod 4755), changing file ownership to "
                "gain access, or modifying permissions to hide files. Note that auditd file watches with "
                "'-p wa' capture attribute changes only on specifically watched files -- these syscall "
                "rules provide coverage for permission changes on ANY file on the system."
            ).format(len(all_syscalls)),
            remediation="No action required.",
            category="rules",
            platform="linux",
            evidence=evidence,
            mitre_techniques=["T1222.002"],
        )

    syscall_explanations = {
        "chmod": "chmod -- changes file permission bits; can make a binary SUID (run as owner) or world-writable",
        "fchmod": "fchmod -- changes permissions via file descriptor; functionally identical to chmod but "
                  "operates on an already-opened file, often used by programs internally",
        "fchmodat": "fchmodat -- changes permissions relative to a directory file descriptor; the modern "
                    "variant used by many standard utilities and libraries",
        "chown": "chown -- changes file owner and group; an attacker can take ownership of sensitive files "
                 "or assign files to root to create SUID binaries",
        "fchown": "fchown -- changes ownership via file descriptor; same as chown but for already-opened files",
        "fchownat": "fchownat -- changes ownership relative to a directory file descriptor; the modern "
                    "variant used by standard utilities",
        "lchown": "lchown -- changes ownership of a symbolic link itself (not its target); used in symlink "
                  "attacks where the attacker creates links to sensitive files",
    }

    missing_details = []
    for m in all_missing:
        if m in syscall_explanations:
            missing_details.append(syscall_explanations[m])
        else:
            missing_details.append(m)

    remediation_lines = [
        "Add the following rules to /etc/audit/rules.d/50-perm-change.rules.\n"
        "These syscalls control file permissions and ownership. Auditd file watches with '-p wa' "
        "capture writes and attribute changes on specific watched files, but they do NOT capture "
        "permission changes via syscall on files that aren't explicitly watched. These syscall rules "
        "close that gap by monitoring permission changes on ANY file on the system:"
    ]
    if chmod_missing:
        remediation_lines.append(
            "  -a always,exit -F arch=b64 -S {} -F auid>=1000 -F auid!=unset -k perm_change".format(
                ",".join(chmod_syscalls)))
        remediation_lines.append(
            "  -a always,exit -F arch=b32 -S {} -F auid>=1000 -F auid!=unset -k perm_change".format(
                ",".join(chmod_syscalls)))
    if chown_missing:
        remediation_lines.append(
            "  -a always,exit -F arch=b64 -S {} -F auid>=1000 -F auid!=unset -k perm_change".format(
                ",".join(chown_syscalls)))
        remediation_lines.append(
            "  -a always,exit -F arch=b32 -S {} -F auid>=1000 -F auid!=unset -k perm_change".format(
                ",".join(chown_syscalls)))
    remediation_lines.append(
        "Without these rules, an attacker running 'chmod 4755 /tmp/backdoor' to create a SUID root "
        "binary generates no audit event unless /tmp/backdoor is explicitly watched. The auid filter "
        "reduces noise by limiting to human-initiated changes.\n"
        "Then reload: sudo augenrules --load"
    )

    return CheckResult(
        check_id="LINUX-RULES-014",
        title="Permission change syscall monitoring incomplete",
        severity="WARN",
        detail=(
            "The chmod and chown syscall families control file permissions and ownership on the system. "
            "Auditd file watches with '-p wa' capture writes and attribute changes on specific watched "
            "files, but they do NOT capture permission changes via syscall on files that aren't explicitly "
            "watched. These syscalls let an attacker make any binary SUID (run as root), change file "
            "ownership to gain access, or modify permissions to hide files. Without monitoring, an "
            "'chmod 4755 /tmp/backdoor' creating a SUID root binary generates no audit event.\n"
            "Missing monitoring for:\n  {}"
        ).format("\n  ".join(missing_details)),
        remediation="\n".join(remediation_lines),
        category="rules",
        platform="linux",
        evidence=evidence,
        mitre_techniques=["T1222.002"],
    )


def _check_file_deletion_monitoring(lines):
    """LINUX-RULES-015: File deletion syscall monitoring (unlink/rename)."""
    evidence = {}

    deletion_syscalls = ["unlink", "unlinkat", "rename", "renameat"]
    found = []
    missing = []

    for sc in deletion_syscalls:
        if _rules_contain(lines, r'-S\s+(?:[\w,]*,)?' + sc + r'(?:,|\s|$)'):
            found.append(sc)
        else:
            missing.append(sc)

    evidence["found"] = found
    evidence["missing"] = missing

    if not missing:
        return CheckResult(
            check_id="LINUX-RULES-015",
            title="File deletion syscall monitoring present",
            severity="PASS",
            detail=(
                "The unlink, unlinkat, rename, and renameat syscalls are the kernel entry points for "
                "file deletion and renaming. All {} deletion-related syscalls are being monitored. "
                "This provides visibility into evidence destruction (deleting logs, removing dropped "
                "tools), anti-forensics (renaming files to avoid detection), and data manipulation "
                "attacks."
            ).format(len(deletion_syscalls)),
            remediation="No action required.",
            category="rules",
            platform="linux",
            evidence=evidence,
            mitre_techniques=["T1070.004"],
        )

    syscall_explanations = {
        "unlink": "unlink -- the classic file deletion syscall; this is what rm calls to remove files",
        "unlinkat": "unlinkat -- the modern directory-relative variant of unlink; used by many standard "
                    "utilities and libraries for file deletion",
        "rename": "rename -- moves or renames files; attackers use this to move evidence out of monitored "
                  "directories or rename malicious files to blend in with legitimate ones",
        "renameat": "renameat -- the modern directory-relative variant of rename; used internally by "
                    "standard utilities like mv",
    }

    missing_details = []
    for m in missing:
        if m in syscall_explanations:
            missing_details.append(syscall_explanations[m])
        else:
            missing_details.append(m)

    return CheckResult(
        check_id="LINUX-RULES-015",
        title="File deletion syscall monitoring incomplete",
        severity="WARN",
        detail=(
            "File deletion and renaming are primary evidence destruction techniques. An attacker who "
            "gains access will delete logs, remove dropped tools, and rename files to avoid detection. "
            "Without these audit rules, 'rm -rf /var/log/audit/*' or shred operations create no audit "
            "trail beyond the file watches on specific watched paths (which only cover a handful of "
            "critical files). The unlink/unlinkat syscalls handle deletion, while rename/renameat handle "
            "moving and renaming -- together they cover all file removal and relocation operations.\n"
            "Missing monitoring for:\n  {}"
        ).format("\n  ".join(missing_details)),
        remediation=(
            "Add the following rules to /etc/audit/rules.d/50-deletion.rules:\n"
            "  -a always,exit -F arch=b64 -S unlink,unlinkat,rename,renameat -F auid>=1000 -F auid!=unset -k file_deletion\n"
            "  -a always,exit -F arch=b32 -S unlink,unlinkat,rename,renameat -F auid>=1000 -F auid!=unset -k file_deletion\n"
            "What these rules do:\n"
            "  - '-S unlink,unlinkat' captures all file deletion operations (what rm uses)\n"
            "  - '-S rename,renameat' captures file moves and renames (what mv uses)\n"
            "  - '-F auid>=1000' limits to human-initiated actions, reducing noise from system services "
            "that perform routine file cleanup (log rotation, temp file management)\n"
            "Trade-off: on systems with high file churn (build servers, log processors), these rules "
            "can generate significant volume. The auid filter helps, but you may need to add exclusions "
            "for specific paths or processes in high-throughput environments.\n"
            "Then reload: sudo augenrules --load"
        ),
        category="rules",
        platform="linux",
        evidence=evidence,
        mitre_techniques=["T1070.004"],
    )


def _check_tmp_exec_monitoring(lines):
    """LINUX-RULES-016: Execution from temporary directories."""
    evidence = {}

    tmp_dirs = ["/tmp", "/dev/shm", "/var/tmp"]
    monitored = []
    missing = []

    for d in tmp_dirs:
        # Look for execve rules with -F dir=<path>
        escaped = re.escape(d)
        pattern = r'-S\s+execve.*-F\s+dir=' + escaped
        if _rules_contain(lines, pattern):
            monitored.append(d)
        else:
            # Also check reverse order (dir before -S)
            pattern_alt = r'-F\s+dir=' + escaped + r'.*-S\s+execve'
            if _rules_contain(lines, pattern_alt):
                monitored.append(d)
            else:
                missing.append(d)

    evidence["monitored"] = monitored
    evidence["missing"] = missing

    if not missing:
        return CheckResult(
            check_id="LINUX-RULES-016",
            title="Temp directory execution monitoring present",
            severity="PASS",
            detail=(
                "World-writable temporary directories (/tmp, /dev/shm, /var/tmp) are the most common "
                "locations where attackers drop and execute tools after initial access. Targeted execve "
                "monitoring is configured for all {} temporary directories. This enables trivial SIEM "
                "alerting on a pattern that is almost always suspicious on servers: binary execution "
                "from world-writable temporary paths."
            ).format(len(tmp_dirs)),
            remediation="No action required.",
            category="rules",
            platform="linux",
            evidence=evidence,
            mitre_techniques=["T1059"],
        )

    dir_explanations = {
        "/tmp": "/tmp -- the primary temporary directory; world-writable and automatically cleaned, "
                "making it the most common location for attackers to drop and execute tools, exploits, "
                "and reverse shells after initial access",
        "/dev/shm": "/dev/shm -- a RAM-backed tmpfs filesystem; favored by attackers because files here "
                    "never touch disk (making forensic recovery impossible) and it is world-writable "
                    "by default on virtually all Linux systems",
        "/var/tmp": "/var/tmp -- persistent temporary storage that survives reboots; attackers use this "
                    "when they need dropped tools to persist across system restarts, unlike /tmp which "
                    "may be cleared on boot",
    }

    missing_details = []
    for m in missing:
        if m in dir_explanations:
            missing_details.append(dir_explanations[m])
        else:
            missing_details.append(m)

    remediation_lines = [
        "Add the following rules to /etc/audit/rules.d/50-tmp-exec.rules.\n"
        "While general execve monitoring captures executions from these directories, targeted rules "
        "with a distinct -k key make it trivial to write SIEM alerts specifically for execution "
        "from temp directories -- a pattern that is almost always suspicious on servers:"
    ]
    for d in missing:
        remediation_lines.append(
            "  -a always,exit -F arch=b64 -S execve -F dir={} -k tmp_exec".format(d))
        remediation_lines.append(
            "  -a always,exit -F arch=b32 -S execve -F dir={} -k tmp_exec".format(d))
    remediation_lines.append(
        "These rules use '-F dir=<path>' to limit the execve monitoring to specific directories, "
        "and the '-k tmp_exec' key lets you search all temp-directory executions with "
        "'ausearch -k tmp_exec'. On production servers, legitimate execution from /tmp is rare -- "
        "most hits will be worth investigating.\n"
        "Then reload: sudo augenrules --load"
    )

    return CheckResult(
        check_id="LINUX-RULES-016",
        title="Temp directory execution monitoring not configured",
        severity="INFO",
        detail=(
            "World-writable temporary directories (/tmp, /dev/shm, /var/tmp) are the most common "
            "location where attackers drop and execute tools after initial access. While general "
            "execve monitoring captures these executions, a targeted rule with a distinct -k key "
            "(like 'tmp_exec') makes it trivial to write SIEM alerts specifically for execution from "
            "temp directories -- a pattern that is almost always suspicious on servers.\n"
            "Unmonitored directories:\n  {}"
        ).format("\n  ".join(missing_details)),
        remediation="\n".join(remediation_lines),
        category="rules",
        platform="linux",
        evidence=evidence,
        mitre_techniques=["T1059"],
    )


def run_checks():
    """Return all auditd rules checks."""
    lines, sources = _read_all_rules()
    return [
        _check_execve_monitoring(lines),
        _check_privileged_commands(lines),
        _check_critical_file_watches(lines),
        _check_cron_monitoring(lines),
        _check_module_monitoring(lines),
        _check_network_monitoring(lines),
        _check_time_monitoring(lines),
        _check_user_group_monitoring(lines),
        _check_rule_key_coverage(lines),
        _check_arch_coverage(lines),
        _check_ld_preload_watches(lines),
        _check_ptrace_monitoring(lines),
        _check_mount_monitoring(lines),
        _check_permission_change_monitoring(lines),
        _check_file_deletion_monitoring(lines),
        _check_tmp_exec_monitoring(lines),
    ]
