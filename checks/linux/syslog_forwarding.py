"""Syslog forwarding checks: rsyslog/syslog-ng service, remote targets, auth facility."""

import glob
import re

from core.result import CheckResult
from core.platform_utils import (
    safe_run, read_file_safe, file_exists, is_elevated,
    get_package_manager, parse_config_file, get_file_mtime,
    check_process_running, get_linux_distro,
)


def _read_rsyslog_configs():
    """Read all rsyslog configuration content."""
    configs = {}
    main_conf = "/etc/rsyslog.conf"
    content = read_file_safe(main_conf)
    if content:
        configs[main_conf] = content

    for f in sorted(glob.glob("/etc/rsyslog.d/*.conf")):
        content = read_file_safe(f)
        if content:
            configs[f] = content

    return configs


def _read_syslog_ng_configs():
    """Read syslog-ng configuration content."""
    configs = {}
    main_conf = "/etc/syslog-ng/syslog-ng.conf"
    content = read_file_safe(main_conf)
    if content:
        configs[main_conf] = content

    for f in sorted(glob.glob("/etc/syslog-ng/conf.d/*.conf")):
        content = read_file_safe(f)
        if content:
            configs[f] = content

    return configs


def _check_syslog_installed_running():
    """LINUX-SYSLOG-001: rsyslog/syslog-ng installed and running."""
    evidence = {}

    # Check rsyslog
    rsyslog_active = False
    rc, out, _ = safe_run(["systemctl", "is-active", "rsyslog"])
    evidence["rsyslog_systemctl"] = out.strip()
    if rc == 0 and out.strip() == "active":
        rsyslog_active = True

    # Check syslog-ng
    syslogng_active = False
    rc, out, _ = safe_run(["systemctl", "is-active", "syslog-ng"])
    evidence["syslog_ng_systemctl"] = out.strip()
    if rc == 0 and out.strip() == "active":
        syslogng_active = True

    # Check process fallback
    if not rsyslog_active:
        rsyslog_active = check_process_running("rsyslogd")
        evidence["rsyslogd_process"] = rsyslog_active
    if not syslogng_active:
        syslogng_active = check_process_running("syslog-ng")
        evidence["syslog_ng_process"] = syslogng_active

    if rsyslog_active or syslogng_active:
        daemon = "rsyslog" if rsyslog_active else "syslog-ng"
        return CheckResult(
            check_id="LINUX-SYSLOG-001",
            title="Syslog daemon running",
            severity="PASS",
            detail=(
                "A syslog daemon is the standard Linux system logging service that collects "
                "messages from the kernel, system services, and applications into centralized "
                "log files. {} is active and running on this host. This is the backbone of "
                "log collection -- without a running syslog daemon, most system events would "
                "not be written to disk or forwarded to a remote SIEM, leaving you blind to "
                "security-relevant activity."
            ).format(daemon),
            remediation="No action required.",
            category="forwarding",
            platform="linux",
            evidence=evidence,
            mitre_techniques=["T1562.001"],
        )

    pm = get_package_manager()
    install_cmds = {
        "apt-get": "sudo apt-get install -y rsyslog && sudo systemctl enable --now rsyslog",
        "dnf": "sudo dnf install -y rsyslog && sudo systemctl enable --now rsyslog",
        "yum": "sudo yum install -y rsyslog && sudo systemctl enable --now rsyslog",
        "zypper": "sudo zypper install -y rsyslog && sudo systemctl enable --now rsyslog",
        "pacman": "sudo pacman -S syslog-ng && sudo systemctl enable --now syslog-ng",
    }
    install_cmd = install_cmds.get(pm, "Install rsyslog or syslog-ng for your distribution.")

    return CheckResult(
        check_id="LINUX-SYSLOG-001",
        title="No syslog daemon running",
        severity="FAIL",
        detail=(
            "A syslog daemon is the standard Linux system logging service that collects "
            "messages from the kernel, system services, and applications into centralized "
            "log files. Neither rsyslog nor syslog-ng is running on this host. Without a "
            "syslog daemon, critical security events such as authentication failures, "
            "privilege escalation attempts, and service errors are not being written to "
            "persistent log files or forwarded to any remote collector. An attacker could "
            "operate on this system without generating any durable log trail."
        ),
        remediation=(
            "Install and enable a syslog daemon. The 'enable --now' flag both starts the "
            "service immediately and configures it to start automatically on boot:\n"
            "  {}\n"
            "After installation, verify it is running with: systemctl status rsyslog"
        ).format(install_cmd),
        category="forwarding",
        platform="linux",
        evidence=evidence,
        mitre_techniques=["T1562.001"],
    )


def _check_remote_forwarding():
    """LINUX-SYSLOG-002: Remote forwarding configured."""
    evidence = {}
    remote_targets = []

    # Check rsyslog configs
    rsyslog_configs = _read_rsyslog_configs()
    for path, content in rsyslog_configs.items():
        for line in content.splitlines():
            line = line.strip()
            if line.startswith("#") or not line:
                continue
            # @@ for TCP, @ for UDP, also check action() format
            if re.search(r'@@\S+', line):
                remote_targets.append({"file": path, "line": line, "protocol": "TCP"})
            elif re.search(r'(?<![@@])@\S+', line) and not line.startswith("$"):
                remote_targets.append({"file": path, "line": line, "protocol": "UDP"})
            # omfwd action format
            elif re.search(r'action\s*\(.*type="omfwd"', line, re.IGNORECASE):
                remote_targets.append({"file": path, "line": line, "protocol": "omfwd"})

    # Check syslog-ng configs for destination
    syslogng_configs = _read_syslog_ng_configs()
    for path, content in syslogng_configs.items():
        if re.search(r'destination\s+\w+\s*\{[^}]*(?:tcp|udp|network)\s*\(', content, re.DOTALL):
            remote_targets.append({"file": path, "line": "syslog-ng remote destination", "protocol": "syslog-ng"})

    evidence["remote_targets"] = remote_targets

    if remote_targets:
        protocols = set(t["protocol"] for t in remote_targets)
        return CheckResult(
            check_id="LINUX-SYSLOG-002",
            title="Remote syslog forwarding configured",
            severity="PASS",
            detail=(
                "Remote syslog forwarding sends a copy of log events to an off-host "
                "collector (such as a SIEM) so that logs survive even if this host is "
                "compromised. Found {} remote forwarding target(s) using protocol(s): {}. "
                "This means an attacker who gains root access on this machine cannot "
                "destroy the only copy of the logs -- the remote server retains an "
                "independent record of all forwarded events."
            ).format(len(remote_targets), ", ".join(protocols)),
            remediation="No action required.",
            category="forwarding",
            platform="linux",
            evidence=evidence,
            mitre_techniques=["T1070.002"],
        )

    return CheckResult(
        check_id="LINUX-SYSLOG-002",
        title="No remote syslog forwarding configured",
        severity="FAIL",
        detail=(
            "Remote syslog forwarding sends a copy of log events to an off-host collector "
            "so that logs survive even if this host is compromised. No remote syslog targets "
            "were found in any rsyslog or syslog-ng configuration file. This means all logs "
            "exist only on this machine's local disk. If an attacker gains root access, they "
            "can simply run 'rm -rf /var/log/*' and all evidence of their intrusion -- login "
            "records, command history, privilege escalation traces -- is permanently destroyed."
        ),
        remediation=(
            "Add remote forwarding to /etc/rsyslog.d/50-remote.conf. In rsyslog syntax, "
            "'@@' denotes TCP forwarding which provides delivery guarantees (the sender "
            "retries if the connection drops), while '@' denotes UDP which is best-effort "
            "and events can be silently lost if the network is congested or the receiver is "
            "down. TCP is strongly recommended for security logs:\n"
            "  *.* @@your-siem-server:514  # TCP forwarding (reliable, recommended)\n"
            "Or for UDP (lower overhead but events can be silently dropped):\n"
            "  *.* @your-siem-server:514   # UDP forwarding (best-effort only)\n"
            "Then restart: sudo systemctl restart rsyslog"
        ),
        category="forwarding",
        platform="linux",
        evidence=evidence,
        mitre_techniques=["T1070.002"],
    )


def _check_auth_forwarding():
    """LINUX-SYSLOG-003: auth/security facility forwarding."""
    evidence = {}
    auth_forwarding_found = False

    rsyslog_configs = _read_rsyslog_configs()
    for path, content in rsyslog_configs.items():
        for line in content.splitlines():
            line = line.strip()
            if line.startswith("#") or not line:
                continue
            # Check for auth/authpriv facility with remote target
            if re.search(r'(auth|authpriv)\.\*?\s+@@?', line):
                auth_forwarding_found = True
                evidence["auth_forward_line"] = line
                evidence["auth_forward_file"] = path
                break
            # Check for *.* which includes auth
            if re.search(r'\*\.\*\s+@@?', line):
                auth_forwarding_found = True
                evidence["wildcard_forward_line"] = line
                evidence["wildcard_forward_file"] = path
                break
        if auth_forwarding_found:
            break

    # Check syslog-ng
    if not auth_forwarding_found:
        syslogng_configs = _read_syslog_ng_configs()
        for path, content in syslogng_configs.items():
            if re.search(r'filter.*facility\s*\(\s*auth', content):
                auth_forwarding_found = True
                evidence["syslog_ng_auth_filter"] = path
                break

    evidence["auth_forwarding_found"] = auth_forwarding_found

    if auth_forwarding_found:
        return CheckResult(
            check_id="LINUX-SYSLOG-003",
            title="Auth facility forwarding configured",
            severity="PASS",
            detail=(
                "The auth and authpriv syslog facilities are Linux's categorization for "
                "authentication-related events -- this includes SSH login attempts (both "
                "successful and failed), sudo usage, PAM authentication activity, su session "
                "changes, and password modifications. These are the most critical logs for "
                "detecting unauthorized access. Authentication logs are confirmed to be "
                "forwarded to a remote target, ensuring that evidence of login-based attacks "
                "is preserved off-host."
            ),
            remediation="No action required.",
            category="forwarding",
            platform="linux",
            evidence=evidence,
            mitre_techniques=["T1070.002", "T1110"],
        )

    return CheckResult(
        check_id="LINUX-SYSLOG-003",
        title="Auth facility not explicitly forwarded",
        severity="WARN",
        detail=(
            "The auth and authpriv syslog facilities are Linux's categorization for "
            "authentication-related events -- this includes SSH login attempts (both "
            "successful and failed), sudo usage, PAM authentication activity, su session "
            "changes, and password modifications. No explicit remote forwarding rule was "
            "found for auth or authpriv facilities. If a wildcard '*.* @@server' rule is "
            "not configured either, then authentication events exist only locally. These "
            "are the single most important logs for detecting unauthorized access: without "
            "them forwarded off-host, an attacker who gains root can erase all evidence of "
            "how they got in, what accounts they compromised, and what privileges they escalated to."
        ),
        remediation=(
            "Add an explicit auth forwarding rule to /etc/rsyslog.d/50-remote.conf. The "
            "'auth,authpriv.*' selector captures all priority levels from both the auth "
            "facility (general authentication messages) and authpriv facility (private "
            "authentication messages that may contain sensitive details). Use '@@' for TCP "
            "to ensure reliable delivery:\n"
            "  auth,authpriv.* @@your-siem-server:514\n"
            "Then restart: sudo systemctl restart rsyslog"
        ),
        category="forwarding",
        platform="linux",
        evidence=evidence,
        mitre_techniques=["T1070.002", "T1110"],
    )


def _check_tls_encryption():
    """LINUX-SYSLOG-004: TLS encryption on forwarding."""
    evidence = {}
    remote_found = False
    tls_found = False
    udp_found = False

    # Check rsyslog configs
    rsyslog_configs = _read_rsyslog_configs()
    for path, content in rsyslog_configs.items():
        for line in content.splitlines():
            line_stripped = line.strip()
            if line_stripped.startswith("#") or not line_stripped:
                continue
            # Detect remote forwarding
            if re.search(r'@@\S+', line_stripped):
                remote_found = True
            elif re.search(r'(?<![@@])@\S+', line_stripped) and not line_stripped.startswith("$"):
                remote_found = True
                udp_found = True
                evidence["udp_forwarding"] = line_stripped
            elif re.search(r'action\s*\(.*type="omfwd"', line_stripped, re.IGNORECASE):
                remote_found = True

        # Check for TLS indicators in full config content
        if re.search(r'StreamDriver="(gtls|ossl)"', content, re.IGNORECASE):
            tls_found = True
            evidence["tls_indicator"] = "StreamDriver gtls/ossl found"
        if re.search(r'streamDriverMode="1"', content, re.IGNORECASE):
            tls_found = True
            evidence["tls_stream_mode"] = "streamDriverMode=1 found"
        if re.search(r'StreamDriverAuthMode', content, re.IGNORECASE):
            tls_found = True
            evidence["tls_auth_mode"] = "StreamDriverAuthMode found"
        if re.search(r'\$DefaultNetstreamDriver\s+(gtls|ossl)', content, re.IGNORECASE):
            tls_found = True
            evidence["tls_default_driver"] = "DefaultNetstreamDriver found"
        if re.search(r'\$ActionSendStreamDriverMode\s+1', content, re.IGNORECASE):
            tls_found = True
            evidence["tls_action_mode"] = "ActionSendStreamDriverMode 1 found"

    # Check syslog-ng configs
    syslogng_configs = _read_syslog_ng_configs()
    for path, content in syslogng_configs.items():
        if re.search(r'destination\s+\w+\s*\{[^}]*(?:tcp|udp|network)\s*\(', content, re.DOTALL):
            remote_found = True
        if re.search(r'transport\s*\(\s*"?tls"?\s*\)', content, re.IGNORECASE):
            tls_found = True
            evidence["syslog_ng_tls"] = "transport(tls) found"

    evidence["remote_forwarding_found"] = remote_found
    evidence["tls_found"] = tls_found
    evidence["udp_found"] = udp_found

    if not remote_found:
        return CheckResult(
            check_id="LINUX-SYSLOG-004",
            title="No remote forwarding to check for TLS",
            severity="INFO",
            detail=(
                "Syslog forwarding over plain TCP or UDP transmits log data — including "
                "usernames, IP addresses, commands executed, and authentication details — in "
                "cleartext across the network. Any attacker with network access (or a compromised "
                "switch/router) can passively capture this data. Beyond confidentiality, "
                "unencrypted syslog is vulnerable to injection attacks where an attacker sends "
                "crafted syslog messages to your SIEM, potentially creating false evidence or "
                "triggering alert fatigue.\n\n"
                "No remote forwarding configuration was detected, so TLS is not applicable."
            ),
            remediation="Configure remote forwarding first (see LINUX-SYSLOG-002).",
            category="forwarding",
            platform="linux",
            evidence=evidence,
            mitre_techniques=["T1040", "T1565.001"],
        )

    if udp_found:
        return CheckResult(
            check_id="LINUX-SYSLOG-004",
            title="Syslog forwarding uses UDP",
            severity="WARN",
            detail=(
                "Syslog forwarding over plain TCP or UDP transmits log data — including "
                "usernames, IP addresses, commands executed, and authentication details — in "
                "cleartext across the network. Any attacker with network access (or a compromised "
                "switch/router) can passively capture this data. Beyond confidentiality, "
                "unencrypted syslog is vulnerable to injection attacks where an attacker sends "
                "crafted syslog messages to your SIEM, potentially creating false evidence or "
                "triggering alert fatigue.\n\n"
                "UDP forwarding was detected, which provides no delivery guarantee AND no "
                "encryption. Events can be silently lost due to network congestion, and the "
                "data is transmitted in cleartext."
            ),
            remediation=(
                "Switch to TLS-encrypted TCP forwarding. For rsyslog, configure TLS in "
                "/etc/rsyslog.d/:\n"
                "  $DefaultNetstreamDriver gtls\n"
                "  $DefaultNetstreamDriverCAFile /etc/rsyslog-certs/ca.pem\n"
                "  $ActionSendStreamDriverMode 1\n"
                "  $ActionSendStreamDriverAuthMode x509/name\n"
                "  *.* @@your-siem-server:6514\n"
                "Then restart: sudo systemctl restart rsyslog"
            ),
            category="forwarding",
            platform="linux",
            evidence=evidence,
            mitre_techniques=["T1040", "T1565.001"],
        )

    if not tls_found:
        return CheckResult(
            check_id="LINUX-SYSLOG-004",
            title="Syslog forwarding without TLS encryption",
            severity="WARN",
            detail=(
                "Syslog forwarding over plain TCP or UDP transmits log data — including "
                "usernames, IP addresses, commands executed, and authentication details — in "
                "cleartext across the network. Any attacker with network access (or a compromised "
                "switch/router) can passively capture this data. Beyond confidentiality, "
                "unencrypted syslog is vulnerable to injection attacks where an attacker sends "
                "crafted syslog messages to your SIEM, potentially creating false evidence or "
                "triggering alert fatigue.\n\n"
                "Remote forwarding is configured but no TLS encryption indicators were found. "
                "Log data is being transmitted in cleartext."
            ),
            remediation=(
                "Configure TLS encryption for syslog forwarding. For rsyslog, configure TLS in "
                "/etc/rsyslog.d/:\n"
                "  $DefaultNetstreamDriver gtls\n"
                "  $DefaultNetstreamDriverCAFile /etc/rsyslog-certs/ca.pem\n"
                "  $ActionSendStreamDriverMode 1\n"
                "  $ActionSendStreamDriverAuthMode x509/name\n"
                "  *.* @@your-siem-server:6514\n"
                "Then restart: sudo systemctl restart rsyslog"
            ),
            category="forwarding",
            platform="linux",
            evidence=evidence,
            mitre_techniques=["T1040", "T1565.001"],
        )

    return CheckResult(
        check_id="LINUX-SYSLOG-004",
        title="Syslog forwarding uses TLS encryption",
        severity="PASS",
        detail=(
            "Syslog forwarding over plain TCP or UDP transmits log data — including "
            "usernames, IP addresses, commands executed, and authentication details — in "
            "cleartext across the network. Any attacker with network access (or a compromised "
            "switch/router) can passively capture this data. Beyond confidentiality, "
            "unencrypted syslog is vulnerable to injection attacks where an attacker sends "
            "crafted syslog messages to your SIEM, potentially creating false evidence or "
            "triggering alert fatigue.\n\n"
            "TLS encryption is configured for syslog forwarding, which protects log data "
            "in transit from eavesdropping and injection attacks."
        ),
        remediation="No action required.",
        category="forwarding",
        platform="linux",
        evidence=evidence,
        mitre_techniques=["T1040", "T1565.001"],
    )


def _check_queue_configuration():
    """LINUX-SYSLOG-005: Queue/buffer configuration."""
    evidence = {}
    remote_found = False
    queue_found = False

    rsyslog_configs = _read_rsyslog_configs()
    for path, content in rsyslog_configs.items():
        for line in content.splitlines():
            line_stripped = line.strip()
            if line_stripped.startswith("#") or not line_stripped:
                continue
            # Detect remote forwarding
            if re.search(r'@@\S+', line_stripped):
                remote_found = True
            elif re.search(r'(?<![@@])@\S+', line_stripped) and not line_stripped.startswith("$"):
                remote_found = True
            elif re.search(r'action\s*\(.*type="omfwd"', line_stripped, re.IGNORECASE):
                remote_found = True

        # Check for queue settings in legacy format
        if re.search(r'\$ActionQueueType', content):
            queue_found = True
            evidence["queue_type"] = "$ActionQueueType found"
        if re.search(r'\$ActionQueueFileName', content):
            queue_found = True
            evidence["queue_filename"] = "$ActionQueueFileName found"
        if re.search(r'\$ActionQueueSaveOnShutdown', content):
            evidence["queue_save_on_shutdown"] = "$ActionQueueSaveOnShutdown found"
        if re.search(r'\$ActionQueueSize', content):
            evidence["queue_size"] = "$ActionQueueSize found"
        if re.search(r'\$ActionResumeRetryCount', content):
            evidence["resume_retry"] = "$ActionResumeRetryCount found"

        # Check for queue settings in newer action() format
        if re.search(r'queue\.type\s*=', content, re.IGNORECASE):
            queue_found = True
            evidence["queue_type_new"] = "queue.type found in action() format"
        if re.search(r'queue\.filename\s*=', content, re.IGNORECASE):
            queue_found = True
            evidence["queue_filename_new"] = "queue.filename found in action() format"
        if re.search(r'queue\.saveonshutdown\s*=', content, re.IGNORECASE):
            evidence["queue_save_new"] = "queue.saveonshutdown found in action() format"

    # Check syslog-ng for remote destinations
    syslogng_configs = _read_syslog_ng_configs()
    for path, content in syslogng_configs.items():
        if re.search(r'destination\s+\w+\s*\{[^}]*(?:tcp|udp|network)\s*\(', content, re.DOTALL):
            remote_found = True

    evidence["remote_forwarding_found"] = remote_found
    evidence["queue_found"] = queue_found

    if not remote_found:
        return CheckResult(
            check_id="LINUX-SYSLOG-005",
            title="No remote forwarding to check for queue config",
            severity="INFO",
            detail=(
                "By default, rsyslog uses an in-memory queue for forwarding. If rsyslog cannot "
                "reach the remote SIEM (network outage, SIEM maintenance, firewall change), "
                "events accumulate in memory until the queue is full, then new events are dropped "
                "permanently. When rsyslog restarts, the in-memory queue is lost entirely. A "
                "disk-assisted queue (LinkedList with a filename) writes overflow events to disk "
                "and replays them when the connection is restored, providing guaranteed delivery "
                "across outages and restarts.\n\n"
                "No remote forwarding configuration was detected, so queue configuration is "
                "not applicable."
            ),
            remediation="Configure remote forwarding first (see LINUX-SYSLOG-002).",
            category="forwarding",
            platform="linux",
            evidence=evidence,
            mitre_techniques=["T1070.002"],
        )

    if not queue_found:
        return CheckResult(
            check_id="LINUX-SYSLOG-005",
            title="No disk-assisted queue for syslog forwarding",
            severity="WARN",
            detail=(
                "By default, rsyslog uses an in-memory queue for forwarding. If rsyslog cannot "
                "reach the remote SIEM (network outage, SIEM maintenance, firewall change), "
                "events accumulate in memory until the queue is full, then new events are dropped "
                "permanently. When rsyslog restarts, the in-memory queue is lost entirely. A "
                "disk-assisted queue (LinkedList with a filename) writes overflow events to disk "
                "and replays them when the connection is restored, providing guaranteed delivery "
                "across outages and restarts.\n\n"
                "Remote forwarding is configured but no disk-assisted queue settings were found. "
                "Events will be lost during SIEM outages or rsyslog restarts."
            ),
            remediation=(
                "Add queue configuration to your rsyslog forwarding config in /etc/rsyslog.d/:\n"
                "  $ActionQueueType LinkedList\n"
                "  $ActionQueueFileName srvrfwd\n"
                "  $ActionQueueSaveOnShutdown on\n"
                "  $ActionResumeRetryCount -1\n"
                "  $ActionQueueSize 100000\n"
                "Or in the newer action() format:\n"
                "  action(type=\"omfwd\" target=\"your-siem\" port=\"514\" protocol=\"tcp\"\n"
                "         queue.type=\"LinkedList\" queue.filename=\"srvrfwd\"\n"
                "         queue.saveonshutdown=\"on\" action.resumeRetryCount=\"-1\")\n"
                "Then restart: sudo systemctl restart rsyslog"
            ),
            category="forwarding",
            platform="linux",
            evidence=evidence,
            mitre_techniques=["T1070.002"],
        )

    return CheckResult(
        check_id="LINUX-SYSLOG-005",
        title="Disk-assisted queue configured for forwarding",
        severity="PASS",
        detail=(
            "By default, rsyslog uses an in-memory queue for forwarding. If rsyslog cannot "
            "reach the remote SIEM (network outage, SIEM maintenance, firewall change), "
            "events accumulate in memory until the queue is full, then new events are dropped "
            "permanently. When rsyslog restarts, the in-memory queue is lost entirely. A "
            "disk-assisted queue (LinkedList with a filename) writes overflow events to disk "
            "and replays them when the connection is restored, providing guaranteed delivery "
            "across outages and restarts.\n\n"
            "A disk-assisted queue configuration was found, which provides resilience against "
            "SIEM outages and rsyslog restarts."
        ),
        remediation="No action required.",
        category="forwarding",
        platform="linux",
        evidence=evidence,
        mitre_techniques=["T1070.002"],
    )


def _check_forwarding_health():
    """LINUX-SYSLOG-006: Forwarding health check."""
    evidence = {}

    # Check if rsyslog is running
    rc, out, _ = safe_run(["systemctl", "is-active", "rsyslog"])
    rsyslog_active = rc == 0 and out.strip() == "active"
    evidence["rsyslog_active"] = rsyslog_active

    if not rsyslog_active:
        return CheckResult(
            check_id="LINUX-SYSLOG-006",
            title="Rsyslog not running (health check skipped)",
            severity="INFO",
            detail=(
                "A configured-but-failing syslog forwarder creates a dangerous false sense of "
                "security. The forwarding configuration looks correct, the remote target is "
                "specified, but events are silently being dropped because the connection is down, "
                "the certificate expired, the remote port changed, or the SIEM is rejecting the "
                "data. This check looks at rsyslog's own operational logs for signs that "
                "forwarding is failing.\n\n"
                "Rsyslog is not running, so forwarding health cannot be assessed."
            ),
            remediation="Start rsyslog first: sudo systemctl start rsyslog",
            category="forwarding",
            platform="linux",
            evidence=evidence,
            mitre_techniques=["T1562.001"],
        )

    # Check journald for rsyslog errors in the last hour
    error_patterns = [
        r'connection refused',
        r'could not connect',
        r'action\s.*suspended',
        r'omfwd.*error',
        r'remote host.*not responding',
    ]
    error_lines = []

    rc, out, _ = safe_run(
        ["journalctl", "-u", "rsyslog", "--since", "1 hour ago", "--no-pager", "-q"],
        timeout=10,
    )
    if rc == 0 and out.strip():
        for line in out.splitlines():
            for pattern in error_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    error_lines.append(line.strip())
                    break

    # Also check /var/log/syslog and /var/log/messages for rsyslog errors
    for log_path in ["/var/log/syslog", "/var/log/messages"]:
        content = read_file_safe(log_path)
        if content:
            # Only check the last 200 lines to approximate recent activity
            recent_lines = content.splitlines()[-200:]
            for line in recent_lines:
                if "rsyslog" not in line.lower():
                    continue
                for pattern in error_patterns:
                    if re.search(pattern, line, re.IGNORECASE):
                        error_lines.append(line.strip())
                        break

    evidence["error_count"] = len(error_lines)
    evidence["sample_errors"] = error_lines[:5]

    if error_lines:
        return CheckResult(
            check_id="LINUX-SYSLOG-006",
            title="Syslog forwarding errors detected",
            severity="WARN",
            detail=(
                "A configured-but-failing syslog forwarder creates a dangerous false sense of "
                "security. The forwarding configuration looks correct, the remote target is "
                "specified, but events are silently being dropped because the connection is down, "
                "the certificate expired, the remote port changed, or the SIEM is rejecting the "
                "data. This check looks at rsyslog's own operational logs for signs that "
                "forwarding is failing.\n\n"
                "Found {} error(s) in rsyslog logs indicating forwarding problems. Events may "
                "be silently dropped or queued without reaching the remote target."
            ).format(len(error_lines)),
            remediation=(
                "Investigate rsyslog forwarding errors:\n"
                "  1. Check rsyslog status: sudo systemctl status rsyslog\n"
                "  2. View recent errors: journalctl -u rsyslog --since '1 hour ago'\n"
                "  3. Test connectivity to SIEM: nc -zv <siem-host> <port>\n"
                "  4. Check TLS certificates if applicable: openssl s_client -connect <host>:<port>\n"
                "  5. Restart rsyslog after fixing: sudo systemctl restart rsyslog"
            ),
            category="forwarding",
            platform="linux",
            evidence=evidence,
            mitre_techniques=["T1562.001"],
        )

    return CheckResult(
        check_id="LINUX-SYSLOG-006",
        title="No syslog forwarding errors detected",
        severity="PASS",
        detail=(
            "A configured-but-failing syslog forwarder creates a dangerous false sense of "
            "security. The forwarding configuration looks correct, the remote target is "
            "specified, but events are silently being dropped because the connection is down, "
            "the certificate expired, the remote port changed, or the SIEM is rejecting the "
            "data. This check looks at rsyslog's own operational logs for signs that "
            "forwarding is failing.\n\n"
            "No forwarding errors were found in recent rsyslog logs, indicating the "
            "forwarding pipeline is operating normally."
        ),
        remediation="No action required.",
        category="forwarding",
        platform="linux",
        evidence=evidence,
        mitre_techniques=["T1562.001"],
    )


def run_checks():
    """Return all syslog forwarding checks."""
    return [
        _check_syslog_installed_running(),
        _check_remote_forwarding(),
        _check_auth_forwarding(),
        _check_tls_encryption(),
        _check_queue_configuration(),
        _check_forwarding_health(),
    ]
