"""Authentication log checks: file existence, SSH logging, failed auth detection."""

import glob
import os
import re
import stat
import time

from core.result import CheckResult
from core.platform_utils import (
    safe_run, read_file_safe, file_exists, is_elevated,
    get_package_manager, parse_config_file, get_file_mtime,
    check_process_running, get_linux_distro,
)


_AUTH_LOG_PATHS = [
    "/var/log/auth.log",      # Debian/Ubuntu
    "/var/log/secure",        # RHEL/CentOS/Fedora
]

_SSHD_CONFIG_PATHS = [
    "/etc/ssh/sshd_config",
]


def _find_auth_log():
    """Find the active auth log path for this distro."""
    for path in _AUTH_LOG_PATHS:
        if file_exists(path):
            return path
    return None


def _check_auth_log_exists():
    """LINUX-AUTH-001: Auth log file exists and is being written to."""
    evidence = {}

    auth_log = _find_auth_log()
    evidence["checked_paths"] = _AUTH_LOG_PATHS
    evidence["found_path"] = auth_log

    if not auth_log:
        distro = get_linux_distro()
        return CheckResult(
            check_id="LINUX-AUTH-001",
            title="Auth log file not found",
            severity="FAIL",
            detail=(
                "The auth log (auth.log on Debian/Ubuntu, secure on RHEL/CentOS) is the "
                "central record of every authentication event on the system -- this includes "
                "every SSH login attempt (successful and failed), every sudo command execution, "
                "every PAM authentication decision, every su session change, and every password "
                "modification. Neither /var/log/auth.log nor /var/log/secure exists on this "
                "system. Without this file, there is no local record of who logged in, when, "
                "from where, or what privileged commands they ran."
            ),
            remediation=(
                "Ensure rsyslog or syslog-ng is installed and running, and that the auth "
                "facility is configured to write to a file. Add this line to your rsyslog "
                "configuration if missing (it tells rsyslog to write all auth and authpriv "
                "messages to the standard auth log location):\n"
                "  auth,authpriv.* /var/log/auth.log\n"
                "Then restart: sudo systemctl restart rsyslog"
            ),
            category="coverage",
            platform="linux",
            evidence=evidence,
            mitre_techniques=["T1070.002", "T1110"],
        )

    # Check if file has been written to recently
    mtime = get_file_mtime(auth_log)
    evidence["mtime"] = mtime
    now = time.time()

    if mtime is not None:
        age_hours = (now - mtime) / 3600
        evidence["age_hours"] = round(age_hours, 1)

        if age_hours > 24:
            return CheckResult(
                check_id="LINUX-AUTH-001",
                title="Auth log stale",
                severity="WARN",
                detail=(
                    "The auth log records every authentication event on the system -- SSH "
                    "logins, sudo commands, PAM decisions, su sessions, and password changes. "
                    "{} exists but was last modified {:.1f} hours ago. A stale auth log is a "
                    "strong indicator that something is broken in the logging pipeline: either "
                    "rsyslog has crashed, the auth facility is misconfigured, or the file "
                    "permissions prevent writing. This means authentication events that are "
                    "happening right now are likely not being recorded anywhere."
                ).format(auth_log, age_hours),
                remediation=(
                    "Diagnose why the auth log is not being updated:\n"
                    "  1. Check syslog service: sudo systemctl status rsyslog\n"
                    "  2. Test logging manually: logger -p auth.info 'test auth message'\n"
                    "  3. Verify config: grep auth /etc/rsyslog.conf /etc/rsyslog.d/*.conf\n"
                    "If rsyslog is running but the log is still stale, the auth facility "
                    "may be misconfigured or the log file may have incorrect permissions."
                ),
                category="coverage",
                platform="linux",
                evidence=evidence,
                mitre_techniques=["T1070.002", "T1110"],
            )

    return CheckResult(
        check_id="LINUX-AUTH-001",
        title="Auth log active",
        severity="PASS",
        detail=(
            "The auth log records every authentication event on the system -- SSH logins, "
            "sudo commands, PAM decisions, su sessions, and password changes. {} exists and "
            "has been recently updated, confirming that the logging pipeline is actively "
            "capturing authentication events. This is essential for detecting unauthorized "
            "access attempts and for forensic investigation of security incidents."
        ).format(auth_log),
        remediation="No action required.",
        category="coverage",
        platform="linux",
        evidence=evidence,
        mitre_techniques=["T1070.002", "T1110"],
    )


def _check_ssh_log_level():
    """LINUX-AUTH-002: SSH logging level."""
    evidence = {}

    sshd_config_path = None
    for path in _SSHD_CONFIG_PATHS:
        if file_exists(path):
            sshd_config_path = path
            break

    if not sshd_config_path:
        return CheckResult(
            check_id="LINUX-AUTH-002",
            title="sshd_config not found",
            severity="INFO",
            detail=(
                "SSH LogLevel controls how much detail the SSH daemon records about "
                "connections and authentication. No sshd_config file was found, which "
                "typically means SSH is not installed on this system."
            ),
            remediation="If SSH is needed, install and configure OpenSSH.",
            category="config",
            platform="linux",
            evidence=evidence,
            mitre_techniques=["T1021.004"],
        )

    content = read_file_safe(sshd_config_path)
    evidence["config_path"] = sshd_config_path

    if content is None:
        if not is_elevated():
            return CheckResult(
                check_id="LINUX-AUTH-002",
                title="Cannot read sshd_config (not elevated)",
                severity="SKIP",
                detail="Insufficient privileges to read sshd_config.",
                remediation="Re-run with sudo for full SSH logging analysis.",
                category="config",
                platform="linux",
                evidence=evidence,
                mitre_techniques=["T1021.004"],
            )
        return CheckResult(
            check_id="LINUX-AUTH-002",
            title="Cannot read sshd_config",
            severity="WARN",
            detail="Could not read {}.".format(sshd_config_path),
            remediation="Check file permissions on {}.".format(sshd_config_path),
            category="config",
            platform="linux",
            evidence=evidence,
            mitre_techniques=["T1021.004"],
        )

    # Also check sshd_config.d drop-ins
    all_content = content
    for dropin in sorted(glob.glob("/etc/ssh/sshd_config.d/*.conf")):
        dropin_content = read_file_safe(dropin)
        if dropin_content:
            all_content += "\n" + dropin_content

    # Parse LogLevel (last non-commented value wins)
    log_level = None
    for line in all_content.splitlines():
        stripped = line.strip()
        if stripped.startswith("#") or not stripped:
            continue
        match = re.match(r'^LogLevel\s+(\S+)', stripped, re.IGNORECASE)
        if match:
            log_level = match.group(1).upper()

    evidence["LogLevel"] = log_level or "not set (default: INFO)"

    good_levels = {"INFO", "VERBOSE"}
    quiet_levels = {"QUIET", "FATAL", "ERROR"}

    if log_level is None or log_level == "INFO":
        return CheckResult(
            check_id="LINUX-AUTH-002",
            title="SSH LogLevel is adequate",
            severity="PASS",
            detail=(
                "SSH LogLevel controls the verbosity of the SSH daemon's log output. The "
                "current level is {} which logs connection attempts, authentication "
                "successes and failures, and session open/close events. This provides the "
                "basic information needed to detect unauthorized SSH access. However, INFO "
                "does not log key fingerprints, so if a user has multiple authorized SSH "
                "keys, you cannot determine which specific key was used to authenticate."
            ).format(log_level or "INFO (default)"),
            remediation=(
                "For enhanced logging, consider upgrading to VERBOSE. VERBOSE adds SSH key "
                "fingerprints to each authentication log entry, which lets you identify "
                "exactly WHICH key was used when a user has multiple authorized keys. This "
                "is critical for key revocation -- if a key is compromised, you need to know "
                "which sessions used it:\n"
                "  LogLevel VERBOSE\nin {}".format(sshd_config_path)
            ),
            category="config",
            platform="linux",
            evidence=evidence,
            mitre_techniques=["T1021.004"],
        )

    if log_level == "VERBOSE":
        return CheckResult(
            check_id="LINUX-AUTH-002",
            title="SSH LogLevel is VERBOSE",
            severity="PASS",
            detail=(
                "SSH LogLevel controls the verbosity of the SSH daemon's log output. "
                "LogLevel=VERBOSE provides enhanced logging that includes SSH key fingerprints "
                "for each authentication event. This means you can identify exactly which SSH "
                "key was used for each login session -- critical when users have multiple "
                "authorized keys (e.g., one per workstation). If a key is compromised or "
                "needs revocation, VERBOSE logging lets you audit which sessions used that "
                "specific key."
            ),
            remediation="No action required.",
            category="config",
            platform="linux",
            evidence=evidence,
            mitre_techniques=["T1021.004"],
        )

    if log_level in quiet_levels:
        return CheckResult(
            check_id="LINUX-AUTH-002",
            title="SSH LogLevel too low",
            severity="FAIL",
            detail=(
                "SSH LogLevel controls the verbosity of the SSH daemon's log output. The "
                "current level is {}, which suppresses important authentication information. "
                "QUIET suppresses almost all logging entirely. FATAL only logs conditions "
                "that cause sshd to crash. ERROR logs error conditions but not normal "
                "authentication events. At any of these levels, SSH brute-force attacks, "
                "successful unauthorized logins, and session activity will not appear in "
                "logs at all, leaving you completely blind to SSH-based intrusions."
            ).format(log_level),
            remediation=(
                "Raise the log level to capture authentication events. VERBOSE is recommended "
                "as it logs everything INFO does plus SSH key fingerprints. Edit {} and set:\n"
                "  LogLevel VERBOSE\n"
                "Then restart: sudo systemctl restart sshd\n"
                "Note: this change takes effect for new connections only; existing sessions "
                "are not affected."
            ).format(sshd_config_path),
            category="config",
            platform="linux",
            evidence=evidence,
            mitre_techniques=["T1021.004"],
        )

    # DEBUG levels are fine but noisy
    if log_level.startswith("DEBUG"):
        return CheckResult(
            check_id="LINUX-AUTH-002",
            title="SSH LogLevel is DEBUG",
            severity="WARN",
            detail=(
                "SSH LogLevel controls the verbosity of the SSH daemon's log output. "
                "LogLevel={} generates extremely verbose output including protocol-level "
                "details, key exchange negotiations, and internal state transitions. While "
                "this captures everything VERBOSE does and more, the massive volume of "
                "output can overwhelm log storage and make it harder to find relevant "
                "security events. DEBUG levels are intended for temporary troubleshooting, "
                "not production use."
            ).format(log_level),
            remediation=(
                "Reduce to VERBOSE for production use. VERBOSE provides all the security-"
                "relevant detail (including key fingerprints) without the protocol-level "
                "noise of DEBUG:\n"
                "  LogLevel VERBOSE\n"
                "in {}"
            ).format(sshd_config_path),
            category="config",
            platform="linux",
            evidence=evidence,
            mitre_techniques=["T1021.004"],
        )

    return CheckResult(
        check_id="LINUX-AUTH-002",
        title="SSH LogLevel setting",
        severity="INFO",
        detail=(
            "SSH LogLevel controls the verbosity of the SSH daemon's log output. "
            "The current level is {}, which is not a standard recognized level. "
            "The recommended level is VERBOSE, which logs authentication events "
            "including SSH key fingerprints."
        ).format(log_level),
        remediation="Recommended: LogLevel VERBOSE",
        category="config",
        platform="linux",
        evidence=evidence,
        mitre_techniques=["T1021.004"],
    )


def _check_failed_auth_presence():
    """LINUX-AUTH-003: Failed auth log presence."""
    evidence = {}

    if not is_elevated():
        auth_log = _find_auth_log()
        if auth_log:
            # Try to read anyway -- some systems allow group read
            content = read_file_safe(auth_log)
            if content is None:
                return CheckResult(
                    check_id="LINUX-AUTH-003",
                    title="Cannot read auth log (not elevated)",
                    severity="SKIP",
                    detail="Insufficient privileges to read auth log.",
                    remediation="Re-run with sudo to analyze failed authentication entries.",
                    category="coverage",
                    platform="linux",
                    evidence=evidence,
                    mitre_techniques=["T1110"],
                )
        else:
            return CheckResult(
                check_id="LINUX-AUTH-003",
                title="Auth log not found",
                severity="SKIP",
                detail="No auth log found to scan for failed entries.",
                remediation="Ensure auth logging is configured.",
                category="coverage",
                platform="linux",
                evidence=evidence,
                mitre_techniques=["T1110"],
            )

    auth_log = _find_auth_log()
    if not auth_log:
        return CheckResult(
            check_id="LINUX-AUTH-003",
            title="Auth log not found for failed auth scan",
            severity="FAIL",
            detail=(
                "The failed authentication count is a key health indicator for both security "
                "and logging. No auth log file was found on this system, so failed "
                "authentication analysis cannot be performed."
            ),
            remediation="Configure syslog auth facility logging.",
            category="coverage",
            platform="linux",
            evidence=evidence,
            mitre_techniques=["T1110"],
        )

    content = read_file_safe(auth_log)
    if content is None:
        return CheckResult(
            check_id="LINUX-AUTH-003",
            title="Cannot read auth log",
            severity="SKIP",
            detail="Could not read {}.".format(auth_log),
            remediation="Re-run with elevated privileges.",
            category="coverage",
            platform="linux",
            evidence=evidence,
            mitre_techniques=["T1110"],
        )

    # Look for failed auth patterns
    failed_patterns = [
        r'Failed password',
        r'authentication failure',
        r'Failed publickey',
        r'pam_unix.*authentication failure',
        r'Invalid user',
        r'Connection closed by.*\[preauth\]',
    ]

    failed_count = 0
    sample_lines = []
    for line in content.splitlines():
        for pattern in failed_patterns:
            if re.search(pattern, line, re.IGNORECASE):
                failed_count += 1
                if len(sample_lines) < 5:
                    sample_lines.append(line.strip())
                break

    evidence["auth_log"] = auth_log
    evidence["failed_auth_count"] = failed_count
    evidence["sample_lines"] = sample_lines

    if failed_count > 0:
        severity = "PASS"
        detail = (
            "The failed authentication count is a health indicator for both security monitoring "
            "and logging pipeline integrity. {} contains {} failed authentication entries "
            "(matching patterns like 'Failed password', 'Invalid user', and PAM failures). "
            "The presence of failed auth events confirms that the logging pipeline is correctly "
            "capturing authentication failures -- this data is essential for detecting brute-force "
            "attacks, credential stuffing, and unauthorized access attempts."
        ).format(auth_log, failed_count)
        if failed_count > 1000:
            severity = "WARN"
            detail = (
                "The failed authentication count is a health indicator for both security monitoring "
                "and logging pipeline integrity. {} contains {} failed authentication entries, "
                "which is an unusually high volume. This strongly suggests active brute-force "
                "or credential-stuffing attacks against this host. Each entry represents someone "
                "(or an automated tool) attempting to authenticate with invalid credentials. At "
                "this volume, you should investigate the source IP addresses and targeted "
                "usernames to determine if this is a targeted attack or opportunistic scanning."
            ).format(auth_log, failed_count)

        return CheckResult(
            check_id="LINUX-AUTH-003",
            title="Failed auth entries present" if failed_count <= 1000 else "High failed auth volume",
            severity=severity,
            detail=detail,
            remediation="No action required." if failed_count <= 1000 else
                        "Investigate potential brute-force attacks. Consider:\n"
                        "  - Installing fail2ban: sudo apt-get install fail2ban\n"
                        "  - Reviewing source IPs in auth log\n"
                        "  - Enabling rate limiting in sshd_config: MaxAuthTries 3",
            category="coverage",
            platform="linux",
            evidence=evidence,
            mitre_techniques=["T1110"],
        )

    return CheckResult(
        check_id="LINUX-AUTH-003",
        title="No failed auth entries found",
        severity="INFO",
        detail=(
            "The failed authentication count is a health indicator for both security monitoring "
            "and logging pipeline integrity. No failed authentication entries were found in {}. "
            "This has two possible interpretations: either no one has attempted to log in with "
            "invalid credentials (normal on newly provisioned or isolated systems), or the "
            "logging pipeline is broken and failed auth events are not being captured. On any "
            "internet-facing system, zero failed SSH logins is suspicious -- automated scanners "
            "typically generate failed login attempts within hours of a host being exposed."
        ).format(auth_log),
        remediation=(
            "Verify the logging pipeline is actually working by generating a test event:\n"
            "  logger -p auth.info 'test auth message'\n"
            "Then check that the message appears in the auth log. Also confirm that sshd "
            "LogLevel is at least INFO -- lower levels suppress authentication log entries."
        ),
        category="coverage",
        platform="linux",
        evidence=evidence,
        mitre_techniques=["T1110"],
    )


def _check_sshd_dropin_overrides():
    """LINUX-AUTH-004: sshd_config drop-in overrides."""
    evidence = {}
    dropin_dir = "/etc/ssh/sshd_config.d"

    if not file_exists(dropin_dir):
        return CheckResult(
            check_id="LINUX-AUTH-004",
            title="No sshd_config drop-in directory",
            severity="INFO",
            detail=(
                "OpenSSH 8.2+ supports drop-in configuration files in /etc/ssh/sshd_config.d/. "
                "These files are processed in lexicographic order and the FIRST matching directive "
                "wins (unlike most Linux configs where last wins). This means a file like "
                "00-defaults.conf with LogLevel INFO will override LogLevel VERBOSE in the main "
                "sshd_config. Automated deployment tools (Ansible, Puppet, cloud-init) often drop "
                "files here that can silently downgrade SSH logging without anyone noticing.\n\n"
                "The drop-in directory /etc/ssh/sshd_config.d does not exist on this system."
            ),
            remediation="No action required.",
            category="config",
            platform="linux",
            evidence=evidence,
            mitre_techniques=["T1562.001"],
        )

    # Read main sshd_config LogLevel
    main_log_level = None
    main_config = read_file_safe("/etc/ssh/sshd_config")
    if main_config:
        for line in main_config.splitlines():
            stripped = line.strip()
            if stripped.startswith("#") or not stripped:
                continue
            match = re.match(r'^LogLevel\s+(\S+)', stripped, re.IGNORECASE)
            if match:
                main_log_level = match.group(1).upper()

    evidence["main_sshd_config_LogLevel"] = main_log_level or "not set (default: INFO)"

    # Read drop-in configs for LogLevel overrides
    dropin_log_levels = {}
    for dropin in sorted(glob.glob("/etc/ssh/sshd_config.d/*.conf")):
        dropin_content = read_file_safe(dropin)
        if not dropin_content:
            continue
        for line in dropin_content.splitlines():
            stripped = line.strip()
            if stripped.startswith("#") or not stripped:
                continue
            match = re.match(r'^LogLevel\s+(\S+)', stripped, re.IGNORECASE)
            if match:
                dropin_log_levels[dropin] = match.group(1).upper()
                break

    evidence["dropin_log_levels"] = dropin_log_levels

    if not dropin_log_levels:
        return CheckResult(
            check_id="LINUX-AUTH-004",
            title="No LogLevel overrides in sshd drop-ins",
            severity="PASS",
            detail=(
                "OpenSSH 8.2+ supports drop-in configuration files in /etc/ssh/sshd_config.d/. "
                "These files are processed in lexicographic order and the FIRST matching directive "
                "wins (unlike most Linux configs where last wins). This means a file like "
                "00-defaults.conf with LogLevel INFO will override LogLevel VERBOSE in the main "
                "sshd_config. Automated deployment tools (Ansible, Puppet, cloud-init) often drop "
                "files here that can silently downgrade SSH logging without anyone noticing.\n\n"
                "No drop-in configuration files set a LogLevel directive, so the main sshd_config "
                "setting is not being overridden."
            ),
            remediation="No action required.",
            category="config",
            platform="linux",
            evidence=evidence,
            mitre_techniques=["T1562.001"],
        )

    # SSH LogLevel ordering: QUIET < FATAL < ERROR < INFO < VERBOSE < DEBUG*
    level_rank = {
        "QUIET": 0, "FATAL": 1, "ERROR": 2, "INFO": 3, "VERBOSE": 4,
        "DEBUG": 5, "DEBUG1": 5, "DEBUG2": 6, "DEBUG3": 7,
    }

    effective_main = main_log_level or "INFO"
    main_rank = level_rank.get(effective_main, 3)

    # In OpenSSH, first match wins -- the first dropin (lexicographic) takes precedence
    downgrade_found = False
    for dropin_path, dropin_level in sorted(dropin_log_levels.items()):
        dropin_rank = level_rank.get(dropin_level, 3)
        if dropin_rank < main_rank:
            downgrade_found = True
            evidence["downgrade_file"] = dropin_path
            evidence["downgrade_level"] = dropin_level
            break

    if downgrade_found:
        return CheckResult(
            check_id="LINUX-AUTH-004",
            title="Drop-in downgrades SSH LogLevel",
            severity="WARN",
            detail=(
                "OpenSSH 8.2+ supports drop-in configuration files in /etc/ssh/sshd_config.d/. "
                "These files are processed in lexicographic order and the FIRST matching directive "
                "wins (unlike most Linux configs where last wins). This means a file like "
                "00-defaults.conf with LogLevel INFO will override LogLevel VERBOSE in the main "
                "sshd_config. Automated deployment tools (Ansible, Puppet, cloud-init) often drop "
                "files here that can silently downgrade SSH logging without anyone noticing.\n\n"
                "A drop-in file ({}) sets LogLevel to {}, which is lower than the main "
                "sshd_config level of {}. Because OpenSSH uses first-match-wins, this drop-in "
                "will take precedence if it sorts before the main config is read, effectively "
                "downgrading SSH logging."
            ).format(
                evidence.get("downgrade_file", "unknown"),
                evidence.get("downgrade_level", "unknown"),
                effective_main,
            ),
            remediation=(
                "Either remove the LogLevel directive from the drop-in file, or set it to "
                "match or exceed the desired level. To see effective config:\n"
                "  sshd -T | grep loglevel\n"
                "To remove the override:\n"
                "  sudo sed -i '/^LogLevel/d' {}\n"
                "Then restart: sudo systemctl restart sshd"
            ).format(evidence.get("downgrade_file", "/etc/ssh/sshd_config.d/<file>.conf")),
            category="config",
            platform="linux",
            evidence=evidence,
            mitre_techniques=["T1562.001"],
        )

    return CheckResult(
        check_id="LINUX-AUTH-004",
        title="Drop-in LogLevel maintains or increases logging",
        severity="PASS",
        detail=(
            "OpenSSH 8.2+ supports drop-in configuration files in /etc/ssh/sshd_config.d/. "
            "These files are processed in lexicographic order and the FIRST matching directive "
            "wins (unlike most Linux configs where last wins). This means a file like "
            "00-defaults.conf with LogLevel INFO will override LogLevel VERBOSE in the main "
            "sshd_config. Automated deployment tools (Ansible, Puppet, cloud-init) often drop "
            "files here that can silently downgrade SSH logging without anyone noticing.\n\n"
            "Drop-in files set LogLevel but do not downgrade below the main sshd_config level."
        ),
        remediation="No action required.",
        category="config",
        platform="linux",
        evidence=evidence,
        mitre_techniques=["T1562.001"],
    )


def _check_wtmp_btmp_lastlog():
    """LINUX-AUTH-005: wtmp/btmp/lastlog health."""
    evidence = {}
    warnings = []
    now = time.time()
    stale_threshold = 7 * 24 * 3600  # 7 days

    login_files = {
        "/var/log/wtmp": {
            "description": "login/logout records (read by `last`)",
            "expected_perms": 0o664,
            "expected_perms_str": "664",
        },
        "/var/log/btmp": {
            "description": "failed login attempts (read by `lastb`)",
            "expected_perms": 0o600,
            "expected_perms_str": "600",
        },
        "/var/log/lastlog": {
            "description": "most recent login per user (read by `lastlog`)",
            "expected_perms": None,
            "expected_perms_str": None,
        },
    }

    for path, info in login_files.items():
        file_evidence = {}
        if not file_exists(path):
            warnings.append("{} is missing ({})".format(path, info["description"]))
            file_evidence["exists"] = False
        else:
            file_evidence["exists"] = True
            try:
                st = os.stat(path)
                file_evidence["size"] = st.st_size
                file_evidence["mtime"] = st.st_mtime
                actual_perms = stat.S_IMODE(st.st_mode)
                file_evidence["permissions"] = oct(actual_perms)

                if st.st_size == 0:
                    warnings.append("{} exists but is empty ({})".format(path, info["description"]))

                age = now - st.st_mtime
                if age > stale_threshold:
                    age_days = age / 86400
                    warnings.append(
                        "{} is stale (last modified {:.0f} days ago)".format(path, age_days)
                    )

                if info["expected_perms"] is not None:
                    if actual_perms != info["expected_perms"]:
                        warnings.append(
                            "{} has permissions {} (expected {})".format(
                                path, oct(actual_perms), info["expected_perms_str"]
                            )
                        )
            except OSError as exc:
                file_evidence["error"] = str(exc)
                warnings.append("{} exists but cannot stat: {}".format(path, exc))

        evidence[path] = file_evidence

    evidence["warnings"] = warnings

    if warnings:
        return CheckResult(
            check_id="LINUX-AUTH-005",
            title="Login record file issues detected",
            severity="WARN",
            detail=(
                "These are binary login record databases, not traditional text logs. wtmp records "
                "all logins and logouts (read by the `last` command), btmp records failed login "
                "attempts (read by `lastb`), and lastlog records the most recent login per user "
                "(read by `lastlog`). If these files are missing, corrupted, or stale, forensic "
                "commands like `last` and `lastb` return empty or incomplete results. Attackers "
                "sometimes truncate these files to erase evidence of their logins.\n\n"
                "Issues found:\n  - {}".format("\n  - ".join(warnings))
            ),
            remediation=(
                "Recreate missing files with correct permissions:\n"
                "  sudo touch /var/log/wtmp /var/log/btmp /var/log/lastlog\n"
                "  sudo chmod 664 /var/log/wtmp\n"
                "  sudo chmod 600 /var/log/btmp\n"
                "  sudo chown root:utmp /var/log/wtmp /var/log/btmp /var/log/lastlog\n"
                "For stale files, verify that login services (sshd, login, systemd-logind) are "
                "functioning correctly."
            ),
            category="coverage",
            platform="linux",
            evidence=evidence,
            mitre_techniques=["T1070.002"],
        )

    return CheckResult(
        check_id="LINUX-AUTH-005",
        title="Login record files healthy",
        severity="PASS",
        detail=(
            "These are binary login record databases, not traditional text logs. wtmp records "
            "all logins and logouts (read by the `last` command), btmp records failed login "
            "attempts (read by `lastb`), and lastlog records the most recent login per user "
            "(read by `lastlog`). If these files are missing, corrupted, or stale, forensic "
            "commands like `last` and `lastb` return empty or incomplete results. Attackers "
            "sometimes truncate these files to erase evidence of their logins.\n\n"
            "All login record files (wtmp, btmp, lastlog) exist, are non-empty, have been "
            "recently modified, and have appropriate permissions."
        ),
        remediation="No action required.",
        category="coverage",
        platform="linux",
        evidence=evidence,
        mitre_techniques=["T1070.002"],
    )


def _check_login_defs():
    """LINUX-AUTH-006: login.defs logging settings."""
    evidence = {}
    login_defs_path = "/etc/login.defs"
    warnings = []

    content = read_file_safe(login_defs_path)
    if content is None:
        return CheckResult(
            check_id="LINUX-AUTH-006",
            title="Cannot read login.defs",
            severity="INFO",
            detail=(
                "/etc/login.defs is the shadow-utils configuration file that controls login "
                "behavior system-wide. LOG_OK_LOGINS controls whether successful local console "
                "and terminal logins generate a syslog entry. If set to no, successful logins "
                "are only recorded in wtmp (binary) but NOT in syslog — meaning they won't be "
                "forwarded to your SIEM. FAILLOG_ENAB controls whether failed login attempts "
                "are tracked in /var/log/faillog.\n\n"
                "Could not read {}."
            ).format(login_defs_path),
            remediation="Check that {} exists and is readable.".format(login_defs_path),
            category="config",
            platform="linux",
            evidence=evidence,
            mitre_techniques=["T1078"],
        )

    # Parse login.defs for relevant settings
    log_ok_logins = None
    faillog_enab = None
    for line in content.splitlines():
        stripped = line.strip()
        if stripped.startswith("#") or not stripped:
            continue
        match = re.match(r'^LOG_OK_LOGINS\s+(\S+)', stripped)
        if match:
            log_ok_logins = match.group(1).lower()
        match = re.match(r'^FAILLOG_ENAB\s+(\S+)', stripped)
        if match:
            faillog_enab = match.group(1).lower()

    evidence["LOG_OK_LOGINS"] = log_ok_logins or "not set"
    evidence["FAILLOG_ENAB"] = faillog_enab or "not set"
    evidence["config_path"] = login_defs_path

    if log_ok_logins != "yes":
        warnings.append(
            "LOG_OK_LOGINS is {} -- successful local logins will not generate syslog "
            "entries and will not be forwarded to your SIEM".format(
                "'{}'".format(log_ok_logins) if log_ok_logins else "not set"
            )
        )

    if faillog_enab != "yes":
        warnings.append(
            "FAILLOG_ENAB is {} -- failed login tracking via /var/log/faillog is "
            "disabled".format(
                "'{}'".format(faillog_enab) if faillog_enab else "not set"
            )
        )

    evidence["warnings"] = warnings

    if warnings:
        return CheckResult(
            check_id="LINUX-AUTH-006",
            title="login.defs logging settings need attention",
            severity="WARN",
            detail=(
                "/etc/login.defs is the shadow-utils configuration file that controls login "
                "behavior system-wide. LOG_OK_LOGINS controls whether successful local console "
                "and terminal logins generate a syslog entry. If set to no, successful logins "
                "are only recorded in wtmp (binary) but NOT in syslog — meaning they won't be "
                "forwarded to your SIEM. FAILLOG_ENAB controls whether failed login attempts "
                "are tracked in /var/log/faillog.\n\n"
                "Issues found:\n  - {}".format("\n  - ".join(warnings))
            ),
            remediation=(
                "Edit {} and set:\n"
                "  LOG_OK_LOGINS yes\n"
                "  FAILLOG_ENAB yes\n"
                "These changes take effect for new login sessions (no service restart needed)."
            ).format(login_defs_path),
            category="config",
            platform="linux",
            evidence=evidence,
            mitre_techniques=["T1078"],
        )

    return CheckResult(
        check_id="LINUX-AUTH-006",
        title="login.defs logging settings configured",
        severity="PASS",
        detail=(
            "/etc/login.defs is the shadow-utils configuration file that controls login "
            "behavior system-wide. LOG_OK_LOGINS controls whether successful local console "
            "and terminal logins generate a syslog entry. If set to no, successful logins "
            "are only recorded in wtmp (binary) but NOT in syslog — meaning they won't be "
            "forwarded to your SIEM. FAILLOG_ENAB controls whether failed login attempts "
            "are tracked in /var/log/faillog.\n\n"
            "Both LOG_OK_LOGINS and FAILLOG_ENAB are set to 'yes', ensuring that successful "
            "logins are logged via syslog (and thus forwarded to your SIEM) and that failed "
            "login attempts are tracked in the faillog database."
        ),
        remediation="No action required.",
        category="config",
        platform="linux",
        evidence=evidence,
        mitre_techniques=["T1078"],
    )


def run_checks():
    """Return all authentication log checks."""
    return [
        _check_auth_log_exists(),
        _check_ssh_log_level(),
        _check_failed_auth_presence(),
        _check_sshd_dropin_overrides(),
        _check_wtmp_btmp_lastlog(),
        _check_login_defs(),
    ]
