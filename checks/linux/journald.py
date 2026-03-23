"""Journald configuration checks: storage, forwarding, and size limits."""

import glob

from core.result import CheckResult
from core.platform_utils import (
    safe_run, read_file_safe, file_exists, is_elevated,
    get_package_manager, parse_config_file, get_file_mtime,
    check_process_running, get_linux_distro,
)


_JOURNALD_CONF = "/etc/systemd/journald.conf"


def _get_journald_config():
    """Parse journald.conf, also checking conf.d drop-ins."""
    config = parse_config_file(_JOURNALD_CONF)
    # Check drop-in overrides
    for dropin in sorted(glob.glob("/etc/systemd/journald.conf.d/*.conf")):
        override = parse_config_file(dropin)
        config.update(override)
    return config


def _check_persistent_storage():
    """LINUX-JOURNALD-001: Persistent storage enabled."""
    evidence = {}
    config = _get_journald_config()

    storage = config.get("Storage", "").lower()
    evidence["Storage"] = storage or "not set (default: auto)"
    evidence["config_file"] = _JOURNALD_CONF

    # Default is 'auto' which uses persistent if /var/log/journal exists
    if storage == "persistent":
        return CheckResult(
            check_id="LINUX-JOURNALD-001",
            title="Journald persistent storage enabled",
            severity="PASS",
            detail=(
                "systemd-journald is systemd's built-in logging service that collects "
                "structured, indexed log data from all systemd units, the kernel, and "
                "standard output/error of services. Unlike rsyslog which stores plain-text "
                "log files, journald uses a binary format that supports fast indexed "
                "queries (e.g., 'journalctl -u sshd --since yesterday'). Storage=persistent "
                "is explicitly set, which means journal logs are written to /var/log/journal "
                "and survive reboots. This ensures you have a durable local record of all "
                "system activity for forensic investigation."
            ),
            remediation="No action required.",
            category="config",
            platform="linux",
            evidence=evidence,
            mitre_techniques=["T1070.002"],
        )

    if storage in ("", "auto"):
        # Check if /var/log/journal exists (auto mode uses it if present)
        journal_dir_exists = file_exists("/var/log/journal")
        evidence["var_log_journal_exists"] = journal_dir_exists
        if journal_dir_exists:
            return CheckResult(
                check_id="LINUX-JOURNALD-001",
                title="Journald persistent storage active (auto mode)",
                severity="PASS",
                detail=(
                    "systemd-journald is systemd's built-in logging service that collects "
                    "structured, indexed log data from all systemd units, the kernel, and "
                    "standard output/error of services. Unlike rsyslog which stores plain-text "
                    "log files, journald uses a binary format that supports fast indexed "
                    "queries. Storage is set to 'auto' (the default), which means journald "
                    "checks whether /var/log/journal exists at startup -- if it does, logs "
                    "are written there persistently; if it does not, logs go to /run/log/journal "
                    "in RAM and are lost on reboot. The directory /var/log/journal exists on "
                    "this system, so journals are currently persistent. However, this is "
                    "fragile: if the directory is ever removed, persistence silently stops."
                ),
                remediation=(
                    "For explicit, reliable persistence that does not depend on the directory "
                    "pre-existing, set Storage=persistent in {}. This causes journald to "
                    "create /var/log/journal automatically if it is missing:\n"
                    "  [Journal]\n  Storage=persistent"
                ).format(_JOURNALD_CONF),
                category="config",
                platform="linux",
                evidence=evidence,
                mitre_techniques=["T1070.002"],
            )
        else:
            return CheckResult(
                check_id="LINUX-JOURNALD-001",
                title="Journald using volatile storage",
                severity="WARN",
                detail=(
                    "systemd-journald is systemd's built-in logging service that collects "
                    "structured, indexed log data from all systemd units, the kernel, and "
                    "standard output/error of services. Storage is set to 'auto' (the default) "
                    "but the directory /var/log/journal does not exist, so journald falls back "
                    "to volatile mode. In volatile mode, all logs are stored in /run/log/journal "
                    "which is a tmpfs (RAM-backed filesystem) -- every reboot, power loss, or "
                    "crash wipes all journal data. This means you have zero historical log "
                    "data after any restart, making post-incident forensics impossible for "
                    "events that occurred before the most recent boot."
                ),
                remediation=(
                    "Create the persistent journal directory. The 'systemd-tmpfiles' command "
                    "sets the correct ownership and permissions (root:systemd-journal, 2755):\n"
                    "  sudo mkdir -p /var/log/journal && "
                    "sudo systemd-tmpfiles --create --prefix /var/log/journal\n"
                    "Or set in {} (this causes journald to create the directory automatically):\n"
                    "  [Journal]\n  Storage=persistent\n"
                    "Then restart: sudo systemctl restart systemd-journald"
                ).format(_JOURNALD_CONF),
                category="config",
                platform="linux",
                evidence=evidence,
                mitre_techniques=["T1070.002"],
            )

    if storage == "volatile":
        return CheckResult(
            check_id="LINUX-JOURNALD-001",
            title="Journald storage is volatile",
            severity="FAIL",
            detail=(
                "systemd-journald is systemd's built-in logging service that collects "
                "structured, indexed log data from all systemd units, the kernel, and "
                "standard output/error of services. Storage is explicitly set to 'volatile', "
                "which forces all journal data into /run/log/journal (a RAM-backed tmpfs). "
                "Every reboot, power loss, or crash permanently destroys all journal data. "
                "This configuration provides zero log retention across restarts and makes "
                "forensic investigation of past events impossible."
            ),
            remediation=(
                "Change Storage from 'volatile' to 'persistent'. This tells journald to "
                "write logs to /var/log/journal on disk, where they survive reboots. Edit {} "
                "and set:\n"
                "  [Journal]\n  Storage=persistent\n"
                "Then restart: sudo systemctl restart systemd-journald\n"
                "Note: existing volatile logs in /run/log/journal will not be migrated -- "
                "only new events will be written persistently."
            ).format(_JOURNALD_CONF),
            category="config",
            platform="linux",
            evidence=evidence,
            mitre_techniques=["T1070.002"],
        )

    if storage == "none":
        return CheckResult(
            check_id="LINUX-JOURNALD-001",
            title="Journald storage disabled",
            severity="FAIL",
            detail=(
                "systemd-journald is systemd's built-in logging service that collects "
                "structured, indexed log data from all systemd units, the kernel, and "
                "standard output/error of services. Storage is set to 'none', which "
                "completely disables all log storage. Journald will still receive log "
                "messages and can forward them (e.g., to rsyslog), but it will not write "
                "anything to disk or memory. If ForwardToSyslog is also disabled, events "
                "from systemd units are silently discarded with no record anywhere."
            ),
            remediation=(
                "Re-enable log storage by changing Storage to 'persistent'. Edit {} and set:\n"
                "  [Journal]\n  Storage=persistent\n"
                "Then restart: sudo systemctl restart systemd-journald"
            ).format(_JOURNALD_CONF),
            category="config",
            platform="linux",
            evidence=evidence,
            mitre_techniques=["T1070.002"],
        )

    return CheckResult(
        check_id="LINUX-JOURNALD-001",
        title="Journald storage setting unknown",
        severity="WARN",
        detail=(
            "systemd-journald is systemd's built-in logging service. "
            "Storage='{}' -- this is an unexpected value that may not be recognized "
            "by journald. The service may fall back to default behavior, but the "
            "actual storage behavior is unpredictable."
        ).format(storage),
        remediation="Set Storage=persistent in {}".format(_JOURNALD_CONF),
        category="config",
        platform="linux",
        evidence=evidence,
        mitre_techniques=["T1070.002"],
    )


def _check_forward_to_syslog():
    """LINUX-JOURNALD-002: ForwardToSyslog setting."""
    evidence = {}
    config = _get_journald_config()

    fwd = config.get("ForwardToSyslog", "").lower()
    evidence["ForwardToSyslog"] = fwd or "not set (default varies by distro)"

    if fwd == "yes":
        return CheckResult(
            check_id="LINUX-JOURNALD-002",
            title="Journald forwards to syslog",
            severity="PASS",
            detail=(
                "ForwardToSyslog controls the journald-to-rsyslog pipeline. Journald natively "
                "collects log output from all systemd-managed services (via their stdout/stderr "
                "and the sd_journal API), but these events are stored only in the binary journal "
                "by default. When ForwardToSyslog=yes, journald copies each event to the "
                "/dev/log syslog socket, where rsyslog (or syslog-ng) picks it up. Rsyslog can "
                "then forward these events off-host to a SIEM. This setting is enabled, so "
                "events from systemd services will flow through the journald -> rsyslog -> SIEM "
                "pipeline. Without this setting, events from systemd-managed services would "
                "only exist in the local journal and never reach a remote collector via syslog."
            ),
            remediation="No action required.",
            category="forwarding",
            platform="linux",
            evidence=evidence,
            mitre_techniques=["T1070.002"],
        )

    if fwd == "no":
        return CheckResult(
            check_id="LINUX-JOURNALD-002",
            title="Journald not forwarding to syslog",
            severity="WARN",
            detail=(
                "ForwardToSyslog controls the journald-to-rsyslog pipeline. Journald natively "
                "collects log output from all systemd-managed services (via their stdout/stderr "
                "and the sd_journal API), but these events are stored only in the binary journal "
                "by default. ForwardToSyslog is set to 'no', which means journal events are NOT "
                "being copied to the syslog socket. If rsyslog is your mechanism for remote log "
                "forwarding to a SIEM, and rsyslog does not also load the imjournal module "
                "(which reads directly from the journal), then events from systemd-managed "
                "services will never leave this host. Services like sshd, nginx, docker, and "
                "any custom systemd units would have their logs trapped in the local journal only."
            ),
            remediation=(
                "Enable the journald-to-syslog pipeline so that journal events reach rsyslog "
                "for remote forwarding. Edit {} and set:\n"
                "  [Journal]\n  ForwardToSyslog=yes\n"
                "Then restart: sudo systemctl restart systemd-journald\n"
                "Note: if rsyslog already loads the imjournal module (which reads directly from "
                "the journal API), enabling ForwardToSyslog would create duplicate events. "
                "Check your rsyslog config for 'imjournal' before enabling."
            ).format(_JOURNALD_CONF),
            category="forwarding",
            platform="linux",
            evidence=evidence,
            mitre_techniques=["T1070.002"],
        )

    # Not set -- default depends on distro/version, report as info
    return CheckResult(
        check_id="LINUX-JOURNALD-002",
        title="Journald ForwardToSyslog not explicitly set",
        severity="INFO",
        detail=(
            "ForwardToSyslog controls the journald-to-rsyslog pipeline. Journald natively "
            "collects log output from all systemd-managed services, but these events are "
            "stored only in the binary journal by default. ForwardToSyslog is not explicitly "
            "configured in journald.conf. The default value varies by distribution and systemd "
            "version -- older systemd versions defaulted to 'yes', while newer versions "
            "(232+) default to 'no' because rsyslog's imjournal module is the preferred "
            "integration path. Without knowing the effective default, it is uncertain whether "
            "journal events are reaching rsyslog for remote forwarding."
        ),
        remediation=(
            "Explicitly set ForwardToSyslog to remove ambiguity. If rsyslog does NOT load "
            "the imjournal module, set ForwardToSyslog=yes so journal events reach rsyslog. "
            "If rsyslog DOES load imjournal, set ForwardToSyslog=no to avoid duplicates. "
            "Edit {}:\n"
            "  [Journal]\n  ForwardToSyslog=yes"
        ).format(_JOURNALD_CONF),
        category="forwarding",
        platform="linux",
        evidence=evidence,
        mitre_techniques=["T1070.002"],
    )


def _check_journal_size_limits():
    """LINUX-JOURNALD-003: Journal size limits (SystemMaxUse)."""
    evidence = {}
    config = _get_journald_config()

    max_use = config.get("SystemMaxUse", "")
    evidence["SystemMaxUse"] = max_use or "not set (default: 10% of filesystem or 4G)"

    runtime_max = config.get("RuntimeMaxUse", "")
    evidence["RuntimeMaxUse"] = runtime_max or "not set"

    if not max_use:
        return CheckResult(
            check_id="LINUX-JOURNALD-003",
            title="Journal size limit uses default",
            severity="INFO",
            detail=(
                "SystemMaxUse controls the maximum disk space that journald's persistent "
                "logs (in /var/log/journal) are allowed to consume. When this limit is "
                "reached, journald automatically rotates out the oldest journal files to "
                "make room for new events. SystemMaxUse is not explicitly set, so journald "
                "defaults to 10%% of the filesystem size (capped at 4G). This default is "
                "usually adequate for general-purpose systems, but on security-sensitive "
                "hosts where you need longer forensic retention (e.g., 90+ days of logs), "
                "you may want to increase it. On systems with small disks, the 10%% default "
                "may result in very short retention windows, causing old logs to be rotated "
                "away before an investigation can begin."
            ),
            remediation=(
                "To set an explicit limit, edit {} and add a value appropriate for your "
                "disk size and retention requirements. A larger value preserves more "
                "historical log data for forensic analysis but consumes more disk space:\n"
                "  [Journal]\n  SystemMaxUse=2G\n"
                "Then restart: sudo systemctl restart systemd-journald"
            ).format(_JOURNALD_CONF),
            category="config",
            platform="linux",
            evidence=evidence,
            mitre_techniques=[],
        )

    # Parse the size value
    size_str = max_use.strip().upper()
    multipliers = {"K": 1/1024, "M": 1, "G": 1024, "T": 1024*1024}
    size_mb = None
    for suffix, mult in multipliers.items():
        if size_str.endswith(suffix):
            try:
                size_mb = float(size_str[:-1]) * mult
            except ValueError:
                pass
            break
    else:
        # Try bare number (bytes)
        try:
            size_mb = int(size_str) / (1024 * 1024)
        except ValueError:
            pass

    evidence["parsed_size_mb"] = size_mb

    if size_mb is None:
        return CheckResult(
            check_id="LINUX-JOURNALD-003",
            title="Cannot parse journal size limit",
            severity="WARN",
            detail=(
                "SystemMaxUse controls the maximum disk space that journald's persistent logs "
                "are allowed to consume. The current value '{}' could not be parsed as a valid "
                "size. Journald may ignore this setting and fall back to defaults, or it may "
                "fail to apply size limits entirely."
            ).format(max_use),
            remediation=(
                "Set a valid size using standard suffixes (K, M, G, T) in {}, e.g.:\n"
                "  SystemMaxUse=2G"
            ).format(_JOURNALD_CONF),
            category="config",
            platform="linux",
            evidence=evidence,
            mitre_techniques=[],
        )

    if size_mb < 100:
        return CheckResult(
            check_id="LINUX-JOURNALD-003",
            title="Journal size limit very small",
            severity="WARN",
            detail=(
                "SystemMaxUse controls the maximum disk space that journald's persistent logs "
                "are allowed to consume. The current limit is {} ({:.0f} MB), which is very "
                "small. On an active system, this amount of space may only hold a few hours "
                "or days of logs before the oldest entries are rotated away. During a security "
                "incident, investigators often need weeks or months of historical data to "
                "reconstruct an attacker's timeline. A small retention window means critical "
                "forensic evidence may already be gone by the time an intrusion is discovered."
            ).format(max_use, size_mb),
            remediation=(
                "Increase SystemMaxUse in {} to provide adequate forensic retention. The "
                "right value depends on your log volume and disk capacity. 2G is a reasonable "
                "starting point for most systems:\n"
                "  SystemMaxUse=2G\n"
                "Then restart: sudo systemctl restart systemd-journald\n"
                "Trade-off: larger values consume more disk space but preserve older log "
                "data that may be critical for incident investigation."
            ).format(_JOURNALD_CONF),
            category="config",
            platform="linux",
            evidence=evidence,
            mitre_techniques=[],
        )

    return CheckResult(
        check_id="LINUX-JOURNALD-003",
        title="Journal size limit configured",
        severity="PASS",
        detail=(
            "SystemMaxUse controls the maximum disk space that journald's persistent logs "
            "are allowed to consume. It is set to {} ({:.0f} MB), which provides a reasonable "
            "amount of space for log retention. When this limit is reached, journald "
            "automatically rotates out the oldest journal files. The effective retention "
            "period depends on your system's log volume -- a busy server may fill this "
            "faster than a quiet one."
        ).format(max_use, size_mb),
        remediation="No action required.",
        category="config",
        platform="linux",
        evidence=evidence,
        mitre_techniques=[],
    )


def _check_rate_limiting():
    """LINUX-JOURNALD-004: Rate limiting configuration."""
    evidence = {}
    config = _get_journald_config()

    interval = config.get("RateLimitIntervalSec", "")
    burst = config.get("RateLimitBurst", "")
    evidence["RateLimitIntervalSec"] = interval or "not set (default: 30s)"
    evidence["RateLimitBurst"] = burst or "not set (default: 10000)"
    evidence["config_file"] = _JOURNALD_CONF

    # Check if rate limiting is explicitly disabled
    interval_disabled = False
    burst_disabled = False
    if interval:
        try:
            # Strip trailing unit suffixes like 's', 'sec', 'min', etc.
            interval_val = interval.strip().rstrip("sSecminMIN ")
            if interval_val == "0":
                interval_disabled = True
        except (ValueError, AttributeError):
            pass
    if burst:
        try:
            if int(burst.strip()) == 0:
                burst_disabled = True
        except (ValueError, AttributeError):
            pass

    if interval_disabled or burst_disabled:
        return CheckResult(
            check_id="LINUX-JOURNALD-004",
            title="Journald rate limiting disabled",
            severity="INFO",
            detail=(
                "This is the biggest hidden logging gap on most Linux systems. When a service "
                "exceeds the burst threshold within the interval, journald silently discards all "
                "subsequent messages from that service until the interval resets. No warning is "
                "logged about the dropped events — they simply vanish. An attacker can exploit "
                "this by intentionally flooding a service's log output (e.g., triggering thousands "
                "of auth failures rapidly) to cause legitimate security events from that service "
                "to be silently discarded. Your SIEM will never receive the dropped events and "
                "you will have no indication they ever existed.\n\n"
                "Rate limiting is explicitly disabled (RateLimitIntervalSec={}, RateLimitBurst={}). "
                "This guarantees that no events will be silently dropped due to rate limiting, "
                "but trades disk/memory risk for guaranteed event delivery."
            ).format(interval or "default", burst or "default"),
            remediation="No action required. Rate limiting is disabled, ensuring no events are silently dropped.",
            category="config",
            platform="linux",
            evidence=evidence,
            mitre_techniques=["T1562.001"],
        )

    # Check if not explicitly configured (using defaults)
    if not interval and not burst:
        return CheckResult(
            check_id="LINUX-JOURNALD-004",
            title="Journald rate limiting uses defaults",
            severity="WARN",
            detail=(
                "This is the biggest hidden logging gap on most Linux systems. When a service "
                "exceeds the burst threshold within the interval, journald silently discards all "
                "subsequent messages from that service until the interval resets. No warning is "
                "logged about the dropped events — they simply vanish. An attacker can exploit "
                "this by intentionally flooding a service's log output (e.g., triggering thousands "
                "of auth failures rapidly) to cause legitimate security events from that service "
                "to be silently discarded. Your SIEM will never receive the dropped events and "
                "you will have no indication they ever existed.\n\n"
                "Neither RateLimitIntervalSec nor RateLimitBurst is explicitly configured. The "
                "defaults are 30s interval and 10,000 burst — meaning journald silently drops ALL "
                "events from a service that exceeds 10,000 messages in 30 seconds."
            ),
            remediation=(
                "Set explicit rate limit values in {}:\n"
                "  [Journal]\n"
                "  RateLimitIntervalSec=30s\n"
                "  RateLimitBurst=100000\n"
                "Or set to 0 to disable rate limiting entirely, which trades disk/memory risk "
                "for guaranteed event delivery.\n"
                "Then restart: sudo systemctl restart systemd-journald"
            ).format(_JOURNALD_CONF),
            category="config",
            platform="linux",
            evidence=evidence,
            mitre_techniques=["T1562.001"],
        )

    # Check if burst is set very low
    burst_val = None
    if burst:
        try:
            burst_val = int(burst.strip())
        except (ValueError, AttributeError):
            pass

    if burst_val is not None and burst_val < 1000:
        return CheckResult(
            check_id="LINUX-JOURNALD-004",
            title="Journald rate limit burst dangerously low",
            severity="FAIL",
            detail=(
                "This is the biggest hidden logging gap on most Linux systems. When a service "
                "exceeds the burst threshold within the interval, journald silently discards all "
                "subsequent messages from that service until the interval resets. No warning is "
                "logged about the dropped events — they simply vanish. An attacker can exploit "
                "this by intentionally flooding a service's log output (e.g., triggering thousands "
                "of auth failures rapidly) to cause legitimate security events from that service "
                "to be silently discarded. Your SIEM will never receive the dropped events and "
                "you will have no indication they ever existed.\n\n"
                "RateLimitBurst is set to {}, which is very low and will definitely cause event "
                "loss during normal operation. Many services routinely generate hundreds of "
                "messages per interval during startup, log rotation, or high-activity periods."
            ).format(burst_val),
            remediation=(
                "Increase RateLimitBurst in {}:\n"
                "  [Journal]\n"
                "  RateLimitIntervalSec=30s\n"
                "  RateLimitBurst=100000\n"
                "Or set to 0 to disable rate limiting entirely, which trades disk/memory risk "
                "for guaranteed event delivery.\n"
                "Then restart: sudo systemctl restart systemd-journald"
            ).format(_JOURNALD_CONF),
            category="config",
            platform="linux",
            evidence=evidence,
            mitre_techniques=["T1562.001"],
        )

    # Burst is explicitly set to a reasonable value
    if burst_val is not None and burst_val >= 10000:
        return CheckResult(
            check_id="LINUX-JOURNALD-004",
            title="Journald rate limiting configured",
            severity="PASS",
            detail=(
                "This is the biggest hidden logging gap on most Linux systems. When a service "
                "exceeds the burst threshold within the interval, journald silently discards all "
                "subsequent messages from that service until the interval resets. No warning is "
                "logged about the dropped events — they simply vanish. An attacker can exploit "
                "this by intentionally flooding a service's log output (e.g., triggering thousands "
                "of auth failures rapidly) to cause legitimate security events from that service "
                "to be silently discarded. Your SIEM will never receive the dropped events and "
                "you will have no indication they ever existed.\n\n"
                "Rate limiting is explicitly configured with RateLimitIntervalSec={} and "
                "RateLimitBurst={}. The burst value is set to a reasonable threshold that "
                "should accommodate normal service activity while still providing some "
                "protection against runaway logging."
            ).format(interval or "default", burst),
            remediation="No action required.",
            category="config",
            platform="linux",
            evidence=evidence,
            mitre_techniques=["T1562.001"],
        )

    # Burst is between 1000 and 10000 — warn
    return CheckResult(
        check_id="LINUX-JOURNALD-004",
        title="Journald rate limit burst may cause event loss",
        severity="WARN",
        detail=(
            "This is the biggest hidden logging gap on most Linux systems. When a service "
            "exceeds the burst threshold within the interval, journald silently discards all "
            "subsequent messages from that service until the interval resets. No warning is "
            "logged about the dropped events — they simply vanish. An attacker can exploit "
            "this by intentionally flooding a service's log output (e.g., triggering thousands "
            "of auth failures rapidly) to cause legitimate security events from that service "
            "to be silently discarded. Your SIEM will never receive the dropped events and "
            "you will have no indication they ever existed.\n\n"
            "RateLimitBurst is set to {} which may cause event loss during high-activity "
            "periods. Consider increasing to at least 10,000 or higher."
        ).format(burst),
        remediation=(
            "Increase RateLimitBurst in {}:\n"
            "  [Journal]\n"
            "  RateLimitIntervalSec=30s\n"
            "  RateLimitBurst=100000\n"
            "Or set to 0 to disable rate limiting entirely, which trades disk/memory risk "
            "for guaranteed event delivery.\n"
            "Then restart: sudo systemctl restart systemd-journald"
        ).format(_JOURNALD_CONF),
        category="config",
        platform="linux",
        evidence=evidence,
        mitre_techniques=["T1562.001"],
    )


def _check_forward_sealing():
    """LINUX-JOURNALD-005: Forward sealing (Seal)."""
    evidence = {}
    config = _get_journald_config()

    seal = config.get("Seal", "").lower()
    evidence["Seal"] = seal or "not set (default: no)"
    evidence["config_file"] = _JOURNALD_CONF

    if seal == "yes":
        return CheckResult(
            check_id="LINUX-JOURNALD-005",
            title="Journald forward sealing enabled",
            severity="PASS",
            detail=(
                "Forward Secure Sealing (FSS) creates a cryptographic hash chain within journal "
                "files using a sealing key that advances forward in time. Once an interval is "
                "sealed, even an attacker with root access cannot modify the sealed entries "
                "without breaking the chain. The verification key (stored separately) can detect "
                "tampering. This provides tamper-evidence for forensic integrity — useful if you "
                "need to prove in court or to auditors that logs haven't been modified.\n\n"
                "Seal=yes is configured, which means journal files are being cryptographically "
                "sealed for tamper detection."
            ),
            remediation="No action required.",
            category="config",
            platform="linux",
            evidence=evidence,
            mitre_techniques=["T1070.002"],
        )

    return CheckResult(
        check_id="LINUX-JOURNALD-005",
        title="Journald forward sealing not enabled",
        severity="INFO",
        detail=(
            "Forward Secure Sealing (FSS) creates a cryptographic hash chain within journal "
            "files using a sealing key that advances forward in time. Once an interval is "
            "sealed, even an attacker with root access cannot modify the sealed entries "
            "without breaking the chain. The verification key (stored separately) can detect "
            "tampering. This provides tamper-evidence for forensic integrity — useful if you "
            "need to prove in court or to auditors that logs haven't been modified.\n\n"
            "Seal is not enabled (current value: {}). This is a low-priority enhancement "
            "that provides tamper-evidence rather than tamper-prevention."
        ).format(seal or "not set"),
        remediation=(
            "Set Seal=yes in {}. Then generate sealing keys with:\n"
            "  journalctl --setup-keys\n"
            "Store the verification key offline/off-host securely. Verify integrity with:\n"
            "  journalctl --verify\n"
            "Then restart: sudo systemctl restart systemd-journald"
        ).format(_JOURNALD_CONF),
        category="config",
        platform="linux",
        evidence=evidence,
        mitre_techniques=["T1070.002"],
    )


def run_checks():
    """Return all journald checks."""
    return [
        _check_persistent_storage(),
        _check_forward_to_syslog(),
        _check_journal_size_limits(),
        _check_rate_limiting(),
        _check_forward_sealing(),
    ]
