"""NTP time synchronization health checks."""

import re

from core.result import CheckResult
from core.platform_utils import safe_run, check_process_running


def _check_ntp_sync():
    """LINUX-NTP-001: Time synchronization health."""
    evidence = {}

    # Check for chrony
    chrony_running = check_process_running("chronyd")
    evidence["chronyd_running"] = chrony_running

    # Check for ntpd
    ntpd_running = check_process_running("ntpd")
    evidence["ntpd_running"] = ntpd_running

    # Also check systemd-timesyncd
    rc, out, _ = safe_run(["systemctl", "is-active", "systemd-timesyncd"])
    timesyncd_running = out.strip() == "active"
    evidence["timesyncd_running"] = timesyncd_running

    if not chrony_running and not ntpd_running and not timesyncd_running:
        # Check systemctl for chrony as well
        rc, out, _ = safe_run(["systemctl", "is-active", "chronyd"])
        if out.strip() == "active":
            chrony_running = True
            evidence["chronyd_running"] = True
        rc, out, _ = safe_run(["systemctl", "is-active", "chrony"])
        if out.strip() == "active":
            chrony_running = True
            evidence["chronyd_running"] = True
        rc, out, _ = safe_run(["systemctl", "is-active", "ntpd"])
        if out.strip() == "active":
            ntpd_running = True
            evidence["ntpd_running"] = True
        rc, out, _ = safe_run(["systemctl", "is-active", "ntp"])
        if out.strip() == "active":
            ntpd_running = True
            evidence["ntpd_running"] = True

    if not chrony_running and not ntpd_running and not timesyncd_running:
        return CheckResult(
            check_id="LINUX-NTP-001",
            title="No NTP service running",
            severity="FAIL",
            detail=(
                "Every log entry on every system depends on accurate timestamps. "
                "When your SIEM correlates events across multiple hosts -- matching "
                "a login on the domain controller with a process execution on the "
                "endpoint -- it relies on timestamps being consistent. If this "
                "host's clock is off by even a few seconds, events will appear out "
                "of order in the SIEM timeline. A 30-second drift means an "
                "attacker's lateral movement from Host A to Host B might appear to "
                "happen BEFORE the initial compromise on Host A, making the attack "
                "chain impossible to reconstruct. NTP (Network Time Protocol) keeps "
                "clocks synchronized. No NTP service (chronyd, ntpd, or "
                "systemd-timesyncd) is running on this host -- timestamps will "
                "drift and become unreliable."
            ),
            remediation=(
                "Install and enable an NTP service. chrony is recommended for most "
                "modern Linux distributions:\n"
                "  sudo apt-get install chrony  # Debian/Ubuntu\n"
                "  sudo dnf install chrony      # RHEL/Fedora\n"
                "  sudo systemctl enable --now chronyd\n\n"
                "The default configuration synchronizes with pool.ntp.org servers, "
                "which is suitable for most environments. For isolated networks, "
                "configure internal NTP servers in /etc/chrony.conf."
            ),
            category="config",
            platform="linux",
            evidence=evidence,
            mitre_techniques=["T1070.006"],
        )

    # Get sync status and parse offset
    offset_seconds = None
    sync_source = None

    if chrony_running:
        sync_source = "chrony"
        rc, out, _ = safe_run(["chronyc", "tracking"], timeout=10)
        evidence["chronyc_tracking"] = out.strip() if rc == 0 else "failed"
        if rc == 0:
            # Parse "System time : 0.000001234 seconds slow of NTP time"
            match = re.search(
                r'System time\s*:\s*([\d.]+)\s+seconds\s+(slow|fast)',
                out,
            )
            if match:
                offset_seconds = float(match.group(1))
            # Also check "Last offset"
            match = re.search(r'Last offset\s*:\s*([+-]?[\d.]+)', out)
            if match:
                offset_seconds = abs(float(match.group(1)))

    elif ntpd_running:
        sync_source = "ntpd"
        rc, out, _ = safe_run(["ntpq", "-pn"], timeout=10)
        evidence["ntpq_output"] = out.strip() if rc == 0 else "failed"
        if rc == 0:
            # Parse ntpq output -- offset is in milliseconds in the "offset" column
            for line in out.splitlines():
                if line.startswith("*") or line.startswith("+"):
                    parts = line.split()
                    if len(parts) >= 9:
                        try:
                            offset_seconds = abs(float(parts[8])) / 1000.0
                        except ValueError:
                            pass
                    break

    elif timesyncd_running:
        sync_source = "systemd-timesyncd"
        rc, out, _ = safe_run(["timedatectl", "show-timesync", "--no-pager"], timeout=10)
        if rc != 0:
            rc, out, _ = safe_run(["timedatectl", "status"], timeout=10)
        evidence["timedatectl_output"] = out.strip() if rc == 0 else "failed"
        if rc == 0:
            # Parse "NTP synchronized: yes" and offset if available
            match = re.search(r'Offset\s*[:=]\s*([+-]?[\d.]+)', out)
            if match:
                offset_seconds = abs(float(match.group(1)))

    evidence["sync_source"] = sync_source
    evidence["offset_seconds"] = offset_seconds

    if offset_seconds is not None and offset_seconds > 1.0:
        return CheckResult(
            check_id="LINUX-NTP-001",
            title="Clock offset too high ({:.3f}s via {})".format(
                offset_seconds, sync_source
            ),
            severity="WARN",
            detail=(
                "Every log entry on every system depends on accurate timestamps. "
                "When your SIEM correlates events across multiple hosts -- matching "
                "a login on the domain controller with a process execution on the "
                "endpoint -- it relies on timestamps being consistent. If this "
                "host's clock is off by even a few seconds, events will appear out "
                "of order in the SIEM timeline. A 30-second drift means an "
                "attacker's lateral movement from Host A to Host B might appear to "
                "happen BEFORE the initial compromise on Host A, making the attack "
                "chain impossible to reconstruct. NTP (Network Time Protocol) keeps "
                "clocks synchronized. The current clock offset is {:.3f} seconds, "
                "which is large enough to break SIEM event correlation."
            ).format(offset_seconds),
            remediation=(
                "Investigate why the clock is drifting. Common causes:\n"
                "  - NTP server unreachable (firewall blocking UDP 123)\n"
                "  - Virtual machine without guest time sync tools\n"
                "  - Hardware clock issues\n"
                "Force an immediate sync:\n"
                "  sudo chronyc makestep   # for chrony\n"
                "  sudo ntpdate -u pool.ntp.org   # for ntpd\n"
                "Check NTP server reachability:\n"
                "  chronyc sources -v   # for chrony\n"
                "  ntpq -pn            # for ntpd"
            ),
            category="config",
            platform="linux",
            evidence=evidence,
            mitre_techniques=["T1070.006"],
        )

    return CheckResult(
        check_id="LINUX-NTP-001",
        title="Time synchronized via {}".format(sync_source),
        severity="PASS",
        detail=(
            "Every log entry on every system depends on accurate timestamps. "
            "When your SIEM correlates events across multiple hosts -- matching "
            "a login on the domain controller with a process execution on the "
            "endpoint -- it relies on timestamps being consistent. If this "
            "host's clock is off by even a few seconds, events will appear out "
            "of order in the SIEM timeline. A 30-second drift means an "
            "attacker's lateral movement from Host A to Host B might appear to "
            "happen BEFORE the initial compromise on Host A, making the attack "
            "chain impossible to reconstruct. NTP (Network Time Protocol) keeps "
            "clocks synchronized. {} is running and the clock offset is within "
            "acceptable limits{}."
        ).format(
            sync_source,
            " ({:.6f}s)".format(offset_seconds) if offset_seconds is not None else "",
        ),
        remediation="No action required.",
        category="config",
        platform="linux",
        evidence=evidence,
        mitre_techniques=["T1070.006"],
    )


def run_checks():
    """Return all NTP checks."""
    return [
        _check_ntp_sync(),
    ]
