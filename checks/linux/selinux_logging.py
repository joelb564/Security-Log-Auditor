"""SELinux logging status checks."""

from core.result import CheckResult
from core.platform_utils import safe_run, file_exists


def _check_selinux_audit_logging():
    """LINUX-SELINUX-001: SELinux audit logging status."""
    evidence = {}

    # Check SELinux mode
    rc, out, err = safe_run(["getenforce"])
    if rc != 0:
        evidence["getenforce"] = "not available"
        evidence["error"] = err.strip()
        return CheckResult(
            check_id="LINUX-SELINUX-001",
            title="SELinux not available",
            severity="INFO",
            detail=(
                "SELinux (Security-Enhanced Linux) is a mandatory access control "
                "system built into the Linux kernel that generates AVC (Access Vector "
                "Cache) denial logs. These logs record every action that violates "
                "SELinux security policy, providing valuable security telemetry. "
                "getenforce could not be executed on this system, indicating that "
                "SELinux is not installed or not supported by this distribution. "
                "Distributions like Ubuntu use AppArmor by default instead of SELinux."
            ),
            remediation=(
                "If your distribution supports SELinux and you want AVC telemetry, "
                "install the SELinux packages for your distribution. For RHEL/CentOS/"
                "Fedora systems, SELinux should be available by default."
            ),
            category="config",
            platform="linux",
            evidence=evidence,
            mitre_techniques=["T1562.001"],
        )

    selinux_mode = out.strip()
    evidence["getenforce"] = selinux_mode

    # Get sestatus for more detail
    rc, out, _ = safe_run(["sestatus"])
    if rc == 0:
        evidence["sestatus"] = out.strip()

    # Check for recent AVC entries
    if file_exists("/var/log/audit/audit.log"):
        rc, out, _ = safe_run(
            ["grep", "-c", "type=AVC", "/var/log/audit/audit.log"],
            timeout=10,
        )
        try:
            avc_count = int(out.strip()) if rc == 0 else 0
        except ValueError:
            avc_count = 0
        evidence["avc_count"] = avc_count

    if selinux_mode == "Disabled":
        return CheckResult(
            check_id="LINUX-SELINUX-001",
            title="SELinux is disabled",
            severity="WARN",
            detail=(
                "SELinux is completely disabled. When disabled, SELinux generates "
                "zero AVC (Access Vector Cache) denial logs. These denial logs are "
                "a valuable telemetry source -- they record every action that "
                "SELinux's mandatory access control policy would block, including "
                "process attempts to access files, ports, or other processes outside "
                "their security context. In permissive mode, SELinux logs these "
                "denials without actually blocking them, giving you visibility into "
                "potentially suspicious behavior with zero operational impact. In "
                "enforcing mode, SELinux both logs AND blocks unauthorized actions, "
                "providing both detection and prevention. Even if your organization "
                "is not ready for enforcing mode, switching to permissive generates "
                "security telemetry at no risk."
            ),
            remediation=(
                "To enable SELinux logging without enforcement risk: edit "
                "/etc/selinux/config and set SELINUX=permissive, then reboot. This "
                "generates all AVC denial logs (which can be forwarded to your SIEM) "
                "without blocking any operations."
            ),
            category="config",
            platform="linux",
            evidence=evidence,
            mitre_techniques=["T1562.001"],
        )

    if selinux_mode == "Permissive":
        return CheckResult(
            check_id="LINUX-SELINUX-001",
            title="SELinux is permissive (logging but not enforcing)",
            severity="INFO",
            detail=(
                "SELinux is in permissive mode, which means it logs all AVC (Access "
                "Vector Cache) denial events but does not actually block any "
                "operations. This provides valuable security telemetry -- every "
                "action that violates SELinux policy is recorded in the audit log, "
                "including suspicious process behavior like attempts to access files "
                "or ports outside a process's security context. However, since "
                "enforcement is off, SELinux is providing detection-only capability "
                "without prevention."
            ),
            remediation=(
                "Consider switching to enforcing mode for both detection and "
                "prevention: edit /etc/selinux/config and set SELINUX=enforcing, "
                "then reboot. Before switching, review current AVC denials with "
                "'ausearch -m avc -ts recent' to ensure no legitimate applications "
                "would be blocked."
            ),
            category="config",
            platform="linux",
            evidence=evidence,
            mitre_techniques=["T1562.001"],
        )

    if selinux_mode == "Enforcing":
        return CheckResult(
            check_id="LINUX-SELINUX-001",
            title="SELinux is enforcing",
            severity="PASS",
            detail=(
                "SELinux is in enforcing mode, providing both AVC denial logging "
                "and active enforcement of mandatory access control policy. Every "
                "action that violates SELinux policy is both logged to the audit "
                "log AND blocked at the kernel level. This provides the strongest "
                "combination of detection and prevention -- suspicious process "
                "behavior is recorded for investigation AND prevented from "
                "succeeding."
            ),
            remediation="No action required.",
            category="config",
            platform="linux",
            evidence=evidence,
            mitre_techniques=["T1562.001"],
        )

    # Unknown mode
    return CheckResult(
        check_id="LINUX-SELINUX-001",
        title="SELinux mode unrecognized: {}".format(selinux_mode),
        severity="INFO",
        detail=(
            "getenforce returned an unrecognized mode: '{}'. Unable to determine "
            "SELinux logging status."
        ).format(selinux_mode),
        remediation="Verify SELinux status manually with 'sestatus'.",
        category="config",
        platform="linux",
        evidence=evidence,
        mitre_techniques=["T1562.001"],
    )


def run_checks():
    """Return all SELinux logging checks."""
    return [
        _check_selinux_audit_logging(),
    ]
