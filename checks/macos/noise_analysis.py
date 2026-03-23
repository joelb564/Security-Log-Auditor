"""macOS noise analysis checks: Unified Logging System volume assessment."""

from core.result import CheckResult
from core.platform_utils import (
    safe_run, read_file_safe, file_exists, is_elevated,
    check_process_running, get_os,
)


def _check_uls_volume():
    """MAC-NOISE-001: ULS volume assessment."""
    evidence = {}

    # Use 'log stats' to get volume information
    rc, out, err = safe_run(["log", "stats"], timeout=15)
    evidence["log_stats_rc"] = rc
    evidence["log_stats_output"] = out[:1000] if out else ""
    evidence["log_stats_error"] = err[:300] if err else ""

    if rc != 0:
        # Fallback: check diagnostics directory size
        rc2, out2, _ = safe_run(["du", "-sh", "/var/db/diagnostics"], timeout=15)
        evidence["diagnostics_size"] = out2.strip() if rc2 == 0 else "unknown"

        if rc2 == 0 and out2.strip():
            size_str = out2.strip().split()[0] if out2.strip() else "unknown"
            evidence["parsed_size"] = size_str

            # Parse size (rough heuristic)
            size_gb = _parse_size_to_gb(size_str)
            evidence["size_gb"] = size_gb

            if size_gb is not None and size_gb > 10:
                return CheckResult(
                    check_id="MAC-NOISE-001",
                    title="ULS data store is large ({})".format(size_str),
                    severity="WARN",
                    detail=(
                        "The ULS data store at /var/db/diagnostics is {} in size. "
                        "This suggests high log volume. Without log filtering or "
                        "profile-based log level configuration, excessive ULS data "
                        "can consume disk space and make security analysis difficult."
                    ).format(size_str),
                    remediation=(
                        "Reduce ULS noise with a custom logging profile:\n"
                        "  1. Create a .plist logging profile to set subsystem log levels\n"
                        "  2. Install via: sudo log config --mode 'level:default' "
                        "--subsystem com.apple.noisy.subsystem\n"
                        "  3. Review active subsystems: log config --status\n\n"
                        "Consider deploying a log collection tool (osquery, EDR agent) "
                        "that filters relevant events rather than collecting all ULS data."
                    ),
                    category="noise",
                    platform="macos",
                    evidence=evidence,
                    mitre_techniques=["T1562.002"],
                )

            return CheckResult(
                check_id="MAC-NOISE-001",
                title="ULS volume is {}".format(size_str),
                severity="PASS",
                detail=(
                    "The ULS data store at /var/db/diagnostics is {} in size. "
                    "This is within normal range."
                ).format(size_str),
                remediation="No action required.",
                category="noise",
                platform="macos",
                evidence=evidence,
                mitre_techniques=[],
            )

        return CheckResult(
            check_id="MAC-NOISE-001",
            title="Unable to assess ULS volume",
            severity="INFO",
            detail=(
                "'log stats' command failed and directory size could not be determined. "
                "This may require elevated privileges."
            ),
            remediation="Re-run with sudo for full ULS volume analysis.",
            category="noise",
            platform="macos",
            evidence=evidence,
            mitre_techniques=[],
        )

    # Parse log stats output for volume data
    evidence["log_stats_parsed"] = True

    # Try to count recent event rate using 'log show' with a short window
    rc3, out3, _ = safe_run(
        ["log", "show", "--last", "1m", "--style", "ndjson"],
        timeout=30,
    )
    event_count = 0
    if rc3 == 0 and out3:
        event_count = out3.count("\n")
    evidence["events_last_minute"] = event_count

    # Also check diagnostics directory size
    rc4, out4, _ = safe_run(["du", "-sh", "/var/db/diagnostics"], timeout=15)
    if rc4 == 0 and out4.strip():
        size_str = out4.strip().split()[0]
        evidence["diagnostics_size"] = size_str
        size_gb = _parse_size_to_gb(size_str)
        evidence["size_gb"] = size_gb

    # Assess volume
    if event_count > 5000:
        return CheckResult(
            check_id="MAC-NOISE-001",
            title="High ULS event volume ({} events/min)".format(event_count),
            severity="WARN",
            detail=(
                "ULS generated approximately {} events in the last minute. "
                "High event volume without filtering makes security-relevant "
                "event detection difficult and consumes storage rapidly."
            ).format(event_count),
            remediation=(
                "Reduce ULS noise:\n"
                "  1. Identify noisy subsystems: log show --last 5m --info | "
                "cut -d' ' -f5 | sort | uniq -c | sort -rn | head -20\n"
                "  2. Adjust log levels for noisy subsystems:\n"
                "     sudo log config --mode 'level:error' --subsystem <noisy.subsystem>\n"
                "  3. Deploy a selective log collection tool (osquery, EDR) that "
                "filters relevant security events."
            ),
            category="noise",
            platform="macos",
            evidence=evidence,
            mitre_techniques=["T1562.002"],
        )

    if event_count > 1000:
        return CheckResult(
            check_id="MAC-NOISE-001",
            title="Moderate ULS event volume ({} events/min)".format(event_count),
            severity="INFO",
            detail=(
                "ULS generated approximately {} events in the last minute. "
                "This is moderate volume. Consider whether all subsystems need "
                "current log levels."
            ).format(event_count),
            remediation=(
                "Review active log levels:\n"
                "  log config --status\n"
                "Consider lowering debug/info levels for non-security subsystems."
            ),
            category="noise",
            platform="macos",
            evidence=evidence,
            mitre_techniques=[],
        )

    return CheckResult(
        check_id="MAC-NOISE-001",
        title="ULS volume is normal",
        severity="PASS",
        detail=(
            "ULS generated approximately {} events in the last minute. "
            "Log volume appears manageable."
        ).format(event_count),
        remediation="No action required.",
        category="noise",
        platform="macos",
        evidence=evidence,
        mitre_techniques=[],
    )


def _parse_size_to_gb(size_str):
    """Parse a du -sh size string (e.g., '2.5G', '500M') to GB as float."""
    try:
        size_str = size_str.strip()
        if size_str.endswith("G"):
            return float(size_str[:-1])
        elif size_str.endswith("M"):
            return float(size_str[:-1]) / 1024.0
        elif size_str.endswith("K"):
            return float(size_str[:-1]) / (1024.0 * 1024.0)
        elif size_str.endswith("T"):
            return float(size_str[:-1]) * 1024.0
        elif size_str.endswith("B"):
            return float(size_str[:-1]) / (1024.0 * 1024.0 * 1024.0)
        else:
            # Assume bytes
            return float(size_str) / (1024.0 * 1024.0 * 1024.0)
    except (ValueError, IndexError):
        return None


def run_checks():
    """Return all macOS noise analysis checks. Returns empty list on non-macOS."""
    if get_os() != "macos":
        return []

    return [
        _check_uls_volume(),
    ]
