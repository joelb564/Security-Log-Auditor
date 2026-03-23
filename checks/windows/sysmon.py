"""Windows Sysmon installation and configuration checks."""

import platform
import re

from core.result import CheckResult
from core.platform_utils import safe_run, read_file_safe, file_exists, is_elevated, check_process_running

try:
    import winreg
except ImportError:
    winreg = None


def _is_windows():
    return platform.system() == "Windows"


def _check_sysmon_service(service_name):
    """Check if a Windows service exists and is running via sc query."""
    rc, out, err = safe_run(["sc", "query", service_name], timeout=10)
    if rc != 0:
        return False, "not found"
    if "RUNNING" in out:
        return True, "running"
    if "STOPPED" in out:
        return True, "stopped"
    return True, "unknown"


def _check_sysmon_installed():
    """WIN-SYSMON-001: Sysmon installed and running."""
    check_id = "WIN-SYSMON-001"
    title_base = "Sysmon Installation"
    evidence = {}

    # Check both 32-bit and 64-bit service names
    sysmon_found = False
    sysmon_running = False
    service_name = None

    for svc in ["Sysmon64", "Sysmon"]:
        exists, state = _check_sysmon_service(svc)
        evidence[svc] = state
        if exists:
            sysmon_found = True
            service_name = svc
            if state == "running":
                sysmon_running = True
            break

    # Also check process
    for proc in ["Sysmon64.exe", "Sysmon.exe"]:
        if check_process_running(proc):
            sysmon_found = True
            sysmon_running = True
            evidence["process_running"] = proc
            break

    if sysmon_running:
        return CheckResult(
            check_id=check_id,
            title="{} - Running".format(title_base),
            severity="PASS",
            detail="Sysmon is installed and running (service: {}).".format(
                service_name or "detected via process"),
            remediation="No action required.",
            category="service",
            platform="windows",
            evidence=evidence,
        )

    if sysmon_found:
        return CheckResult(
            check_id=check_id,
            title="{} - Installed But Not Running".format(title_base),
            severity="FAIL",
            detail="Sysmon service '{}' is installed but not running.".format(service_name),
            remediation="net start {}\n\n"
                        "Or: sc config {} start=auto && net start {}".format(
                            service_name, service_name, service_name),
            category="service",
            platform="windows",
            evidence=evidence,
        )

    return CheckResult(
        check_id=check_id,
        title="{} - Not Installed".format(title_base),
        severity="FAIL",
        detail="Sysmon is not installed. Sysmon provides critical visibility into process "
               "creation, network connections, file creation, registry changes, and more. "
               "It is one of the most important tools for Windows endpoint visibility.",
        remediation="Download Sysmon from Microsoft Sysinternals:\n"
                    "  https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon\n\n"
                    "Install with a community config (e.g., SwiftOnSecurity):\n"
                    "  sysmon64 -accepteula -i sysmonconfig-export.xml\n\n"
                    "Recommended configs:\n"
                    "  - https://github.com/SwiftOnSecurity/sysmon-config\n"
                    "  - https://github.com/olafhartong/sysmon-modular",
        category="service",
        platform="windows",
        evidence=evidence,
    )


def _check_sysmon_config_quality():
    """WIN-SYSMON-002: Sysmon configuration quality (key event types covered)."""
    check_id = "WIN-SYSMON-002"
    title_base = "Sysmon Configuration Quality"
    evidence = {}

    # First check if Sysmon is even running
    sysmon_running = False
    sysmon_exe = None
    for proc in ["Sysmon64.exe", "Sysmon.exe"]:
        if check_process_running(proc):
            sysmon_running = True
            sysmon_exe = proc.replace(".exe", "")
            break

    if not sysmon_running:
        for svc in ["Sysmon64", "Sysmon"]:
            _, state = _check_sysmon_service(svc)
            if state == "running":
                sysmon_running = True
                sysmon_exe = svc
                break

    if not sysmon_running:
        return CheckResult(
            check_id=check_id,
            title="{} - Sysmon Not Running".format(title_base),
            severity="SKIP",
            detail="Sysmon is not running; cannot assess configuration quality.",
            remediation="Install and start Sysmon first.",
            category="config",
            platform="windows",
            evidence=evidence,
        )

    # Export current Sysmon config
    exe_name = sysmon_exe or "sysmon64"
    rc, out, err = safe_run([exe_name, "-c"], timeout=15)
    if rc != 0:
        # Try alternate path
        rc, out, err = safe_run(
            [r"C:\Windows\{}".format(exe_name), "-c"], timeout=15
        )

    evidence["sysmon_config_output"] = out[:2000] if rc == 0 else ""
    evidence["sysmon_config_error"] = err[:500] if rc != 0 else ""

    # Key event types to look for in Sysmon config
    # EventType ID: Description
    key_event_types = {
        1: "ProcessCreate",
        3: "NetworkConnect",
        7: "ImageLoaded",
        8: "CreateRemoteThread",
        10: "ProcessAccess",
        11: "FileCreate",
        12: "RegistryEvent (Create/Delete)",
        13: "RegistryEvent (Value Set)",
        15: "FileCreateStreamHash",
        22: "DNSQuery",
    }

    if rc != 0 or not out.strip():
        return CheckResult(
            check_id=check_id,
            title="{} - Cannot Assess".format(title_base),
            severity="WARN",
            detail="Sysmon is running but could not export configuration. "
                   "This may indicate a renamed binary or restricted permissions.",
            remediation="Run '{} -c' as Administrator to verify configuration.\n"
                        "Ensure these event types are configured: {}".format(
                            exe_name,
                            ", ".join("{}({})".format(v, k) for k, v in key_event_types.items())),
            category="config",
            platform="windows",
            evidence=evidence,
        )

    # Parse config output for event type rules
    config_text = out.lower()
    found_types = []
    missing_types = []

    for eid, name in key_event_types.items():
        # Look for references to the event type in config output
        # Sysmon -c output shows rule groups like "ProcessCreate", "NetworkConnect", etc.
        if name.lower() in config_text or "eventtype {}".format(eid) in config_text:
            found_types.append("{}({})".format(name, eid))
        else:
            missing_types.append("{}({})".format(name, eid))

    evidence["found_event_types"] = found_types
    evidence["missing_event_types"] = missing_types

    coverage_pct = len(found_types) / len(key_event_types) * 100

    if coverage_pct >= 80:
        return CheckResult(
            check_id=check_id,
            title="{} - Good ({:.0f}% coverage)".format(title_base, coverage_pct),
            severity="PASS",
            detail="Sysmon config covers {}/{} key event types. "
                   "Found: {}".format(len(found_types), len(key_event_types),
                                      ", ".join(found_types)),
            remediation="No action required." if not missing_types else
                        "Consider adding rules for: {}".format(", ".join(missing_types)),
            category="config",
            platform="windows",
            evidence=evidence,
        )

    if coverage_pct >= 50:
        severity = "WARN"
    else:
        severity = "FAIL"

    return CheckResult(
        check_id=check_id,
        title="{} - Incomplete ({:.0f}% coverage)".format(title_base, coverage_pct),
        severity=severity,
        detail="Sysmon config only covers {}/{} key event types. "
               "Missing: {}".format(len(found_types), len(key_event_types),
                                    ", ".join(missing_types)),
        remediation="Update Sysmon configuration to include missing event types.\n"
                    "Consider using a comprehensive community config:\n"
                    "  sysmon64 -c sysmonconfig-export.xml\n\n"
                    "Recommended configs:\n"
                    "  - https://github.com/SwiftOnSecurity/sysmon-config\n"
                    "  - https://github.com/olafhartong/sysmon-modular",
        category="config",
        platform="windows",
        evidence=evidence,
    )


def _check_sysmon_log_size():
    """WIN-SYSMON-003: Sysmon log channel size."""
    check_id = "WIN-SYSMON-003"
    title_base = "Sysmon Log Channel Size"
    channel = "Microsoft-Windows-Sysmon/Operational"

    rc, out, err = safe_run(["wevtutil", "gl", channel], timeout=10)
    if rc != 0:
        return CheckResult(
            check_id=check_id,
            title="{} - Channel Not Found".format(title_base),
            severity="INFO",
            detail="Sysmon Operational log channel not found. Sysmon may not be installed.",
            remediation="Install Sysmon to create the log channel.",
            category="config",
            platform="windows",
            evidence={"error": err},
        )

    evidence = {"raw_config": out}

    # Parse maxSize
    max_size_bytes = 0
    for line in out.splitlines():
        line = line.strip()
        if line.lower().startswith("maxsize:"):
            try:
                max_size_bytes = int(line.split(":", 1)[1].strip())
            except ValueError:
                pass

    max_size_mb = max_size_bytes / (1024 * 1024)
    evidence["maxsize_bytes"] = max_size_bytes
    evidence["maxsize_mb"] = max_size_mb

    if max_size_mb >= 1024:
        return CheckResult(
            check_id=check_id,
            title="{} - Adequate ({:.0f} MB)".format(title_base, max_size_mb),
            severity="PASS",
            detail="Sysmon log channel is {:.0f} MB (>= 1 GB).".format(max_size_mb),
            remediation="No action required.",
            category="config",
            platform="windows",
            evidence=evidence,
        )

    return CheckResult(
        check_id=check_id,
        title="{} - Too Small ({:.0f} MB)".format(title_base, max_size_mb),
        severity="WARN",
        detail="Sysmon log channel is only {:.0f} MB. With comprehensive Sysmon rules, "
               "this fills very quickly. Recommend at least 1 GB.".format(max_size_mb),
        remediation='wevtutil sl "Microsoft-Windows-Sysmon/Operational" /ms:1073741824',
        category="config",
        platform="windows",
        evidence=evidence,
    )


def run_checks():
    """Return all Sysmon checks."""
    if not _is_windows():
        return []

    if not is_elevated():
        return [CheckResult(
            check_id="WIN-SYSMON-001",
            title="Sysmon Checks - Elevation Required",
            severity="SKIP",
            detail="Sysmon checks require administrator privileges.",
            remediation="Re-run this tool as Administrator.",
            category="service",
            platform="windows",
            evidence={},
        )]

    return [
        _check_sysmon_installed(),
        _check_sysmon_config_quality(),
        _check_sysmon_log_size(),
    ]
