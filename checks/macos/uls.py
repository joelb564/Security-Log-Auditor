"""macOS Unified Logging System (ULS) checks: operational status, subsystem consumers, osquery."""

import os
import re

from core.result import CheckResult
from core.platform_utils import (
    safe_run, read_file_safe, file_exists, is_elevated,
    check_process_running, get_os, list_processes,
)


def _check_uls_operational():
    """MAC-ULS-001: Unified logging system operational."""
    evidence = {}

    # Check /var/db/diagnostics exists (ULS data store)
    diagnostics_exists = file_exists("/var/db/diagnostics")
    evidence["diagnostics_dir_exists"] = diagnostics_exists

    # Try running 'log stats' for a brief system check
    rc, out, err = safe_run(["log", "stats"], timeout=15)
    evidence["log_stats_rc"] = rc
    evidence["log_stats_output"] = out[:500] if out else ""
    evidence["log_stats_error"] = err[:300] if err else ""

    if diagnostics_exists:
        # Check for recent log data
        try:
            uuidtext_path = "/var/db/diagnostics/Persist"
            if file_exists(uuidtext_path):
                evidence["persist_dir_exists"] = True
        except (OSError, PermissionError):
            pass

        return CheckResult(
            check_id="MAC-ULS-001",
            title="Unified Logging System is operational",
            severity="INFO",
            detail=(
                "The macOS Unified Logging System (ULS) is operational. "
                "/var/db/diagnostics exists and stores structured log data. "
                "ULS is always running on modern macOS (10.12+) and replaces "
                "ASL/syslog. It captures system, security, and application events "
                "by default."
            ),
            remediation="No action required. ULS is managed by the OS.",
            category="service",
            platform="macos",
            evidence=evidence,
            mitre_techniques=["T1562.002"],
        )

    # /var/db/diagnostics missing is unusual
    return CheckResult(
        check_id="MAC-ULS-001",
        title="ULS data store not found",
        severity="WARN",
        detail=(
            "/var/db/diagnostics does not exist. This directory stores Unified "
            "Logging System data. Its absence is abnormal and may indicate "
            "system corruption or tampering."
        ),
        remediation=(
            "Investigate why /var/db/diagnostics is missing:\n"
            "  ls -la /var/db/diagnostics\n"
            "  log show --last 5m --info\n"
            "If the system has been tampered with, consider reimaging. "
            "Contact Apple support if this appears to be filesystem corruption."
        ),
        category="service",
        platform="macos",
        evidence=evidence,
        mitre_techniques=["T1562.002", "T1070"],
    )


def _check_uls_consumers():
    """MAC-ULS-002: Security-relevant ULS subsystem consumers."""
    evidence = {}

    # Known security tools that consume ULS events
    security_tools = {
        "osqueryd": "osquery",
        "osqueryctl": "osquery",
        "falcond": "CrowdStrike Falcon",
        "CSFalconService": "CrowdStrike Falcon",
        "SentinelAgent": "SentinelOne",
        "sentineld": "SentinelOne",
        "mdatp": "Microsoft Defender for Endpoint",
        "MsSense": "Microsoft Defender for Endpoint",
        "cbdefense": "Carbon Black",
        "CbDefense": "Carbon Black",
    }

    process_list = list_processes()
    evidence["process_list_length"] = len(process_list.splitlines()) if process_list else 0

    detected_tools = []
    for proc_name, tool_label in security_tools.items():
        if proc_name.lower() in process_list.lower():
            if tool_label not in detected_tools:
                detected_tools.append(tool_label)

    evidence["detected_security_tools"] = detected_tools

    if detected_tools:
        return CheckResult(
            check_id="MAC-ULS-002",
            title="Security tools consuming ULS events",
            severity="PASS",
            detail=(
                "Detected security tool(s) that subscribe to macOS ULS streams: {}. "
                "These tools collect and forward ULS security events for analysis."
            ).format(", ".join(detected_tools)),
            remediation="No action required.",
            category="service",
            platform="macos",
            evidence=evidence,
            mitre_techniques=["T1562.002"],
        )

    return CheckResult(
        check_id="MAC-ULS-002",
        title="No security tool consuming ULS events",
        severity="WARN",
        detail=(
            "No known security tool was detected consuming macOS ULS events. "
            "Without a tool subscribing to ULS streams, security-relevant events "
            "(process execution, authentication, network activity) are only "
            "retained locally with default retention policies."
        ),
        remediation=(
            "Deploy a security tool that consumes macOS ULS events:\n"
            "  - osquery: brew install --cask osquery\n"
            "  - CrowdStrike Falcon (commercial)\n"
            "  - SentinelOne (commercial)\n"
            "  - Microsoft Defender for Endpoint (included with M365 E5)\n"
            "At minimum, install osquery for open-source ULS event collection."
        ),
        category="service",
        platform="macos",
        evidence=evidence,
        mitre_techniques=["T1562.002"],
    )


def _check_osquery():
    """MAC-ULS-003: osquery presence and configuration."""
    evidence = {}

    osqueryd_running = check_process_running("osqueryd")
    evidence["osqueryd_running"] = osqueryd_running

    osquery_dir_exists = file_exists("/var/osquery")
    evidence["osquery_dir_exists"] = osquery_dir_exists

    # Also check brew-installed location
    osquery_bin_exists = file_exists("/usr/local/bin/osqueryd") or \
                         file_exists("/opt/osquery/bin/osqueryd")
    evidence["osquery_bin_exists"] = osquery_bin_exists

    if not osqueryd_running and not osquery_dir_exists and not osquery_bin_exists:
        return CheckResult(
            check_id="MAC-ULS-003",
            title="osquery not detected",
            severity="WARN",
            detail=(
                "osquery is not installed or running. osquery provides powerful "
                "SQL-based querying of macOS security events including process "
                "execution, file changes, network connections, and ULS events."
            ),
            remediation=(
                "Install osquery:\n"
                "  brew install --cask osquery\n"
                "Or download from: https://osquery.io/downloads\n\n"
                "Start the daemon:\n"
                "  sudo osqueryctl start\n\n"
                "Configure scheduled queries in /var/osquery/osquery.conf"
            ),
            category="service",
            platform="macos",
            evidence=evidence,
            mitre_techniques=["T1562.002", "T1059"],
        )

    if not osqueryd_running:
        return CheckResult(
            check_id="MAC-ULS-003",
            title="osquery installed but not running",
            severity="WARN",
            detail=(
                "osquery appears to be installed (found at {}) but osqueryd "
                "is not running. Security queries are not being collected."
            ).format("/var/osquery" if osquery_dir_exists else "binary found"),
            remediation=(
                "Start the osquery daemon:\n"
                "  sudo osqueryctl start\n"
                "Or via launchd:\n"
                "  sudo launchctl load /Library/LaunchDaemons/io.osquery.agent.plist"
            ),
            category="service",
            platform="macos",
            evidence=evidence,
            mitre_techniques=["T1562.002"],
        )

    # osquery is running - check configuration
    config_paths = [
        "/var/osquery/osquery.conf",
        "/etc/osquery/osquery.conf",
        "/opt/osquery/share/osquery/osquery.conf",
    ]
    config_content = None
    config_path = None
    for cp in config_paths:
        content = read_file_safe(cp)
        if content:
            config_content = content
            config_path = cp
            break

    evidence["config_path"] = config_path

    if not config_content:
        return CheckResult(
            check_id="MAC-ULS-003",
            title="osquery running but config not found",
            severity="WARN",
            detail=(
                "osqueryd is running but no configuration file was found at "
                "standard locations. osquery may be running with default settings "
                "and no scheduled security queries."
            ),
            remediation=(
                "Create an osquery configuration with security-relevant scheduled queries:\n"
                "  sudo cp /var/osquery/osquery.example.conf /var/osquery/osquery.conf\n"
                "Add packs for: process_events, socket_events, file_events, user_events.\n"
                "Restart: sudo osqueryctl restart"
            ),
            category="config",
            platform="macos",
            evidence=evidence,
            mitre_techniques=["T1562.002"],
        )

    evidence["config_snippet"] = config_content[:500]

    # Check for security-relevant scheduled queries
    security_keywords = [
        "process_events", "socket_events", "file_events",
        "user_events", "hardware_events", "disk_events",
        "es_process_events", "login", "auth", "sudo",
        "listening_ports", "open_sockets",
    ]
    found_queries = [kw for kw in security_keywords if kw in config_content.lower()]
    evidence["security_queries_found"] = found_queries

    if not found_queries:
        return CheckResult(
            check_id="MAC-ULS-003",
            title="osquery running but no security queries detected",
            severity="WARN",
            detail=(
                "osqueryd is running with config at {} but no security-relevant "
                "scheduled queries were detected. osquery is not collecting "
                "security events."
            ).format(config_path),
            remediation=(
                "Add security-relevant scheduled queries to {}. Example:\n"
                '  "schedule": {{\n'
                '    "process_events": {{\n'
                '      "query": "SELECT * FROM process_events;",\n'
                '      "interval": 60\n'
                "    }}\n"
                "  }}\n"
                "Then restart: sudo osqueryctl restart"
            ).format(config_path),
            category="config",
            platform="macos",
            evidence=evidence,
            mitre_techniques=["T1059"],
        )

    return CheckResult(
        check_id="MAC-ULS-003",
        title="osquery running with security queries",
        severity="PASS",
        detail=(
            "osqueryd is running with config at {}. Found {} security-relevant "
            "query keyword(s): {}."
        ).format(config_path, len(found_queries), ", ".join(found_queries)),
        remediation="No action required.",
        category="service",
        platform="macos",
        evidence=evidence,
        mitre_techniques=["T1059"],
    )


def run_checks():
    """Return all macOS ULS checks. Returns empty list on non-macOS."""
    if get_os() != "macos":
        return []

    return [
        _check_uls_operational(),
        _check_uls_consumers(),
        _check_osquery(),
    ]
