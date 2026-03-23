#!/usr/bin/env python3
"""
Security Log Auditor — Cross-platform security logging audit tool.

Inspects the logging and audit configuration of a host and produces a
detailed report of what is correctly configured, what is misconfigured,
what is missing, and what is generating unnecessary noise.

Usage:
    python log_auditor.py [OPTIONS]

Options:
    --html              Generate HTML report
    --json              Generate JSON output
    --output-dir PATH   Directory for report files (default: current directory)
    --checks CATEGORY   Only run checks in specified category
    --severity LEVEL    Only show findings at or above this severity
    --no-color          Disable terminal colors
    --quiet             Only show FAIL findings in terminal
    --list-checks       Print all check IDs and titles then exit
    --version           Show version
"""

import argparse
import os
import sys

__version__ = "1.0.0"

# Ensure the project root is in sys.path so imports work
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from core.platform_utils import get_os, is_elevated, get_hostname
from core.runner import run_all_checks, list_all_checks
from core.reporter import print_terminal_report, generate_json_report, generate_html_report, save_report


def print_privilege_warning():
    """Print warning about checks that will be skipped without elevation."""
    current_os = get_os()
    print("\033[93mWARNING: Running without elevated privileges.\033[0m")
    print("")
    if current_os == "linux":
        print("The following checks require root and will be skipped:")
        print("  - Reading /etc/audit/auditd.conf and audit rules")
        print("  - Reading /etc/shadow permissions")
        print("  - Inspecting auditd service status (may be limited)")
        print("  - Parsing Splunk forwarder configs in /opt/")
        print("  - Reading auth log contents")
    elif current_os == "windows":
        print("The following checks require Administrator and will be skipped:")
        print("  - Querying audit policy (auditpol)")
        print("  - Reading event log configuration")
        print("  - Querying Sysmon configuration")
        print("  - Accessing registry keys for logging settings")
    elif current_os == "macos":
        print("The following checks require root and will be skipped:")
        print("  - Reading /etc/security/audit_control")
        print("  - Inspecting /var/audit/ contents")
        print("  - Querying system log statistics")
    print("")
    print("Run with elevated privileges for a complete audit:")
    if current_os == "windows":
        print("  Right-click Command Prompt -> Run as Administrator")
    else:
        print("  sudo python3 log_auditor.py")
    print("")


def main():
    parser = argparse.ArgumentParser(
        description="Security Log Auditor — Inspect and validate host security logging configuration.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--html", action="store_true", help="Generate HTML report")
    parser.add_argument("--json", action="store_true", help="Generate JSON output")
    parser.add_argument("--output-dir", default=".", help="Directory for report files (default: current directory)")
    parser.add_argument(
        "--checks",
        choices=["service", "config", "rules", "forwarding", "noise", "edr", "coverage"],
        help="Only run checks in specified category",
    )
    parser.add_argument(
        "--severity",
        choices=["FAIL", "WARN", "INFO"],
        help="Only show findings at or above this severity",
    )
    parser.add_argument("--no-color", action="store_true", help="Disable terminal colors")
    parser.add_argument("--quiet", action="store_true", help="Only show FAIL findings in terminal")
    parser.add_argument("--list-checks", action="store_true", help="Print all check IDs and titles then exit")
    parser.add_argument("--version", action="version", version="log_auditor {}".format(__version__))

    args = parser.parse_args()

    # List checks mode
    if args.list_checks:
        checks = list_all_checks()
        current_os = get_os()
        print("Security Log Auditor — All Checks")
        print("=" * 60)
        print("{:<22} {:<45} {}".format("CHECK ID", "TITLE", "PLATFORM"))
        print("-" * 60)
        for check_id, title, plat in checks:
            marker = " *" if plat == current_os or plat == "all" else ""
            print("{:<22} {:<45} {}{}".format(check_id, title, plat, marker))
        print("")
        print("* = applicable to this host ({})".format(current_os))
        print("Total: {} checks".format(len(checks)))
        sys.exit(0)

    # Banner
    use_color = not args.no_color and sys.stdout.isatty()
    if use_color:
        print("\033[96m\033[1m")
    print(r"""
  _                      _             _ _ _
 | |    ___   __ _      / \  _   _  __| (_) |_ ___  _ __
 | |   / _ \ / _` |    / _ \| | | |/ _` | | __/ _ \| '__|
 | |__| (_) | (_| |   / ___ \ |_| | (_| | | || (_) | |
 |_____\___/ \__, |  /_/   \_\__,_|\__,_|_|\__\___/|_|
             |___/
    """)
    if use_color:
        print("\033[0m")
    print("  Security Log Auditor v{}".format(__version__))
    print("  Platform: {}".format(get_os()))
    print("")

    # Privilege check
    elevated = is_elevated()
    if not elevated:
        print_privilege_warning()

    # Run checks
    print("Running checks...")
    print("")
    report = run_all_checks(
        category_filter=args.checks,
        severity_filter=args.severity,
    )

    # Terminal output
    print_terminal_report(report, use_color=use_color, quiet=args.quiet)

    # File outputs
    hostname = get_hostname()
    timestamp = report.timestamp.replace(":", "-").replace("T", "_").rstrip("Z")
    output_dir = args.output_dir

    if args.json:
        json_content = generate_json_report(report)
        json_path = os.path.join(output_dir, "log_audit_{}_{}.json".format(hostname, timestamp))
        result = save_report(json_content, json_path)
        if result:
            print("JSON report saved to: {}".format(result))

    if args.html:
        html_content = generate_html_report(report)
        html_path = os.path.join(output_dir, "log_audit_{}_{}.html".format(hostname, timestamp))
        result = save_report(html_content, html_path)
        if result:
            print("HTML report saved to: {}".format(result))

    # Exit code: 1 if any FAIL findings, 0 otherwise
    if report.summary.get("FAIL", 0) > 0:
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
