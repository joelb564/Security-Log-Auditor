"""macOS log shipper detection checks: Splunk Universal Forwarder and Filebeat."""

import glob
import re

from core.result import CheckResult
from core.platform_utils import (
    safe_run, read_file_safe, file_exists, is_elevated,
    check_process_running, get_os,
)


def _check_splunk_forwarder():
    """MAC-SHIPPER-001: Splunk Universal Forwarder detection and config validation."""
    evidence = {}

    # Common Splunk UF paths on macOS
    splunk_paths = [
        "/Applications/SplunkForwarder",
        "/opt/splunkforwarder",
        "/Applications/splunk",
        "/opt/splunk",
    ]

    splunk_home = None
    for path in splunk_paths:
        if file_exists(path):
            splunk_home = path
            break

    evidence["checked_paths"] = splunk_paths
    evidence["splunk_home"] = splunk_home

    splunkd_running = check_process_running("splunkd")
    evidence["splunkd_running"] = splunkd_running

    if not splunk_home and not splunkd_running:
        return CheckResult(
            check_id="MAC-SHIPPER-001",
            title="Splunk Universal Forwarder not detected",
            severity="INFO",
            detail="No Splunk Universal Forwarder installation found on macOS.",
            remediation=(
                "If Splunk is your SIEM, install the Universal Forwarder for macOS:\n"
                "  1. Download from https://www.splunk.com/en_us/download/universal-forwarder.html\n"
                "  2. Install the .dmg package\n"
                "  3. sudo /Applications/SplunkForwarder/bin/splunk start --accept-license\n"
                "  4. Configure inputs.conf to monitor /var/log/ and /var/audit/"
            ),
            category="forwarding",
            platform="macos",
            evidence=evidence,
            mitre_techniques=["T1070.002"],
        )

    if not splunkd_running:
        return CheckResult(
            check_id="MAC-SHIPPER-001",
            title="Splunk UF installed but not running",
            severity="WARN",
            detail=(
                "Splunk UF found at {} but splunkd process is not running. "
                "Logs are not being forwarded."
            ).format(splunk_home),
            remediation=(
                "Start the Splunk forwarder:\n"
                "  sudo {}/bin/splunk start\n"
                "  sudo {}/bin/splunk enable boot-start"
            ).format(splunk_home, splunk_home),
            category="forwarding",
            platform="macos",
            evidence=evidence,
            mitre_techniques=["T1070.002"],
        )

    # Splunk is running - validate inputs.conf
    inputs_conf = None
    inputs_path = None
    if splunk_home:
        search_paths = [
            "{}/etc/system/local/inputs.conf".format(splunk_home),
        ]
        search_paths.extend(glob.glob("{}/etc/apps/*/local/inputs.conf".format(splunk_home)))

        for ipath in search_paths:
            content = read_file_safe(ipath)
            if content:
                inputs_conf = content
                inputs_path = ipath
                break

    evidence["inputs_conf_path"] = inputs_path

    monitored_paths = []
    if inputs_conf:
        evidence["inputs_conf_snippet"] = inputs_conf[:500]
        for match in re.finditer(r'\[monitor://([^\]]+)\]', inputs_conf):
            monitored_paths.append(match.group(1))

    evidence["monitored_paths"] = monitored_paths

    # Check for critical macOS log paths
    critical_paths = ["/var/log/auth.log", "/var/audit"]
    monitoring_auth = any(
        any(cp in mp for cp in critical_paths)
        for mp in monitored_paths
    )
    evidence["monitoring_auth_logs"] = monitoring_auth

    issues = []
    if not monitored_paths:
        issues.append("No monitored inputs found in inputs.conf.")
    if not monitoring_auth:
        issues.append(
            "Not monitoring /var/log/auth.log or /var/audit/. "
            "Security-critical authentication and audit events are not being forwarded."
        )

    if issues:
        return CheckResult(
            check_id="MAC-SHIPPER-001",
            title="Splunk UF running but config incomplete",
            severity="WARN",
            detail="Splunk UF is running but: {}".format(" ".join(issues)),
            remediation=(
                "Add security log monitoring to inputs.conf ({}):\n"
                "  [monitor:///var/log/auth.log]\n"
                "  sourcetype = macos:auth\n"
                "  index = security\n\n"
                "  [monitor:///var/audit/]\n"
                "  sourcetype = macos:bsm\n"
                "  index = security\n\n"
                "Then restart: sudo {}/bin/splunk restart"
            ).format(
                inputs_path or "{}/etc/system/local/inputs.conf".format(splunk_home),
                splunk_home,
            ),
            category="forwarding",
            platform="macos",
            evidence=evidence,
            mitre_techniques=["T1070.002"],
        )

    return CheckResult(
        check_id="MAC-SHIPPER-001",
        title="Splunk UF running and configured",
        severity="PASS",
        detail=(
            "Splunk UF is running, monitoring {} input path(s) including "
            "security-critical logs."
        ).format(len(monitored_paths)),
        remediation="No action required.",
        category="forwarding",
        platform="macos",
        evidence=evidence,
        mitre_techniques=["T1070.002"],
    )


def _check_filebeat():
    """MAC-SHIPPER-002: Filebeat detection and macOS system module."""
    evidence = {}

    filebeat_running = check_process_running("filebeat")
    evidence["filebeat_running"] = filebeat_running

    # Check common install locations on macOS
    filebeat_paths = [
        "/usr/local/etc/filebeat/filebeat.yml",
        "/etc/filebeat/filebeat.yml",
        "/opt/homebrew/etc/filebeat/filebeat.yml",
    ]
    filebeat_installed = any(file_exists(p) for p in filebeat_paths)
    evidence["filebeat_installed"] = filebeat_installed

    if not filebeat_running and not filebeat_installed:
        return CheckResult(
            check_id="MAC-SHIPPER-002",
            title="Filebeat not detected",
            severity="INFO",
            detail="Filebeat is not installed or running on this macOS system.",
            remediation=(
                "If using Elastic Stack, install Filebeat:\n"
                "  brew install elastic/tap/filebeat-full\n"
                "Or download from https://www.elastic.co/downloads/beats/filebeat\n\n"
                "Enable the system module for macOS:\n"
                "  filebeat modules enable system"
            ),
            category="forwarding",
            platform="macos",
            evidence=evidence,
            mitre_techniques=["T1070.002"],
        )

    if not filebeat_running:
        return CheckResult(
            check_id="MAC-SHIPPER-002",
            title="Filebeat installed but not running",
            severity="WARN",
            detail="Filebeat configuration found but the service is not active.",
            remediation=(
                "Start Filebeat:\n"
                "  sudo brew services start elastic/tap/filebeat-full\n"
                "Or:\n"
                "  sudo filebeat -e -c /usr/local/etc/filebeat/filebeat.yml &"
            ),
            category="forwarding",
            platform="macos",
            evidence=evidence,
            mitre_techniques=["T1070.002"],
        )

    # Filebeat is running - check system module
    config_content = None
    config_path = None
    for cp in filebeat_paths:
        content = read_file_safe(cp)
        if content:
            config_content = content
            config_path = cp
            break

    evidence["config_path"] = config_path

    # Check modules directory for system module
    system_module_enabled = False
    modules_dirs = [
        "/usr/local/etc/filebeat/modules.d",
        "/etc/filebeat/modules.d",
        "/opt/homebrew/etc/filebeat/modules.d",
    ]
    for mod_dir in modules_dirs:
        system_yml = "{}/system.yml".format(mod_dir)
        system_disabled = "{}/system.yml.disabled".format(mod_dir)
        if file_exists(system_yml):
            content = read_file_safe(system_yml)
            if content and "enabled: true" in content:
                system_module_enabled = True
                evidence["system_module_path"] = system_yml
                break
        if file_exists(system_disabled):
            evidence["system_module_disabled_path"] = system_disabled

    evidence["system_module_enabled"] = system_module_enabled

    if not system_module_enabled:
        return CheckResult(
            check_id="MAC-SHIPPER-002",
            title="Filebeat running but system module not enabled",
            severity="WARN",
            detail=(
                "Filebeat is running but the system module is not enabled for macOS. "
                "The system module collects auth and syslog events."
            ),
            remediation=(
                "Enable the Filebeat system module:\n"
                "  sudo filebeat modules enable system\n"
                "Configure the system module for macOS paths:\n"
                "  Edit modules.d/system.yml:\n"
                "    - module: system\n"
                "      auth:\n"
                "        enabled: true\n"
                "        var.paths: [\"/var/log/auth.log\"]\n"
                "      syslog:\n"
                "        enabled: true\n"
                "        var.paths: [\"/var/log/system.log\"]\n"
                "Then restart Filebeat."
            ),
            category="forwarding",
            platform="macos",
            evidence=evidence,
            mitre_techniques=["T1070.002"],
        )

    return CheckResult(
        check_id="MAC-SHIPPER-002",
        title="Filebeat running with system module enabled",
        severity="PASS",
        detail="Filebeat is active with the system module enabled for macOS log collection.",
        remediation="No action required.",
        category="forwarding",
        platform="macos",
        evidence=evidence,
        mitre_techniques=["T1070.002"],
    )


def run_checks():
    """Return all macOS log shipper checks. Returns empty list on non-macOS."""
    if get_os() != "macos":
        return []

    return [
        _check_splunk_forwarder(),
        _check_filebeat(),
    ]
