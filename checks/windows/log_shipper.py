"""Windows log shipper detection checks: Splunk UF, Winlogbeat, any shipper."""

import os
import platform
import re

from core.result import CheckResult
from core.platform_utils import safe_run, read_file_safe, file_exists, is_elevated, check_process_running


def _is_windows():
    return platform.system() == "Windows"


def _check_service_running(service_name):
    """Check if a Windows service is running. Returns (exists, running)."""
    rc, out, err = safe_run(["sc", "query", service_name], timeout=10)
    if rc != 0:
        return False, False
    running = "RUNNING" in out
    return True, running


def _find_splunk_home():
    """Find Splunk Universal Forwarder installation directory."""
    candidates = [
        r"C:\Program Files\SplunkUniversalForwarder",
        r"C:\Program Files (x86)\SplunkUniversalForwarder",
        r"C:\SplunkUniversalForwarder",
        r"C:\Program Files\Splunk",
        r"D:\SplunkUniversalForwarder",
    ]
    for path in candidates:
        if file_exists(path):
            return path

    # Check SPLUNK_HOME environment variable
    splunk_home = os.environ.get("SPLUNK_HOME")
    if splunk_home and file_exists(splunk_home):
        return splunk_home

    return None


def _check_splunk_forwarder():
    """WIN-SHIPPER-001: Splunk Universal Forwarder."""
    check_id = "WIN-SHIPPER-001"
    title_base = "Splunk Universal Forwarder"
    evidence = {}

    # Check service
    svc_exists, svc_running = _check_service_running("SplunkForwarder")
    evidence["service_exists"] = svc_exists
    evidence["service_running"] = svc_running

    # Check process
    process_running = check_process_running("splunkd.exe")
    evidence["splunkd_process"] = process_running

    # Find installation
    splunk_home = _find_splunk_home()
    evidence["splunk_home"] = splunk_home

    if not svc_exists and not process_running and not splunk_home:
        return CheckResult(
            check_id=check_id,
            title="{} - Not Detected".format(title_base),
            severity="INFO",
            detail="Splunk Universal Forwarder is not installed.",
            remediation="If Splunk is your SIEM, install the Universal Forwarder:\n"
                        "  1. Download from https://www.splunk.com/en_us/download/universal-forwarder.html\n"
                        "  2. Install: msiexec /i splunkforwarder.msi AGREETOLICENSE=yes /quiet\n"
                        "  3. Configure: splunk add forward-server <indexer>:9997\n"
                        "  4. Add inputs: splunk add monitor WinEventLog://Security",
            category="forwarding",
            platform="windows",
            evidence=evidence,
        )

    if not svc_running and not process_running:
        return CheckResult(
            check_id=check_id,
            title="{} - Not Running".format(title_base),
            severity="WARN",
            detail="Splunk UF is installed at {} but is not running.".format(
                splunk_home or "unknown location"),
            remediation="net start SplunkForwarder\n\n"
                        "Or: sc config SplunkForwarder start=auto && net start SplunkForwarder",
            category="forwarding",
            platform="windows",
            evidence=evidence,
        )

    # Running - check inputs.conf for WinEventLog stanzas
    inputs_conf_content = None
    inputs_conf_path = None
    wineventlog_stanzas = []

    if splunk_home:
        # Check various inputs.conf locations
        inputs_paths = [
            os.path.join(splunk_home, "etc", "system", "local", "inputs.conf"),
            os.path.join(splunk_home, "etc", "apps", "SplunkUniversalForwarder", "local", "inputs.conf"),
        ]
        # Also check deployed apps
        apps_dir = os.path.join(splunk_home, "etc", "apps")
        if file_exists(apps_dir):
            try:
                for app in os.listdir(apps_dir):
                    local_inputs = os.path.join(apps_dir, app, "local", "inputs.conf")
                    if file_exists(local_inputs):
                        inputs_paths.append(local_inputs)
            except OSError:
                pass

        for ipath in inputs_paths:
            content = read_file_safe(ipath)
            if content and "WinEventLog" in content:
                inputs_conf_content = content
                inputs_conf_path = ipath
                break
            elif content and not inputs_conf_content:
                inputs_conf_content = content
                inputs_conf_path = ipath

    evidence["inputs_conf_path"] = inputs_conf_path

    if inputs_conf_content:
        evidence["inputs_conf_snippet"] = inputs_conf_content[:1000]
        # Parse WinEventLog stanzas
        for match in re.finditer(r'\[WinEventLog://([^\]]+)\]', inputs_conf_content):
            wineventlog_stanzas.append(match.group(1))

    evidence["wineventlog_stanzas"] = wineventlog_stanzas

    # Check outputs.conf for forwarding target
    outputs_conf = None
    has_forward_server = False
    if splunk_home:
        outputs_paths = [
            os.path.join(splunk_home, "etc", "system", "local", "outputs.conf"),
        ]
        apps_dir = os.path.join(splunk_home, "etc", "apps")
        if file_exists(apps_dir):
            try:
                for app in os.listdir(apps_dir):
                    local_outputs = os.path.join(apps_dir, app, "local", "outputs.conf")
                    if file_exists(local_outputs):
                        outputs_paths.append(local_outputs)
            except OSError:
                pass

        for opath in outputs_paths:
            content = read_file_safe(opath)
            if content:
                outputs_conf = content
                evidence["outputs_conf_path"] = opath
                if re.search(r'server\s*=', content):
                    has_forward_server = True
                break

    evidence["has_forward_server"] = has_forward_server

    issues = []
    if not wineventlog_stanzas:
        issues.append("No WinEventLog stanzas found in inputs.conf")
    else:
        key_logs = ["Security", "System", "Application"]
        missing_logs = [log for log in key_logs if log not in wineventlog_stanzas]
        if missing_logs:
            issues.append("Missing key event logs: {}".format(", ".join(missing_logs)))

    if not has_forward_server:
        issues.append("No forwarding server configured in outputs.conf")

    if issues:
        remediation_parts = []
        if not wineventlog_stanzas or missing_logs:
            remediation_parts.append(
                "Add WinEventLog inputs to inputs.conf:\n"
                "  [WinEventLog://Security]\n"
                "  disabled = 0\n"
                "  index = wineventlog\n"
                "  [WinEventLog://System]\n"
                "  disabled = 0\n"
                "  index = wineventlog\n"
                "  [WinEventLog://Application]\n"
                "  disabled = 0\n"
                "  index = wineventlog\n"
                "  [WinEventLog://Microsoft-Windows-Sysmon/Operational]\n"
                "  disabled = 0\n"
                "  index = wineventlog\n"
                "  [WinEventLog://Microsoft-Windows-PowerShell/Operational]\n"
                "  disabled = 0\n"
                "  index = wineventlog"
            )
        if not has_forward_server:
            remediation_parts.append(
                "Configure outputs.conf:\n"
                "  [tcpout]\n"
                "  defaultGroup = default-autolb-group\n"
                "  [tcpout:default-autolb-group]\n"
                "  server = <indexer_host>:9997"
            )

        return CheckResult(
            check_id=check_id,
            title="{} - Configuration Gaps".format(title_base),
            severity="WARN",
            detail="Splunk UF is running but: {}".format("; ".join(issues)),
            remediation="\n\n".join(remediation_parts),
            category="forwarding",
            platform="windows",
            evidence=evidence,
        )

    return CheckResult(
        check_id=check_id,
        title="{} - Running and Configured".format(title_base),
        severity="PASS",
        detail="Splunk UF is running with {} WinEventLog input(s) and forwarding "
               "configured. Collecting: {}".format(
                   len(wineventlog_stanzas), ", ".join(wineventlog_stanzas)),
        remediation="No action required.",
        category="forwarding",
        platform="windows",
        evidence=evidence,
    )


def _check_winlogbeat():
    """WIN-SHIPPER-002: Winlogbeat detection and configuration."""
    check_id = "WIN-SHIPPER-002"
    title_base = "Winlogbeat"
    evidence = {}

    # Check service
    svc_exists, svc_running = _check_service_running("winlogbeat")
    evidence["service_exists"] = svc_exists
    evidence["service_running"] = svc_running

    # Check process
    process_running = check_process_running("winlogbeat.exe")
    evidence["process_running"] = process_running

    running = svc_running or process_running

    if not svc_exists and not process_running:
        # Check common installation paths
        winlogbeat_paths = [
            r"C:\Program Files\Winlogbeat",
            r"C:\Program Files\winlogbeat",
            r"C:\winlogbeat",
            r"C:\ProgramData\winlogbeat",
        ]
        installed = False
        install_path = None
        for path in winlogbeat_paths:
            if file_exists(path):
                installed = True
                install_path = path
                break

        evidence["installed"] = installed
        evidence["install_path"] = install_path

        if installed:
            return CheckResult(
                check_id=check_id,
                title="{} - Installed But Not Running".format(title_base),
                severity="WARN",
                detail="Winlogbeat found at {} but service is not running.".format(install_path),
                remediation="Install and start the service:\n"
                            '  cd "{}"\n'
                            "  .\\install-service-winlogbeat.ps1\n"
                            "  Start-Service winlogbeat".format(install_path),
                category="forwarding",
                platform="windows",
                evidence=evidence,
            )

        return CheckResult(
            check_id=check_id,
            title="{} - Not Detected".format(title_base),
            severity="INFO",
            detail="Winlogbeat is not installed.",
            remediation="If using Elastic Stack, install Winlogbeat:\n"
                        "  1. Download from https://www.elastic.co/downloads/beats/winlogbeat\n"
                        "  2. Extract to C:\\Program Files\\Winlogbeat\n"
                        "  3. Edit winlogbeat.yml\n"
                        "  4. .\\install-service-winlogbeat.ps1\n"
                        "  5. Start-Service winlogbeat",
            category="forwarding",
            platform="windows",
            evidence=evidence,
        )

    # Running - check configuration
    config_content = None
    config_path = None
    config_candidates = [
        r"C:\Program Files\Winlogbeat\winlogbeat.yml",
        r"C:\Program Files\winlogbeat\winlogbeat.yml",
        r"C:\winlogbeat\winlogbeat.yml",
        r"C:\ProgramData\winlogbeat\winlogbeat.yml",
        r"C:\ProgramData\Elastic\Beats\winlogbeat\winlogbeat.yml",
    ]

    for cpath in config_candidates:
        content = read_file_safe(cpath)
        if content:
            config_content = content
            config_path = cpath
            break

    evidence["config_path"] = config_path

    if not config_content:
        return CheckResult(
            check_id=check_id,
            title="{} - Running, Config Not Found".format(title_base),
            severity="WARN",
            detail="Winlogbeat is running but configuration file could not be located.",
            remediation="Verify configuration: winlogbeat.exe test config -c <path_to_config>",
            category="forwarding",
            platform="windows",
            evidence=evidence,
        )

    evidence["config_snippet"] = config_content[:1500]

    # Parse winlogbeat.yml for event log names
    event_logs = []
    for match in re.finditer(r'name:\s*(.+)', config_content):
        log_name = match.group(1).strip().strip("'\"")
        if log_name and not log_name.startswith("#"):
            event_logs.append(log_name)
    evidence["configured_event_logs"] = event_logs

    # Check output configuration
    has_output = bool(re.search(r'output\.(elasticsearch|logstash|kafka|redis)', config_content))
    evidence["has_output"] = has_output

    issues = []
    if not event_logs:
        issues.append("No event log names found in configuration")
    if not has_output:
        issues.append("No output configuration detected")

    if issues:
        return CheckResult(
            check_id=check_id,
            title="{} - Configuration Incomplete".format(title_base),
            severity="WARN",
            detail="Winlogbeat is running but: {}".format("; ".join(issues)),
            remediation="Edit {}:\n"
                        "  winlogbeat.event_logs:\n"
                        "    - name: Security\n"
                        "    - name: System\n"
                        "    - name: Application\n"
                        "    - name: Microsoft-Windows-Sysmon/Operational\n"
                        "    - name: Microsoft-Windows-PowerShell/Operational\n\n"
                        "  output.elasticsearch:\n"
                        "    hosts: [\"<elasticsearch_host>:9200\"]".format(
                            config_path or "winlogbeat.yml"),
            category="forwarding",
            platform="windows",
            evidence=evidence,
        )

    return CheckResult(
        check_id=check_id,
        title="{} - Running and Configured".format(title_base),
        severity="PASS",
        detail="Winlogbeat is running and collecting {} event log(s): {}".format(
            len(event_logs), ", ".join(event_logs[:10])),
        remediation="No action required.",
        category="forwarding",
        platform="windows",
        evidence=evidence,
    )


def _check_any_shipper():
    """WIN-SHIPPER-003: Any log shipper detected."""
    check_id = "WIN-SHIPPER-003"
    title_base = "Log Shipper Detection"
    evidence = {}

    shippers = {
        "SplunkForwarder": "Splunk Universal Forwarder",
        "winlogbeat": "Winlogbeat",
        "filebeat": "Filebeat",
        "elastic-agent": "Elastic Agent",
        "nxlog": "NXLog",
        "fluentd": "Fluentd",
        "fluent-bit": "Fluent Bit",
        "WinCollect": "IBM QRadar WinCollect",
        "ossec": "OSSEC/Wazuh",
        "wazuh-agent": "Wazuh Agent",
        "cribl": "Cribl Stream",
    }

    detected = []

    # Check services
    for svc_name, label in shippers.items():
        exists, running = _check_service_running(svc_name)
        if running:
            detected.append(label)
            evidence[svc_name] = "running"
        elif exists:
            evidence[svc_name] = "stopped"

    # Check processes as fallback
    process_names = {
        "splunkd.exe": "Splunk Universal Forwarder",
        "winlogbeat.exe": "Winlogbeat",
        "filebeat.exe": "Filebeat",
        "elastic-agent.exe": "Elastic Agent",
        "nxlog.exe": "NXLog",
        "ossec-agent.exe": "OSSEC/Wazuh",
        "wazuh-agent.exe": "Wazuh Agent",
    }
    for proc, label in process_names.items():
        if label not in detected and check_process_running(proc):
            detected.append(label)
            evidence[proc] = "running"

    # Check Windows Event Forwarding (WEF)
    rc, out, _ = safe_run(["wecutil", "gs"], timeout=10)
    if rc == 0 and out.strip():
        detected.append("Windows Event Forwarding (WEF)")
        evidence["wef_subscriptions"] = out.strip()[:500]

    evidence["detected_shippers"] = detected

    if detected:
        return CheckResult(
            check_id=check_id,
            title="{} - Found".format(title_base),
            severity="PASS",
            detail="Detected log shipper(s): {}".format(", ".join(detected)),
            remediation="No action required.",
            category="forwarding",
            platform="windows",
            evidence=evidence,
        )

    return CheckResult(
        check_id=check_id,
        title="{} - None Found".format(title_base),
        severity="FAIL",
        detail="No log shipping agent was detected. Windows event logs exist only locally "
               "and are vulnerable to tampering, deletion, or loss. Without centralized "
               "log collection, incident response and threat detection are severely limited.",
        remediation="Install a log shipper to forward Windows event logs to your SIEM:\n\n"
                    "Splunk UF:\n"
                    "  msiexec /i splunkforwarder.msi AGREETOLICENSE=yes /quiet\n\n"
                    "Winlogbeat:\n"
                    "  Download from elastic.co, configure winlogbeat.yml, install service\n\n"
                    "Windows Event Forwarding (built-in):\n"
                    "  wecutil cs subscription.xml\n"
                    "  (configure WEF on collector and source machines via GPO)",
        category="forwarding",
        platform="windows",
        evidence=evidence,
    )


def run_checks():
    """Return all Windows log shipper checks."""
    if not _is_windows():
        return []

    return [
        _check_splunk_forwarder(),
        _check_winlogbeat(),
        _check_any_shipper(),
    ]
