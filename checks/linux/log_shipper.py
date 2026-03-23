"""Log shipper detection checks: Splunk UF, Filebeat/Elastic Agent, any shipper."""

import glob
import re

from core.result import CheckResult
from core.platform_utils import (
    safe_run, read_file_safe, file_exists, is_elevated,
    get_package_manager, parse_config_file, get_file_mtime,
    check_process_running, get_linux_distro,
)


def _check_splunk_forwarder():
    """LINUX-SHIPPER-001: Splunk Universal Forwarder detection and config validation."""
    evidence = {}

    # Common Splunk UF paths
    splunk_paths = [
        "/opt/splunkforwarder",
        "/opt/splunk",
    ]

    splunk_home = None
    for path in splunk_paths:
        if file_exists(path):
            splunk_home = path
            break

    evidence["checked_paths"] = splunk_paths
    evidence["splunk_home"] = splunk_home

    # Check if splunkd process is running
    splunkd_running = check_process_running("splunkd")
    evidence["splunkd_running"] = splunkd_running

    if not splunk_home and not splunkd_running:
        return CheckResult(
            check_id="LINUX-SHIPPER-001",
            title="Splunk Universal Forwarder not detected",
            severity="INFO",
            detail=(
                "The Splunk Universal Forwarder (UF) is a lightweight agent that "
                "reads local log files and streams them to a Splunk indexer (your "
                "centralized search/analytics platform) in near real-time. No Splunk "
                "UF installation was found on this host. If Splunk is not your SIEM "
                "platform, this is expected and you can disregard this finding. If "
                "Splunk IS your SIEM, this host's logs are not reaching your "
                "analysts, meaning security events here are invisible to your SOC."
            ),
            remediation=(
                "If Splunk is your SIEM, install the Universal Forwarder. The UF is "
                "designed to be lightweight (minimal CPU/memory impact) and only "
                "forwards data -- it does not index or search locally.\n"
                "  wget -O splunkforwarder.deb 'https://download.splunk.com/...'\n"
                "  sudo dpkg -i splunkforwarder.deb\n"
                "  sudo /opt/splunkforwarder/bin/splunk start --accept-license\n\n"
                "After installation you will need to configure inputs.conf (which "
                "log files to monitor) and outputs.conf (which Splunk indexer to "
                "send data to). These are covered in subsequent checks."
            ),
            category="forwarding",
            platform="linux",
            evidence=evidence,
            mitre_techniques=["T1070.002"],
        )

    if not splunkd_running:
        return CheckResult(
            check_id="LINUX-SHIPPER-001",
            title="Splunk UF installed but not running",
            severity="WARN",
            detail=(
                "The Splunk Universal Forwarder is installed at {} but the splunkd "
                "process is not running. This means the agent is present on disk but "
                "is not actively reading or forwarding any log data. Logs generated "
                "while the forwarder is stopped will accumulate locally but will NOT "
                "reach your SIEM, creating a gap in your security visibility. If the "
                "forwarder has been stopped for a long time, you may also have a "
                "backlog of unsent data that could cause an ingestion spike when "
                "restarted."
            ).format(splunk_home),
            remediation=(
                "Start the Splunk forwarder and enable it to survive reboots:\n"
                "  sudo {}/bin/splunk start\n"
                "  sudo {}/bin/splunk enable boot-start\n\n"
                "The first command starts the splunkd daemon immediately. The second "
                "creates a systemd unit (or init script) so the forwarder starts "
                "automatically on boot. Without boot-start, a server reboot will "
                "silently stop log forwarding until someone manually restarts it."
            ).format(splunk_home, splunk_home),
            category="forwarding",
            platform="linux",
            evidence=evidence,
            mitre_techniques=["T1070.002"],
        )

    # Validate outputs.conf
    outputs_conf = None
    outputs_paths = []
    if splunk_home:
        outputs_paths = [
            "{}/etc/system/local/outputs.conf".format(splunk_home),
            "{}/etc/apps/search/local/outputs.conf".format(splunk_home),
        ]
        # Also check deployed apps
        outputs_paths.extend(glob.glob("{}/etc/apps/*/local/outputs.conf".format(splunk_home)))

    for opath in outputs_paths:
        content = read_file_safe(opath)
        if content:
            outputs_conf = content
            evidence["outputs_conf_path"] = opath
            break

    # Check for forwarding server
    has_forward_server = False
    if outputs_conf:
        evidence["outputs_conf_snippet"] = outputs_conf[:500]
        if re.search(r'server\s*=', outputs_conf):
            has_forward_server = True

    evidence["has_forward_server"] = has_forward_server

    # Check inputs.conf for monitored paths
    inputs_conf = None
    if splunk_home:
        inputs_paths = [
            "{}/etc/system/local/inputs.conf".format(splunk_home),
        ]
        inputs_paths.extend(glob.glob("{}/etc/apps/*/local/inputs.conf".format(splunk_home)))
        for ipath in inputs_paths:
            content = read_file_safe(ipath)
            if content:
                inputs_conf = content
                evidence["inputs_conf_path"] = ipath
                break

    monitored_paths = []
    if inputs_conf:
        for match in re.finditer(r'\[monitor://([^\]]+)\]', inputs_conf):
            monitored_paths.append(match.group(1))
    evidence["monitored_paths"] = monitored_paths

    issues = []
    if not has_forward_server:
        issues.append("No forwarding server configured in outputs.conf.")
    if not monitored_paths:
        issues.append("No monitored inputs found in inputs.conf.")

    if issues:
        return CheckResult(
            check_id="LINUX-SHIPPER-001",
            title="Splunk UF running but config incomplete",
            severity="WARN",
            detail=(
                "The Splunk Universal Forwarder is running but has configuration "
                "gaps: {}. The UF relies on two key config files: outputs.conf "
                "defines WHERE to send data (the IP/hostname and port of your Splunk "
                "indexer or heavy forwarder), and inputs.conf defines WHICH local "
                "log files to monitor using [monitor://] stanzas. Without a valid "
                "outputs.conf, collected data has nowhere to go. Without inputs.conf "
                "entries, the forwarder is running but not actually reading any logs. "
                "Either way, your SIEM is not receiving data from this host."
            ).format(" ".join(issues)),
            remediation=(
                "Configure outputs.conf to tell the forwarder where to send data. "
                "The 'server' setting specifies your indexer's address and receiving "
                "port (default 9997). The defaultGroup setting enables automatic "
                "load balancing if you have multiple indexers:\n"
                "  [tcpout]\n"
                "  defaultGroup = default-autolb-group\n"
                "  [tcpout:default-autolb-group]\n"
                "  server = your-splunk-indexer:9997\n\n"
                "Configure inputs.conf to specify which log files to monitor. Each "
                "[monitor://] stanza watches a file path. The 'sourcetype' setting "
                "is critical -- it tells Splunk's search-time parser how to interpret "
                "the log format (field extraction, timestamp parsing, line breaking). "
                "Using the wrong sourcetype means Splunk will misparse the data, "
                "resulting in broken fields and unusable search results:\n"
                "  [monitor:///var/log/audit/audit.log]\n"
                "  sourcetype = linux:audit\n"
                "  index = security"
            ),
            category="forwarding",
            platform="linux",
            evidence=evidence,
            mitre_techniques=["T1070.002"],
        )

    return CheckResult(
        check_id="LINUX-SHIPPER-001",
        title="Splunk UF running and configured",
        severity="PASS",
        detail=(
            "The Splunk Universal Forwarder is running with a valid forwarding "
            "server configured in outputs.conf, and is actively monitoring {} "
            "input path(s) defined in inputs.conf. This means local log data is "
            "being read and streamed to your Splunk indexer in near real-time, "
            "ensuring your SOC has visibility into this host's activity."
        ).format(len(monitored_paths)),
        remediation=(
            "No action required. For ongoing maintenance, periodically verify "
            "that the monitored paths in inputs.conf still match the log files "
            "your detection rules expect, especially after OS upgrades or "
            "application changes that may move log file locations."
        ),
        category="forwarding",
        platform="linux",
        evidence=evidence,
        mitre_techniques=["T1070.002"],
    )


def _check_filebeat_elastic():
    """LINUX-SHIPPER-002: Filebeat / Elastic Agent detection."""
    evidence = {}

    # Check Filebeat
    filebeat_running = check_process_running("filebeat")
    evidence["filebeat_running"] = filebeat_running

    rc, out, _ = safe_run(["systemctl", "is-active", "filebeat"])
    evidence["filebeat_systemctl"] = out.strip()
    if out.strip() == "active":
        filebeat_running = True

    # Check Elastic Agent
    elastic_agent_running = check_process_running("elastic-agent")
    evidence["elastic_agent_running"] = elastic_agent_running

    rc, out, _ = safe_run(["systemctl", "is-active", "elastic-agent"])
    evidence["elastic_agent_systemctl"] = out.strip()
    if out.strip() == "active":
        elastic_agent_running = True

    if not filebeat_running and not elastic_agent_running:
        # Check if installed but not running
        filebeat_installed = file_exists("/etc/filebeat/filebeat.yml") or \
                            file_exists("/usr/share/filebeat/bin/filebeat")
        elastic_installed = file_exists("/opt/Elastic/Agent/elastic-agent") or \
                           file_exists("/usr/share/elastic-agent/bin/elastic-agent")

        evidence["filebeat_installed"] = filebeat_installed
        evidence["elastic_agent_installed"] = elastic_installed

        if filebeat_installed or elastic_installed:
            product = "Filebeat" if filebeat_installed else "Elastic Agent"
            return CheckResult(
                check_id="LINUX-SHIPPER-002",
                title="{} installed but not running".format(product),
                severity="WARN",
                detail=(
                    "{agent} is a log shipping agent that reads local log files and "
                    "forwards them to an Elasticsearch cluster or Logstash pipeline "
                    "for centralized storage and analysis. {agent} is installed on "
                    "this host but the service is not active. While the agent is "
                    "stopped, no logs are being forwarded -- security events on this "
                    "host are invisible to your Elastic SIEM, and any detection rules "
                    "or dashboards that depend on this host's data will have gaps."
                ).format(agent=product),
                remediation=(
                    "Enable and start the service so it runs now and automatically "
                    "after reboots. The --now flag combines 'enable' (persist across "
                    "reboots) and 'start' (begin immediately) in a single command:\n"
                    "  sudo systemctl enable --now {}\n\n"
                    "After starting, check the agent's logs for connection errors to "
                    "your Elasticsearch cluster or Logstash endpoint."
                ).format("filebeat" if filebeat_installed else "elastic-agent"),
                category="forwarding",
                platform="linux",
                evidence=evidence,
                mitre_techniques=["T1070.002"],
            )

        return CheckResult(
            check_id="LINUX-SHIPPER-002",
            title="Filebeat/Elastic Agent not detected",
            severity="INFO",
            detail=(
                "Filebeat and Elastic Agent are log shipping agents for the Elastic "
                "Stack ecosystem. Filebeat is a lightweight shipper that reads log "
                "files and forwards them to Elasticsearch or Logstash. Elastic Agent "
                "is a unified agent that bundles Filebeat's functionality with "
                "additional capabilities like endpoint security and fleet management. "
                "Neither agent was found on this host. If you use the Elastic Stack "
                "(Elasticsearch, Kibana, Elastic SIEM) as your log analytics "
                "platform, this host's logs are not reaching it."
            ),
            remediation=(
                "If using the Elastic Stack as your SIEM, install Filebeat. Filebeat "
                "includes pre-built 'modules' for common log sources (system logs, "
                "audit logs, nginx, etc.). Each module comes with parsing rules, "
                "field mappings, and optional Kibana dashboards -- so you get "
                "structured, searchable data without writing custom parsers:\n"
                "  curl -L -O https://artifacts.elastic.co/downloads/beats/filebeat/filebeat-<version>-amd64.deb\n"
                "  sudo dpkg -i filebeat-*.deb\n"
                "  sudo filebeat modules enable system audit  # Enable system and audit log modules\n"
                "  sudo filebeat setup  # Load index templates, dashboards, and ML jobs\n"
                "  sudo systemctl enable --now filebeat\n\n"
                "The 'setup' command creates Elasticsearch index templates (which "
                "define field types for efficient searching) and imports Kibana "
                "dashboards for the enabled modules."
            ),
            category="forwarding",
            platform="linux",
            evidence=evidence,
            mitre_techniques=["T1070.002"],
        )

    # Running -- validate config
    agent = "filebeat" if filebeat_running else "elastic-agent"
    config_path = None
    config_content = None

    if filebeat_running:
        for path in ["/etc/filebeat/filebeat.yml", "/usr/share/filebeat/filebeat.yml"]:
            content = read_file_safe(path)
            if content:
                config_path = path
                config_content = content
                break
    else:
        for path in ["/opt/Elastic/Agent/elastic-agent.yml",
                     "/etc/elastic-agent/elastic-agent.yml"]:
            content = read_file_safe(path)
            if content:
                config_path = path
                config_content = content
                break

    evidence["config_path"] = config_path
    has_output = False
    if config_content:
        evidence["config_snippet"] = config_content[:300]
        # Check for output configuration
        if re.search(r'output\.(elasticsearch|logstash|kafka|redis)', config_content):
            has_output = True
        # For elastic-agent, check fleet enrollment
        if re.search(r'fleet\.|url:', config_content):
            has_output = True

    evidence["has_output"] = has_output

    if not has_output and config_content:
        return CheckResult(
            check_id="LINUX-SHIPPER-002",
            title="{} running but output not confirmed".format(agent),
            severity="WARN",
            detail=(
                "{agent} is running but no output destination was detected in its "
                "configuration file. The output section of the config defines where "
                "collected logs are sent -- typically an Elasticsearch cluster "
                "(direct ingest), a Logstash pipeline (for additional parsing/ "
                "enrichment before indexing), or a message queue like Kafka (for "
                "buffering). Without a valid output, {agent} may be reading log "
                "files but the data is going nowhere, effectively the same as not "
                "running a shipper at all."
            ).format(agent=agent),
            remediation=(
                "Configure an output destination in {config}. The most common "
                "option is output.elasticsearch, which sends data directly to your "
                "Elasticsearch cluster. Use output.logstash if you need to apply "
                "additional parsing, filtering, or enrichment before indexing:\n"
                "  output.elasticsearch:\n"
                "    hosts: [\"your-es-server:9200\"]\n\n"
                "For Elastic Agent managed via Fleet, enroll the agent with your "
                "Fleet server instead -- Fleet centrally manages the agent's config "
                "including outputs, so you would not edit the YAML directly."
            ).format(config=config_path or "/etc/{}/{}.yml".format(agent, agent)),
            category="forwarding",
            platform="linux",
            evidence=evidence,
            mitre_techniques=["T1070.002"],
        )

    return CheckResult(
        check_id="LINUX-SHIPPER-002",
        title="{} running and configured".format(agent.capitalize()),
        severity="PASS",
        detail=(
            "{agent} is active and has a valid output destination configured. "
            "This means local log data is being collected and forwarded to your "
            "Elastic Stack for centralized analysis, search, and alerting. Your "
            "SOC has visibility into this host through the Elastic SIEM."
        ).format(agent=agent.capitalize()),
        remediation=(
            "No action required. For best coverage, verify that the appropriate "
            "Filebeat modules are enabled (e.g., 'system' for syslog/auth, "
            "'auditd' for audit logs). Each module includes pre-built parsing "
            "rules and field mappings that ensure your data is correctly "
            "structured for Elastic SIEM detection rules."
        ),
        category="forwarding",
        platform="linux",
        evidence=evidence,
        mitre_techniques=["T1070.002"],
    )


def _check_shipper_connection_health():
    """LINUX-SHIPPER-004: Shipper connection health."""
    evidence = {}

    # Detect which shipper is running
    splunkd_running = check_process_running("splunkd")
    filebeat_running = check_process_running("filebeat")
    nxlog_running = check_process_running("nxlog")
    evidence["splunkd_running"] = splunkd_running
    evidence["filebeat_running"] = filebeat_running
    evidence["nxlog_running"] = nxlog_running

    if not splunkd_running and not filebeat_running and not nxlog_running:
        # Also check systemctl
        for svc, key in [("filebeat", "filebeat_running"), ("nxlog", "nxlog_running")]:
            rc, out, _ = safe_run(["systemctl", "is-active", svc])
            if out.strip() == "active":
                if svc == "filebeat":
                    filebeat_running = True
                else:
                    nxlog_running = True
                evidence[key] = True

    if not splunkd_running and not filebeat_running and not nxlog_running:
        return CheckResult(
            check_id="LINUX-SHIPPER-004",
            title="No shipper detected for connection health check",
            severity="SKIP",
            detail=(
                "No Splunk Universal Forwarder, Filebeat, or NXLog process was "
                "detected on this host, so there is no shipper connection health "
                "to assess."
            ),
            remediation="See LINUX-SHIPPER-003 for shipper deployment guidance.",
            category="forwarding",
            platform="linux",
            evidence=evidence,
            mitre_techniques=["T1562.001"],
        )

    error_patterns_found = []
    shipper_name = None

    if splunkd_running:
        shipper_name = "Splunk UF"
        splunk_log_paths = [
            "/opt/splunkforwarder/var/log/splunk/splunkd.log",
            "/opt/splunk/var/log/splunk/splunkd.log",
        ]
        splunk_errors = [
            "Connection refused",
            "Failed to connect",
            "Unable to connect",
            "Connection timed out",
            "ERROR",
        ]
        for log_path in splunk_log_paths:
            content = read_file_safe(log_path)
            if content:
                evidence["splunk_log_path"] = log_path
                # Only check last 50 lines
                lines = content.splitlines()[-50:]
                for line in lines:
                    for pattern in splunk_errors:
                        if pattern.lower() in line.lower():
                            error_patterns_found.append(line.strip())
                            break
                break

    elif filebeat_running:
        shipper_name = "Filebeat"
        filebeat_errors = ["connection refused", "error", "failed to publish"]

        # Try journalctl first
        rc, out, _ = safe_run(
            ["journalctl", "-u", "filebeat", "--since", "1 hour ago",
             "--no-pager", "-q"],
            timeout=15,
        )
        if rc == 0 and out.strip():
            evidence["filebeat_log_source"] = "journalctl"
            lines = out.strip().splitlines()[-50:]
            for line in lines:
                for pattern in filebeat_errors:
                    if pattern in line.lower():
                        error_patterns_found.append(line.strip())
                        break
        else:
            # Fall back to log file
            log_path = "/var/log/filebeat/filebeat"
            content = read_file_safe(log_path)
            if content:
                evidence["filebeat_log_source"] = log_path
                lines = content.splitlines()[-50:]
                for line in lines:
                    for pattern in filebeat_errors:
                        if pattern in line.lower():
                            error_patterns_found.append(line.strip())
                            break

    elif nxlog_running:
        shipper_name = "NXLog"
        nxlog_errors = ["error", "connection refused", "failed to connect",
                        "could not connect", "connection timed out", "couldn't open"]
        nxlog_log_paths = [
            "/var/log/nxlog/nxlog.log",
            "/opt/nxlog/var/log/nxlog/nxlog.log",
        ]
        # Try journalctl first
        rc, out, _ = safe_run(
            ["journalctl", "-u", "nxlog", "--since", "1 hour ago",
             "--no-pager", "-q"],
            timeout=15,
        )
        if rc == 0 and out.strip():
            evidence["nxlog_log_source"] = "journalctl"
            lines = out.strip().splitlines()[-50:]
            for line in lines:
                for pattern in nxlog_errors:
                    if pattern in line.lower():
                        error_patterns_found.append(line.strip())
                        break
        else:
            for log_path in nxlog_log_paths:
                content = read_file_safe(log_path)
                if content:
                    evidence["nxlog_log_source"] = log_path
                    lines = content.splitlines()[-50:]
                    for line in lines:
                        for pattern in nxlog_errors:
                            if pattern in line.lower():
                                error_patterns_found.append(line.strip())
                                break
                    break

    evidence["shipper_name"] = shipper_name
    evidence["error_count"] = len(error_patterns_found)
    evidence["error_samples"] = error_patterns_found[:5]

    if error_patterns_found:
        return CheckResult(
            check_id="LINUX-SHIPPER-004",
            title="{} connection errors detected".format(shipper_name),
            severity="WARN",
            detail=(
                "A log shipper that is installed and configured but failing to connect "
                "to its destination creates the most dangerous type of logging gap -- "
                "a false sense of security. The configuration looks correct, the "
                "service is running, but events are silently accumulating in local "
                "queues (or being dropped if queues are full). This check examines "
                "the shipper's own operational logs for signs of delivery failure. "
                "{} error pattern(s) were found in the last 50 lines of {} logs, "
                "indicating the shipper is having trouble delivering events to its "
                "destination."
            ).format(len(error_patterns_found), shipper_name),
            remediation=(
                "Investigate the {} connection errors. Common causes:\n"
                "  - Destination server is down or unreachable (check network/firewall)\n"
                "  - Destination port is wrong or blocked\n"
                "  - TLS certificate mismatch or expiration\n"
                "  - Authentication token expired or revoked\n"
                "Check the shipper logs for specific error messages:\n"
                "  Sample errors: {}"
            ).format(shipper_name, "; ".join(error_patterns_found[:3])),
            category="forwarding",
            platform="linux",
            evidence=evidence,
            mitre_techniques=["T1562.001"],
        )

    return CheckResult(
        check_id="LINUX-SHIPPER-004",
        title="{} connection healthy".format(shipper_name),
        severity="PASS",
        detail=(
            "A log shipper that is installed and configured but failing to connect "
            "to its destination creates the most dangerous type of logging gap -- "
            "a false sense of security. The configuration looks correct, the "
            "service is running, but events are silently accumulating in local "
            "queues (or being dropped if queues are full). This check examines "
            "the shipper's own operational logs for signs of delivery failure. "
            "No error patterns were found in the recent {} logs, indicating "
            "the shipper is successfully delivering events."
        ).format(shipper_name),
        remediation="No action required.",
        category="forwarding",
        platform="linux",
        evidence=evidence,
        mitre_techniques=["T1562.001"],
    )


def _check_critical_log_input_coverage():
    """LINUX-SHIPPER-005: Critical log input coverage."""
    evidence = {}

    splunkd_running = check_process_running("splunkd")
    filebeat_running = check_process_running("filebeat")
    nxlog_running = check_process_running("nxlog")

    if not splunkd_running and not filebeat_running and not nxlog_running:
        for svc, key in [("filebeat", "filebeat"), ("nxlog", "nxlog")]:
            rc, out, _ = safe_run(["systemctl", "is-active", svc])
            if out.strip() == "active":
                if svc == "filebeat":
                    filebeat_running = True
                else:
                    nxlog_running = True

    if not splunkd_running and not filebeat_running and not nxlog_running:
        return CheckResult(
            check_id="LINUX-SHIPPER-005",
            title="No shipper detected for input coverage check",
            severity="SKIP",
            detail=(
                "No Splunk Universal Forwarder, Filebeat, or NXLog process was "
                "detected on this host, so there is no shipper input configuration "
                "to assess."
            ),
            remediation="See LINUX-SHIPPER-003 for shipper deployment guidance.",
            category="forwarding",
            platform="linux",
            evidence=evidence,
            mitre_techniques=["T1070.002"],
        )

    # Determine which auth log this distro uses
    distro = get_linux_distro()
    distro_id = distro.get("ID", "").lower()
    evidence["distro_id"] = distro_id

    if distro_id in ("rhel", "centos", "fedora", "rocky", "alma", "ol", "amzn"):
        auth_log_path = "/var/log/secure"
    else:
        auth_log_path = "/var/log/auth.log"

    critical_paths = {
        "/var/log/audit/audit.log": "auditd kernel-level audit records",
        auth_log_path: "authentication events (SSH, sudo, PAM)",
    }
    evidence["critical_paths"] = list(critical_paths.keys())

    missing_paths = []
    covered_paths = []

    if splunkd_running:
        evidence["shipper"] = "Splunk UF"
        # Parse all inputs.conf files
        all_monitored = []
        splunk_homes = ["/opt/splunkforwarder", "/opt/splunk"]
        for shome in splunk_homes:
            if not file_exists(shome):
                continue
            inputs_files = ["{}/etc/system/local/inputs.conf".format(shome)]
            inputs_files.extend(
                glob.glob("{}/etc/apps/*/local/inputs.conf".format(shome))
            )
            for ipath in inputs_files:
                content = read_file_safe(ipath)
                if content:
                    for match in re.finditer(r'\[monitor://([^\]]+)\]', content):
                        all_monitored.append(match.group(1))

        evidence["monitored_inputs"] = all_monitored

        for cpath, desc in critical_paths.items():
            found = False
            for m in all_monitored:
                if cpath in m or m in cpath:
                    found = True
                    break
            if found:
                covered_paths.append(cpath)
            else:
                missing_paths.append(cpath)

    elif filebeat_running:
        evidence["shipper"] = "Filebeat"
        config_content = None
        for path in ["/etc/filebeat/filebeat.yml", "/usr/share/filebeat/filebeat.yml"]:
            content = read_file_safe(path)
            if content:
                config_content = content
                evidence["config_path"] = path
                break

        if config_content:
            config_lower = config_content.lower()
            # Check for auditd coverage
            audit_covered = (
                "auditd" in config_lower
                or "audit.log" in config_lower
                or "/var/log/audit" in config_content
            )
            # Check for auth coverage
            auth_covered = (
                auth_log_path in config_content
                or "auth.log" in config_lower
                or "/var/log/secure" in config_content
                or re.search(r'module.*system', config_lower) is not None
            )

            if audit_covered:
                covered_paths.append("/var/log/audit/audit.log")
            else:
                missing_paths.append("/var/log/audit/audit.log")

            if auth_covered:
                covered_paths.append(auth_log_path)
            else:
                missing_paths.append(auth_log_path)
        else:
            # Cannot read config, mark all as unknown
            missing_paths = list(critical_paths.keys())

    elif nxlog_running:
        evidence["shipper"] = "NXLog"
        _, config_content = _find_nxlog_config()
        if config_content:
            inputs, _, _ = _parse_nxlog_blocks(config_content)
            nxlog_files = []
            for inp in inputs:
                for line in inp["lines"]:
                    file_match = re.match(r'File\s+["\']?([^"\']+)["\']?', line, re.IGNORECASE)
                    if file_match:
                        nxlog_files.append(file_match.group(1))
            evidence["monitored_inputs"] = nxlog_files

            for cpath, desc in critical_paths.items():
                found = False
                for f in nxlog_files:
                    if cpath in f or f in cpath:
                        found = True
                        break
                if found:
                    covered_paths.append(cpath)
                else:
                    missing_paths.append(cpath)
        else:
            missing_paths = list(critical_paths.keys())

    evidence["covered_paths"] = covered_paths
    evidence["missing_paths"] = missing_paths

    if missing_paths:
        missing_detail = ", ".join(missing_paths)
        return CheckResult(
            check_id="LINUX-SHIPPER-005",
            title="Critical log sources not in shipper inputs",
            severity="WARN",
            detail=(
                "Even with a properly functioning shipper, the most common "
                "misconfiguration is missing critical log sources from the input "
                "configuration. The shipper only forwards what it is told to monitor. "
                "If /var/log/audit/audit.log is not in Splunk's inputs.conf or "
                "Filebeat's configuration, all auditd telemetry stays on the host. "
                "Similarly, if {} is missing, authentication events never reach your "
                "SIEM. Missing inputs on this host: {}."
            ).format(auth_log_path, missing_detail),
            remediation=(
                "Add the missing critical log sources to your shipper configuration. "
                "These are the minimum log sources every Linux host should forward:\n"
                "  - /var/log/audit/audit.log (auditd records)\n"
                "  - {} (authentication events)\n\n"
                "For Splunk UF, add [monitor://] stanzas to inputs.conf.\n"
                "For Filebeat, enable the 'auditd' and 'system' modules or add "
                "manual paths to filebeat.yml.\n"
                "For NXLog, add <Input> blocks with Module im_file and File "
                "directives in nxlog.conf."
            ).format(auth_log_path),
            category="forwarding",
            platform="linux",
            evidence=evidence,
            mitre_techniques=["T1070.002"],
        )

    return CheckResult(
        check_id="LINUX-SHIPPER-005",
        title="Critical log sources covered by shipper",
        severity="PASS",
        detail=(
            "Even with a properly functioning shipper, the most common "
            "misconfiguration is missing critical log sources from the input "
            "configuration. The shipper only forwards what it is told to monitor. "
            "If /var/log/audit/audit.log is not in Splunk's inputs.conf or "
            "Filebeat's configuration, all auditd telemetry stays on the host. "
            "Similarly, if {} is missing, authentication events never reach your "
            "SIEM. All critical log paths are present in the shipper's input "
            "configuration: {}."
        ).format(auth_log_path, ", ".join(covered_paths)),
        remediation="No action required.",
        category="forwarding",
        platform="linux",
        evidence=evidence,
        mitre_techniques=["T1070.002"],
    )


def _check_any_shipper():
    """LINUX-SHIPPER-003: Any shipper detected at all?"""
    evidence = {}

    shippers = {
        "splunkd": "Splunk Universal Forwarder",
        "filebeat": "Filebeat",
        "elastic-agent": "Elastic Agent",
        "fluentd": "Fluentd",
        "fluent-bit": "Fluent Bit",
        "td-agent": "Treasure Data Agent (Fluentd)",
        "nxlog": "NXLog",
        "rsyslogd": "rsyslog (as forwarder)",
        "syslog-ng": "syslog-ng (as forwarder)",
        "vector": "Vector",
        "logstash": "Logstash",
        "cribl": "Cribl Stream",
    }

    detected = []
    for process_name, label in shippers.items():
        if check_process_running(process_name):
            detected.append(label)

    # Also check systemd service names
    extra_services = ["filebeat", "elastic-agent", "fluentd", "fluent-bit",
                      "td-agent", "nxlog", "vector"]
    for svc in extra_services:
        rc, out, _ = safe_run(["systemctl", "is-active", svc])
        if rc == 0 and out.strip() == "active":
            label = shippers.get(svc, svc)
            if label not in detected:
                detected.append(label)

    evidence["detected_shippers"] = detected

    if detected:
        return CheckResult(
            check_id="LINUX-SHIPPER-003",
            title="Log shipper(s) detected",
            severity="PASS",
            detail=(
                "A log shipper is an agent that reads local log files and forwards "
                "them to a centralized SIEM or log management platform in near "
                "real-time. Detected log shipper(s) on this host: {}. This means "
                "local security events (authentication attempts, process execution, "
                "audit records) are being forwarded off-host, where they are "
                "protected from local tampering and available for correlation with "
                "events from other systems."
            ).format(", ".join(detected)),
            remediation=(
                "No action required. The presence of a running log shipper is the "
                "foundational requirement for centralized security monitoring. "
                "Verify that the shipper is configured to collect security-relevant "
                "logs (auth.log, audit.log, syslog at minimum) and that data is "
                "actually arriving in your SIEM by searching for recent events "
                "from this host."
            ),
            category="forwarding",
            platform="linux",
            evidence=evidence,
            mitre_techniques=["T1070.002"],
        )

    return CheckResult(
        check_id="LINUX-SHIPPER-003",
        title="No log shipper detected",
        severity="FAIL",
        detail=(
            "A log shipper is an agent that reads local log files and forwards "
            "them to a centralized SIEM or log management platform in near "
            "real-time. No log shipping agent of any kind was detected on this "
            "host. This is the single most critical finding in this audit because "
            "it means all other logging configuration is effectively pointless -- "
            "even perfectly configured audit rules and authentication logging only "
            "produce data that sits on local disk. If this host is compromised, "
            "an attacker with root access can delete or modify every log file, "
            "destroying all evidence of their activity. Centralized log forwarding "
            "is the only defense against log tampering because once data reaches "
            "your SIEM, the attacker cannot reach it (without also compromising "
            "the SIEM). Without a shipper, your SOC has zero visibility into "
            "this host."
        ),
        remediation=(
            "Install a log shipper to forward logs to your SIEM. Choose the agent "
            "that matches your SIEM platform:\n"
            "  - Splunk UF (for Splunk): /opt/splunkforwarder/bin/splunk start\n"
            "  - Filebeat (for Elastic Stack): sudo apt-get install filebeat\n"
            "  - Fluent Bit (lightweight, vendor-neutral): sudo apt-get install fluent-bit\n"
            "  - Vector (high-performance, vendor-neutral): curl --proto '=https' -fLsS https://sh.vector.dev | bash\n\n"
            "At minimum, configure the shipper to forward these security-critical "
            "log sources:\n"
            "  - /var/log/auth.log (or /var/log/secure on RHEL) -- SSH logins, "
            "sudo usage, PAM authentication events\n"
            "  - /var/log/audit/audit.log -- auditd kernel-level audit records "
            "(syscalls, file access, process execution)\n"
            "  - /var/log/syslog (or /var/log/messages) -- general system events "
            "including service starts/stops and cron execution\n\n"
            "Trade-off note: log shippers consume some CPU and network bandwidth. "
            "Fluent Bit and Vector are the most resource-efficient options if "
            "overhead is a concern on resource-constrained hosts."
        ),
        category="forwarding",
        platform="linux",
        evidence=evidence,
        mitre_techniques=["T1070.002"],
    )


def _find_nxlog_config():
    """Locate and read NXLog configuration file."""
    config_paths = [
        "/etc/nxlog/nxlog.conf",
        "/opt/nxlog/etc/nxlog.conf",
        "/etc/nxlog.conf",
    ]
    # Also check conf.d drop-ins
    dropin_dirs = [
        "/etc/nxlog/conf.d/",
        "/opt/nxlog/etc/conf.d/",
    ]
    combined = ""
    config_found = None
    for path in config_paths:
        content = read_file_safe(path)
        if content:
            config_found = path
            combined += content + "\n"
            break
    for ddir in dropin_dirs:
        for f in sorted(glob.glob("{}*.conf".format(ddir))):
            content = read_file_safe(f)
            if content:
                combined += content + "\n"
    return config_found, combined


def _parse_nxlog_blocks(content):
    """Parse NXLog config into Input, Output, and Route blocks."""
    inputs = []
    outputs = []
    routes = []
    current_block = None
    current_type = None
    current_name = None

    for line in content.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        # Block start
        input_match = re.match(r'<Input\s+(\S+)>', stripped, re.IGNORECASE)
        output_match = re.match(r'<Output\s+(\S+)>', stripped, re.IGNORECASE)
        route_match = re.match(r'<Route\s+(\S+)>', stripped, re.IGNORECASE)

        if input_match:
            current_type = "input"
            current_name = input_match.group(1)
            current_block = {"name": current_name, "lines": []}
        elif output_match:
            current_type = "output"
            current_name = output_match.group(1)
            current_block = {"name": current_name, "lines": []}
        elif route_match:
            current_type = "route"
            current_name = route_match.group(1)
            current_block = {"name": current_name, "lines": []}
        elif re.match(r'</(?:Input|Output|Route)>', stripped, re.IGNORECASE):
            if current_block:
                if current_type == "input":
                    inputs.append(current_block)
                elif current_type == "output":
                    outputs.append(current_block)
                elif current_type == "route":
                    routes.append(current_block)
            current_block = None
            current_type = None
        elif current_block is not None:
            current_block["lines"].append(stripped)

    return inputs, outputs, routes


def _check_nxlog():
    """LINUX-SHIPPER-006: NXLog detection and config validation."""
    evidence = {}

    # Check if NXLog is running
    nxlog_running = check_process_running("nxlog")
    evidence["nxlog_running"] = nxlog_running

    # Check systemd service
    rc, out, _ = safe_run(["systemctl", "is-active", "nxlog"])
    nxlog_service_active = (rc == 0 and out.strip() == "active")
    evidence["nxlog_service"] = out.strip()

    # Check for binary
    rc_bin, out_bin, _ = safe_run(["which", "nxlog"])
    nxlog_installed = rc_bin == 0
    if not nxlog_installed:
        for bpath in ["/usr/bin/nxlog", "/opt/nxlog/bin/nxlog"]:
            if file_exists(bpath):
                nxlog_installed = True
                out_bin = bpath
                break
    evidence["nxlog_binary"] = out_bin.strip() if nxlog_installed else "not found"

    # Find config
    config_path, config_content = _find_nxlog_config()
    evidence["config_path"] = config_path

    if not nxlog_installed and not nxlog_running and not nxlog_service_active:
        return CheckResult(
            check_id="LINUX-SHIPPER-006",
            title="NXLog not detected",
            severity="INFO",
            detail=(
                "NXLog is a cross-platform log collection and forwarding agent that "
                "can read from files, the kernel, Windows Event Log, and many other "
                "sources, then transform and forward events to a SIEM. It supports "
                "both the community edition (CE, open source) and enterprise edition "
                "(EE, commercial with additional modules like im_msvistalog for "
                "Windows and om_elasticsearch). No NXLog installation was found on "
                "this host."
            ),
            remediation="If NXLog is not your chosen shipper, this finding can be ignored.",
            category="forwarding",
            platform="linux",
            evidence=evidence,
            mitre_techniques=["T1070.002"],
        )

    # NXLog is installed — check if running
    if not nxlog_running and not nxlog_service_active:
        return CheckResult(
            check_id="LINUX-SHIPPER-006",
            title="NXLog installed but not running",
            severity="FAIL",
            detail=(
                "NXLog is a log collection and forwarding agent. The binary was "
                "found at {} but the service is not running (systemd reports '{}'). "
                "While NXLog is stopped, no log events are being collected or "
                "forwarded by this agent. If NXLog is your primary shipper, this "
                "means logs are accumulating locally but not reaching your SIEM."
            ).format(evidence["nxlog_binary"], evidence["nxlog_service"]),
            remediation=(
                "Start and enable the NXLog service:\n"
                "  sudo systemctl start nxlog\n"
                "  sudo systemctl enable nxlog\n\n"
                "If the service fails to start, check the NXLog log for errors:\n"
                "  sudo journalctl -u nxlog --no-pager -n 50\n"
                "  cat /var/log/nxlog/nxlog.log"
            ),
            category="forwarding",
            platform="linux",
            evidence=evidence,
            mitre_techniques=["T1070.002"],
        )

    # NXLog is running — validate config
    if not config_content:
        return CheckResult(
            check_id="LINUX-SHIPPER-006",
            title="NXLog running but config not found",
            severity="WARN",
            detail=(
                "NXLog is running but no configuration file was found at the "
                "standard locations (/etc/nxlog/nxlog.conf or "
                "/opt/nxlog/etc/nxlog.conf). Cannot validate input sources, "
                "output destinations, or routing configuration."
            ),
            remediation=(
                "Verify the NXLog config location by checking the service unit:\n"
                "  systemctl cat nxlog | grep ExecStart\n"
                "The -c flag shows which config file NXLog is using."
            ),
            category="forwarding",
            platform="linux",
            evidence=evidence,
            mitre_techniques=["T1070.002"],
        )

    # Parse config blocks
    inputs, outputs, routes = _parse_nxlog_blocks(config_content)
    evidence["input_count"] = len(inputs)
    evidence["output_count"] = len(outputs)
    evidence["route_count"] = len(routes)

    issues = []

    # Check for input modules
    input_modules = []
    input_files = []
    for inp in inputs:
        for line in inp["lines"]:
            mod_match = re.match(r'Module\s+(\S+)', line, re.IGNORECASE)
            if mod_match:
                input_modules.append(mod_match.group(1))
            file_match = re.match(r'File\s+["\']?([^"\']+)["\']?', line, re.IGNORECASE)
            if file_match:
                input_files.append(file_match.group(1))
    evidence["input_modules"] = input_modules
    evidence["input_files"] = input_files

    if not inputs:
        issues.append("No <Input> blocks defined -- NXLog is not reading any log sources")

    # Check for output modules
    output_modules = []
    output_destinations = []
    has_network_output = False
    for outp in outputs:
        for line in outp["lines"]:
            mod_match = re.match(r'Module\s+(\S+)', line, re.IGNORECASE)
            if mod_match:
                mod = mod_match.group(1)
                output_modules.append(mod)
                if mod in ("om_tcp", "om_udp", "om_ssl", "om_tls",
                           "om_http", "om_elasticsearch", "om_kafka",
                           "om_batchcompress"):
                    has_network_output = True
            host_match = re.match(r'Host\s+(\S+)', line, re.IGNORECASE)
            if host_match:
                output_destinations.append(host_match.group(1))
    evidence["output_modules"] = output_modules
    evidence["output_destinations"] = output_destinations

    if not outputs:
        issues.append("No <Output> blocks defined -- NXLog has nowhere to send events")
    elif not has_network_output:
        local_only = [m for m in output_modules if m == "om_file"]
        if local_only and len(local_only) == len(output_modules):
            issues.append(
                "All outputs use om_file (local file) -- events are not being "
                "forwarded off-host to a SIEM"
            )

    # Check for routes
    if not routes and inputs and outputs:
        issues.append(
            "No <Route> blocks defined -- inputs and outputs exist but are not "
            "connected, so no events are flowing"
        )

    # Check for TLS on outputs
    has_tls = any(m in ("om_ssl", "om_tls") for m in output_modules)
    has_plain = any(m in ("om_tcp", "om_udp") for m in output_modules)
    if has_plain and not has_tls:
        issues.append(
            "Output uses om_tcp or om_udp (unencrypted) -- log data including "
            "usernames and commands is transmitted in cleartext"
        )
    evidence["has_tls"] = has_tls

    # Check for critical log file inputs
    audit_covered = any(
        "audit" in f.lower() for f in input_files
    )
    auth_covered = any(
        "auth.log" in f or "secure" in f for f in input_files
    )
    evidence["audit_log_covered"] = audit_covered
    evidence["auth_log_covered"] = auth_covered

    if not audit_covered and input_files:
        issues.append(
            "/var/log/audit/audit.log not found in any <Input> File directive -- "
            "auditd telemetry is not being forwarded"
        )
    if not auth_covered and input_files:
        issues.append(
            "Neither /var/log/auth.log nor /var/log/secure found in any <Input> "
            "File directive -- authentication events are not being forwarded"
        )

    if issues:
        severity = "FAIL" if any("nowhere to send" in i or "not connected" in i
                                 or "not reading" in i for i in issues) else "WARN"
        return CheckResult(
            check_id="LINUX-SHIPPER-006",
            title="NXLog running with configuration issues",
            severity=severity,
            detail=(
                "NXLog is a cross-platform log collection and forwarding agent. It "
                "is running on this host but has configuration issues:\n"
                + "\n".join("  - {}".format(i) for i in issues)
            ),
            remediation=(
                "Edit the NXLog configuration at {}. A minimal working config "
                "needs three parts:\n\n"
                "1. <Input> block with Module im_file and File directives pointing "
                "to your log sources\n"
                "2. <Output> block with a network module (om_tcp, om_ssl) and Host/Port\n"
                "3. <Route> block connecting the input to the output\n\n"
                "Example for forwarding audit and auth logs over TLS:\n"
                "  <Input audit_log>\n"
                "    Module  im_file\n"
                "    File    '/var/log/audit/audit.log'\n"
                "  </Input>\n"
                "  <Input auth_log>\n"
                "    Module  im_file\n"
                "    File    '/var/log/auth.log'\n"
                "  </Input>\n"
                "  <Output siem>\n"
                "    Module  om_ssl\n"
                "    Host    your-siem-server\n"
                "    Port    6514\n"
                "    CAFile  /etc/nxlog/ca.pem\n"
                "  </Output>\n"
                "  <Route default>\n"
                "    Path    audit_log, auth_log => siem\n"
                "  </Route>\n\n"
                "Then restart: sudo systemctl restart nxlog"
            ).format(config_path or "/etc/nxlog/nxlog.conf"),
            category="forwarding",
            platform="linux",
            evidence=evidence,
            mitre_techniques=["T1070.002"],
        )

    return CheckResult(
        check_id="LINUX-SHIPPER-006",
        title="NXLog running and configured",
        severity="PASS",
        detail=(
            "NXLog is a cross-platform log collection and forwarding agent. It "
            "is running on this host with {} input(s), {} output(s), and {} "
            "route(s) configured. {}{}{}".format(
                len(inputs), len(outputs), len(routes),
                "TLS encryption is enabled on output. " if has_tls else "",
                "Audit log is being collected. " if audit_covered else "",
                "Auth log is being collected." if auth_covered else "",
            )
        ),
        remediation="No action required.",
        category="forwarding",
        platform="linux",
        evidence=evidence,
        mitre_techniques=["T1070.002"],
    )


def run_checks():
    """Return all log shipper checks."""
    return [
        _check_splunk_forwarder(),
        _check_filebeat_elastic(),
        _check_nxlog(),
        _check_any_shipper(),
        _check_shipper_connection_health(),
        _check_critical_log_input_coverage(),
    ]
