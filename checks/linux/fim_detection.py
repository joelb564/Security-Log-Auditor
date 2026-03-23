"""File Integrity Monitoring (FIM) detection checks."""

from core.result import CheckResult
from core.platform_utils import (
    safe_run, file_exists, check_process_running,
)


def _check_fim_presence():
    """LINUX-FIM-001: File Integrity Monitoring presence."""
    evidence = {}

    # --- Check for dedicated FIM tools ---
    fim_tools = {
        "aide": {
            "label": "AIDE",
            "processes": ["aide"],
            "binaries": ["aide"],
            "configs": ["/etc/aide.conf", "/etc/aide/aide.conf"],
            "database": ["/var/lib/aide/aide.db", "/var/lib/aide/aide.db.gz"],
        },
        "ossec": {
            "label": "OSSEC",
            "processes": ["ossec-syscheckd", "ossec-control"],
            "binaries": ["ossec-control"],
            "configs": ["/var/ossec/etc/ossec.conf"],
            "database": [],
        },
        "wazuh": {
            "label": "Wazuh",
            "processes": ["wazuh-syscheckd", "wazuh-agentd"],
            "binaries": ["wazuh-control"],
            "configs": ["/var/ossec/etc/ossec.conf"],
            "database": [],
        },
        "tripwire": {
            "label": "Tripwire",
            "processes": ["tripwire"],
            "binaries": ["tripwire"],
            "configs": ["/etc/tripwire/twcfg.txt", "/etc/tripwire/twpol.txt"],
            "database": [],
        },
        "samhain": {
            "label": "Samhain",
            "processes": ["samhain"],
            "binaries": ["samhain"],
            "configs": ["/etc/samhainrc"],
            "database": [],
        },
    }

    detected_fim = []
    for tool_id, info in fim_tools.items():
        found = False

        # Check processes
        for proc in info["processes"]:
            if check_process_running(proc):
                found = True
                break

        # Check binaries
        if not found:
            for binary in info["binaries"]:
                rc, _, _ = safe_run(["which", binary])
                if rc == 0:
                    found = True
                    break

        # Check config files
        if not found:
            for cfg in info["configs"]:
                if file_exists(cfg):
                    found = True
                    break

        # Check database files (AIDE-specific)
        if not found:
            for db in info.get("database", []):
                if file_exists(db):
                    found = True
                    break

        if found:
            detected_fim.append(info["label"])

    evidence["detected_fim_tools"] = detected_fim

    # --- Check for EDR ---
    edr_processes = {
        "falcon-sensor": "CrowdStrike Falcon",
        "cbagentd": "Carbon Black",
        "MFEcma": "McAfee/Trellix",
        "ds_agent": "Trend Micro Deep Security",
        "qualys-cloud-agent": "Qualys",
        "SentinelAgent": "SentinelOne",
        "cylancesvc": "Cylance",
        "elastic-endpoint": "Elastic Endpoint Security",
        "mdatp": "Microsoft Defender for Endpoint",
    }

    detected_edr = []
    for proc, label in edr_processes.items():
        if check_process_running(proc):
            detected_edr.append(label)

    evidence["detected_edr"] = detected_edr

    # --- Check for shipper (as proxy for SIEM integration) ---
    shipper_processes = [
        "splunkd", "filebeat", "elastic-agent", "fluentd",
        "fluent-bit", "td-agent", "nxlog", "vector",
    ]
    detected_shippers = []
    for proc in shipper_processes:
        if check_process_running(proc):
            detected_shippers.append(proc)

    evidence["detected_shippers"] = detected_shippers
    has_shipper = len(detected_shippers) > 0

    # --- Decision matrix ---
    if detected_fim:
        return CheckResult(
            check_id="LINUX-FIM-001",
            title="File Integrity Monitoring detected: {}".format(
                ", ".join(detected_fim)
            ),
            severity="PASS",
            detail=(
                "File Integrity Monitoring (FIM) takes a baseline snapshot of "
                "critical files -- cryptographic hashes, permissions, ownership, "
                "timestamps -- and periodically checks whether anything has changed. "
                "When FIM detects that /usr/bin/ssh has a different SHA256 hash than "
                "its baseline, it generates a log entry with the old hash, new hash, "
                "what changed, and when. This complements auditd file watches: "
                "auditd tells you WHO changed a file and HOW (which process, which "
                "syscall), while FIM tells you WHAT changed in the file's content. "
                "FIM is specifically required by PCI-DSS 11.5 and recommended by "
                "CIS benchmarks. Detected FIM tool(s): {}."
            ).format(", ".join(detected_fim)),
            remediation="No action required.",
            category="service",
            platform="linux",
            evidence=evidence,
            mitre_techniques=["T1565.001"],
        )

    if detected_edr and has_shipper:
        return CheckResult(
            check_id="LINUX-FIM-001",
            title="No standalone FIM but EDR with SIEM forwarding detected",
            severity="INFO",
            detail=(
                "File Integrity Monitoring (FIM) takes a baseline snapshot of "
                "critical files -- cryptographic hashes, permissions, ownership, "
                "timestamps -- and periodically checks whether anything has changed. "
                "When FIM detects that /usr/bin/ssh has a different SHA256 hash than "
                "its baseline, it generates a log entry with the old hash, new hash, "
                "what changed, and when. This complements auditd file watches: "
                "auditd tells you WHO changed a file and HOW (which process, which "
                "syscall), while FIM tells you WHAT changed in the file's content. "
                "FIM is specifically required by PCI-DSS 11.5 and recommended by "
                "CIS benchmarks. FIM functionality likely covered by EDR telemetry "
                "forwarded to SIEM via {}. Standalone FIM provides additional "
                "hash-based change verification but is optional when EDR telemetry "
                "is being forwarded. Detected EDR: {}."
            ).format(
                ", ".join(detected_shippers),
                ", ".join(detected_edr),
            ),
            remediation=(
                "No immediate action required. If PCI-DSS compliance requires "
                "dedicated FIM, consider installing AIDE as a lightweight option:\n"
                "  sudo apt-get install aide\n"
                "  sudo aideinit\n"
                "  sudo cp /var/lib/aide/aide.db.new /var/lib/aide/aide.db"
            ),
            category="service",
            platform="linux",
            evidence=evidence,
            mitre_techniques=["T1565.001"],
        )

    if detected_edr and not has_shipper:
        return CheckResult(
            check_id="LINUX-FIM-001",
            title="EDR present but no SIEM forwarding for FIM telemetry",
            severity="WARN",
            detail=(
                "File Integrity Monitoring (FIM) takes a baseline snapshot of "
                "critical files -- cryptographic hashes, permissions, ownership, "
                "timestamps -- and periodically checks whether anything has changed. "
                "When FIM detects that /usr/bin/ssh has a different SHA256 hash than "
                "its baseline, it generates a log entry with the old hash, new hash, "
                "what changed, and when. This complements auditd file watches: "
                "auditd tells you WHO changed a file and HOW (which process, which "
                "syscall), while FIM tells you WHAT changed in the file's content. "
                "FIM is specifically required by PCI-DSS 11.5 and recommended by "
                "CIS benchmarks. EDR is installed ({}) but no log shipper forwards "
                "its telemetry to your SIEM. File change events are only visible "
                "in the EDR vendor console, not in your SIEM. Consider deploying "
                "standalone FIM or configuring EDR-to-SIEM integration."
            ).format(", ".join(detected_edr)),
            remediation=(
                "Either configure EDR-to-SIEM integration so file change events "
                "reach your SIEM, or deploy standalone FIM. For standalone FIM, "
                "AIDE is a lightweight option:\n"
                "  sudo apt-get install aide\n"
                "  sudo aideinit\n"
                "  sudo cp /var/lib/aide/aide.db.new /var/lib/aide/aide.db\n"
                "  # Add to cron for daily checks:\n"
                "  echo '0 5 * * * root /usr/bin/aide --check' | sudo tee "
                "/etc/cron.d/aide-check\n\n"
                "Also consider deploying a log shipper to forward EDR telemetry "
                "to your SIEM."
            ),
            category="service",
            platform="linux",
            evidence=evidence,
            mitre_techniques=["T1565.001"],
        )

    # No FIM, no EDR
    return CheckResult(
        check_id="LINUX-FIM-001",
        title="No file integrity monitoring detected",
        severity="WARN",
        detail=(
            "File Integrity Monitoring (FIM) takes a baseline snapshot of "
            "critical files -- cryptographic hashes, permissions, ownership, "
            "timestamps -- and periodically checks whether anything has changed. "
            "When FIM detects that /usr/bin/ssh has a different SHA256 hash than "
            "its baseline, it generates a log entry with the old hash, new hash, "
            "what changed, and when. This complements auditd file watches: "
            "auditd tells you WHO changed a file and HOW (which process, which "
            "syscall), while FIM tells you WHAT changed in the file's content. "
            "FIM is specifically required by PCI-DSS 11.5 and recommended by "
            "CIS benchmarks. No file integrity monitoring detected. Changes to "
            "critical system binaries, configuration files, and web application "
            "files will not be detected or logged."
        ),
        remediation=(
            "Install a file integrity monitoring tool. AIDE is the most common "
            "open-source option for Linux:\n"
            "  sudo apt-get install aide    # Debian/Ubuntu\n"
            "  sudo dnf install aide        # RHEL/Fedora\n"
            "  sudo aideinit               # Initialize baseline database\n"
            "  sudo cp /var/lib/aide/aide.db.new /var/lib/aide/aide.db\n\n"
            "Schedule daily integrity checks via cron:\n"
            "  echo '0 5 * * * root /usr/bin/aide --check' | sudo tee "
            "/etc/cron.d/aide-check\n\n"
            "AIDE will compare the current state of monitored files against the "
            "baseline database and report any changes to hashes, permissions, "
            "ownership, or timestamps. After legitimate changes (e.g., package "
            "updates), update the baseline with 'aide --update'."
        ),
        category="service",
        platform="linux",
        evidence=evidence,
        mitre_techniques=["T1565.001"],
    )


def run_checks():
    """Return all FIM detection checks."""
    return [
        _check_fim_presence(),
    ]
