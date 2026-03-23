"""EDR/AV agent detection: identify installed security agents and assess coverage gaps."""

from core.result import CheckResult
from core.platform_utils import (
    safe_run, read_file_safe, file_exists, is_elevated,
    check_process_running, get_os, list_processes,
)


# Agent definitions: name -> {processes, paths, description, platforms}
AGENTS = {
    "SentinelOne": {
        "processes": ["SentinelAgent", "sentineld"],
        "paths": ["/opt/sentinelone/", "/Library/Sentinel/"],
        "description": "SentinelOne Singularity XDR",
        "platforms": ["linux", "macos", "windows"],
    },
    "CrowdStrike Falcon": {
        "processes": ["CSFalconService", "falcond", "falcon-sensor"],
        "paths": ["/opt/CrowdStrike/", "/Library/CS/"],
        "description": "CrowdStrike Falcon EDR",
        "platforms": ["linux", "macos", "windows"],
    },
    "Microsoft Defender for Endpoint": {
        "processes": ["MsSense", "mdatp", "wdavdaemon"],
        "paths": [
            "/Library/Application Support/Microsoft/Defender/",
            "/opt/microsoft/mdatp/",
        ],
        "description": "Microsoft Defender for Endpoint (MDE)",
        "platforms": ["linux", "macos", "windows"],
    },
    "Carbon Black": {
        "processes": ["CbDefense", "cbdefense", "cbagentd", "cbdaemon"],
        "paths": ["/opt/carbonblack/", "/Applications/VMware Carbon Black Cloud/"],
        "description": "VMware Carbon Black Cloud",
        "platforms": ["linux", "macos", "windows"],
    },
    "Cybereason": {
        "processes": ["minionhost", "CyrHostSvc", "crond_service"],
        "paths": [],
        "description": "Cybereason Defense Platform",
        "platforms": ["linux", "macos", "windows"],
    },
    "Cortex XDR": {
        "processes": ["cortex-xdr", "traps", "cortex_xdr"],
        "paths": ["/opt/traps/", "/Library/Application Support/PaloAltoNetworks/Traps/"],
        "description": "Palo Alto Cortex XDR",
        "platforms": ["linux", "macos", "windows"],
    },
    "Windows Defender": {
        "processes": ["WinDefend", "MsMpEng", "MpCmdRun"],
        "paths": [],
        "description": "Windows Defender Antivirus",
        "platforms": ["windows"],
    },
}


def _detect_agents():
    """Detect which EDR/AV agents are present on the system."""
    current_os = get_os()
    process_list = list_processes()
    detected = {}

    for agent_name, info in AGENTS.items():
        if current_os not in info["platforms"]:
            continue

        found_via = []

        # Check processes
        for proc in info["processes"]:
            if proc.lower() in process_list.lower():
                found_via.append("process:{}".format(proc))
            elif check_process_running(proc):
                found_via.append("process:{}".format(proc))

        # Check paths
        for path in info["paths"]:
            if file_exists(path):
                found_via.append("path:{}".format(path))

        # Windows-specific: check service
        if current_os == "windows":
            for proc in info["processes"]:
                rc, out, _ = safe_run(["sc", "query", proc])
                if rc == 0 and "RUNNING" in out:
                    if "service:{}".format(proc) not in found_via:
                        found_via.append("service:{}".format(proc))

        if found_via:
            detected[agent_name] = {
                "found_via": found_via,
                "description": info["description"],
            }

    return detected


def _check_edr_presence(detected):
    """ALL-EDR-001: EDR agent presence detection."""
    evidence = {"detected_agents": {}}

    if not detected:
        return CheckResult(
            check_id="ALL-EDR-001",
            title="No EDR/AV agent detected",
            severity="WARN",
            detail=(
                "Endpoint Detection and Response (EDR) is software that continuously "
                "monitors endpoint activity in real-time, looking for malicious "
                "behaviors such as process injection, credential dumping, lateral "
                "movement, and ransomware encryption patterns. Unlike traditional "
                "antivirus -- which primarily scans files against a database of known "
                "malware signatures -- EDR uses behavioral analysis to detect novel "
                "and fileless attacks that have no signature. EDR agents also provide "
                "rich telemetry (process trees, network connections, file operations) "
                "to a centralized console, giving your SOC forensic visibility even "
                "after an incident. No EDR or antivirus agent was detected on this "
                "system. This means there is no real-time threat detection, no "
                "automated blocking of malicious activity, and no endpoint telemetry "
                "being collected. If malware executes on this host, nothing will "
                "alert on it or attempt to stop it."
            ),
            remediation=(
                "Deploy an EDR agent appropriate for your environment. EDR agents "
                "run as a kernel-level or privileged service and typically consume "
                "1-3%% CPU with 100-300 MB RAM:\n"
                "  - CrowdStrike Falcon (commercial) -- widely regarded for threat "
                "intelligence and detection efficacy\n"
                "  - SentinelOne (commercial) -- strong autonomous response and "
                "rollback capabilities\n"
                "  - Microsoft Defender for Endpoint (included with M365 E5 license) "
                "-- good integration with Azure AD and Microsoft ecosystem\n"
                "  - Carbon Black (commercial) -- strong in application control and "
                "audit/remediation workflows\n\n"
                "At minimum on Linux/macOS, install osquery as an open-source "
                "alternative for scheduled telemetry queries. Note that osquery "
                "provides visibility (query-based inspection) but NOT real-time "
                "threat prevention -- it is a complement to EDR, not a replacement."
            ),
            category="edr",
            platform="all",
            evidence=evidence,
            mitre_techniques=["T1562.001"],
        )

    agent_list = []
    for name, info in detected.items():
        agent_list.append("{} ({})".format(name, ", ".join(info["found_via"])))
        evidence["detected_agents"][name] = info

    return CheckResult(
        check_id="ALL-EDR-001",
        title="EDR/AV agent(s) detected",
        severity="INFO",
        detail=(
            "Endpoint Detection and Response (EDR) agents monitor endpoint activity "
            "in real-time, detecting malicious behaviors like process injection, "
            "credential theft, and lateral movement through behavioral analysis "
            "rather than just signature matching. Detected EDR/AV agent(s) on this "
            "host: {}. These agents provide real-time threat detection, automated "
            "response capabilities, and endpoint telemetry to their respective "
            "cloud management consoles."
        ).format("; ".join(agent_list)),
        remediation=(
            "No action required. Verify that the detected agent(s) are reporting "
            "to their management console, that policies are up to date, and that "
            "the agent version is current. Outdated EDR agents may miss detections "
            "for recently discovered attack techniques."
        ),
        category="edr",
        platform="all",
        evidence=evidence,
        mitre_techniques=["T1562.001"],
    )


def _check_s1_cloud_funnel_gaps(detected):
    """ALL-EDR-002: SentinelOne Cloud Funnel gap analysis."""
    evidence = {}

    if "SentinelOne" not in detected:
        return None

    evidence["sentinelone_detected"] = True
    evidence["sentinelone_info"] = detected["SentinelOne"]

    # SentinelOne Cloud Funnel (formerly Deep Visibility) covers many event types
    # but has known gaps in certain areas
    known_gaps = [
        "Detailed command-line arguments for child processes may be truncated",
        "DNS query logging is limited compared to Sysmon/auditd",
        "File integrity monitoring (FIM) may not cover all paths without configuration",
        "Network connection events may lack full packet-level detail",
        "PowerShell script block logging requires separate OS-level configuration",
        "Authentication events (login/logout) may not be fully captured via Cloud Funnel",
    ]

    # Check if other sources cover these gaps
    other_agents = [name for name in detected if name != "SentinelOne"]
    evidence["other_agents"] = other_agents

    gap_note = ""
    if other_agents:
        gap_note = (
            " Other detected agents ({}) may cover some of these gaps."
        ).format(", ".join(other_agents))

    evidence["known_gaps"] = known_gaps

    return CheckResult(
        check_id="ALL-EDR-002",
        title="SentinelOne Cloud Funnel gap analysis",
        severity="WARN",
        detail=(
            "SentinelOne Cloud Funnel (formerly Deep Visibility) is SentinelOne's "
            "mechanism for streaming raw endpoint telemetry to external platforms "
            "like Splunk, Elasticsearch, or a data lake. Cloud Funnel provides "
            "process creation/termination events, file read/write/delete operations, "
            "and network connection data -- valuable for threat hunting and forensic "
            "investigation. However, Cloud Funnel does NOT capture several categories "
            "of security-critical events that your SIEM detection rules likely depend "
            "on:\n"
            "  - Windows authentication events (Event IDs 4624/4625 for login "
            "success/failure, 4648 for explicit credential use)\n"
            "  - Active Directory changes (user creation, group membership changes, "
            "GPO modifications)\n"
            "  - Full PowerShell script block content (the actual code being "
            "executed, not just the process launch)\n"
            "  - Linux PAM authentication events (SSH logins, sudo usage, "
            "password changes)\n\n"
            "These gaps exist because Cloud Funnel captures kernel-level telemetry "
            "from the S1 agent, while the events above are generated by the OS audit "
            "subsystem (Windows Security Event Log, Linux auditd/PAM). Additional "
            "known limitations:\n"
            "  - {}{}"
        ).format("\n  - ".join(known_gaps), gap_note),
        remediation=(
            "Cloud Funnel is not a replacement for native OS audit logging. You must "
            "supplement SentinelOne telemetry with OS-level log sources forwarded "
            "independently to your SIEM via a log shipper:\n"
            "  - OS-level audit logging (auditd on Linux, BSM/ULS on macOS, "
            "Windows Security Event Log) -- these capture authentication, "
            "privilege use, and policy changes that Cloud Funnel cannot see\n"
            "  - Sysmon (Windows) for detailed process creation events with full "
            "command lines, network connections with DNS query logging, and "
            "file/registry change tracking -- complements Cloud Funnel's process "
            "telemetry with richer context\n"
            "  - osquery for scheduled telemetry queries (installed packages, "
            "listening ports, user accounts) that provide point-in-time snapshots\n"
            "  - Forward auth logs (/var/log/auth.log on Linux, Security event log "
            "on Windows) directly to your SIEM -- these contain SSH logins, sudo "
            "events, and account lockouts that are essential for identity-based "
            "detection rules\n"
            "  - Enable PowerShell ScriptBlock logging (Windows) independently via "
            "Group Policy -- this captures the full script content that detection "
            "rules need to identify obfuscated malicious scripts"
        ),
        category="edr",
        platform="all",
        evidence=evidence,
        mitre_techniques=["T1562.002", "T1059.001"],
    )


def _check_mde_audit_dependency(detected):
    """ALL-EDR-003: MDE audit policy dependency (Windows only)."""
    current_os = get_os()
    evidence = {}

    if "Microsoft Defender for Endpoint" not in detected:
        return None

    if current_os != "windows":
        return None

    evidence["mde_detected"] = True

    # MDE on Windows relies on Windows audit policies being correctly configured
    # for certain detection capabilities
    return CheckResult(
        check_id="ALL-EDR-003",
        title="MDE depends on Windows audit policy configuration",
        severity="INFO",
        detail=(
            "Microsoft Defender for Endpoint (MDE) is detected on this Windows host. "
            "MDE automatically configures some Windows audit subcategories for its own "
            "internal detection engine -- for example, it enables Process Creation "
            "auditing to feed its behavioral analysis. However, MDE only enables the "
            "specific audit subcategories it needs for its own detections, which is a "
            "subset of what your SIEM-based detection rules likely require.\n\n"
            "Your SOC's custom SIEM detection rules, correlation logic, and threat "
            "hunting queries typically depend on additional Windows Security Event Log "
            "subcategories that MDE does not auto-enable. Key dependencies:\n"
            "  - Logon events (4624/4625) for identity-based detections such as "
            "brute force, impossible travel, and pass-the-hash\n"
            "  - Process creation (4688) with command-line logging for behavioral "
            "analysis of living-off-the-land techniques (LOLBins)\n"
            "  - Privilege use (4672/4673) for detecting privilege escalation "
            "attempts and abnormal use of sensitive privileges\n"
            "  - Object access auditing for file and registry monitoring needed by "
            "file integrity monitoring (FIM) rules\n\n"
            "If you rely solely on MDE's auto-configuration, your SIEM may be "
            "missing events that its detection rules expect, resulting in silent "
            "detection failures -- rules that exist but never fire because the "
            "underlying data is not being generated."
        ),
        remediation=(
            "Explicitly configure Windows audit policies to support both MDE and "
            "your SIEM detection rules. MDE's auto-configuration and your manual "
            "policy can coexist -- the more permissive setting wins:\n"
            "  1. Review current audit policy settings:\n"
            "     auditpol /get /category:*\n"
            "  2. Verify these subcategories are set to 'Success and Failure'. "
            "Each subcategory generates specific Event IDs your SIEM rules need:\n"
            "     - Logon/Logoff > Logon -- generates 4624 (successful logon) and "
            "4625 (failed logon), essential for brute force and credential "
            "stuffing detection\n"
            "     - Detailed Tracking > Process Creation -- generates 4688, the "
            "foundation for all process-based detection rules\n"
            "     - Privilege Use > Sensitive Privilege Use -- generates 4672/4673, "
            "needed to detect abnormal privilege usage\n"
            "     - Object Access > File System (if FIM is needed) -- generates "
            "4663/4656 for file access tracking, required for compliance and "
            "data exfiltration detection\n"
            "  3. Enable command-line logging in process creation events. Without "
            "this, Event 4688 shows that a process launched but not WHAT it did, "
            "making behavioral detection impossible:\n"
            "     reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\"
            "Policies\\System\\Audit /v ProcessCreationIncludeCmdLine_Enabled "
            "/t REG_DWORD /d 1 /f\n\n"
            "Trade-off: enabling more audit subcategories increases Security Event "
            "Log volume. Plan for approximately 5-15 GB/day per server depending "
            "on workload. Ensure your log shipper and SIEM can handle the "
            "additional volume."
        ),
        category="edr",
        platform="windows",
        evidence=evidence,
        mitre_techniques=["T1562.002", "T1059"],
    )


def _check_edr_without_shipper(detected, shipper_detected):
    """ALL-EDR-004: EDR detected but no SIEM forwarder."""
    evidence = {}
    evidence["edr_agents"] = list(detected.keys())
    evidence["shipper_detected"] = shipper_detected

    if not detected:
        return None

    if shipper_detected:
        return CheckResult(
            check_id="ALL-EDR-004",
            title="EDR and log shipper both present",
            severity="PASS",
            detail=(
                "EDR agent(s) detected ({agents}) alongside a log shipping agent. "
                "This is the recommended configuration: the EDR agent sends its "
                "behavioral telemetry to the vendor's cloud console (e.g., "
                "SentinelOne Management Console, CrowdStrike Falcon Console) for "
                "real-time threat detection and response, while the log shipper "
                "independently forwards OS-level logs (authentication events, "
                "audit records, syslog) to your SIEM for custom detection rules, "
                "cross-host correlation, and long-term retention under your control."
            ).format(agents=", ".join(detected.keys())),
            remediation=(
                "No action required. This dual-channel setup provides defense in "
                "depth: if the EDR agent is disabled by an attacker (a common "
                "technique -- see MITRE T1562.001), OS-level logs forwarded by "
                "the shipper continue to provide visibility. Conversely, if log "
                "files are tampered with locally, the EDR's kernel-level telemetry "
                "provides an independent record."
            ),
            category="edr",
            platform="all",
            evidence=evidence,
            mitre_techniques=["T1070.002"],
        )

    return CheckResult(
        check_id="ALL-EDR-004",
        title="EDR present but no SIEM log forwarder detected",
        severity="WARN",
        detail=(
            "EDR agent(s) detected ({agents}) but no log shipping agent (Splunk "
            "UF, Filebeat, Fluentd, etc.) was found. This is a significant "
            "architectural gap. Here is why: EDR agents send their telemetry to "
            "the vendor's cloud console (e.g., the CrowdStrike Falcon portal or "
            "SentinelOne Management Console). That console is designed for the "
            "vendor's own detection rules and analyst workflows. However, your "
            "SOC's SIEM (Splunk, Elastic, Sentinel, etc.) has its own detection "
            "rules, correlation logic, dashboards, and retention policies that "
            "require OS-level logs -- authentication events, audit trails, syslog "
            "-- forwarded separately. Without a log shipper, these OS-level logs "
            "exist only on local disk, meaning:\n"
            "  - Your SIEM detection rules that depend on auth/audit data will "
            "never fire for this host\n"
            "  - Cross-host correlation (e.g., lateral movement detection) is "
            "impossible because this host's logs are not in the SIEM\n"
            "  - If the EDR vendor has an outage or the agent is disabled by an "
            "attacker, you have zero visibility into this host\n"
            "  - You have no independent log retention -- you are entirely "
            "dependent on the EDR vendor's data retention policy"
        ).format(agents=", ".join(detected.keys())),
        remediation=(
            "Deploy a log shipper to forward OS-level logs to your SIEM "
            "independently of the EDR agent:\n"
            "  - Splunk UF: forward /var/log/auth.log, /var/log/audit/audit.log\n"
            "  - Filebeat: enable system module for auth/syslog collection\n"
            "  - Fluent Bit / Vector: lightweight alternatives for "
            "resource-constrained hosts\n\n"
            "EDR telemetry and OS-level logs serve different purposes and should "
            "be treated as complementary, not redundant:\n"
            "  - EDR telemetry: behavioral detections, process trees, automated "
            "response -- managed by the vendor\n"
            "  - OS audit logs: authentication events, sudo/privilege use, "
            "service changes, cron modifications -- managed by your SOC\n\n"
            "The OS audit logs provide independent evidence that persists even "
            "if the EDR agent is tampered with, disabled, or uninstalled by an "
            "attacker (MITRE T1562.001 -- Impair Defenses: Disable or Modify "
            "Tools)."
        ),
        category="edr",
        platform="all",
        evidence=evidence,
        mitre_techniques=["T1070.002", "T1562.001"],
    )


def run_checks(shipper_detected: bool = False):
    """Return all EDR detection checks.

    Args:
        shipper_detected: Whether a log shipping agent was detected by other checks.

    Returns:
        List of CheckResult objects.
    """
    detected = _detect_agents()
    results = []

    results.append(_check_edr_presence(detected))

    s1_result = _check_s1_cloud_funnel_gaps(detected)
    if s1_result:
        results.append(s1_result)

    mde_result = _check_mde_audit_dependency(detected)
    if mde_result:
        results.append(mde_result)

    edr_shipper_result = _check_edr_without_shipper(detected, shipper_detected)
    if edr_shipper_result:
        results.append(edr_shipper_result)

    return results
