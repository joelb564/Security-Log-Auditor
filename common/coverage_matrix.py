"""MITRE ATT&CK coverage matrix: assess detection coverage based on check results."""

from typing import List

from core.result import CheckResult


# MITRE ATT&CK technique-to-tactic mapping
MITRE_TACTICS = {
    "Initial Access": ["T1078", "T1190", "T1566"],
    "Execution": ["T1059", "T1059.001", "T1053"],
    "Persistence": ["T1136", "T1098", "T1053", "T1547"],
    "Privilege Escalation": ["T1078.003", "T1134", "T1055", "T1548"],
    "Defense Evasion": ["T1562.002", "T1036", "T1027", "T1070"],
    "Credential Access": ["T1110", "T1558.003", "T1550.003", "T1003"],
    "Discovery": ["T1087", "T1082"],
    "Lateral Movement": ["T1021"],
    "Collection": ["T1560"],
    "Command and Control": ["T1071"],
    "Exfiltration": ["T1041"],
    "Impact": ["T1489"],
}

# Tactic descriptions: plain-English explanation with example techniques
_TACTIC_DESCRIPTIONS = {
    "Initial Access": (
        "Initial Access is how attackers first get into your environment (e.g., "
        "using stolen valid credentials, exploiting a public-facing web application, "
        "or sending phishing emails with malicious attachments)."
    ),
    "Execution": (
        "Execution is how attackers run malicious code once they have access (e.g., "
        "running PowerShell scripts, creating scheduled tasks, or invoking command-line "
        "interpreters like bash or cmd.exe)."
    ),
    "Persistence": (
        "Persistence is how attackers maintain access to your environment even after "
        "a reboot or password change (e.g., creating new user accounts, adding cron "
        "jobs or systemd services, installing startup scripts, or modifying existing "
        "account permissions)."
    ),
    "Privilege Escalation": (
        "Privilege Escalation is how attackers gain higher privileges than their "
        "initial foothold provides (e.g., exploiting sudo misconfigurations, "
        "manipulating access tokens, injecting code into privileged processes, or "
        "abusing SUID/SGID binaries)."
    ),
    "Defense Evasion": (
        "Defense Evasion is how attackers avoid detection by your security tools "
        "(e.g., disabling or modifying audit logging, masquerading process names to "
        "look legitimate, obfuscating malicious payloads, or clearing log files to "
        "destroy evidence)."
    ),
    "Credential Access": (
        "Credential Access is how attackers steal usernames and passwords (e.g., "
        "brute-forcing login pages, Kerberoasting service accounts in Active "
        "Directory, dumping credentials from LSASS memory, or intercepting "
        "authentication tokens)."
    ),
    "Discovery": (
        "Discovery is how attackers map your environment after gaining initial "
        "access (e.g., enumerating user accounts and group memberships, gathering "
        "system information like OS version and installed software, or scanning "
        "for network services)."
    ),
    "Lateral Movement": (
        "Lateral Movement is how attackers move between systems in your network "
        "after compromising one host (e.g., using SSH with stolen keys, RDP with "
        "harvested credentials, or WMI/WinRM for remote command execution)."
    ),
    "Collection": (
        "Collection is how attackers gather and stage data before stealing it "
        "(e.g., archiving sensitive files into compressed archives, collecting "
        "data from shared drives, or capturing clipboard contents and keystrokes)."
    ),
    "Command and Control": (
        "Command and Control (C2) is how attackers communicate with compromised "
        "hosts to issue commands and receive stolen data (e.g., DNS tunneling to "
        "hide traffic in DNS queries, HTTP/HTTPS beacons that blend with normal "
        "web traffic, or using legitimate cloud services as relay points)."
    ),
    "Exfiltration": (
        "Exfiltration is how attackers steal data from your network (e.g., "
        "transferring files over the C2 channel, uploading data to cloud storage "
        "services, or using alternative protocols like DNS or ICMP to sneak data "
        "past network controls)."
    ),
    "Impact": (
        "Impact is how attackers cause damage to your systems or data (e.g., "
        "stopping critical services to cause outages, encrypting files for ransom, "
        "wiping disks to destroy data, or defacing public-facing websites)."
    ),
}

# Tactic-specific remediation guidance for GAP findings
_TACTIC_REMEDIATIONS = {
    "Initial Access": (
        "No detection coverage for the Initial Access tactic. To detect how "
        "attackers first enter your environment, you need:\n"
        "  - Authentication logs forwarded to SIEM (SSH auth.log, Windows "
        "4624/4625 events) to detect brute force, credential stuffing, and "
        "use of valid accounts (T1078)\n"
        "  - Web application/proxy logs to detect exploitation of public-facing "
        "services (T1190)\n"
        "  - Email gateway logs and EDR telemetry to detect phishing payload "
        "delivery and execution (T1566)\n"
        "  - Add SIEM detection rules for: {techniques}"
    ),
    "Execution": (
        "No detection coverage for the Execution tactic. To detect how attackers "
        "run malicious code, you need:\n"
        "  - Process creation logging with full command lines (auditd execve "
        "rules on Linux, Sysmon Event 1 or Windows 4688 with command-line "
        "auditing on Windows) to detect suspicious script interpreters and "
        "LOLBin usage (T1059)\n"
        "  - PowerShell ScriptBlock logging (Windows) to capture the actual "
        "code being executed, including deobfuscated content (T1059.001)\n"
        "  - Scheduled task/cron monitoring to detect attacker-created jobs "
        "(T1053)\n"
        "  - Deploy EDR for behavioral detection of malicious execution patterns\n"
        "  - Forward all logs to SIEM for correlation\n"
        "  - Add detection rules for: {techniques}"
    ),
    "Persistence": (
        "No detection coverage for the Persistence tactic. To detect how "
        "attackers maintain access after reboot, you need:\n"
        "  - User/group creation monitoring (auditd rules for useradd/groupadd "
        "on Linux, Windows 4720/4732 events) to detect new accounts (T1136)\n"
        "  - Account modification tracking (Windows 4738, Linux audit rules for "
        "usermod/passwd) to detect permission changes (T1098)\n"
        "  - Scheduled task/cron job auditing to detect new persistence "
        "mechanisms (T1053)\n"
        "  - Startup item monitoring (systemd unit files on Linux, Run keys and "
        "Startup folder on Windows) to detect boot persistence (T1547)\n"
        "  - Deploy EDR for real-time persistence mechanism detection\n"
        "  - Forward logs to SIEM for correlation\n"
        "  - Add detection rules for: {techniques}"
    ),
    "Privilege Escalation": (
        "No detection coverage for the Privilege Escalation tactic. To detect "
        "how attackers gain higher privileges, you need:\n"
        "  - Sudo and su usage logging (Linux auth.log/PAM events) and Windows "
        "Sensitive Privilege Use auditing (4672/4673) to detect abnormal "
        "privilege use (T1078.003)\n"
        "  - Process token manipulation monitoring via EDR or Sysmon (Event 10 "
        "for process access) to detect token theft (T1134)\n"
        "  - Process injection detection via EDR behavioral analysis to catch "
        "code injected into privileged processes (T1055)\n"
        "  - SUID/SGID binary monitoring (Linux) and UAC bypass detection "
        "(Windows) for abuse of elevation mechanisms (T1548)\n"
        "  - Forward audit logs to SIEM for correlation\n"
        "  - Add detection rules for: {techniques}"
    ),
    "Defense Evasion": (
        "No detection coverage for the Defense Evasion tactic. To detect how "
        "attackers avoid your security controls, you need:\n"
        "  - Audit log integrity monitoring to detect when logging is disabled "
        "or audit policies are weakened (T1562.002) -- this requires a log "
        "shipper forwarding logs off-host in real-time so tampered local logs "
        "do not affect your SIEM copy\n"
        "  - Process name and path monitoring via EDR or Sysmon to detect "
        "masquerading (e.g., malware named svchost.exe in wrong directory) "
        "(T1036)\n"
        "  - EDR behavioral analysis for obfuscated/encoded payloads (T1027)\n"
        "  - Log file deletion/modification monitoring via auditd file watches "
        "or FIM to detect evidence destruction (T1070)\n"
        "  - Forward all logs to SIEM for correlation\n"
        "  - Add detection rules for: {techniques}"
    ),
    "Credential Access": (
        "No detection coverage for the Credential Access tactic. To detect how "
        "attackers steal credentials, you need:\n"
        "  - Authentication failure logging (Linux auth.log, Windows 4625 "
        "events) with SIEM rules for brute force thresholds (T1110)\n"
        "  - Kerberos TGS request logging (Windows 4769) to detect "
        "Kerberoasting attacks against service accounts (T1558.003)\n"
        "  - NTLM authentication monitoring and EDR alerts for pass-the-hash "
        "and pass-the-ticket activity (T1550.003)\n"
        "  - LSASS process access monitoring via EDR or Sysmon Event 10 to "
        "detect credential dumping tools like Mimikatz (T1003)\n"
        "  - Forward authentication logs to SIEM for correlation\n"
        "  - Add detection rules for: {techniques}"
    ),
    "Discovery": (
        "No detection coverage for the Discovery tactic. To detect how "
        "attackers map your environment, you need:\n"
        "  - Process command-line logging (auditd execve on Linux, Sysmon "
        "Event 1 on Windows) to detect reconnaissance commands like 'whoami', "
        "'net user', 'systeminfo', 'cat /etc/passwd' (T1087, T1082)\n"
        "  - EDR telemetry for behavioral baselining -- Discovery commands are "
        "normal individually but suspicious in rapid succession from a single "
        "session\n"
        "  - LDAP query logging (Windows) to detect large-scale directory "
        "enumeration\n"
        "  - Forward logs to SIEM and add detection rules for: {techniques}"
    ),
    "Lateral Movement": (
        "No detection coverage for the Lateral Movement tactic. To detect how "
        "attackers move between systems, you need:\n"
        "  - Authentication logs from ALL hosts forwarded to SIEM (not just "
        "servers) to detect unusual logon patterns -- SSH auth.log on Linux, "
        "Windows 4624 Type 3 (network) and Type 10 (RDP) events (T1021)\n"
        "  - Network connection logging via EDR or firewall logs to detect "
        "unexpected host-to-host communication (e.g., workstation-to-workstation "
        "SMB)\n"
        "  - SIEM correlation rules that track authentication across multiple "
        "hosts to identify lateral chains\n"
        "  - Add detection rules for: {techniques}"
    ),
    "Collection": (
        "No detection coverage for the Collection tactic. To detect how "
        "attackers gather data before exfiltration, you need:\n"
        "  - File access auditing on sensitive directories (auditd file watches "
        "on Linux, Windows Object Access auditing on file shares) to detect "
        "unusual access patterns (T1560)\n"
        "  - Process command-line logging to detect archiving tools (tar, zip, "
        "7z, rar) being used on sensitive data directories\n"
        "  - EDR file telemetry to detect staging of large archives\n"
        "  - Forward logs to SIEM for correlation\n"
        "  - Add detection rules for: {techniques}"
    ),
    "Command and Control": (
        "No detection coverage for the Command and Control tactic. To detect "
        "how attackers communicate with compromised hosts, you need:\n"
        "  - DNS query logging (Linux DNS resolver logs, Windows DNS Client "
        "events, or network DNS server logs) to detect DNS tunneling and DGA "
        "domains (T1071)\n"
        "  - Web proxy or firewall logs forwarded to SIEM to detect HTTP/HTTPS "
        "beaconing patterns (regular interval callbacks to suspicious domains)\n"
        "  - EDR network telemetry for anomalous outbound connections\n"
        "  - Network metadata (NetFlow/IPFIX) for volumetric analysis\n"
        "  - Add detection rules for: {techniques}"
    ),
    "Exfiltration": (
        "No detection coverage for the Exfiltration tactic. To detect how "
        "attackers steal data from your network, you need:\n"
        "  - Network flow monitoring (NetFlow, firewall logs) to detect "
        "unusually large outbound transfers (T1041)\n"
        "  - Web proxy logs to detect uploads to cloud storage services "
        "(Dropbox, Google Drive, Mega, etc.)\n"
        "  - DNS query size monitoring to detect DNS-based exfiltration\n"
        "  - DLP (Data Loss Prevention) integration with your SIEM\n"
        "  - EDR network telemetry for anomalous data transfer patterns\n"
        "  - Add detection rules for: {techniques}"
    ),
    "Impact": (
        "No detection coverage for the Impact tactic. To detect how attackers "
        "cause damage, you need:\n"
        "  - Service monitoring (systemd on Linux, Windows Service Control "
        "Manager events 7034/7036/7045) to detect unexpected service stops "
        "and new service installations (T1489)\n"
        "  - File system integrity monitoring (FIM) to detect mass file "
        "modifications (ransomware encryption patterns)\n"
        "  - EDR behavioral analysis for ransomware indicators (rapid file "
        "enumeration + encryption + ransom note creation)\n"
        "  - Backup system monitoring to detect backup deletion or tampering\n"
        "  - Forward logs to SIEM for correlation\n"
        "  - Add detection rules for: {techniques}"
    ),
}


def _assess_tactic_coverage(tactic, techniques, all_results):
    """Assess coverage for a single tactic based on check results.

    A technique is considered COVERED if at least one check referencing it
    has severity PASS. A technique is PARTIAL if referenced but only by
    WARN/INFO/FAIL checks. A technique is a GAP if no check references it.

    Tactic-level assessment:
      - COVERED: all techniques have at least one PASS result
      - PARTIAL: some techniques have PASS, some do not
      - GAP: no techniques have any PASS result
    """
    technique_status = {}

    for tech_id in techniques:
        # Find all results that reference this technique (including sub-techniques)
        matching_results = []
        for r in all_results:
            for mt in r.mitre_techniques:
                # Match exact or parent technique (T1059 matches T1059.001)
                if mt == tech_id or tech_id.startswith(mt) or mt.startswith(tech_id.split(".")[0]):
                    if mt == tech_id:
                        matching_results.append(r)
                        break
                    elif "." not in tech_id and mt.startswith(tech_id):
                        # Parent technique matches sub-technique references
                        matching_results.append(r)
                        break

        if not matching_results:
            technique_status[tech_id] = "GAP"
        elif any(r.severity == "PASS" for r in matching_results):
            technique_status[tech_id] = "COVERED"
        else:
            technique_status[tech_id] = "PARTIAL"

    return technique_status


def run_checks(all_results: List[CheckResult] = None):
    """Generate MITRE ATT&CK coverage assessment based on all check results.

    Args:
        all_results: Complete list of CheckResult objects from all checks.

    Returns:
        List of CheckResult objects, one per MITRE tactic.
    """
    if all_results is None:
        all_results = []

    results = []

    for tactic, techniques in MITRE_TACTICS.items():
        evidence = {}
        technique_status = _assess_tactic_coverage(tactic, techniques, all_results)
        evidence["techniques"] = technique_status

        covered_count = sum(1 for s in technique_status.values() if s == "COVERED")
        partial_count = sum(1 for s in technique_status.values() if s == "PARTIAL")
        gap_count = sum(1 for s in technique_status.values() if s == "GAP")
        total = len(techniques)

        evidence["covered"] = covered_count
        evidence["partial"] = partial_count
        evidence["gaps"] = gap_count
        evidence["total"] = total

        tactic_desc = _TACTIC_DESCRIPTIONS.get(tactic, "")

        # Determine tactic-level coverage
        if covered_count == total:
            severity = "PASS"
            coverage_label = "COVERED"
            detail = (
                "{desc}\n\n"
                "{tactic}: all {total} technique(s) have PASS coverage, meaning "
                "your logging and detection infrastructure is generating and "
                "collecting the data needed to detect these attack techniques. "
                "Techniques: {tech_list}"
            ).format(
                desc=tactic_desc,
                tactic=tactic, total=total,
                tech_list=", ".join(
                    "{} ({})".format(t, s) for t, s in technique_status.items()
                ),
            )
            remediation = (
                "No action required. Coverage is confirmed for all tracked "
                "techniques in this tactic. To maintain this coverage, ensure "
                "that audit policies, log shippers, and EDR agents remain active "
                "and correctly configured. Periodically re-run this audit after "
                "infrastructure changes (OS upgrades, SIEM migrations, EDR agent "
                "updates) to confirm coverage has not regressed."
            )
        elif covered_count > 0 or partial_count > 0:
            severity = "WARN"
            coverage_label = "PARTIAL"
            gap_techniques = [
                t for t, s in technique_status.items() if s in ("GAP", "PARTIAL")
            ]
            detail = (
                "{desc}\n\n"
                "{tactic}: PARTIAL coverage -- {covered}/{total} techniques fully "
                "covered, {partial} partially covered (log source exists but has "
                "issues like missing shipper or incomplete config), {gaps} gap(s) "
                "(no relevant log source detected at all). Gaps and partial "
                "coverage mean your SOC may not be able to detect these specific "
                "attack techniques if they are used against this host. "
                "Gaps/partial: {gap_list}"
            ).format(
                desc=tactic_desc,
                tactic=tactic, covered=covered_count, total=total,
                partial=partial_count, gaps=gap_count,
                gap_list=", ".join(gap_techniques),
            )
            remediation = (
                "Improve coverage for the {tactic} tactic by addressing the log "
                "sources and detection rules for these techniques: {gap_list}. "
                "For each technique, consult the MITRE ATT&CK matrix "
                "(attack.mitre.org) which lists the specific data sources needed "
                "for detection (e.g., Process Creation, Authentication Log, "
                "Network Traffic). Ensure those data sources are: (1) being "
                "generated by the OS audit subsystem, (2) being collected by a "
                "log shipper, and (3) have corresponding detection rules in your "
                "SIEM."
            ).format(tactic=tactic, gap_list=", ".join(gap_techniques))
        else:
            severity = "FAIL"
            coverage_label = "GAP"
            detail = (
                "{desc}\n\n"
                "{tactic}: NO coverage -- 0/{total} techniques have PASS status. "
                "This means none of the logging or detection checks relevant to "
                "this tactic passed on this host. If an attacker uses any of these "
                "techniques, your SOC will have no visibility into the activity "
                "from this host's data. Techniques without coverage: {tech_list}"
            ).format(
                desc=tactic_desc,
                tactic=tactic, total=total,
                tech_list=", ".join(techniques),
            )
            remediation = _TACTIC_REMEDIATIONS.get(tactic, "").format(
                techniques=", ".join(techniques)
            )

        evidence["coverage_label"] = coverage_label

        results.append(CheckResult(
            check_id="COVERAGE-{}".format(
                tactic.upper().replace(" ", "-")
            ),
            title="{}: {}".format(tactic, coverage_label),
            severity=severity,
            detail=detail,
            remediation=remediation,
            category="coverage",
            platform="all",
            evidence=evidence,
            mitre_techniques=techniques,
        ))

    return results
