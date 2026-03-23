"""Firewall logging configuration checks."""

import re

from core.result import CheckResult
from core.platform_utils import safe_run, is_elevated


def _check_firewall_logging():
    """LINUX-FW-001: Firewall logging configuration."""
    evidence = {}

    if not is_elevated():
        return CheckResult(
            check_id="LINUX-FW-001",
            title="Cannot check firewall logging (not elevated)",
            severity="SKIP",
            detail="Root privileges required to inspect firewall rules.",
            remediation="Re-run with sudo for firewall logging analysis.",
            category="config",
            platform="linux",
            evidence=evidence,
            mitre_techniques=["T1562.004"],
        )

    # Check for nftables first (modern)
    nft_available = False
    nft_log_found = False
    nft_log_chains = []
    rc, out, _ = safe_run(["nft", "list", "ruleset"], timeout=15)
    if rc == 0 and out.strip():
        nft_available = True
        evidence["nft_ruleset_size"] = len(out.splitlines())
        for line in out.splitlines():
            if re.search(r'\blog\b', line, re.IGNORECASE):
                nft_log_found = True
                nft_log_chains.append(line.strip())

    evidence["nft_available"] = nft_available
    evidence["nft_log_rules"] = nft_log_chains[:10]

    # Check for iptables
    ipt_available = False
    ipt_log_found = False
    ipt_log_chains = []
    rc, out, _ = safe_run(["iptables", "-L", "-n"], timeout=15)
    if rc == 0 and out.strip():
        # Check if there are actual rules beyond default empty chains
        rule_lines = [
            l for l in out.splitlines()
            if l.strip() and not l.startswith("Chain") and not l.startswith("target")
        ]
        if rule_lines:
            ipt_available = True
        evidence["iptables_rule_count"] = len(rule_lines)

        for line in out.splitlines():
            if "LOG" in line or "NFLOG" in line:
                ipt_log_found = True
                ipt_log_chains.append(line.strip())

    evidence["ipt_available"] = ipt_available
    evidence["ipt_log_rules"] = ipt_log_chains[:10]

    if not nft_available and not ipt_available:
        return CheckResult(
            check_id="LINUX-FW-001",
            title="No firewall rules loaded",
            severity="INFO",
            detail=(
                "The Linux kernel firewall (iptables or nftables) can generate log "
                "entries for network connections -- both allowed and denied. Without "
                "LOG targets in your firewall rules, dropped packets and connection "
                "attempts generate zero evidence. Firewall logs capture source/"
                "destination IPs, ports, protocols, and packet flags for network "
                "activity that never reaches application-layer logging. This is "
                "critical for detecting port scanning, lateral movement attempts, "
                "C2 beaconing to unusual ports, and data exfiltration. Without "
                "firewall logging, the only network visibility comes from EDR (if "
                "installed) or full packet capture (rarely deployed on individual "
                "hosts). Neither iptables nor nftables has rules loaded on this "
                "host, so there is nothing to configure logging on."
            ),
            remediation=(
                "Deploy a host firewall policy. Both iptables and nftables can "
                "provide network-level logging. Start with a basic policy that "
                "logs dropped connections:\n"
                "  # nftables example:\n"
                "  nft add rule inet filter input ct state invalid log prefix "
                "\"NFT-DROP: \" drop\n"
                "  # iptables example:\n"
                "  iptables -A INPUT -j LOG --log-prefix \"IPT-DROP: \" "
                "--log-level 4"
            ),
            category="config",
            platform="linux",
            evidence=evidence,
            mitre_techniques=["T1562.004"],
        )

    has_logging = nft_log_found or ipt_log_found

    if not has_logging:
        fw_type = "nftables" if nft_available else "iptables"
        return CheckResult(
            check_id="LINUX-FW-001",
            title="Firewall active but no LOG targets configured",
            severity="WARN",
            detail=(
                "The Linux kernel firewall (iptables or nftables) can generate log "
                "entries for network connections -- both allowed and denied. Without "
                "LOG targets in your firewall rules, dropped packets and connection "
                "attempts generate zero evidence. Firewall logs capture source/"
                "destination IPs, ports, protocols, and packet flags for network "
                "activity that never reaches application-layer logging. This is "
                "critical for detecting port scanning, lateral movement attempts, "
                "C2 beaconing to unusual ports, and data exfiltration. Without "
                "firewall logging, the only network visibility comes from EDR (if "
                "installed) or full packet capture (rarely deployed on individual "
                "hosts). {} has rules loaded but no LOG or NFLOG targets were found, "
                "meaning dropped and rejected packets are silently discarded with "
                "no record."
            ).format(fw_type),
            remediation=(
                "Add LOG targets to your firewall rules, especially before DROP "
                "and REJECT rules. This logs packets that are about to be blocked, "
                "capturing evidence of unauthorized connection attempts:\n\n"
                "For iptables (add BEFORE your DROP rules):\n"
                "  iptables -A INPUT -m limit --limit 5/min -j LOG "
                "--log-prefix \"IPT-INPUT-DROP: \" --log-level 4\n"
                "  iptables -A FORWARD -m limit --limit 5/min -j LOG "
                "--log-prefix \"IPT-FORWARD-DROP: \" --log-level 4\n\n"
                "For nftables:\n"
                "  nft add rule inet filter input ct state invalid "
                "log prefix \"NFT-DROP: \" drop\n\n"
                "The --limit flag prevents log flooding from port scans or "
                "DDoS traffic. Adjust the rate based on your environment."
            ),
            category="config",
            platform="linux",
            evidence=evidence,
            mitre_techniques=["T1562.004"],
        )

    # Logging is configured
    log_details = []
    if nft_log_found:
        log_details.append(
            "nftables ({} log rule(s))".format(len(nft_log_chains))
        )
    if ipt_log_found:
        log_details.append(
            "iptables ({} LOG/NFLOG target(s))".format(len(ipt_log_chains))
        )

    return CheckResult(
        check_id="LINUX-FW-001",
        title="Firewall logging configured",
        severity="PASS",
        detail=(
            "The Linux kernel firewall (iptables or nftables) can generate log "
            "entries for network connections -- both allowed and denied. Without "
            "LOG targets in your firewall rules, dropped packets and connection "
            "attempts generate zero evidence. Firewall logs capture source/"
            "destination IPs, ports, protocols, and packet flags for network "
            "activity that never reaches application-layer logging. This is "
            "critical for detecting port scanning, lateral movement attempts, "
            "C2 beaconing to unusual ports, and data exfiltration. Without "
            "firewall logging, the only network visibility comes from EDR (if "
            "installed) or full packet capture (rarely deployed on individual "
            "hosts). Firewall logging is active: {}."
        ).format(", ".join(log_details)),
        remediation="No action required.",
        category="config",
        platform="linux",
        evidence=evidence,
        mitre_techniques=["T1562.004"],
    )


def run_checks():
    """Return all firewall logging checks."""
    return [
        _check_firewall_logging(),
    ]
