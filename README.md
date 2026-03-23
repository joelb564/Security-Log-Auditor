# 🔍 Security Log Auditor

> Cross-platform security logging audit tool. Inspect, validate, and score your host's audit and log configuration against security best practices — in seconds.

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20Windows%20%7C%20macOS-lightgrey.svg)](#platform-support)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

---

## Overview

Security Log Auditor runs a comprehensive suite of checks against your host's security logging stack and produces a **scored, actionable report** telling you exactly what is correctly configured, what is broken, and how to fix it.

It is designed for:
- **Blue teamers** validating detection coverage before a red team engagement
- **SOC engineers** hardening new hosts and confirming SIEM ingestion
- **Sysadmins** auditing logging health across a fleet
- **Compliance teams** verifying auditd, Sysmon, and SIEM forwarder configuration

Each finding maps to a **check ID**, a **severity**, a **detailed explanation of what was found**, a **remediation step**, and (where applicable) the relevant **MITRE ATT&CK technique IDs**.

---

## Features

- **100+ checks** across Linux, Windows, and macOS
- **Weighted health score** (0–100) based on finding severity and category importance
- **MITRE ATT&CK coverage matrix** — shows which tactics your logging stack covers
- **EDR detection** — identifies CrowdStrike, Defender/MDE, SentinelOne, Carbon Black, and more
- **Noise analysis** — flags high-volume or noisy rules that pollute your SIEM
- **Log shipper validation** — checks Splunk UF, Filebeat/Elastic Agent, NXLog, Winlogbeat
- **HTML report** — self-contained, shareable, no external dependencies
- **JSON output** — machine-readable, CI/CD friendly
- **Zero dependencies** — pure Python standard library, runs anywhere

---

## Quick Start

```bash
# Clone the repo
git clone https://github.com/joelb564/Security-Log-Auditor.git
cd Security-Log-Auditor

# Run with terminal output (no root required, some checks will be skipped)
python3 log_auditor.py

# Full audit with elevated privileges (recommended)
sudo python3 log_auditor.py

# Generate an HTML report
sudo python3 log_auditor.py --html --output-dir /tmp/audit

# Generate JSON output for automation
sudo python3 log_auditor.py --json --output-dir /tmp/audit
```

No pip install, no virtualenv, no external libraries required.

---

## Platform Support

| Platform | Checks | Notes |
|----------|--------|-------|
| **Linux** | 65+ | auditd, journald, syslog, auth logs, FIM, firewall, SELinux, NTP, log shippers |
| **Windows** | 20+ | Audit policy, event log config, PowerShell logging, Sysmon, Winlogbeat, Splunk UF |
| **macOS** | 9+ | BSM audit, Unified Logging System (ULS), Splunk UF, Filebeat, osquery |
| **All** | 5+ | EDR presence, SIEM shipper gap analysis, MITRE ATT&CK coverage |

The tool auto-detects the current platform and runs only the applicable checks.

---

## Check Categories

Checks are grouped into logical categories, each with a different weight in the health score calculation:

| Category | Weight | What it covers |
|----------|--------|----------------|
| `forwarding` | 3.0× | Log shippers, syslog remote forwarding — critical for SIEM ingestion |
| `rules` | 2.5× | auditd rules, audit policy, PowerShell logging rules |
| `service` | 2.0× | auditd/sysmon service health, Sysmon installation |
| `config` | 2.0× | auditd.conf, journald.conf, event log sizes, retention |
| `edr` | 1.5× | EDR presence and SIEM integration gaps |
| `noise` | 1.0× | Noisy rules and filters that generate unhelpful volume |
| `coverage` | 1.0× | MITRE ATT&CK tactic coverage derived from all active checks |

---

## Check ID Reference

Check IDs follow the format `PLATFORM-CATEGORY-NNN`:

```
LINUX-AUDITD-001  → Linux / auditd service check #1
WIN-PS-001        → Windows / PowerShell logging check #1
MAC-BSM-001       → macOS / BSM audit check #1
ALL-EDR-001       → All platforms / EDR detection check #1
ALL-COVERAGE-*    → All platforms / MITRE ATT&CK tactic coverage
```

### Linux Checks (65+)

<details>
<summary>Click to expand</summary>

#### auditd Service
| ID | Check |
|----|-------|
| `LINUX-AUDITD-001` | auditd installed |
| `LINUX-AUDITD-002` | auditd service running |
| `LINUX-AUDITD-003` | auditd enabled at boot |
| `LINUX-AUDITD-013` | Kernel audit subsystem status |

#### auditd Configuration
| ID | Check |
|----|-------|
| `LINUX-AUDITD-004` | Audit backlog buffer size |
| `LINUX-AUDITD-005` | disk_full_action configuration |
| `LINUX-AUDITD-006` | Log rotation configuration |
| `LINUX-AUDITD-007` | Immutable mode (`-e 2`) |
| `LINUX-AUDITD-008` | `log_format ENRICHED` |
| `LINUX-AUDITD-009` | `space_left` early warning |
| `LINUX-AUDITD-010` | `max_log_file_action` |
| `LINUX-AUDITD-011` | `name_format` hostname embedding |
| `LINUX-AUDITD-012` | `freq` flush frequency |
| `LINUX-AUDITD-014` | Audit log file permissions |

#### auditd Rules
| ID | Check |
|----|-------|
| `LINUX-RULES-001` | execve syscall monitoring |
| `LINUX-RULES-002` | Privileged command monitoring |
| `LINUX-RULES-003` | Critical file watches (`/etc/passwd`, `/etc/shadow`, etc.) |
| `LINUX-RULES-004` | Cron monitoring |
| `LINUX-RULES-005` | Module load/unload monitoring |
| `LINUX-RULES-006` | Network configuration changes |
| `LINUX-RULES-007` | Time change monitoring |
| `LINUX-RULES-008` | User/group management syscalls |
| `LINUX-RULES-009` | Rule key coverage |
| `LINUX-RULES-010` | Architecture coverage consistency (b64+b32) |
| `LINUX-RULES-011` | LD_PRELOAD file watches |
| `LINUX-RULES-012` | ptrace syscall monitoring |
| `LINUX-RULES-013` | mount/umount syscall monitoring |
| `LINUX-RULES-014` | Permission change syscalls |
| `LINUX-RULES-015` | File deletion syscalls |
| `LINUX-RULES-016` | Execution from temp directories |

#### Syslog / Journald / Auth
| ID | Check |
|----|-------|
| `LINUX-SYSLOG-001` | rsyslog/syslog-ng service running |
| `LINUX-SYSLOG-002` | Remote forwarding configured |
| `LINUX-SYSLOG-003` | auth/security facility forwarding |
| `LINUX-SYSLOG-004` | TLS encryption on forwarding |
| `LINUX-SYSLOG-005` | Queue/buffer configuration |
| `LINUX-SYSLOG-006` | Forwarding health check |
| `LINUX-JOURNALD-001` | Persistent storage enabled |
| `LINUX-JOURNALD-002` | ForwardToSyslog |
| `LINUX-JOURNALD-003` | Journal size limits |
| `LINUX-JOURNALD-004` | Rate limiting configuration |
| `LINUX-JOURNALD-005` | Forward sealing (Seal) |
| `LINUX-AUTH-001` | Auth log file health |
| `LINUX-AUTH-002` | SSH logging level |
| `LINUX-AUTH-003` | Failed auth log presence |
| `LINUX-AUTH-004` | sshd_config drop-in overrides |
| `LINUX-AUTH-005` | wtmp/btmp/lastlog health |
| `LINUX-AUTH-006` | login.defs logging settings |

#### Log Shippers
| ID | Check |
|----|-------|
| `LINUX-SHIPPER-001` | Splunk Universal Forwarder detection and config |
| `LINUX-SHIPPER-002` | Filebeat / Elastic Agent |
| `LINUX-SHIPPER-003` | Any shipper detected |
| `LINUX-SHIPPER-004` | Shipper connection health |
| `LINUX-SHIPPER-005` | Critical log input coverage |
| `LINUX-SHIPPER-006` | NXLog detection and config |

#### Noise, Retention, and Other
| ID | Check |
|----|-------|
| `LINUX-NOISE-001` | auid=unset filter on execve |
| `LINUX-NOISE-002` | Broad /tmp watches |
| `LINUX-NOISE-003` | System process execve noise |
| `LINUX-NOISE-004` | Duplicate syslog/auditd forwarding |
| `LINUX-NOISE-005` | aureport summary statistics |
| `LINUX-NOISE-006` | High-volume event type detection |
| `LINUX-RETENTION-001` | Combined log retention estimate |
| `LINUX-SELINUX-001` | SELinux audit logging status |
| `LINUX-NTP-001` | Time synchronization health |
| `LINUX-FW-001` | Firewall logging configuration |
| `LINUX-FIM-001` | File Integrity Monitoring presence |

</details>

### Windows Checks (20+)

<details>
<summary>Click to expand</summary>

| ID | Check |
|----|-------|
| `WIN-AUDIT-001` | Credential Validation audit policy |
| `WIN-AUDIT-002` | Kerberos Authentication audit policy |
| `WIN-AUDIT-003` | Logon/Logoff audit policy |
| `WIN-AUDIT-004` | Process Creation audit policy |
| `WIN-AUDIT-005` | Account Management audit policy |
| `WIN-AUDIT-006` | Policy Change audit policy |
| `WIN-AUDIT-007` | Privilege Use audit policy |
| `WIN-AUDIT-008` | Object Access audit policy |
| `WIN-AUDIT-009` | System events audit policy |
| `WIN-AUDIT-010` | Detailed Tracking audit policy |
| `WIN-EVTLOG-001` | Security log maximum size |
| `WIN-EVTLOG-002` | Security log retention policy |
| `WIN-EVTLOG-003` | PowerShell Operational log size |
| `WIN-EVTLOG-004` | Key channels enabled |
| `WIN-EVTLOG-005` | Log fill rate estimation |
| `WIN-PS-001` | PowerShell Script Block Logging |
| `WIN-PS-002` | PowerShell Module Logging |
| `WIN-PS-003` | PowerShell Transcription |
| `WIN-PS-004` | PowerShell v2 presence |
| `WIN-SYSMON-001` | Sysmon installed |
| `WIN-SYSMON-002` | Sysmon configuration quality |
| `WIN-SYSMON-003` | Sysmon log channel size |
| `WIN-SHIPPER-001` | Splunk Universal Forwarder |
| `WIN-SHIPPER-002` | Winlogbeat |
| `WIN-SHIPPER-003` | Any shipper detected |
| `WIN-NOISE-001` | 4634 Logoff filtering |
| `WIN-NOISE-002` | 4658/4690 Handle events |
| `WIN-NOISE-003` | 5156/5158 WFP connection events |
| `WIN-NOISE-004` | 4703 Token right adjusted |

</details>

### macOS Checks

<details>
<summary>Click to expand</summary>

| ID | Check |
|----|-------|
| `MAC-BSM-001` | auditd running (macOS BSM) |
| `MAC-BSM-002` | audit_control configuration |
| `MAC-BSM-003` | Audit log location and size |
| `MAC-ULS-001` | Unified Logging System operational |
| `MAC-ULS-002` | Security-relevant ULS subsystems |
| `MAC-ULS-003` | osquery presence and configuration |
| `MAC-SHIPPER-001` | Splunk Universal Forwarder |
| `MAC-SHIPPER-002` | Filebeat |
| `MAC-NOISE-001` | ULS volume assessment |

</details>

### Cross-Platform Checks

| ID | Check |
|----|-------|
| `ALL-EDR-001` | EDR presence (CrowdStrike, Defender/MDE, SentinelOne, Carbon Black, etc.) |
| `ALL-EDR-002` | SentinelOne Cloud Funnel gap analysis |
| `ALL-EDR-003` | MDE audit policy dependency (Windows) |
| `ALL-EDR-004` | EDR detected but no SIEM forwarder |
| `ALL-COVERAGE-*` | MITRE ATT&CK tactic coverage (12 tactics) |

---

## Usage Reference

```
Usage: python3 log_auditor.py [OPTIONS]

Options:
  --html                Generate a self-contained HTML report
  --json                Generate machine-readable JSON output
  --output-dir PATH     Directory for output files (default: current directory)
  --checks CATEGORY     Only run checks in one category:
                          service | config | rules | forwarding |
                          noise | edr | coverage
  --severity LEVEL      Only show findings at or above this severity:
                          FAIL | WARN | INFO
  --no-color            Disable ANSI terminal colours
  --quiet               Only show FAIL findings in terminal output
  --list-checks         Print all check IDs and titles then exit
  --version             Show version number
```

### Examples

```bash
# Full audit, terminal only
sudo python3 log_auditor.py

# Only show failures
sudo python3 log_auditor.py --severity FAIL

# Only run auditd rules checks
sudo python3 log_auditor.py --checks rules

# HTML + JSON, saved to /var/reports/
sudo python3 log_auditor.py --html --json --output-dir /var/reports/

# List all available check IDs (* = applicable to this platform)
python3 log_auditor.py --list-checks

# CI/CD: exit code is 1 if any FAIL findings, 0 if clean
sudo python3 log_auditor.py --severity FAIL --quiet
echo $?
```

---

## Output and Severity

Each check produces one of the following severities:

| Severity | Meaning |
|----------|---------|
| `PASS` | Check passed — configuration is correct |
| `WARN` | Suboptimal but not broken — partial credit in health score |
| `FAIL` | Check failed — security gap, requires remediation |
| `INFO` | Informational finding — no score impact |
| `SKIP` | Check was skipped (insufficient privileges or not applicable) |

The **health score** (0–100) is a weighted average of all PASS/WARN/FAIL results. Categories with higher security impact (log forwarding, auditd rules) carry more weight.

---

## Project Structure

```
Security-Log-Auditor/
├── log_auditor.py              # Entry point — CLI parsing, orchestration
│
├── core/
│   ├── runner.py               # Loads and runs all applicable checks
│   ├── reporter.py             # Terminal, JSON, and HTML report generation
│   ├── result.py               # CheckResult and Report dataclasses
│   └── platform_utils.py       # OS detection, file helpers, subprocess wrappers
│
├── checks/
│   ├── linux/                  # Linux-specific checks
│   │   ├── auditd_service.py   # Installation and service health
│   │   ├── auditd_config.py    # auditd.conf settings
│   │   ├── auditd_rules.py     # Audit rule coverage
│   │   ├── syslog_forwarding.py# rsyslog/syslog-ng remote forwarding
│   │   ├── journald.py         # systemd-journald configuration
│   │   ├── auth_logs.py        # /var/log/auth.log, SSH logging
│   │   ├── log_shipper.py      # Splunk UF, Filebeat, NXLog
│   │   ├── noise_analysis.py   # Noisy rules and event volume
│   │   ├── log_retention.py    # Retention capacity estimation
│   │   ├── selinux_logging.py  # SELinux audit logging
│   │   ├── ntp_logging.py      # Time synchronization health
│   │   ├── firewall_logging.py # nftables/iptables log rules
│   │   └── fim_detection.py    # AIDE, OSSEC, Wazuh, Tripwire, auditd FIM
│   │
│   ├── windows/                # Windows-specific checks
│   │   ├── audit_policy.py     # auditpol subcategory checks
│   │   ├── event_log_config.py # Event log sizes and retention
│   │   ├── powershell_logging.py # Script block, module, transcription
│   │   ├── sysmon.py           # Sysmon installation and config
│   │   ├── log_shipper.py      # Splunk UF, Winlogbeat
│   │   └── noise_analysis.py   # High-volume Windows event filtering
│   │
│   └── macos/                  # macOS-specific checks
│       ├── bsm_audit.py        # BSM auditd, audit_control
│       ├── uls.py              # Unified Logging System
│       ├── log_shipper.py      # Splunk UF, Filebeat (macOS)
│       └── noise_analysis.py   # ULS volume assessment
│
├── common/
│   ├── edr_detection.py        # Cross-platform EDR and SIEM gap analysis
│   └── coverage_matrix.py      # MITRE ATT&CK tactic coverage scoring
│
└── templates/
    └── report.html             # HTML report template
```

---

## Privilege Requirements

Some checks require elevated privileges to read protected configuration files and query system services.

### Linux (root / sudo)
- Reading `/etc/audit/auditd.conf` and rule files
- Inspecting auditd and rsyslog service status
- Reading `/var/log/auth.log` and `/var/log/secure`
- Checking Splunk forwarder configs in `/opt/`
- Reading `/etc/shadow` permissions

### Windows (Administrator)
- Running `auditpol` to query audit policy subcategories
- Reading event log configuration from the registry
- Querying Sysmon configuration

### macOS (root / sudo)
- Reading `/etc/security/audit_control`
- Inspecting `/var/audit/` contents
- Querying system log statistics

Running without elevation is supported — checks that require root will show as `SKIP` with a clear message.

---

## HTML Report

The `--html` flag generates a self-contained report file:
- **No external dependencies** — everything is inline (CSS, JS)
- **Named by hostname and timestamp**: `log_audit_<hostname>_<timestamp>.html`
- Includes executive summary, health score, finding breakdown by category, and full evidence for each check

Example filename: `log_audit_myserver_2026-03-23_11-05-11.html`

---

## Extending with New Checks

Each check module exposes a `run_checks()` function that returns a list of `CheckResult` objects.

```python
# checks/linux/my_new_check.py
from core.result import CheckResult
from core.platform_utils import safe_run

def _check_my_thing():
    """MY-CHECK-001: Description of what this validates."""
    evidence = {}
    rc, out, err = safe_run(["some", "command"])

    if rc == 0:
        return CheckResult(
            check_id="MY-CHECK-001",
            title="My thing is configured correctly",
            severity="PASS",
            detail="Found the expected configuration: {}".format(out.strip()),
            remediation="",
            category="config",
            platform="linux",
            evidence=evidence,
            mitre_techniques=["T1005"],
        )
    else:
        return CheckResult(
            check_id="MY-CHECK-001",
            title="My thing is missing or misconfigured",
            severity="FAIL",
            detail="Command returned non-zero: {}".format(err.strip()),
            remediation="Run: some-fix-command",
            category="config",
            platform="linux",
            evidence={"rc": rc, "stderr": err},
            mitre_techniques=["T1005"],
        )

def run_checks():
    return [_check_my_thing()]
```

Then register it in `core/runner.py` inside `_run_linux_checks()`.

---

## MITRE ATT&CK Coverage

The tool evaluates coverage across all 12 ATT&CK tactics:

| Tactic | Example techniques covered |
|--------|---------------------------|
| Initial Access | Auth log monitoring |
| Execution | execve, PowerShell logging, Script Block |
| Persistence | Cron monitoring, file watches on rc.d/crontab |
| Privilege Escalation | Privileged command monitoring, ptrace |
| Defense Evasion | Module load/unload, LD_PRELOAD, temp dir execution |
| Credential Access | /etc/shadow and /etc/passwd watches |
| Discovery | (requires EDR or Sysmon for full coverage) |
| Lateral Movement | SSH logging, auth log analysis |
| Collection | FIM, file access auditing |
| Command and Control | Firewall logging, network config changes |
| Exfiltration | Network monitoring rules |
| Impact | Time change monitoring, disk_full_action |

---

## Requirements

- **Python 3.8+**
- No external packages — uses only the Python standard library
- Tested on: Ubuntu 22.04/24.04, RHEL 8/9, Debian 12, Windows Server 2019/2022, macOS 13+

---

## License

MIT License. See [LICENSE](LICENSE) for details.

---

## Contributing

Issues and PRs are welcome. When adding new checks:
1. Follow the existing check module pattern (`run_checks()` → `List[CheckResult]`)
2. Include a clear `detail` (what was found) and `remediation` (exact fix steps)
3. Map to MITRE ATT&CK techniques where applicable
4. Add the check ID to `core/runner.py`'s `list_all_checks()` function
