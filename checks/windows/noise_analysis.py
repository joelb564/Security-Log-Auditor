"""Windows event log noise analysis checks."""

import platform

from core.result import CheckResult
from core.platform_utils import safe_run, read_file_safe, file_exists, is_elevated, check_process_running


def _is_windows():
    return platform.system() == "Windows"


def _count_events(log_name, event_id, time_range_ms=3600000):
    """Count events in a Windows event log by Event ID within a time range.

    Args:
        log_name: Event log name (e.g., "Security")
        event_id: Event ID to count
        time_range_ms: Time range in milliseconds (default: 1 hour)

    Returns:
        (count, raw_output) or (-1, error_message)
    """
    # Use wevtutil to count events with a time-based XPath query
    # TimeDiff is in milliseconds
    xpath = (
        "*[System[EventID={eid} and "
        "TimeCreated[timediff(@SystemTime) <= {ms}]]]"
    ).format(eid=event_id, ms=time_range_ms)

    rc, out, err = safe_run(
        ["wevtutil", "qe", log_name, "/q:{}".format(xpath), "/c:1", "/rd:true", "/f:text"],
        timeout=30
    )

    # Use a count query instead for efficiency
    rc, out, err = safe_run(
        ["powershell", "-NoProfile", "-Command",
         "(Get-WinEvent -FilterHashtable @{{LogName='{}';ID={};StartTime=(Get-Date).AddHours(-1)}} "
         "-ErrorAction SilentlyContinue | Measure-Object).Count".format(log_name, event_id)],
        timeout=60
    )

    if rc != 0:
        return -1, err or "Failed to query events"

    try:
        count = int(out.strip())
        return count, out.strip()
    except ValueError:
        return -1, "Could not parse count: {}".format(out.strip())


def _check_logoff_noise():
    """WIN-NOISE-001: Event 4634 Logoff noise (machine account $ filtering)."""
    check_id = "WIN-NOISE-001"
    title_base = "Logoff Event (4634) Noise"
    evidence = {}

    count, raw = _count_events("Security", 4634)
    evidence["event_4634_count_1hr"] = count
    evidence["raw_output"] = raw

    if count < 0:
        return CheckResult(
            check_id=check_id,
            title="{} - Cannot Assess".format(title_base),
            severity="INFO",
            detail="Could not query Event ID 4634 count: {}".format(raw),
            remediation="Ensure PowerShell remoting and WinRM are available.",
            category="noise",
            platform="windows",
            evidence=evidence,
        )

    # Also count machine account logoffs (accounts ending with $)
    rc, out, err = safe_run(
        ["powershell", "-NoProfile", "-Command",
         "(Get-WinEvent -FilterHashtable @{LogName='Security';ID=4634;"
         "StartTime=(Get-Date).AddHours(-1)} -ErrorAction SilentlyContinue | "
         "Where-Object { $_.Properties[1].Value -like '*$' } | Measure-Object).Count"],
        timeout=60
    )
    machine_count = -1
    if rc == 0:
        try:
            machine_count = int(out.strip())
        except ValueError:
            pass
    evidence["machine_account_4634_count"] = machine_count

    if count > 5000:
        severity = "WARN"
        detail = ("Event 4634 (Logoff) generated {} events in the last hour. "
                  "Machine account (ending with $) logoffs: {}. "
                  "High volume of logoff events is common and creates significant noise. "
                  "Consider filtering machine account logoffs in your SIEM.".format(
                      count, machine_count if machine_count >= 0 else "unknown"))
        remediation = (
            "Filter machine account logoff events in your SIEM/log shipper:\n\n"
            "Splunk: index=wineventlog EventCode=4634 Account_Name!=\"*$\"\n\n"
            "Winlogbeat (processors):\n"
            "  processors:\n"
            "    - drop_event:\n"
            "        when:\n"
            "          and:\n"
            "            - equals.winlog.event_id: 4634\n"
            "            - regexp.winlog.event_data.TargetUserName: '.*\\$'"
        )
    elif count > 1000:
        severity = "INFO"
        detail = ("Event 4634 (Logoff) generated {} events in the last hour. "
                  "Moderate volume. Machine account logoffs: {}.".format(
                      count, machine_count if machine_count >= 0 else "unknown"))
        remediation = "Consider filtering machine account ($) logoffs if volume increases."
    else:
        severity = "PASS"
        detail = "Event 4634 (Logoff) volume is low ({} events/hour).".format(count)
        remediation = "No action required."

    return CheckResult(
        check_id=check_id,
        title="{} - {} events/hr".format(title_base, count),
        severity=severity,
        detail=detail,
        remediation=remediation,
        category="noise",
        platform="windows",
        evidence=evidence,
    )


def _check_handle_events():
    """WIN-NOISE-002: Event 4658/4690 Handle events noise."""
    check_id = "WIN-NOISE-002"
    title_base = "Handle Events (4658/4690) Noise"
    evidence = {}

    count_4658, raw_4658 = _count_events("Security", 4658)
    count_4690, raw_4690 = _count_events("Security", 4690)
    evidence["event_4658_count_1hr"] = count_4658
    evidence["event_4690_count_1hr"] = count_4690

    if count_4658 < 0 and count_4690 < 0:
        return CheckResult(
            check_id=check_id,
            title="{} - Cannot Assess".format(title_base),
            severity="INFO",
            detail="Could not query handle event counts.",
            remediation="Ensure PowerShell is available for event log queries.",
            category="noise",
            platform="windows",
            evidence=evidence,
        )

    total = max(count_4658, 0) + max(count_4690, 0)

    if total > 10000:
        severity = "WARN"
        detail = ("Handle events generated {} events in the last hour "
                  "(4658: {}, 4690: {}). These are extremely high-volume events "
                  "with limited security value. They significantly increase log volume "
                  "and SIEM costs.".format(total, count_4658, count_4690))
        remediation = (
            "Consider disabling handle manipulation auditing if not specifically needed:\n"
            '  auditpol /set /subcategory:"Handle Manipulation" /success:disable /failure:disable\n\n'
            "Or filter at the SIEM level:\n"
            "  Splunk: index=wineventlog NOT (EventCode=4658 OR EventCode=4690)\n\n"
            "  Winlogbeat:\n"
            "    processors:\n"
            "      - drop_event:\n"
            "          when:\n"
            "            or:\n"
            "              - equals.winlog.event_id: 4658\n"
            "              - equals.winlog.event_id: 4690"
        )
    elif total > 1000:
        severity = "INFO"
        detail = ("Handle events: {} events/hour (4658: {}, 4690: {}). "
                  "Moderate volume.".format(total, count_4658, count_4690))
        remediation = "Monitor volume trends. Consider filtering if volume increases significantly."
    else:
        severity = "PASS"
        detail = "Handle event volume is low ({} events/hour).".format(total)
        remediation = "No action required."

    return CheckResult(
        check_id=check_id,
        title="{} - {} events/hr".format(title_base, total),
        severity=severity,
        detail=detail,
        remediation=remediation,
        category="noise",
        platform="windows",
        evidence=evidence,
    )


def _check_wfp_events():
    """WIN-NOISE-003: Event 5156/5158 WFP connection events noise."""
    check_id = "WIN-NOISE-003"
    title_base = "WFP Connection Events (5156/5158) Noise"
    evidence = {}

    count_5156, raw_5156 = _count_events("Security", 5156)
    count_5158, raw_5158 = _count_events("Security", 5158)
    evidence["event_5156_count_1hr"] = count_5156
    evidence["event_5158_count_1hr"] = count_5158

    if count_5156 < 0 and count_5158 < 0:
        return CheckResult(
            check_id=check_id,
            title="{} - Cannot Assess".format(title_base),
            severity="INFO",
            detail="Could not query WFP event counts.",
            remediation="Ensure PowerShell is available for event log queries.",
            category="noise",
            platform="windows",
            evidence=evidence,
        )

    total = max(count_5156, 0) + max(count_5158, 0)

    if total > 20000:
        severity = "WARN"
        detail = ("Windows Filtering Platform (WFP) events generated {} events in the last "
                  "hour (5156: {}, 5158: {}). These network connection events are extremely "
                  "noisy on servers with high network activity. Consider using Sysmon Event ID 3 "
                  "(NetworkConnect) instead for more targeted network monitoring.".format(
                      total, count_5156, count_5158))
        remediation = (
            "Disable WFP connection auditing (use Sysmon for network monitoring instead):\n"
            '  auditpol /set /subcategory:"Filtering Platform Connection" '
            "/success:disable /failure:disable\n"
            '  auditpol /set /subcategory:"Filtering Platform Packet Drop" '
            "/success:disable /failure:disable\n\n"
            "Or filter at the SIEM level:\n"
            "  Splunk: index=wineventlog NOT (EventCode=5156 OR EventCode=5158)\n\n"
            "  Winlogbeat:\n"
            "    processors:\n"
            "      - drop_event:\n"
            "          when:\n"
            "            or:\n"
            "              - equals.winlog.event_id: 5156\n"
            "              - equals.winlog.event_id: 5158"
        )
    elif total > 5000:
        severity = "INFO"
        detail = ("WFP events: {} events/hour (5156: {}, 5158: {}). "
                  "Moderate volume.".format(total, count_5156, count_5158))
        remediation = ("Consider whether WFP events provide value beyond what Sysmon "
                       "Event ID 3 (NetworkConnect) offers.")
    else:
        severity = "PASS"
        detail = "WFP event volume is low ({} events/hour).".format(total)
        remediation = "No action required."

    return CheckResult(
        check_id=check_id,
        title="{} - {} events/hr".format(title_base, total),
        severity=severity,
        detail=detail,
        remediation=remediation,
        category="noise",
        platform="windows",
        evidence=evidence,
    )


def _check_token_right_adjusted():
    """WIN-NOISE-004: Event 4703 Token right adjusted events."""
    check_id = "WIN-NOISE-004"
    title_base = "Token Right Adjusted (4703) Noise"
    evidence = {}

    count, raw = _count_events("Security", 4703)
    evidence["event_4703_count_1hr"] = count

    if count < 0:
        return CheckResult(
            check_id=check_id,
            title="{} - Cannot Assess".format(title_base),
            severity="INFO",
            detail="Could not query Event ID 4703 count.",
            remediation="Ensure PowerShell is available for event log queries.",
            category="noise",
            platform="windows",
            evidence=evidence,
        )

    if count > 5000:
        severity = "WARN"
        detail = ("Event 4703 (Token Right Adjusted) generated {} events in the last hour. "
                  "This event fires whenever a process adjusts its token privileges, which "
                  "happens frequently during normal operations. High volume significantly "
                  "increases log storage and SIEM ingestion costs.".format(count))
        remediation = (
            "Filter 4703 events at the SIEM or shipper level:\n\n"
            "Splunk: index=wineventlog EventCode=4703 | where NOT match(Process_Name, "
            "\"(?i)(svchost|services|lsass)\\.exe\")\n\n"
            "Winlogbeat:\n"
            "  processors:\n"
            "    - drop_event:\n"
            "        when:\n"
            "          equals.winlog.event_id: 4703\n\n"
            "Or reduce noise by disabling non-sensitive privilege use auditing:\n"
            '  auditpol /set /subcategory:"Non Sensitive Privilege Use" /success:disable'
        )
    elif count > 1000:
        severity = "INFO"
        detail = ("Event 4703 (Token Right Adjusted): {} events/hour. "
                  "Moderate volume.".format(count))
        remediation = ("Consider filtering routine token adjustment events from known "
                       "system processes (svchost.exe, services.exe, lsass.exe).")
    else:
        severity = "PASS"
        detail = "Event 4703 volume is low ({} events/hour).".format(count)
        remediation = "No action required."

    return CheckResult(
        check_id=check_id,
        title="{} - {} events/hr".format(title_base, count),
        severity=severity,
        detail=detail,
        remediation=remediation,
        category="noise",
        platform="windows",
        evidence=evidence,
    )


def run_checks():
    """Return all Windows noise analysis checks."""
    if not _is_windows():
        return []

    if not is_elevated():
        return [CheckResult(
            check_id="WIN-NOISE-001",
            title="Noise Analysis Checks - Elevation Required",
            severity="SKIP",
            detail="Noise analysis requires administrator privileges to query event logs.",
            remediation="Re-run this tool as Administrator.",
            category="noise",
            platform="windows",
            evidence={},
        )]

    return [
        _check_logoff_noise(),
        _check_handle_events(),
        _check_wfp_events(),
        _check_token_right_adjusted(),
    ]
