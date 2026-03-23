"""Windows PowerShell logging configuration checks via registry."""

import platform

from core.result import CheckResult
from core.platform_utils import safe_run, read_file_safe, file_exists, is_elevated, check_process_running

try:
    import winreg
except ImportError:
    winreg = None


def _is_windows():
    return platform.system() == "Windows"


def _read_registry_dword(hive, subkey, value_name):
    """Read a DWORD value from the registry. Returns the value or None."""
    if winreg is None:
        return None
    try:
        key = winreg.OpenKey(hive, subkey)
        val, reg_type = winreg.QueryValueEx(key, value_name)
        winreg.CloseKey(key)
        return val
    except Exception:
        return None


def _read_registry_string(hive, subkey, value_name):
    """Read a string value from the registry. Returns the value or None."""
    if winreg is None:
        return None
    try:
        key = winreg.OpenKey(hive, subkey)
        val, reg_type = winreg.QueryValueEx(key, value_name)
        winreg.CloseKey(key)
        return val
    except Exception:
        return None


def _check_script_block_logging():
    """WIN-PS-001: PowerShell Script Block Logging."""
    check_id = "WIN-PS-001"
    title_base = "PowerShell Script Block Logging"
    reg_path = r"SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
    value_name = "EnableScriptBlockLogging"

    val = _read_registry_dword(winreg.HKEY_LOCAL_MACHINE, reg_path, value_name)
    evidence = {
        "registry_path": "HKLM\\{}".format(reg_path),
        "value_name": value_name,
        "value": val,
    }

    if val == 1:
        return CheckResult(
            check_id=check_id,
            title="{} - Enabled".format(title_base),
            severity="PASS",
            detail="PowerShell Script Block Logging is enabled. All script blocks "
                   "executed will be logged to the PowerShell Operational log (Event ID 4104).",
            remediation="No action required.",
            category="config",
            platform="windows",
            evidence=evidence,
            mitre_techniques=["T1059.001", "T1027"],
        )

    return CheckResult(
        check_id=check_id,
        title="{} - Not Enabled".format(title_base),
        severity="FAIL",
        detail="PowerShell Script Block Logging is NOT enabled (value={}). This is critical "
               "for detecting obfuscated PowerShell attacks, fileless malware, and encoded "
               "command execution.".format(val),
        remediation='reg add "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging" '
                    '/v EnableScriptBlockLogging /t REG_DWORD /d 1 /f\n\n'
                    'Or via Group Policy:\n'
                    '  Computer Configuration > Administrative Templates > '
                    'Windows Components > Windows PowerShell > '
                    'Turn on PowerShell Script Block Logging = Enabled',
        category="config",
        platform="windows",
        evidence=evidence,
        mitre_techniques=["T1059.001", "T1027"],
    )


def _check_module_logging():
    """WIN-PS-002: PowerShell Module Logging."""
    check_id = "WIN-PS-002"
    title_base = "PowerShell Module Logging"
    reg_path = r"SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging"
    value_name = "EnableModuleLogging"

    val = _read_registry_dword(winreg.HKEY_LOCAL_MACHINE, reg_path, value_name)
    evidence = {
        "registry_path": "HKLM\\{}".format(reg_path),
        "value_name": value_name,
        "value": val,
    }

    # Also check which modules are being logged
    modules_path = r"SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames"
    module_names = []
    if winreg is not None:
        try:
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, modules_path)
            i = 0
            while True:
                try:
                    name, value, _ = winreg.EnumValue(key, i)
                    module_names.append(name)
                    i += 1
                except OSError:
                    break
            winreg.CloseKey(key)
        except Exception:
            pass
    evidence["logged_modules"] = module_names

    if val == 1:
        detail = "PowerShell Module Logging is enabled."
        if module_names:
            detail += " Logging modules: {}".format(", ".join(module_names[:10]))
        else:
            detail += " Warning: no specific modules configured. Add '*' to log all modules."

        return CheckResult(
            check_id=check_id,
            title="{} - Enabled".format(title_base),
            severity="PASS",
            detail=detail,
            remediation="No action required." if module_names else
                        'Add modules to log:\n'
                        'reg add "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\'
                        'ModuleLogging\\ModuleNames" /v * /t REG_SZ /d * /f',
            category="config",
            platform="windows",
            evidence=evidence,
        )

    return CheckResult(
        check_id=check_id,
        title="{} - Not Enabled".format(title_base),
        severity="WARN",
        detail="PowerShell Module Logging is not enabled (value={}). Module logging "
               "captures pipeline execution details including parameter values and "
               "command invocations (Event ID 4103).".format(val),
        remediation='reg add "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ModuleLogging" '
                    '/v EnableModuleLogging /t REG_DWORD /d 1 /f\n'
                    'reg add "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\'
                    'ModuleLogging\\ModuleNames" /v * /t REG_SZ /d * /f\n\n'
                    'Or via Group Policy:\n'
                    '  Computer Configuration > Administrative Templates > '
                    'Windows Components > Windows PowerShell > '
                    'Turn on Module Logging = Enabled\n'
                    '  Module Names: *',
        category="config",
        platform="windows",
        evidence=evidence,
    )


def _check_transcription():
    """WIN-PS-003: PowerShell Transcription."""
    check_id = "WIN-PS-003"
    title_base = "PowerShell Transcription"
    reg_path = r"SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription"
    value_name = "EnableTranscripting"

    val = _read_registry_dword(winreg.HKEY_LOCAL_MACHINE, reg_path, value_name)
    evidence = {
        "registry_path": "HKLM\\{}".format(reg_path),
        "value_name": value_name,
        "value": val,
    }

    # Check output directory
    output_dir = _read_registry_string(
        winreg.HKEY_LOCAL_MACHINE, reg_path, "OutputDirectory"
    )
    evidence["output_directory"] = output_dir

    # Check if invocation headers are enabled
    invocation_header = _read_registry_dword(
        winreg.HKEY_LOCAL_MACHINE, reg_path, "EnableInvocationHeader"
    )
    evidence["enable_invocation_header"] = invocation_header

    if val == 1:
        detail = "PowerShell Transcription is enabled."
        if output_dir:
            detail += " Output directory: {}".format(output_dir)
        if invocation_header == 1:
            detail += " Invocation headers included."
        return CheckResult(
            check_id=check_id,
            title="{} - Enabled".format(title_base),
            severity="PASS",
            detail=detail,
            remediation="No action required.",
            category="config",
            platform="windows",
            evidence=evidence,
        )

    return CheckResult(
        check_id=check_id,
        title="{} - Not Enabled".format(title_base),
        severity="INFO",
        detail="PowerShell Transcription is not enabled (value={}). Transcription creates "
               "text-based logs of all PowerShell sessions, useful for forensic analysis "
               "but can consume significant disk space.".format(val),
        remediation='reg add "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\Transcription" '
                    '/v EnableTranscripting /t REG_DWORD /d 1 /f\n'
                    'reg add "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\Transcription" '
                    '/v OutputDirectory /t REG_SZ /d "C:\\PSTranscripts" /f\n'
                    'reg add "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\Transcription" '
                    '/v EnableInvocationHeader /t REG_DWORD /d 1 /f\n\n'
                    'Or via Group Policy:\n'
                    '  Computer Configuration > Administrative Templates > '
                    'Windows Components > Windows PowerShell > '
                    'Turn on PowerShell Transcription = Enabled',
        category="config",
        platform="windows",
        evidence=evidence,
    )


def _check_powershell_v2():
    """WIN-PS-004: PowerShell v2 engine installed."""
    check_id = "WIN-PS-004"
    title_base = "PowerShell v2 Engine"

    evidence = {}

    # Check if PowerShell v2 feature is installed via DISM or Get-WindowsOptionalFeature
    rc, out, err = safe_run(
        ["powershell", "-NoProfile", "-Command",
         "(Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2).State"],
        timeout=30
    )
    evidence["ps_v2_feature_state"] = out.strip() if rc == 0 else "query failed"
    evidence["ps_v2_query_error"] = err.strip() if rc != 0 else ""

    if rc == 0 and "Enabled" in out:
        return CheckResult(
            check_id=check_id,
            title="{} - Still Installed".format(title_base),
            severity="WARN",
            detail="PowerShell v2 engine is installed and enabled. PowerShell v2 can be used "
                   "to bypass Script Block Logging and other security features added in later "
                   "versions. Attackers use 'powershell -version 2' to evade detection.",
            remediation='Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root -NoRestart\n'
                        'Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2 -NoRestart\n\n'
                        'Or via DISM:\n'
                        '  dism /online /disable-feature /featurename:MicrosoftWindowsPowerShellV2Root /norestart\n'
                        '  dism /online /disable-feature /featurename:MicrosoftWindowsPowerShellV2 /norestart',
            category="config",
            platform="windows",
            evidence=evidence,
            mitre_techniques=["T1059.001"],
        )

    if rc == 0 and "Disabled" in out:
        return CheckResult(
            check_id=check_id,
            title="{} - Disabled".format(title_base),
            severity="PASS",
            detail="PowerShell v2 engine is disabled. Attackers cannot use -version 2 to "
                   "bypass modern PowerShell logging.",
            remediation="No action required.",
            category="config",
            platform="windows",
            evidence=evidence,
            mitre_techniques=["T1059.001"],
        )

    # Fallback: check if powershell v2 engine DLL exists
    v2_dll = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell_ise.exe"
    rc2, out2, _ = safe_run(
        ["powershell", "-NoProfile", "-Command",
         "Test-Path $env:SystemRoot\\System32\\WindowsPowerShell\\v1.0\\PowerShellEngine2.dll"],
        timeout=15
    )
    evidence["engine_dll_exists"] = out2.strip()

    if rc2 == 0 and "True" in out2:
        return CheckResult(
            check_id=check_id,
            title="{} - Possibly Installed".format(title_base),
            severity="WARN",
            detail="PowerShell v2 engine DLL found. The v2 engine may be available for "
                   "attackers to bypass logging.",
            remediation='Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root -NoRestart',
            category="config",
            platform="windows",
            evidence=evidence,
            mitre_techniques=["T1059.001"],
        )

    return CheckResult(
        check_id=check_id,
        title="{} - Check Inconclusive".format(title_base),
        severity="INFO",
        detail="Could not determine PowerShell v2 status. Manual verification recommended.",
        remediation='Run: Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2',
        category="config",
        platform="windows",
        evidence=evidence,
        mitre_techniques=["T1059.001"],
    )


def run_checks():
    """Return all PowerShell logging checks."""
    if not _is_windows():
        return []

    if winreg is None:
        return [CheckResult(
            check_id="WIN-PS-001",
            title="PowerShell Logging Checks - Not on Windows",
            severity="SKIP",
            detail="winreg module not available. These checks require Windows.",
            remediation="Run this tool on a Windows system.",
            category="config",
            platform="windows",
            evidence={},
        )]

    if not is_elevated():
        return [CheckResult(
            check_id="WIN-PS-001",
            title="PowerShell Logging Checks - Elevation Required",
            severity="SKIP",
            detail="PowerShell logging checks require administrator privileges to read "
                   "HKLM registry keys.",
            remediation="Re-run this tool as Administrator.",
            category="config",
            platform="windows",
            evidence={},
        )]

    return [
        _check_script_block_logging(),
        _check_module_logging(),
        _check_transcription(),
        _check_powershell_v2(),
    ]
