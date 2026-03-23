"""OS detection, privilege checking, and safe subprocess wrapper."""

import os
import platform
import subprocess
from typing import Tuple, Optional, Dict


def get_os() -> str:
    """Return 'linux', 'windows', or 'macos'."""
    s = platform.system()
    if s == "Linux":
        return "linux"
    elif s == "Windows":
        return "windows"
    elif s == "Darwin":
        return "macos"
    return s.lower()


def is_elevated() -> bool:
    """Check if running with elevated privileges."""
    current_os = get_os()
    if current_os in ("linux", "macos"):
        return os.geteuid() == 0
    elif current_os == "windows":
        try:
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    return False


def get_hostname() -> str:
    return platform.node()


def get_os_info() -> str:
    """Return a descriptive OS info string."""
    current_os = get_os()
    info = "{} {} {}".format(platform.system(), platform.release(), platform.machine())
    if current_os == "linux":
        distro = get_linux_distro()
        if distro.get("NAME"):
            info = "{} ({} {})".format(info, distro.get("NAME", ""), distro.get("VERSION_ID", ""))
    return info


def get_linux_distro() -> Dict[str, str]:
    """Parse /etc/os-release for distro info."""
    result = {}
    try:
        with open("/etc/os-release", "r") as f:
            for line in f:
                line = line.strip()
                if "=" in line:
                    key, _, value = line.partition("=")
                    result[key] = value.strip('"').strip("'")
    except (FileNotFoundError, PermissionError):
        pass
    return result


def get_package_manager() -> str:
    """Detect the system package manager."""
    for pm in ["apt-get", "dnf", "yum", "zypper", "pacman"]:
        rc, _, _ = safe_run(["which", pm])
        if rc == 0:
            return pm
    return "unknown"


def safe_run(cmd: list, timeout: int = 10, input_data: Optional[str] = None) -> Tuple[int, str, str]:
    """
    Run a command safely. Returns (returncode, stdout, stderr).
    Never raises - catches all exceptions and returns (-1, '', error_msg).
    """
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            stdin=subprocess.DEVNULL if input_data is None else subprocess.PIPE,
            input=input_data,
        )
        return (proc.returncode, proc.stdout, proc.stderr)
    except subprocess.TimeoutExpired:
        return (-1, "", "Command timed out after {} seconds: {}".format(timeout, " ".join(cmd)))
    except FileNotFoundError:
        return (-1, "", "Command not found: {}".format(cmd[0] if cmd else "empty"))
    except PermissionError:
        return (-1, "", "Permission denied: {}".format(" ".join(cmd)))
    except Exception as e:
        return (-1, "", "Error running command: {}".format(str(e)))


def read_file_safe(path: str) -> Optional[str]:
    """Read a file safely, returning None on any error."""
    try:
        with open(path, "r") as f:
            return f.read()
    except Exception:
        return None


def parse_config_file(path: str) -> Dict[str, str]:
    """Parse a key=value or key value config file, ignoring comments."""
    result = {}
    content = read_file_safe(path)
    if content is None:
        return result
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith(";"):
            continue
        if "=" in line:
            key, _, value = line.partition("=")
            result[key.strip()] = value.strip()
        else:
            parts = line.split(None, 1)
            if len(parts) == 2:
                result[parts[0]] = parts[1]
    return result


def file_exists(path: str) -> bool:
    return os.path.exists(path)


def get_file_mtime(path: str) -> Optional[float]:
    """Get file modification time, or None if not accessible."""
    try:
        return os.path.getmtime(path)
    except Exception:
        return None


def check_process_running(name: str) -> bool:
    """Check if a process with the given name is running."""
    current_os = get_os()
    if current_os == "windows":
        rc, out, _ = safe_run(["tasklist", "/FI", "IMAGENAME eq {}".format(name), "/NH"])
        if rc == 0 and name.lower() in out.lower():
            return True
    else:
        rc, out, _ = safe_run(["pgrep", "-x", name])
        if rc == 0 and out.strip():
            return True
        rc, out, _ = safe_run(["pgrep", "-f", name])
        if rc == 0 and out.strip():
            return True
    return False


def list_processes() -> str:
    """Get list of running processes."""
    current_os = get_os()
    if current_os == "windows":
        rc, out, _ = safe_run(["tasklist", "/FO", "CSV", "/NH"], timeout=15)
    else:
        rc, out, _ = safe_run(["ps", "aux"], timeout=15)
    return out if rc == 0 else ""
