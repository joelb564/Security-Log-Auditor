"""Tests for platform utility functions."""

import os
import subprocess
import tempfile
from unittest.mock import patch, MagicMock

from core.platform_utils import get_os, is_elevated, safe_run, read_file_safe


def test_get_os_linux():
    with patch("platform.system", return_value="Linux"):
        assert get_os() == "linux"


def test_get_os_windows():
    with patch("platform.system", return_value="Windows"):
        assert get_os() == "windows"


def test_get_os_macos():
    with patch("platform.system", return_value="Darwin"):
        assert get_os() == "macos"


def test_is_elevated_root():
    with patch("core.platform_utils.get_os", return_value="linux"), \
         patch("os.geteuid", return_value=0):
        assert is_elevated() is True


def test_safe_run_success():
    mock_result = MagicMock()
    mock_result.returncode = 0
    mock_result.stdout = "hello"
    mock_result.stderr = ""
    with patch("subprocess.run", return_value=mock_result):
        rc, out, err = safe_run(["echo", "hello"])
        assert rc == 0
        assert out == "hello"
        assert err == ""


def test_safe_run_timeout():
    with patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd=["sleep"], timeout=10)):
        rc, out, err = safe_run(["sleep", "100"])
        assert rc == -1
        assert out == ""
        assert "timed out" in err.lower() or "timeout" in err.lower()


def test_read_file_safe_exists():
    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        f.write("test data")
        f.flush()
        try:
            result = read_file_safe(f.name)
            assert result == "test data"
        finally:
            os.unlink(f.name)


def test_read_file_safe_missing():
    result = read_file_safe("/nonexistent/path/xyz/test.txt")
    assert result is None
