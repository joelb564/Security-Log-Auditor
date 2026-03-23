"""Tests for auditd service checks with mocked system calls."""

from unittest.mock import patch

from checks.linux.auditd_service import _check_auditd_installed, _check_auditd_running


def test_auditd_installed_found():
    with patch("checks.linux.auditd_service.safe_run") as mock_run, \
         patch("checks.linux.auditd_service.get_package_manager", return_value="apt-get"), \
         patch("checks.linux.auditd_service.get_linux_distro", return_value={"NAME": "Ubuntu"}):
        mock_run.return_value = (0, "/sbin/auditd", "")
        result = _check_auditd_installed()
        assert result.check_id == "LINUX-AUDITD-001"
        assert result.severity == "PASS"


def test_auditd_installed_not_found():
    with patch("checks.linux.auditd_service.safe_run") as mock_run, \
         patch("checks.linux.auditd_service.get_package_manager", return_value="apt-get"), \
         patch("checks.linux.auditd_service.get_linux_distro", return_value={"NAME": "Ubuntu"}):
        # which fails, dpkg fails
        mock_run.return_value = (1, "", "not found")
        result = _check_auditd_installed()
        assert result.check_id == "LINUX-AUDITD-001"
        assert result.severity in ("FAIL", "WARN")


def test_auditd_service_running():
    with patch("checks.linux.auditd_service.safe_run") as mock_run:
        mock_run.return_value = (0, "active", "")
        result = _check_auditd_running()
        assert result.check_id == "LINUX-AUDITD-002"
        assert result.severity == "PASS"


def test_auditd_service_not_running():
    with patch("checks.linux.auditd_service.safe_run") as mock_run:
        # All methods of checking fail
        mock_run.return_value = (1, "inactive", "")
        with patch("checks.linux.auditd_service.check_process_running", return_value=False):
            result = _check_auditd_running()
            assert result.check_id == "LINUX-AUDITD-002"
            assert result.severity in ("FAIL", "WARN")
