"""Tests for the runner orchestration."""

import os
import tempfile
from unittest.mock import patch, MagicMock

from core.result import CheckResult, Report


def _make_result(check_id="TEST-001", severity="PASS", title="Test", category="service"):
    return CheckResult(
        check_id=check_id,
        title=title,
        severity=severity,
        detail="d",
        remediation="r",
        category=category,
        platform="linux",
    )


def test_run_all_checks_linux():
    with patch("core.runner.get_os", return_value="linux"), \
         patch("core.runner.is_elevated", return_value=False), \
         patch("core.runner.get_hostname", return_value="testhost"), \
         patch("core.runner.get_os_info", return_value="Linux 5.15"), \
         patch("core.runner._run_linux_checks", return_value=[]), \
         patch("core.runner._run_common_checks", return_value=[]), \
         patch("core.runner.load_suppressions", return_value=set()):
        from core.runner import run_all_checks
        report = run_all_checks()
        assert isinstance(report, Report)
        assert report.hostname == "testhost"
        assert report.os_info == "Linux 5.15"
        assert report.timestamp  # non-empty


def test_run_all_checks_applies_suppression():
    results = [_make_result("LINUX-SELINUX-001", "WARN", "SELinux check")]

    with patch("core.runner.get_os", return_value="linux"), \
         patch("core.runner.is_elevated", return_value=False), \
         patch("core.runner.get_hostname", return_value="testhost"), \
         patch("core.runner.get_os_info", return_value="Linux 5.15"), \
         patch("core.runner._run_linux_checks", return_value=results), \
         patch("core.runner._run_common_checks", return_value=[]), \
         patch("core.runner.load_suppressions", return_value={"LINUX-SELINUX-001"}):
        from core.runner import run_all_checks
        report = run_all_checks()
        suppressed = [r for r in report.results if r.severity == "SUPPRESSED"]
        assert len(suppressed) == 1
        assert suppressed[0].check_id == "LINUX-SELINUX-001"


def test_category_filter_service():
    with patch("core.runner.get_os", return_value="linux"), \
         patch("core.runner.is_elevated", return_value=False), \
         patch("core.runner.get_hostname", return_value="testhost"), \
         patch("core.runner.get_os_info", return_value="Linux 5.15"), \
         patch("core.runner.load_suppressions", return_value=set()):
        # Mock the individual check modules
        mock_service = MagicMock(return_value=[_make_result(category="service")])
        mock_config = MagicMock(return_value=[_make_result(category="config")])
        mock_fim = MagicMock(return_value=[_make_result(category="service")])

        with patch.dict("sys.modules", {
            "checks.linux.auditd_service": MagicMock(run_checks=mock_service),
            "checks.linux.auditd_config": MagicMock(run_checks=mock_config),
            "checks.linux.auditd_rules": MagicMock(run_checks=mock_config),
            "checks.linux.syslog_forwarding": MagicMock(run_checks=mock_config),
            "checks.linux.journald": MagicMock(run_checks=mock_config),
            "checks.linux.auth_logs": MagicMock(run_checks=mock_config),
            "checks.linux.log_shipper": MagicMock(run_checks=mock_config),
            "checks.linux.noise_analysis": MagicMock(run_checks=mock_config),
            "checks.linux.log_retention": MagicMock(run_checks=mock_config),
            "checks.linux.selinux_logging": MagicMock(run_checks=mock_config),
            "checks.linux.ntp_logging": MagicMock(run_checks=mock_config),
            "checks.linux.firewall_logging": MagicMock(run_checks=mock_config),
            "checks.linux.fim_detection": MagicMock(run_checks=mock_fim),
        }):
            # We need to reload the module to pick up the mocked imports
            # Instead, just test _should_run logic directly
            from core.runner import _should_run
            assert _should_run("service", "service") is True
            assert _should_run("service", "config") is False
            assert _should_run(None, "service") is True
