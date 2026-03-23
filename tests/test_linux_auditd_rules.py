"""Tests for auditd rules checks with mocked rule content."""

from unittest.mock import patch

from checks.linux.auditd_rules import (
    _check_execve_monitoring,
)
from checks.linux.auditd_config import _check_immutable_mode


def test_execve_rule_present():
    rules = [
        "-a always,exit -F arch=b64 -S execve -F auid>=1000 -F auid!=4294967295 -k exec",
        "-a always,exit -F arch=b32 -S execve -F auid>=1000 -F auid!=4294967295 -k exec",
    ]
    result = _check_execve_monitoring(rules)
    assert result.check_id == "LINUX-RULES-001"
    assert result.severity == "PASS"


def test_execve_rule_missing():
    result = _check_execve_monitoring([])
    assert result.check_id == "LINUX-RULES-001"
    assert result.severity == "FAIL"


def test_immutable_mode_present():
    with patch("checks.linux.auditd_config._read_all_rules",
               return_value=["-a always,exit -F arch=b64 -S execve", "-e 2"]):
        result = _check_immutable_mode()
        assert result.check_id == "LINUX-AUDITD-007"
        assert result.severity == "PASS"


def test_immutable_mode_missing():
    with patch("checks.linux.auditd_config._read_all_rules",
               return_value=["-a always,exit -F arch=b64 -S execve"]):
        result = _check_immutable_mode()
        assert result.check_id == "LINUX-AUDITD-007"
        assert result.severity in ("WARN", "FAIL")
