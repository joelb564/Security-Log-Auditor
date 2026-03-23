"""Tests for the suppression mechanism."""

import os
import tempfile

from core.result import CheckResult
from core.suppression import load_suppressions, apply_suppressions


def _make_result(check_id="TEST-001", severity="FAIL", title="Test check"):
    return CheckResult(
        check_id=check_id,
        title=title,
        severity=severity,
        detail="detail",
        remediation="fix",
        category="service",
        platform="linux",
    )


def test_load_suppressions_missing_file():
    result = load_suppressions("/nonexistent/path/.audit-suppress-xyz")
    assert result == set()


def test_load_suppressions_valid():
    content = """suppress:
  - check_id: LINUX-SELINUX-001
    reason: "Not used"
  - check_id: LINUX-SHIPPER-003
    reason: "Using journald remote"
"""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
        f.write(content)
        f.flush()
        try:
            result = load_suppressions(f.name)
            assert result == {"LINUX-SELINUX-001", "LINUX-SHIPPER-003"}
        finally:
            os.unlink(f.name)


def test_load_suppressions_empty_suppress_key():
    content = "suppress: []\n"
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
        f.write(content)
        f.flush()
        try:
            result = load_suppressions(f.name)
            assert result == set()
        finally:
            os.unlink(f.name)


def test_apply_suppressions_marks_matching():
    results = [_make_result("LINUX-SELINUX-001", "WARN", "SELinux check")]
    apply_suppressions(results, {"LINUX-SELINUX-001"})
    assert results[0].severity == "SUPPRESSED"
    assert results[0].title.endswith("[suppressed]")


def test_apply_suppressions_ignores_non_matching():
    results = [_make_result("LINUX-AUDITD-001", "PASS", "Auditd installed")]
    apply_suppressions(results, {"LINUX-SELINUX-001"})
    assert results[0].severity == "PASS"
    assert "[suppressed]" not in results[0].title


def test_apply_suppressions_empty_set():
    results = [
        _make_result("LINUX-AUDITD-001", "PASS", "Auditd installed"),
        _make_result("LINUX-SELINUX-001", "WARN", "SELinux check"),
    ]
    apply_suppressions(results, set())
    assert results[0].severity == "PASS"
    assert results[1].severity == "WARN"
