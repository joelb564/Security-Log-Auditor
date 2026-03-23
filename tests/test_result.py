"""Tests for CheckResult and Report dataclasses and scoring logic."""

from core.result import CheckResult, Report


def _make_result(severity="PASS", category="service", check_id="TEST-001"):
    return CheckResult(
        check_id=check_id,
        title="Test check",
        severity=severity,
        detail="detail",
        remediation="fix it",
        category=category,
        platform="linux",
    )


def test_check_result_fields():
    r = CheckResult(
        check_id="LINUX-AUDITD-001",
        title="Auditd installed",
        severity="PASS",
        detail="Found auditd",
        remediation="No action",
        category="service",
        platform="linux",
        evidence={"path": "/sbin/auditd"},
        mitre_techniques=["T1562.001"],
    )
    assert r.check_id == "LINUX-AUDITD-001"
    assert r.title == "Auditd installed"
    assert r.severity == "PASS"
    assert r.detail == "Found auditd"
    assert r.remediation == "No action"
    assert r.category == "service"
    assert r.platform == "linux"
    assert r.evidence == {"path": "/sbin/auditd"}
    assert r.mitre_techniques == ["T1562.001"]


def test_report_calculate_summary():
    results = [
        _make_result("PASS"),
        _make_result("PASS"),
        _make_result("WARN"),
        _make_result("FAIL"),
        _make_result("SKIP"),
    ]
    report = Report(hostname="h", os_info="o", timestamp="t", is_elevated=True, results=results)
    report.calculate_summary()
    assert report.summary["PASS"] == 2
    assert report.summary["WARN"] == 1
    assert report.summary["FAIL"] == 1
    assert report.summary["SKIP"] == 1
    assert report.summary["INFO"] == 0


def test_health_score_all_pass():
    results = [_make_result("PASS") for _ in range(5)]
    report = Report(hostname="h", os_info="o", timestamp="t", is_elevated=True, results=results)
    report.calculate_health_score()
    assert report.health_score == 100


def test_health_score_all_fail():
    results = [_make_result("FAIL") for _ in range(5)]
    report = Report(hostname="h", os_info="o", timestamp="t", is_elevated=True, results=results)
    report.calculate_health_score()
    assert report.health_score == 0


def test_health_score_mixed():
    results = [
        _make_result("PASS"),
        _make_result("WARN"),
        _make_result("FAIL"),
    ]
    report = Report(hostname="h", os_info="o", timestamp="t", is_elevated=True, results=results)
    report.calculate_health_score()
    assert 0 < report.health_score < 100

    # WARN should score between PASS and FAIL (i.e., between 0 and 100 for a single check)
    only_warn = Report(hostname="h", os_info="o", timestamp="t", is_elevated=True,
                       results=[_make_result("WARN")])
    only_warn.calculate_health_score()
    assert 0 < only_warn.health_score < 100


def test_health_score_excludes_skip_and_info():
    results = [
        _make_result("PASS"),
        _make_result("SKIP"),
        _make_result("INFO"),
    ]
    report = Report(hostname="h", os_info="o", timestamp="t", is_elevated=True, results=results)
    report.calculate_health_score()
    # Only the PASS counts, so score should be 100
    assert report.health_score == 100


def test_skipped_count():
    results = [
        _make_result("PASS"),
        _make_result("SKIP"),
        _make_result("SKIP"),
        _make_result("SKIP"),
        _make_result("FAIL"),
    ]
    report = Report(hostname="h", os_info="o", timestamp="t", is_elevated=True, results=results)
    report.calculate_health_score()
    assert report.skipped_count == 3
