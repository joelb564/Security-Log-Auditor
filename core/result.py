"""CheckResult dataclass for storing individual check findings."""

from dataclasses import dataclass, field
from typing import Dict, List


@dataclass
class CheckResult:
    check_id: str        # e.g. "LINUX-AUDITD-001"
    title: str           # Short title
    severity: str        # "PASS" | "WARN" | "FAIL" | "INFO" | "SKIP"
    detail: str          # What was found, described clearly
    remediation: str     # Exact steps to fix
    category: str        # "service" | "config" | "rules" | "forwarding" | "noise" | "edr" | "coverage"
    platform: str        # "linux" | "windows" | "macos" | "all"
    evidence: Dict = field(default_factory=dict)
    mitre_techniques: List[str] = field(default_factory=list)


@dataclass
class Report:
    hostname: str
    os_info: str
    timestamp: str
    is_elevated: bool
    results: List[CheckResult] = field(default_factory=list)
    summary: Dict[str, int] = field(default_factory=dict)
    health_score: int = 0
    skipped_count: int = 0

    def calculate_summary(self):
        self.summary = {"PASS": 0, "WARN": 0, "FAIL": 0, "INFO": 0, "SKIP": 0, "SUPPRESSED": 0}
        for r in self.results:
            if r.severity in self.summary:
                self.summary[r.severity] += 1

    def calculate_health_score(self):
        category_weights = {
            "forwarding": 3.0,
            "rules": 2.5,
            "service": 2.0,
            "config": 2.0,
            "edr": 1.5,
            "noise": 1.0,
            "coverage": 1.0,
        }
        total_weight = 0.0
        earned = 0.0
        self.skipped_count = sum(1 for r in self.results if r.severity == "SKIP")
        for r in self.results:
            if r.severity in ("INFO", "SKIP"):
                continue
            w = category_weights.get(r.category, 1.0)
            total_weight += w
            if r.severity == "PASS":
                earned += w
            elif r.severity == "WARN":
                earned += w * 0.5
            # FAIL earns 0
        if total_weight == 0:
            self.health_score = 100
        else:
            self.health_score = int(round((earned / total_weight) * 100))
