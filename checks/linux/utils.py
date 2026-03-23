"""Shared utilities for Linux audit checks."""

import glob

from core.platform_utils import read_file_safe, file_exists


def read_all_rules():
    """Read and combine all audit rule lines from rules.d and audit.rules.

    Returns:
        tuple: (lines, sources) where lines is a list of all non-comment rule
               lines and sources is a dict mapping file paths to their lines.
    """
    lines = []
    sources = {}
    rule_files = sorted(glob.glob("/etc/audit/rules.d/*.rules"))
    if file_exists("/etc/audit/audit.rules"):
        rule_files.append("/etc/audit/audit.rules")
    for rf in rule_files:
        content = read_file_safe(rf)
        if content:
            file_lines = []
            for line in content.splitlines():
                stripped = line.strip()
                if stripped and not stripped.startswith("#"):
                    file_lines.append(stripped)
                    lines.append(stripped)
            if file_lines:
                sources[rf] = file_lines
    return lines, sources
