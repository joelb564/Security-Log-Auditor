"""Terminal, HTML, and JSON report output."""

import json
import os
import sys
from dataclasses import asdict

from core.result import Report, CheckResult

# Try colorama for Windows terminal color support
try:
    import colorama
    colorama.init()
    HAS_COLORAMA = True
except ImportError:
    HAS_COLORAMA = True  # ANSI codes work on Linux/macOS natively

# Try jinja2 for HTML report
try:
    import jinja2
    HAS_JINJA2 = True
except ImportError:
    HAS_JINJA2 = False


# ANSI color codes
class Colors:
    RED = "\033[91m"
    YELLOW = "\033[93m"
    GREEN = "\033[92m"
    BLUE = "\033[94m"
    GREY = "\033[90m"
    BOLD = "\033[1m"
    RESET = "\033[0m"
    WHITE = "\033[97m"
    CYAN = "\033[96m"


NO_COLOR = type("NoColor", (), {k: "" for k in dir(Colors) if not k.startswith("_")})()


def _severity_color(severity, colors):
    return {
        "FAIL": colors.RED,
        "WARN": colors.YELLOW,
        "PASS": colors.GREEN,
        "INFO": colors.BLUE,
        "SKIP": colors.GREY,
    }.get(severity, colors.RESET)


def _severity_badge(severity, colors):
    c = _severity_color(severity, colors)
    return "{}[{}]{}".format(c, severity.center(4), colors.RESET)


def print_terminal_report(report, use_color=True, quiet=False):
    """Print the full report to terminal."""
    c = Colors if use_color else NO_COLOR

    # Header
    print("")
    print("{}{}==============================================={}".format(c.BOLD, c.CYAN, c.RESET))
    print("{}{}  Security Log Auditor Report{}".format(c.BOLD, c.WHITE, c.RESET))
    print("{}{}==============================================={}".format(c.BOLD, c.CYAN, c.RESET))
    print("  Hostname:   {}{}{}".format(c.BOLD, report.hostname, c.RESET))
    print("  OS:         {}".format(report.os_info))
    print("  Timestamp:  {}".format(report.timestamp))
    print("  Privileges: {}".format(
        "{}Elevated (root/admin){}".format(c.GREEN, c.RESET)
        if report.is_elevated
        else "{}Not elevated — some checks skipped{}".format(c.YELLOW, c.RESET)
    ))
    print("{}==============================================={}".format(c.CYAN, c.RESET))
    print("")

    # Summary
    score = report.health_score
    if score >= 80:
        score_color = c.GREEN
    elif score >= 50:
        score_color = c.YELLOW
    else:
        score_color = c.RED
    print("  {}{}Health Score: {}/100{}".format(c.BOLD, score_color, score, c.RESET))
    if report.skipped_count > 0:
        print("  {}⚠  Score excludes {} skipped checks — re-run with sudo for accurate results.{}".format(
            c.YELLOW, report.skipped_count, c.RESET))
    print("")
    print("  {}FAIL {}{}{}   {}WARN {}{}{}   {}PASS {}{}{}   {}INFO {}{}{}   {}SKIP {}{}{}".format(
        c.RED, c.BOLD, report.summary.get("FAIL", 0), c.RESET,
        c.YELLOW, c.BOLD, report.summary.get("WARN", 0), c.RESET,
        c.GREEN, c.BOLD, report.summary.get("PASS", 0), c.RESET,
        c.BLUE, c.BOLD, report.summary.get("INFO", 0), c.RESET,
        c.GREY, c.BOLD, report.summary.get("SKIP", 0), c.RESET,
    ))
    print("")

    # Top issues — quick executive summary of FAILs
    fails = [r for r in report.results if r.severity == "FAIL" and r.category != "coverage"]
    if fails:
        print("{}{}  TOP ISSUES{}".format(c.BOLD, c.RED, c.RESET))
        print("  {}----------{}".format(c.RED, c.RESET))
        for r in fails:
            print("  {} {} — {}".format(_severity_badge("FAIL", c), r.check_id, r.title))
        print("")

    # Group by category with logical order
    categories = {}
    for r in report.results:
        if quiet and r.severity != "FAIL":
            continue
        categories.setdefault(r.category, []).append(r)

    category_order = ["service", "config", "rules", "forwarding", "noise", "edr", "coverage"]
    category_descriptions = {
        "service": "Are the logging daemons installed, running, and persistent?",
        "config": "Are services tuned for security, retention, and resilience?",
        "rules": "What activity is being recorded at the kernel level?",
        "forwarding": "Are logs being sent off-host to your SIEM?",
        "noise": "Are high-volume, low-value events wasting SIEM capacity?",
        "edr": "Is behavioral threat detection present?",
        "coverage": "Which attacker tactics can you detect?",
    }

    severity_order = {"FAIL": 0, "WARN": 1, "PASS": 2, "INFO": 3, "SKIP": 4}
    ordered_cats = [cat for cat in category_order if cat in categories]
    # Add any categories not in the predefined order
    for cat in sorted(categories.keys()):
        if cat not in ordered_cats:
            ordered_cats.append(cat)

    for cat in ordered_cats:
        results = sorted(categories[cat], key=lambda r: severity_order.get(r.severity, 5))

        # Skip coverage category in main body — it's shown as the matrix below
        if cat == "coverage":
            continue

        cat_desc = category_descriptions.get(cat, "")
        print("{}{}  [{}]{} {}{}{}".format(
            c.BOLD, c.CYAN, cat.upper(), c.RESET,
            c.GREY, cat_desc, c.RESET))
        print("  {}{}{}".format(c.CYAN, "-" * 50, c.RESET))

        for r in results:
            _print_finding(r, c, quiet)
        print("")

    # Coverage matrix — compact grid, not individual findings
    coverage_results = [r for r in report.results if r.category == "coverage"]
    if coverage_results:
        # Filter out non-tactic results (like auth log checks that ended up in coverage)
        tactic_results = [r for r in coverage_results if r.check_id.startswith("COVERAGE-")]
        other_coverage = [r for r in coverage_results if not r.check_id.startswith("COVERAGE-")]

        # Show non-tactic coverage findings normally
        if other_coverage and not quiet:
            print("{}{}  [COVERAGE]{} {}{}{}".format(
                c.BOLD, c.CYAN, c.RESET,
                c.GREY, "Which attacker tactics can you detect?", c.RESET))
            print("  {}{}{}".format(c.CYAN, "-" * 50, c.RESET))
            for r in other_coverage:
                _print_finding(r, c, quiet)
            print("")

        # Show tactic matrix as compact grid
        if tactic_results:
            print("{}{}  MITRE ATT&CK COVERAGE{}".format(c.BOLD, c.WHITE, c.RESET))
            print("  {}{}{}".format(c.CYAN, "-" * 50, c.RESET))
            for r in tactic_results:
                badge = _severity_badge(r.severity, c)
                tactic = r.title.replace("MITRE Coverage: ", "")
                print("  {} {}".format(badge, tactic))
            print("")

            # Show remediation for GAP/PARTIAL only if not quiet
            if not quiet:
                gap_results = [r for r in tactic_results if r.severity in ("FAIL", "WARN")]
                if gap_results:
                    print("  {}Use --html for detailed remediation per tactic.{}".format(c.GREY, c.RESET))
                    print("")

    # Footer
    print("{}==============================================={}".format(c.CYAN, c.RESET))
    print("{}{}  NEXT STEPS{}".format(c.BOLD, c.WHITE, c.RESET))
    print("{}==============================================={}".format(c.CYAN, c.RESET))
    fail_count = report.summary.get("FAIL", 0)
    warn_count = report.summary.get("WARN", 0)
    if fail_count > 0:
        print("  {}1. Address {} FAIL findings — critical logging gaps{}".format(c.RED, fail_count, c.RESET))
    if warn_count > 0:
        print("  {}2. Review {} WARN findings — improvements to strengthen logging{}".format(c.YELLOW, warn_count, c.RESET))
    if fail_count == 0 and warn_count == 0:
        print("  {}All checks passed! Review INFO findings for optimizations.{}".format(c.GREEN, c.RESET))
    print("  3. Re-run after making changes to validate fixes")
    print("  4. Use --html for a shareable report with full detail")
    print("")


def _wrap_text(text, width=76, indent="    "):
    """Wrap text to width with indent, preserving explicit newlines and indented lines."""
    import textwrap
    lines = text.split("\n")
    wrapped = []
    for line in lines:
        if line.startswith("  ") or line.startswith("\t"):
            # Preserve indented lines (config examples, commands)
            wrapped.append(indent + "  " + line.strip())
        elif len(line) > width:
            wrapped.extend(textwrap.wrap(line, width=width, initial_indent=indent, subsequent_indent=indent))
        else:
            wrapped.append(indent + line)
    return "\n".join(wrapped)


def _print_finding(r, c, quiet=False):
    """Print a single finding. PASS/INFO are compact; FAIL/WARN get full detail."""
    badge = _severity_badge(r.severity, c)

    if r.severity == "PASS":
        # One-liner for passing checks
        print("  {} {}{}{} — {}".format(badge, c.GREY, r.check_id, c.RESET, r.title))
        return

    if r.severity == "INFO":
        # Brief for info — title + one-line summary
        print("  {} {}{}{} — {}".format(badge, c.GREY, r.check_id, c.RESET, r.title))
        # Show first sentence only
        first_sentence = r.detail.split(". ")[0] + "." if ". " in r.detail else r.detail
        if len(first_sentence) > 120:
            first_sentence = first_sentence[:117] + "..."
        print("    {}{}{}".format(c.GREY, first_sentence, c.RESET))
        return

    if r.severity == "SKIP":
        print("  {} {}{}{} — {}".format(badge, c.GREY, r.check_id, c.RESET, r.title))
        return

    # FAIL and WARN get full detail + remediation
    print("")
    print("  {} {}{}{} — {}".format(badge, c.BOLD, r.check_id, c.RESET, r.title))
    print(_wrap_text(r.detail))
    if r.remediation:
        print("")
        print("    {}Remediation:{}".format(c.BOLD, c.RESET))
        print(_wrap_text(r.remediation, indent="      "))
    if r.mitre_techniques:
        print("    {}MITRE:{} {}".format(c.GREY, c.RESET, ", ".join(r.mitre_techniques)))


def generate_json_report(report):
    """Return the report as a JSON string."""
    data = {
        "hostname": report.hostname,
        "os_info": report.os_info,
        "timestamp": report.timestamp,
        "is_elevated": report.is_elevated,
        "summary": report.summary,
        "health_score": report.health_score,
        "results": [asdict(r) for r in report.results],
    }
    return json.dumps(data, indent=2, default=str)


def generate_html_report(report):
    """Generate an HTML report. Uses Jinja2 if available, otherwise simple HTML."""
    if HAS_JINJA2:
        return _generate_html_jinja(report)
    return _generate_html_simple(report)


def _generate_html_jinja(report):
    """Generate HTML using Jinja2 template."""
    template_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "templates")
    template_path = os.path.join(template_dir, "report.html")
    if not os.path.exists(template_path):
        return _generate_html_simple(report)
    env = jinja2.Environment(
        loader=jinja2.FileSystemLoader(template_dir),
        autoescape=True,
    )
    template = env.get_template("report.html")
    categories = {}
    for r in report.results:
        categories.setdefault(r.category, []).append(r)
    severity_order = {"FAIL": 0, "WARN": 1, "PASS": 2, "INFO": 3, "SKIP": 4}
    for cat in categories:
        categories[cat].sort(key=lambda r: severity_order.get(r.severity, 5))
    coverage_results = [r for r in report.results if r.category == "coverage"]
    return template.render(
        report=report,
        categories=categories,
        coverage_results=coverage_results,
        severity_order=severity_order,
    )


def _generate_html_simple(report):
    """Generate a self-contained HTML report without Jinja2."""
    severity_colors = {
        "FAIL": "#ef4444",
        "WARN": "#f59e0b",
        "PASS": "#22c55e",
        "INFO": "#3b82f6",
        "SKIP": "#6b7280",
    }

    category_order = ["service", "config", "rules", "forwarding", "noise", "edr", "coverage"]
    category_descriptions = {
        "service": "Core audit/logging services",
        "config": "Configuration quality and tuning",
        "rules": "Kernel-level audit rules",
        "forwarding": "Off-host log forwarding",
        "noise": "Signal-to-noise optimization",
        "edr": "Endpoint detection and response",
        "coverage": "MITRE ATT&amp;CK detection coverage",
    }

    categories = {}
    for r in report.results:
        categories.setdefault(r.category, []).append(r)
    severity_order = {"FAIL": 0, "WARN": 1, "PASS": 2, "INFO": 3, "SKIP": 4}
    for cat in categories:
        categories[cat].sort(key=lambda r: severity_order.get(r.severity, 5))

    ordered_cats = [cat for cat in category_order if cat in categories]
    for cat in sorted(categories.keys()):
        if cat not in ordered_cats:
            ordered_cats.append(cat)

    # Compute per-category severity counts
    cat_sev_counts = {}
    for cat in ordered_cats:
        counts = {}
        for r in categories[cat]:
            counts[r.severity] = counts.get(r.severity, 0) + 1
        cat_sev_counts[cat] = counts

    # Determine which categories have FAIL or WARN (expanded by default)
    cats_with_issues = set()
    for cat in ordered_cats:
        for r in categories[cat]:
            if r.severity in ("FAIL", "WARN"):
                cats_with_issues.add(cat)
                break

    # Collect FAIL findings for top issues (exclude coverage)
    fail_findings = [r for r in report.results if r.severity == "FAIL" and r.category != "coverage"]

    # Coverage results for MITRE matrix
    coverage_results = [r for r in report.results if r.category == "coverage" and r.check_id.startswith("COVERAGE-")]

    # --- Build sidebar nav ---
    sidebar_html = ""
    for cat in ordered_cats:
        counts = cat_sev_counts[cat]
        badges = ""
        for sev in ["FAIL", "WARN", "PASS", "INFO", "SKIP"]:
            cnt = counts.get(sev, 0)
            if cnt > 0:
                badges += '<span class="nav-badge nav-badge-{sev_lower}">{cnt}</span>'.format(
                    sev_lower=sev.lower(), cnt=cnt)
        sidebar_html += '<a class="nav-link" href="#cat-{cat}">{cat_upper}{badges}</a>\n'.format(
            cat=_html_escape(cat), cat_upper=_html_escape(cat.upper()), badges=badges)
    sidebar_html += '<a class="nav-link" href="#mitre-matrix">MITRE ATT&amp;CK</a>\n'
    sidebar_html += '<a class="nav-link" href="#next-steps">NEXT STEPS</a>\n'

    # --- Build findings HTML ---
    findings_html = ""
    finding_index = 0
    for cat in ordered_cats:
        if cat == "coverage":
            continue
        cat_desc = category_descriptions.get(cat, "")
        is_expanded = cat in cats_with_issues
        expanded_class = "expanded" if is_expanded else "collapsed"
        counts = cat_sev_counts[cat]
        count_badges = ""
        for sev in ["FAIL", "WARN", "PASS", "INFO", "SKIP"]:
            cnt = counts.get(sev, 0)
            if cnt > 0:
                count_badges += ' <span class="cat-count-badge badge-{sev_lower}">{cnt} {sev}</span>'.format(
                    sev_lower=sev.lower(), sev=sev, cnt=cnt)

        findings_html += '<div class="category" id="cat-{cat}">\n'.format(cat=_html_escape(cat))
        findings_html += '<div class="cat-header {expanded_class}" onclick="toggleSection(this)">\n'.format(
            expanded_class=expanded_class)
        findings_html += '  <div class="cat-title-row"><span class="cat-chevron"></span><span class="cat-name">{cat_upper}</span>{count_badges}</div>\n'.format(
            cat_upper=_html_escape(cat.upper()), count_badges=count_badges)
        findings_html += '  <div class="cat-desc">{cat_desc}</div>\n'.format(cat_desc=cat_desc)
        findings_html += '</div>\n'
        findings_html += '<div class="cat-body" style="display:{display};">\n'.format(
            display="block" if is_expanded else "none")

        for r in categories[cat]:
            sev_lower = r.severity.lower()
            finding_id = "finding-{idx}".format(idx=finding_index)
            finding_index += 1

            if r.severity == "PASS":
                findings_html += '<div class="finding finding-{sev_lower}" data-severity="{severity}" id="{fid}">\n'.format(
                    sev_lower=sev_lower, severity=r.severity, fid=finding_id)
                findings_html += '  <div class="finding-header finding-compact" onclick="toggleFindingDetail(this)">\n'
                findings_html += '    <span class="badge badge-{sev_lower}">{severity}</span>\n'.format(
                    sev_lower=sev_lower, severity=r.severity)
                findings_html += '    <span class="check-id">{check_id}</span> &mdash; {title}\n'.format(
                    check_id=_html_escape(r.check_id), title=_html_escape(r.title))
                findings_html += '  </div>\n'
                findings_html += '  <div class="finding-detail-collapsible" style="display:none;">\n'
                findings_html += '    <p class="detail">{detail}</p>\n'.format(detail=_html_escape(r.detail))
                if r.evidence:
                    findings_html += _build_evidence_html(r.evidence)
                findings_html += '  </div>\n'
                findings_html += '</div>\n'

            elif r.severity == "INFO":
                first_sentence = r.detail.split(". ")[0] + "." if ". " in r.detail else r.detail
                findings_html += '<div class="finding finding-{sev_lower}" data-severity="{severity}" id="{fid}">\n'.format(
                    sev_lower=sev_lower, severity=r.severity, fid=finding_id)
                findings_html += '  <div class="finding-header finding-compact" onclick="toggleFindingDetail(this)">\n'
                findings_html += '    <span class="badge badge-{sev_lower}">{severity}</span>\n'.format(
                    sev_lower=sev_lower, severity=r.severity)
                findings_html += '    <span class="check-id">{check_id}</span> &mdash; {title}\n'.format(
                    check_id=_html_escape(r.check_id), title=_html_escape(r.title))
                findings_html += '    <span class="info-summary">{first}</span>\n'.format(
                    first=_html_escape(first_sentence))
                findings_html += '  </div>\n'
                findings_html += '  <div class="finding-detail-collapsible" style="display:none;">\n'
                findings_html += '    <p class="detail">{detail}</p>\n'.format(detail=_html_escape(r.detail))
                if r.remediation:
                    findings_html += _build_remediation_html(r.remediation)
                if r.mitre_techniques:
                    findings_html += '    <p class="mitre">MITRE: {techniques}</p>\n'.format(
                        techniques=", ".join(_html_escape(t) for t in r.mitre_techniques))
                if r.evidence:
                    findings_html += _build_evidence_html(r.evidence)
                findings_html += '  </div>\n'
                findings_html += '</div>\n'

            elif r.severity == "SKIP":
                findings_html += '<div class="finding finding-skip" data-severity="SKIP" id="{fid}">\n'.format(
                    fid=finding_id)
                findings_html += '  <span class="badge badge-skip">SKIP</span>\n'
                findings_html += '  <span class="check-id">{check_id}</span> &mdash; {title}\n'.format(
                    check_id=_html_escape(r.check_id), title=_html_escape(r.title))
                findings_html += '</div>\n'

            else:
                # FAIL or WARN: full detail
                findings_html += '<div class="finding finding-{sev_lower}" data-severity="{severity}" id="{fid}">\n'.format(
                    sev_lower=sev_lower, severity=r.severity, fid=finding_id)
                findings_html += '  <span class="badge badge-{sev_lower}">{severity}</span>\n'.format(
                    sev_lower=sev_lower, severity=r.severity)
                findings_html += '  <span class="check-id">{check_id}</span> &mdash; {title}\n'.format(
                    check_id=_html_escape(r.check_id), title=_html_escape(r.title))
                findings_html += '  <p class="detail">{detail}</p>\n'.format(detail=_html_escape(r.detail))
                if r.remediation:
                    findings_html += _build_remediation_html(r.remediation)
                if r.mitre_techniques:
                    findings_html += '  <p class="mitre">MITRE: {techniques}</p>\n'.format(
                        techniques=", ".join(_html_escape(t) for t in r.mitre_techniques))
                if r.evidence:
                    findings_html += _build_evidence_html(r.evidence)
                findings_html += '</div>\n'

        findings_html += '</div></div>\n'

    # --- Top issues HTML ---
    top_issues_html = ""
    if fail_findings:
        top_issues_html = '<div class="top-issues" id="top-issues">\n'
        top_issues_html += '  <h2>Top Issues</h2>\n'
        top_issues_html += '  <ul>\n'
        fi = 0
        for cat in ordered_cats:
            if cat == "coverage":
                continue
            for r in categories.get(cat, []):
                if r.severity == "FAIL":
                    top_issues_html += '    <li><a href="#finding-{idx}">{check_id} &mdash; {title}</a></li>\n'.format(
                        idx=fi, check_id=_html_escape(r.check_id), title=_html_escape(r.title))
                fi += 1
        top_issues_html += '  </ul>\n'
        top_issues_html += '</div>\n'

    # --- Coverage / MITRE matrix HTML ---
    mitre_html = ""
    if coverage_results:
        mitre_html = '<div class="mitre-section" id="mitre-matrix">\n'
        mitre_html += '  <h2>MITRE ATT&amp;CK Coverage Matrix</h2>\n'
        mitre_html += '  <div class="mitre-grid">\n'
        for r in coverage_results:
            sev = r.severity
            if sev == "PASS":
                status_label = "COVERED"
                card_class = "mitre-covered"
            elif sev == "WARN":
                status_label = "PARTIAL"
                card_class = "mitre-partial"
            elif sev == "FAIL":
                status_label = "GAP"
                card_class = "mitre-gap"
            else:
                status_label = sev
                card_class = "mitre-other"
            tactic = _html_escape(r.title.replace("MITRE Coverage: ", ""))
            detail_text = _html_escape(r.detail) if r.detail else ""
            remediation_text = ""
            if r.remediation:
                remediation_text = '<div class="mitre-card-remediation"><strong>&#128295; Remediation:</strong><pre class="remediation-code">{rem}</pre></div>'.format(
                    rem=_html_escape(r.remediation))
            mitre_html += '    <div class="mitre-card {card_class}" onclick="toggleMitreCard(this)">\n'.format(
                card_class=card_class)
            mitre_html += '      <div class="mitre-card-header"><span class="mitre-tactic">{tactic}</span><span class="mitre-status">{status}</span></div>\n'.format(
                tactic=tactic, status=status_label)
            mitre_html += '      <div class="mitre-card-body" style="display:none;">\n'
            mitre_html += '        <p>{detail}</p>\n'.format(detail=detail_text)
            mitre_html += '        {remediation}\n'.format(remediation=remediation_text)
            mitre_html += '      </div>\n'
            mitre_html += '    </div>\n'
        mitre_html += '  </div>\n'
        mitre_html += '</div>\n'

    # --- Summary bar ---
    total = sum(report.summary.values())
    summary_bar = ""
    if total > 0:
        for sev in ["FAIL", "WARN", "PASS", "INFO", "SKIP"]:
            count = report.summary.get(sev, 0)
            pct = round((count / total) * 100, 1)
            if pct > 0:
                summary_bar += '<div class="bar-segment bar-{sev_lower}" title="{sev}: {count} ({pct}%)">{label}</div>'.format(
                    sev_lower=sev.lower(), sev=sev, count=count, pct=pct,
                    label="{0} {1}".format(count, sev) if pct > 8 else str(count) if pct > 4 else "")

    score = report.health_score
    score_int = int(round(score))
    if score >= 80:
        score_color = "var(--pass)"
    elif score >= 50:
        score_color = "var(--warn)"
    else:
        score_color = "var(--fail)"

    if report.skipped_count > 0:
        skipped_warning_html = '<div style="background:rgba(245,158,11,0.15);border:1px solid var(--warn);border-radius:8px;padding:10px 16px;margin:12px 0;color:var(--warn);font-size:0.95em;">&#9888;  Score excludes {n} skipped checks &mdash; re-run with sudo for accurate results.</div>'.format(n=report.skipped_count)
    else:
        skipped_warning_html = ""

    # Build the full HTML document
    html = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Security Log Audit Report &mdash; {hostname}</title>
<style>
  :root {{
    --bg-primary: #0f0f1a;
    --bg-card: rgba(22, 33, 62, 0.7);
    --bg-card-solid: #16213e;
    --bg-code: #0a1628;
    --border: rgba(15, 52, 96, 0.6);
    --text: #e0e0e0;
    --text-muted: #9ca3af;
    --text-heading: #f1f5f9;
    --accent: #e94560;
    --fail: #ef4444;
    --warn: #f59e0b;
    --pass: #22c55e;
    --info: #3b82f6;
    --skip: #6b7280;
    --sidebar-width: 220px;
    --glass-bg: rgba(22, 33, 62, 0.55);
    --glass-blur: 12px;
  }}

  * {{ margin: 0; padding: 0; box-sizing: border-box; }}

  body {{
    font-family: 'Segoe UI', -apple-system, BlinkMacSystemFont, Roboto, Oxygen, Ubuntu, sans-serif;
    background: var(--bg-primary);
    color: var(--text);
    line-height: 1.6;
  }}

  /* --- Sidebar --- */
  .sidebar {{
    position: fixed;
    top: 0;
    left: 0;
    width: var(--sidebar-width);
    height: 100vh;
    background: var(--glass-bg);
    backdrop-filter: blur(var(--glass-blur));
    -webkit-backdrop-filter: blur(var(--glass-blur));
    border-right: 1px solid var(--border);
    overflow-y: auto;
    padding: 16px 0;
    z-index: 100;
  }}
  .sidebar-title {{
    font-size: 0.75em;
    text-transform: uppercase;
    letter-spacing: 0.1em;
    color: var(--text-muted);
    padding: 8px 16px 12px;
    border-bottom: 1px solid var(--border);
    margin-bottom: 8px;
  }}
  .nav-link {{
    display: block;
    padding: 6px 16px;
    color: var(--text-muted);
    text-decoration: none;
    font-size: 0.85em;
    transition: background 0.15s, color 0.15s;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }}
  .nav-link:hover {{ background: rgba(255,255,255,0.05); color: var(--text); }}
  .nav-badge {{
    display: inline-block;
    font-size: 0.7em;
    padding: 1px 5px;
    border-radius: 3px;
    margin-left: 4px;
    color: #fff;
    font-weight: 600;
  }}
  .nav-badge-fail {{ background: var(--fail); }}
  .nav-badge-warn {{ background: var(--warn); color: #000; }}
  .nav-badge-pass {{ background: var(--pass); color: #000; }}
  .nav-badge-info {{ background: var(--info); }}
  .nav-badge-skip {{ background: var(--skip); }}

  /* --- Main content --- */
  .main {{
    margin-left: var(--sidebar-width);
    padding: 24px 32px;
    max-width: 1100px;
  }}

  /* --- Header --- */
  .header {{
    background: var(--glass-bg);
    backdrop-filter: blur(var(--glass-blur));
    -webkit-backdrop-filter: blur(var(--glass-blur));
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 28px;
    margin-bottom: 24px;
  }}
  .header h1 {{
    color: var(--accent);
    margin-bottom: 10px;
    font-size: 1.6em;
  }}
  .header-meta {{
    color: var(--text-muted);
    font-size: 0.9em;
    line-height: 1.8;
  }}
  .header-meta strong {{ color: var(--text); }}

  .score-and-summary {{
    display: flex;
    gap: 24px;
    align-items: center;
    flex-wrap: wrap;
    margin-bottom: 24px;
  }}

  /* --- Circular gauge --- */
  .score-gauge {{
    width: 120px;
    height: 120px;
    border-radius: 50%;
    display: flex;
    align-items: center;
    justify-content: center;
    flex-shrink: 0;
    position: relative;
  }}
  .score-gauge-inner {{
    width: 88px;
    height: 88px;
    border-radius: 50%;
    background: var(--bg-primary);
    display: flex;
    align-items: center;
    justify-content: center;
    flex-direction: column;
  }}
  .score-value {{
    font-size: 1.8em;
    font-weight: 700;
    line-height: 1;
  }}
  .score-label {{
    font-size: 0.65em;
    color: var(--text-muted);
    text-transform: uppercase;
    letter-spacing: 0.05em;
  }}

  /* --- Summary cards --- */
  .summary-cards {{
    display: flex;
    gap: 12px;
    flex-wrap: wrap;
    flex: 1;
  }}
  .summary-card {{
    background: var(--glass-bg);
    backdrop-filter: blur(var(--glass-blur));
    -webkit-backdrop-filter: blur(var(--glass-blur));
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 12px 18px;
    text-align: center;
    min-width: 72px;
    transition: transform 0.15s;
  }}
  .summary-card:hover {{ transform: translateY(-2px); }}
  .summary-card .number {{ font-size: 1.6em; font-weight: 700; }}
  .summary-card .label {{ font-size: 0.75em; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.05em; }}

  /* --- Distribution bar --- */
  .bar {{
    display: flex;
    height: 28px;
    border-radius: 6px;
    overflow: hidden;
    margin-bottom: 24px;
    background: rgba(255,255,255,0.05);
  }}
  .bar-segment {{
    display: flex;
    align-items: center;
    justify-content: center;
    color: #fff;
    font-size: 0.75em;
    font-weight: 600;
    transition: flex-basis 0.3s;
  }}
  .bar-fail {{ background: var(--fail); }}
  .bar-warn {{ background: var(--warn); color: #000; }}
  .bar-pass {{ background: var(--pass); color: #000; }}
  .bar-info {{ background: var(--info); }}
  .bar-skip {{ background: var(--skip); }}

  /* --- Top issues --- */
  .top-issues {{
    background: var(--glass-bg);
    backdrop-filter: blur(var(--glass-blur));
    -webkit-backdrop-filter: blur(var(--glass-blur));
    border: 1px solid var(--border);
    border-left: 4px solid var(--fail);
    border-radius: 8px;
    padding: 20px 24px;
    margin-bottom: 24px;
  }}
  .top-issues h2 {{
    color: var(--fail);
    font-size: 1.1em;
    margin-bottom: 12px;
  }}
  .top-issues ul {{
    list-style: none;
    padding: 0;
  }}
  .top-issues li {{
    padding: 4px 0;
  }}
  .top-issues li::before {{
    content: "\\2716\\0020";
    color: var(--fail);
  }}
  .top-issues a {{
    color: var(--text);
    text-decoration: none;
    border-bottom: 1px dotted var(--fail);
    transition: color 0.15s;
  }}
  .top-issues a:hover {{ color: var(--fail); }}

  /* --- Filter buttons --- */
  .filter-bar {{
    display: flex;
    gap: 8px;
    margin-bottom: 24px;
    flex-wrap: wrap;
  }}
  .filter-btn {{
    padding: 6px 16px;
    border: 1px solid var(--border);
    border-radius: 6px;
    background: var(--glass-bg);
    color: var(--text-muted);
    cursor: pointer;
    font-size: 0.85em;
    font-weight: 600;
    transition: background 0.15s, color 0.15s, border-color 0.15s;
  }}
  .filter-btn:hover {{ background: rgba(255,255,255,0.08); color: var(--text); }}
  .filter-btn.active {{
    background: rgba(255,255,255,0.12);
    color: var(--text);
    border-color: var(--accent);
  }}

  /* --- Category --- */
  .category {{
    margin-bottom: 20px;
  }}
  .cat-header {{
    background: var(--glass-bg);
    backdrop-filter: blur(var(--glass-blur));
    -webkit-backdrop-filter: blur(var(--glass-blur));
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 14px 18px;
    cursor: pointer;
    transition: background 0.15s;
    user-select: none;
  }}
  .cat-header:hover {{ background: rgba(255,255,255,0.06); }}
  .cat-title-row {{
    display: flex;
    align-items: center;
    gap: 8px;
    flex-wrap: wrap;
  }}
  .cat-chevron::before {{ content: "\\25B6"; font-size: 0.7em; color: var(--text-muted); transition: transform 0.2s; display: inline-block; }}
  .cat-header.expanded .cat-chevron::before {{ transform: rotate(90deg); }}
  .cat-name {{ font-weight: 700; font-size: 1em; color: var(--text-heading); letter-spacing: 0.04em; }}
  .cat-desc {{ font-size: 0.8em; color: var(--text-muted); margin-top: 2px; }}
  .cat-count-badge {{
    font-size: 0.7em;
    padding: 2px 8px;
    border-radius: 4px;
    font-weight: 600;
    color: #fff;
  }}
  .badge-fail {{ background: var(--fail); }}
  .badge-warn {{ background: var(--warn); color: #000; }}
  .badge-pass {{ background: var(--pass); color: #000; }}
  .badge-info {{ background: var(--info); }}
  .badge-skip {{ background: var(--skip); }}

  .cat-body {{
    padding: 4px 0 0 0;
    overflow: hidden;
    transition: max-height 0.35s ease;
  }}

  /* --- Finding --- */
  .finding {{
    background: var(--glass-bg);
    backdrop-filter: blur(var(--glass-blur));
    -webkit-backdrop-filter: blur(var(--glass-blur));
    border: 1px solid var(--border);
    border-radius: 8px;
    margin: 6px 0;
    padding: 12px 16px;
    border-left: 4px solid var(--skip);
    transition: opacity 0.2s, max-height 0.3s;
  }}
  .finding.hidden {{ display: none; }}
  .finding-fail {{ border-left-color: var(--fail); }}
  .finding-warn {{ border-left-color: var(--warn); }}
  .finding-pass {{ border-left-color: var(--pass); }}
  .finding-info {{ border-left-color: var(--info); }}
  .finding-skip {{ border-left-color: var(--skip); }}

  .finding-header.finding-compact {{ cursor: pointer; }}
  .finding-header.finding-compact:hover {{ opacity: 0.85; }}

  .badge {{
    display: inline-block;
    padding: 2px 10px;
    border-radius: 4px;
    color: #fff;
    font-weight: 700;
    font-size: 0.8em;
    margin-right: 8px;
    vertical-align: middle;
  }}
  .check-id {{ color: var(--text-muted); font-family: monospace; font-size: 0.9em; }}
  .info-summary {{ display: block; margin-top: 4px; color: var(--text-muted); font-size: 0.85em; }}
  .detail {{ margin: 10px 0; color: #c0c8d8; line-height: 1.7; }}
  .mitre {{ color: var(--text-muted); font-size: 0.82em; margin-top: 6px; }}

  /* --- Remediation --- */
  .remediation-block {{
    background: var(--bg-code);
    border: 1px solid var(--border);
    border-radius: 6px;
    margin: 10px 0;
    padding: 14px 16px;
  }}
  .remediation-header {{
    font-weight: 700;
    font-size: 0.85em;
    color: var(--warn);
    margin-bottom: 8px;
  }}
  pre.remediation-code {{
    background: transparent;
    color: #8be9fd;
    font-family: 'Fira Code', 'Consolas', 'Monaco', monospace;
    font-size: 0.85em;
    line-height: 1.6;
    white-space: pre-wrap;
    word-wrap: break-word;
    margin: 0;
    padding: 0;
    overflow-x: auto;
  }}

  /* --- Evidence --- */
  .evidence-toggle {{
    margin-top: 10px;
  }}
  .evidence-btn {{
    background: none;
    border: 1px solid var(--border);
    border-radius: 4px;
    color: var(--info);
    cursor: pointer;
    font-size: 0.8em;
    padding: 4px 12px;
    transition: background 0.15s;
  }}
  .evidence-btn:hover {{ background: rgba(59,130,246,0.1); }}
  .evidence-panel {{
    display: none;
    margin-top: 8px;
  }}
  .evidence-panel.open {{ display: block; }}
  pre.evidence-json {{
    background: var(--bg-code);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 14px;
    font-family: 'Fira Code', 'Consolas', 'Monaco', monospace;
    font-size: 0.82em;
    line-height: 1.5;
    overflow-x: auto;
    white-space: pre-wrap;
    word-wrap: break-word;
  }}
  .json-key {{ color: #bd93f9; }}
  .json-str {{ color: #f1fa8c; }}
  .json-num {{ color: #8be9fd; }}
  .json-bool {{ color: #ff79c6; }}
  .json-null {{ color: #6272a4; }}

  /* --- MITRE section --- */
  .mitre-section {{
    background: var(--glass-bg);
    backdrop-filter: blur(var(--glass-blur));
    -webkit-backdrop-filter: blur(var(--glass-blur));
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 24px;
    margin: 24px 0;
  }}
  .mitre-section h2 {{
    color: var(--text-heading);
    margin-bottom: 16px;
    font-size: 1.2em;
  }}
  .mitre-grid {{
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 12px;
  }}
  .mitre-card {{
    background: var(--bg-code);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 12px;
    cursor: pointer;
    transition: transform 0.15s, box-shadow 0.15s;
  }}
  .mitre-card:hover {{ transform: translateY(-2px); box-shadow: 0 4px 12px rgba(0,0,0,0.3); }}
  .mitre-covered {{ border-color: var(--pass); }}
  .mitre-partial {{ border-color: var(--warn); }}
  .mitre-gap {{ border-color: var(--fail); }}
  .mitre-other {{ border-color: var(--skip); }}
  .mitre-card-header {{
    display: flex;
    justify-content: space-between;
    align-items: center;
    gap: 8px;
  }}
  .mitre-tactic {{ font-weight: 600; font-size: 0.85em; }}
  .mitre-status {{
    font-size: 0.7em;
    font-weight: 700;
    padding: 2px 8px;
    border-radius: 4px;
    text-transform: uppercase;
  }}
  .mitre-covered .mitre-status {{ background: var(--pass); color: #000; }}
  .mitre-partial .mitre-status {{ background: var(--warn); color: #000; }}
  .mitre-gap .mitre-status {{ background: var(--fail); color: #fff; }}
  .mitre-other .mitre-status {{ background: var(--skip); color: #fff; }}
  .mitre-card-body {{
    margin-top: 10px;
    font-size: 0.85em;
    color: var(--text-muted);
    line-height: 1.6;
  }}
  .mitre-card-remediation {{ margin-top: 8px; }}
  .mitre-card-remediation strong {{ color: var(--warn); font-size: 0.9em; }}

  /* --- Next steps --- */
  .next-steps {{
    background: var(--glass-bg);
    backdrop-filter: blur(var(--glass-blur));
    -webkit-backdrop-filter: blur(var(--glass-blur));
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 24px;
    margin-top: 24px;
  }}
  .next-steps h2 {{
    color: var(--text-heading);
    margin-bottom: 12px;
    font-size: 1.1em;
  }}
  .next-steps p {{
    color: var(--text-muted);
    line-height: 1.8;
  }}

  /* --- Mobile --- */
  @media (max-width: 767px) {{
    .sidebar {{
      position: relative;
      width: 100%;
      height: auto;
      max-height: none;
      border-right: none;
      border-bottom: 1px solid var(--border);
      display: flex;
      flex-wrap: wrap;
      padding: 8px;
      gap: 4px;
    }}
    .sidebar-title {{
      width: 100%;
      padding: 4px 8px;
      margin-bottom: 0;
      border-bottom: none;
    }}
    .nav-link {{
      padding: 4px 10px;
      font-size: 0.78em;
    }}
    .main {{
      margin-left: 0;
      padding: 16px;
    }}
    .score-and-summary {{
      flex-direction: column;
      align-items: stretch;
    }}
    .score-gauge {{
      align-self: center;
    }}
    .mitre-grid {{
      grid-template-columns: repeat(2, 1fr);
    }}
  }}

  /* --- Print --- */
  @media print {{
    :root {{
      --bg-primary: #fff;
      --bg-card: #f8f9fa;
      --bg-card-solid: #f8f9fa;
      --bg-code: #f1f3f5;
      --border: #dee2e6;
      --text: #212529;
      --text-muted: #6c757d;
      --text-heading: #212529;
      --glass-bg: #f8f9fa;
    }}
    body {{ background: #fff; color: #212529; }}
    .sidebar {{ display: none; }}
    .main {{ margin-left: 0; }}
    .filter-bar {{ display: none; }}
    .cat-body {{ display: block !important; }}
    .finding-detail-collapsible {{ display: block !important; }}
    .evidence-panel {{ display: block !important; }}
    .mitre-card-body {{ display: block !important; }}
    .finding {{ break-inside: avoid; }}
    pre.remediation-code {{ color: #333; }}
    pre.evidence-json {{ color: #333; }}
    .json-key {{ color: #6f42c1; }}
    .json-str {{ color: #032f62; }}
    .json-num {{ color: #005cc5; }}
    .json-bool {{ color: #d73a49; }}
  }}
</style>
</head>
<body>

<nav class="sidebar">
  <div class="sidebar-title">Navigation</div>
  {sidebar_nav}
</nav>

<div class="main">

  <div class="header">
    <h1>Security Log Audit Report</h1>
    <div class="header-meta">
      <strong>Hostname:</strong> {hostname}<br>
      <strong>OS:</strong> {os_info}<br>
      <strong>Timestamp:</strong> {timestamp}<br>
      <strong>Privileges:</strong> {privileges}
    </div>
  </div>

  <div class="score-and-summary">
    <div class="score-gauge" style="background: conic-gradient({score_color} {score_deg}deg, rgba(255,255,255,0.08) {score_deg}deg 360deg);">
      <div class="score-gauge-inner">
        <div class="score-value" style="color:{score_color};">{score_int}</div>
        <div class="score-label">Health</div>
      </div>
    </div>
    <div class="summary-cards">
      <div class="summary-card"><div class="number" style="color:var(--fail);">{fail}</div><div class="label">Fail</div></div>
      <div class="summary-card"><div class="number" style="color:var(--warn);">{warn}</div><div class="label">Warn</div></div>
      <div class="summary-card"><div class="number" style="color:var(--pass);">{pass_}</div><div class="label">Pass</div></div>
      <div class="summary-card"><div class="number" style="color:var(--info);">{info}</div><div class="label">Info</div></div>
      <div class="summary-card"><div class="number" style="color:var(--skip);">{skip}</div><div class="label">Skip</div></div>
    </div>
  </div>

  <div class="bar">{summary_bar}</div>

  {skipped_warning_html}

  {top_issues_html}

  <div class="filter-bar">
    <button class="filter-btn active" onclick="filterBySeverity('ALL', this)">ALL</button>
    <button class="filter-btn" onclick="filterBySeverity('FAIL', this)">FAIL</button>
    <button class="filter-btn" onclick="filterBySeverity('WARN', this)">WARN</button>
    <button class="filter-btn" onclick="filterBySeverity('PASS', this)">PASS</button>
    <button class="filter-btn" onclick="filterBySeverity('INFO', this)">INFO</button>
  </div>

  {findings_html}

  {mitre_html}

  <div class="next-steps" id="next-steps">
    <h2>Next Steps</h2>
    <p>1. Address FAIL findings first &mdash; these represent critical security logging gaps.<br>
    2. Review WARN findings for improvements to strengthen telemetry.<br>
    3. Re-run this tool after making changes to validate fixes.<br>
    4. Share this report with your security operations team.</p>
  </div>

</div>

<script>
function toggleSection(el) {{
  var body = el.nextElementSibling;
  if (body.style.display === 'none') {{
    body.style.display = 'block';
    el.classList.remove('collapsed');
    el.classList.add('expanded');
  }} else {{
    body.style.display = 'none';
    el.classList.remove('expanded');
    el.classList.add('collapsed');
  }}
}}

function toggleFindingDetail(el) {{
  var detail = el.nextElementSibling;
  if (detail) {{
    detail.style.display = detail.style.display === 'none' ? 'block' : 'none';
  }}
}}

function toggleEvidence(btn) {{
  var panel = btn.parentElement.querySelector('.evidence-panel');
  if (panel) {{
    var isOpen = panel.classList.contains('open');
    panel.classList.toggle('open');
    btn.textContent = isOpen ? '\\u25B6 Show raw data' : '\\u25BC Hide raw data';
  }}
}}

function toggleMitreCard(el) {{
  var body = el.querySelector('.mitre-card-body');
  if (body) {{
    body.style.display = body.style.display === 'none' ? 'block' : 'none';
  }}
}}

function filterBySeverity(severity, btn) {{
  var buttons = document.querySelectorAll('.filter-btn');
  for (var i = 0; i < buttons.length; i++) {{
    buttons[i].classList.remove('active');
  }}
  btn.classList.add('active');

  var findings = document.querySelectorAll('.finding[data-severity]');
  for (var j = 0; j < findings.length; j++) {{
    if (severity === 'ALL' || findings[j].getAttribute('data-severity') === severity) {{
      findings[j].classList.remove('hidden');
    }} else {{
      findings[j].classList.add('hidden');
    }}
  }}
}}

/* Auto-collapse all-PASS categories on load */
(function() {{
  var headers = document.querySelectorAll('.cat-header.collapsed');
  /* Already collapsed via initial style; nothing extra needed */
}})();
</script>

</body>
</html>""".format(
        hostname=_html_escape(report.hostname),
        os_info=_html_escape(report.os_info),
        timestamp=_html_escape(report.timestamp),
        privileges="Elevated (root/admin)" if report.is_elevated else "Not elevated &mdash; some checks skipped",
        score_color=score_color,
        score_int=score_int,
        score_deg=int(round(score * 3.6)),
        fail=report.summary.get("FAIL", 0),
        warn=report.summary.get("WARN", 0),
        pass_=report.summary.get("PASS", 0),
        info=report.summary.get("INFO", 0),
        skip=report.summary.get("SKIP", 0),
        summary_bar=summary_bar,
        skipped_warning_html=skipped_warning_html,
        sidebar_nav=sidebar_html,
        top_issues_html=top_issues_html,
        findings_html=findings_html,
        mitre_html=mitre_html,
    )
    return html


def _build_remediation_html(remediation_text):
    """Build HTML for a remediation block with preserved whitespace."""
    return '  <div class="remediation-block"><div class="remediation-header">&#128295; Remediation</div><pre class="remediation-code">{text}</pre></div>\n'.format(
        text=_html_escape(remediation_text))


def _build_evidence_html(evidence):
    """Build HTML for a collapsible evidence panel with syntax-highlighted JSON."""
    raw_json = json.dumps(evidence, indent=2, default=str)
    highlighted = _highlight_json(_html_escape(raw_json))
    html = '  <div class="evidence-toggle">\n'
    html += '    <button class="evidence-btn" onclick="toggleEvidence(this)">&#9654; Show raw data</button>\n'
    html += '    <div class="evidence-panel"><pre class="evidence-json">{json_content}</pre></div>\n'.format(
        json_content=highlighted)
    html += '  </div>\n'
    return html


def _highlight_json(escaped_json):
    """Apply CSS class spans to JSON keys and values for syntax highlighting.

    Expects already HTML-escaped JSON text. Uses simple string scanning
    rather than regex to stay readable and avoid edge-case failures.
    """
    import re
    # Highlight keys: "key":
    result = re.sub(
        r'(&quot;)(.*?)(&quot;)\s*:',
        r'<span class="json-key">\1\2\3</span>:',
        escaped_json,
    )
    # Highlight string values (after colon or in arrays)
    result = re.sub(
        r':\s*(&quot;)(.*?)(&quot;)',
        r': <span class="json-str">\1\2\3</span>',
        result,
    )
    # Highlight numbers
    result = re.sub(
        r'(?<=: )(\d+\.?\d*)',
        r'<span class="json-num">\1</span>',
        result,
    )
    # Highlight booleans
    result = re.sub(
        r'\b(true|false)\b',
        r'<span class="json-bool">\1</span>',
        result,
    )
    # Highlight null
    result = re.sub(
        r'\bnull\b',
        r'<span class="json-null">null</span>',
        result,
    )
    return result


def _html_escape(s):
    """Basic HTML escaping."""
    if not isinstance(s, str):
        s = str(s)
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")


def save_report(content, filepath):
    """Save report content to a file."""
    try:
        with open(filepath, "w") as f:
            f.write(content)
        # If run via sudo, fix ownership so the calling user can read the file
        sudo_uid = os.environ.get("SUDO_UID")
        sudo_gid = os.environ.get("SUDO_GID")
        if sudo_uid and sudo_gid:
            os.chown(filepath, int(sudo_uid), int(sudo_gid))
        return filepath
    except Exception as e:
        print("Error saving report to {}: {}".format(filepath, e), file=sys.stderr)
        return None
