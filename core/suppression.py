"""Suppression mechanism for known-intentional findings."""

import os

try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False


def _parse_yaml_simple(text):
    """Minimal YAML parser for the .audit-suppress format (no external deps).

    Handles only the specific structure we need:
        suppress:
          - check_id: VALUE
            reason: "VALUE"
    """
    entries = []
    current = {}
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.startswith("- check_id:"):
            if current.get("check_id"):
                entries.append(current)
            current = {"check_id": stripped.split(":", 1)[1].strip().strip('"').strip("'")}
        elif stripped.startswith("check_id:"):
            if current.get("check_id"):
                entries.append(current)
            current = {"check_id": stripped.split(":", 1)[1].strip().strip('"').strip("'")}
        elif stripped.startswith("reason:"):
            current["reason"] = stripped.split(":", 1)[1].strip().strip('"').strip("'")
    if current.get("check_id"):
        entries.append(current)
    return entries


def load_suppressions(path=".audit-suppress"):
    """Load suppressed check IDs from a YAML file.

    Returns:
        set[str]: Set of check IDs to suppress. Empty set if file missing.
    """
    if not os.path.exists(path):
        return set()

    try:
        with open(path, "r") as f:
            content = f.read()
    except Exception:
        return set()

    if not content.strip():
        return set()

    if HAS_YAML:
        try:
            data = yaml.safe_load(content)
            if not isinstance(data, dict):
                return set()
            entries = data.get("suppress") or []
            return {e["check_id"] for e in entries if isinstance(e, dict) and "check_id" in e}
        except Exception:
            pass

    # Fallback to simple parser
    entries = _parse_yaml_simple(content)
    return {e["check_id"] for e in entries}


def apply_suppressions(results, suppressed_ids):
    """Mark matching results as SUPPRESSED.

    Args:
        results: List of CheckResult objects.
        suppressed_ids: Set of check IDs to suppress.

    Returns:
        list: The same list (modified in place) for convenience.
    """
    if not suppressed_ids:
        return results

    for r in results:
        if r.check_id in suppressed_ids:
            r.severity = "SUPPRESSED"
            if not r.title.endswith("[suppressed]"):
                r.title = r.title + " [suppressed]"
    return results
