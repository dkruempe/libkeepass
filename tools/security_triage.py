#!/usr/bin/env python3
"""Render a Markdown triage report from GitHub code-scanning alerts.

Usage:
    gh api --paginate /repos/OWNER/REPO/code-scanning/alerts?state=open \
        > alerts.json
    tools/security_triage.py alerts.json > security-triage.md

The report covers CodeQL and any SARIF-producing workflow (including the OSV
dependency scan) because both upload to the same code-scanning API.
"""

from __future__ import annotations

import json
import sys
from collections import Counter


def alert_rows(alerts: list[dict]) -> list[tuple[str, str, str, str, str]]:
    rows = []
    for alert in alerts:
        rule = alert.get("rule") or {}
        severity = (rule.get("security_severity_level") or rule.get("severity") or "unknown").lower()
        tool = ((alert.get("tool") or {}).get("name")) or "unknown"
        instance = alert.get("most_recent_instance") or {}
        location = instance.get("location") or {}
        path = location.get("path") or "?"
        line = location.get("start_line")
        where = f"{path}:{line}" if line else path
        description = rule.get("description") or rule.get("id") or "unnamed rule"
        url = alert.get("html_url") or ""
        rows.append((severity, tool, description, where, url))
    return sorted(rows, key=lambda row: (row[0], row[1], row[3]))


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__, file=sys.stderr)
        return 2

    with open(sys.argv[1], encoding="utf-8") as handle:
        payload = json.load(handle)

    if isinstance(payload, dict):
        print(f"# Security triage\n\nGitHub API error: `{payload.get('message', payload)}`\n")
        return 0

    alerts = list(payload)
    print("# Security triage\n")
    print(f"Open code-scanning alerts: **{len(alerts)}**\n")

    if not alerts:
        print("No open CodeQL or dependency-scanning alerts.\n")
        return 0

    rows = alert_rows(alerts)
    counts = Counter(row[0] for row in rows)
    print("| Severity | Count |")
    print("|---|---:|")
    for severity in ("critical", "high", "medium", "low", "unknown"):
        if counts.get(severity):
            print(f"| {severity} | {counts[severity]} |")
    print()

    print("| Severity | Tool | Finding | Location | Link |")
    print("|---|---|---|---|---|")
    for severity, tool, description, where, url in rows:
        link = f"[details]({url})" if url else ""
        print(f"| {severity} | {tool} | {description} | `{where}` | {link} |")
    print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
