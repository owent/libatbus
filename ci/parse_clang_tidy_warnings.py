#!/usr/bin/env python3
# Copyright 2026 atframework
# Parse clang-tidy build log and generate a markdown report with deduplicated warnings.

import argparse
import re
import sys
from pathlib import Path


def parse_warnings(log_content: str) -> list[dict]:
    """Extract clang-tidy warnings from build log content."""
    # Match lines like: /path/to/file.cpp:123:45: warning: message [check-name]
    pattern = re.compile(
        r"^(.+?):(\d+):(\d+):\s+warning:\s+(.+?)\s+\[([a-zA-Z0-9,._-]+)\]\s*$"
    )
    warnings = []
    for line in log_content.splitlines():
        m = pattern.match(line.strip())
        if m:
            warnings.append(
                {
                    "file": m.group(1),
                    "line": int(m.group(2)),
                    "col": int(m.group(3)),
                    "message": m.group(4),
                    "check": m.group(5),
                }
            )
    return warnings


def deduplicate(warnings: list[dict]) -> list[dict]:
    """Deduplicate warnings by (file, line, check)."""
    seen = set()
    unique = []
    for w in warnings:
        key = (w["file"], w["line"], w["check"])
        if key not in seen:
            seen.add(key)
            unique.append(w)
    return unique


def normalize_path(filepath: str, workspace: str = "") -> str:
    """Normalize file path relative to workspace root."""
    if workspace and filepath.startswith(workspace):
        rel = filepath[len(workspace) :].lstrip("/")
        return rel
    return filepath


def generate_report(warnings: list[dict], workspace: str = "") -> str:
    """Generate a markdown report from deduplicated warnings."""
    lines = ["# Clang-Tidy Warning Report", ""]

    if not warnings:
        lines.append("No warnings found. :tada:")
        return "\n".join(lines)

    lines.append(f"**Total unique warnings: {len(warnings)}**")
    lines.append("")

    # Group by check name
    by_check: dict[str, list[dict]] = {}
    for w in warnings:
        check = w["check"]
        by_check.setdefault(check, []).append(w)

    lines.append("## Summary by Check")
    lines.append("")
    lines.append("| Check | Count |")
    lines.append("|-------|-------|")
    for check in sorted(by_check.keys()):
        lines.append(f"| `{check}` | {len(by_check[check])} |")
    lines.append("")

    # Detailed list
    lines.append("## Details")
    lines.append("")
    for w in warnings:
        fpath = normalize_path(w["file"], workspace)
        lines.append(
            f"- `{fpath}:{w['line']}:{w['col']}` — {w['message']} [`{w['check']}`]"
        )
    lines.append("")

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="Parse clang-tidy warnings from build log")
    parser.add_argument("--build_log", required=True, help="Path to the build log file")
    parser.add_argument("--output", default="", help="Path to write the markdown report")
    parser.add_argument("--workspace", default="", help="Workspace root for path normalization")
    parser.add_argument(
        "--count-only",
        action="store_true",
        help="Only print the deduplicated warning count",
    )
    args = parser.parse_args()

    log_path = Path(args.build_log)
    if not log_path.exists():
        print(f"Build log not found: {log_path}", file=sys.stderr)
        if args.count_only:
            print(0)
        sys.exit(0)

    log_content = log_path.read_text(encoding="utf-8", errors="replace")
    warnings = parse_warnings(log_content)
    unique_warnings = deduplicate(warnings)

    if args.count_only:
        print(len(unique_warnings))
        return

    report = generate_report(unique_warnings, workspace=args.workspace)

    if args.output:
        out_path = Path(args.output)
        out_path.write_text(report, encoding="utf-8")
        print(f"Report written to: {out_path}")
        print(f"TOTAL_WARNINGS={len(unique_warnings)}")
        print(f"REPORT_PATH={out_path}")
    else:
        print(report)


if __name__ == "__main__":
    main()
