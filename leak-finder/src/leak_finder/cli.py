"""Command-line interface for secrets scanner."""

import argparse
import json
import sys
from pathlib import Path

from .scanner import scan_directory
from .git_utils import scan_git_history
from .models import Finding


def format_findings_table(findings: list[Finding], title: str = "Findings") -> str:
    """Format findings as a readable table."""
    if not findings:
        return f"\n{title}: None\n"

    lines = [f"\n{title} ({len(findings)}):", "-" * 80]

    for f in findings:
        severity_colors = {
            "critical": "\033[91m",  # Red
            "high": "\033[93m",      # Yellow
            "medium": "\033[94m",    # Blue
            "low": "\033[90m",       # Gray
            "info": "\033[90m",      # Gray
        }
        reset = "\033[0m"
        color = severity_colors.get(f.severity, "")

        status = ""
        if f.rotated:
            status = " [ROTATED]"
        if f.in_history:
            status += " [HISTORY]"

        lines.append(
            f"{color}[{f.severity.upper():8}]{reset} {f.type}"
            f"{status}"
        )
        lines.append(f"           File: {f.file}:{f.line}")
        lines.append(f"           Preview: {f.preview}")
        lines.append(f"           {f.recommendation}")
        lines.append("")

    return "\n".join(lines)


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description="Scan directories for exposed secrets and credentials.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python -m leak_finder.cli ./my-project
  python -m leak_finder.cli ./my-project --deep
  python -m leak_finder.cli ./my-project --rotated AKIA1234,sk_live_abc
  python -m leak_finder.cli ./my-project --json
        """,
    )
    parser.add_argument(
        "path",
        type=str,
        help="Path to directory to scan",
    )
    parser.add_argument(
        "--deep",
        action="store_true",
        help="Enable deep scan including git history",
    )
    parser.add_argument(
        "--rotated",
        type=str,
        default="",
        help="Comma-separated list of rotated key prefixes",
    )
    parser.add_argument(
        "--exclude",
        type=str,
        default="",
        help="Comma-separated list of directory names to skip during scanning",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        dest="json_output",
        help="Output results as JSON",
    )

    args = parser.parse_args()

    # Validate path
    scan_path = Path(args.path)
    if not scan_path.exists():
        print(f"Error: Path does not exist: {args.path}", file=sys.stderr)
        sys.exit(1)
    if not scan_path.is_dir():
        print(f"Error: Path is not a directory: {args.path}", file=sys.stderr)
        sys.exit(1)

    # Parse rotated keys
    rotated_keys = [k.strip() for k in args.rotated.split(",") if k.strip()]

    # Parse exclude dirs
    extra_skip_dirs = {d.strip() for d in args.exclude.split(",") if d.strip()} or None

    # Scan current files
    findings = scan_directory(scan_path, extra_skip_dirs=extra_skip_dirs)

    # Apply rotated keys to current findings
    if rotated_keys:
        for finding in findings:
            if any(finding.preview.startswith(rk[:4]) for rk in rotated_keys):
                finding.rotated = True
                finding.severity = "info"
                finding.recommendation = "Key marked as rotated."

    # Deep scan if requested
    history_findings = []
    if args.deep:
        git_dir = scan_path / ".git"
        if git_dir.exists():
            history_findings = scan_git_history(scan_path, rotated_keys)
        else:
            print("Warning: --deep specified but no .git directory found", file=sys.stderr)

    # Output results
    if args.json_output:
        result = {
            "findings": [f.model_dump() for f in findings],
            "history_findings": [f.model_dump() for f in history_findings],
            "summary": {
                "total_current": len(findings),
                "total_history": len(history_findings),
                "critical": sum(1 for f in findings + history_findings if f.severity == "critical"),
            },
        }
        print(json.dumps(result, indent=2))
    else:
        print(format_findings_table(findings, "Current Files"))
        if args.deep:
            print(format_findings_table(history_findings, "Git History"))

        # Summary
        total = len(findings) + len(history_findings)
        critical = sum(1 for f in findings + history_findings if f.severity == "critical")
        print(f"\nSummary: {total} findings ({critical} critical)")

    # Exit code
    has_critical = any(f.severity == "critical" for f in findings + history_findings)
    sys.exit(1 if has_critical else 0)


if __name__ == "__main__":
    main()
