#!/usr/bin/env python3
"""
Sandbox entrypoint for leak-finder.
Reads scan parameters from stdin JSON, scans repository for secrets, outputs JSON to stdout.
"""

import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "src"))

from leak_finder.scanner import scan_directory
from leak_finder.git_utils import clone_repo, clone_repo_full, scan_git_history, cleanup_repo
from leak_finder.llm_analyzer import validate_findings_sync


def main():
    try:
        input_data = json.load(sys.stdin)
    except json.JSONDecodeError as e:
        print(json.dumps({"error": f"Invalid JSON input: {e}"}))
        sys.exit(1)

    # Support multiple input formats:
    # - repo_url: Clone and scan a remote repository
    # - path/directory: Scan a local directory
    repo_url = input_data.get("repo_url")
    local_path = input_data.get("path") or input_data.get("directory")

    if not repo_url and not local_path:
        print(json.dumps({
            "error": "Missing required input. Provide either 'repo_url' (GitHub URL) or 'path'/'directory' (local path)",
            "examples": {
                "remote": {"repo_url": "https://github.com/user/repo"},
                "local": {"path": "."},
            }
        }))
        sys.exit(1)

    branch = input_data.get("branch")
    deep_scan = input_data.get("deep_scan", False)
    rotated_keys = input_data.get("rotated_keys", [])
    exclude = set(input_data.get("exclude", []))

    repo_path = None
    is_local = False
    try:
        if local_path:
            # Use local directory directly
            local_dir = Path(local_path).resolve()
            if not local_dir.exists():
                print(json.dumps({"error": f"Path does not exist: {local_path}"}))
                sys.exit(1)
            if not local_dir.is_dir():
                print(json.dumps({"error": f"Path is not a directory: {local_path}"}))
                sys.exit(1)
            repo_path = str(local_dir)
            is_local = True
        else:
            # Clone repository
            if deep_scan:
                repo_path = clone_repo_full(repo_url)
            else:
                repo_path = clone_repo(repo_url, branch)

        # Scan current files
        findings = scan_directory(repo_path, extra_skip_dirs=exclude or None)

        # Mark rotated keys
        for finding in findings:
            for rk in rotated_keys:
                if len(rk) >= 4 and finding.preview.startswith(rk[:4]):
                    finding.rotated = True
                    finding.severity = "info"
                    finding.recommendation = "Key marked as rotated."

        # LLM validation (optional)
        api_key = os.environ.get("GEMINI_API_KEY")
        if api_key and findings:
            try:
                findings = validate_findings_sync(findings)
            except Exception:
                pass

        # Deep scan: git history
        history_findings = []
        if deep_scan:
            history_findings = scan_git_history(repo_path, rotated_keys)
            if api_key and history_findings:
                try:
                    history_findings = validate_findings_sync(history_findings)
                except Exception:
                    pass

        # Build result
        total_current = len(findings)
        total_history = len(history_findings)
        critical_current = sum(1 for f in findings if f.severity == "critical")
        critical_history = sum(1 for f in history_findings if f.severity == "critical")

        if total_current == 0 and total_history == 0:
            summary = "No secrets found."
        elif deep_scan:
            summary = f"Found {total_current} secrets in current files ({critical_current} critical), {total_history} in git history ({critical_history} critical)."
        else:
            summary = f"Found {total_current} potential secrets ({critical_current} critical)."

        result = {
            "mode": "deep" if deep_scan else "quick",
            "findings": [f.model_dump() for f in findings],
            "history_findings": [f.model_dump() for f in history_findings] if deep_scan else [],
            "summary": summary,
            "stats": {
                "total_current": total_current,
                "total_history": total_history,
                "critical_current": critical_current,
                "critical_history": critical_history,
            },
        }
        print(json.dumps(result))

    except Exception as e:
        print(json.dumps({"error": str(e)}))
        sys.exit(1)
    finally:
        # Only cleanup if we cloned a repo (don't delete local directories)
        if repo_path and not is_local:
            cleanup_repo(repo_path)


if __name__ == "__main__":
    main()
