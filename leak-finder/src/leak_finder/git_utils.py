"""Git utilities for cloning and history scanning."""

import shutil
import tempfile
from pathlib import Path

from git import Repo

from .models import Finding
from .patterns import SECRET_PATTERNS
from .scanner import redact_secret, get_recommendation


def clone_repo(repo_url: str, branch: str | None = None) -> Path:
    """
    Clone a git repository to a temporary directory.

    Args:
        repo_url: URL of the repository to clone
        branch: Optional branch to checkout

    Returns:
        Path to the cloned repository
    """
    temp_dir = tempfile.mkdtemp(prefix="secrets_scan_")
    temp_path = Path(temp_dir)

    clone_kwargs = {"depth": 1}  # Shallow clone for quick scan
    if branch:
        clone_kwargs["branch"] = branch

    Repo.clone_from(repo_url, temp_path, **clone_kwargs)
    return temp_path


def clone_repo_full(repo_url: str) -> Path:
    """
    Clone a git repository with full history for deep scanning.

    Args:
        repo_url: URL of the repository to clone

    Returns:
        Path to the cloned repository
    """
    temp_dir = tempfile.mkdtemp(prefix="secrets_scan_deep_")
    temp_path = Path(temp_dir)

    Repo.clone_from(repo_url, temp_path)
    return temp_path


def cleanup_repo(repo_path: Path) -> None:
    """
    Remove a cloned repository directory.

    Args:
        repo_path: Path to the repository to remove
    """
    if repo_path.exists():
        shutil.rmtree(repo_path, ignore_errors=True)


def scan_git_history(repo_path: Path, rotated_keys: list[str] | None = None) -> list[Finding]:
    """
    Scan git history for secrets using git log -p.

    Args:
        repo_path: Path to the git repository
        rotated_keys: List of key prefixes that have been rotated

    Returns:
        List of Finding objects found in git history
    """
    if rotated_keys is None:
        rotated_keys = []

    findings = []
    repo = Repo(repo_path)

    # Get all commits with diffs
    for commit in repo.iter_commits("--all"):
        try:
            # Get the diff for this commit
            if commit.parents:
                diffs = commit.diff(commit.parents[0], create_patch=True)
            else:
                # Initial commit - diff against empty tree
                diffs = commit.diff(None, create_patch=True)

            for diff in diffs:
                if diff.diff:
                    try:
                        diff_text = diff.diff.decode("utf-8", errors="ignore")
                    except (AttributeError, UnicodeDecodeError):
                        continue

                    # Parse the diff looking for added lines with secrets
                    file_path = diff.b_path or diff.a_path or "unknown"

                    for line_num, line in enumerate(diff_text.split("\n"), start=1):
                        # Only check added lines (starting with +)
                        if not line.startswith("+"):
                            continue

                        for pattern_name, pattern_info in SECRET_PATTERNS.items():
                            matches = pattern_info["regex"].finditer(line)
                            for match in matches:
                                try:
                                    secret_value = match.group(1) if match.lastindex else match.group(0)
                                except IndexError:
                                    secret_value = match.group(0)

                                # Check if this key has been rotated
                                is_rotated = any(
                                    secret_value.startswith(rk) for rk in rotated_keys
                                )

                                finding = Finding(
                                    type=pattern_name,
                                    severity="info" if is_rotated else pattern_info["severity"],
                                    file=f"{file_path} (commit {commit.hexsha[:8]})",
                                    line=line_num,
                                    preview=redact_secret(secret_value),
                                    in_history=True,
                                    rotated=is_rotated,
                                    recommendation=get_recommendation(pattern_name, pattern_info["severity"]) if not is_rotated else "Key marked as rotated.",
                                )
                                findings.append(finding)
        except Exception:
            # Skip problematic commits
            continue

    return findings
