"""Git utilities for cloning repositories."""

import shutil
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import Generator

from git import Repo
from git.exc import GitCommandError


def clone_repo(repo_url: str, branch: str | None = None) -> Path:
    """
    Clone a git repository to a temporary directory.

    Supports both https:// and git@ URL formats.

    Args:
        repo_url: URL of the repository to clone (https or git@ format)
        branch: Optional branch to checkout

    Returns:
        Path to the cloned repository

    Raises:
        GitCommandError: If cloning fails
    """
    temp_dir = tempfile.mkdtemp(prefix="dep_scan_")
    temp_path = Path(temp_dir)

    clone_kwargs = {"depth": 1}  # Shallow clone is sufficient for scanning dependencies
    if branch:
        clone_kwargs["branch"] = branch

    try:
        Repo.clone_from(repo_url, temp_path, **clone_kwargs)
        return temp_path
    except GitCommandError:
        # Clean up temp directory on failure
        shutil.rmtree(temp_path, ignore_errors=True)
        raise


def cleanup_repo(repo_path: Path) -> None:
    """
    Remove a cloned repository directory.

    Args:
        repo_path: Path to the repository to remove
    """
    if repo_path.exists():
        shutil.rmtree(repo_path, ignore_errors=True)


@contextmanager
def cloned_repo(repo_url: str, branch: str | None = None) -> Generator[Path, None, None]:
    """
    Context manager that clones a repo and ensures cleanup.

    Usage:
        with cloned_repo("https://github.com/user/repo") as repo_path:
            # scan the repo
            pass
        # repo is automatically cleaned up

    Args:
        repo_url: URL of the repository to clone
        branch: Optional branch to checkout

    Yields:
        Path to the cloned repository
    """
    repo_path = clone_repo(repo_url, branch)
    try:
        yield repo_path
    finally:
        cleanup_repo(repo_path)
