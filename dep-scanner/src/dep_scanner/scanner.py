"""Unified scanner orchestration module."""

import logging
import uuid
from pathlib import Path

from .git_utils import cloned_repo
from .models import Finding, ScanResponse, ScanSummary
from .scanners.npm import detect_npm, run_npm_audit, get_npm_package_count
from .scanners.pip import detect_python_deps, run_pip_audit, get_pip_package_count

logger = logging.getLogger(__name__)

# Severity levels in order from lowest to highest
SEVERITY_ORDER = ["low", "medium", "high", "critical"]


def scan_repository(
    repo_url: str | None = None,
    local_path: str | Path | None = None,
    package_managers: list[str] | None = None,
    severity_threshold: str = "low",
) -> ScanResponse:
    """
    Scan a repository for dependency vulnerabilities.

    Args:
        repo_url: URL of the git repository to scan (mutually exclusive with local_path)
        local_path: Local directory path to scan (mutually exclusive with repo_url)
        package_managers: Optional list of package managers to scan (auto-detect if None)
        severity_threshold: Minimum severity to include (low/medium/high/critical)

    Returns:
        ScanResponse with findings and summary
    """
    if not repo_url and not local_path:
        raise ValueError("Either repo_url or local_path must be provided")

    scan_id = str(uuid.uuid4())
    all_findings: list[Finding] = []
    detected_managers: list[str] = []
    total_packages = 0

    if local_path:
        # Scan local directory directly
        repo_path = Path(local_path).resolve()
        if not repo_path.exists():
            raise ValueError(f"Path does not exist: {local_path}")
        if not repo_path.is_dir():
            raise ValueError(f"Path is not a directory: {local_path}")

        all_findings, detected_managers, total_packages = _run_scanners(
            repo_path, package_managers
        )
    else:
        # Clone and scan remote repository
        with cloned_repo(repo_url) as repo_path:
            all_findings, detected_managers, total_packages = _run_scanners(
                repo_path, package_managers
            )

    # Filter findings by severity threshold
    filtered_findings = _filter_by_severity(all_findings, severity_threshold)

    # Build summary from filtered findings
    summary = _build_summary(filtered_findings, total_packages)

    return ScanResponse(
        scan_id=scan_id,
        detected_managers=detected_managers,
        findings=filtered_findings,
        summary=summary,
    )


def _run_scanners(
    repo_path: Path, package_managers: list[str] | None
) -> tuple[list[Finding], list[str], int]:
    """Run the appropriate scanners on a directory."""
    all_findings: list[Finding] = []
    detected_managers: list[str] = []
    total_packages = 0

    # Determine which scanners to run
    scanners_to_run = _determine_scanners(repo_path, package_managers)

    # Run each scanner
    for manager in scanners_to_run:
        logger.info(f"Running {manager} scanner...")

        if manager == "npm":
            findings = run_npm_audit(repo_path)
            all_findings.extend(findings)
            detected_managers.append("npm")
            total_packages += get_npm_package_count(repo_path)

        elif manager == "pip":
            findings = run_pip_audit(repo_path)
            all_findings.extend(findings)
            detected_managers.append("pip")
            total_packages += get_pip_package_count(repo_path)

    return all_findings, detected_managers, total_packages


def _filter_by_severity(
    findings: list[Finding], threshold: str
) -> list[Finding]:
    """
    Filter findings to only include those at or above the severity threshold.

    Args:
        findings: List of all findings
        threshold: Minimum severity to include (low/medium/high/critical)

    Returns:
        Filtered list of findings
    """
    threshold = threshold.lower()
    if threshold not in SEVERITY_ORDER:
        logger.warning(f"Invalid severity threshold '{threshold}', defaulting to 'low'")
        threshold = "low"

    threshold_index = SEVERITY_ORDER.index(threshold)

    return [
        finding
        for finding in findings
        if SEVERITY_ORDER.index(finding.severity.lower()) >= threshold_index
    ]


def _determine_scanners(
    repo_path: Path, package_managers: list[str] | None
) -> list[str]:
    """
    Determine which scanners to run based on request and repo contents.

    Args:
        repo_path: Path to the cloned repository
        package_managers: Optional list of requested package managers

    Returns:
        List of package manager names to scan
    """
    if package_managers:
        # User specified which managers to scan
        return package_managers

    # Auto-detect based on files present
    scanners = []

    if detect_npm(repo_path):
        scanners.append("npm")

    if detect_python_deps(repo_path):
        scanners.append("pip")

    return scanners


def _build_summary(findings: list[Finding], total_packages: int) -> ScanSummary:
    """
    Build a summary of findings by severity.

    Args:
        findings: List of all findings
        total_packages: Total number of packages scanned

    Returns:
        ScanSummary with counts by severity
    """
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}

    for finding in findings:
        severity = finding.severity.lower()
        if severity in counts:
            counts[severity] += 1

    return ScanSummary(
        critical=counts["critical"],
        high=counts["high"],
        medium=counts["medium"],
        low=counts["low"],
        total_packages_scanned=total_packages,
    )
