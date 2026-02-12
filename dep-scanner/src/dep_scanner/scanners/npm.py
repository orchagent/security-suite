"""NPM audit scanner for detecting vulnerabilities in Node.js dependencies."""

import json
import logging
import subprocess
from pathlib import Path

from ..models import Finding

logger = logging.getLogger(__name__)


def detect_npm(repo_path: Path) -> bool:
    """Check if the repository uses npm (has package.json)."""
    return (repo_path / "package.json").exists()


def run_npm_audit(repo_path: Path) -> list[Finding]:
    """
    Run npm audit and parse the results into Finding objects.

    Args:
        repo_path: Path to the repository to scan

    Returns:
        List of Finding objects representing detected vulnerabilities
    """
    if not detect_npm(repo_path):
        logger.info("No package.json found, skipping npm audit")
        return []

    findings: list[Finding] = []

    try:
        # Run npm audit with JSON output
        # Use --package-lock-only if no node_modules exists (faster, no install needed)
        has_node_modules = (repo_path / "node_modules").exists()
        has_lock_file = (repo_path / "package-lock.json").exists()

        if not has_lock_file:
            # Generate a package-lock.json if it doesn't exist
            logger.info("No package-lock.json found, generating one...")
            subprocess.run(
                ["npm", "install", "--package-lock-only", "--ignore-scripts"],
                cwd=repo_path,
                capture_output=True,
                text=True,
                timeout=120,
            )

        audit_args = ["npm", "audit", "--json"]
        if not has_node_modules:
            audit_args.append("--package-lock-only")

        result = subprocess.run(
            audit_args,
            cwd=repo_path,
            capture_output=True,
            text=True,
            timeout=120,
        )

        # npm audit returns non-zero exit code if vulnerabilities are found
        # so we can't just check returncode
        if result.stdout:
            findings = parse_npm_audit_output(result.stdout)
        elif result.stderr and "ERR!" in result.stderr:
            logger.warning(f"npm audit error: {result.stderr}")

    except subprocess.TimeoutExpired:
        logger.error("npm audit timed out")
    except FileNotFoundError:
        logger.warning("npm not found, skipping npm audit")
    except json.JSONDecodeError as e:
        logger.error(f"Failed to parse npm audit output: {e}")

    return findings


def parse_npm_audit_output(output: str) -> list[Finding]:
    """
    Parse npm audit JSON output into Finding objects.

    npm audit JSON format (v7+):
    {
        "vulnerabilities": {
            "package-name": {
                "name": "package-name",
                "severity": "high",
                "via": [...],
                "effects": [...],
                "range": ">=1.0.0 <2.0.0",
                "nodes": ["node_modules/package-name"],
                "fixAvailable": true | { "name": "...", "version": "...", ... }
            }
        },
        "metadata": {
            "vulnerabilities": { "info": 0, "low": 1, "moderate": 2, "high": 0, "critical": 0, "total": 3 },
            "dependencies": { "prod": 100, "dev": 50, "optional": 10, "peer": 5, "peerOptional": 0, "total": 165 }
        }
    }
    """
    findings: list[Finding] = []

    try:
        data = json.loads(output)
    except json.JSONDecodeError:
        logger.error("Failed to parse npm audit JSON output")
        return findings

    vulnerabilities = data.get("vulnerabilities", {})

    for pkg_name, vuln_info in vulnerabilities.items():
        # Skip if this is just a dependency path (not a direct vulnerability)
        via = vuln_info.get("via", [])
        if not via:
            continue

        # Get vulnerability details from 'via' field
        # 'via' can contain strings (reference to another package) or objects (actual CVE info)
        cve_info = None
        for v in via:
            if isinstance(v, dict):
                cve_info = v
                break

        if cve_info is None:
            # This package is vulnerable via another package, skip to avoid duplicates
            continue

        # Map npm severity to our model (npm uses "moderate" instead of "medium")
        severity = cve_info.get("severity", "unknown")
        if severity == "moderate":
            severity = "medium"

        # Get fix information
        fix_available = vuln_info.get("fixAvailable")
        if isinstance(fix_available, dict):
            fixed_in = fix_available.get("version", "unknown")
            recommendation = f"Run: npm update {fix_available.get('name', pkg_name)}"
        elif fix_available:
            fixed_in = "latest"
            recommendation = f"Run: npm update {pkg_name}"
        else:
            fixed_in = "no fix available"
            recommendation = "Review and consider replacing this package"

        # Get the vulnerable version range
        version = cve_info.get("range", vuln_info.get("range", "unknown"))

        finding = Finding(
            package=pkg_name,
            version=version,
            severity=severity,
            cve=cve_info.get("cve", cve_info.get("url", "unknown")),
            title=cve_info.get("title", "Unknown vulnerability"),
            fixed_in=fixed_in,
            recommendation=recommendation,
        )
        findings.append(finding)

    return findings


def get_npm_package_count(repo_path: Path) -> int:
    """
    Get the total number of npm packages in the dependency tree.

    Returns:
        Number of packages, or 0 if unable to determine
    """
    try:
        result = subprocess.run(
            ["npm", "ls", "--all", "--json"],
            cwd=repo_path,
            capture_output=True,
            text=True,
            timeout=60,
        )
        if result.stdout:
            data = json.loads(result.stdout)
            # Count all dependencies recursively
            return count_dependencies(data.get("dependencies", {}))
    except (subprocess.TimeoutExpired, FileNotFoundError, json.JSONDecodeError):
        pass
    return 0


def count_dependencies(deps: dict) -> int:
    """Recursively count dependencies."""
    count = len(deps)
    for dep_info in deps.values():
        if isinstance(dep_info, dict):
            count += count_dependencies(dep_info.get("dependencies", {}))
    return count
