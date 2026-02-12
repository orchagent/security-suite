"""pip-audit scanner for detecting vulnerabilities in Python dependencies."""

import json
import logging
import subprocess
from pathlib import Path

from ..models import Finding

logger = logging.getLogger(__name__)


def detect_python_deps(repo_path: Path) -> bool:
    """Check if the repository has Python dependency files."""
    return (
        (repo_path / "requirements.txt").exists()
        or (repo_path / "pyproject.toml").exists()
        or (repo_path / "Pipfile").exists()
        or (repo_path / "setup.py").exists()
    )


def run_pip_audit(repo_path: Path) -> list[Finding]:
    """
    Run pip-audit and parse the results into Finding objects.

    Args:
        repo_path: Path to the repository to scan

    Returns:
        List of Finding objects representing detected vulnerabilities
    """
    if not detect_python_deps(repo_path):
        logger.info("No Python dependency files found, skipping pip-audit")
        return []

    findings: list[Finding] = []

    try:
        # Determine which file to use for pip-audit
        audit_args = ["pip-audit", "--format", "json"]

        # pip-audit can use different input sources
        if (repo_path / "requirements.txt").exists():
            audit_args.extend(["--requirement", str(repo_path / "requirements.txt")])
        elif (repo_path / "pyproject.toml").exists():
            # pip-audit can scan pyproject.toml directly with --requirement flag
            # But we need to try without it first (it auto-detects)
            pass  # Let pip-audit auto-detect
        elif (repo_path / "Pipfile").exists():
            # pip-audit doesn't directly support Pipfile, need to use Pipfile.lock
            if (repo_path / "Pipfile.lock").exists():
                # Use pipenv to export requirements
                pass  # Skip for now, complex setup
            else:
                logger.info("Pipfile found but no Pipfile.lock, skipping pip-audit")
                return []

        result = subprocess.run(
            audit_args,
            cwd=repo_path,
            capture_output=True,
            text=True,
            timeout=120,
        )

        # pip-audit returns exit code 1 when vulnerabilities are found
        if result.stdout:
            findings = parse_pip_audit_output(result.stdout)
        elif result.stderr:
            # Check if pip-audit is not installed
            if "No module named" in result.stderr or "not found" in result.stderr.lower():
                logger.warning("pip-audit not installed, skipping Python dependency scan")
            else:
                logger.warning(f"pip-audit error: {result.stderr}")

    except subprocess.TimeoutExpired:
        logger.error("pip-audit timed out")
    except FileNotFoundError:
        logger.warning("pip-audit not found, skipping Python dependency scan")
    except json.JSONDecodeError as e:
        logger.error(f"Failed to parse pip-audit output: {e}")

    return findings


def parse_pip_audit_output(output: str) -> list[Finding]:
    """
    Parse pip-audit JSON output into Finding objects.

    pip-audit JSON format:
    {
        "dependencies": [
            {
                "name": "requests",
                "version": "2.25.0",
                "vulns": [
                    {
                        "id": "GHSA-xxxx-xxxx-xxxx",
                        "fix_versions": ["2.31.0"],
                        "aliases": ["CVE-2023-32681"],
                        "description": "Vulnerability description..."
                    }
                ]
            }
        ],
        "fixes": []
    }

    Or for vulnerable packages:
    [
        {
            "name": "package-name",
            "version": "1.0.0",
            "vulns": [...]
        }
    ]
    """
    findings: list[Finding] = []

    try:
        data = json.loads(output)
    except json.JSONDecodeError:
        logger.error("Failed to parse pip-audit JSON output")
        return findings

    # Handle both array and object formats
    if isinstance(data, list):
        dependencies = data
    elif isinstance(data, dict):
        dependencies = data.get("dependencies", [])
    else:
        return findings

    for dep in dependencies:
        pkg_name = dep.get("name", "unknown")
        pkg_version = dep.get("version", "unknown")
        vulns = dep.get("vulns", [])

        for vuln in vulns:
            # Get CVE from aliases or use the primary ID
            vuln_id = vuln.get("id", "unknown")
            aliases = vuln.get("aliases", [])

            # Prefer CVE identifier if available
            cve = vuln_id
            for alias in aliases:
                if alias.startswith("CVE-"):
                    cve = alias
                    break

            # Get fix version
            fix_versions = vuln.get("fix_versions", [])
            if fix_versions:
                fixed_in = fix_versions[0]
                recommendation = f"Run: pip install --upgrade {pkg_name}>={fixed_in}"
            else:
                fixed_in = "no fix available"
                recommendation = "Review and consider replacing this package"

            # pip-audit doesn't provide severity directly, derive from source
            # GHSA advisories typically include severity in the API, but not in pip-audit output
            # Default to "medium" or try to infer from description
            severity = determine_severity(vuln)

            # Get title from description (first line or truncated)
            description = vuln.get("description", "Unknown vulnerability")
            title = description.split("\n")[0][:100] if description else "Unknown vulnerability"

            finding = Finding(
                package=pkg_name,
                version=pkg_version,
                severity=severity,
                cve=cve,
                title=title,
                fixed_in=fixed_in,
                recommendation=recommendation,
            )
            findings.append(finding)

    return findings


def determine_severity(vuln: dict) -> str:
    """
    Determine severity from vulnerability data.

    pip-audit doesn't always include severity, so we default to 'medium'
    or try to infer from the vulnerability ID or description.
    """
    # Check if severity is directly provided
    if "severity" in vuln:
        return vuln["severity"].lower()

    # PYSEC advisories often have severity
    vuln_id = vuln.get("id", "")
    description = vuln.get("description", "").lower()

    # Try to infer from description keywords
    if any(word in description for word in ["remote code execution", "rce", "critical"]):
        return "critical"
    elif any(word in description for word in ["arbitrary code", "sql injection", "command injection"]):
        return "high"
    elif any(word in description for word in ["denial of service", "dos", "crash"]):
        return "medium"

    # Default to medium if unknown
    return "medium"


def get_pip_package_count(repo_path: Path) -> int:
    """
    Get the total number of Python packages from requirements.

    Returns:
        Number of packages, or 0 if unable to determine
    """
    count = 0

    # Count from requirements.txt
    requirements_file = repo_path / "requirements.txt"
    if requirements_file.exists():
        try:
            with open(requirements_file) as f:
                for line in f:
                    line = line.strip()
                    # Skip comments and empty lines
                    if line and not line.startswith("#") and not line.startswith("-"):
                        count += 1
        except Exception:
            pass

    # Could also parse pyproject.toml but that's more complex
    return count
