"""Pydantic models for dependency scanner."""

from typing import Optional
from pydantic import BaseModel, Field


class ScanRequest(BaseModel):
    """Request body for scanning a repository's dependencies."""

    repo_url: str = Field(description="URL of the git repository to scan")
    package_managers: Optional[list[str]] = Field(
        default=None, description="Package managers to scan (auto-detect if omitted)"
    )
    severity_threshold: str = Field(
        default="low",
        description="Minimum severity to include: low, medium, high, critical",
    )


class Finding(BaseModel):
    """A detected vulnerability in a dependency."""

    package: str = Field(description="Name of the vulnerable package")
    version: str = Field(description="Installed version of the package")
    severity: str = Field(description="Severity level: critical, high, medium, low")
    cve: str = Field(description="CVE identifier (e.g., CVE-2021-23337)")
    title: str = Field(description="Brief description of the vulnerability")
    fixed_in: str = Field(description="Version that fixes the vulnerability")
    recommendation: str = Field(description="Recommended action to remediate")


class ScanSummary(BaseModel):
    """Summary counts by severity."""

    critical: int = Field(default=0, description="Number of critical vulnerabilities")
    high: int = Field(default=0, description="Number of high vulnerabilities")
    medium: int = Field(default=0, description="Number of medium vulnerabilities")
    low: int = Field(default=0, description="Number of low vulnerabilities")
    total_packages_scanned: int = Field(
        default=0, description="Total number of packages scanned"
    )


class ScanResponse(BaseModel):
    """Response from a dependency scan."""

    scan_id: str = Field(description="Unique identifier for this scan")
    detected_managers: list[str] = Field(
        default_factory=list, description="Package managers detected in the repo"
    )
    findings: list[Finding] = Field(
        default_factory=list, description="List of vulnerability findings"
    )
    summary: ScanSummary = Field(
        default_factory=ScanSummary, description="Summary counts by severity"
    )
