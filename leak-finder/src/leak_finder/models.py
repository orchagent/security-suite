"""Pydantic models for secrets scanner."""

from typing import Optional
from pydantic import BaseModel, Field


class Finding(BaseModel):
    """A detected secret or credential in the codebase."""

    type: str = Field(description="Type of secret (e.g., 'aws_access_key', 'github_pat')")
    severity: str = Field(description="Severity level: critical, high, medium, low, info")
    file: str = Field(description="File path where the secret was found")
    line: int = Field(description="Line number where the secret was found")
    preview: str = Field(description="Redacted preview of the secret (first 4 and last 4 chars)")
    in_history: bool = Field(default=False, description="Whether the secret was found in git history")
    rotated: bool = Field(default=False, description="Whether the secret has been marked as rotated")
    recommendation: str = Field(default="", description="Recommended action to remediate")
    likely_false_positive: bool = Field(default=False, description="Whether this is likely a false positive")
    fp_reason: Optional[str] = Field(default=None, description="Explanation of why this might be a false positive")


class ScanRequest(BaseModel):
    """Request body for scanning a repository."""

    repo_url: str = Field(description="URL of the git repository to scan")
    branch: Optional[str] = Field(default=None, description="Branch to scan (defaults to default branch)")


class DeepScanRequest(BaseModel):
    """Request body for deep scanning a repository including git history."""

    repo_url: str = Field(description="URL of the git repository to scan")
    rotated_keys: Optional[list[str]] = Field(default=None, description="List of keys that have been rotated")


class ScanResult(BaseModel):
    """Result of a repository scan."""

    scan_id: str = Field(description="Unique identifier for this scan")
    mode: str = Field(description="Scan mode: 'quick' or 'deep'")
    findings: list[Finding] = Field(default_factory=list, description="List of findings from current files")
    history_findings: list[Finding] = Field(default_factory=list, description="List of findings from git history")
    summary: str = Field(description="Human-readable summary of the scan results")
    offer_deep_scan: bool = Field(default=False, description="Whether to offer a deep scan")
