"""FastAPI application for secrets scanner."""

import logging
import os
import uuid

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from .models import ScanRequest, DeepScanRequest, ScanResult
from .scanner import scan_directory
from .git_utils import clone_repo, clone_repo_full, scan_git_history, cleanup_repo

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="Secrets Scanner",
    description="Scans repositories for exposed secrets and credentials",
    version="0.1.0",
)

# CORS - allow common development origins
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://localhost:3000",
        "http://localhost:8000",
    ],
    allow_methods=["POST", "GET"],
    allow_headers=["*"],
)

# Check for GEMINI_API_KEY on startup (warn if missing)
if not os.environ.get("GEMINI_API_KEY"):
    logger.warning(
        "GEMINI_API_KEY environment variable not set. "
        "LLM-based false positive filtering will be disabled."
    )


@app.get("/health")
async def health():
    """Health check endpoint."""
    return {"status": "ok"}


@app.post("/scan", response_model=ScanResult)
async def scan(request: ScanRequest) -> ScanResult:
    """
    Scan a repository for exposed secrets.

    - **repo_url**: URL of the git repository to scan
    - **branch**: Optional branch to scan (defaults to default branch)
    """
    repo_path = None
    try:
        # Clone the repository
        logger.info(f"Cloning repository: {request.repo_url}")
        repo_path = clone_repo(request.repo_url, request.branch)

        # Scan the repository
        logger.info(f"Scanning repository at: {repo_path}")
        findings = scan_directory(repo_path)

        # Generate summary
        if not findings:
            summary = "No secrets found in the repository."
        else:
            critical_count = sum(1 for f in findings if f.severity == "critical")
            high_count = sum(1 for f in findings if f.severity == "high")
            summary = f"Found {len(findings)} potential secrets: {critical_count} critical, {high_count} high severity."

        return ScanResult(
            scan_id=str(uuid.uuid4()),
            mode="quick",
            findings=findings,
            summary=summary,
            offer_deep_scan=len(findings) > 0,
        )

    except Exception as e:
        logger.error(f"Scan failed: {e}")
        raise HTTPException(status_code=500, detail=f"Scan failed: {str(e)}")

    finally:
        # Clean up temp directory
        if repo_path:
            cleanup_repo(repo_path)


@app.post("/scan/deep", response_model=ScanResult)
async def scan_deep(request: DeepScanRequest) -> ScanResult:
    """
    Deep scan a repository including git history.

    - **repo_url**: URL of the git repository to scan
    - **rotated_keys**: Optional list of key prefixes that have been rotated
    """
    repo_path = None
    try:
        # Clone the repository with full history
        logger.info(f"Cloning repository with full history: {request.repo_url}")
        repo_path = clone_repo_full(request.repo_url)

        # Scan current files
        logger.info(f"Scanning current files at: {repo_path}")
        current_findings = scan_directory(repo_path)

        # Scan git history
        logger.info("Scanning git history...")
        history_findings = scan_git_history(repo_path, request.rotated_keys)

        # Mark rotated keys in current findings too
        if request.rotated_keys:
            for finding in current_findings:
                if any(finding.preview.startswith(rk[:4]) for rk in request.rotated_keys):
                    finding.rotated = True
                    finding.severity = "info"
                    finding.recommendation = "Key marked as rotated."

        # Generate summary
        total_current = len(current_findings)
        total_history = len(history_findings)
        critical_current = sum(1 for f in current_findings if f.severity == "critical")
        critical_history = sum(1 for f in history_findings if f.severity == "critical")

        if total_current == 0 and total_history == 0:
            summary = "No secrets found in current files or git history."
        else:
            summary = (
                f"Found {total_current} secrets in current files ({critical_current} critical), "
                f"{total_history} in git history ({critical_history} critical)."
            )

        return ScanResult(
            scan_id=str(uuid.uuid4()),
            mode="deep",
            findings=current_findings,
            history_findings=history_findings,
            summary=summary,
            offer_deep_scan=False,
        )

    except Exception as e:
        logger.error(f"Deep scan failed: {e}")
        raise HTTPException(status_code=500, detail=f"Deep scan failed: {str(e)}")

    finally:
        # Clean up temp directory
        if repo_path:
            cleanup_repo(repo_path)
