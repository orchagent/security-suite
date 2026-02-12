"""FastAPI application for dependency scanner."""

import logging

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from git.exc import GitCommandError

from .models import ScanRequest, ScanResponse
from .scanner import scan_repository

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="Dependency Scanner",
    description="Scans repositories for known vulnerabilities in dependencies",
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


@app.get("/health")
async def health():
    """Health check endpoint."""
    return {"status": "ok"}


@app.post("/scan", response_model=ScanResponse)
async def scan(request: ScanRequest) -> ScanResponse:
    """
    Scan a repository for dependency vulnerabilities.

    - **repo_url**: URL of the git repository to scan
    - **package_managers**: Optional list of package managers to scan
    - **severity_threshold**: Minimum severity to include (low/medium/high/critical)
    """
    try:
        logger.info(f"Scanning repository: {request.repo_url}")

        response = scan_repository(
            repo_url=request.repo_url,
            package_managers=request.package_managers,
            severity_threshold=request.severity_threshold,
        )

        return response

    except GitCommandError as e:
        logger.error(f"Failed to clone repository: {e}")
        raise HTTPException(
            status_code=400,
            detail=f"Failed to clone repository: {request.repo_url}",
        )
    except Exception as e:
        logger.error(f"Scan failed: {e}")
        raise HTTPException(status_code=500, detail=f"Scan failed: {str(e)}")
