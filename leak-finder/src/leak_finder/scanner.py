"""File and directory scanning for secrets."""

import os
import re
from pathlib import Path

from .models import Finding
from .patterns import SECRET_PATTERNS

# Directories to skip during scanning
SKIP_DIRS = {
    "node_modules",
    ".git",
    "venv",
    ".venv",
    "env",
    ".env",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    "dist",
    "build",
    ".next",
    ".nuxt",
    "coverage",
    ".coverage",
    "vendor",
    "target",
    # iOS / CocoaPods
    "Pods",
    # Legacy JS
    "bower_components",
    # Java / Kotlin
    ".gradle",
    # Rust
    ".cargo",
    # Xcode
    "DerivedData",
    # Ruby Bundler
    ".bundle",
    # Python tooling
    ".tox",
    ".eggs",
}

# Binary file extensions to skip
BINARY_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".webp", ".svg",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".zip", ".tar", ".gz", ".rar", ".7z",
    ".exe", ".dll", ".so", ".dylib",
    ".woff", ".woff2", ".ttf", ".eot",
    ".mp3", ".mp4", ".avi", ".mov", ".wav",
    ".pyc", ".pyo", ".class", ".o",
    ".lock", ".min.js", ".min.css",
}


def redact_secret(value: str) -> str:
    """Redact a secret value, showing only first 4 and last 4 chars."""
    if len(value) <= 8:
        return "*" * len(value)
    return f"{value[:4]}{'*' * (len(value) - 8)}{value[-4:]}"


# Patterns that indicate fake/test data
FAKE_VALUE_INDICATORS = [
    "fake", "test", "example", "placeholder", "xxx", "dummy", "sample",
    "changeme", "your_", "my_", "todo", "fixme", "replace",
]

FAKE_CREDENTIAL_PATTERNS = [
    r"user:pass@localhost",
    r"admin:password@",
    r"password123",
    r"secret12345",
    r"secret_12345",
    r"sk_test_secret",
    r"api_key_here",
]

def is_fake_value(value: str) -> tuple[bool, str | None]:
    """Check if a value looks like fake test data. Returns (is_fake, indicator_found)."""
    value_lower = value.lower()
    for indicator in FAKE_VALUE_INDICATORS:
        if indicator in value_lower:
            return True, indicator
    for pattern in FAKE_CREDENTIAL_PATTERNS:
        if re.search(pattern, value_lower):
            return True, pattern
    return False, None


# Patterns for generic pattern false-positive detection
GENERIC_PATTERN_NAMES = {"generic_secret", "generic_api_key"}

# Type annotation patterns: `password: str`, `secret: String`, `api_key?: string`
_TYPE_ANNOTATION_RE = re.compile(
    r"(?:password|passwd|pwd|secret|api_key|apikey)\??\s*:\s*"
    r"(?:str|string|String|int|bool|bytes|Optional|None|Any)\b",
    re.IGNORECASE,
)

# Property declarations: `NSString *password;`, `Password string `json:"password"``
_PROPERTY_DECL_RE = re.compile(
    r"(?:NSString|NSData|char|String|var|let|const|val)\s+\*?\s*"
    r"(?:password|passwd|pwd|secret|api_key|apikey)\b",
    re.IGNORECASE,
)

# Self-assignment / parameter forwarding: `self.password = password`
_SELF_ASSIGN_RE = re.compile(
    r"self\.\w+\s*=\s*(?:password|passwd|pwd|secret|api_key|apikey)\s*$",
    re.IGNORECASE,
)

# Env var references: `password = os.environ[...]`, `secret = process.env.SECRET`
_ENV_VAR_RE = re.compile(
    r"(?:os\.environ|os\.getenv|process\.env\b|ENV\[|getenv)\s*[\[\(.]",
    re.IGNORECASE,
)

# Function signatures: `def set_password(self, password):`
_FUNC_SIG_RE = re.compile(
    r"(?:def|func|function|fn)\s+\w*(?:password|passwd|pwd|secret|api_key|apikey)\w*\s*\(",
    re.IGNORECASE,
)

# SQL DDL: `password VARCHAR(255)`
_SQL_DDL_RE = re.compile(
    r"(?:password|passwd|pwd|secret|api_key)\s+"
    r"(?:VARCHAR|TEXT|CHAR|BLOB|INTEGER|INT|BYTEA|NVARCHAR)\s*\(",
    re.IGNORECASE,
)


def is_code_declaration(line: str) -> tuple[bool, str | None]:
    """Check if a line is a code declaration rather than a secret assignment.

    Returns (is_declaration, reason) for generic pattern matches only.
    """
    stripped = line.strip()

    if _TYPE_ANNOTATION_RE.search(stripped):
        return True, "Type annotation (e.g. password: str)"

    if _PROPERTY_DECL_RE.search(stripped):
        return True, "Property declaration (e.g. NSString *password)"

    if _SELF_ASSIGN_RE.search(stripped):
        return True, "Self-assignment / parameter forwarding"

    if _ENV_VAR_RE.search(stripped):
        return True, "Environment variable reference"

    if _FUNC_SIG_RE.search(stripped):
        return True, "Function signature"

    if _SQL_DDL_RE.search(stripped):
        return True, "SQL DDL column definition"

    return False, None


# Known non-secret keywords that appear as captured values
_LOW_ENTROPY_KEYWORDS = {
    "password", "passwd", "pwd", "secret", "string", "str",
    "none", "null", "undefined", "required", "optional",
    "true", "false", "changeme", "redacted", "encrypted",
}

# Repeating character pattern: xxxxxxxx, ********
_REPEATING_CHAR_RE = re.compile(r"^(.)\1{7,}$")

# Single plain English word: no digits/special chars, under 20 chars
_PLAIN_WORD_RE = re.compile(r"^[a-zA-Z]{1,19}$")


def is_low_entropy_value(value: str) -> tuple[bool, str | None]:
    """Check if a captured value is clearly not a secret.

    Returns (is_low_entropy, reason).
    """
    if value.lower() in _LOW_ENTROPY_KEYWORDS:
        return True, f"Known keyword: {value.lower()}"

    if _REPEATING_CHAR_RE.match(value):
        return True, "Repeating characters"

    if _PLAIN_WORD_RE.match(value):
        return True, f"Single plain word: {value}"

    return False, None


# File context indicators
DOC_INDICATORS = ["/docs/", ".md", "readme", "changelog", "example"]
TEST_INDICATORS = ["/tests/", "/test/", "test_", "_test.", ".test.", ".spec."]

def get_file_context_reason(file_path: str) -> str | None:
    """Return reasoning if file is likely docs/test, else None."""
    path_lower = file_path.lower()
    for ind in DOC_INDICATORS:
        if ind in path_lower:
            return f"File appears to be documentation ({ind} in path)"
    for ind in TEST_INDICATORS:
        if ind in path_lower:
            return f"File appears to be a test ({ind} in path)"
    return None


def is_binary_file(file_path: Path) -> bool:
    """Check if a file is binary based on extension or content."""
    if file_path.suffix.lower() in BINARY_EXTENSIONS:
        return True
    try:
        with open(file_path, "rb") as f:
            chunk = f.read(1024)
            if b"\x00" in chunk:
                return True
    except (IOError, OSError):
        return True
    return False


def get_recommendation(pattern_name: str, severity: str) -> str:
    """Generate a recommendation based on the finding type."""
    recommendations = {
        "critical": "Rotate this credential immediately and remove from codebase.",
        "high": "Rotate this credential and use environment variables instead.",
        "medium": "Consider using environment variables for this value.",
        "low": "Review if this should be in the codebase.",
        "info": "Informational finding - review as needed.",
    }
    return recommendations.get(severity, "Review this finding.")


def scan_file(file_path: str | Path, base_path: str | Path | None = None) -> list[Finding]:
    """
    Scan a single file for secrets.

    Args:
        file_path: Path to the file to scan
        base_path: Base path for relative file paths in findings

    Returns:
        List of Finding objects
    """
    file_path = Path(file_path)

    if not file_path.exists() or not file_path.is_file():
        return []

    if is_binary_file(file_path):
        return []

    findings = []

    # Determine relative path for display
    if base_path:
        try:
            display_path = str(file_path.relative_to(base_path))
        except ValueError:
            display_path = str(file_path)
    else:
        display_path = str(file_path)

    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            for line_num, line in enumerate(f, start=1):
                for pattern_name, pattern_info in SECRET_PATTERNS.items():
                    matches = pattern_info["regex"].finditer(line)
                    for match in matches:
                        # Get the matched value (use group 1 if it exists, else group 0)
                        try:
                            secret_value = match.group(1) if match.lastindex else match.group(0)
                        except IndexError:
                            secret_value = match.group(0)

                        # Build reasoning from multiple signals
                        reasons = []
                        if file_context_reason := get_file_context_reason(display_path):
                            reasons.append(file_context_reason)
                        is_fake, fake_indicator = is_fake_value(secret_value)
                        if is_fake:
                            reasons.append(f"Value looks like test data (contains '{fake_indicator}')")

                        # Additional FP checks for generic patterns only
                        if pattern_name in GENERIC_PATTERN_NAMES:
                            is_decl, decl_reason = is_code_declaration(line)
                            if is_decl:
                                reasons.append(f"Code declaration: {decl_reason}")
                            is_low, low_reason = is_low_entropy_value(secret_value)
                            if is_low:
                                reasons.append(f"Low-entropy value: {low_reason}")

                        fp_reason = "; ".join(reasons) if reasons else None

                        finding = Finding(
                            type=pattern_name,
                            severity=pattern_info["severity"],
                            file=display_path,
                            line=line_num,
                            preview=redact_secret(secret_value),
                            in_history=False,
                            rotated=False,
                            recommendation=get_recommendation(pattern_name, pattern_info["severity"]),
                            likely_false_positive=fp_reason is not None,
                            fp_reason=fp_reason,
                        )
                        findings.append(finding)
    except (IOError, OSError):
        pass

    return findings


def scan_directory(
    dir_path: str | Path,
    base_path: str | Path | None = None,
    extra_skip_dirs: set[str] | None = None,
) -> list[Finding]:
    """
    Recursively scan a directory for secrets.

    Args:
        dir_path: Path to the directory to scan
        base_path: Base path for relative file paths in findings
        extra_skip_dirs: Additional directory names to skip (merged with SKIP_DIRS)

    Returns:
        List of Finding objects
    """
    dir_path = Path(dir_path)

    if not dir_path.exists() or not dir_path.is_dir():
        return []

    if base_path is None:
        base_path = dir_path

    skip = SKIP_DIRS | extra_skip_dirs if extra_skip_dirs else SKIP_DIRS

    findings = []

    for root, dirs, files in os.walk(dir_path):
        # Filter out directories to skip
        dirs[:] = [d for d in dirs if d not in skip]

        for file_name in files:
            file_path = Path(root) / file_name
            file_findings = scan_file(file_path, base_path)
            findings.extend(file_findings)

    return findings
