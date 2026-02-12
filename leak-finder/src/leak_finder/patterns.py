"""Secret detection patterns for common credential types."""

import re

# Each pattern has: regex (compiled), severity, description
SECRET_PATTERNS: dict[str, dict] = {
    # AWS
    "aws_access_key_id": {
        "regex": re.compile(r"(?:A3T[A-Z0-9]|AKIA|ABIA|ACCA|AGPA|AIDA|AIPA|ANPA|ANVA|APKA|AROA|ASCA|ASIA)[A-Z0-9]{16}"),
        "severity": "critical",
        "description": "AWS Access Key ID",
    },
    "aws_secret_access_key": {
        "regex": re.compile(r"(?i)aws[_\-\.]?secret[_\-\.]?access[_\-\.]?key['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?"),
        "severity": "critical",
        "description": "AWS Secret Access Key",
    },
    # Stripe
    "stripe_live_key": {
        "regex": re.compile(r"sk_live_[A-Za-z0-9]{24,}"),
        "severity": "critical",
        "description": "Stripe Live Secret Key",
    },
    "stripe_test_key": {
        "regex": re.compile(r"sk_test_[A-Za-z0-9]{24,}"),
        "severity": "low",
        "description": "Stripe Test Secret Key",
    },
    "stripe_publishable_live": {
        "regex": re.compile(r"pk_live_[A-Za-z0-9]{24,}"),
        "severity": "medium",
        "description": "Stripe Live Publishable Key",
    },
    # GitHub
    "github_pat": {
        "regex": re.compile(r"ghp_[A-Za-z0-9]{36}"),
        "severity": "critical",
        "description": "GitHub Personal Access Token",
    },
    "github_oauth": {
        "regex": re.compile(r"gho_[A-Za-z0-9]{36}"),
        "severity": "critical",
        "description": "GitHub OAuth Access Token",
    },
    "github_app_token": {
        "regex": re.compile(r"ghu_[A-Za-z0-9]{36}"),
        "severity": "critical",
        "description": "GitHub App User Token",
    },
    "github_refresh_token": {
        "regex": re.compile(r"ghr_[A-Za-z0-9]{36}"),
        "severity": "critical",
        "description": "GitHub Refresh Token",
    },
    # Clerk
    "clerk_secret_key": {
        "regex": re.compile(r"sk_live_[A-Za-z0-9]{24,}"),
        "severity": "critical",
        "description": "Clerk Secret Key (Live)",
    },
    "clerk_test_key": {
        "regex": re.compile(r"sk_test_[A-Za-z0-9]{24,}"),
        "severity": "low",
        "description": "Clerk Secret Key (Test)",
    },
    # Supabase
    "supabase_service_role": {
        "regex": re.compile(r"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.[A-Za-z0-9_-]{50,}\.[A-Za-z0-9_-]{20,}"),
        "severity": "high",
        "description": "Supabase/JWT Service Role Key",
    },
    # Private Keys
    "private_key_rsa": {
        "regex": re.compile(r"-----BEGIN RSA PRIVATE KEY-----\n[A-Za-z0-9+/=\n]{64,}"),
        "severity": "critical",
        "description": "RSA Private Key",
    },
    "private_key_openssh": {
        "regex": re.compile(r"-----BEGIN OPENSSH PRIVATE KEY-----\n[A-Za-z0-9+/=\n]{64,}"),
        "severity": "critical",
        "description": "OpenSSH Private Key",
    },
    "private_key_ec": {
        "regex": re.compile(r"-----BEGIN EC PRIVATE KEY-----\n[A-Za-z0-9+/=\n]{64,}"),
        "severity": "critical",
        "description": "EC Private Key",
    },
    "private_key_pgp": {
        "regex": re.compile(r"-----BEGIN PGP PRIVATE KEY BLOCK-----\n[A-Za-z0-9+/=\n]{64,}"),
        "severity": "critical",
        "description": "PGP Private Key",
    },
    # Generic API Keys
    "generic_api_key": {
        "regex": re.compile(r"(?i)(?:api[_\-]?key|apikey)['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9_\-]{20,})['\"]?"),
        "severity": "medium",
        "description": "Generic API Key",
    },
    "generic_secret": {
        "regex": re.compile(r"(?i)(?:secret|password|passwd|pwd)['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9_\-!@#$%^&*]{8,})['\"]?"),
        "severity": "high",
        "description": "Generic Secret/Password",
    },
    # Database
    "postgres_uri": {
        "regex": re.compile(r"postgres(?:ql)?://[^:]+:[^@]+@[^/]+/[^\s]+"),
        "severity": "critical",
        "description": "PostgreSQL Connection URI with credentials",
    },
    "mysql_uri": {
        "regex": re.compile(r"mysql://[^:]+:[^@]+@[^/]+/[^\s]+"),
        "severity": "critical",
        "description": "MySQL Connection URI with credentials",
    },
    # Slack
    "slack_token": {
        "regex": re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"),
        "severity": "high",
        "description": "Slack Token",
    },
    # SendGrid
    "sendgrid_api_key": {
        "regex": re.compile(r"SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}"),
        "severity": "high",
        "description": "SendGrid API Key",
    },
    # Twilio
    "twilio_api_key": {
        "regex": re.compile(r"SK[a-f0-9]{32}"),
        "severity": "high",
        "description": "Twilio API Key",
    },
}
