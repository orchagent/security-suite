# Security Suite

Monorepo containing a security scanning orchestrator and its tool dependencies.

## Components

| Component | Type | Description |
|-----------|------|-------------|
| **security-agent** | `agent` | Orchestrator that coordinates leak-finder and dep-scanner for comprehensive security audits |
| **leak-finder** | `tool` | Scans repositories for exposed secrets and credentials (23+ secret types) |
| **dep-scanner** | `tool` | Audits package dependencies for known CVEs across npm, pip, cargo, and more |

## Architecture

```
security-agent (orchestrator)
├── calls → leak-finder (isolated sandbox)
└── calls → dep-scanner (isolated sandbox)
```

Each component runs in its own isolated container. The orchestrator agent decides which tools to call and compiles the results into a structured security report.

## Usage

```bash
# Import all components via orchagent GitHub App
# Then run the orchestrator:
orch run orchagent/security-agent --cloud --data '{"repo_url": "https://github.com/your-org/your-repo"}'
```
