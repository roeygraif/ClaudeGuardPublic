# Claude Guard

AI-powered cloud infrastructure supervisor for Claude Code. Intercepts AWS and GCP CLI commands, analyzes risk using AI, and warns you before dangerous operations execute.

## Install

```bash
pip install git+https://github.com/roeygraif/ClaudeGuardPublic.git
```

For GCP support:

```bash
pip install "claude-guard[gcp] @ git+https://github.com/roeygraif/ClaudeGuardPublic.git"
```

## Usage

### Solo mode (local analysis)

Requires an Anthropic API key or an active Claude Code login.

```bash
export ANTHROPIC_API_KEY=sk-ant-...
claude-guard
```

### Team mode (server analysis)

```bash
claude-guard login
# Register with your team's invite code, or log in to an existing account

claude-guard
```

### Other commands

```bash
claude-guard scan        # Manually scan your AWS/GCP infrastructure
claude-guard scan --aws  # Scan AWS only
claude-guard scan --gcp  # Scan GCP only
claude-guard status      # Show watchdog status (resource count, last scan, etc.)
claude-guard logout      # Remove stored credentials
```

## How it works

1. `claude-guard` launches Claude Code with a `PreToolUse` hook registered
2. Every Bash command is checked — non-cloud commands pass through instantly
3. Cloud READ commands (`describe`, `list`, `get`) pass through silently
4. Cloud WRITE/DELETE/ADMIN commands trigger AI risk analysis
5. A risk assessment is displayed with blast radius, cost estimate, and recommendation
6. Claude Code prompts you to confirm or cancel

## Requirements

- Python 3.9+
- Claude Code installed (`claude` binary in PATH)
- AWS credentials configured (for AWS commands)
- GCP credentials configured (for GCP commands)
