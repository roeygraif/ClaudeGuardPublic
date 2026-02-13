#!/usr/bin/env python3
"""
Cloud Watchdog — PreToolUse hook entrypoint.

This script is invoked by Claude Code before every tool use. It reads
the tool invocation from stdin as JSON, and:

1. Ignores non-Bash tools (exit 0).
2. Parses the bash command for cloud CLI invocations.
3. If no cloud command is found, exits silently (exit 0).
4. If the infrastructure graph is empty for this provider/account,
   triggers a full scan ("wake up") and shows a red banner on stderr.
5. For READ operations, exits silently (exit 0).
6. For WRITE/DELETE/ADMIN operations:
   a. Gathers full infrastructure context around the target resource.
   b. Sends the context to a separate Claude API call for risk analysis.
   c. Displays the risk assessment in red on stderr.
   d. Outputs JSON to stdout requesting user confirmation.
"""

from __future__ import annotations

import json
import os
import sys
import logging

# Configure logging to stderr so it doesn't interfere with JSON stdout.
logging.basicConfig(
    level=logging.WARNING,
    format="%(name)s: %(message)s",
    stream=sys.stderr,
)
logger = logging.getLogger("cloud-watchdog")


def main() -> None:
    try:
        input_data = json.load(sys.stdin)
    except (json.JSONDecodeError, ValueError):
        # Not valid JSON — not a tool invocation we care about.
        sys.exit(0)

    # Only intercept Bash tool calls.
    if input_data.get("tool_name") != "Bash":
        sys.exit(0)

    command = input_data.get("tool_input", {}).get("command", "")
    if not command:
        sys.exit(0)

    # --- Import watchdog modules (deferred to avoid startup cost on non-cloud commands) ---
    from watchdog.parser import parse_command
    from watchdog.context import gather_context
    from watchdog.brain import analyze_risk
    from watchdog.display import (
        print_scan_header,
        print_scan_progress,
        print_scan_complete,
        format_warning,
        format_fallback_warning,
    )
    from scanner.graph import GraphDB

    parsed = parse_command(command)
    if parsed is None:
        sys.exit(0)  # Not a cloud command.

    db = GraphDB()

    # --- WAKE UP if graph is empty for this provider/account ---
    account_key = parsed.profile  # May be None for default credentials.
    if not db.is_populated_for(parsed.provider, account_key):
        print_scan_header(parsed.provider.upper())

        def _progress(service_name):
            print_scan_progress(service_name)

        try:
            if parsed.provider == "aws":
                from scanner.aws import scan_aws
                summary = scan_aws(db, profile=parsed.profile, region=parsed.region, on_progress=_progress)
            elif parsed.provider == "gcp":
                from scanner.gcp import scan_gcp
                summary = scan_gcp(db, project=parsed.profile, on_progress=_progress)
            else:
                summary = {
                    "account_or_project": "unknown",
                    "region": "unknown",
                    "resource_count": 0,
                    "relationship_count": 0,
                    "environments": {"prod": 0, "staging": 0, "dev": 0, "unknown": 0},
                }
            print_scan_complete(summary)
        except Exception as exc:
            logger.warning("Infrastructure scan failed: %s", exc)
            print(
                "\033[31m  Scan failed — proceeding with limited context.\033[0m",
                file=sys.stderr,
            )
            sys.stderr.flush()

    # --- READs pass silently ---
    if parsed.action_type == "READ":
        sys.exit(0)

    # --- WRITE/DELETE/ADMIN: gather context, ask Claude, show warning ---

    # Server mode: if GUARD_SERVER_URL and GUARD_TOKEN are set, delegate
    # analysis to the backend instead of running the brain locally.
    server_url = os.environ.get("GUARD_SERVER_URL")
    server_token = os.environ.get("GUARD_TOKEN")

    if server_url and server_token:
        assessment = _analyze_via_server(server_url, server_token, parsed)
    else:
        context = gather_context(parsed, db)

        api_key = os.environ.get("ANTHROPIC_API_KEY")

        aws_session_kwargs = None
        gcp_project = None
        if parsed.provider == "aws":
            aws_session_kwargs = {}
            if parsed.profile:
                aws_session_kwargs["profile_name"] = parsed.profile
            if parsed.region:
                aws_session_kwargs["region_name"] = parsed.region
        elif parsed.provider == "gcp":
            gcp_project = parsed.profile

        assessment = analyze_risk(
            context, api_key=api_key,
            aws_session_kwargs=aws_session_kwargs, gcp_project=gcp_project,
        )

    # Log to audit file.
    _audit_log(command, assessment)

    print(format_warning(assessment, parsed), file=sys.stderr)
    sys.stderr.flush()

    # Output the hook response to stdout — request user confirmation.
    json.dump(
        {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "ask",
                "permissionDecisionReason": assessment.summary,
            }
        },
        sys.stdout,
    )
    sys.exit(0)


def _analyze_via_server(server_url: str, token: str, parsed) -> "RiskAssessment":
    """Send analysis request to the Claude Guard server.

    Falls back to a deterministic assessment if the server is unreachable.
    """
    from watchdog.brain import RiskAssessment

    try:
        import requests

        resp = requests.post(
            f"{server_url.rstrip('/')}/api/v1/analyze",
            json={
                "command": parsed.raw_command,
                "provider": parsed.provider,
                "service": parsed.service,
                "action": parsed.action,
                "action_type": parsed.action_type,
                "resource_id": parsed.resource_id,
                "flags": parsed.flags,
                "region": parsed.region,
                "profile": parsed.profile,
                "warning": getattr(parsed, "warning", None),
            },
            headers={"Authorization": f"Bearer {token}"},
            timeout=90,
        )
        resp.raise_for_status()
        data = resp.json()
        return RiskAssessment(
            risk_level=data.get("risk_level", "HIGH"),
            summary=data.get("summary", "Server analysis complete."),
            blast_radius=data.get("blast_radius", []),
            explanation=data.get("explanation", ""),
            reversible=data.get("reversible", False),
            recommendation=data.get("recommendation", ""),
            detailed_analysis=data.get("detailed_analysis", ""),
            cost_estimate=data.get("cost_estimate", ""),
        )
    except Exception as exc:
        logger.warning("Server analysis failed: %s — using fallback", exc)
        return _fallback_assessment(parsed)


def _fallback_assessment(parsed) -> "RiskAssessment":
    """Deterministic fallback when the server is unreachable."""
    from watchdog.brain import RiskAssessment

    action_type = getattr(parsed, "action_type", "WRITE")
    return RiskAssessment(
        risk_level="HIGH" if action_type in ("DELETE", "ADMIN") else "MEDIUM",
        summary=(
            "Cloud Watchdog server unreachable — basic risk assessment "
            "based on action type."
        ),
        blast_radius=[],
        explanation=(
            f"A {action_type} operation was requested. The analysis server "
            "could not be reached, so this is a conservative assessment."
        ),
        reversible=action_type != "DELETE",
        recommendation="Verify the command manually before proceeding.",
    )


def _audit_log(command: str, assessment) -> None:
    """Append an entry to the audit log at ~/.cloud-watchdog/audit.log."""
    try:
        from datetime import datetime, timezone

        log_dir = os.path.expanduser("~/.cloud-watchdog")
        os.makedirs(log_dir, exist_ok=True)
        log_path = os.path.join(log_dir, "audit.log")

        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "command": command,
            "risk_level": assessment.risk_level,
            "summary": assessment.summary,
        }
        with open(log_path, "a") as f:
            f.write(json.dumps(entry) + "\n")
    except Exception:
        pass  # Audit logging is best-effort.


if __name__ == "__main__":
    main()
