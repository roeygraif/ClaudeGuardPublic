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

# Ensure the package root is on sys.path so that "import watchdog" resolves
# to our package, not the unrelated "watchdog" file-system watcher library.
_PACKAGE_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _PACKAGE_ROOT not in sys.path:
    sys.path.insert(0, _PACKAGE_ROOT)

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
        print_incremental_progress,
        format_warning,
        format_fallback_warning,
    )
    from scanner.graph import GraphDB

    parsed = parse_command(command)
    if parsed is None:
        sys.exit(0)  # Not a cloud command.

    db = GraphDB()

    # --- WAKE UP if graph is empty or stale for this provider/account ---
    account_key = parsed.profile  # May be None for default credentials.
    needs_scan = not db.is_populated_for(parsed.provider, account_key)
    is_refresh = False

    if not needs_scan:
        stale = db.staleness_minutes(account_key)
        if stale == -1 or stale > 60:  # No scan log or >1 hour old
            needs_scan = True
            is_refresh = True

    if needs_scan:
        print_scan_header(parsed.provider.upper(), refresh=is_refresh)

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
            _sync_if_logged_in(db)
        except Exception as exc:
            logger.warning("Infrastructure scan failed: %s", exc)
            print(
                "\033[31m  Scan failed — proceeding with limited context.\033[0m",
                file=sys.stderr,
            )
            sys.stderr.flush()
    elif parsed.action_type != "READ":
        _incremental_discover(parsed, db)

    # --- READs pass silently ---
    if parsed.action_type == "READ":
        sys.exit(0)

    # --- WRITE/DELETE/ADMIN: gather context, ask Claude, show warning ---

    # Server mode: read config file for server URL + tokens.
    # The config file has a refresh_token so we can recover from expired
    # access tokens without requiring the user to re-login.
    server_url, server_token = _resolve_server_creds()

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


_CONFIG_FILE = os.path.join(os.path.expanduser("~"), ".cloud-watchdog", "config.json")


def _incremental_discover(parsed, db) -> None:
    """Run a quick single-service rescan for WRITE/DELETE/ADMIN commands.

    This keeps the graph fresh for the service being modified, without
    the overhead of a full infrastructure scan.
    """
    from watchdog.display import print_incremental_progress

    service = parsed.service
    if not service:
        return

    print_incremental_progress(service)

    try:
        if parsed.provider == "aws":
            from scanner.aws import scan_aws_service
            scan_aws_service(
                db, service,
                profile=parsed.profile,
                region=parsed.region,
            )
        elif parsed.provider == "gcp":
            from scanner.gcp import scan_gcp_service
            scan_gcp_service(db, service, project=parsed.profile)
    except Exception as exc:
        logger.warning("Incremental discovery failed for %s: %s", service, exc)

    _sync_if_logged_in(db)


def _sync_if_logged_in(db) -> None:
    """If the user is logged in to Claude Guard, sync local graph to server."""
    try:
        with open(_CONFIG_FILE) as f:
            cfg = json.load(f)
    except (FileNotFoundError, ValueError, KeyError):
        return

    server_url = cfg.get("server_url")
    access_token = cfg.get("access_token")
    if not server_url or not access_token:
        return

    try:
        import requests
        import sqlite3

        summary = db.get_scan_summary()
        if summary["resource_count"] == 0:
            return

        conn = sqlite3.connect(db._db_path)
        conn.row_factory = sqlite3.Row

        resources = []
        for row in conn.execute("SELECT * FROM resources"):
            r = dict(row)
            for key in ("metadata", "tags"):
                if r.get(key) and isinstance(r[key], str):
                    try:
                        r[key] = json.loads(r[key])
                    except (json.JSONDecodeError, TypeError):
                        pass
            resources.append(r)

        relationships = []
        for row in conn.execute("SELECT * FROM relationships"):
            r = dict(row)
            if r.get("metadata") and isinstance(r["metadata"], str):
                try:
                    r["metadata"] = json.loads(r["metadata"])
                except (json.JSONDecodeError, TypeError):
                    pass
            relationships.append({
                "source_arn": r["source_arn"],
                "target_arn": r["target_arn"],
                "rel_type": r["rel_type"],
                "metadata": r.get("metadata"),
            })
        conn.close()

        requests.post(
            f"{server_url.rstrip('/')}/api/v1/graph/sync",
            json={"resources": resources, "relationships": relationships},
            headers={"Authorization": f"Bearer {access_token}"},
            timeout=30,
        )
    except Exception as exc:
        logger.debug("Server sync failed: %s", exc)


def _resolve_server_creds() -> tuple[str | None, str | None]:
    """Read server URL and access token from the config file.

    Falls back to env vars for backwards compatibility.
    """
    # Try config file first (has refresh_token for auto-renewal).
    try:
        with open(_CONFIG_FILE) as f:
            import json as _json
            cfg = _json.load(f)
        server_url = cfg.get("server_url")
        access_token = cfg.get("access_token")
        if server_url and access_token:
            return server_url, access_token
    except (FileNotFoundError, ValueError, KeyError):
        pass

    # Fall back to env vars.
    return (
        os.environ.get("GUARD_SERVER_URL"),
        os.environ.get("GUARD_TOKEN"),
    )


def _refresh_and_retry(server_url: str, parsed) -> "RiskAssessment | None":
    """Try to refresh the access token and retry the analysis."""
    try:
        import requests
        with open(_CONFIG_FILE) as f:
            import json as _json
            cfg = _json.load(f)

        refresh_token = cfg.get("refresh_token")
        if not refresh_token:
            return None

        resp = requests.post(
            f"{server_url.rstrip('/')}/api/v1/auth/refresh",
            json={"refresh_token": refresh_token},
            timeout=15,
        )
        if resp.status_code != 200:
            return None

        data = resp.json()
        new_token = data["access_token"]

        # Save updated tokens.
        cfg["access_token"] = new_token
        if data.get("refresh_token"):
            cfg["refresh_token"] = data["refresh_token"]
        with open(_CONFIG_FILE, "w") as f:
            import json as _json
            _json.dump(cfg, f)

        # Retry analysis with the new token.
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
            headers={"Authorization": f"Bearer {new_token}"},
            timeout=90,
        )
        resp.raise_for_status()

        from watchdog.brain import RiskAssessment
        d = resp.json()
        return RiskAssessment(
            risk_level=d.get("risk_level", "HIGH"),
            summary=d.get("summary", "Server analysis complete."),
            blast_radius=d.get("blast_radius", []),
            explanation=d.get("explanation", ""),
            reversible=d.get("reversible", False),
            recommendation=d.get("recommendation", ""),
            detailed_analysis=d.get("detailed_analysis", ""),
            cost_estimate=d.get("cost_estimate", ""),
        )
    except Exception as exc:
        logger.warning("Token refresh failed: %s", exc)
        return None


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
        if resp.status_code == 401:
            # Token expired — try refreshing.
            refreshed = _refresh_and_retry(server_url, parsed)
            if refreshed:
                return refreshed
            return _fallback_assessment(parsed)

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
