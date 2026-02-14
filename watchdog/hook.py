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
   b. Runs a deterministic risk assessment (no external API calls).
   c. Displays the risk assessment in red on stderr.
   d. Packs infrastructure context into permissionDecisionReason so
      Claude Code's active model can reason about the risk.
   e. Outputs JSON to stdout requesting user confirmation.
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

    server_url, server_token = _resolve_server_creds()
    if not server_url or not server_token:
        print(
            "\033[33m  Cloud Watchdog requires login. Run: claude-guard login\033[0m",
            file=sys.stderr,
        )
        sys.stderr.flush()
        sys.exit(0)

    db = GraphDB(server_url=server_url, token=server_token)

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

    # --- WRITE/DELETE/ADMIN: gather context, build deterministic assessment ---
    context = gather_context(parsed, db)

    # --- DENY destructive ops on unknown resources ---
    target = context.get("target")
    resource_id = getattr(parsed, "resource_id", None) or ""
    if (
        resource_id
        and target is None
        and parsed.action_type in ("DELETE", "ADMIN")
    ):
        reason = _build_investigation_reason(parsed, context)
        json.dump(
            {
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": "deny",
                    "permissionDecisionReason": reason,
                }
            },
            sys.stdout,
        )
        sys.exit(0)

    # Try Gemini agent on the server; fall back to deterministic.
    assessment = _analyze_on_server(server_url, server_token, parsed)
    if assessment is None:
        assessment = _deterministic_assessment(context)

    # Log to audit file.
    _audit_log(command, assessment)

    print(format_warning(assessment, parsed), file=sys.stderr)
    sys.stderr.flush()

    # Build a rich reason string for Claude Code's confirmation dialog.
    reason = _build_permission_reason(assessment, context)

    # Output the hook response to stdout — request user confirmation.
    json.dump(
        {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "ask",
                "permissionDecisionReason": reason,
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

        # Flush buffered resources to the server so that gather_context
        # (which queries the server API) can find them.
        db.flush()
    except Exception as exc:
        logger.warning("Incremental discovery failed for %s: %s", service, exc)


def _resolve_server_creds() -> tuple[str | None, str | None]:
    """Read server URL and access token from the config file.

    If the access token is expired, attempts to refresh it using the
    stored refresh_token and writes the new tokens back to disk.
    Falls back to env vars for backwards compatibility.
    """
    # Try config file first.
    try:
        with open(_CONFIG_FILE) as f:
            import json as _json
            cfg = _json.load(f)
        server_url = cfg.get("server_url")
        access_token = cfg.get("access_token")
        if not server_url or not access_token:
            raise ValueError("missing creds")

        # Quick check: is the token still valid?
        if _token_needs_refresh(server_url, access_token):
            refreshed = _refresh_access_token(server_url, cfg.get("refresh_token"))
            if refreshed:
                access_token = refreshed
                cfg["access_token"] = access_token
                try:
                    with open(_CONFIG_FILE, "w") as f:
                        _json.dump(cfg, f, indent=2)
                except Exception:
                    pass

        return server_url, access_token
    except (FileNotFoundError, ValueError, KeyError):
        pass

    # Fall back to env vars.
    return (
        os.environ.get("GUARD_SERVER_URL"),
        os.environ.get("GUARD_TOKEN"),
    )


def _token_needs_refresh(server_url: str, token: str) -> bool:
    """Return True if the access token is expired or invalid."""
    try:
        import urllib.request
        import urllib.error

        req = urllib.request.Request(
            f"{server_url.rstrip('/')}/api/v1/graph/populated?provider=aws",
            headers={"Authorization": f"Bearer {token}"},
        )
        urllib.request.urlopen(req, timeout=5)
        return False  # Token works.
    except urllib.error.HTTPError as e:
        return e.code == 401
    except Exception:
        return False  # Network error — don't try to refresh.


def _refresh_access_token(server_url: str, refresh_token: str | None) -> str | None:
    """Call the refresh endpoint and return the new access token."""
    if not refresh_token:
        return None
    try:
        import urllib.request

        payload = json.dumps({"refresh_token": refresh_token}).encode("utf-8")
        req = urllib.request.Request(
            f"{server_url.rstrip('/')}/api/v1/auth/refresh",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        resp = urllib.request.urlopen(req, timeout=10)
        data = json.loads(resp.read().decode("utf-8"))
        return data.get("access_token")
    except Exception:
        return None


def _analyze_on_server(
    server_url: str | None,
    server_token: str | None,
    parsed,
) -> "RiskAssessment | None":
    """POST to /api/v1/analyze and return a RiskAssessment, or None on failure.

    The server runs a Gemini agent with infrastructure graph tools to
    produce an informed risk assessment.  Timeout is 15s to allow for
    multiple tool-call rounds.
    """
    if not server_url or not server_token:
        return None

    try:
        import urllib.request
        import urllib.error

        from watchdog.brain import RiskAssessment

        payload = json.dumps({
            "provider": getattr(parsed, "provider", None),
            "service": getattr(parsed, "service", None),
            "action": getattr(parsed, "action", None),
            "action_type": getattr(parsed, "action_type", None),
            "resource_id": getattr(parsed, "resource_id", None),
            "command": getattr(parsed, "raw_command", ""),
            "flags": getattr(parsed, "flags", {}),
            "region": getattr(parsed, "region", None),
            "profile": getattr(parsed, "profile", None),
        }).encode("utf-8")

        url = f"{server_url.rstrip('/')}/api/v1/analyze"
        req = urllib.request.Request(
            url,
            data=payload,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {server_token}",
            },
            method="POST",
        )
        resp = urllib.request.urlopen(req, timeout=15)
        data = json.loads(resp.read().decode("utf-8"))

        return RiskAssessment(
            risk_level=data.get("risk_level", "MEDIUM"),
            summary=data.get("summary", ""),
            blast_radius=data.get("blast_radius", []),
            explanation=data.get("explanation", ""),
            reversible=data.get("reversible", True),
            recommendation=data.get("recommendation", ""),
            detailed_analysis=data.get("detailed_analysis", ""),
            cost_estimate=data.get("cost_estimate", ""),
        )
    except Exception:
        return None


def _deterministic_assessment(context: dict) -> "RiskAssessment":
    """Build a risk assessment deterministically from gathered context.

    Uses action type + environment to set risk level, populates blast
    radius from connected resources, and includes warnings. No API
    calls, no network — instant.
    """
    from watchdog.brain import (
        RiskAssessment,
        _ACTION_ENV_RISK_MAP,
        _ACTION_EXPLANATIONS,
    )

    action_type = str(context.get("action_type", "")).upper()

    # Extract environment from target.
    target = context.get("target") or {}
    if isinstance(target, dict):
        environment = str(target.get("environment", "")).lower()
    else:
        environment = ""

    # Look up risk level.
    risk_level = (
        _ACTION_ENV_RISK_MAP.get((action_type, environment))
        or _ACTION_ENV_RISK_MAP.get((action_type, "_default"))
    )
    if risk_level is None:
        risk_level = "LOW"

    # Build blast radius from connected resources.
    connected = context.get("connected_resources") or []
    blast_radius = []
    for res in connected:
        res_type = res.get("type", "resource")
        res_rel = res.get("relationship", "connected")
        res_arn = res.get("arn", "")
        # Use ARN's last segment as name if no better label.
        name = res_arn.rsplit("/", 1)[-1] if "/" in res_arn else res_arn.rsplit(":", 1)[-1] if ":" in res_arn else res_arn
        if name:
            blast_radius.append(f"{res_type}: {name} ({res_rel})")
        else:
            blast_radius.append(f"{res_type} ({res_rel})")

    # Build summary from warnings.
    warnings = context.get("warnings") or []
    if warnings:
        summary = "; ".join(warnings[:3])
    else:
        target_name = target.get("name", "") if isinstance(target, dict) else ""
        summary = f"{action_type} operation on {target_name}" if target_name else f"{action_type} operation"

    explanation = _ACTION_EXPLANATIONS.get(
        action_type,
        "An operation was requested. Review carefully before proceeding.",
    )

    reversible = action_type != "DELETE"

    return RiskAssessment(
        risk_level=risk_level,
        summary=summary,
        blast_radius=blast_radius,
        explanation=explanation,
        reversible=reversible,
        recommendation="Review the infrastructure context below before proceeding.",
    )


def _build_permission_reason(assessment, context: dict) -> str:
    """Build a rich permission reason with infrastructure context.

    This text is set as ``permissionDecisionReason`` in the hook
    response. Claude Code's active model sees this field and uses
    the infrastructure context to inform the user about risks.
    """
    risk = getattr(assessment, "risk_level", "UNKNOWN")
    summary = getattr(assessment, "summary", "")
    blast = getattr(assessment, "blast_radius", []) or []
    reversible = getattr(assessment, "reversible", None)

    RED = "\033[31m"
    BOLD_RED = "\033[1;31m"
    RESET = "\033[0m"

    lines = []
    lines.append(f"{BOLD_RED}////// CLOUD WATCHDOG — Risk: {risk} //////{RESET}")
    lines.append("")

    if summary:
        lines.append(f"{RED}{summary}{RESET}")
        lines.append("")

    # --- Target resource details ---
    target = context.get("target")
    if isinstance(target, dict) and target:
        lines.append(f"{RED}Target Resource:{RESET}")
        if target.get("name"):
            lines.append(f"{RED}  Name: {target['name']}{RESET}")
        if target.get("type"):
            lines.append(f"{RED}  Type: {target['type']}{RESET}")
        if target.get("environment"):
            lines.append(f"{RED}  Environment: {target['environment']}{RESET}")
        if target.get("is_active"):
            activity = target.get("activity", "active")
            lines.append(f"{RED}  Status: ACTIVE ({activity}){RESET}")
        lines.append("")

    # --- Connected resources (blast radius) ---
    connected = context.get("connected_resources") or []
    if connected:
        lines.append(f"{RED}Connected Resources ({len(connected)}):{RESET}")
        for res in connected[:8]:
            res_type = res.get("type", "resource")
            res_rel = res.get("relationship", "connected")
            res_arn = res.get("arn", "")
            name = res_arn.rsplit("/", 1)[-1] if "/" in res_arn else res_arn.rsplit(":", 1)[-1] if ":" in res_arn else res_arn
            lines.append(f"{RED}  - {res_type}: {name} ({res_rel}){RESET}")
        if len(connected) > 8:
            lines.append(f"{RED}  ... and {len(connected) - 8} more{RESET}")
        lines.append("")

    # --- Warnings ---
    warnings = context.get("warnings") or []
    if warnings:
        lines.append(f"{BOLD_RED}Warnings:{RESET}")
        for w in warnings:
            lines.append(f"{RED}  - {w}{RESET}")
        lines.append("")

    # --- IAM context ---
    iam = context.get("iam_context")
    if isinstance(iam, dict) and iam:
        lines.append(f"{RED}IAM Context:{RESET}")
        if iam.get("role"):
            lines.append(f"{RED}  Role: {iam['role']}{RESET}")
        policies = iam.get("current_policies") or []
        if policies:
            lines.append(f"{RED}  Current policies: {len(policies)}{RESET}")
            for p in policies[:5]:
                p_arn = p.get("arn", "")
                p_name = p_arn.rsplit("/", 1)[-1] if "/" in p_arn else p_arn
                lines.append(f"{RED}    - {p_name}{RESET}")
        using = iam.get("resources_using_role") or []
        if using:
            lines.append(f"{RED}  Resources using this role: {len(using)}{RESET}")
            for r in using[:5]:
                r_type = r.get("type", "resource")
                r_arn = r.get("arn", "")
                r_name = r_arn.rsplit("/", 1)[-1] if "/" in r_arn else r_arn
                lines.append(f"{RED}    - {r_type}: {r_name}{RESET}")
        policy_attached = iam.get("policy_being_attached")
        if isinstance(policy_attached, dict) and policy_attached:
            lines.append(f"{RED}  Policy being attached: {policy_attached.get('name', policy_attached.get('arn', ''))}{RESET}")
        lines.append("")

    # --- Network context ---
    net = context.get("network_context")
    if isinstance(net, dict) and net:
        lines.append(f"{RED}Network Context:{RESET}")
        if net.get("security_group"):
            lines.append(f"{RED}  Security Group: {net['security_group']}{RESET}")
        rules = net.get("current_rules") or []
        if rules:
            lines.append(f"{RED}  Current rules: {len(rules)}{RESET}")
        attached = net.get("attached_resources") or []
        if attached:
            lines.append(f"{RED}  Attached to {len(attached)} resources{RESET}")
        rule_added = net.get("rule_being_added")
        if isinstance(rule_added, dict) and rule_added:
            lines.append(f"{RED}  Rule being added: {json.dumps(rule_added)}{RESET}")
        lines.append("")

    # --- Reversibility ---
    if reversible is not None:
        lines.append(f"{RED}Reversible: {'Yes' if reversible else 'NO'}{RESET}")
        lines.append("")

    # --- Instruction for Claude Code's model ---
    lines.append(f"{BOLD_RED}You are Cloud Watchdog. Based on the infrastructure context above, "
                  f"explain the risks of this command to the user. Be specific about what "
                  f"could break.{RESET}")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Describe commands for investigation flow
# ---------------------------------------------------------------------------

_DESCRIBE_COMMANDS: dict[str, list[str]] = {
    "ec2": [
        "aws ec2 describe-instances --instance-ids {resource_id}",
        "aws ec2 describe-instance-status --instance-ids {resource_id}",
    ],
    "rds": [
        "aws rds describe-db-instances --db-instance-identifier {resource_id}",
    ],
    "s3": [
        "aws s3api head-bucket --bucket {resource_id}",
        "aws s3api get-bucket-versioning --bucket {resource_id}",
    ],
    "lambda": [
        "aws lambda get-function --function-name {resource_id}",
    ],
    "iam": [
        "aws iam get-role --role-name {resource_id}",
        "aws iam list-attached-role-policies --role-name {resource_id}",
    ],
    "dynamodb": [
        "aws dynamodb describe-table --table-name {resource_id}",
        "aws dynamodb describe-continuous-backups --table-name {resource_id}",
    ],
    "ecs": [
        "aws ecs describe-services --cluster default --services {resource_id}",
    ],
    "eks": [
        "aws eks describe-cluster --name {resource_id}",
    ],
    "elbv2": [
        "aws elbv2 describe-load-balancers --names {resource_id}",
    ],
    "elb": [
        "aws elbv2 describe-load-balancers --names {resource_id}",
    ],
    "route53": [
        "aws route53 get-hosted-zone --id {resource_id}",
    ],
    "cloudfront": [
        "aws cloudfront get-distribution --id {resource_id}",
    ],
    "sqs": [
        "aws sqs get-queue-attributes --queue-url {resource_id} --attribute-names All",
    ],
    "sns": [
        "aws sns get-topic-attributes --topic-arn {resource_id}",
    ],
}


def _build_investigation_reason(parsed, context: dict) -> str:
    """Build a deny reason that tells Claude Code to investigate first.

    When a destructive operation targets an unknown resource, the hook
    denies the command and returns specific read-only describe commands
    that Claude Code should run so that incremental discovery can find
    the resource on the next attempt.
    """
    RED = "\033[31m"
    BOLD_RED = "\033[1;31m"
    RESET = "\033[0m"

    service = getattr(parsed, "service", "") or ""
    resource_id = getattr(parsed, "resource_id", "") or ""
    action_type = getattr(parsed, "action_type", "") or ""

    lines = []
    lines.append(
        f"{BOLD_RED}////// CLOUD WATCHDOG — DENIED: Unknown Resource //////{RESET}"
    )
    lines.append("")
    lines.append(
        f"{RED}A {action_type} operation was attempted on a resource that is "
        f"not in the infrastructure graph.{RESET}"
    )
    lines.append(
        f"{RED}Service: {service}  |  Resource: {resource_id}{RESET}"
    )
    lines.append("")
    lines.append(
        f"{BOLD_RED}Before retrying, run these read-only commands to "
        f"investigate:{RESET}"
    )

    templates = _DESCRIBE_COMMANDS.get(service.lower(), [])
    if templates:
        for tmpl in templates:
            cmd = tmpl.format(resource_id=resource_id)
            lines.append(f"{RED}  $ {cmd}{RESET}")
    else:
        lines.append(
            f"{RED}  $ aws {service} describe-* (check the resource exists){RESET}"
        )

    lines.append("")
    lines.append(
        f"{RED}After investigating, re-run the original command. "
        f"The incremental scanner will pick up the resource and provide "
        f"full context.{RESET}"
    )

    return "\n".join(lines)


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
