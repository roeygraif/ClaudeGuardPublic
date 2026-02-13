"""
Command parser for cloud CLI commands (AWS and GCP).

Parses raw bash command strings, extracts cloud command details,
and classifies actions by type (READ, WRITE, DELETE, ADMIN).
Returns None for non-cloud commands.
"""

from __future__ import annotations

import re
import shlex
from dataclasses import dataclass, field


@dataclass
class ParsedCommand:
    provider: str  # "aws" | "gcp"
    service: str  # "rds" | "ec2" | "iam" | "s3" | "compute" | ...
    action: str  # "delete-db-instance" | "authorize-security-group-ingress"
    action_type: str  # "READ" | "WRITE" | "DELETE" | "ADMIN"
    resource_id: str | None  # "prod-main" | "sg-abc123" (if extractable)
    raw_command: str
    flags: dict = field(default_factory=dict)
    region: str | None = None
    profile: str | None = None  # AWS profile for multi-account
    warning: str | None = None  # Set when segment has unresolvable variables, etc.


# ---------------------------------------------------------------------------
# Action-type keyword maps
# ---------------------------------------------------------------------------

_READ_PREFIXES = (
    "describe",
    "list",
    "get",
    "head",
    "show",
    "lookup",
    "search",
    "check",
    "wait",
    "ls",
    "cat",
    "cp",       # s3 cp is a WRITE, handled as override below
    "fetch",
    "download",
    "receive",
    "peek",
    "view",
    "export",
)

_WRITE_PREFIXES = (
    "create",
    "put",
    "update",
    "modify",
    "attach",
    "authorize",
    "tag",
    "untag",
    "add",
    "set",
    "enable",
    "disable",
    "register",
    "deregister",
    "associate",
    "disassociate",
    "import",
    "upload",
    "copy",
    "move",
    "replace",
    "start",
    "stop",
    "reboot",
    "run",
    "invoke",
    "publish",
    "send",
    "apply",
    "allocate",
    "release",
    "assign",
    "unassign",
    "restore",
    "reset",
    "sync",
    "deploy",
    "cp",  # s3 cp is a WRITE
    "mv",  # s3 mv is a WRITE
    "mb",  # s3 mb (make bucket) is a WRITE
)

_DELETE_PREFIXES = (
    "delete",
    "remove",
    "detach",
    "revoke",
    "terminate",
    "destroy",
    "deregister",
    "purge",
    "cancel",
    "rb",  # s3 rb (remove bucket)
    "rm",  # s3 rm
)

# Services that always get ADMIN classification regardless of the verb.
_ADMIN_SERVICES_AWS = frozenset({
    "iam",
    "sts",
    "organizations",
    "sso",
    "sso-admin",
    "access-analyzer",
    "ram",          # Resource Access Manager
    "guardduty",
    "securityhub",
    "inspector",
    "macie",
    "config",
    "cloudtrail",
    "kms",
})

_ADMIN_SERVICES_GCP = frozenset({
    "iam",
    "organizations",
    "resource-manager",
    "org-policies",
    "access-context-manager",
    "identity",
    "kms",
    "secrets",  # secret-manager
})

# Specific AWS actions that should be ADMIN even when the service is not in the admin set.
_ADMIN_ACTION_PATTERNS = (
    re.compile(r"security.group.*(?:ingress|egress|rule)", re.IGNORECASE),
    re.compile(r"network-acl-entry", re.IGNORECASE),
    re.compile(r"route-table", re.IGNORECASE),
    re.compile(r"(?:policy|role|user|group)-", re.IGNORECASE),
)

# AWS flags that commonly hold the resource identifier, keyed by service.
_AWS_RESOURCE_FLAGS: dict[str, list[str]] = {
    "rds": [
        "--db-instance-identifier",
        "--db-cluster-identifier",
        "--db-snapshot-identifier",
    ],
    "ec2": [
        "--instance-ids",
        "--group-id",
        "--security-group-ids",
        "--subnet-id",
        "--vpc-id",
        "--image-id",
        "--volume-id",
        "--snapshot-id",
        "--network-interface-id",
        "--allocation-id",
    ],
    "s3": ["--bucket"],
    "s3api": ["--bucket"],
    "lambda": ["--function-name"],
    "iam": [
        "--role-name",
        "--user-name",
        "--group-name",
        "--policy-arn",
        "--instance-profile-name",
    ],
    "ecs": ["--cluster", "--service-name", "--task-definition"],
    "eks": ["--name", "--cluster-name"],
    "dynamodb": ["--table-name"],
    "sqs": ["--queue-url"],
    "sns": ["--topic-arn"],
    "cloudformation": ["--stack-name"],
    "elasticache": ["--cache-cluster-id", "--replication-group-id"],
    "redshift": ["--cluster-identifier"],
    "kinesis": ["--stream-name"],
    "logs": ["--log-group-name"],
    "events": ["--rule", "--name"],
    "secretsmanager": ["--secret-id"],
    "ssm": ["--name"],
    "route53": ["--hosted-zone-id"],
    "elbv2": ["--load-balancer-arn", "--target-group-arn"],
    "elb": ["--load-balancer-name"],
    "autoscaling": ["--auto-scaling-group-name"],
    "sts": ["--role-arn"],
    "kms": ["--key-id"],
    "sso": ["--instance-arn"],
}

# Flattened set of all known AWS resource flags for quick lookup.
_ALL_AWS_RESOURCE_FLAGS: set[str] = set()
for _flags in _AWS_RESOURCE_FLAGS.values():
    _ALL_AWS_RESOURCE_FLAGS.update(_flags)


# ---------------------------------------------------------------------------
# Shell splitting helpers
# ---------------------------------------------------------------------------

def _split_compound(command: str) -> list[str]:
    """Split a compound command string on &&, ;, and | operators.

    Returns a list of individual command segments (stripped of whitespace).
    Respects quoting so that operators inside quotes are not treated as
    delimiters.
    """
    segments: list[str] = []
    current: list[str] = []
    i = 0
    in_single = False
    in_double = False
    length = len(command)

    while i < length:
        ch = command[i]

        # Handle escapes.
        if ch == "\\" and i + 1 < length:
            current.append(ch)
            current.append(command[i + 1])
            i += 2
            continue

        # Track quoting state.
        if ch == "'" and not in_double:
            in_single = not in_single
            current.append(ch)
            i += 1
            continue
        if ch == '"' and not in_single:
            in_double = not in_double
            current.append(ch)
            i += 1
            continue

        if in_single or in_double:
            current.append(ch)
            i += 1
            continue

        # Outside quotes: check for compound operators.
        if ch == ";" or ch == "|":
            seg = "".join(current).strip()
            if seg:
                segments.append(seg)
            current = []
            i += 1
            continue

        if ch == "&" and i + 1 < length and command[i + 1] == "&":
            seg = "".join(current).strip()
            if seg:
                segments.append(seg)
            current = []
            i += 2
            continue

        current.append(ch)
        i += 1

    seg = "".join(current).strip()
    if seg:
        segments.append(seg)

    return segments


def _safe_shlex_split(command: str) -> list[str] | None:
    """Attempt shlex.split; return None on failure (unbalanced quotes, etc.)."""
    try:
        return shlex.split(command)
    except ValueError:
        return None


def _has_unresolvable_variables(segment: str) -> bool:
    """Return True if the segment references shell variables or subshells
    that we cannot resolve statically."""
    # $VAR, ${VAR}, $(cmd), `cmd`
    if re.search(r"\$\{?\w+\}?", segment):
        return True
    if re.search(r"\$\(", segment):
        return True
    if "`" in segment:
        return True
    return False


def _is_opaque_command(segment: str) -> bool:
    """Return True if the segment is an opaque wrapper (bash script, eval, etc.)."""
    stripped = segment.lstrip()
    opaque_starts = (
        "bash ",
        "sh ",
        "zsh ",
        "source ",
        ". ",
        "eval ",
        "exec ",
    )
    for prefix in opaque_starts:
        if stripped.startswith(prefix):
            return True
    if stripped.endswith(".sh"):
        return True
    return False


# ---------------------------------------------------------------------------
# Flag / token parsing helpers
# ---------------------------------------------------------------------------

def _parse_flags(tokens: list[str], start_index: int) -> dict[str, str | bool]:
    """Parse CLI flags from a token list starting at *start_index*.

    Returns a dict mapping flag names to their values.  Boolean flags
    (those with no following value or followed by another flag) map to True.
    """
    flags: dict[str, str | bool] = {}
    i = start_index
    while i < len(tokens):
        token = tokens[i]
        if token.startswith("-"):
            # Handle --flag=value syntax.
            if "=" in token:
                key, _, value = token.partition("=")
                flags[key] = value
                i += 1
                continue

            # Peek at next token to decide if this flag has a value.
            if i + 1 < len(tokens) and not tokens[i + 1].startswith("-"):
                flags[token] = tokens[i + 1]
                i += 2
            else:
                flags[token] = True
                i += 1
        else:
            # Positional argument — store under a numbered key.
            pos_key = f"_pos_{sum(1 for k in flags if k.startswith('_pos_'))}"
            flags[pos_key] = token
            i += 1

    return flags


# ---------------------------------------------------------------------------
# Action type classification
# ---------------------------------------------------------------------------

def _classify_action(service: str, action: str, provider: str) -> str:
    """Classify an action into READ, WRITE, DELETE, or ADMIN."""

    service_lower = service.lower()
    action_lower = action.lower()

    # ADMIN takes priority: certain services are always admin.
    # For AWS, exact match on the service name.
    if provider == "aws" and service_lower in _ADMIN_SERVICES_AWS:
        return "ADMIN"
    # For GCP, the service may be multi-token (e.g. "iam service-accounts"),
    # so check if the first token of the service is in the admin set.
    if provider == "gcp":
        gcp_service_root = service_lower.split()[0] if service_lower else ""
        if gcp_service_root in _ADMIN_SERVICES_GCP:
            return "ADMIN"

    # Check for admin action patterns (e.g. security group ingress changes).
    for pattern in _ADMIN_ACTION_PATTERNS:
        if pattern.search(action_lower):
            return "ADMIN"

    # For compound GCP actions like "add-iam-policy-binding", check for IAM.
    if "iam" in action_lower and ("policy" in action_lower or "binding" in action_lower):
        return "ADMIN"

    # DELETE checks.
    for prefix in _DELETE_PREFIXES:
        if action_lower == prefix or action_lower.startswith(prefix + "-"):
            return "DELETE"

    # WRITE checks — must come after DELETE so that "deregister" is not
    # caught by the "register" write prefix.
    for prefix in _WRITE_PREFIXES:
        if action_lower == prefix or action_lower.startswith(prefix + "-"):
            return "WRITE"

    # READ checks.
    for prefix in _READ_PREFIXES:
        if action_lower == prefix or action_lower.startswith(prefix + "-"):
            return "READ"

    # Default to WRITE for unknown actions (safer to over-classify).
    return "WRITE"


# ---------------------------------------------------------------------------
# AWS-specific parsing
# ---------------------------------------------------------------------------

def _extract_aws_resource_id(service: str, flags: dict) -> str | None:
    """Try to pull a meaningful resource identifier out of parsed flags."""
    # First try service-specific flags.
    service_flags = _AWS_RESOURCE_FLAGS.get(service.lower(), [])
    for flag_name in service_flags:
        val = flags.get(flag_name)
        if val and isinstance(val, str):
            return val

    # s3 commands often have positional S3 URIs.
    for key, val in flags.items():
        if isinstance(val, str) and val.startswith("s3://"):
            return val

    # Generic fallback: scan all known resource flags.
    for flag_name in _ALL_AWS_RESOURCE_FLAGS:
        val = flags.get(flag_name)
        if val and isinstance(val, str):
            return val

    # Last resort: look for ARNs in any flag value.
    for val in flags.values():
        if isinstance(val, str) and val.startswith("arn:"):
            return val

    return None


def _parse_aws(tokens: list[str], raw_command: str) -> ParsedCommand | None:
    """Parse an AWS CLI command from pre-split tokens.

    Expected format: aws [options] <service> <action> [flags...]
    """
    # Skip past the leading "aws" token and any global options that precede
    # the service name (e.g. --profile, --region, --endpoint-url, --debug ...).
    idx = 1  # skip 'aws'

    # Collect global options first so we can extract profile/region.
    global_flags: dict[str, str | bool] = {}
    while idx < len(tokens):
        token = tokens[idx]
        if token.startswith("-"):
            if "=" in token:
                key, _, value = token.partition("=")
                global_flags[key] = value
                idx += 1
            elif idx + 1 < len(tokens) and not tokens[idx + 1].startswith("-"):
                global_flags[token] = tokens[idx + 1]
                idx += 2
            else:
                global_flags[token] = True
                idx += 1
        else:
            break  # First non-flag token is the service.

    if idx >= len(tokens):
        return None  # No service found.

    service = tokens[idx]
    idx += 1

    # The action may be a single token like "describe-instances" or, for s3
    # high-level commands, something like "cp" / "ls" / "sync".
    if idx >= len(tokens):
        return None  # No action found.

    action = tokens[idx]
    idx += 1

    # Parse remaining flags.
    sub_flags = _parse_flags(tokens, idx)

    # Merge global flags into sub_flags (sub_flags take precedence).
    merged_flags: dict[str, str | bool] = {**global_flags, **sub_flags}

    # Extract region and profile.
    region = None
    for rkey in ("--region",):
        val = merged_flags.get(rkey)
        if isinstance(val, str):
            region = val
            break

    profile = None
    for pkey in ("--profile",):
        val = merged_flags.get(pkey)
        if isinstance(val, str):
            profile = val
            break

    # Override action type for s3 high-level commands.
    action_type = _classify_action(service, action, "aws")

    # For s3 cp / mv / sync, override READ -> WRITE (reading is still a data
    # transfer that deserves attention in some cases, but structurally these
    # are writes).
    if service == "s3" and action in ("cp", "mv", "sync", "mb"):
        action_type = "WRITE"
    if service == "s3" and action in ("rb", "rm"):
        action_type = "DELETE"

    resource_id = _extract_aws_resource_id(service, merged_flags)

    return ParsedCommand(
        provider="aws",
        service=service,
        action=action,
        action_type=action_type,
        resource_id=resource_id,
        raw_command=raw_command,
        flags=merged_flags,
        region=region,
        profile=profile,
    )


# ---------------------------------------------------------------------------
# GCP-specific parsing
# ---------------------------------------------------------------------------

# GCP services that are expressed as multi-token groups (e.g. "compute instances").
_GCP_MULTI_TOKEN_SERVICES = frozenset({
    "compute",
    "container",
    "sql",
    "app",
    "functions",
    "pubsub",
    "dns",
    "logging",
    "storage",
    "iam",
    "kms",
    "secrets",
    "run",
    "builds",
    "artifacts",
    "dataflow",
    "dataproc",
    "bigtable",
    "spanner",
    "redis",
    "memcache",
    "filestore",
    "composer",
    "notebooks",
    "ai-platform",
    "endpoints",
    "services",
    "projects",
    "organizations",
    "resource-manager",
    "org-policies",
    "access-context-manager",
    "identity",
    "firebase",
    "healthcare",
})


def _parse_gcp(tokens: list[str], raw_command: str) -> ParsedCommand | None:
    """Parse a gcloud CLI command from pre-split tokens.

    GCP commands have a variable structure:
        gcloud <group> [<subgroup>...] <action> [<resource>] [flags...]

    Examples:
        gcloud compute instances delete my-instance --zone=us-central1-a
        gcloud iam service-accounts create my-sa
        gcloud sql instances describe prod-db
    """
    idx = 1  # skip 'gcloud'

    # Skip global flags that may appear before the command group.
    global_flags: dict[str, str | bool] = {}
    while idx < len(tokens):
        token = tokens[idx]
        if token.startswith("-"):
            if "=" in token:
                key, _, value = token.partition("=")
                global_flags[key] = value
                idx += 1
            elif idx + 1 < len(tokens) and not tokens[idx + 1].startswith("-"):
                global_flags[token] = tokens[idx + 1]
                idx += 2
            else:
                global_flags[token] = True
                idx += 1
        else:
            break

    if idx >= len(tokens):
        return None

    # Collect service group tokens (e.g. "compute", "instances" -> service = "compute instances").
    service_parts: list[str] = []
    # The first non-flag token is always part of the service path.
    service_parts.append(tokens[idx])
    idx += 1

    # Consume additional sub-group tokens that are NOT flags and NOT an
    # action verb.  We use a simple heuristic: keep consuming tokens that
    # don't start with '-' and aren't obviously action verbs until we see
    # something that looks like an action.
    _ACTION_VERBS = {
        "create", "delete", "describe", "list", "update", "get", "set",
        "remove", "add", "enable", "disable", "deploy", "run", "submit",
        "start", "stop", "restart", "resize", "reset", "import", "export",
        "copy", "move", "ssh", "scp", "connect", "tail", "read", "write",
        "browse", "apply", "destroy", "attach", "detach", "bind", "unbind",
        "revoke", "grant", "invoke",
    }

    # Gather subgroups: keep going while the token is not a known action and
    # there's at least one more non-flag token after it (which would be the
    # action).  This is heuristic but works well for standard gcloud patterns.
    while idx < len(tokens):
        token = tokens[idx]
        if token.startswith("-"):
            break
        # If this token is a known action verb, stop — it's the action.
        if token in _ACTION_VERBS:
            break
        # If the token contains a known action verb as a prefix with a hyphen
        # (e.g. "add-iam-policy-binding"), treat it as the action.
        if any(token.startswith(v + "-") for v in _ACTION_VERBS):
            break
        # Otherwise, treat it as part of the service group.
        service_parts.append(token)
        idx += 1

    service = " ".join(service_parts) if service_parts else ""

    if idx >= len(tokens):
        # No action token found — the last service_part might actually be
        # an implicit "list" or similar.  Return what we have.
        return ParsedCommand(
            provider="gcp",
            service=service,
            action="",
            action_type="READ",
            resource_id=None,
            raw_command=raw_command,
            flags=global_flags,
            region=global_flags.get("--region") if isinstance(global_flags.get("--region"), str) else None,
            profile=global_flags.get("--project") if isinstance(global_flags.get("--project"), str) else None,
        )

    action = tokens[idx]
    idx += 1

    # The next positional token (if any, before flags) is often the resource.
    resource_id: str | None = None
    if idx < len(tokens) and not tokens[idx].startswith("-"):
        resource_id = tokens[idx]
        idx += 1

    # Parse remaining flags.
    sub_flags = _parse_flags(tokens, idx)
    merged_flags: dict[str, str | bool] = {**global_flags, **sub_flags}

    # Extract region/zone and project.
    region = None
    for rkey in ("--region", "--zone"):
        val = merged_flags.get(rkey)
        if isinstance(val, str):
            region = val
            break

    project = None
    val = merged_flags.get("--project")
    if isinstance(val, str):
        project = val

    # Build a combined service string for classification.
    action_type = _classify_action(service, action, "gcp")

    return ParsedCommand(
        provider="gcp",
        service=service,
        action=action,
        action_type=action_type,
        resource_id=resource_id,
        raw_command=raw_command,
        flags=merged_flags,
        region=region,
        profile=project,
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def parse_command(command: str) -> ParsedCommand | None:
    """Parse a single raw bash command string into a ParsedCommand.

    Returns None if the command is not a recognized cloud CLI command
    (AWS or GCP).
    """
    if not command or not command.strip():
        return None

    stripped = command.strip()

    # Quick check: does the command start with a cloud CLI binary?
    # Account for common prefixes like sudo, env vars, time, etc.
    effective = _strip_command_prefix(stripped)

    if effective is None:
        return None

    has_variables = _has_unresolvable_variables(stripped)
    is_opaque = _is_opaque_command(stripped)

    tokens = _safe_shlex_split(effective)
    if tokens is None:
        # shlex failed — try a naive split so we can still extract something.
        tokens = effective.split()

    if not tokens:
        return None

    base = tokens[0].lower()

    parsed: ParsedCommand | None = None

    if base == "aws":
        parsed = _parse_aws(tokens, stripped)
    elif base == "gcloud":
        parsed = _parse_gcp(tokens, stripped)
    else:
        return None

    if parsed is not None:
        if has_variables:
            parsed.warning = "Command contains unresolvable shell variables"
            if parsed.resource_id and re.search(r"\$\{?\w+\}?", parsed.resource_id):
                parsed.resource_id = None
        if is_opaque:
            parsed.warning = "Command is an opaque wrapper; contents unknown"

    return parsed


def parse_compound_command(command: str) -> list[ParsedCommand]:
    """Split a compound command on &&, ;, | and parse each segment.

    Non-cloud segments are silently dropped.  Segments with unresolvable
    shell variables or opaque wrappers are included with appropriate
    warnings and resource_id set to None.
    """
    if not command or not command.strip():
        return []

    segments = _split_compound(command)
    results: list[ParsedCommand] = []

    for segment in segments:
        segment = segment.strip()
        if not segment:
            continue

        has_variables = _has_unresolvable_variables(segment)
        is_opaque = _is_opaque_command(segment)

        parsed = parse_command(segment)

        if parsed is not None:
            # Warnings may already be set by parse_command; add compound-level
            # warnings if needed.
            warnings: list[str] = []
            if parsed.warning:
                warnings.append(parsed.warning)
            if has_variables and not any("variable" in w for w in warnings):
                warnings.append("Segment contains unresolvable shell variables ($VAR)")
                parsed.resource_id = None
            if is_opaque and not any("opaque" in w for w in warnings):
                warnings.append("Segment is an opaque wrapper (e.g. bash script)")
                parsed.resource_id = None
            if warnings:
                parsed.warning = "; ".join(warnings)
            results.append(parsed)
        else:
            # If the segment is opaque but references cloud tools, still flag it.
            if is_opaque or has_variables:
                # Check if the segment *mentions* cloud CLIs even if we can't parse it.
                if _mentions_cloud_cli(segment):
                    results.append(ParsedCommand(
                        provider="unknown",
                        service="unknown",
                        action="unknown",
                        action_type="WRITE",  # Conservative default.
                        resource_id=None,
                        raw_command=segment,
                        flags={},
                        region=None,
                        profile=None,
                        warning="Opaque or variable-dependent cloud command; cannot parse",
                    ))

    return results


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _strip_command_prefix(command: str) -> str | None:
    """Strip common non-cloud prefixes (sudo, env assignments, time, etc.)
    and return the effective command string starting from the cloud CLI binary.

    Returns None if no cloud CLI binary is found.
    """
    # Remove leading env-var assignments like FOO=bar.
    working = command
    while True:
        match = re.match(r"^\s*\w+=\S+\s+", working)
        if match:
            working = working[match.end():]
        else:
            break

    # Remove common wrapper commands.
    wrapper_pattern = re.compile(
        r"^\s*(?:sudo|time|nohup|nice|ionice|strace|ltrace|env)\s+"
    )
    while wrapper_pattern.match(working):
        working = wrapper_pattern.sub("", working, count=1)

    working = working.strip()

    # Check if what remains starts with a cloud CLI.
    if re.match(r"^(aws|gcloud)\b", working):
        return working

    return None


def _mentions_cloud_cli(segment: str) -> bool:
    """Return True if the segment textually mentions aws or gcloud."""
    return bool(re.search(r"\b(aws|gcloud)\b", segment))
