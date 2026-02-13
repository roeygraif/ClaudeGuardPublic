"""
Cloud Watchdog Brain — Claude API integration for risk analysis.

Makes Anthropic API calls with infrastructure context and optional read-only
cloud API tools, returning a structured risk assessment.  Supports a tool-use
message loop so Claude can query live infrastructure during analysis.
"""

import json
import os
import re
from dataclasses import dataclass

import anthropic


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class RiskAssessment:
    risk_level: str          # CRITICAL | HIGH | MEDIUM | LOW | INFO
    summary: str             # One-line
    blast_radius: list[str]  # Affected resources with impact description
    explanation: str         # Detailed paragraph
    reversible: bool
    recommendation: str
    detailed_analysis: str = ""  # Optional rich markdown from Claude
    cost_estimate: str = ""      # e.g. "~$73/month (db.m5.large)"


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

MAX_ROUNDS = 8  # Cap tool-use loop iterations (brain investigates before judging)


# ---------------------------------------------------------------------------
# Prompts
# ---------------------------------------------------------------------------

_SYSTEM_PROMPT = """\
You are Cloud Watchdog, an automated security investigator for cloud infrastructure.
You receive a command about to be executed on a REAL cloud environment.
Your job is to INVESTIGATE first, then report ONLY specific findings.

## CRITICAL RULES

1. **INVESTIGATE BEFORE JUDGING.** You have read-only cloud API tools. USE THEM.
   - For deletions: call describe/get on the target resource to check its actual state, size, usage
   - Check CloudWatch metrics (last 24h) to see if the resource is actively receiving traffic
   - Check Lambda event source mappings to find stream consumers
   - Check CloudTrail for recent API activity on the resource
   - Check for backups, replicas, point-in-time recovery

2. **NEVER give generic advice.** Do NOT say things like:
   - "Check application configurations" — YOU check them
   - "Verify its usage and dependencies" — YOU verify them
   - "Ensure a backup exists" — YOU check if backups exist
   - "Check CloudWatch metrics" — YOU check CloudWatch metrics
   The user cannot see your investigation — they only see your CONCLUSIONS.

3. **Report only what you FOUND.** Examples of good findings:
   - "Table has 50,000 items (2.3 GB) and received 1,200 read operations in the last hour"
   - "2 Lambda functions have DynamoDB Streams triggers on this table"
   - "Point-in-time recovery is DISABLED — deletion is permanent"
   - "No CloudWatch activity in the last 7 days — table appears unused"
   - "Security group sg-abc123 is attached to 3 running EC2 instances"

4. **Risk level reflects EVIDENCE, not assumptions.**
   - If you find active traffic + no backups + dependencies → CRITICAL/HIGH
   - If you find zero activity + no dependencies → LOW
   - If you couldn't gather evidence (tools failed) → default to HIGH with explanation

## What to investigate per action type

**DELETE operations:**
- Describe the target resource (size, status, configuration)
- Check CloudWatch metrics for recent activity (last 24-48h)
- Check for backups/snapshots/replicas/point-in-time recovery
- Find dependent resources (Lambda triggers, event sources, connected services)
- Estimate monthly savings from the deletion

**WRITE/modify operations:**
- Describe current state of the target resource
- Identify what will change and the blast radius
- For IAM: get the actual policy document, list who/what uses the role
- For security groups: get current rules, list attached instances
- Estimate cost impact if applicable

**ADMIN/privilege operations:**
- Get the actual policy document being attached/modified
- List all resources that assume or use the role
- Check for wildcard permissions (Resource: *)

## Cost estimates
- For new resources: estimate monthly cost (e.g., "~$73/month for db.m5.large")
- For deletions: estimate savings (e.g., "Savings: ~$5/month for on-demand DynamoDB with 50K items")
- For resizing: estimate delta
- Use actual resource config from your tool calls, not guesses
- Omit for non-billing operations (IAM, SG rules, tags)

## Output Format

Respond ONLY with JSON (no markdown, no code fences):
{
  "risk_level": "CRITICAL|HIGH|MEDIUM|LOW|INFO",
  "summary": "One-line summary with SPECIFIC findings (e.g., 'Table has 50K items, 2 Lambda consumers, no backups')",
  "blast_radius": ["Lambda function X — DynamoDB Streams trigger will break", "..."],
  "explanation": "What you found during investigation. Cite actual numbers, names, and states.",
  "reversible": true,
  "recommendation": "Specific next steps based on your findings (e.g., 'Enable PITR backup before deleting' not 'check if backups exist')",
  "detailed_analysis": "Optional markdown for complex scenarios.",
  "cost_estimate": "Based on actual resource config from your investigation."
}\
"""


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def analyze_risk(
    context: dict,
    api_key: str = None,
    aws_session_kwargs: dict = None,
    gcp_project: str = None,
    tools: list | None = None,
) -> RiskAssessment:
    """Analyse the risk of a cloud operation via the Anthropic API.

    Parameters
    ----------
    context:
        The full infrastructure context dict that will be sent to Claude.
    api_key:
        Optional Anthropic API key.  Falls back to the ``ANTHROPIC_API_KEY``
        environment variable when *None*.
    aws_session_kwargs:
        Optional dict of kwargs for ``boto3.Session()`` (e.g. profile_name,
        region_name).  Passed through to tool execution.
    gcp_project:
        Optional GCP project ID for tool execution.
    tools:
        Explicit tool definitions list.  Pass ``[]`` to disable tools
        (e.g. server-side analysis where no cloud creds are available).
        Pass ``None`` (default) to auto-build tools from the provider.

    Returns
    -------
    RiskAssessment
        A structured risk assessment — either from Claude or from the
        deterministic fallback if anything goes wrong.
    """
    try:
        key = api_key or os.environ.get("ANTHROPIC_API_KEY")
        if not key:
            # Try Claude Code's stored credentials as a last resort.
            try:
                from claude_guard import resolve_api_key
                key = resolve_api_key()
            except ImportError:
                pass
        if not key:
            return _fallback_assessment(context)

        client = anthropic.Anthropic(
            api_key=key,
            timeout=60.0,
        )

        # Determine provider for tool selection.
        # When tools is explicitly passed (including []), use it as-is.
        # When None, auto-build from provider.
        if tools is None:
            provider = context.get("provider") or _detect_provider(context)
            tools = _build_tools(provider)

        messages = [
            {
                "role": "user",
                "content": json.dumps(context, indent=2),
            },
        ]

        # Tool-use message loop
        for _ in range(MAX_ROUNDS):
            create_kwargs = dict(
                model="claude-sonnet-4-5-20250929",
                max_tokens=4096,
                system=_SYSTEM_PROMPT,
                messages=messages,
            )
            if tools:
                create_kwargs["tools"] = tools

            response = client.messages.create(**create_kwargs)

            if response.stop_reason == "tool_use":
                # Process tool calls and continue loop
                assistant_content = response.content
                messages.append({"role": "assistant", "content": assistant_content})

                tool_results = []
                for block in assistant_content:
                    if block.type == "tool_use":
                        from watchdog.tools import execute_tool
                        result_str = execute_tool(
                            block.name,
                            block.input,
                            aws_session_kwargs=aws_session_kwargs,
                            gcp_project=gcp_project,
                        )
                        tool_results.append({
                            "type": "tool_result",
                            "tool_use_id": block.id,
                            "content": result_str,
                        })

                messages.append({"role": "user", "content": tool_results})
            else:
                # Extract final text response
                raw_text = _extract_text(response)
                if raw_text:
                    return _parse_response(raw_text)
                return _fallback_assessment(context)

        # Exhausted MAX_ROUNDS — extract whatever text we have
        raw_text = _extract_text(response)
        if raw_text:
            return _parse_response(raw_text)
        return _fallback_assessment(context)

    except Exception:
        return _fallback_assessment(context)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _detect_provider(context: dict) -> str | None:
    """Try to detect the cloud provider from the context."""
    command = context.get("command", "")
    if "aws " in command or "aws:" in str(context.get("target", {})):
        return "aws"
    if "gcloud " in command or "gcp" in str(context.get("target", {})):
        return "gcp"
    return None


def _build_tools(provider: str | None) -> list[dict]:
    """Build tool definitions, returning empty list if tools module unavailable."""
    try:
        from watchdog.tools import build_tool_definitions
        return build_tool_definitions(provider)
    except ImportError:
        return []


def _extract_text(response) -> str | None:
    """Extract text content from an Anthropic API response."""
    for block in response.content:
        if hasattr(block, "text"):
            return block.text
    return None


# ---------------------------------------------------------------------------
# Response parsing
# ---------------------------------------------------------------------------

_VALID_RISK_LEVELS = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}


def _strip_code_fences(text: str) -> str:
    """Remove optional markdown code fences wrapping JSON."""
    stripped = text.strip()
    # Handle ```json ... ``` or ``` ... ```
    match = re.match(r"^```(?:json)?\s*\n?(.*?)\n?\s*```$", stripped, re.DOTALL)
    if match:
        return match.group(1).strip()
    return stripped


def _parse_response(raw_text: str) -> RiskAssessment:
    """Parse Claude's JSON response into a RiskAssessment.

    Gracefully handles markdown-wrapped JSON and missing / malformed fields
    by substituting sensible defaults.
    """
    cleaned = _strip_code_fences(raw_text)
    data = json.loads(cleaned)

    risk_level = str(data.get("risk_level", "HIGH")).upper()
    if risk_level not in _VALID_RISK_LEVELS:
        risk_level = "HIGH"

    blast_radius_raw = data.get("blast_radius", [])
    if isinstance(blast_radius_raw, list):
        blast_radius = [str(item) for item in blast_radius_raw]
    else:
        blast_radius = []

    reversible_raw = data.get("reversible", False)
    if isinstance(reversible_raw, bool):
        reversible = reversible_raw
    else:
        reversible = str(reversible_raw).lower() in ("true", "1", "yes")

    detailed_analysis = str(data.get("detailed_analysis", ""))
    cost_estimate = str(data.get("cost_estimate", ""))

    return RiskAssessment(
        risk_level=risk_level,
        summary=str(data.get("summary", "No summary provided.")),
        blast_radius=blast_radius,
        explanation=str(data.get("explanation", "No explanation provided.")),
        reversible=reversible,
        recommendation=str(data.get("recommendation", "Review the operation carefully before proceeding.")),
        detailed_analysis=detailed_analysis,
        cost_estimate=cost_estimate,
    )


# ---------------------------------------------------------------------------
# Deterministic fallback
# ---------------------------------------------------------------------------

_ACTION_ENV_RISK_MAP: dict[tuple[str, str], str] = {
    ("DELETE", "prod"):       "CRITICAL",
    ("DELETE", "production"): "CRITICAL",
    ("DELETE", "staging"):    "HIGH",
    ("DELETE", "dev"):        "MEDIUM",
    ("DELETE", "_default"):   "MEDIUM",
    ("ADMIN", "prod"):        "HIGH",
    ("ADMIN", "production"):  "HIGH",
    ("ADMIN", "_default"):    "MEDIUM",
    ("WRITE", "prod"):        "MEDIUM",
    ("WRITE", "production"):  "MEDIUM",
    ("WRITE", "_default"):    "LOW",
}

_ACTION_EXPLANATIONS: dict[str, str] = {
    "DELETE": "A delete operation was requested. Deleted resources may not be recoverable without backups.",
    "ADMIN": "An administrative / privilege-escalation operation was requested. This may grant broad access to sensitive resources.",
    "WRITE": "A write / modify operation was requested. This will change the current state of the target resource.",
}


def _fallback_assessment(context: dict) -> RiskAssessment:
    """Return a deterministic risk assessment when the API is unavailable.

    Uses the action type and target environment extracted from *context* to
    derive a conservative risk level.
    """
    action_type = str(context.get("action_type", "")).upper()
    # Try to extract environment from the target sub-dict, if present.
    target = context.get("target", {})
    if isinstance(target, dict):
        environment = str(target.get("environment", "")).lower()
    else:
        environment = ""

    # Look up risk level using the mapping table.
    risk_level = (
        _ACTION_ENV_RISK_MAP.get((action_type, environment))
        or _ACTION_ENV_RISK_MAP.get((action_type, "_default"))
    )
    if risk_level is None:
        risk_level = "LOW"

    explanation = _ACTION_EXPLANATIONS.get(
        action_type,
        "An operation was requested. Unable to determine detailed risk without the analysis engine.",
    )

    reversible = action_type != "DELETE"

    return RiskAssessment(
        risk_level=risk_level,
        summary=(
            "Cloud Watchdog could not reach its analysis engine. "
            "Basic risk assessment based on action type and environment."
        ),
        blast_radius=[],
        explanation=explanation,
        reversible=reversible,
        recommendation="Verify the command manually before proceeding.",
    )
