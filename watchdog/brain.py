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

MAX_ROUNDS = 5  # Cap tool-use loop iterations


# ---------------------------------------------------------------------------
# Prompts
# ---------------------------------------------------------------------------

_SYSTEM_PROMPT = """\
You are Cloud Watchdog, a security supervisor for cloud infrastructure.
You receive a command that is about to be executed on a real cloud environment,
along with the full infrastructure context around the target resource.

Your job:
1. Assess the risk level: CRITICAL, HIGH, MEDIUM, LOW, or INFO
2. Identify the blast radius — what other resources and services will be affected
3. Explain the risk in plain English — what could go wrong, what depends on this, is this reversible
4. For IAM changes: explain what access is being granted/revoked and to whom
5. For security group changes: explain what network access is opening/closing
6. For deletions: explain what will break and whether backups/replicas exist
7. Estimate AWS/GCP costs when the command will create or resize resources:
   - For new resources: estimate the monthly cost (e.g., "~$73/month for a db.m5.large RDS instance")
   - For resizing: estimate the cost delta (e.g., "Cost increase: ~$50/month, from ~$73 to ~$123")
   - For deletions of running resources: estimate monthly savings (e.g., "Savings: ~$73/month")
   - Use the resource configuration from context or tools (instance type, storage size, etc.)
   - Give a ballpark — precision to the dollar is fine, don't overthink it
   - Omit cost_estimate for operations that don't affect billing (IAM, SG rules, tags, etc.)

Be specific. Reference actual resource names and relationships from the context.
If the target resource was not found in the infrastructure graph, treat it as HIGH risk — unknown resources should be assumed dangerous.

## Tool Usage Guidelines

You have access to read-only cloud API tools that let you query live infrastructure.
- Only call tools when the pre-built context is insufficient to make a thorough assessment
- Focus on risk-relevant information (e.g., checking current SG rules, IAM policy documents, replication status)
- Use CloudWatch metrics, CloudWatch Logs, and CloudTrail to understand traffic, usage patterns, and recent activity on affected resources
- Typically 0-3 tool calls are sufficient — do not make unnecessary queries
- All tools are strictly read-only and cannot modify any resources

## Output Format

Respond ONLY with JSON (no markdown, no code fences):
{
  "risk_level": "CRITICAL|HIGH|MEDIUM|LOW|INFO",
  "summary": "One-line summary of the risk",
  "blast_radius": ["Resource A — will lose DB connectivity", "Resource B — ..."],
  "explanation": "Detailed paragraph explaining the full risk",
  "reversible": true,
  "recommendation": "What the user should consider before proceeding",
  "detailed_analysis": "Optional markdown with tables/headers for complex scenarios. Use ## headers, - bullets, | tables |, and **bold** for structured explanations. Omit this field or set to empty string for simple cases.",
  "cost_estimate": "Optional — estimated monthly cost, cost delta, or savings. Omit or empty string when not applicable."
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
