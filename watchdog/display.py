"""
ANSI terminal display formatter for Cloud Watchdog.

Formats all Cloud Watchdog output as colored ANSI text intended for stderr.
All public functions return strings; the caller is responsible for printing
to stderr.
"""

from __future__ import annotations

import re
import sys
import textwrap
from typing import Any, Dict, List, Optional, Union


# ---------------------------------------------------------------------------
# ANSI colour constants
# ---------------------------------------------------------------------------

RED = "\033[31m"
BOLD_RED = "\033[1;31m"
BOLD_WHITE_ON_RED = "\033[41;37;1m"      # CRITICAL badge
BOLD_WHITE_ON_YELLOW = "\033[43;30;1m"   # HIGH badge
YELLOW = "\033[33m"
RESET = "\033[0m"
BOLD = "\033[1m"

# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

_SEPARATOR_WIDTH = 56
_BORDER = "/" * _SEPARATOR_WIDTH
_INDENT = "  "
_CONTENT_WIDTH = _SEPARATOR_WIDTH - len(_INDENT)


def _get(obj: Any, key: str, default: Any = None) -> Any:
    """Retrieve *key* from a dict **or** an attribute on a dataclass / object."""
    if isinstance(obj, dict):
        return obj.get(key, default)
    return getattr(obj, key, default)


def _wrap_text(text: str, width: int = 56, indent: str = "  ") -> str:
    """Word-wrap *text* so every line fits within *width* characters.

    Each line is prefixed with *indent*.  The effective content width is
    ``width - len(indent)``.
    """
    if not text:
        return ""
    content_width = max(width - len(indent), 20)
    wrapped = textwrap.fill(
        text,
        width=content_width,
        initial_indent=indent,
        subsequent_indent=indent,
    )
    return wrapped


def _risk_badge(level: str) -> str:
    """Return the risk-level string wrapped in the appropriate ANSI colour."""
    level_upper = (level or "").upper()
    if level_upper == "CRITICAL":
        return f"{BOLD_WHITE_ON_RED} CRITICAL {RESET}"
    if level_upper == "HIGH":
        return f"{BOLD_WHITE_ON_YELLOW} HIGH {RESET}"
    if level_upper == "MEDIUM":
        return f"{BOLD}{YELLOW}{level_upper}{RESET}"
    if level_upper == "LOW":
        return f"{YELLOW}{level_upper}{RESET}"
    # INFO or anything else -- plain text
    return level_upper


# ---------------------------------------------------------------------------
# Markdown-to-ANSI renderer
# ---------------------------------------------------------------------------

def _render_markdown_to_ansi(text: str) -> str:
    """Convert lightweight markdown from Claude's output to ANSI-styled text.

    Handles:
    - ``## Header`` -> BOLD red text
    - ``- bullet`` -> arrow-indented red text
    - ``| table | row |`` -> pass-through with indent
    - ``**bold**`` -> BOLD
    - Regular text -> wrapped red text
    """
    if not text or not text.strip():
        return ""

    lines: list[str] = []

    for raw_line in text.splitlines():
        stripped = raw_line.strip()

        if not stripped:
            lines.append("")
            continue

        # ## Header
        header_match = re.match(r"^#{1,3}\s+(.+)$", stripped)
        if header_match:
            header_text = _apply_inline_bold(header_match.group(1))
            lines.append(f"{BOLD_RED}{_INDENT}{header_text}{RESET}")
            continue

        # - bullet / * bullet
        bullet_match = re.match(r"^[-*]\s+(.+)$", stripped)
        if bullet_match:
            bullet_text = _apply_inline_bold(bullet_match.group(1))
            wrapped = textwrap.fill(
                bullet_text,
                width=_CONTENT_WIDTH - 2,
                initial_indent=f"{_INDENT}\u2192 ",
                subsequent_indent=f"{_INDENT}  ",
            )
            lines.append(f"{RED}{wrapped}{RESET}")
            continue

        # | table | row |
        if stripped.startswith("|"):
            lines.append(f"{RED}{_INDENT}{stripped}{RESET}")
            continue

        # Regular text — wrap and apply inline bold
        processed = _apply_inline_bold(stripped)
        wrapped = textwrap.fill(
            processed,
            width=_CONTENT_WIDTH,
            initial_indent=_INDENT,
            subsequent_indent=_INDENT,
        )
        lines.append(f"{RED}{wrapped}{RESET}")

    return "\n".join(lines)


def _apply_inline_bold(text: str) -> str:
    """Replace ``**bold**`` with ANSI bold sequences."""
    return re.sub(
        r"\*\*(.+?)\*\*",
        rf"{BOLD}\1{RESET}{RED}",
        text,
    )


# ---------------------------------------------------------------------------
# Public formatting functions
# ---------------------------------------------------------------------------


def print_scan_header(provider: str, refresh: bool = False) -> None:
    """Print the initial activation banner to stderr.

    Parameters
    ----------
    provider:
        ``"AWS"`` or ``"GCP"`` (displayed in the banner).
    refresh:
        If True, show a shorter refresh message instead of the first-run banner.
    """
    if refresh:
        lines = [
            f"{BOLD_RED}{_BORDER}{RESET}",
            f"{RED}  CLOUD WATCHDOG \u2014 Refreshing infrastructure ({provider}){RESET}",
            f"{BOLD_RED}{_BORDER}{RESET}",
        ]
    else:
        lines = [
            f"{BOLD_RED}{_BORDER}{RESET}",
            f"{RED}  CLOUD WATCHDOG{RESET}",
            f"{RED}  Initial infrastructure scan ({provider}){RESET}",
            f"{RED}  This first scan maps your infrastructure and may{RESET}",
            f"{RED}  take 30-60 seconds. Subsequent commands are faster.{RESET}",
            f"{BOLD_RED}{_BORDER}{RESET}",
        ]
    print("\n".join(lines), file=sys.stderr)
    sys.stderr.flush()


def print_scan_progress(service_name: str) -> None:
    """Print a single service scanning line to stderr.

    Parameters
    ----------
    service_name:
        Human-readable label, e.g. ``"EC2 Instances"``.
    """
    print(f"{RED}  \u2192 Scanning {service_name}...{RESET}", file=sys.stderr)
    sys.stderr.flush()


def print_scan_complete(summary: Dict[str, Any]) -> None:
    """Print the scan-completion banner to stderr.

    Parameters
    ----------
    summary:
        A dict (or dataclass-like object) with keys:
        ``account_or_project``, ``region``, ``resource_count``,
        ``relationship_count``, ``environments`` (a dict with
        ``prod``, ``staging``, ``dev``, ``unknown`` counts).
    """
    account = _get(summary, "account_or_project", "unknown")
    region = _get(summary, "region", "unknown")
    resource_count = _get(summary, "resource_count", 0)
    relationship_count = _get(summary, "relationship_count", 0)
    envs = _get(summary, "environments", {})
    prod = _get(envs, "prod", 0)
    staging = _get(envs, "staging", 0)
    dev = _get(envs, "dev", 0)

    lines = [
        f"{RED}  \u2713 Found: {resource_count} resources, {relationship_count} relationships{RESET}",
        f"{RED}  Account: {account} ({region}){RESET}",
        f"{RED}  Environments: {prod} prod \u00b7 {staging} staging \u00b7 {dev} dev{RESET}",
        f"{RED}  Watchdog is now supervising.{RESET}",
        f"{BOLD_RED}{_BORDER}{RESET}",
    ]
    print("\n".join(lines), file=sys.stderr)
    sys.stderr.flush()


def print_incremental_progress(service: str) -> None:
    """Print a one-liner for a quick single-service rescan.

    Parameters
    ----------
    service:
        The service being refreshed, e.g. ``"ec2"``, ``"s3"``.
    """
    print(
        f"{RED}  \u2192 Refreshing {service} infrastructure...{RESET}",
        file=sys.stderr,
    )
    sys.stderr.flush()


def format_warning(assessment: Any, parsed_command: Any) -> str:
    """Return the main risk-warning display.

    Parameters
    ----------
    assessment:
        Dict or object with keys: ``risk_level``, ``summary``,
        ``blast_radius`` (list of strings), ``explanation``,
        ``reversible`` (bool), ``recommendation``.
    parsed_command:
        Dict or object with ``raw_command``.
    """
    risk_level = _get(assessment, "risk_level", "UNKNOWN")
    raw_command = _get(parsed_command, "raw_command", "<unknown command>")
    blast_radius: List[str] = _get(assessment, "blast_radius", []) or []
    explanation = _get(assessment, "explanation", "")
    recommendation = _get(assessment, "recommendation", "")

    badge = _risk_badge(risk_level)

    lines: list[str] = [
        f"{BOLD_RED}{_BORDER}{RESET}",
        f"{RED}  Risk: {badge}{RESET}",
        f"{RED}  Command: {raw_command}{RESET}",
    ]

    cost_estimate = _get(assessment, "cost_estimate", "")
    if cost_estimate:
        lines.append(f"{RED}  Cost: {BOLD}{cost_estimate}{RESET}")

    lines.append("")

    if blast_radius:
        lines.append(f"{RED}  Blast Radius:{RESET}")
        for item in blast_radius:
            lines.append(f"{RED}  \u2192 {item}{RESET}")
        lines.append("")

    if explanation:
        lines.append(f"{RED}  Assessment:{RESET}")
        wrapped = _wrap_text(explanation, width=_SEPARATOR_WIDTH, indent="  ")
        lines.append(f"{RED}{wrapped}{RESET}")
        lines.append("")

    # Detailed analysis (rich markdown from Claude)
    detailed_analysis = _get(assessment, "detailed_analysis", "")
    if detailed_analysis:
        rendered = _render_markdown_to_ansi(detailed_analysis)
        if rendered.strip():
            lines.append(f"{RED}  {'─' * (_SEPARATOR_WIDTH - 4)}{RESET}")
            lines.append(rendered)
            lines.append("")

    if recommendation:
        rec_wrapped = _wrap_text(
            f"Recommendation: {recommendation}",
            width=_SEPARATOR_WIDTH,
            indent="  ",
        )
        lines.append(f"{RED}{rec_wrapped}{RESET}")

    lines.append(f"{BOLD_RED}{_BORDER}{RESET}")
    return "\n".join(lines)


def format_fallback_warning(action_type: str, environment: str) -> str:
    """Return a simple fallback warning when the Claude brain is unavailable.

    Parameters
    ----------
    action_type:
        A short description of what the command does, e.g.
        ``"delete"``, ``"modify"``, ``"create"``.
    environment:
        The inferred environment, e.g. ``"production"``, ``"staging"``.
    """
    env_display = (environment or "unknown").lower()
    action_display = (action_type or "unknown action").lower()

    if env_display in ("prod", "production"):
        severity_line = (
            f"  {_risk_badge('CRITICAL')} {RED}Production environment detected{RESET}"
        )
    elif env_display == "staging":
        severity_line = (
            f"  {_risk_badge('HIGH')} {RED}Staging environment detected{RESET}"
        )
    else:
        severity_line = (
            f"  {_risk_badge('MEDIUM')} {RED}Environment: {env_display}{RESET}"
        )

    lines = [
        f"{BOLD_RED}{_BORDER}{RESET}",
        severity_line,
        f"{RED}  Action type: {action_display}{RESET}",
        "",
        f"{RED}  Detailed analysis unavailable (brain offline).{RESET}",
        f"{RED}  Proceed with caution.{RESET}",
        f"{BOLD_RED}{_BORDER}{RESET}",
    ]
    return "\n".join(lines)
