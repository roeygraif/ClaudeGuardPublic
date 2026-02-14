"""
Cloud Watchdog Brain — Risk assessment data model and mapping tables.

Provides the ``RiskAssessment`` dataclass and deterministic risk-level
mappings used by the hook to classify cloud operations by action type
and environment.
"""

from dataclasses import dataclass


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
    detailed_analysis: str = ""  # Optional rich markdown
    cost_estimate: str = ""      # e.g. "~$73/month (db.m5.large)"


# ---------------------------------------------------------------------------
# Risk-level mapping tables
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
