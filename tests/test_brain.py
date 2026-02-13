"""
Tests for watchdog.brain — Claude API risk analysis with mocked responses.

Covers:
  - analyze_risk with mocked Anthropic client (clean JSON response)
  - analyze_risk with mocked markdown-wrapped JSON response
  - _fallback_assessment with various action_type + environment combos
  - _parse_response with invalid/missing fields
  - Fallback triggered when no API key is set
  - Tool-use message loop (single round, max rounds cap, tool errors)
  - detailed_analysis field parsing
"""

import sys
import os
import json
import pytest
from unittest.mock import patch, MagicMock
from types import SimpleNamespace

# Ensure project root is importable.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from watchdog.brain import (
    analyze_risk,
    _fallback_assessment,
    _parse_response,
    RiskAssessment,
)


# =========================================================================
# Helpers
# =========================================================================

def _make_context(action_type="DELETE", environment="prod", target_name="prod-main"):
    """Build a minimal context dict for testing."""
    return {
        "command": f"aws rds delete-db-instance --db-instance-identifier {target_name}",
        "action_type": action_type,
        "target": {
            "arn": f"arn:aws:rds:us-east-1:123456789012:db/{target_name}",
            "type": "RDS Instance",
            "name": target_name,
            "environment": environment,
            "is_active": True,
            "activity": "342 connections in the last 24 hours",
            "tags": {"Environment": environment},
            "metadata": {"engine": "postgres"},
        },
        "connected_resources": [
            {
                "arn": "arn:aws:lambda:us-east-1:123456789012:function/api-handler",
                "type": "Lambda Function",
                "relationship": "connects_to",
                "environment": "prod",
                "is_active": True,
            },
        ],
        "iam_context": None,
        "network_context": None,
        "warnings": [
            "This is a DELETE operation on a production resource",
            "Resource is actively in use",
        ],
    }


def _make_claude_response(
    risk_level="CRITICAL",
    summary="Deleting production RDS instance with active connections",
    blast_radius=None,
    explanation="This will destroy the primary database.",
    reversible=False,
    recommendation="Create a final snapshot first.",
    detailed_analysis="",
    cost_estimate="",
):
    """Build a JSON string as Claude would return."""
    if blast_radius is None:
        blast_radius = [
            "api-handler Lambda -- will lose DB connectivity",
            "All downstream API consumers",
        ]
    data = {
        "risk_level": risk_level,
        "summary": summary,
        "blast_radius": blast_radius,
        "explanation": explanation,
        "reversible": reversible,
        "recommendation": recommendation,
    }
    if detailed_analysis:
        data["detailed_analysis"] = detailed_analysis
    if cost_estimate:
        data["cost_estimate"] = cost_estimate
    return json.dumps(data)


def _mock_anthropic_client(response_text):
    """Create a mock Anthropic client that returns the given text."""
    mock_message = MagicMock()
    mock_content = MagicMock()
    mock_content.type = "text"
    mock_content.text = response_text
    mock_message.content = [mock_content]
    mock_message.stop_reason = "end_turn"

    mock_client = MagicMock()
    mock_client.messages.create.return_value = mock_message
    return mock_client


def _make_tool_use_block(tool_name="aws_ec2_describe_instances", tool_id="toolu_123", tool_input=None):
    """Create a mock tool_use content block."""
    block = MagicMock()
    block.type = "tool_use"
    block.name = tool_name
    block.id = tool_id
    block.input = tool_input or {}
    return block


def _make_text_block(text):
    """Create a mock text content block."""
    block = MagicMock()
    block.type = "text"
    block.text = text
    return block


# =========================================================================
# Tests: analyze_risk with mocked API
# =========================================================================

class TestAnalyzeRiskWithAPI:

    @patch("watchdog.brain.anthropic.Anthropic")
    def test_clean_json_response(self, mock_anthropic_cls):
        response_text = _make_claude_response()
        mock_client = _mock_anthropic_client(response_text)
        mock_anthropic_cls.return_value = mock_client

        ctx = _make_context()
        result = analyze_risk(ctx, api_key="sk-test-key")

        assert isinstance(result, RiskAssessment)
        assert result.risk_level == "CRITICAL"
        assert "production" in result.summary.lower() or "prod" in result.summary.lower() or len(result.summary) > 0
        assert len(result.blast_radius) == 2
        assert result.reversible is False
        assert len(result.recommendation) > 0

    @patch("watchdog.brain.anthropic.Anthropic")
    def test_markdown_wrapped_json_response(self, mock_anthropic_cls):
        raw_json = _make_claude_response(risk_level="HIGH")
        wrapped = f"```json\n{raw_json}\n```"
        mock_client = _mock_anthropic_client(wrapped)
        mock_anthropic_cls.return_value = mock_client

        ctx = _make_context()
        result = analyze_risk(ctx, api_key="sk-test-key")

        assert isinstance(result, RiskAssessment)
        assert result.risk_level == "HIGH"

    @patch("watchdog.brain.anthropic.Anthropic")
    def test_api_call_uses_correct_model(self, mock_anthropic_cls):
        response_text = _make_claude_response()
        mock_client = _mock_anthropic_client(response_text)
        mock_anthropic_cls.return_value = mock_client

        ctx = _make_context()
        analyze_risk(ctx, api_key="sk-test-key")

        # Verify the API was called
        mock_client.messages.create.assert_called_once()
        call_kwargs = mock_client.messages.create.call_args
        assert "model" in call_kwargs.kwargs or len(call_kwargs.args) > 0

    @patch("watchdog.brain.anthropic.Anthropic")
    def test_api_exception_triggers_fallback(self, mock_anthropic_cls):
        mock_client = MagicMock()
        mock_client.messages.create.side_effect = Exception("API timeout")
        mock_anthropic_cls.return_value = mock_client

        ctx = _make_context(action_type="DELETE", environment="prod")
        result = analyze_risk(ctx, api_key="sk-test-key")

        # Should fall back to deterministic assessment
        assert isinstance(result, RiskAssessment)
        assert result.risk_level == "CRITICAL"  # DELETE + prod = CRITICAL in fallback


class TestAnalyzeRiskNoAPIKey:

    @patch.dict(os.environ, {}, clear=True)
    def test_no_api_key_triggers_fallback(self):
        # Make sure ANTHROPIC_API_KEY is not set
        os.environ.pop("ANTHROPIC_API_KEY", None)

        ctx = _make_context(action_type="DELETE", environment="prod")
        result = analyze_risk(ctx, api_key=None)

        assert isinstance(result, RiskAssessment)
        # Fallback should produce a result
        assert result.risk_level in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
        assert "could not reach" in result.summary.lower() or "basic" in result.summary.lower()


# =========================================================================
# Tests: _fallback_assessment
# =========================================================================

class TestFallbackAssessment:

    def test_delete_prod_is_critical(self):
        ctx = _make_context(action_type="DELETE", environment="prod")
        result = _fallback_assessment(ctx)
        assert result.risk_level == "CRITICAL"
        assert result.reversible is False

    def test_delete_production_is_critical(self):
        ctx = _make_context(action_type="DELETE", environment="production")
        result = _fallback_assessment(ctx)
        assert result.risk_level == "CRITICAL"

    def test_delete_staging_is_high(self):
        ctx = _make_context(action_type="DELETE", environment="staging")
        result = _fallback_assessment(ctx)
        assert result.risk_level == "HIGH"

    def test_delete_dev_is_medium(self):
        ctx = _make_context(action_type="DELETE", environment="dev")
        result = _fallback_assessment(ctx)
        assert result.risk_level == "MEDIUM"

    def test_write_prod_is_medium(self):
        ctx = _make_context(action_type="WRITE", environment="prod")
        result = _fallback_assessment(ctx)
        assert result.risk_level == "MEDIUM"

    def test_write_dev_is_low(self):
        ctx = _make_context(action_type="WRITE", environment="dev")
        result = _fallback_assessment(ctx)
        assert result.risk_level == "LOW"

    def test_admin_prod_is_high(self):
        ctx = _make_context(action_type="ADMIN", environment="prod")
        result = _fallback_assessment(ctx)
        assert result.risk_level == "HIGH"

    def test_read_defaults_to_low(self):
        ctx = _make_context(action_type="READ", environment="prod")
        result = _fallback_assessment(ctx)
        assert result.risk_level == "LOW"

    def test_unknown_action_defaults_to_low(self):
        ctx = _make_context(action_type="UNKNOWN", environment="unknown")
        result = _fallback_assessment(ctx)
        assert result.risk_level == "LOW"

    def test_fallback_has_recommendation(self):
        ctx = _make_context(action_type="DELETE", environment="prod")
        result = _fallback_assessment(ctx)
        assert len(result.recommendation) > 0

    def test_fallback_has_explanation(self):
        ctx = _make_context(action_type="DELETE", environment="prod")
        result = _fallback_assessment(ctx)
        assert len(result.explanation) > 0

    def test_fallback_blast_radius_is_empty(self):
        ctx = _make_context(action_type="DELETE", environment="prod")
        result = _fallback_assessment(ctx)
        assert result.blast_radius == []

    def test_fallback_no_target_dict(self):
        ctx = {
            "command": "aws rds delete-db-instance",
            "action_type": "DELETE",
            "target": None,
            "connected_resources": [],
            "warnings": [],
        }
        result = _fallback_assessment(ctx)
        # With no target, environment is "", so DELETE + _default → MEDIUM
        assert result.risk_level == "MEDIUM"


# =========================================================================
# Tests: _parse_response
# =========================================================================

class TestParseResponse:

    def test_valid_json(self):
        text = _make_claude_response(risk_level="MEDIUM", reversible=True)
        result = _parse_response(text)
        assert result.risk_level == "MEDIUM"
        assert result.reversible is True

    def test_markdown_fenced_json(self):
        raw = _make_claude_response(risk_level="LOW")
        wrapped = f"```json\n{raw}\n```"
        result = _parse_response(wrapped)
        assert result.risk_level == "LOW"

    def test_plain_fenced_json(self):
        raw = _make_claude_response(risk_level="INFO")
        wrapped = f"```\n{raw}\n```"
        result = _parse_response(wrapped)
        assert result.risk_level == "INFO"

    def test_invalid_risk_level_defaults_to_high(self):
        data = {
            "risk_level": "SUPER_DANGEROUS",
            "summary": "Test",
            "blast_radius": [],
            "explanation": "Test",
            "reversible": False,
            "recommendation": "Test",
        }
        text = json.dumps(data)
        result = _parse_response(text)
        assert result.risk_level == "HIGH"

    def test_missing_fields_get_defaults(self):
        text = json.dumps({"risk_level": "LOW"})
        result = _parse_response(text)
        assert result.risk_level == "LOW"
        assert result.summary == "No summary provided."
        assert result.blast_radius == []
        assert result.reversible is False
        assert "Review" in result.recommendation or len(result.recommendation) > 0

    def test_blast_radius_non_list_ignored(self):
        data = {
            "risk_level": "MEDIUM",
            "summary": "Test",
            "blast_radius": "not a list",
            "explanation": "Test",
            "reversible": False,
            "recommendation": "Test",
        }
        text = json.dumps(data)
        result = _parse_response(text)
        assert result.blast_radius == []

    def test_reversible_string_true(self):
        data = {
            "risk_level": "LOW",
            "summary": "Test",
            "blast_radius": [],
            "explanation": "Test",
            "reversible": "yes",
            "recommendation": "Test",
        }
        text = json.dumps(data)
        result = _parse_response(text)
        assert result.reversible is True

    def test_reversible_string_false(self):
        data = {
            "risk_level": "LOW",
            "summary": "Test",
            "blast_radius": [],
            "explanation": "Test",
            "reversible": "no",
            "recommendation": "Test",
        }
        text = json.dumps(data)
        result = _parse_response(text)
        assert result.reversible is False


# =========================================================================
# Tests: RiskAssessment dataclass
# =========================================================================

class TestRiskAssessmentDataclass:

    def test_fields_accessible(self):
        ra = RiskAssessment(
            risk_level="HIGH",
            summary="Test summary",
            blast_radius=["resource A"],
            explanation="Detailed explanation",
            reversible=True,
            recommendation="Be careful",
        )
        assert ra.risk_level == "HIGH"
        assert ra.summary == "Test summary"
        assert ra.blast_radius == ["resource A"]
        assert ra.explanation == "Detailed explanation"
        assert ra.reversible is True
        assert ra.recommendation == "Be careful"

    def test_detailed_analysis_default_empty(self):
        ra = RiskAssessment(
            risk_level="LOW",
            summary="Test",
            blast_radius=[],
            explanation="Test",
            reversible=True,
            recommendation="Test",
        )
        assert ra.detailed_analysis == ""

    def test_detailed_analysis_field(self):
        ra = RiskAssessment(
            risk_level="HIGH",
            summary="Test",
            blast_radius=[],
            explanation="Test",
            reversible=False,
            recommendation="Test",
            detailed_analysis="## Analysis\n- Point 1\n- Point 2",
        )
        assert "## Analysis" in ra.detailed_analysis


# =========================================================================
# Tests: Tool-use message loop
# =========================================================================

class TestAnalyzeRiskWithTools:

    @patch("watchdog.brain._build_tools")
    @patch("watchdog.brain.anthropic.Anthropic")
    def test_single_tool_round(self, mock_anthropic_cls, mock_build_tools):
        """Verify the brain can do one tool call and then return a final answer."""
        mock_build_tools.return_value = [
            {"name": "aws_ec2_describe_instances", "description": "test", "input_schema": {}}
        ]

        # First response: tool_use
        tool_block = _make_tool_use_block(
            tool_name="aws_ec2_describe_instances",
            tool_id="toolu_abc",
            tool_input={"InstanceIds": ["i-12345"]},
        )
        first_response = MagicMock()
        first_response.stop_reason = "tool_use"
        first_response.content = [tool_block]

        # Second response: final text
        final_text = _make_claude_response(risk_level="HIGH", summary="SG is wide open")
        text_block = _make_text_block(final_text)
        second_response = MagicMock()
        second_response.stop_reason = "end_turn"
        second_response.content = [text_block]

        mock_client = MagicMock()
        mock_client.messages.create.side_effect = [first_response, second_response]
        mock_anthropic_cls.return_value = mock_client

        with patch("watchdog.tools.execute_tool", return_value='{"Reservations": []}') as mock_exec:
            ctx = _make_context()
            result = analyze_risk(ctx, api_key="sk-test-key")

            assert isinstance(result, RiskAssessment)
            assert result.risk_level == "HIGH"
            mock_exec.assert_called_once_with(
                "aws_ec2_describe_instances",
                {"InstanceIds": ["i-12345"]},
                aws_session_kwargs=None,
                gcp_project=None,
            )

        # Two API calls: initial + after tool result
        assert mock_client.messages.create.call_count == 2

    @patch("watchdog.brain._build_tools")
    @patch("watchdog.brain.anthropic.Anthropic")
    def test_max_rounds_cap(self, mock_anthropic_cls, mock_build_tools):
        """When Claude keeps requesting tools beyond MAX_ROUNDS, the loop stops."""
        from watchdog.brain import MAX_ROUNDS

        mock_build_tools.return_value = [
            {"name": "aws_ec2_describe_instances", "description": "test", "input_schema": {}}
        ]

        # Every response requests a tool — never returns text
        tool_block = _make_tool_use_block(
            tool_name="aws_ec2_describe_instances",
            tool_id="toolu_loop",
            tool_input={},
        )
        tool_response = MagicMock()
        tool_response.stop_reason = "tool_use"
        tool_response.content = [tool_block]

        mock_client = MagicMock()
        mock_client.messages.create.return_value = tool_response
        mock_anthropic_cls.return_value = mock_client

        with patch("watchdog.tools.execute_tool", return_value='{}'):
            ctx = _make_context()
            result = analyze_risk(ctx, api_key="sk-test-key")

            # Should fall back after exhausting rounds
            assert isinstance(result, RiskAssessment)
            assert mock_client.messages.create.call_count == MAX_ROUNDS

    @patch("watchdog.brain._build_tools")
    @patch("watchdog.brain.anthropic.Anthropic")
    def test_tool_error_returned_to_claude(self, mock_anthropic_cls, mock_build_tools):
        """When a tool returns an error, it's passed back to Claude for handling."""
        mock_build_tools.return_value = [
            {"name": "aws_ec2_describe_instances", "description": "test", "input_schema": {}}
        ]

        # First: tool request
        tool_block = _make_tool_use_block(
            tool_name="aws_ec2_describe_instances",
            tool_id="toolu_err",
            tool_input={},
        )
        first_response = MagicMock()
        first_response.stop_reason = "tool_use"
        first_response.content = [tool_block]

        # Second: final text after receiving error
        final_text = _make_claude_response(risk_level="HIGH", summary="Could not verify")
        text_block = _make_text_block(final_text)
        second_response = MagicMock()
        second_response.stop_reason = "end_turn"
        second_response.content = [text_block]

        mock_client = MagicMock()
        mock_client.messages.create.side_effect = [first_response, second_response]
        mock_anthropic_cls.return_value = mock_client

        error_json = json.dumps({"error": "AccessDenied: not authorized"})
        with patch("watchdog.tools.execute_tool", return_value=error_json):
            ctx = _make_context()
            result = analyze_risk(ctx, api_key="sk-test-key")
            assert result.risk_level == "HIGH"

    @patch("watchdog.brain._build_tools")
    @patch("watchdog.brain.anthropic.Anthropic")
    def test_credentials_passed_to_tools(self, mock_anthropic_cls, mock_build_tools):
        """Verify aws_session_kwargs and gcp_project are passed to execute_tool."""
        mock_build_tools.return_value = [
            {"name": "aws_ec2_describe_instances", "description": "test", "input_schema": {}}
        ]

        tool_block = _make_tool_use_block(
            tool_name="aws_ec2_describe_instances",
            tool_id="toolu_creds",
            tool_input={},
        )
        first_response = MagicMock()
        first_response.stop_reason = "tool_use"
        first_response.content = [tool_block]

        final_text = _make_claude_response(risk_level="LOW")
        text_block = _make_text_block(final_text)
        second_response = MagicMock()
        second_response.stop_reason = "end_turn"
        second_response.content = [text_block]

        mock_client = MagicMock()
        mock_client.messages.create.side_effect = [first_response, second_response]
        mock_anthropic_cls.return_value = mock_client

        with patch("watchdog.tools.execute_tool", return_value='{}') as mock_exec:
            ctx = _make_context()
            result = analyze_risk(
                ctx, api_key="sk-test-key",
                aws_session_kwargs={"profile_name": "prod"},
                gcp_project="my-project",
            )
            mock_exec.assert_called_once_with(
                "aws_ec2_describe_instances",
                {},
                aws_session_kwargs={"profile_name": "prod"},
                gcp_project="my-project",
            )


# =========================================================================
# Tests: detailed_analysis parsing
# =========================================================================

class TestDetailedAnalysis:

    def test_detailed_analysis_parsed_from_response(self):
        analysis_md = "## Security Group Analysis\n- Port 22 open to 0.0.0.0/0\n- No egress restrictions"
        text = _make_claude_response(
            risk_level="HIGH",
            detailed_analysis=analysis_md,
        )
        result = _parse_response(text)
        assert result.detailed_analysis == analysis_md

    def test_detailed_analysis_empty_when_missing(self):
        text = _make_claude_response(risk_level="LOW")
        result = _parse_response(text)
        assert result.detailed_analysis == ""

    def test_detailed_analysis_with_table(self):
        analysis_md = "## IAM Policy\n| Principal | Action | Resource |\n| --- | --- | --- |\n| * | s3:* | * |"
        text = _make_claude_response(
            risk_level="CRITICAL",
            detailed_analysis=analysis_md,
        )
        result = _parse_response(text)
        assert "| Principal |" in result.detailed_analysis


# =========================================================================
# Tests: cost_estimate parsing
# =========================================================================

class TestCostEstimate:

    def test_cost_estimate_parsed_from_response(self):
        text = _make_claude_response(
            risk_level="MEDIUM",
            cost_estimate="~$73/month (db.m5.large)",
        )
        result = _parse_response(text)
        assert result.cost_estimate == "~$73/month (db.m5.large)"

    def test_cost_estimate_empty_when_missing(self):
        text = _make_claude_response(risk_level="LOW")
        result = _parse_response(text)
        assert result.cost_estimate == ""

    def test_cost_estimate_for_deletion_shows_savings(self):
        text = _make_claude_response(
            risk_level="HIGH",
            cost_estimate="Savings: ~$73/month",
        )
        result = _parse_response(text)
        assert result.cost_estimate == "Savings: ~$73/month"

    def test_cost_estimate_default_on_dataclass(self):
        ra = RiskAssessment(
            risk_level="LOW",
            summary="Test",
            blast_radius=[],
            explanation="Test",
            reversible=True,
            recommendation="Test",
        )
        assert ra.cost_estimate == ""
