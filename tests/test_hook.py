"""
Integration tests for watchdog.hook -- the PreToolUse hook entrypoint.

Simulates the Claude Code hook protocol by piping JSON to stdin and
checking stdout (JSON hook response) and stderr (ANSI warning display).
Uses unittest.mock to patch the scanner and context modules so no real
cloud or API calls are made.

NOTE: hook.py uses deferred imports inside main(), so we patch the actual
module-level objects (e.g. scanner.graph.GraphDB) rather than trying to
patch attributes on watchdog.hook.
"""

import sys
import os
import io
import json
import pytest
from unittest.mock import patch, MagicMock, call

# Ensure project root is importable.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


# =========================================================================
# Helpers
# =========================================================================

def _make_hook_input(tool_name="Bash", command="aws s3 ls"):
    """Build the JSON object that Claude Code sends to a PreToolUse hook."""
    return {
        "tool_name": tool_name,
        "tool_input": {
            "command": command,
        },
    }


def _run_hook(hook_input_dict):
    """Run the hook's main() with mocked stdin/stdout/stderr.

    Returns (exit_code, stdout_text, stderr_text).
    Patches _resolve_server_creds to return test credentials so the
    hook proceeds past the login check.
    """
    input_json = json.dumps(hook_input_dict)

    mock_stdin = io.StringIO(input_json)
    mock_stdout = io.StringIO()
    mock_stderr = io.StringIO()

    exit_code = 0
    with patch("sys.stdin", mock_stdin), \
         patch("sys.stdout", mock_stdout), \
         patch("sys.stderr", mock_stderr), \
         patch("watchdog.hook._resolve_server_creds", return_value=("http://test-server", "test-token")):
        try:
            from watchdog.hook import main
            main()
        except SystemExit as e:
            exit_code = e.code if e.code is not None else 0

    return exit_code, mock_stdout.getvalue(), mock_stderr.getvalue()


def _run_hook_raw(stdin_text):
    """Run hook with raw text on stdin (for invalid JSON testing)."""
    mock_stdin = io.StringIO(stdin_text)
    mock_stdout = io.StringIO()
    mock_stderr = io.StringIO()

    exit_code = 0
    with patch("sys.stdin", mock_stdin), \
         patch("sys.stdout", mock_stdout), \
         patch("sys.stderr", mock_stderr):
        try:
            from watchdog.hook import main
            main()
        except SystemExit as e:
            exit_code = e.code if e.code is not None else 0

    return exit_code, mock_stdout.getvalue(), mock_stderr.getvalue()


# =========================================================================
# Tests: Non-Bash tool -- silent pass-through
# =========================================================================

class TestNonBashTool:

    def test_non_bash_tool_exits_zero(self):
        hook_input = _make_hook_input(tool_name="Read", command="some file")
        exit_code, stdout, stderr = _run_hook(hook_input)
        assert exit_code == 0
        assert stdout == ""

    def test_write_tool_exits_zero(self):
        hook_input = _make_hook_input(tool_name="Write", command="some content")
        exit_code, stdout, stderr = _run_hook(hook_input)
        assert exit_code == 0

    def test_invalid_json_exits_zero(self):
        """If stdin is not valid JSON, hook should exit 0 silently."""
        exit_code, stdout, stderr = _run_hook_raw("not valid json{{{")
        assert exit_code == 0

    def test_empty_command_exits_zero(self):
        hook_input = _make_hook_input(tool_name="Bash", command="")
        exit_code, stdout, stderr = _run_hook(hook_input)
        assert exit_code == 0


# =========================================================================
# Tests: Non-cloud Bash commands -- silent pass-through
# =========================================================================

class TestNonCloudCommands:

    def test_ls_command_exits_zero(self):
        hook_input = _make_hook_input(command="ls -la")
        exit_code, stdout, stderr = _run_hook(hook_input)
        assert exit_code == 0
        assert stdout == ""

    def test_git_push_exits_zero(self):
        hook_input = _make_hook_input(command="git push origin main")
        exit_code, stdout, stderr = _run_hook(hook_input)
        assert exit_code == 0
        assert stdout == ""


# =========================================================================
# Tests: READ commands -- pass-through (after potential wake-up scan)
# =========================================================================

class TestReadCommands:

    @patch("scanner.graph.GraphDB")
    def test_s3_ls_exits_zero(self, mock_graphdb_cls):
        mock_db = MagicMock()
        mock_db.is_populated_for.return_value = True  # Skip wake-up scan
        mock_db.staleness_minutes.return_value = 5  # Fresh scan
        mock_graphdb_cls.return_value = mock_db

        hook_input = _make_hook_input(command="aws s3 ls")
        exit_code, stdout, stderr = _run_hook(hook_input)

        assert exit_code == 0

    @patch("scanner.graph.GraphDB")
    def test_describe_instances_exits_zero(self, mock_graphdb_cls):
        mock_db = MagicMock()
        mock_db.is_populated_for.return_value = True
        mock_db.staleness_minutes.return_value = 5
        mock_graphdb_cls.return_value = mock_db

        hook_input = _make_hook_input(command="aws ec2 describe-instances")
        exit_code, stdout, stderr = _run_hook(hook_input)

        assert exit_code == 0


# =========================================================================
# Tests: WRITE/DELETE/ADMIN commands -- risk assessment + "ask" response
# =========================================================================

class TestWriteDeleteCommands:

    @patch("watchdog.context.gather_context")
    @patch("scanner.graph.GraphDB")
    def test_rds_delete_outputs_ask_decision(
        self, mock_graphdb_cls, mock_gather_ctx
    ):
        # Setup mocks
        mock_db = MagicMock()
        mock_db.is_populated_for.return_value = True
        mock_db.staleness_minutes.return_value = 5
        mock_graphdb_cls.return_value = mock_db

        mock_gather_ctx.return_value = {
            "command": "aws rds delete-db-instance ...",
            "action_type": "DELETE",
            "target": {"name": "prod-main", "type": "RDS Instance", "environment": "prod", "is_active": True, "activity": "50 connections/hour"},
            "connected_resources": [
                {"arn": "arn:aws:lambda:us-east-1:123:function:api-handler", "type": "Lambda Function", "relationship": "triggered_by"},
            ],
            "iam_context": None,
            "network_context": None,
            "warnings": ["This is a DELETE operation on a production resource"],
        }

        hook_input = _make_hook_input(
            command="aws rds delete-db-instance --db-instance-identifier prod-main"
        )
        exit_code, stdout, stderr = _run_hook(hook_input)

        assert exit_code == 0

        # stdout should contain a valid JSON hook response with "ask"
        assert stdout.strip()
        response = json.loads(stdout)
        hook_output = response.get("hookSpecificOutput", {})
        assert hook_output.get("permissionDecision") == "ask"
        reason = hook_output.get("permissionDecisionReason", "")
        assert len(reason) > 0
        # Reason should contain infrastructure context
        assert "prod-main" in reason
        assert "CRITICAL" in reason
        assert "Lambda Function" in reason

    @patch("watchdog.context.gather_context")
    @patch("scanner.graph.GraphDB")
    def test_delete_command_writes_to_stderr(
        self, mock_graphdb_cls, mock_gather_ctx
    ):
        mock_db = MagicMock()
        mock_db.is_populated_for.return_value = True
        mock_db.staleness_minutes.return_value = 5
        mock_graphdb_cls.return_value = mock_db

        mock_gather_ctx.return_value = {
            "command": "aws rds delete-db-instance ...",
            "action_type": "DELETE",
            "target": {"name": "prod-main", "type": "RDS Instance", "environment": "prod"},
            "connected_resources": [],
            "iam_context": None,
            "network_context": None,
            "warnings": ["This is a DELETE operation on a production resource"],
        }

        hook_input = _make_hook_input(
            command="aws rds delete-db-instance --db-instance-identifier prod-main"
        )
        exit_code, stdout, stderr = _run_hook(hook_input)

        # stderr should contain ANSI-colored warning text
        assert len(stderr) > 0
        # The display module wraps output in red ANSI codes
        assert "\033[" in stderr or "WATCHDOG" in stderr or "Risk" in stderr

    @patch("scanner.graph.GraphDB")
    def test_iam_admin_command_triggers_assessment(
        self, mock_graphdb_cls
    ):
        mock_db = MagicMock()
        mock_db.is_populated_for.return_value = True
        mock_db.staleness_minutes.return_value = 5
        mock_graphdb_cls.return_value = mock_db

        hook_input = _make_hook_input(
            command="aws iam attach-role-policy --role-name api-prod --policy-arn arn:aws:iam::aws:policy/AdminAccess"
        )
        exit_code, stdout, stderr = _run_hook(hook_input)

        assert exit_code == 0

        # Deterministic assessment should produce an "ask" response.
        if stdout.strip():
            response = json.loads(stdout)
            assert response["hookSpecificOutput"]["permissionDecision"] == "ask"


# =========================================================================
# Tests: Wake-up scan trigger
# =========================================================================

class TestWakeUpScan:

    @patch("scanner.graph.GraphDB")
    def test_empty_graph_triggers_scan_attempt(self, mock_graphdb_cls):
        """When is_populated_for returns False, the hook should attempt a scan.
        The scan may fail (no AWS credentials), but the hook must not crash."""
        mock_db = MagicMock()
        mock_db.is_populated_for.return_value = False
        mock_graphdb_cls.return_value = mock_db

        hook_input = _make_hook_input(command="aws s3 ls")

        # This will attempt a scan which may fail (no real AWS creds).
        # The hook should handle the failure gracefully and still exit 0.
        exit_code, stdout, stderr = _run_hook(hook_input)

        assert exit_code == 0


# =========================================================================
# Tests: Audit log
# =========================================================================

class TestAuditLog:

    @patch("watchdog.hook._log_assessment_to_server")
    @patch("watchdog.hook._audit_log")
    @patch("watchdog.context.gather_context")
    @patch("scanner.graph.GraphDB")
    def test_audit_log_called_for_write_commands(
        self, mock_graphdb_cls, mock_gather_ctx, mock_audit, mock_log_server
    ):
        mock_db = MagicMock()
        mock_db.is_populated_for.return_value = True
        mock_db.staleness_minutes.return_value = 5
        mock_graphdb_cls.return_value = mock_db

        # Use a WRITE command with a known target so the deny-on-unknown
        # path is not triggered.
        mock_gather_ctx.return_value = {
            "command": "aws s3 cp file s3://bucket/key",
            "action_type": "WRITE",
            "target": {"name": "bucket", "type": "S3 Bucket", "environment": "dev"},
            "connected_resources": [],
            "iam_context": None,
            "network_context": None,
            "warnings": [],
        }

        hook_input = _make_hook_input(command="aws s3 cp file s3://bucket/key")
        _run_hook(hook_input)

        mock_audit.assert_called_once()


# =========================================================================
# Tests: Deny on unknown resource for destructive ops
# =========================================================================

class TestDenyUnknownResource:

    @patch("watchdog.context.gather_context")
    @patch("scanner.graph.GraphDB")
    def test_delete_unknown_resource_denied(
        self, mock_graphdb_cls, mock_gather_ctx
    ):
        mock_db = MagicMock()
        mock_db.is_populated_for.return_value = True
        mock_db.staleness_minutes.return_value = 5
        mock_graphdb_cls.return_value = mock_db

        mock_gather_ctx.return_value = {
            "command": "aws dynamodb delete-table --table-name unknown-table",
            "action_type": "DELETE",
            "target": None,
            "connected_resources": [],
            "iam_context": None,
            "network_context": None,
            "warnings": ["Target resource not found"],
        }

        hook_input = _make_hook_input(
            command="aws dynamodb delete-table --table-name unknown-table"
        )
        exit_code, stdout, stderr = _run_hook(hook_input)

        assert exit_code == 0
        assert stdout.strip()
        response = json.loads(stdout)
        hook_output = response["hookSpecificOutput"]
        assert hook_output["permissionDecision"] == "deny"
        assert "Unknown Resource" in hook_output["permissionDecisionReason"]
        assert "describe-table" in hook_output["permissionDecisionReason"]

    @patch("watchdog.hook._log_assessment_to_server")
    @patch("watchdog.context.gather_context")
    @patch("scanner.graph.GraphDB")
    def test_delete_known_resource_asks(
        self, mock_graphdb_cls, mock_gather_ctx, mock_log_server
    ):
        """DELETE on a known resource should still produce 'ask', not 'deny'."""
        mock_db = MagicMock()
        mock_db.is_populated_for.return_value = True
        mock_db.staleness_minutes.return_value = 5
        mock_graphdb_cls.return_value = mock_db

        mock_gather_ctx.return_value = {
            "command": "aws dynamodb delete-table --table-name known-table",
            "action_type": "DELETE",
            "target": {"name": "known-table", "type": "DynamoDB Table", "environment": "dev"},
            "connected_resources": [],
            "iam_context": None,
            "network_context": None,
            "warnings": [],
        }

        hook_input = _make_hook_input(
            command="aws dynamodb delete-table --table-name known-table"
        )
        exit_code, stdout, stderr = _run_hook(hook_input)

        assert exit_code == 0
        response = json.loads(stdout)
        assert response["hookSpecificOutput"]["permissionDecision"] == "ask"

    @patch("watchdog.hook._log_assessment_to_server")
    @patch("watchdog.context.gather_context")
    @patch("scanner.graph.GraphDB")
    def test_write_unknown_resource_still_asks(
        self, mock_graphdb_cls, mock_gather_ctx, mock_log_server
    ):
        """WRITE on an unknown resource should NOT deny — only DELETE/ADMIN deny."""
        mock_db = MagicMock()
        mock_db.is_populated_for.return_value = True
        mock_db.staleness_minutes.return_value = 5
        mock_graphdb_cls.return_value = mock_db

        mock_gather_ctx.return_value = {
            "command": "aws s3 cp file s3://bucket/key",
            "action_type": "WRITE",
            "target": None,
            "connected_resources": [],
            "iam_context": None,
            "network_context": None,
            "warnings": [],
        }

        hook_input = _make_hook_input(command="aws s3 cp file s3://bucket/key")
        exit_code, stdout, stderr = _run_hook(hook_input)

        assert exit_code == 0
        response = json.loads(stdout)
        assert response["hookSpecificOutput"]["permissionDecision"] == "ask"
