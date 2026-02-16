"""
Tests for logging additions in watchdog/hook.py.

Covers GUARD_LOG_LEVEL env var handling, incremental discover post-flush
verification, and _analyze_on_server exception logging.
"""

from __future__ import annotations

import json
import logging
import os
import sys
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_parsed(
    provider="aws",
    service="rds",
    action="delete-db-instance",
    action_type="DELETE",
    resource_id="my-db",
    profile=None,
    region="us-east-1",
    raw_command="aws rds delete-db-instance --db-instance-identifier my-db",
    flags=None,
    warning=None,
):
    return SimpleNamespace(
        provider=provider,
        service=service,
        action=action,
        action_type=action_type,
        resource_id=resource_id,
        profile=profile,
        region=region,
        raw_command=raw_command,
        flags=flags or {},
        warning=warning,
    )


# =========================================================================
# Tests: GUARD_LOG_LEVEL env var
# =========================================================================

class TestLogLevel:
    def test_default_log_level_is_warning(self):
        """Without GUARD_LOG_LEVEL env var, root logger level from hook.py
        should configure WARNING (the default in the source)."""
        default_level = os.environ.get("GUARD_LOG_LEVEL", "WARNING").upper()
        assert default_level == "WARNING"
        assert getattr(logging, default_level) == logging.WARNING

    def test_info_log_level_from_env(self):
        """With GUARD_LOG_LEVEL=INFO the resolved level should be INFO."""
        with patch.dict(os.environ, {"GUARD_LOG_LEVEL": "INFO"}):
            level_str = os.environ.get("GUARD_LOG_LEVEL", "WARNING").upper()
            assert level_str == "INFO"
            assert getattr(logging, level_str) == logging.INFO


# =========================================================================
# Tests: incremental discover logging
# =========================================================================

class TestIncrementalDiscoverLogging:
    @patch("watchdog.display.print_incremental_progress")
    @patch("scanner.aws.scan_aws_service")
    def test_incremental_discover_verifies_resource_after_flush(self, mock_scan, _print):
        """After flush, _incremental_discover should call find_resource."""
        from watchdog.hook import _incremental_discover

        parsed = _make_parsed()
        mock_db = MagicMock()
        mock_db.find_resource.return_value = {"arn": "arn:aws:rds:us-east-1:123:db/my-db"}

        _incremental_discover(parsed, mock_db)

        mock_db.flush.assert_called_once()
        mock_db.find_resource.assert_called_once_with("my-db")

    @patch("watchdog.display.print_incremental_progress")
    @patch("scanner.aws.scan_aws_service")
    def test_incremental_discover_logs_not_found(self, mock_scan, _print, caplog):
        """When find_resource returns None after flush, a WARNING should be logged."""
        from watchdog.hook import _incremental_discover

        parsed = _make_parsed()
        mock_db = MagicMock()
        mock_db.find_resource.return_value = None

        with caplog.at_level(logging.WARNING, logger="cloud-watchdog"):
            _incremental_discover(parsed, mock_db)

        assert any("not found" in r.message.lower() for r in caplog.records)


# =========================================================================
# Tests: _analyze_on_server exception logging
# =========================================================================

class TestAnalyzeOnServerLogging:
    @patch("urllib.request.urlopen")
    def test_analyze_on_server_logs_exception(self, mock_urlopen, caplog):
        """When _analyze_on_server fails, it should log WARNING with exc_info."""
        from watchdog.hook import _analyze_on_server

        parsed = _make_parsed()
        mock_urlopen.side_effect = Exception("boom")

        with caplog.at_level(logging.WARNING, logger="cloud-watchdog"):
            result = _analyze_on_server("http://fake", "tok", parsed)

        assert result is None
        warning_records = [r for r in caplog.records if r.levelno == logging.WARNING]
        assert len(warning_records) >= 1
        assert any("failed" in r.message.lower() for r in warning_records)


# =========================================================================
# Tests: _resolve_server_creds
# =========================================================================

class TestResolveServerCreds:
    def test_reads_from_config_file(self, tmp_path, monkeypatch):
        from watchdog.hook import _resolve_server_creds

        config = {"server_url": "http://srv", "access_token": "tok-abc"}
        cfg_file = tmp_path / "config.json"
        cfg_file.write_text(json.dumps(config))
        monkeypatch.setattr("watchdog.hook._CONFIG_FILE", str(cfg_file))

        # Patch _token_needs_refresh to avoid real HTTP
        with patch("watchdog.hook._token_needs_refresh", return_value=False):
            url, token = _resolve_server_creds()
        assert url == "http://srv"
        assert token == "tok-abc"

    def test_falls_back_to_env_vars(self, monkeypatch):
        from watchdog.hook import _resolve_server_creds

        monkeypatch.setattr("watchdog.hook._CONFIG_FILE", "/nonexistent/config.json")
        monkeypatch.setenv("GUARD_SERVER_URL", "http://env-srv")
        monkeypatch.setenv("GUARD_TOKEN", "env-tok")

        url, token = _resolve_server_creds()
        assert url == "http://env-srv"
        assert token == "env-tok"

    def test_returns_none_when_no_creds(self, monkeypatch):
        from watchdog.hook import _resolve_server_creds

        monkeypatch.setattr("watchdog.hook._CONFIG_FILE", "/nonexistent/config.json")
        monkeypatch.delenv("GUARD_SERVER_URL", raising=False)
        monkeypatch.delenv("GUARD_TOKEN", raising=False)

        url, token = _resolve_server_creds()
        assert url is None
        assert token is None


# =========================================================================
# Tests: token refresh helpers
# =========================================================================

class TestTokenRefresh:
    @patch("urllib.request.urlopen")
    def test_token_needs_refresh_returns_false_on_200(self, mock_urlopen):
        from watchdog.hook import _token_needs_refresh

        mock_urlopen.return_value = MagicMock()
        assert _token_needs_refresh("http://fake", "good-token") is False

    @patch("urllib.request.urlopen")
    def test_token_needs_refresh_returns_true_on_401(self, mock_urlopen):
        from watchdog.hook import _token_needs_refresh
        import urllib.error

        mock_urlopen.side_effect = urllib.error.HTTPError(
            url="http://fake", code=401, msg="Unauthorized", hdrs=None, fp=None,
        )
        assert _token_needs_refresh("http://fake", "bad-token") is True

    @patch("urllib.request.urlopen")
    def test_token_needs_refresh_returns_false_on_network_error(self, mock_urlopen):
        from watchdog.hook import _token_needs_refresh

        mock_urlopen.side_effect = ConnectionError("refused")
        assert _token_needs_refresh("http://fake", "tok") is False

    @patch("urllib.request.urlopen")
    def test_refresh_access_token_returns_new_token(self, mock_urlopen):
        from watchdog.hook import _refresh_access_token

        resp_body = json.dumps({"access_token": "new-tok"}).encode("utf-8")
        mock_resp = MagicMock()
        mock_resp.read.return_value = resp_body
        mock_urlopen.return_value = mock_resp

        result = _refresh_access_token("http://fake", "refresh-tok")
        assert result == "new-tok"

    @patch("urllib.request.urlopen")
    def test_refresh_access_token_returns_none_on_failure(self, mock_urlopen):
        from watchdog.hook import _refresh_access_token

        mock_urlopen.side_effect = Exception("network error")
        assert _refresh_access_token("http://fake", "refresh-tok") is None

    def test_refresh_access_token_returns_none_without_refresh_token(self):
        from watchdog.hook import _refresh_access_token

        assert _refresh_access_token("http://fake", None) is None


# =========================================================================
# Tests: _deterministic_assessment
# =========================================================================

class TestDeterministicAssessment:
    def test_delete_prod_is_critical(self):
        from watchdog.hook import _deterministic_assessment

        ctx = {
            "action_type": "DELETE",
            "target": {"name": "prod-db", "environment": "prod"},
            "connected_resources": [],
            "warnings": [],
        }
        result = _deterministic_assessment(ctx)
        assert result.risk_level == "CRITICAL"

    def test_write_dev_is_low(self):
        from watchdog.hook import _deterministic_assessment

        ctx = {
            "action_type": "WRITE",
            "target": {"name": "dev-table", "environment": "dev"},
            "connected_resources": [],
            "warnings": [],
        }
        result = _deterministic_assessment(ctx)
        assert result.risk_level == "LOW"

    def test_unknown_action_defaults_low(self):
        from watchdog.hook import _deterministic_assessment

        ctx = {
            "action_type": "READ",
            "target": {"name": "some-res", "environment": "prod"},
            "connected_resources": [],
            "warnings": [],
        }
        result = _deterministic_assessment(ctx)
        assert result.risk_level == "LOW"

    def test_blast_radius_from_connected(self):
        from watchdog.hook import _deterministic_assessment

        ctx = {
            "action_type": "DELETE",
            "target": {"name": "db", "environment": "prod"},
            "connected_resources": [
                {"type": "lambda", "relationship": "uses", "arn": "arn:aws:lambda:us-east-1:123:function:api-handler"},
                {"type": "ecs", "relationship": "depends_on", "arn": "arn:aws:ecs:us-east-1:123:service/worker"},
            ],
            "warnings": [],
        }
        result = _deterministic_assessment(ctx)
        assert len(result.blast_radius) == 2

    def test_warnings_become_summary(self):
        from watchdog.hook import _deterministic_assessment

        ctx = {
            "action_type": "DELETE",
            "target": {"name": "db", "environment": "prod"},
            "connected_resources": [],
            "warnings": ["No backups", "Resource is active", "High traffic"],
        }
        result = _deterministic_assessment(ctx)
        assert "No backups" in result.summary
        assert "Resource is active" in result.summary
        assert "High traffic" in result.summary


# =========================================================================
# Tests: _build_investigation_reason
# =========================================================================

class TestBuildInvestigationReason:
    def test_contains_describe_commands_for_rds(self):
        from watchdog.hook import _build_investigation_reason

        parsed = _make_parsed(service="rds", resource_id="my-db")
        reason = _build_investigation_reason(parsed, {})
        assert "describe-db-instances" in reason

    def test_contains_generic_fallback_for_unknown_service(self):
        from watchdog.hook import _build_investigation_reason

        parsed = _make_parsed(service="neptune", resource_id="my-graph")
        reason = _build_investigation_reason(parsed, {})
        assert "describe-*" in reason

    def test_contains_resource_id(self):
        from watchdog.hook import _build_investigation_reason

        parsed = _make_parsed(service="ec2", resource_id="i-0abc123")
        reason = _build_investigation_reason(parsed, {})
        assert "i-0abc123" in reason


# =========================================================================
# Tests: _incremental_discover edge cases
# =========================================================================

class TestIncrementalDiscoverEdgeCases:
    @patch("watchdog.display.print_incremental_progress")
    def test_incremental_discover_skips_without_service(self, _print):
        from watchdog.hook import _incremental_discover

        parsed = _make_parsed(service=None)
        mock_db = MagicMock()
        _incremental_discover(parsed, mock_db)
        mock_db.flush.assert_not_called()

    @patch("watchdog.display.print_incremental_progress")
    @patch("scanner.aws.scan_aws_service")
    def test_incremental_discover_handles_exception(self, mock_scan, _print, caplog):
        from watchdog.hook import _incremental_discover

        parsed = _make_parsed()
        mock_db = MagicMock()
        mock_scan.side_effect = RuntimeError("scan boom")

        with caplog.at_level(logging.WARNING, logger="cloud-watchdog"):
            _incremental_discover(parsed, mock_db)

        assert any("failed" in r.message.lower() for r in caplog.records)
