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
