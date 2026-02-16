"""
Tests for scanner/graph.py — flush cache, find_resource local fallback,
JSON serialization, and logging.

Uses unittest.mock to patch `requests` (no real HTTP calls).
"""

from __future__ import annotations

import json
import logging
import os
import sys
from datetime import datetime, timezone
from decimal import Decimal
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from scanner.graph import GraphDB


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_db() -> GraphDB:
    """Return a GraphDB wired to a fake server."""
    return GraphDB(server_url="http://fake-server", token="tok-123")


def _make_resource(arn: str, name: str = "res", **extra) -> dict:
    return {"arn": arn, "name": name, "resource_type": "test", **extra}


def _mock_post_200(resources_upserted: int = 1, relationships_upserted: int = 0):
    """Return a mock response for a successful POST."""
    resp = MagicMock()
    resp.status_code = 200
    resp.json.return_value = {
        "resources_upserted": resources_upserted,
        "relationships_upserted": relationships_upserted,
    }
    return resp


# =========================================================================
# Tests: flush cache (_flushed_resources)
# =========================================================================

class TestFlushCache:
    @patch("requests.post")
    def test_flushed_resources_populated_after_flush(self, mock_post):
        db = _make_db()
        res = _make_resource("arn:aws:rds:us-east-1:123:db/mydb")
        db.upsert_resource(res)

        mock_post.return_value = _mock_post_200()
        db.flush()

        assert "arn:aws:rds:us-east-1:123:db/mydb" in db._flushed_resources

    @patch("requests.post")
    def test_buffers_cleared_on_success(self, mock_post):
        db = _make_db()
        db.upsert_resource(_make_resource("arn:1"))
        db.upsert_relationship("arn:1", "arn:2", "connects_to")

        mock_post.return_value = _mock_post_200()
        db.flush()

        assert len(db._resources) == 0
        assert len(db._relationships) == 0

    @patch("requests.post")
    def test_buffers_retained_on_failure(self, mock_post):
        db = _make_db()
        db.upsert_resource(_make_resource("arn:1"))
        db.upsert_relationship("arn:1", "arn:2", "connects_to")

        resp = MagicMock()
        resp.status_code = 500
        resp.text = "Internal Server Error"
        mock_post.return_value = resp
        db.flush()

        assert len(db._resources) == 1
        assert len(db._relationships) == 1

    @patch("requests.post")
    def test_buffers_retained_on_exception(self, mock_post):
        db = _make_db()
        db.upsert_resource(_make_resource("arn:1"))

        mock_post.side_effect = ConnectionError("refused")
        db.flush()

        assert len(db._resources) == 1


# =========================================================================
# Tests: find_resource local cache fallback
# =========================================================================

class TestFindResourceLocal:
    def test_find_in_write_buffer(self):
        db = _make_db()
        res = _make_resource("arn:aws:rds:us-east-1:123:db/mydb")
        db.upsert_resource(res)

        found = db.find_resource("arn:aws:rds:us-east-1:123:db/mydb")
        assert found is not None
        assert found["arn"] == "arn:aws:rds:us-east-1:123:db/mydb"

    @patch("requests.post")
    def test_find_in_flushed_cache(self, mock_post):
        db = _make_db()
        res = _make_resource("arn:aws:rds:us-east-1:123:db/mydb")
        db.upsert_resource(res)

        mock_post.return_value = _mock_post_200()
        db.flush()

        # Write buffer is now empty, but flushed cache has it.
        assert len(db._resources) == 0
        found = db.find_resource("arn:aws:rds:us-east-1:123:db/mydb")
        assert found is not None
        assert found["arn"] == "arn:aws:rds:us-east-1:123:db/mydb"

    def test_find_by_name_in_local_cache(self):
        db = _make_db()
        res = _make_resource("arn:aws:dynamodb:us-east-1:123:table/my-table", name="my-table")
        db.upsert_resource(res)

        found = db.find_resource("my-table")
        assert found is not None
        assert found["name"] == "my-table"

    def test_find_by_arn_substring_in_local_cache(self):
        db = _make_db()
        full_arn = "arn:aws:rds:us-east-1:123456789:db/prod-db"
        db.upsert_resource(_make_resource(full_arn))

        found = db.find_resource("prod-db")
        assert found is not None
        assert found["arn"] == full_arn

    @patch("requests.get")
    def test_falls_back_to_server(self, mock_get):
        db = _make_db()
        server_resource = {"arn": "arn:aws:s3:::bucket", "name": "bucket"}

        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = {"resource": server_resource}
        mock_get.return_value = resp

        found = db.find_resource("arn:aws:s3:::bucket")
        assert found is not None
        assert found["arn"] == "arn:aws:s3:::bucket"

    @patch("requests.get")
    def test_returns_none_when_nowhere(self, mock_get):
        db = _make_db()

        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = {"resource": None}
        mock_get.return_value = resp

        found = db.find_resource("nonexistent")
        assert found is None


# =========================================================================
# Tests: flush JSON serialization with default=str
# =========================================================================

class TestFlushJsonSerialization:
    @patch("requests.post")
    def test_flush_with_datetime_values(self, mock_post):
        db = _make_db()
        res = _make_resource("arn:1")
        res["last_scanned"] = datetime(2025, 1, 15, 12, 0, 0, tzinfo=timezone.utc)
        db.upsert_resource(res)

        mock_post.return_value = _mock_post_200()
        db.flush()

        mock_post.assert_called_once()
        call_kwargs = mock_post.call_args
        body = call_kwargs.kwargs.get("data") or call_kwargs[1].get("data")
        payload = json.loads(body)
        assert "2025-01-15" in str(payload)

    @patch("requests.post")
    def test_flush_with_decimal_values(self, mock_post):
        db = _make_db()
        res = _make_resource("arn:1")
        res["metadata"] = {"size": Decimal("128.5")}
        db.upsert_resource(res)

        mock_post.return_value = _mock_post_200()
        db.flush()

        mock_post.assert_called_once()
        call_kwargs = mock_post.call_args
        body = call_kwargs.kwargs.get("data") or call_kwargs[1].get("data")
        payload = json.loads(body)
        assert "128.5" in str(payload)


# =========================================================================
# Tests: logging levels
# =========================================================================

class TestLogging:
    @patch("requests.get")
    def test_get_failure_logs_warning(self, mock_get, caplog):
        db = _make_db()
        mock_get.side_effect = ConnectionError("refused")

        with caplog.at_level(logging.WARNING, logger="scanner.graph"):
            result = db._get("/api/v1/graph/populated")

        assert result is None
        assert any("failed" in r.message.lower() for r in caplog.records)
        assert any(r.levelno == logging.WARNING for r in caplog.records)

    @patch("requests.post")
    def test_flush_failure_logs_warning(self, mock_post, caplog):
        db = _make_db()
        db.upsert_resource(_make_resource("arn:1"))

        resp = MagicMock()
        resp.status_code = 500
        resp.text = "Internal Server Error"
        mock_post.return_value = resp

        with caplog.at_level(logging.WARNING, logger="scanner.graph"):
            db.flush()

        assert any("sync failed" in r.message.lower() for r in caplog.records)
        assert any(r.levelno == logging.WARNING for r in caplog.records)
