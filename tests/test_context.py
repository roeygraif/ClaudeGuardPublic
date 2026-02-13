"""
Tests for watchdog.context — context gathering with mock graph data.

Uses an in-memory SQLite-backed GraphDB populated with realistic test data
to verify that gather_context correctly builds the context bundle for the
Claude brain.
"""

import sys
import os
import pytest
from unittest.mock import MagicMock, patch, PropertyMock
from types import SimpleNamespace

# Ensure project root is importable.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from watchdog.context import gather_context
from scanner.graph import GraphDB


# =========================================================================
# Helpers — build a populated in-memory GraphDB
# =========================================================================

def _make_db() -> GraphDB:
    """Create an in-memory GraphDB with sample infrastructure data."""
    db = GraphDB(db_path=":memory:")

    # RDS instance (production)
    db.upsert_resource({
        "arn": "arn:aws:rds:us-east-1:123456789012:db/prod-main",
        "provider": "aws",
        "service": "rds",
        "resource_type": "db_instance",
        "name": "prod-main",
        "region": "us-east-1",
        "account_or_project": "123456789012",
        "environment": "prod",
        "is_active": 1,
        "activity_summary": "342 connections in the last 24 hours",
        "tags": {"Environment": "prod", "Team": "backend"},
        "metadata": {
            "engine": "postgres",
            "engine_version": "15.4",
            "instance_class": "db.r6g.xlarge",
            "multi_az": True,
        },
    })

    # Lambda function connected to RDS
    db.upsert_resource({
        "arn": "arn:aws:lambda:us-east-1:123456789012:function/api-handler",
        "provider": "aws",
        "service": "lambda",
        "resource_type": "lambda_function",
        "name": "api-handler",
        "region": "us-east-1",
        "account_or_project": "123456789012",
        "environment": "prod",
        "is_active": 1,
        "activity_summary": "12000 invocations in the last 24 hours",
        "metadata": {"runtime": "python3.11"},
    })

    # Security Group
    db.upsert_resource({
        "arn": "arn:aws:ec2:us-east-1:123456789012:security-group/sg-abc123",
        "provider": "aws",
        "service": "ec2",
        "resource_type": "security_group",
        "name": "rds-sg-prod",
        "region": "us-east-1",
        "account_or_project": "123456789012",
        "environment": "prod",
        "is_active": 1,
        "metadata": {
            "ingress_rules": [
                {"protocol": "tcp", "port": 5432, "cidr": "10.0.0.0/16"},
            ],
        },
    })

    # IAM Role
    db.upsert_resource({
        "arn": "arn:aws:iam::123456789012:role/api-prod",
        "provider": "aws",
        "service": "iam",
        "resource_type": "iam_role",
        "name": "api-prod",
        "region": "global",
        "account_or_project": "123456789012",
        "environment": "prod",
        "is_active": 1,
        "metadata": {"role_name": "api-prod"},
    })

    # IAM Policy connected to role
    db.upsert_resource({
        "arn": "arn:aws:iam::123456789012:policy/api-prod-policy",
        "provider": "aws",
        "service": "iam",
        "resource_type": "iam_policy",
        "name": "api-prod-policy",
        "region": "global",
        "account_or_project": "123456789012",
        "environment": "prod",
        "metadata": {},
    })

    # Relationships
    # Lambda -> RDS (connects_to)
    db.upsert_relationship(
        "arn:aws:lambda:us-east-1:123456789012:function/api-handler",
        "arn:aws:rds:us-east-1:123456789012:db/prod-main",
        "connects_to",
    )

    # RDS -> SG (attached_to)
    db.upsert_relationship(
        "arn:aws:rds:us-east-1:123456789012:db/prod-main",
        "arn:aws:ec2:us-east-1:123456789012:security-group/sg-abc123",
        "attached_to",
    )

    # Lambda -> SG (attached_to)
    db.upsert_relationship(
        "arn:aws:lambda:us-east-1:123456789012:function/api-handler",
        "arn:aws:ec2:us-east-1:123456789012:security-group/sg-abc123",
        "attached_to",
    )

    # Role -> Policy (attached_policy)
    db.upsert_relationship(
        "arn:aws:iam::123456789012:role/api-prod",
        "arn:aws:iam::123456789012:policy/api-prod-policy",
        "attached_policy",
    )

    # Lambda -> Role (assumes)
    db.upsert_relationship(
        "arn:aws:lambda:us-east-1:123456789012:function/api-handler",
        "arn:aws:iam::123456789012:role/api-prod",
        "assumes",
    )

    # Log a scan so staleness is current
    db.log_scan("aws", "123456789012", 5, 5)

    return db


def _make_parsed(**kwargs):
    """Create a mock ParsedCommand-like object from keyword arguments."""
    defaults = {
        "provider": "aws",
        "service": "rds",
        "action": "delete-db-instance",
        "action_type": "DELETE",
        "resource_id": "prod-main",
        "raw_command": "aws rds delete-db-instance --db-instance-identifier prod-main",
        "flags": {"--db-instance-identifier": "prod-main"},
        "region": "us-east-1",
        "profile": None,
    }
    defaults.update(kwargs)
    return SimpleNamespace(**defaults)


# =========================================================================
# Tests
# =========================================================================

class TestGatherContextTargetFound:
    """Test that gather_context finds the target resource and its connections."""

    def test_target_found_for_rds_delete(self):
        db = _make_db()
        parsed = _make_parsed()
        ctx = gather_context(parsed, db)

        assert ctx["target"] is not None
        assert ctx["target"]["name"] == "prod-main"
        assert ctx["target"]["type"] == "RDS Instance"
        assert ctx["target"]["environment"] == "prod"

    def test_connections_include_lambda_and_sg(self):
        db = _make_db()
        parsed = _make_parsed()
        ctx = gather_context(parsed, db)

        conn_types = {c["type"] for c in ctx["connected_resources"]}
        # Should find both the SG (outgoing from RDS) and the Lambda (incoming)
        assert len(ctx["connected_resources"]) >= 2
        assert "Security Group" in conn_types or "Lambda Function" in conn_types

    def test_action_type_in_context(self):
        db = _make_db()
        parsed = _make_parsed()
        ctx = gather_context(parsed, db)

        assert ctx["action_type"] == "DELETE"

    def test_command_in_context(self):
        db = _make_db()
        parsed = _make_parsed()
        ctx = gather_context(parsed, db)

        assert "delete-db-instance" in ctx["command"]


class TestGatherContextTargetNotFound:
    """Test behaviour when the target resource is not in the graph."""

    def test_unknown_resource_yields_warning(self):
        db = _make_db()
        parsed = _make_parsed(resource_id="nonexistent-db")
        ctx = gather_context(parsed, db)

        assert ctx["target"] is None
        assert any("not found" in w.lower() for w in ctx["warnings"])

    def test_no_connections_when_target_missing(self):
        db = _make_db()
        parsed = _make_parsed(resource_id="nonexistent-db")
        ctx = gather_context(parsed, db)

        assert ctx["connected_resources"] == []


class TestGatherContextVariableResource:
    """Test behaviour when the resource_id contains shell variables."""

    def test_variable_resource_yields_warning(self):
        db = _make_db()
        parsed = _make_parsed(resource_id="$DB_NAME")
        ctx = gather_context(parsed, db)

        assert ctx["target"] is None
        assert any("variable" in w.lower() for w in ctx["warnings"])


class TestGatherContextStaleness:
    """Test staleness warning when graph is old."""

    def test_stale_graph_yields_warning(self):
        db = _make_db()
        parsed = _make_parsed()

        # Mock staleness_minutes to return a very old value
        db.staleness_minutes = MagicMock(return_value=180)

        ctx = gather_context(parsed, db)

        assert any("hours old" in w.lower() for w in ctx["warnings"])

    def test_fresh_graph_no_staleness_warning(self):
        db = _make_db()
        parsed = _make_parsed()

        # Mock staleness_minutes to return fresh
        db.staleness_minutes = MagicMock(return_value=5)

        ctx = gather_context(parsed, db)

        stale_warnings = [w for w in ctx["warnings"] if "old" in w.lower()]
        assert len(stale_warnings) == 0

    def test_no_scan_yields_warning(self):
        db = _make_db()
        parsed = _make_parsed()

        # staleness_minutes returns -1 when no scans recorded
        db.staleness_minutes = MagicMock(return_value=-1)

        ctx = gather_context(parsed, db)

        assert any("no infrastructure scan" in w.lower() for w in ctx["warnings"])


class TestGatherContextIAM:
    """Test that IAM context is populated for IAM commands."""

    def test_iam_context_for_iam_command(self):
        db = _make_db()
        parsed = _make_parsed(
            service="iam",
            action="attach-role-policy",
            action_type="ADMIN",
            resource_id="api-prod",
            raw_command="aws iam attach-role-policy --role-name api-prod --policy-arn arn:aws:iam::aws:policy/AdminAccess",
            flags={
                "--role-name": "api-prod",
                "--policy-arn": "arn:aws:iam::aws:policy/AdminAccess",
            },
        )
        ctx = gather_context(parsed, db)

        assert ctx["iam_context"] is not None
        assert ctx["iam_context"]["role"] == "api-prod"

    def test_iam_context_none_for_non_iam(self):
        db = _make_db()
        parsed = _make_parsed()  # rds delete — not IAM
        ctx = gather_context(parsed, db)

        assert ctx["iam_context"] is None


class TestGatherContextNetwork:
    """Test that network context is populated for SG commands."""

    def test_network_context_for_sg_command(self):
        db = _make_db()
        parsed = _make_parsed(
            service="ec2",
            action="authorize-security-group-ingress",
            action_type="ADMIN",
            resource_id="sg-abc123",
            raw_command="aws ec2 authorize-security-group-ingress --group-id sg-abc123 --protocol tcp --port 22 --cidr 0.0.0.0/0",
            flags={
                "--group-id": "sg-abc123",
                "--protocol": "tcp",
                "--port": "22",
                "--cidr": "0.0.0.0/0",
            },
        )
        ctx = gather_context(parsed, db)

        assert ctx["network_context"] is not None
        assert ctx["network_context"]["security_group"] != ""

    def test_network_context_none_for_non_sg(self):
        db = _make_db()
        parsed = _make_parsed()  # rds delete — not SG
        ctx = gather_context(parsed, db)

        assert ctx["network_context"] is None

    def test_network_context_includes_rule_being_added(self):
        db = _make_db()
        parsed = _make_parsed(
            service="ec2",
            action="authorize-security-group-ingress",
            action_type="ADMIN",
            resource_id="sg-abc123",
            raw_command="aws ec2 authorize-security-group-ingress --group-id sg-abc123 --protocol tcp --port 443 --cidr 10.0.0.0/8",
            flags={
                "--group-id": "sg-abc123",
                "--protocol": "tcp",
                "--port": "443",
                "--cidr": "10.0.0.0/8",
            },
        )
        ctx = gather_context(parsed, db)

        rule = ctx["network_context"]["rule_being_added"]
        assert rule is not None
        assert rule["protocol"] == "tcp"
        assert rule["port"] == "443"
        assert rule["cidr"] == "10.0.0.0/8"


class TestGatherContextWarnings:
    """Test specific warning patterns."""

    def test_delete_on_production_warning(self):
        db = _make_db()
        parsed = _make_parsed()  # DELETE on prod-main (prod environment)
        ctx = gather_context(parsed, db)

        assert any("production" in w.lower() for w in ctx["warnings"])

    def test_active_resource_deletion_warning(self):
        db = _make_db()
        parsed = _make_parsed()  # prod-main has activity_summary set
        ctx = gather_context(parsed, db)

        assert any("actively in use" in w.lower() for w in ctx["warnings"])

    def test_no_replica_warning_for_rds_delete(self):
        db = _make_db()
        parsed = _make_parsed()
        ctx = gather_context(parsed, db)

        assert any("no read replica" in w.lower() for w in ctx["warnings"])

    def test_internet_open_sg_warning(self):
        db = _make_db()
        parsed = _make_parsed(
            service="ec2",
            action="authorize-security-group-ingress",
            action_type="ADMIN",
            resource_id="sg-abc123",
            raw_command="aws ec2 authorize-security-group-ingress --group-id sg-abc123 --cidr 0.0.0.0/0",
            flags={"--group-id": "sg-abc123", "--cidr": "0.0.0.0/0"},
        )
        ctx = gather_context(parsed, db)

        assert any("entire internet" in w.lower() for w in ctx["warnings"])


class TestGatherContextNoResourceId:
    """Test behaviour when there is no resource_id (e.g. aws sts get-caller-identity)."""

    def test_no_resource_id_no_crash(self):
        db = _make_db()
        parsed = _make_parsed(
            service="sts",
            action="get-caller-identity",
            action_type="ADMIN",
            resource_id=None,
            raw_command="aws sts get-caller-identity",
            flags={},
        )
        ctx = gather_context(parsed, db)

        # Should not crash and target should be None (no resource to look up)
        assert ctx["target"] is None
        assert isinstance(ctx["warnings"], list)
