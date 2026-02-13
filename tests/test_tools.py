"""
Tests for watchdog.tools — allowlists, tool name parsing, serialization,
and execution dispatch.

Covers:
  - Allowlist validation: all AWS methods are read-only (describe_/list_/get_)
  - Allowlist validation: all GCP methods are read-only (get/list/aggregated_list)
  - Tool name roundtrip encoding/decoding
  - Serialization of datetime, bytes, ResponseMetadata, truncation
  - Execution dispatch with mocked boto3.Session
  - Unknown tool raises ToolNotAllowedError / returns error dict
"""

import sys
import os
import json
import pytest
from datetime import datetime, timezone
from unittest.mock import patch, MagicMock

# Ensure project root is importable.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from watchdog.tools import (
    AWS_ALLOWLIST,
    GCP_ALLOWLIST,
    ToolNotAllowedError,
    _make_tool_name,
    _parse_tool_name,
    _serialize_value,
    _serialize_response,
    build_tool_definitions,
    execute_tool,
    MAX_RESPONSE_BYTES,
)


# =========================================================================
# Tests: Allowlist validation
# =========================================================================

class TestAllowlist:

    def test_all_aws_methods_are_read_only(self):
        """Every AWS allowlisted method must start with describe_, list_, or get_."""
        read_prefixes = ("describe_", "list_", "get_", "filter_", "lookup_")
        for (service, method), desc in AWS_ALLOWLIST.items():
            assert any(method.startswith(p) for p in read_prefixes), (
                f"AWS method {service}.{method} does not start with a read-only prefix"
            )

    def test_all_gcp_methods_are_read_only(self):
        """Every GCP allowlisted method must be get, list, or aggregated_list."""
        allowed_methods = {"get", "list", "aggregated_list",
                           "get_cluster", "list_clusters", "list_node_pools",
                           "get_function", "list_functions",
                           "get_service", "list_services", "list_revisions",
                           "get_bucket", "list_buckets", "get_bucket_iam_policy",
                           "get_iam_policy", "get_service_account",
                           "list_service_accounts", "list_service_account_keys",
                           "list_time_series", "list_entries"}
        for (service, method), desc in GCP_ALLOWLIST.items():
            assert method in allowed_methods or method.startswith("get_") or method.startswith("list_"), (
                f"GCP method {service}.{method} is not a recognized read-only operation"
            )

    def test_aws_allowlist_not_empty(self):
        assert len(AWS_ALLOWLIST) >= 40

    def test_gcp_allowlist_not_empty(self):
        assert len(GCP_ALLOWLIST) >= 20

    def test_all_aws_entries_have_descriptions(self):
        for (service, method), desc in AWS_ALLOWLIST.items():
            assert isinstance(desc, str) and len(desc) > 0

    def test_all_gcp_entries_have_descriptions(self):
        for (service, method), desc in GCP_ALLOWLIST.items():
            assert isinstance(desc, str) and len(desc) > 0


# =========================================================================
# Tests: Tool name parsing
# =========================================================================

class TestToolNameParsing:

    def test_aws_roundtrip(self):
        name = _make_tool_name("aws", "ec2", "describe_instances")
        assert name == "aws_ec2_describe_instances"
        provider, service, method = _parse_tool_name(name)
        assert provider == "aws"
        assert service == "ec2"
        assert method == "describe_instances"

    def test_gcp_roundtrip(self):
        name = _make_tool_name("gcp", "compute_firewalls", "list")
        assert name == "gcp_compute_firewalls_list"
        provider, service, method = _parse_tool_name(name)
        assert provider == "gcp"
        assert service == "compute_firewalls"
        assert method == "list"

    def test_aws_iam_roundtrip(self):
        name = _make_tool_name("aws", "iam", "list_attached_role_policies")
        provider, service, method = _parse_tool_name(name)
        assert provider == "aws"
        assert service == "iam"
        assert method == "list_attached_role_policies"

    def test_unknown_tool_raises(self):
        with pytest.raises(ToolNotAllowedError):
            _parse_tool_name("aws_ec2_terminate_instances")

    def test_invalid_format_raises(self):
        with pytest.raises(ToolNotAllowedError):
            _parse_tool_name("noprovider")

    def test_unknown_provider_raises(self):
        with pytest.raises(ToolNotAllowedError):
            _parse_tool_name("azure_compute_list_vms")

    def test_all_aws_tools_roundtrip(self):
        """Every AWS allowlist entry must roundtrip through name encoding."""
        for (service, method) in AWS_ALLOWLIST:
            name = _make_tool_name("aws", service, method)
            p, s, m = _parse_tool_name(name)
            assert (p, s, m) == ("aws", service, method)

    def test_all_gcp_tools_roundtrip(self):
        """Every GCP allowlist entry must roundtrip through name encoding."""
        for (service, method) in GCP_ALLOWLIST:
            name = _make_tool_name("gcp", service, method)
            p, s, m = _parse_tool_name(name)
            assert (p, s, m) == ("gcp", service, method)


# =========================================================================
# Tests: Serialization
# =========================================================================

class TestSerialization:

    def test_datetime_serialized_to_iso(self):
        dt = datetime(2024, 1, 15, 10, 30, 0, tzinfo=timezone.utc)
        result = _serialize_value(dt)
        assert result == "2024-01-15T10:30:00+00:00"

    def test_bytes_serialized_to_placeholder(self):
        result = _serialize_value(b"\x00\x01\x02")
        assert result == "<binary data omitted>"

    def test_response_metadata_stripped(self):
        response = {
            "ResponseMetadata": {"RequestId": "abc123", "HTTPStatusCode": 200},
            "Instances": [{"InstanceId": "i-12345"}],
        }
        result = _serialize_value(response)
        assert "ResponseMetadata" not in result
        assert result["Instances"] == [{"InstanceId": "i-12345"}]

    def test_nested_datetime_and_bytes(self):
        response = {
            "Items": [
                {
                    "Created": datetime(2024, 6, 1, tzinfo=timezone.utc),
                    "Data": b"binary",
                    "Name": "test",
                }
            ]
        }
        result = _serialize_value(response)
        assert result["Items"][0]["Created"] == "2024-06-01T00:00:00+00:00"
        assert result["Items"][0]["Data"] == "<binary data omitted>"
        assert result["Items"][0]["Name"] == "test"

    def test_none_passthrough(self):
        assert _serialize_value(None) is None

    def test_bool_passthrough(self):
        assert _serialize_value(True) is True
        assert _serialize_value(False) is False

    def test_string_passthrough(self):
        assert _serialize_value("hello") == "hello"

    def test_int_passthrough(self):
        assert _serialize_value(42) == 42

    def test_list_serialization(self):
        result = _serialize_value([1, "two", datetime(2024, 1, 1, tzinfo=timezone.utc)])
        assert result == [1, "two", "2024-01-01T00:00:00+00:00"]

    def test_truncation(self):
        large_data = {"data": "x" * (MAX_RESPONSE_BYTES + 1000)}
        result = _serialize_response(large_data)
        assert "TRUNCATED" in result
        assert len(result.encode("utf-8")) <= MAX_RESPONSE_BYTES + 200  # some overhead for truncation message

    def test_small_response_not_truncated(self):
        small_data = {"key": "value"}
        result = _serialize_response(small_data)
        assert "TRUNCATED" not in result


# =========================================================================
# Tests: build_tool_definitions
# =========================================================================

class TestBuildToolDefinitions:

    def test_aws_only(self):
        tools = build_tool_definitions(provider="aws")
        assert len(tools) == len(AWS_ALLOWLIST)
        for tool in tools:
            assert tool["name"].startswith("aws_")
            assert "description" in tool
            assert "input_schema" in tool

    def test_gcp_only(self):
        tools = build_tool_definitions(provider="gcp")
        assert len(tools) == len(GCP_ALLOWLIST)
        for tool in tools:
            assert tool["name"].startswith("gcp_")

    def test_both_providers(self):
        tools = build_tool_definitions(provider=None)
        assert len(tools) == len(AWS_ALLOWLIST) + len(GCP_ALLOWLIST)

    def test_tool_has_required_fields(self):
        tools = build_tool_definitions(provider="aws")
        for tool in tools:
            assert "name" in tool
            assert "description" in tool
            assert "input_schema" in tool
            assert isinstance(tool["input_schema"], dict)


# =========================================================================
# Tests: execute_tool
# =========================================================================

class TestExecuteTool:

    @patch("watchdog.tools._boto3")
    def test_aws_ec2_describe_instances(self, mock_boto3):
        mock_client = MagicMock()
        mock_client.describe_instances.return_value = {
            "ResponseMetadata": {"HTTPStatusCode": 200},
            "Reservations": [{"Instances": [{"InstanceId": "i-12345"}]}],
        }
        mock_session = MagicMock()
        mock_session.client.return_value = mock_client
        mock_boto3.Session.return_value = mock_session

        result = execute_tool(
            "aws_ec2_describe_instances",
            {"InstanceIds": ["i-12345"]},
            aws_session_kwargs={"profile_name": "test"},
        )

        parsed = json.loads(result)
        assert "Reservations" in parsed
        assert "ResponseMetadata" not in parsed
        mock_boto3.Session.assert_called_once_with(profile_name="test")
        mock_session.client.assert_called_with("ec2")
        mock_client.describe_instances.assert_called_once_with(InstanceIds=["i-12345"])

    @patch("watchdog.tools._boto3")
    def test_aws_iam_get_role(self, mock_boto3):
        mock_client = MagicMock()
        mock_client.get_role.return_value = {
            "ResponseMetadata": {"HTTPStatusCode": 200},
            "Role": {"RoleName": "test-role", "Arn": "arn:aws:iam::123:role/test"},
        }
        mock_session = MagicMock()
        mock_session.client.return_value = mock_client
        mock_boto3.Session.return_value = mock_session

        result = execute_tool("aws_iam_get_role", {"RoleName": "test-role"})
        parsed = json.loads(result)
        assert parsed["Role"]["RoleName"] == "test-role"

    def test_unknown_tool_returns_error(self):
        result = execute_tool("aws_ec2_terminate_instances", {})
        parsed = json.loads(result)
        assert "error" in parsed

    def test_unknown_provider_returns_error(self):
        result = execute_tool("azure_compute_list_vms", {})
        parsed = json.loads(result)
        assert "error" in parsed

    @patch("watchdog.tools._boto3")
    def test_aws_exception_returns_error(self, mock_boto3):
        mock_client = MagicMock()
        mock_client.describe_instances.side_effect = Exception("AccessDenied")
        mock_session = MagicMock()
        mock_session.client.return_value = mock_client
        mock_boto3.Session.return_value = mock_session

        result = execute_tool("aws_ec2_describe_instances", {})
        parsed = json.loads(result)
        assert "error" in parsed
        assert "AccessDenied" in parsed["error"]

    @patch("watchdog.tools._boto3")
    def test_aws_s3_list_buckets(self, mock_boto3):
        mock_client = MagicMock()
        mock_client.list_buckets.return_value = {
            "ResponseMetadata": {"HTTPStatusCode": 200},
            "Buckets": [{"Name": "my-bucket"}],
        }
        mock_session = MagicMock()
        mock_session.client.return_value = mock_client
        mock_boto3.Session.return_value = mock_session

        result = execute_tool("aws_s3_list_buckets", {})
        parsed = json.loads(result)
        assert "Buckets" in parsed

    @patch("watchdog.tools._boto3")
    def test_aws_session_kwargs_passed_through(self, mock_boto3):
        mock_client = MagicMock()
        mock_client.get_caller_identity.return_value = {
            "ResponseMetadata": {"HTTPStatusCode": 200},
            "Account": "123456789012",
        }
        mock_session = MagicMock()
        mock_session.client.return_value = mock_client
        mock_boto3.Session.return_value = mock_session

        execute_tool(
            "aws_sts_get_caller_identity",
            {},
            aws_session_kwargs={"profile_name": "prod", "region_name": "eu-west-1"},
        )
        mock_boto3.Session.assert_called_once_with(
            profile_name="prod", region_name="eu-west-1"
        )

    @patch("watchdog.tools._boto3")
    def test_aws_cloudwatch_get_metric_statistics(self, mock_boto3):
        mock_client = MagicMock()
        mock_client.get_metric_statistics.return_value = {
            "ResponseMetadata": {"HTTPStatusCode": 200},
            "Datapoints": [{"Average": 23.5, "Unit": "Percent"}],
        }
        mock_session = MagicMock()
        mock_session.client.return_value = mock_client
        mock_boto3.Session.return_value = mock_session

        result = execute_tool(
            "aws_cloudwatch_get_metric_statistics",
            {
                "Namespace": "AWS/EC2",
                "MetricName": "CPUUtilization",
                "StartTime": "2024-01-01T00:00:00Z",
                "EndTime": "2024-01-02T00:00:00Z",
                "Period": 300,
                "Statistics": ["Average"],
            },
        )
        parsed = json.loads(result)
        assert "Datapoints" in parsed
        mock_session.client.assert_called_with("cloudwatch")
        mock_client.get_metric_statistics.assert_called_once()

    @patch("watchdog.tools._boto3")
    def test_aws_logs_filter_log_events(self, mock_boto3):
        mock_client = MagicMock()
        mock_client.filter_log_events.return_value = {
            "ResponseMetadata": {"HTTPStatusCode": 200},
            "events": [{"message": "test log line", "timestamp": 1704067200000}],
        }
        mock_session = MagicMock()
        mock_session.client.return_value = mock_client
        mock_boto3.Session.return_value = mock_session

        result = execute_tool(
            "aws_logs_filter_log_events",
            {"logGroupName": "/aws/lambda/my-func", "filterPattern": "ERROR"},
        )
        parsed = json.loads(result)
        assert "events" in parsed
        mock_session.client.assert_called_with("logs")
        mock_client.filter_log_events.assert_called_once_with(
            logGroupName="/aws/lambda/my-func", filterPattern="ERROR"
        )

    @patch("watchdog.tools._boto3")
    def test_aws_cloudtrail_lookup_events(self, mock_boto3):
        mock_client = MagicMock()
        mock_client.lookup_events.return_value = {
            "ResponseMetadata": {"HTTPStatusCode": 200},
            "Events": [{"EventName": "RunInstances", "EventSource": "ec2.amazonaws.com"}],
        }
        mock_session = MagicMock()
        mock_session.client.return_value = mock_client
        mock_boto3.Session.return_value = mock_session

        result = execute_tool(
            "aws_cloudtrail_lookup_events",
            {
                "StartTime": "2024-01-01T00:00:00Z",
                "EndTime": "2024-01-02T00:00:00Z",
                "MaxResults": 10,
            },
        )
        parsed = json.loads(result)
        assert "Events" in parsed
        mock_session.client.assert_called_with("cloudtrail")
        mock_client.lookup_events.assert_called_once()
