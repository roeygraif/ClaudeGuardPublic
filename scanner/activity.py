"""
Activity / liveness checking for cloud resources.

Queries CloudWatch (AWS) or Cloud Monitoring (GCP) metrics to determine
whether a resource has been actively used in the last 24 hours.

SECURITY PRINCIPLE: Every monitoring API call in this module is a
HARDCODED, LITERAL, read-only method call.  There is NO dynamic dispatch
-- every method name appears verbatim in the source code.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def check_activity(
    resource: dict,
    provider: str,
    session: Any = None,
) -> tuple[str, str]:
    """Determine whether *resource* is actively used.

    Parameters
    ----------
    resource:
        A resource dict containing at least ``arn``, ``service``,
        ``resource_type``, ``name``, ``region``, and ``metadata``.
    provider:
        ``"aws"`` or ``"gcp"``.
    session:
        For AWS -- an optional ``boto3.Session`` (defaults to the default
        session).  For GCP -- unused (the monitoring client is created
        from Application Default Credentials).

    Returns
    -------
    tuple[str, str]
        ``(status, summary)`` where *status* is one of
        ``"ACTIVE"``, ``"IDLE"``, or ``"UNKNOWN"`` and *summary* is a
        human-readable explanation.
    """
    try:
        if provider == "aws":
            return _check_aws_activity(resource, session)
        elif provider == "gcp":
            return _check_gcp_activity(resource)
        else:
            return ("UNKNOWN", f"Unsupported provider: {provider}")
    except Exception as exc:
        logger.debug("Activity check failed for %s: %s", resource.get("arn"), exc)
        return ("UNKNOWN", "Could not check activity")


# ===================================================================
# AWS activity checks
# ===================================================================

def _check_aws_activity(resource: dict, session: Any = None) -> tuple[str, str]:
    """Route an AWS resource to the appropriate CloudWatch check."""
    try:
        import boto3
    except ImportError:
        return ("UNKNOWN", "boto3 is not installed")

    service = resource.get("service", "").lower()
    resource_type = resource.get("resource_type", "").lower()
    region = resource.get("region")
    name = resource.get("name", "")
    metadata = resource.get("metadata") or {}

    if session is not None:
        cloudwatch = session.client("cloudwatch", region_name=region)
    else:
        cloudwatch = boto3.client("cloudwatch", region_name=region)

    # --- EC2 instances ---
    if service == "ec2" and resource_type in ("instance", "instances"):
        instance_id = _extract_resource_id(resource)
        return _check_ec2_activity(cloudwatch, instance_id, region)

    # --- RDS instances ---
    if service == "rds" and resource_type in (
        "db", "db-instance", "instance", "cluster",
    ):
        db_id = name or _extract_resource_id(resource)
        return _check_rds_activity(cloudwatch, db_id, region)

    # --- Lambda functions ---
    if service == "lambda" and resource_type in ("function", "functions"):
        function_name = name or _extract_resource_id(resource)
        return _check_lambda_activity(cloudwatch, function_name, region)

    # --- ELB / ALB ---
    if service in ("elasticloadbalancing", "elbv2", "elb") and resource_type in (
        "loadbalancer", "load-balancer", "targetgroup",
    ):
        lb_name = _extract_elb_name(resource)
        return _check_elb_activity(cloudwatch, lb_name, region)

    return ("UNKNOWN", f"No activity check for AWS {service}/{resource_type}")


# ---------------------------------------------------------------------------
# EC2
# ---------------------------------------------------------------------------

def _check_ec2_activity(
    cloudwatch: Any,
    instance_id: str,
    region: str,
) -> tuple[str, str]:
    """Check EC2 instance CPU utilization over the last 24 hours."""
    try:
        now = datetime.now(timezone.utc)
        start = now - timedelta(hours=24)

        # HARDCODED CloudWatch API call -- read-only.
        response = cloudwatch.get_metric_statistics(
            Namespace="AWS/EC2",
            MetricName="CPUUtilization",
            Dimensions=[{"Name": "InstanceId", "Value": instance_id}],
            StartTime=start,
            EndTime=now,
            Period=3600,
            Statistics=["Average"],
        )

        datapoints = response.get("Datapoints", [])

        if not datapoints:
            return ("UNKNOWN", "No CPU datapoints in the last 24 hours")

        avg_values = [dp["Average"] for dp in datapoints]
        peak = max(avg_values)
        overall_avg = sum(avg_values) / len(avg_values)

        if any(v > 1.0 for v in avg_values):
            return (
                "ACTIVE",
                f"CPU avg {overall_avg:.1f}% (peak {peak:.1f}%) over 24 hours",
            )
        else:
            return (
                "IDLE",
                f"CPU avg {overall_avg:.2f}% (peak {peak:.2f}%) -- near zero over 24 hours",
            )

    except Exception as exc:
        logger.debug("EC2 activity check failed for %s: %s", instance_id, exc)
        return ("UNKNOWN", "Could not check activity")


# ---------------------------------------------------------------------------
# RDS
# ---------------------------------------------------------------------------

def _check_rds_activity(
    cloudwatch: Any,
    db_instance_id: str,
    region: str,
) -> tuple[str, str]:
    """Check RDS database connections over the last 24 hours."""
    try:
        now = datetime.now(timezone.utc)
        start = now - timedelta(hours=24)

        # HARDCODED CloudWatch API call -- read-only.
        response = cloudwatch.get_metric_statistics(
            Namespace="AWS/RDS",
            MetricName="DatabaseConnections",
            Dimensions=[{"Name": "DBInstanceIdentifier", "Value": db_instance_id}],
            StartTime=start,
            EndTime=now,
            Period=3600,
            Statistics=["Sum"],
        )

        datapoints = response.get("Datapoints", [])

        if not datapoints:
            return ("UNKNOWN", "No connection datapoints in the last 24 hours")

        total_connections = int(sum(dp["Sum"] for dp in datapoints))

        if total_connections > 0:
            return (
                "ACTIVE",
                f"{total_connections} database connections in the last 24 hours",
            )
        else:
            return ("IDLE", "0 database connections in the last 24 hours")

    except Exception as exc:
        logger.debug("RDS activity check failed for %s: %s", db_instance_id, exc)
        return ("UNKNOWN", "Could not check activity")


# ---------------------------------------------------------------------------
# Lambda
# ---------------------------------------------------------------------------

def _check_lambda_activity(
    cloudwatch: Any,
    function_name: str,
    region: str,
) -> tuple[str, str]:
    """Check Lambda invocation count over the last 24 hours."""
    try:
        now = datetime.now(timezone.utc)
        start = now - timedelta(hours=24)

        # HARDCODED CloudWatch API call -- read-only.
        response = cloudwatch.get_metric_statistics(
            Namespace="AWS/Lambda",
            MetricName="Invocations",
            Dimensions=[{"Name": "FunctionName", "Value": function_name}],
            StartTime=start,
            EndTime=now,
            Period=3600,
            Statistics=["Sum"],
        )

        datapoints = response.get("Datapoints", [])

        if not datapoints:
            return ("UNKNOWN", "No invocation datapoints in the last 24 hours")

        total_invocations = int(sum(dp["Sum"] for dp in datapoints))

        if total_invocations > 0:
            return (
                "ACTIVE",
                f"{total_invocations} invocations in the last 24 hours",
            )
        else:
            return ("IDLE", "0 invocations in the last 24 hours")

    except Exception as exc:
        logger.debug("Lambda activity check failed for %s: %s", function_name, exc)
        return ("UNKNOWN", "Could not check activity")


# ---------------------------------------------------------------------------
# ELB / ALB
# ---------------------------------------------------------------------------

def _check_elb_activity(
    cloudwatch: Any,
    lb_name: str,
    region: str,
) -> tuple[str, str]:
    """Check ALB/ELB request count over the last 24 hours."""
    try:
        now = datetime.now(timezone.utc)
        start = now - timedelta(hours=24)

        # HARDCODED CloudWatch API call -- read-only.
        response = cloudwatch.get_metric_statistics(
            Namespace="AWS/ApplicationELB",
            MetricName="RequestCount",
            Dimensions=[{"Name": "LoadBalancer", "Value": lb_name}],
            StartTime=start,
            EndTime=now,
            Period=3600,
            Statistics=["Sum"],
        )

        datapoints = response.get("Datapoints", [])

        if not datapoints:
            return ("UNKNOWN", "No request datapoints in the last 24 hours")

        total_requests = int(sum(dp["Sum"] for dp in datapoints))

        if total_requests > 0:
            return (
                "ACTIVE",
                f"{total_requests} requests in the last 24 hours",
            )
        else:
            return ("IDLE", "0 requests in the last 24 hours")

    except Exception as exc:
        logger.debug("ELB activity check failed for %s: %s", lb_name, exc)
        return ("UNKNOWN", "Could not check activity")


# ===================================================================
# GCP activity checks
# ===================================================================

def _check_gcp_activity(resource: dict) -> tuple[str, str]:
    """Route a GCP resource to the appropriate Cloud Monitoring check."""
    try:
        from google.cloud import monitoring_v3  # noqa: F401
    except ImportError:
        return ("UNKNOWN", "google-cloud-monitoring is not installed")

    service = resource.get("service", "").lower()
    resource_type = resource.get("resource_type", "").lower()
    metadata = resource.get("metadata") or {}

    project = metadata.get("project") or resource.get("account_or_project", "")
    if not project:
        return ("UNKNOWN", "No GCP project found for resource")

    monitoring_client = monitoring_v3.MetricServiceClient()

    # --- Compute Engine instances ---
    if service == "compute" and resource_type in ("instance", "instances"):
        instance_id = metadata.get("instance_id") or resource.get("name", "")
        return _check_gce_activity(monitoring_client, project, instance_id)

    # --- Cloud SQL ---
    if service in ("sqladmin", "cloudsql", "sql") and resource_type in (
        "instance", "instances", "database",
    ):
        instance_id = resource.get("name", "")
        return _check_cloudsql_activity(monitoring_client, project, instance_id)

    # --- Cloud Functions ---
    if service in ("cloudfunctions", "functions") and resource_type in (
        "function", "functions",
    ):
        function_name = resource.get("name", "")
        return _check_cloud_function_activity(monitoring_client, project, function_name)

    return ("UNKNOWN", f"No activity check for GCP {service}/{resource_type}")


# ---------------------------------------------------------------------------
# GCE
# ---------------------------------------------------------------------------

def _check_gce_activity(
    monitoring_client: Any,
    project: str,
    instance_id: str,
) -> tuple[str, str]:
    """Check GCE instance CPU utilization via Cloud Monitoring."""
    try:
        from google.cloud import monitoring_v3
        from google.protobuf.timestamp_pb2 import Timestamp

        now = datetime.now(timezone.utc)
        start = now - timedelta(hours=24)

        start_ts = Timestamp()
        start_ts.FromDatetime(start)
        end_ts = Timestamp()
        end_ts.FromDatetime(now)

        interval = monitoring_v3.TimeInterval(
            start_time=start_ts,
            end_time=end_ts,
        )

        # HARDCODED Cloud Monitoring API call -- read-only.
        results = monitoring_client.list_time_series(
            request={
                "name": f"projects/{project}",
                "filter": (
                    'metric.type = "compute.googleapis.com/instance/cpu/utilization"'
                    f' AND resource.labels.instance_id = "{instance_id}"'
                ),
                "interval": interval,
                "view": monitoring_v3.ListTimeSeriesRequest.TimeSeriesView.FULL,
            }
        )

        values = []
        for ts in results:
            for point in ts.points:
                values.append(point.value.double_value)

        if not values:
            return ("UNKNOWN", "No CPU datapoints in the last 24 hours")

        # GCE CPU utilization is reported as a fraction (0.0 - 1.0).
        peak = max(values) * 100
        avg = (sum(values) / len(values)) * 100

        if any(v > 0.01 for v in values):  # > 1% as a fraction
            return (
                "ACTIVE",
                f"CPU avg {avg:.1f}% (peak {peak:.1f}%) over 24 hours",
            )
        else:
            return (
                "IDLE",
                f"CPU avg {avg:.2f}% (peak {peak:.2f}%) -- near zero over 24 hours",
            )

    except ImportError:
        return ("UNKNOWN", "google-cloud-monitoring is not installed")
    except Exception as exc:
        logger.debug("GCE activity check failed for %s: %s", instance_id, exc)
        return ("UNKNOWN", "Could not check activity")


# ---------------------------------------------------------------------------
# Cloud SQL
# ---------------------------------------------------------------------------

def _check_cloudsql_activity(
    monitoring_client: Any,
    project: str,
    instance_id: str,
) -> tuple[str, str]:
    """Check Cloud SQL connection count via Cloud Monitoring."""
    try:
        from google.cloud import monitoring_v3
        from google.protobuf.timestamp_pb2 import Timestamp

        now = datetime.now(timezone.utc)
        start = now - timedelta(hours=24)

        start_ts = Timestamp()
        start_ts.FromDatetime(start)
        end_ts = Timestamp()
        end_ts.FromDatetime(now)

        interval = monitoring_v3.TimeInterval(
            start_time=start_ts,
            end_time=end_ts,
        )

        # HARDCODED Cloud Monitoring API call -- read-only.
        results = monitoring_client.list_time_series(
            request={
                "name": f"projects/{project}",
                "filter": (
                    'metric.type = "cloudsql.googleapis.com/database/network/connections"'
                    f' AND resource.labels.database_id = "{project}:{instance_id}"'
                ),
                "interval": interval,
                "view": monitoring_v3.ListTimeSeriesRequest.TimeSeriesView.FULL,
            }
        )

        total_connections = 0
        has_data = False
        for ts in results:
            for point in ts.points:
                has_data = True
                total_connections += int(point.value.int64_value)

        if not has_data:
            return ("UNKNOWN", "No connection datapoints in the last 24 hours")

        if total_connections > 0:
            return (
                "ACTIVE",
                f"{total_connections} database connections in the last 24 hours",
            )
        else:
            return ("IDLE", "0 database connections in the last 24 hours")

    except ImportError:
        return ("UNKNOWN", "google-cloud-monitoring is not installed")
    except Exception as exc:
        logger.debug("Cloud SQL activity check failed for %s: %s", instance_id, exc)
        return ("UNKNOWN", "Could not check activity")


# ---------------------------------------------------------------------------
# Cloud Functions
# ---------------------------------------------------------------------------

def _check_cloud_function_activity(
    monitoring_client: Any,
    project: str,
    function_name: str,
) -> tuple[str, str]:
    """Check Cloud Function invocation count via Cloud Monitoring."""
    try:
        from google.cloud import monitoring_v3
        from google.protobuf.timestamp_pb2 import Timestamp

        now = datetime.now(timezone.utc)
        start = now - timedelta(hours=24)

        start_ts = Timestamp()
        start_ts.FromDatetime(start)
        end_ts = Timestamp()
        end_ts.FromDatetime(now)

        interval = monitoring_v3.TimeInterval(
            start_time=start_ts,
            end_time=end_ts,
        )

        # HARDCODED Cloud Monitoring API call -- read-only.
        results = monitoring_client.list_time_series(
            request={
                "name": f"projects/{project}",
                "filter": (
                    'metric.type = "cloudfunctions.googleapis.com/function/execution_count"'
                    f' AND resource.labels.function_name = "{function_name}"'
                ),
                "interval": interval,
                "view": monitoring_v3.ListTimeSeriesRequest.TimeSeriesView.FULL,
            }
        )

        total_invocations = 0
        has_data = False
        for ts in results:
            for point in ts.points:
                has_data = True
                total_invocations += int(point.value.int64_value)

        if not has_data:
            return ("UNKNOWN", "No invocation datapoints in the last 24 hours")

        if total_invocations > 0:
            return (
                "ACTIVE",
                f"{total_invocations} invocations in the last 24 hours",
            )
        else:
            return ("IDLE", "0 invocations in the last 24 hours")

    except ImportError:
        return ("UNKNOWN", "google-cloud-monitoring is not installed")
    except Exception as exc:
        logger.debug(
            "Cloud Function activity check failed for %s: %s", function_name, exc
        )
        return ("UNKNOWN", "Could not check activity")


# ===================================================================
# Helpers
# ===================================================================

def _extract_resource_id(resource: dict) -> str:
    """Best-effort extraction of the resource identifier from an ARN or name.

    For an ARN like ``arn:aws:ec2:us-east-1:123456:instance/i-abc123``,
    returns ``i-abc123``.  Falls back to the ``name`` field or the full ARN.
    """
    arn = resource.get("arn", "")
    if "/" in arn:
        return arn.rsplit("/", 1)[-1]
    if ":" in arn:
        return arn.rsplit(":", 1)[-1]
    return resource.get("name", arn)


def _extract_elb_name(resource: dict) -> str:
    """Extract the ELB/ALB dimension value from a resource.

    ALB ARNs look like:
        arn:aws:elasticloadbalancing:region:acct:loadbalancer/app/my-lb/abc123

    The CloudWatch dimension ``LoadBalancer`` expects the portion after
    ``loadbalancer/``, e.g. ``app/my-lb/abc123``.
    """
    arn = resource.get("arn", "")
    marker = "loadbalancer/"
    idx = arn.find(marker)
    if idx != -1:
        return arn[idx + len(marker):]
    # Fallback: use the name field.
    return resource.get("name", arn)
