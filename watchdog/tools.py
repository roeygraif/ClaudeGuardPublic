"""
Cloud Watchdog Tools — Read-only cloud API tool definitions and execution engine.

Provides hardcoded allowlists of read-only AWS (boto3) and GCP (google.cloud)
API operations, tool schemas for Claude tool-use, and a safe execution engine
that dispatches calls through an explicit if/elif chain (never getattr).
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, date
from typing import Any

try:
    import boto3 as _boto3
except ImportError:
    _boto3 = None  # type: ignore[assignment]

logger = logging.getLogger("cloud-watchdog.tools")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

MAX_RESPONSE_BYTES = 50 * 1024  # 50 KB truncation limit


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class ToolNotAllowedError(Exception):
    """Raised when a tool name does not match any allowlisted operation."""


# ---------------------------------------------------------------------------
# AWS Allowlist — (service, method) -> description
# ---------------------------------------------------------------------------

AWS_ALLOWLIST: dict[tuple[str, str], str] = {
    # EC2
    ("ec2", "describe_instances"): "List EC2 instances with optional filters",
    ("ec2", "describe_security_groups"): "List security groups with optional filters",
    ("ec2", "describe_vpcs"): "List VPCs",
    ("ec2", "describe_subnets"): "List subnets",
    ("ec2", "describe_network_interfaces"): "List network interfaces",
    ("ec2", "describe_images"): "List AMIs owned by the account",
    ("ec2", "describe_volumes"): "List EBS volumes",
    ("ec2", "describe_snapshots"): "List EBS snapshots",
    ("ec2", "describe_addresses"): "List Elastic IP addresses",
    ("ec2", "describe_nat_gateways"): "List NAT gateways",
    ("ec2", "describe_internet_gateways"): "List internet gateways",
    ("ec2", "describe_route_tables"): "List route tables",
    ("ec2", "describe_network_acls"): "List network ACLs",
    # RDS
    ("rds", "describe_db_instances"): "List RDS DB instances",
    ("rds", "describe_db_clusters"): "List RDS DB clusters",
    ("rds", "describe_db_snapshots"): "List RDS DB snapshots",
    ("rds", "describe_db_subnet_groups"): "List RDS DB subnet groups",
    # Lambda
    ("lambda", "get_function"): "Get Lambda function details",
    ("lambda", "list_functions"): "List Lambda functions",
    ("lambda", "get_function_configuration"): "Get Lambda function configuration",
    ("lambda", "get_policy"): "Get Lambda function resource policy",
    ("lambda", "list_event_source_mappings"): "List Lambda event source mappings",
    # ECS
    ("ecs", "describe_clusters"): "Describe ECS clusters",
    ("ecs", "describe_services"): "Describe ECS services",
    ("ecs", "describe_task_definition"): "Describe an ECS task definition",
    ("ecs", "list_services"): "List ECS services in a cluster",
    ("ecs", "list_tasks"): "List ECS tasks in a cluster",
    # EKS
    ("eks", "describe_cluster"): "Describe an EKS cluster",
    ("eks", "list_clusters"): "List EKS clusters",
    ("eks", "list_nodegroups"): "List EKS node groups",
    ("eks", "describe_nodegroup"): "Describe an EKS node group",
    # ELBv2
    ("elbv2", "describe_load_balancers"): "List Application/Network Load Balancers",
    ("elbv2", "describe_target_groups"): "List target groups",
    ("elbv2", "describe_listeners"): "List listeners for a load balancer",
    ("elbv2", "describe_target_health"): "Describe target health for a target group",
    # S3
    ("s3", "list_buckets"): "List S3 buckets",
    ("s3", "get_bucket_policy"): "Get S3 bucket policy",
    ("s3", "get_bucket_acl"): "Get S3 bucket ACL",
    ("s3", "get_bucket_versioning"): "Get S3 bucket versioning configuration",
    ("s3", "get_bucket_encryption"): "Get S3 bucket encryption configuration",
    ("s3", "get_bucket_lifecycle_configuration"): "Get S3 bucket lifecycle configuration",
    ("s3", "get_bucket_tagging"): "Get S3 bucket tags",
    # IAM
    ("iam", "get_role"): "Get IAM role details",
    ("iam", "list_roles"): "List IAM roles",
    ("iam", "list_attached_role_policies"): "List policies attached to a role",
    ("iam", "get_policy"): "Get IAM policy details",
    ("iam", "get_policy_version"): "Get a specific version of an IAM policy",
    ("iam", "list_role_policies"): "List inline policies for a role",
    ("iam", "get_role_policy"): "Get an inline policy for a role",
    ("iam", "get_user"): "Get IAM user details",
    ("iam", "list_users"): "List IAM users",
    ("iam", "list_attached_user_policies"): "List policies attached to a user",
    ("iam", "list_groups_for_user"): "List groups a user belongs to",
    ("iam", "get_instance_profile"): "Get instance profile details",
    # Route53
    ("route53", "list_hosted_zones"): "List Route53 hosted zones",
    ("route53", "list_resource_record_sets"): "List DNS records in a hosted zone",
    ("route53", "get_hosted_zone"): "Get hosted zone details",
    # CloudFront
    ("cloudfront", "get_distribution"): "Get CloudFront distribution details",
    ("cloudfront", "list_distributions"): "List CloudFront distributions",
    # DynamoDB
    ("dynamodb", "describe_table"): "Describe a DynamoDB table (status, item count, size, throughput, GSIs)",
    ("dynamodb", "describe_continuous_backups"): "Check if point-in-time recovery is enabled for a DynamoDB table",
    ("dynamodb", "describe_time_to_live"): "Check TTL configuration for a DynamoDB table",
    ("dynamodb", "list_tags_of_resource"): "List tags on a DynamoDB resource",
    # SQS
    ("sqs", "get_queue_attributes"): "Get SQS queue attributes (message count, policy, DLQ config)",
    ("sqs", "list_queues"): "List SQS queues",
    # SNS
    ("sns", "get_topic_attributes"): "Get SNS topic attributes (subscriptions, policy)",
    ("sns", "list_subscriptions_by_topic"): "List subscriptions for an SNS topic",
    # STS
    ("sts", "get_caller_identity"): "Get the current IAM caller identity",
    # CloudWatch
    ("cloudwatch", "get_metric_statistics"): "Get metric data points (CPU, network, connections, etc.)",
    ("cloudwatch", "list_metrics"): "List available CloudWatch metrics for a resource",
    ("cloudwatch", "describe_alarms"): "List CloudWatch alarms",
    # CloudWatch Logs
    ("logs", "describe_log_groups"): "List CloudWatch log groups",
    ("logs", "filter_log_events"): "Search/filter CloudWatch log events across streams",
    # CloudTrail
    ("cloudtrail", "lookup_events"): "Look up recent AWS API activity events",
}


# ---------------------------------------------------------------------------
# GCP Allowlist — (service, method) -> description
# ---------------------------------------------------------------------------

GCP_ALLOWLIST: dict[tuple[str, str], str] = {
    # Compute
    ("compute_instances", "get"): "Get a Compute Engine instance",
    ("compute_instances", "aggregated_list"): "List all Compute Engine instances across zones",
    ("compute_firewalls", "list"): "List firewall rules",
    ("compute_firewalls", "get"): "Get a firewall rule",
    ("compute_networks", "list"): "List VPC networks",
    ("compute_networks", "get"): "Get a VPC network",
    ("compute_subnetworks", "list"): "List subnetworks",
    ("compute_subnetworks", "aggregated_list"): "List all subnetworks across regions",
    ("compute_addresses", "aggregated_list"): "List all addresses across regions",
    ("compute_forwarding_rules", "aggregated_list"): "List all forwarding rules",
    # GKE
    ("container", "get_cluster"): "Get a GKE cluster",
    ("container", "list_clusters"): "List GKE clusters",
    ("container", "list_node_pools"): "List node pools in a GKE cluster",
    # Cloud SQL
    ("sqladmin", "get"): "Get a Cloud SQL instance",
    ("sqladmin", "list"): "List Cloud SQL instances",
    # Storage
    ("storage", "get_bucket"): "Get a Cloud Storage bucket",
    ("storage", "list_buckets"): "List Cloud Storage buckets",
    ("storage", "get_bucket_iam_policy"): "Get IAM policy for a bucket",
    # IAM
    ("iam", "get_iam_policy"): "Get project IAM policy",
    ("iam", "get_service_account"): "Get a service account",
    ("iam", "list_service_accounts"): "List service accounts",
    ("iam", "list_service_account_keys"): "List keys for a service account",
    # Cloud Functions
    ("functions", "get_function"): "Get a Cloud Function",
    ("functions", "list_functions"): "List Cloud Functions",
    # Cloud Run
    ("run_services", "get_service"): "Get a Cloud Run service",
    ("run_services", "list_services"): "List Cloud Run services",
    ("run_revisions", "list_revisions"): "List Cloud Run revisions",
    # Cloud Monitoring
    ("monitoring", "list_time_series"): "List time series metric data",
    # Cloud Logging
    ("logging", "list_entries"): "List log entries",
}


# ---------------------------------------------------------------------------
# Tool schemas — parameter definitions for each tool
# ---------------------------------------------------------------------------

_AWS_TOOL_SCHEMAS: dict[tuple[str, str], dict] = {
    # EC2
    ("ec2", "describe_instances"): {
        "type": "object",
        "properties": {
            "InstanceIds": {"type": "array", "items": {"type": "string"}, "description": "Instance IDs to filter by"},
            "Filters": {"type": "array", "items": {"type": "object"}, "description": "Boto3 filters"},
        },
    },
    ("ec2", "describe_security_groups"): {
        "type": "object",
        "properties": {
            "GroupIds": {"type": "array", "items": {"type": "string"}, "description": "Security group IDs"},
            "Filters": {"type": "array", "items": {"type": "object"}, "description": "Boto3 filters"},
        },
    },
    ("ec2", "describe_vpcs"): {
        "type": "object",
        "properties": {
            "VpcIds": {"type": "array", "items": {"type": "string"}},
            "Filters": {"type": "array", "items": {"type": "object"}},
        },
    },
    ("ec2", "describe_subnets"): {
        "type": "object",
        "properties": {
            "SubnetIds": {"type": "array", "items": {"type": "string"}},
            "Filters": {"type": "array", "items": {"type": "object"}},
        },
    },
    ("ec2", "describe_network_interfaces"): {
        "type": "object",
        "properties": {
            "NetworkInterfaceIds": {"type": "array", "items": {"type": "string"}},
            "Filters": {"type": "array", "items": {"type": "object"}},
        },
    },
    ("ec2", "describe_images"): {
        "type": "object",
        "properties": {
            "ImageIds": {"type": "array", "items": {"type": "string"}},
            "Owners": {"type": "array", "items": {"type": "string"}},
            "Filters": {"type": "array", "items": {"type": "object"}},
        },
    },
    ("ec2", "describe_volumes"): {
        "type": "object",
        "properties": {
            "VolumeIds": {"type": "array", "items": {"type": "string"}},
            "Filters": {"type": "array", "items": {"type": "object"}},
        },
    },
    ("ec2", "describe_snapshots"): {
        "type": "object",
        "properties": {
            "SnapshotIds": {"type": "array", "items": {"type": "string"}},
            "OwnerIds": {"type": "array", "items": {"type": "string"}},
            "Filters": {"type": "array", "items": {"type": "object"}},
        },
    },
    ("ec2", "describe_addresses"): {
        "type": "object",
        "properties": {
            "AllocationIds": {"type": "array", "items": {"type": "string"}},
            "Filters": {"type": "array", "items": {"type": "object"}},
        },
    },
    ("ec2", "describe_nat_gateways"): {
        "type": "object",
        "properties": {
            "NatGatewayIds": {"type": "array", "items": {"type": "string"}},
            "Filter": {"type": "array", "items": {"type": "object"}},
        },
    },
    ("ec2", "describe_internet_gateways"): {
        "type": "object",
        "properties": {
            "InternetGatewayIds": {"type": "array", "items": {"type": "string"}},
            "Filters": {"type": "array", "items": {"type": "object"}},
        },
    },
    ("ec2", "describe_route_tables"): {
        "type": "object",
        "properties": {
            "RouteTableIds": {"type": "array", "items": {"type": "string"}},
            "Filters": {"type": "array", "items": {"type": "object"}},
        },
    },
    ("ec2", "describe_network_acls"): {
        "type": "object",
        "properties": {
            "NetworkAclIds": {"type": "array", "items": {"type": "string"}},
            "Filters": {"type": "array", "items": {"type": "object"}},
        },
    },
    # RDS
    ("rds", "describe_db_instances"): {
        "type": "object",
        "properties": {
            "DBInstanceIdentifier": {"type": "string"},
            "Filters": {"type": "array", "items": {"type": "object"}},
        },
    },
    ("rds", "describe_db_clusters"): {
        "type": "object",
        "properties": {
            "DBClusterIdentifier": {"type": "string"},
            "Filters": {"type": "array", "items": {"type": "object"}},
        },
    },
    ("rds", "describe_db_snapshots"): {
        "type": "object",
        "properties": {
            "DBSnapshotIdentifier": {"type": "string"},
            "DBInstanceIdentifier": {"type": "string"},
            "Filters": {"type": "array", "items": {"type": "object"}},
        },
    },
    ("rds", "describe_db_subnet_groups"): {
        "type": "object",
        "properties": {
            "DBSubnetGroupName": {"type": "string"},
        },
    },
    # Lambda
    ("lambda", "get_function"): {
        "type": "object",
        "properties": {
            "FunctionName": {"type": "string", "description": "Function name or ARN"},
        },
        "required": ["FunctionName"],
    },
    ("lambda", "list_functions"): {
        "type": "object",
        "properties": {},
    },
    ("lambda", "get_function_configuration"): {
        "type": "object",
        "properties": {
            "FunctionName": {"type": "string"},
        },
        "required": ["FunctionName"],
    },
    ("lambda", "get_policy"): {
        "type": "object",
        "properties": {
            "FunctionName": {"type": "string"},
        },
        "required": ["FunctionName"],
    },
    ("lambda", "list_event_source_mappings"): {
        "type": "object",
        "properties": {
            "FunctionName": {"type": "string"},
        },
    },
    # ECS
    ("ecs", "describe_clusters"): {
        "type": "object",
        "properties": {
            "clusters": {"type": "array", "items": {"type": "string"}},
        },
    },
    ("ecs", "describe_services"): {
        "type": "object",
        "properties": {
            "cluster": {"type": "string"},
            "services": {"type": "array", "items": {"type": "string"}},
        },
        "required": ["cluster", "services"],
    },
    ("ecs", "describe_task_definition"): {
        "type": "object",
        "properties": {
            "taskDefinition": {"type": "string"},
        },
        "required": ["taskDefinition"],
    },
    ("ecs", "list_services"): {
        "type": "object",
        "properties": {
            "cluster": {"type": "string"},
        },
    },
    ("ecs", "list_tasks"): {
        "type": "object",
        "properties": {
            "cluster": {"type": "string"},
        },
    },
    # EKS
    ("eks", "describe_cluster"): {
        "type": "object",
        "properties": {
            "name": {"type": "string"},
        },
        "required": ["name"],
    },
    ("eks", "list_clusters"): {
        "type": "object",
        "properties": {},
    },
    ("eks", "list_nodegroups"): {
        "type": "object",
        "properties": {
            "clusterName": {"type": "string"},
        },
        "required": ["clusterName"],
    },
    ("eks", "describe_nodegroup"): {
        "type": "object",
        "properties": {
            "clusterName": {"type": "string"},
            "nodegroupName": {"type": "string"},
        },
        "required": ["clusterName", "nodegroupName"],
    },
    # ELBv2
    ("elbv2", "describe_load_balancers"): {
        "type": "object",
        "properties": {
            "LoadBalancerArns": {"type": "array", "items": {"type": "string"}},
            "Names": {"type": "array", "items": {"type": "string"}},
        },
    },
    ("elbv2", "describe_target_groups"): {
        "type": "object",
        "properties": {
            "TargetGroupArns": {"type": "array", "items": {"type": "string"}},
            "LoadBalancerArn": {"type": "string"},
        },
    },
    ("elbv2", "describe_listeners"): {
        "type": "object",
        "properties": {
            "LoadBalancerArn": {"type": "string"},
        },
        "required": ["LoadBalancerArn"],
    },
    ("elbv2", "describe_target_health"): {
        "type": "object",
        "properties": {
            "TargetGroupArn": {"type": "string"},
        },
        "required": ["TargetGroupArn"],
    },
    # S3
    ("s3", "list_buckets"): {
        "type": "object",
        "properties": {},
    },
    ("s3", "get_bucket_policy"): {
        "type": "object",
        "properties": {
            "Bucket": {"type": "string"},
        },
        "required": ["Bucket"],
    },
    ("s3", "get_bucket_acl"): {
        "type": "object",
        "properties": {
            "Bucket": {"type": "string"},
        },
        "required": ["Bucket"],
    },
    ("s3", "get_bucket_versioning"): {
        "type": "object",
        "properties": {
            "Bucket": {"type": "string"},
        },
        "required": ["Bucket"],
    },
    ("s3", "get_bucket_encryption"): {
        "type": "object",
        "properties": {
            "Bucket": {"type": "string"},
        },
        "required": ["Bucket"],
    },
    ("s3", "get_bucket_lifecycle_configuration"): {
        "type": "object",
        "properties": {
            "Bucket": {"type": "string"},
        },
        "required": ["Bucket"],
    },
    ("s3", "get_bucket_tagging"): {
        "type": "object",
        "properties": {
            "Bucket": {"type": "string"},
        },
        "required": ["Bucket"],
    },
    # IAM
    ("iam", "get_role"): {
        "type": "object",
        "properties": {
            "RoleName": {"type": "string"},
        },
        "required": ["RoleName"],
    },
    ("iam", "list_roles"): {
        "type": "object",
        "properties": {},
    },
    ("iam", "list_attached_role_policies"): {
        "type": "object",
        "properties": {
            "RoleName": {"type": "string"},
        },
        "required": ["RoleName"],
    },
    ("iam", "get_policy"): {
        "type": "object",
        "properties": {
            "PolicyArn": {"type": "string"},
        },
        "required": ["PolicyArn"],
    },
    ("iam", "get_policy_version"): {
        "type": "object",
        "properties": {
            "PolicyArn": {"type": "string"},
            "VersionId": {"type": "string"},
        },
        "required": ["PolicyArn", "VersionId"],
    },
    ("iam", "list_role_policies"): {
        "type": "object",
        "properties": {
            "RoleName": {"type": "string"},
        },
        "required": ["RoleName"],
    },
    ("iam", "get_role_policy"): {
        "type": "object",
        "properties": {
            "RoleName": {"type": "string"},
            "PolicyName": {"type": "string"},
        },
        "required": ["RoleName", "PolicyName"],
    },
    ("iam", "get_user"): {
        "type": "object",
        "properties": {
            "UserName": {"type": "string"},
        },
    },
    ("iam", "list_users"): {
        "type": "object",
        "properties": {},
    },
    ("iam", "list_attached_user_policies"): {
        "type": "object",
        "properties": {
            "UserName": {"type": "string"},
        },
        "required": ["UserName"],
    },
    ("iam", "list_groups_for_user"): {
        "type": "object",
        "properties": {
            "UserName": {"type": "string"},
        },
        "required": ["UserName"],
    },
    ("iam", "get_instance_profile"): {
        "type": "object",
        "properties": {
            "InstanceProfileName": {"type": "string"},
        },
        "required": ["InstanceProfileName"],
    },
    # Route53
    ("route53", "list_hosted_zones"): {
        "type": "object",
        "properties": {},
    },
    ("route53", "list_resource_record_sets"): {
        "type": "object",
        "properties": {
            "HostedZoneId": {"type": "string"},
        },
        "required": ["HostedZoneId"],
    },
    ("route53", "get_hosted_zone"): {
        "type": "object",
        "properties": {
            "Id": {"type": "string"},
        },
        "required": ["Id"],
    },
    # CloudFront
    ("cloudfront", "get_distribution"): {
        "type": "object",
        "properties": {
            "Id": {"type": "string"},
        },
        "required": ["Id"],
    },
    ("cloudfront", "list_distributions"): {
        "type": "object",
        "properties": {},
    },
    # DynamoDB
    ("dynamodb", "describe_table"): {
        "type": "object",
        "properties": {
            "TableName": {"type": "string", "description": "DynamoDB table name"},
        },
        "required": ["TableName"],
    },
    ("dynamodb", "describe_continuous_backups"): {
        "type": "object",
        "properties": {
            "TableName": {"type": "string"},
        },
        "required": ["TableName"],
    },
    ("dynamodb", "describe_time_to_live"): {
        "type": "object",
        "properties": {
            "TableName": {"type": "string"},
        },
        "required": ["TableName"],
    },
    ("dynamodb", "list_tags_of_resource"): {
        "type": "object",
        "properties": {
            "ResourceArn": {"type": "string", "description": "DynamoDB table ARN"},
        },
        "required": ["ResourceArn"],
    },
    # SQS
    ("sqs", "get_queue_attributes"): {
        "type": "object",
        "properties": {
            "QueueUrl": {"type": "string"},
            "AttributeNames": {"type": "array", "items": {"type": "string"}, "description": "e.g. [All]"},
        },
        "required": ["QueueUrl", "AttributeNames"],
    },
    ("sqs", "list_queues"): {
        "type": "object",
        "properties": {
            "QueueNamePrefix": {"type": "string"},
        },
    },
    # SNS
    ("sns", "get_topic_attributes"): {
        "type": "object",
        "properties": {
            "TopicArn": {"type": "string"},
        },
        "required": ["TopicArn"],
    },
    ("sns", "list_subscriptions_by_topic"): {
        "type": "object",
        "properties": {
            "TopicArn": {"type": "string"},
        },
        "required": ["TopicArn"],
    },
    # STS
    ("sts", "get_caller_identity"): {
        "type": "object",
        "properties": {},
    },
    # CloudWatch
    ("cloudwatch", "get_metric_statistics"): {
        "type": "object",
        "properties": {
            "Namespace": {"type": "string", "description": "e.g. AWS/EC2, AWS/RDS, AWS/ELB"},
            "MetricName": {"type": "string", "description": "e.g. CPUUtilization, DatabaseConnections"},
            "Dimensions": {"type": "array", "items": {"type": "object"}, "description": "[{Name, Value}]"},
            "StartTime": {"type": "string", "description": "ISO 8601 timestamp"},
            "EndTime": {"type": "string", "description": "ISO 8601 timestamp"},
            "Period": {"type": "integer", "description": "Granularity in seconds (e.g. 300)"},
            "Statistics": {"type": "array", "items": {"type": "string"}, "description": "e.g. [Average, Sum, Maximum]"},
        },
        "required": ["Namespace", "MetricName", "StartTime", "EndTime", "Period", "Statistics"],
    },
    ("cloudwatch", "list_metrics"): {
        "type": "object",
        "properties": {
            "Namespace": {"type": "string"},
            "MetricName": {"type": "string"},
            "Dimensions": {"type": "array", "items": {"type": "object"}},
        },
    },
    ("cloudwatch", "describe_alarms"): {
        "type": "object",
        "properties": {
            "AlarmNames": {"type": "array", "items": {"type": "string"}},
            "AlarmNamePrefix": {"type": "string"},
            "StateValue": {"type": "string", "description": "OK | ALARM | INSUFFICIENT_DATA"},
        },
    },
    # CloudWatch Logs
    ("logs", "describe_log_groups"): {
        "type": "object",
        "properties": {
            "logGroupNamePrefix": {"type": "string"},
        },
    },
    ("logs", "filter_log_events"): {
        "type": "object",
        "properties": {
            "logGroupName": {"type": "string"},
            "filterPattern": {"type": "string", "description": "CloudWatch Logs filter pattern"},
            "startTime": {"type": "integer", "description": "Epoch milliseconds"},
            "endTime": {"type": "integer", "description": "Epoch milliseconds"},
            "limit": {"type": "integer", "description": "Max events to return (default 50, max 10000)"},
        },
        "required": ["logGroupName"],
    },
    # CloudTrail
    ("cloudtrail", "lookup_events"): {
        "type": "object",
        "properties": {
            "LookupAttributes": {"type": "array", "items": {"type": "object"}, "description": "[{AttributeKey, AttributeValue}]"},
            "StartTime": {"type": "string", "description": "ISO 8601 timestamp"},
            "EndTime": {"type": "string", "description": "ISO 8601 timestamp"},
            "MaxResults": {"type": "integer", "description": "1-50, default 50"},
        },
    },
}

_GCP_TOOL_SCHEMAS: dict[tuple[str, str], dict] = {
    # Compute
    ("compute_instances", "get"): {
        "type": "object",
        "properties": {
            "project": {"type": "string"},
            "zone": {"type": "string"},
            "instance": {"type": "string"},
        },
        "required": ["project", "zone", "instance"],
    },
    ("compute_instances", "aggregated_list"): {
        "type": "object",
        "properties": {
            "project": {"type": "string"},
        },
        "required": ["project"],
    },
    ("compute_firewalls", "list"): {
        "type": "object",
        "properties": {
            "project": {"type": "string"},
        },
        "required": ["project"],
    },
    ("compute_firewalls", "get"): {
        "type": "object",
        "properties": {
            "project": {"type": "string"},
            "firewall": {"type": "string"},
        },
        "required": ["project", "firewall"],
    },
    ("compute_networks", "list"): {
        "type": "object",
        "properties": {
            "project": {"type": "string"},
        },
        "required": ["project"],
    },
    ("compute_networks", "get"): {
        "type": "object",
        "properties": {
            "project": {"type": "string"},
            "network": {"type": "string"},
        },
        "required": ["project", "network"],
    },
    ("compute_subnetworks", "list"): {
        "type": "object",
        "properties": {
            "project": {"type": "string"},
            "region": {"type": "string"},
        },
        "required": ["project", "region"],
    },
    ("compute_subnetworks", "aggregated_list"): {
        "type": "object",
        "properties": {
            "project": {"type": "string"},
        },
        "required": ["project"],
    },
    ("compute_addresses", "aggregated_list"): {
        "type": "object",
        "properties": {
            "project": {"type": "string"},
        },
        "required": ["project"],
    },
    ("compute_forwarding_rules", "aggregated_list"): {
        "type": "object",
        "properties": {
            "project": {"type": "string"},
        },
        "required": ["project"],
    },
    # GKE
    ("container", "get_cluster"): {
        "type": "object",
        "properties": {
            "name": {"type": "string", "description": "Full resource name: projects/*/locations/*/clusters/*"},
        },
        "required": ["name"],
    },
    ("container", "list_clusters"): {
        "type": "object",
        "properties": {
            "parent": {"type": "string", "description": "Parent: projects/*/locations/*"},
        },
        "required": ["parent"],
    },
    ("container", "list_node_pools"): {
        "type": "object",
        "properties": {
            "parent": {"type": "string", "description": "Parent: projects/*/locations/*/clusters/*"},
        },
        "required": ["parent"],
    },
    # Cloud SQL
    ("sqladmin", "get"): {
        "type": "object",
        "properties": {
            "project": {"type": "string"},
            "instance": {"type": "string"},
        },
        "required": ["project", "instance"],
    },
    ("sqladmin", "list"): {
        "type": "object",
        "properties": {
            "project": {"type": "string"},
        },
        "required": ["project"],
    },
    # Storage
    ("storage", "get_bucket"): {
        "type": "object",
        "properties": {
            "bucket_name": {"type": "string"},
        },
        "required": ["bucket_name"],
    },
    ("storage", "list_buckets"): {
        "type": "object",
        "properties": {
            "project": {"type": "string"},
        },
    },
    ("storage", "get_bucket_iam_policy"): {
        "type": "object",
        "properties": {
            "bucket_name": {"type": "string"},
        },
        "required": ["bucket_name"],
    },
    # IAM
    ("iam", "get_iam_policy"): {
        "type": "object",
        "properties": {
            "resource": {"type": "string", "description": "Resource name: projects/{project}"},
        },
        "required": ["resource"],
    },
    ("iam", "get_service_account"): {
        "type": "object",
        "properties": {
            "name": {"type": "string", "description": "Full name: projects/*/serviceAccounts/*"},
        },
        "required": ["name"],
    },
    ("iam", "list_service_accounts"): {
        "type": "object",
        "properties": {
            "name": {"type": "string", "description": "Project: projects/{project}"},
        },
        "required": ["name"],
    },
    ("iam", "list_service_account_keys"): {
        "type": "object",
        "properties": {
            "name": {"type": "string", "description": "Service account: projects/*/serviceAccounts/*"},
        },
        "required": ["name"],
    },
    # Cloud Functions
    ("functions", "get_function"): {
        "type": "object",
        "properties": {
            "name": {"type": "string", "description": "Full name: projects/*/locations/*/functions/*"},
        },
        "required": ["name"],
    },
    ("functions", "list_functions"): {
        "type": "object",
        "properties": {
            "parent": {"type": "string", "description": "Parent: projects/*/locations/*"},
        },
        "required": ["parent"],
    },
    # Cloud Run
    ("run_services", "get_service"): {
        "type": "object",
        "properties": {
            "name": {"type": "string", "description": "Full name: projects/*/locations/*/services/*"},
        },
        "required": ["name"],
    },
    ("run_services", "list_services"): {
        "type": "object",
        "properties": {
            "parent": {"type": "string", "description": "Parent: projects/*/locations/*"},
        },
        "required": ["parent"],
    },
    ("run_revisions", "list_revisions"): {
        "type": "object",
        "properties": {
            "parent": {"type": "string", "description": "Parent: projects/*/locations/*/services/*"},
        },
        "required": ["parent"],
    },
    # Cloud Monitoring
    ("monitoring", "list_time_series"): {
        "type": "object",
        "properties": {
            "name": {"type": "string", "description": "Project: projects/{project_id}"},
            "filter": {"type": "string", "description": "Monitoring filter, e.g. metric.type=\"compute.googleapis.com/instance/cpu/utilization\""},
            "interval": {"type": "object", "description": "{start_time, end_time} as ISO 8601 strings"},
            "aggregation": {"type": "object", "description": "Optional aggregation settings"},
        },
        "required": ["name", "filter", "interval"],
    },
    # Cloud Logging
    ("logging", "list_entries"): {
        "type": "object",
        "properties": {
            "resource_names": {"type": "array", "items": {"type": "string"}, "description": "e.g. [projects/{project}]"},
            "filter": {"type": "string", "description": "Logging filter expression"},
            "order_by": {"type": "string", "description": "timestamp asc or timestamp desc"},
            "page_size": {"type": "integer", "description": "Max entries to return"},
        },
        "required": ["resource_names"],
    },
}


# ---------------------------------------------------------------------------
# Tool name encoding / decoding
# ---------------------------------------------------------------------------

def _make_tool_name(provider: str, service: str, method: str) -> str:
    """Encode a (provider, service, method) triple into a tool name string."""
    return f"{provider}_{service}_{method}"


def _parse_tool_name(tool_name: str) -> tuple[str, str, str]:
    """Decode a tool name into (provider, service, method).

    Raises ToolNotAllowedError if the name does not have the expected format.
    """
    parts = tool_name.split("_", 1)
    if len(parts) < 2:
        raise ToolNotAllowedError(f"Invalid tool name format: {tool_name}")

    provider = parts[0]
    remainder = parts[1]

    if provider == "aws":
        # AWS: aws_{service}_{method} — method may contain underscores
        for (svc, meth) in AWS_ALLOWLIST:
            expected = f"{svc}_{meth}"
            if remainder == expected:
                return provider, svc, meth
        raise ToolNotAllowedError(f"Unknown AWS tool: {tool_name}")

    elif provider == "gcp":
        # GCP: gcp_{service}_{method}
        for (svc, meth) in GCP_ALLOWLIST:
            expected = f"{svc}_{meth}"
            if remainder == expected:
                return provider, svc, meth
        raise ToolNotAllowedError(f"Unknown GCP tool: {tool_name}")

    else:
        raise ToolNotAllowedError(f"Unknown provider in tool name: {tool_name}")


# ---------------------------------------------------------------------------
# Build tool definitions for the Anthropic API
# ---------------------------------------------------------------------------

def build_tool_definitions(provider: str | None = None) -> list[dict]:
    """Build the list of tool definition dicts for the Anthropic messages API.

    Parameters
    ----------
    provider:
        ``"aws"``, ``"gcp"``, or None.  When None, returns tools for both.
    """
    tools: list[dict] = []

    if provider in (None, "aws"):
        for (service, method), description in AWS_ALLOWLIST.items():
            schema = _AWS_TOOL_SCHEMAS.get((service, method), {"type": "object", "properties": {}})
            tools.append({
                "name": _make_tool_name("aws", service, method),
                "description": description,
                "input_schema": schema,
            })

    if provider in (None, "gcp"):
        for (service, method), description in GCP_ALLOWLIST.items():
            schema = _GCP_TOOL_SCHEMAS.get((service, method), {"type": "object", "properties": {}})
            tools.append({
                "name": _make_tool_name("gcp", service, method),
                "description": description,
                "input_schema": schema,
            })

    return tools


# ---------------------------------------------------------------------------
# Serialization
# ---------------------------------------------------------------------------

def _serialize_value(obj: Any) -> Any:
    """Recursively convert an object to JSON-serializable form."""
    if obj is None or isinstance(obj, (bool, int, float, str)):
        return obj
    if isinstance(obj, bytes):
        return "<binary data omitted>"
    if isinstance(obj, (datetime, date)):
        return obj.isoformat()
    if isinstance(obj, dict):
        result = {}
        for k, v in obj.items():
            # Strip boto3 ResponseMetadata
            if k == "ResponseMetadata":
                continue
            result[str(k)] = _serialize_value(v)
        return result
    if isinstance(obj, (list, tuple)):
        return [_serialize_value(item) for item in obj]

    # GCP protobuf objects
    try:
        from google.protobuf.json_format import MessageToDict
        if hasattr(obj, "DESCRIPTOR"):
            return MessageToDict(obj, preserving_proto_field_name=True)
    except ImportError:
        pass

    # GCP pager objects — consume into list
    if hasattr(obj, "__iter__") and hasattr(obj, "pages"):
        items = []
        for item in obj:
            items.append(_serialize_value(item))
        return items

    # Fallback
    return str(obj)


def _serialize_response(response: Any) -> str:
    """Serialize a cloud API response to a JSON string, with truncation."""
    serialized = _serialize_value(response)
    text = json.dumps(serialized, indent=2, default=str)

    if len(text.encode("utf-8")) > MAX_RESPONSE_BYTES:
        truncated = text.encode("utf-8")[:MAX_RESPONSE_BYTES].decode("utf-8", errors="ignore")
        truncated += "\n\n... [TRUNCATED — response exceeded 50KB limit]"
        return truncated

    return text


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

def _validate_aws(service: str, method: str) -> None:
    if (service, method) not in AWS_ALLOWLIST:
        raise ToolNotAllowedError(f"AWS operation not allowlisted: {service}.{method}")


def _validate_gcp(service: str, method: str) -> None:
    if (service, method) not in GCP_ALLOWLIST:
        raise ToolNotAllowedError(f"GCP operation not allowlisted: {service}.{method}")


# ---------------------------------------------------------------------------
# AWS execution — explicit dispatch
# ---------------------------------------------------------------------------

def _execute_aws(service: str, method: str, tool_input: dict, session_kwargs: dict | None = None) -> str:
    """Execute an AWS API call through explicit if/elif dispatch."""
    if _boto3 is None:
        raise ImportError("boto3 is required for AWS tool execution")

    _validate_aws(service, method)
    session = _boto3.Session(**(session_kwargs or {}))

    # --- EC2 ---
    if (service, method) == ("ec2", "describe_instances"):
        client = session.client("ec2")
        return _serialize_response(client.describe_instances(**tool_input))
    elif (service, method) == ("ec2", "describe_security_groups"):
        client = session.client("ec2")
        return _serialize_response(client.describe_security_groups(**tool_input))
    elif (service, method) == ("ec2", "describe_vpcs"):
        client = session.client("ec2")
        return _serialize_response(client.describe_vpcs(**tool_input))
    elif (service, method) == ("ec2", "describe_subnets"):
        client = session.client("ec2")
        return _serialize_response(client.describe_subnets(**tool_input))
    elif (service, method) == ("ec2", "describe_network_interfaces"):
        client = session.client("ec2")
        return _serialize_response(client.describe_network_interfaces(**tool_input))
    elif (service, method) == ("ec2", "describe_images"):
        client = session.client("ec2")
        return _serialize_response(client.describe_images(**tool_input))
    elif (service, method) == ("ec2", "describe_volumes"):
        client = session.client("ec2")
        return _serialize_response(client.describe_volumes(**tool_input))
    elif (service, method) == ("ec2", "describe_snapshots"):
        client = session.client("ec2")
        return _serialize_response(client.describe_snapshots(**tool_input))
    elif (service, method) == ("ec2", "describe_addresses"):
        client = session.client("ec2")
        return _serialize_response(client.describe_addresses(**tool_input))
    elif (service, method) == ("ec2", "describe_nat_gateways"):
        client = session.client("ec2")
        return _serialize_response(client.describe_nat_gateways(**tool_input))
    elif (service, method) == ("ec2", "describe_internet_gateways"):
        client = session.client("ec2")
        return _serialize_response(client.describe_internet_gateways(**tool_input))
    elif (service, method) == ("ec2", "describe_route_tables"):
        client = session.client("ec2")
        return _serialize_response(client.describe_route_tables(**tool_input))
    elif (service, method) == ("ec2", "describe_network_acls"):
        client = session.client("ec2")
        return _serialize_response(client.describe_network_acls(**tool_input))

    # --- RDS ---
    elif (service, method) == ("rds", "describe_db_instances"):
        client = session.client("rds")
        return _serialize_response(client.describe_db_instances(**tool_input))
    elif (service, method) == ("rds", "describe_db_clusters"):
        client = session.client("rds")
        return _serialize_response(client.describe_db_clusters(**tool_input))
    elif (service, method) == ("rds", "describe_db_snapshots"):
        client = session.client("rds")
        return _serialize_response(client.describe_db_snapshots(**tool_input))
    elif (service, method) == ("rds", "describe_db_subnet_groups"):
        client = session.client("rds")
        return _serialize_response(client.describe_db_subnet_groups(**tool_input))

    # --- Lambda ---
    elif (service, method) == ("lambda", "get_function"):
        client = session.client("lambda")
        return _serialize_response(client.get_function(**tool_input))
    elif (service, method) == ("lambda", "list_functions"):
        client = session.client("lambda")
        return _serialize_response(client.list_functions(**tool_input))
    elif (service, method) == ("lambda", "get_function_configuration"):
        client = session.client("lambda")
        return _serialize_response(client.get_function_configuration(**tool_input))
    elif (service, method) == ("lambda", "get_policy"):
        client = session.client("lambda")
        return _serialize_response(client.get_policy(**tool_input))
    elif (service, method) == ("lambda", "list_event_source_mappings"):
        client = session.client("lambda")
        return _serialize_response(client.list_event_source_mappings(**tool_input))

    # --- ECS ---
    elif (service, method) == ("ecs", "describe_clusters"):
        client = session.client("ecs")
        return _serialize_response(client.describe_clusters(**tool_input))
    elif (service, method) == ("ecs", "describe_services"):
        client = session.client("ecs")
        return _serialize_response(client.describe_services(**tool_input))
    elif (service, method) == ("ecs", "describe_task_definition"):
        client = session.client("ecs")
        return _serialize_response(client.describe_task_definition(**tool_input))
    elif (service, method) == ("ecs", "list_services"):
        client = session.client("ecs")
        return _serialize_response(client.list_services(**tool_input))
    elif (service, method) == ("ecs", "list_tasks"):
        client = session.client("ecs")
        return _serialize_response(client.list_tasks(**tool_input))

    # --- EKS ---
    elif (service, method) == ("eks", "describe_cluster"):
        client = session.client("eks")
        return _serialize_response(client.describe_cluster(**tool_input))
    elif (service, method) == ("eks", "list_clusters"):
        client = session.client("eks")
        return _serialize_response(client.list_clusters(**tool_input))
    elif (service, method) == ("eks", "list_nodegroups"):
        client = session.client("eks")
        return _serialize_response(client.list_nodegroups(**tool_input))
    elif (service, method) == ("eks", "describe_nodegroup"):
        client = session.client("eks")
        return _serialize_response(client.describe_nodegroup(**tool_input))

    # --- ELBv2 ---
    elif (service, method) == ("elbv2", "describe_load_balancers"):
        client = session.client("elbv2")
        return _serialize_response(client.describe_load_balancers(**tool_input))
    elif (service, method) == ("elbv2", "describe_target_groups"):
        client = session.client("elbv2")
        return _serialize_response(client.describe_target_groups(**tool_input))
    elif (service, method) == ("elbv2", "describe_listeners"):
        client = session.client("elbv2")
        return _serialize_response(client.describe_listeners(**tool_input))
    elif (service, method) == ("elbv2", "describe_target_health"):
        client = session.client("elbv2")
        return _serialize_response(client.describe_target_health(**tool_input))

    # --- S3 ---
    elif (service, method) == ("s3", "list_buckets"):
        client = session.client("s3")
        return _serialize_response(client.list_buckets(**tool_input))
    elif (service, method) == ("s3", "get_bucket_policy"):
        client = session.client("s3")
        return _serialize_response(client.get_bucket_policy(**tool_input))
    elif (service, method) == ("s3", "get_bucket_acl"):
        client = session.client("s3")
        return _serialize_response(client.get_bucket_acl(**tool_input))
    elif (service, method) == ("s3", "get_bucket_versioning"):
        client = session.client("s3")
        return _serialize_response(client.get_bucket_versioning(**tool_input))
    elif (service, method) == ("s3", "get_bucket_encryption"):
        client = session.client("s3")
        return _serialize_response(client.get_bucket_encryption(**tool_input))
    elif (service, method) == ("s3", "get_bucket_lifecycle_configuration"):
        client = session.client("s3")
        return _serialize_response(client.get_bucket_lifecycle_configuration(**tool_input))
    elif (service, method) == ("s3", "get_bucket_tagging"):
        client = session.client("s3")
        return _serialize_response(client.get_bucket_tagging(**tool_input))

    # --- IAM ---
    elif (service, method) == ("iam", "get_role"):
        client = session.client("iam")
        return _serialize_response(client.get_role(**tool_input))
    elif (service, method) == ("iam", "list_roles"):
        client = session.client("iam")
        return _serialize_response(client.list_roles(**tool_input))
    elif (service, method) == ("iam", "list_attached_role_policies"):
        client = session.client("iam")
        return _serialize_response(client.list_attached_role_policies(**tool_input))
    elif (service, method) == ("iam", "get_policy"):
        client = session.client("iam")
        return _serialize_response(client.get_policy(**tool_input))
    elif (service, method) == ("iam", "get_policy_version"):
        client = session.client("iam")
        return _serialize_response(client.get_policy_version(**tool_input))
    elif (service, method) == ("iam", "list_role_policies"):
        client = session.client("iam")
        return _serialize_response(client.list_role_policies(**tool_input))
    elif (service, method) == ("iam", "get_role_policy"):
        client = session.client("iam")
        return _serialize_response(client.get_role_policy(**tool_input))
    elif (service, method) == ("iam", "get_user"):
        client = session.client("iam")
        return _serialize_response(client.get_user(**tool_input))
    elif (service, method) == ("iam", "list_users"):
        client = session.client("iam")
        return _serialize_response(client.list_users(**tool_input))
    elif (service, method) == ("iam", "list_attached_user_policies"):
        client = session.client("iam")
        return _serialize_response(client.list_attached_user_policies(**tool_input))
    elif (service, method) == ("iam", "list_groups_for_user"):
        client = session.client("iam")
        return _serialize_response(client.list_groups_for_user(**tool_input))
    elif (service, method) == ("iam", "get_instance_profile"):
        client = session.client("iam")
        return _serialize_response(client.get_instance_profile(**tool_input))

    # --- Route53 ---
    elif (service, method) == ("route53", "list_hosted_zones"):
        client = session.client("route53")
        return _serialize_response(client.list_hosted_zones(**tool_input))
    elif (service, method) == ("route53", "list_resource_record_sets"):
        client = session.client("route53")
        return _serialize_response(client.list_resource_record_sets(**tool_input))
    elif (service, method) == ("route53", "get_hosted_zone"):
        client = session.client("route53")
        return _serialize_response(client.get_hosted_zone(**tool_input))

    # --- CloudFront ---
    elif (service, method) == ("cloudfront", "get_distribution"):
        client = session.client("cloudfront")
        return _serialize_response(client.get_distribution(**tool_input))
    elif (service, method) == ("cloudfront", "list_distributions"):
        client = session.client("cloudfront")
        return _serialize_response(client.list_distributions(**tool_input))

    # --- DynamoDB ---
    elif (service, method) == ("dynamodb", "describe_table"):
        client = session.client("dynamodb")
        return _serialize_response(client.describe_table(**tool_input))
    elif (service, method) == ("dynamodb", "describe_continuous_backups"):
        client = session.client("dynamodb")
        return _serialize_response(client.describe_continuous_backups(**tool_input))
    elif (service, method) == ("dynamodb", "describe_time_to_live"):
        client = session.client("dynamodb")
        return _serialize_response(client.describe_time_to_live(**tool_input))
    elif (service, method) == ("dynamodb", "list_tags_of_resource"):
        client = session.client("dynamodb")
        return _serialize_response(client.list_tags_of_resource(**tool_input))

    # --- SQS ---
    elif (service, method) == ("sqs", "get_queue_attributes"):
        client = session.client("sqs")
        return _serialize_response(client.get_queue_attributes(**tool_input))
    elif (service, method) == ("sqs", "list_queues"):
        client = session.client("sqs")
        return _serialize_response(client.list_queues(**tool_input))

    # --- SNS ---
    elif (service, method) == ("sns", "get_topic_attributes"):
        client = session.client("sns")
        return _serialize_response(client.get_topic_attributes(**tool_input))
    elif (service, method) == ("sns", "list_subscriptions_by_topic"):
        client = session.client("sns")
        return _serialize_response(client.list_subscriptions_by_topic(**tool_input))

    # --- STS ---
    elif (service, method) == ("sts", "get_caller_identity"):
        client = session.client("sts")
        return _serialize_response(client.get_caller_identity(**tool_input))

    # --- CloudWatch ---
    elif (service, method) == ("cloudwatch", "get_metric_statistics"):
        client = session.client("cloudwatch")
        # Convert ISO strings to datetime for boto3
        from datetime import datetime as _dt, timezone as _tz
        inp = {**tool_input}
        for key in ("StartTime", "EndTime"):
            if isinstance(inp.get(key), str):
                inp[key] = _dt.fromisoformat(inp[key].replace("Z", "+00:00"))
        return _serialize_response(client.get_metric_statistics(**inp))
    elif (service, method) == ("cloudwatch", "list_metrics"):
        client = session.client("cloudwatch")
        return _serialize_response(client.list_metrics(**tool_input))
    elif (service, method) == ("cloudwatch", "describe_alarms"):
        client = session.client("cloudwatch")
        return _serialize_response(client.describe_alarms(**tool_input))

    # --- CloudWatch Logs ---
    elif (service, method) == ("logs", "describe_log_groups"):
        client = session.client("logs")
        return _serialize_response(client.describe_log_groups(**tool_input))
    elif (service, method) == ("logs", "filter_log_events"):
        client = session.client("logs")
        return _serialize_response(client.filter_log_events(**tool_input))

    # --- CloudTrail ---
    elif (service, method) == ("cloudtrail", "lookup_events"):
        client = session.client("cloudtrail")
        from datetime import datetime as _dt, timezone as _tz
        inp = {**tool_input}
        for key in ("StartTime", "EndTime"):
            if isinstance(inp.get(key), str):
                inp[key] = _dt.fromisoformat(inp[key].replace("Z", "+00:00"))
        return _serialize_response(client.lookup_events(**inp))

    else:
        raise ToolNotAllowedError(f"AWS operation not implemented: {service}.{method}")


# ---------------------------------------------------------------------------
# GCP execution — explicit dispatch
# ---------------------------------------------------------------------------

def _execute_gcp(service: str, method: str, tool_input: dict, project: str | None = None) -> str:
    """Execute a GCP API call through explicit if/elif dispatch."""
    _validate_gcp(service, method)

    # --- Compute: Instances ---
    if (service, method) == ("compute_instances", "get"):
        from google.cloud.compute_v1 import InstancesClient
        client = InstancesClient()
        result = client.get(**tool_input)
        return _serialize_response(result)
    elif (service, method) == ("compute_instances", "aggregated_list"):
        from google.cloud.compute_v1 import InstancesClient
        client = InstancesClient()
        result = client.aggregated_list(**tool_input)
        items = {}
        for zone, scoped in result:
            if scoped.instances:
                items[zone] = [_serialize_value(i) for i in scoped.instances]
        return _serialize_response(items)

    # --- Compute: Firewalls ---
    elif (service, method) == ("compute_firewalls", "list"):
        from google.cloud.compute_v1 import FirewallsClient
        client = FirewallsClient()
        result = client.list(**tool_input)
        return _serialize_response(list(result))
    elif (service, method) == ("compute_firewalls", "get"):
        from google.cloud.compute_v1 import FirewallsClient
        client = FirewallsClient()
        result = client.get(**tool_input)
        return _serialize_response(result)

    # --- Compute: Networks ---
    elif (service, method) == ("compute_networks", "list"):
        from google.cloud.compute_v1 import NetworksClient
        client = NetworksClient()
        result = client.list(**tool_input)
        return _serialize_response(list(result))
    elif (service, method) == ("compute_networks", "get"):
        from google.cloud.compute_v1 import NetworksClient
        client = NetworksClient()
        result = client.get(**tool_input)
        return _serialize_response(result)

    # --- Compute: Subnetworks ---
    elif (service, method) == ("compute_subnetworks", "list"):
        from google.cloud.compute_v1 import SubnetworksClient
        client = SubnetworksClient()
        result = client.list(**tool_input)
        return _serialize_response(list(result))
    elif (service, method) == ("compute_subnetworks", "aggregated_list"):
        from google.cloud.compute_v1 import SubnetworksClient
        client = SubnetworksClient()
        result = client.aggregated_list(**tool_input)
        items = {}
        for region, scoped in result:
            if scoped.subnetworks:
                items[region] = [_serialize_value(s) for s in scoped.subnetworks]
        return _serialize_response(items)

    # --- Compute: Addresses ---
    elif (service, method) == ("compute_addresses", "aggregated_list"):
        from google.cloud.compute_v1 import AddressesClient
        client = AddressesClient()
        result = client.aggregated_list(**tool_input)
        items = {}
        for region, scoped in result:
            if scoped.addresses:
                items[region] = [_serialize_value(a) for a in scoped.addresses]
        return _serialize_response(items)

    # --- Compute: Forwarding Rules ---
    elif (service, method) == ("compute_forwarding_rules", "aggregated_list"):
        from google.cloud.compute_v1 import ForwardingRulesClient
        client = ForwardingRulesClient()
        result = client.aggregated_list(**tool_input)
        items = {}
        for region, scoped in result:
            if scoped.forwarding_rules:
                items[region] = [_serialize_value(r) for r in scoped.forwarding_rules]
        return _serialize_response(items)

    # --- GKE ---
    elif (service, method) == ("container", "get_cluster"):
        from google.cloud.container_v1 import ClusterManagerClient
        client = ClusterManagerClient()
        result = client.get_cluster(**tool_input)
        return _serialize_response(result)
    elif (service, method) == ("container", "list_clusters"):
        from google.cloud.container_v1 import ClusterManagerClient
        client = ClusterManagerClient()
        result = client.list_clusters(**tool_input)
        return _serialize_response(result)
    elif (service, method) == ("container", "list_node_pools"):
        from google.cloud.container_v1 import ClusterManagerClient
        client = ClusterManagerClient()
        result = client.list_node_pools(**tool_input)
        return _serialize_response(result)

    # --- Cloud SQL ---
    elif (service, method) == ("sqladmin", "get"):
        from google.cloud.sql_v1 import SqlInstancesServiceClient
        client = SqlInstancesServiceClient()
        result = client.get(**tool_input)
        return _serialize_response(result)
    elif (service, method) == ("sqladmin", "list"):
        from google.cloud.sql_v1 import SqlInstancesServiceClient
        client = SqlInstancesServiceClient()
        result = client.list(**tool_input)
        return _serialize_response(result)

    # --- Storage ---
    elif (service, method) == ("storage", "get_bucket"):
        from google.cloud import storage
        client = storage.Client(project=project)
        bucket = client.get_bucket(tool_input["bucket_name"])
        return _serialize_response({
            "name": bucket.name,
            "location": bucket.location,
            "storage_class": bucket.storage_class,
            "versioning_enabled": bucket.versioning_enabled,
            "labels": dict(bucket.labels) if bucket.labels else {},
            "time_created": bucket.time_created,
        })
    elif (service, method) == ("storage", "list_buckets"):
        from google.cloud import storage
        client = storage.Client(project=project or tool_input.get("project"))
        buckets = list(client.list_buckets())
        return _serialize_response([
            {"name": b.name, "location": b.location, "storage_class": b.storage_class}
            for b in buckets
        ])
    elif (service, method) == ("storage", "get_bucket_iam_policy"):
        from google.cloud import storage
        client = storage.Client(project=project)
        bucket = client.get_bucket(tool_input["bucket_name"])
        policy = bucket.get_iam_policy()
        bindings = []
        for binding in policy.bindings:
            bindings.append({
                "role": binding["role"],
                "members": list(binding["members"]),
            })
        return _serialize_response({"bindings": bindings})

    # --- IAM ---
    elif (service, method) == ("iam", "get_iam_policy"):
        from google.cloud.resourcemanager_v3 import ProjectsClient
        client = ProjectsClient()
        result = client.get_iam_policy(resource=tool_input["resource"])
        return _serialize_response(result)
    elif (service, method) == ("iam", "get_service_account"):
        from google.cloud import iam_admin_v1
        client = iam_admin_v1.IAMClient()
        result = client.get_service_account(name=tool_input["name"])
        return _serialize_response(result)
    elif (service, method) == ("iam", "list_service_accounts"):
        from google.cloud import iam_admin_v1
        client = iam_admin_v1.IAMClient()
        result = client.list_service_accounts(name=tool_input["name"])
        return _serialize_response(list(result))
    elif (service, method) == ("iam", "list_service_account_keys"):
        from google.cloud import iam_admin_v1
        client = iam_admin_v1.IAMClient()
        result = client.list_service_account_keys(name=tool_input["name"])
        return _serialize_response(result)

    # --- Cloud Functions ---
    elif (service, method) == ("functions", "get_function"):
        from google.cloud.functions_v2 import FunctionServiceClient
        client = FunctionServiceClient()
        result = client.get_function(name=tool_input["name"])
        return _serialize_response(result)
    elif (service, method) == ("functions", "list_functions"):
        from google.cloud.functions_v2 import FunctionServiceClient
        client = FunctionServiceClient()
        result = client.list_functions(parent=tool_input["parent"])
        return _serialize_response(list(result))

    # --- Cloud Run ---
    elif (service, method) == ("run_services", "get_service"):
        from google.cloud.run_v2 import ServicesClient
        client = ServicesClient()
        result = client.get_service(name=tool_input["name"])
        return _serialize_response(result)
    elif (service, method) == ("run_services", "list_services"):
        from google.cloud.run_v2 import ServicesClient
        client = ServicesClient()
        result = client.list_services(parent=tool_input["parent"])
        return _serialize_response(list(result))
    elif (service, method) == ("run_revisions", "list_revisions"):
        from google.cloud.run_v2 import RevisionsClient
        client = RevisionsClient()
        result = client.list_revisions(parent=tool_input["parent"])
        return _serialize_response(list(result))

    # --- Cloud Monitoring ---
    elif (service, method) == ("monitoring", "list_time_series"):
        from google.cloud import monitoring_v3
        from google.protobuf.timestamp_pb2 import Timestamp
        client = monitoring_v3.MetricServiceClient()
        # Build the interval from the input
        interval_input = tool_input.get("interval", {})
        interval = monitoring_v3.TimeInterval()
        if "end_time" in interval_input:
            end_ts = Timestamp()
            end_ts.FromJsonString(interval_input["end_time"])
            interval.end_time = end_ts
        if "start_time" in interval_input:
            start_ts = Timestamp()
            start_ts.FromJsonString(interval_input["start_time"])
            interval.start_time = start_ts
        results = client.list_time_series(
            request={
                "name": tool_input["name"],
                "filter": tool_input["filter"],
                "interval": interval,
            }
        )
        return _serialize_response(list(results))

    # --- Cloud Logging ---
    elif (service, method) == ("logging", "list_entries"):
        from google.cloud import logging as gcp_logging
        from google.cloud.logging_v2 import LoggingServiceV2Client
        client = LoggingServiceV2Client()
        result = client.list_log_entries(
            resource_names=tool_input["resource_names"],
            filter_=tool_input.get("filter", ""),
            order_by=tool_input.get("order_by", "timestamp desc"),
            page_size=tool_input.get("page_size", 50),
        )
        entries = []
        for entry in result:
            entries.append(_serialize_value(entry))
            if len(entries) >= tool_input.get("page_size", 50):
                break
        return _serialize_response(entries)

    else:
        raise ToolNotAllowedError(f"GCP operation not implemented: {service}.{method}")


# ---------------------------------------------------------------------------
# Public execution API
# ---------------------------------------------------------------------------

def execute_tool(
    tool_name: str,
    tool_input: dict,
    aws_session_kwargs: dict | None = None,
    gcp_project: str | None = None,
) -> str:
    """Execute a tool call and return the serialized result string.

    On failure, returns a JSON error dict string (does not raise).
    """
    try:
        provider, service, method = _parse_tool_name(tool_name)

        if provider == "aws":
            return _execute_aws(service, method, tool_input, session_kwargs=aws_session_kwargs)
        elif provider == "gcp":
            return _execute_gcp(service, method, tool_input, project=gcp_project)
        else:
            return json.dumps({"error": f"Unknown provider: {provider}"})

    except ToolNotAllowedError as e:
        return json.dumps({"error": str(e)})
    except Exception as e:
        logger.warning("Tool execution error for %s: %s", tool_name, e)
        return json.dumps({"error": f"{type(e).__name__}: {e}"})
