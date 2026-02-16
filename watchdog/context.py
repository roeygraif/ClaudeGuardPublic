"""
Context gathering module for Cloud Watchdog.

Bridges the command parser and the Claude brain by querying the
infrastructure graph and assembling a rich context bundle that describes
the target resource, its connections, IAM/network specifics, and any
warnings about dangerous patterns.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Friendly resource-type labels
# ---------------------------------------------------------------------------

_TYPE_LABELS: Dict[str, str] = {
    "db_instance": "RDS Instance",
    "db_cluster": "RDS Cluster",
    "rds_instance": "RDS Instance",
    "rds_cluster": "RDS Cluster",
    "s3_bucket": "S3 Bucket",
    "bucket": "S3 Bucket",
    "lambda_function": "Lambda Function",
    "function": "Lambda Function",
    "ec2_instance": "EC2 Instance",
    "instance": "EC2 Instance",
    "security_group": "Security Group",
    "iam_role": "IAM Role",
    "role": "IAM Role",
    "iam_policy": "IAM Policy",
    "policy": "IAM Policy",
    "iam_user": "IAM User",
    "user": "IAM User",
    "load_balancer": "Load Balancer",
    "alb": "Application Load Balancer",
    "nlb": "Network Load Balancer",
    "ecs_service": "ECS Service",
    "ecs_cluster": "ECS Cluster",
    "dynamodb_table": "DynamoDB Table",
    "table": "DynamoDB Table",
    "sqs_queue": "SQS Queue",
    "queue": "SQS Queue",
    "sns_topic": "SNS Topic",
    "topic": "SNS Topic",
    "cloudfront_distribution": "CloudFront Distribution",
    "elasticache_cluster": "ElastiCache Cluster",
    "vpc": "VPC",
    "subnet": "Subnet",
    "nat_gateway": "NAT Gateway",
    "internet_gateway": "Internet Gateway",
}


def _friendly_type(resource_type: str | None) -> str:
    """Convert an internal resource_type slug to a human-friendly label."""
    if not resource_type:
        return "Unknown"
    return _TYPE_LABELS.get(resource_type.lower(), resource_type.replace("_", " ").title())


# ---------------------------------------------------------------------------
# IAM-related service detection
# ---------------------------------------------------------------------------

_IAM_SERVICES = frozenset({"iam", "sts"})

_SG_ACTIONS = frozenset({
    "authorize-security-group-ingress",
    "authorize-security-group-egress",
    "revoke-security-group-ingress",
    "revoke-security-group-egress",
    "create-security-group",
    "delete-security-group",
    "modify-security-group-rules",
    "update-security-group-rule-descriptions-ingress",
    "update-security-group-rule-descriptions-egress",
})


def _is_iam_command(parsed: Any) -> bool:
    """Return True if the parsed command targets IAM or STS."""
    service = getattr(parsed, "service", None) or ""
    return service.lower() in _IAM_SERVICES


def _is_security_group_command(parsed: Any) -> bool:
    """Return True if the parsed command targets security groups."""
    action = getattr(parsed, "action", None) or ""
    service = getattr(parsed, "service", None) or ""
    # Direct SG actions.
    if action.lower() in _SG_ACTIONS:
        return True
    # Check for security-group in flags or resource_id.
    resource_id = getattr(parsed, "resource_id", None) or ""
    if resource_id.startswith("sg-"):
        return True
    if service.lower() == "ec2" and "security-group" in action.lower():
        return True
    return False


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def gather_context(parsed: Any, db: Any) -> dict:
    """Assemble a rich context bundle for the Claude brain.

    Parameters
    ----------
    parsed:
        A ``ParsedCommand`` dataclass instance with attributes:
        ``provider``, ``service``, ``action``, ``action_type``,
        ``resource_id``, ``raw_command``, ``flags``, ``region``,
        ``profile``.
    db:
        A ``GraphDB`` instance providing ``find_resource``,
        ``get_connections``, ``get_dependents``, ``staleness_minutes``,
        and ``incremental_fetch``.

    Returns
    -------
    dict
        Context bundle consumed by the Claude brain.
    """
    warnings: List[str] = []
    target: Optional[Dict[str, Any]] = None
    connections: List[Dict[str, Any]] = []

    resource_id: str = getattr(parsed, "resource_id", None) or ""

    # ------------------------------------------------------------------
    # (d) Early exit for unresolved variables
    # ------------------------------------------------------------------
    if "$" in resource_id:
        warnings.append(
            "Command contains unresolved variables \u2014 cannot verify target"
        )
        target = None
    else:
        # ------------------------------------------------------------------
        # (a) Look up the target resource
        # ------------------------------------------------------------------
        if resource_id:
            target_record = db.find_resource(resource_id)
            logger.info(
                "find_resource(%s): %s",
                resource_id, "found" if target_record else "NOT FOUND",
            )

            # ------------------------------------------------------------------
            # (b) Incremental fetch on miss
            # ------------------------------------------------------------------
            if target_record is None:
                provider = getattr(parsed, "provider", None) or ""
                service = getattr(parsed, "service", None) or ""
                try:
                    db.incremental_fetch(provider, service, resource_id)
                except Exception:
                    logger.debug(
                        "incremental_fetch failed for %s/%s/%s",
                        provider, service, resource_id,
                        exc_info=True,
                    )
                target_record = db.find_resource(resource_id)
                logger.info(
                    "find_resource(%s) after incremental_fetch: %s",
                    resource_id, "found" if target_record else "still NOT FOUND",
                )

            # ------------------------------------------------------------------
            # (c) Still not found
            # ------------------------------------------------------------------
            if target_record is None:
                warnings.append(
                    "Target resource not found in infrastructure graph "
                    "\u2014 treating as high risk"
                )
            else:
                target = _build_target(target_record)
        # No resource_id at all — target stays None (no warning needed;
        # some commands like `aws sts get-caller-identity` have no target).

    # ------------------------------------------------------------------
    # (e) Connections
    # ------------------------------------------------------------------
    if target is not None:
        arn = target.get("arn", "")
        if arn:
            try:
                raw_connections = db.get_connections(arn, hops=2)
                connections = _build_connections(raw_connections)
                logger.info("get_connections(%s): %d connections", arn, len(connections))
            except Exception:
                logger.warning(
                    "get_connections failed for %s", arn, exc_info=True
                )

    # ------------------------------------------------------------------
    # (f) & (g) Service-specific context
    # ------------------------------------------------------------------
    iam_context = _extract_iam_context(parsed, target, connections, db)
    network_context = _extract_network_context(parsed, target, connections, db)
    if iam_context:
        logger.info("IAM context: role=%s, policies=%d", iam_context.get("role"), len(iam_context.get("current_policies") or []))
    if network_context:
        logger.info("Network context: sg=%s, rules=%d", network_context.get("security_group"), len(network_context.get("current_rules") or []))

    # ------------------------------------------------------------------
    # (h) & (i) Warnings
    # ------------------------------------------------------------------
    warnings.extend(_check_warnings(parsed, target, connections, db))
    if warnings:
        logger.info("Warnings (%d): %s", len(warnings), "; ".join(warnings[:3]))

    # ------------------------------------------------------------------
    # Assemble final context
    # ------------------------------------------------------------------
    raw_command = getattr(parsed, "raw_command", "") or ""
    action_type = getattr(parsed, "action_type", "") or ""

    context: Dict[str, Any] = {
        "command": raw_command,
        "action_type": action_type.upper() if action_type else "",
        "target": target,
        "connected_resources": connections,
        "iam_context": iam_context,
        "network_context": network_context,
        "warnings": warnings,
    }
    return context


# ---------------------------------------------------------------------------
# Target builder
# ---------------------------------------------------------------------------

def _build_target(record: dict) -> dict:
    """Transform a raw resource record from the graph into the target dict."""
    return {
        "arn": record.get("arn", ""),
        "type": _friendly_type(record.get("resource_type")),
        "name": record.get("name", ""),
        "environment": record.get("environment", "unknown"),
        "is_active": bool(record.get("is_active")),
        "activity": record.get("activity_summary") or "",
        "tags": record.get("tags") or {},
        "metadata": record.get("metadata") or {},
    }


# ---------------------------------------------------------------------------
# Connected-resources builder
# ---------------------------------------------------------------------------

def _build_connections(raw_connections: list[dict]) -> list[dict]:
    """Normalise a list of connection dicts from the graph."""
    results: list[dict] = []
    for conn in raw_connections:
        results.append({
            "arn": conn.get("arn", ""),
            "type": _friendly_type(conn.get("resource_type")),
            "relationship": conn.get("relationship", ""),
            "environment": conn.get("environment", "unknown"),
            "is_active": bool(conn.get("is_active")),
        })
    return results


# ---------------------------------------------------------------------------
# IAM context helper
# ---------------------------------------------------------------------------

def _extract_iam_context(
    parsed: Any,
    target: Optional[dict],
    connections: list[dict],
    db: Any,
) -> Optional[dict]:
    """Build IAM-specific context if the command is IAM-related.

    Returns None when the command does not involve IAM.
    """
    if not _is_iam_command(parsed):
        return None

    action = getattr(parsed, "action", "") or ""
    flags = getattr(parsed, "flags", {}) or {}

    role_name: str = ""
    current_policies: list[dict] = []
    resources_using_role: list[dict] = []
    policy_being_attached: Optional[dict] = None

    # Determine the role name from the target or flags.
    if target:
        role_name = target.get("name", "")
    else:
        # Try to extract from flags.
        role_name = (
            flags.get("--role-name", "")
            or flags.get("--role", "")
            or flags.get("role-name", "")
            or getattr(parsed, "resource_id", "") or ""
        )

    # Gather connected IAM policies and resources using the role.
    for conn in connections:
        conn_type = (conn.get("type") or "").lower()
        relationship = (conn.get("relationship") or "").lower()

        if "policy" in conn_type:
            current_policies.append(conn)
        elif relationship in ("assumes", "uses", "attached_to", "connects_to"):
            resources_using_role.append(conn)

    # If the action is about attaching a policy, parse the policy ARN from flags.
    if "attach" in action.lower() and "policy" in action.lower():
        policy_arn = flags.get("--policy-arn", "") or flags.get("policy-arn", "")
        if policy_arn:
            policy_record = db.find_resource(policy_arn)
            if policy_record:
                policy_being_attached = {
                    "arn": policy_record.get("arn", ""),
                    "name": policy_record.get("name", ""),
                    "type": _friendly_type(policy_record.get("resource_type")),
                    "metadata": policy_record.get("metadata") or {},
                }
            else:
                policy_being_attached = {
                    "arn": policy_arn,
                    "name": policy_arn.rsplit("/", 1)[-1] if "/" in policy_arn else policy_arn,
                    "type": "IAM Policy",
                    "metadata": {},
                }

    # If the action is about detaching a policy, also note it.
    if "detach" in action.lower() and "policy" in action.lower():
        policy_arn = flags.get("--policy-arn", "") or flags.get("policy-arn", "")
        if policy_arn:
            policy_record = db.find_resource(policy_arn)
            if policy_record:
                policy_being_attached = {
                    "arn": policy_record.get("arn", ""),
                    "name": policy_record.get("name", ""),
                    "type": _friendly_type(policy_record.get("resource_type")),
                    "metadata": policy_record.get("metadata") or {},
                }
            else:
                policy_being_attached = {
                    "arn": policy_arn,
                    "name": policy_arn.rsplit("/", 1)[-1] if "/" in policy_arn else policy_arn,
                    "type": "IAM Policy",
                    "metadata": {},
                }

    return {
        "role": role_name,
        "current_policies": current_policies,
        "resources_using_role": resources_using_role,
        "policy_being_attached": policy_being_attached,
    }


# ---------------------------------------------------------------------------
# Network / Security Group context helper
# ---------------------------------------------------------------------------

def _extract_network_context(
    parsed: Any,
    target: Optional[dict],
    connections: list[dict],
    db: Any,
) -> Optional[dict]:
    """Build network / security-group context if the command involves SGs.

    Returns None when the command does not involve security groups.
    """
    if not _is_security_group_command(parsed):
        return None

    flags = getattr(parsed, "flags", {}) or {}
    action = getattr(parsed, "action", "") or ""

    sg_id: str = ""
    current_rules: list[dict] = []
    attached_resources: list[dict] = []
    rule_being_added: Optional[dict] = None

    # Determine security group ID.
    if target:
        sg_id = target.get("name", "") or target.get("arn", "")
    else:
        sg_id = (
            flags.get("--group-id", "")
            or flags.get("group-id", "")
            or getattr(parsed, "resource_id", "") or ""
        )

    # Collect attached resources and existing rules from connections.
    for conn in connections:
        conn_type = (conn.get("type") or "").lower()
        relationship = (conn.get("relationship") or "").lower()

        if "rule" in conn_type or "rule" in relationship:
            current_rules.append(conn)
        else:
            attached_resources.append(conn)

    # If the target itself is in the graph and has metadata with rules,
    # pull them into current_rules.
    if target and target.get("metadata"):
        meta = target["metadata"]
        if isinstance(meta, dict):
            for key in ("inbound_rules", "ingress_rules", "inbound", "ingress"):
                if key in meta and isinstance(meta[key], list):
                    for rule in meta[key]:
                        current_rules.append(rule)
            for key in ("outbound_rules", "egress_rules", "outbound", "egress"):
                if key in meta and isinstance(meta[key], list):
                    for rule in meta[key]:
                        current_rules.append(rule)

    # Parse the rule being added from flags if the action is an authorize.
    if "authorize" in action.lower():
        rule_being_added = _parse_sg_rule_from_flags(flags)

    return {
        "security_group": sg_id,
        "current_rules": current_rules,
        "attached_resources": attached_resources,
        "rule_being_added": rule_being_added,
    }


def _parse_sg_rule_from_flags(flags: dict) -> Optional[dict]:
    """Best-effort parse of a security-group rule from CLI flags."""
    rule: Dict[str, Any] = {}

    # Protocol
    protocol = (
        flags.get("--protocol", "")
        or flags.get("--ip-protocol", "")
        or flags.get("protocol", "")
        or flags.get("ip-protocol", "")
    )
    if protocol:
        rule["protocol"] = protocol

    # Port / port range
    port = (
        flags.get("--port", "")
        or flags.get("--from-port", "")
        or flags.get("port", "")
        or flags.get("from-port", "")
    )
    if port:
        rule["port"] = port

    to_port = flags.get("--to-port", "") or flags.get("to-port", "")
    if to_port:
        rule["to_port"] = to_port

    # CIDR
    cidr = (
        flags.get("--cidr", "")
        or flags.get("--cidr-ip", "")
        or flags.get("cidr", "")
        or flags.get("cidr-ip", "")
    )
    if cidr:
        rule["cidr"] = cidr

    # Source group
    source_group = (
        flags.get("--source-group", "")
        or flags.get("--group-id", "")
        or flags.get("source-group", "")
    )
    if source_group:
        rule["source_group"] = source_group

    # ip-permissions (AWS JSON blob)
    ip_permissions = flags.get("--ip-permissions", "") or flags.get("ip-permissions", "")
    if ip_permissions:
        rule["ip_permissions_raw"] = ip_permissions

    return rule if rule else None


# ---------------------------------------------------------------------------
# Warnings checker
# ---------------------------------------------------------------------------

def _check_warnings(
    parsed: Any,
    target: Optional[dict],
    connections: list[dict],
    db: Any,
) -> List[str]:
    """Detect dangerous patterns and return a list of warning strings."""
    warnings: List[str] = []
    action_type = (getattr(parsed, "action_type", "") or "").upper()
    service = (getattr(parsed, "service", "") or "").lower()
    action = (getattr(parsed, "action", "") or "").lower()
    flags = getattr(parsed, "flags", {}) or {}

    # ------------------------------------------------------------------
    # Staleness check
    # ------------------------------------------------------------------
    try:
        staleness = db.staleness_minutes()
        if staleness > 60:
            hours = staleness / 60
            if hours >= 1:
                warnings.append(
                    f"Infrastructure snapshot is {int(hours)} hours old"
                )
            else:
                warnings.append(
                    f"Infrastructure snapshot is {staleness} minutes old"
                )
        elif staleness < 0:
            warnings.append(
                "No infrastructure scan has been recorded \u2014 "
                "context may be incomplete"
            )
    except Exception:
        logger.debug("staleness_minutes() failed", exc_info=True)

    # ------------------------------------------------------------------
    # RDS deletion with no replica
    # ------------------------------------------------------------------
    if (
        action_type == "DELETE"
        and service == "rds"
        and target is not None
    ):
        has_replica = False
        for conn in connections:
            rel = (conn.get("relationship") or "").lower()
            conn_type = (conn.get("type") or "").lower()
            if "replica" in rel or "replica" in conn_type:
                has_replica = True
                break
        if not has_replica:
            warnings.append(
                "No read replica exists for this RDS instance"
            )

    # ------------------------------------------------------------------
    # DynamoDB table deletion
    # ------------------------------------------------------------------
    if action_type == "DELETE" and service == "dynamodb" and target is not None:
        meta = target.get("metadata") or {}
        if isinstance(meta, dict):
            if not meta.get("pitr_enabled"):
                warnings.append(
                    "Point-in-time recovery (PITR) is disabled — "
                    "data may be unrecoverable after deletion"
                )
            item_count = meta.get("item_count", 0)
            if isinstance(item_count, (int, float)) and item_count > 0:
                warnings.append(
                    f"{int(item_count):,} items will be permanently deleted"
                )

    # ------------------------------------------------------------------
    # S3 bucket deletion
    # ------------------------------------------------------------------
    if action_type == "DELETE" and service == "s3":
        warnings.append(
            "Deleting an S3 bucket is irreversible and will destroy all "
            "data within it"
        )

    # ------------------------------------------------------------------
    # IAM policy with wildcard resources
    # ------------------------------------------------------------------
    if _is_iam_command(parsed):
        # Check the policy being manipulated for wildcard resources.
        _check_iam_wildcard_warnings(flags, warnings)

        # If we have target metadata, check for existing wildcard policies.
        if target and target.get("metadata"):
            meta = target["metadata"]
            if isinstance(meta, dict):
                policy_doc = meta.get("policy_document") or meta.get("document") or {}
                if isinstance(policy_doc, dict):
                    _scan_policy_document_for_wildcards(policy_doc, warnings)

    # ------------------------------------------------------------------
    # Security group opening 0.0.0.0/0
    # ------------------------------------------------------------------
    if _is_security_group_command(parsed):
        cidr = (
            flags.get("--cidr", "")
            or flags.get("--cidr-ip", "")
            or flags.get("cidr", "")
            or flags.get("cidr-ip", "")
            or ""
        )
        if cidr in ("0.0.0.0/0", "::/0"):
            warnings.append(
                "Security group rule opens access to the entire internet "
                f"({cidr})"
            )

        # Check ip-permissions for 0.0.0.0/0 as a string heuristic.
        ip_perms = flags.get("--ip-permissions", "") or flags.get("ip-permissions", "")
        if isinstance(ip_perms, str) and "0.0.0.0/0" in ip_perms:
            # Only add if not already warned above.
            internet_warning = (
                "Security group rule opens access to the entire internet "
                "(0.0.0.0/0)"
            )
            if internet_warning not in warnings:
                warnings.append(internet_warning)

    # ------------------------------------------------------------------
    # DELETE on production resources
    # ------------------------------------------------------------------
    if action_type == "DELETE" and target is not None:
        env = (target.get("environment") or "").lower()
        if env in ("prod", "production"):
            warnings.append(
                "This is a DELETE operation on a production resource"
            )

    # ------------------------------------------------------------------
    # Active resource deletion
    # ------------------------------------------------------------------
    if (
        action_type == "DELETE"
        and target is not None
        and target.get("is_active")
        and target.get("activity")
    ):
        warnings.append(
            f"Resource is actively in use: {target['activity']}"
        )

    return warnings


def _check_iam_wildcard_warnings(flags: dict, warnings: List[str]) -> None:
    """Check CLI flags for IAM policies with wildcard resource specifications."""
    # Policy document may be passed directly as a flag value.
    for key in ("--policy-document", "policy-document", "--policy"):
        doc = flags.get(key, "")
        if isinstance(doc, str) and '"Resource": "*"' in doc:
            warnings.append(
                "IAM policy grants access to all resources (Resource: *)"
            )
            return
        if isinstance(doc, str) and '"Resource":"*"' in doc:
            warnings.append(
                "IAM policy grants access to all resources (Resource: *)"
            )
            return
        if isinstance(doc, dict):
            _scan_policy_document_for_wildcards(doc, warnings)
            return


def _scan_policy_document_for_wildcards(
    policy_doc: dict, warnings: List[str]
) -> None:
    """Scan an IAM policy document dict for wildcard Resource entries."""
    statements = policy_doc.get("Statement") or policy_doc.get("statement") or []
    if isinstance(statements, dict):
        statements = [statements]
    for stmt in statements:
        if not isinstance(stmt, dict):
            continue
        resource = stmt.get("Resource") or stmt.get("resource")
        if resource == "*":
            wildcard_warning = (
                "IAM policy grants access to all resources (Resource: *)"
            )
            if wildcard_warning not in warnings:
                warnings.append(wildcard_warning)
            return
        if isinstance(resource, list) and "*" in resource:
            wildcard_warning = (
                "IAM policy grants access to all resources (Resource: *)"
            )
            if wildcard_warning not in warnings:
                warnings.append(wildcard_warning)
            return
