"""
AWS resource discovery scanner.

Discovers cloud resources across AWS services using boto3 and upserts them
into the local infrastructure graph (GraphDB).  Every boto3 API call in this
module is a hardcoded, literal, read-only method invocation -- no dynamic
dispatch, no getattr, no interpolated method names.
"""

from __future__ import annotations

import json
import logging
import urllib.parse
from typing import Any

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from scanner.graph import GraphDB, classify_environment

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get_account_id(session: boto3.Session) -> str:
    """Return the AWS account ID via STS (hardcoded call)."""
    sts = session.client("sts")
    identity = sts.get_caller_identity()  # HARDCODED read-only
    return identity["Account"]


def _build_arn(
    service: str,
    region: str,
    account: str,
    resource_type: str,
    resource_id: str,
) -> str:
    """Build a well-formed ARN string."""
    # Some services use : separator, others use /.  We default to /.
    return f"arn:aws:{service}:{region}:{account}:{resource_type}/{resource_id}"


# ---------------------------------------------------------------------------
# scan_ec2
# ---------------------------------------------------------------------------

def scan_ec2(session: boto3.Session, db: GraphDB, region: str, account: str) -> None:
    """Discover EC2 instances and their relationships."""
    try:
        ec2 = session.client("ec2", region_name=region)
        paginator_token: str | None = None

        while True:
            if paginator_token:
                response = ec2.describe_instances(NextToken=paginator_token)  # HARDCODED
            else:
                response = ec2.describe_instances()  # HARDCODED

            for reservation in response.get("Reservations", []):
                for instance in reservation.get("Instances", []):
                    instance_id = instance["InstanceId"]
                    tags = {
                        t["Key"]: t["Value"]
                        for t in instance.get("Tags", [])
                    }
                    name = tags.get("Name", instance_id)
                    arn = _build_arn("ec2", region, account, "instance", instance_id)
                    env = classify_environment(tags, name)

                    db.upsert_resource({
                        "arn": arn,
                        "provider": "aws",
                        "service": "ec2",
                        "resource_type": "Instance",
                        "name": name,
                        "region": region,
                        "account_or_project": account,
                        "environment": env,
                        "tags": tags,
                        "metadata": {
                            "instance_id": instance_id,
                            "instance_type": instance.get("InstanceType"),
                            "state": instance.get("State", {}).get("Name"),
                            "launch_time": str(instance.get("LaunchTime", "")),
                            "private_ip": instance.get("PrivateIpAddress"),
                            "public_ip": instance.get("PublicIpAddress"),
                            "ami_id": instance.get("ImageId"),
                            "key_name": instance.get("KeyName"),
                            "platform": instance.get("Platform", "linux"),
                        },
                    })

                    # Relationship: instance -> security groups
                    for sg in instance.get("SecurityGroups", []):
                        sg_id = sg["GroupId"]
                        sg_arn = _build_arn("ec2", region, account, "security-group", sg_id)
                        db.upsert_relationship(arn, sg_arn, "attached_to")

                    # Relationship: instance -> VPC
                    vpc_id = instance.get("VpcId")
                    if vpc_id:
                        vpc_arn = _build_arn("ec2", region, account, "vpc", vpc_id)
                        db.upsert_relationship(arn, vpc_arn, "resides_in")

                    # Relationship: instance -> Subnet
                    subnet_id = instance.get("SubnetId")
                    if subnet_id:
                        subnet_arn = _build_arn("ec2", region, account, "subnet", subnet_id)
                        db.upsert_relationship(arn, subnet_arn, "resides_in")

                    # Relationship: instance -> IAM Instance Profile
                    iam_profile = instance.get("IamInstanceProfile")
                    if iam_profile:
                        profile_arn = iam_profile.get("Arn", "")
                        if profile_arn:
                            db.upsert_relationship(arn, profile_arn, "assumes")

            paginator_token = response.get("NextToken")
            if not paginator_token:
                break

        logger.info("scan_ec2 completed for region %s", region)

    except (ClientError, BotoCoreError) as exc:
        logger.warning("scan_ec2 failed for region %s: %s", region, exc)


# ---------------------------------------------------------------------------
# scan_security_groups
# ---------------------------------------------------------------------------

def scan_security_groups(
    session: boto3.Session, db: GraphDB, region: str, account: str,
) -> None:
    """Discover security groups with ingress/egress rules."""
    try:
        ec2 = session.client("ec2", region_name=region)
        paginator_token: str | None = None

        while True:
            if paginator_token:
                response = ec2.describe_security_groups(NextToken=paginator_token)  # HARDCODED
            else:
                response = ec2.describe_security_groups()  # HARDCODED

            for sg in response.get("SecurityGroups", []):
                sg_id = sg["GroupId"]
                name = sg.get("GroupName", sg_id)
                tags = {
                    t["Key"]: t["Value"]
                    for t in sg.get("Tags", [])
                }
                arn = _build_arn("ec2", region, account, "security-group", sg_id)
                env = classify_environment(tags, name)

                db.upsert_resource({
                    "arn": arn,
                    "provider": "aws",
                    "service": "ec2",
                    "resource_type": "SecurityGroup",
                    "name": name,
                    "region": region,
                    "account_or_project": account,
                    "environment": env,
                    "tags": tags,
                    "metadata": {
                        "group_id": sg_id,
                        "description": sg.get("Description"),
                        "ingress_rules": sg.get("IpPermissions", []),
                        "egress_rules": sg.get("IpPermissionsEgress", []),
                    },
                })

                # Relationship: SG -> VPC
                vpc_id = sg.get("VpcId")
                if vpc_id:
                    vpc_arn = _build_arn("ec2", region, account, "vpc", vpc_id)
                    db.upsert_relationship(arn, vpc_arn, "resides_in")

            paginator_token = response.get("NextToken")
            if not paginator_token:
                break

        logger.info("scan_security_groups completed for region %s", region)

    except (ClientError, BotoCoreError) as exc:
        logger.warning("scan_security_groups failed for region %s: %s", region, exc)


# ---------------------------------------------------------------------------
# scan_rds
# ---------------------------------------------------------------------------

def scan_rds(
    session: boto3.Session, db: GraphDB, region: str, account: str,
) -> None:
    """Discover RDS database instances."""
    try:
        rds = session.client("rds", region_name=region)
        marker: str | None = None

        while True:
            if marker:
                response = rds.describe_db_instances(Marker=marker)  # HARDCODED
            else:
                response = rds.describe_db_instances()  # HARDCODED

            for db_inst in response.get("DBInstances", []):
                db_id = db_inst["DBInstanceIdentifier"]
                arn = db_inst.get(
                    "DBInstanceArn",
                    _build_arn("rds", region, account, "db", db_id),
                )
                tags_list = db_inst.get("TagList", [])
                tags = {t["Key"]: t["Value"] for t in tags_list}
                name = tags.get("Name", db_id)
                env = classify_environment(tags, name)

                db.upsert_resource({
                    "arn": arn,
                    "provider": "aws",
                    "service": "rds",
                    "resource_type": "DBInstance",
                    "name": name,
                    "region": region,
                    "account_or_project": account,
                    "environment": env,
                    "tags": tags,
                    "metadata": {
                        "db_instance_id": db_id,
                        "engine": db_inst.get("Engine"),
                        "engine_version": db_inst.get("EngineVersion"),
                        "instance_class": db_inst.get("DBInstanceClass"),
                        "status": db_inst.get("DBInstanceStatus"),
                        "multi_az": db_inst.get("MultiAZ"),
                        "storage_encrypted": db_inst.get("StorageEncrypted"),
                        "endpoint": db_inst.get("Endpoint", {}).get("Address"),
                        "port": db_inst.get("Endpoint", {}).get("Port"),
                        "publicly_accessible": db_inst.get("PubliclyAccessible"),
                    },
                })

                # Relationship: RDS -> Security Groups
                for sg in db_inst.get("VpcSecurityGroups", []):
                    sg_id = sg.get("VpcSecurityGroupId")
                    if sg_id:
                        sg_arn = _build_arn(
                            "ec2", region, account, "security-group", sg_id,
                        )
                        db.upsert_relationship(arn, sg_arn, "attached_to")

                # Relationship: RDS -> DB Subnet Group
                subnet_group = db_inst.get("DBSubnetGroup")
                if subnet_group:
                    sg_name = subnet_group.get("DBSubnetGroupName", "")
                    if sg_name:
                        sg_arn = _build_arn(
                            "rds", region, account, "subgrp", sg_name,
                        )
                        db.upsert_relationship(arn, sg_arn, "resides_in")

                # Relationship: RDS -> Read Replicas
                for replica_id in db_inst.get("ReadReplicaDBInstanceIdentifiers", []):
                    replica_arn = _build_arn("rds", region, account, "db", replica_id)
                    db.upsert_relationship(arn, replica_arn, "replicates_to")

                # Relationship: RDS -> Source (if this is a replica)
                source_id = db_inst.get("ReadReplicaSourceDBInstanceIdentifier")
                if source_id:
                    source_arn = _build_arn("rds", region, account, "db", source_id)
                    db.upsert_relationship(arn, source_arn, "replica_of")

            marker = response.get("Marker")
            if not marker:
                break

        logger.info("scan_rds completed for region %s", region)

    except (ClientError, BotoCoreError) as exc:
        logger.warning("scan_rds failed for region %s: %s", region, exc)


# ---------------------------------------------------------------------------
# scan_s3
# ---------------------------------------------------------------------------

def scan_s3(
    session: boto3.Session, db: GraphDB, region: str, account: str,
) -> None:
    """Discover S3 buckets and their policies."""
    try:
        s3 = session.client("s3", region_name=region)
        response = s3.list_buckets()  # HARDCODED

        for bucket in response.get("Buckets", []):
            bucket_name = bucket["Name"]
            arn = f"arn:aws:s3:::{bucket_name}"
            env = classify_environment(None, bucket_name)

            metadata: dict[str, Any] = {
                "bucket_name": bucket_name,
                "creation_date": str(bucket.get("CreationDate", "")),
            }

            # Try to fetch the bucket policy (may not exist / permission denied)
            policy_document = None
            try:
                policy_resp = s3.get_bucket_policy(Bucket=bucket_name)  # HARDCODED
                policy_str = policy_resp.get("Policy", "{}")
                policy_document = json.loads(policy_str)
                metadata["policy"] = policy_document
            except (ClientError, BotoCoreError):
                # No policy or no permission -- that is fine.
                pass

            db.upsert_resource({
                "arn": arn,
                "provider": "aws",
                "service": "s3",
                "resource_type": "Bucket",
                "name": bucket_name,
                "region": "global",
                "account_or_project": account,
                "environment": env,
                "tags": {},
                "metadata": metadata,
            })

            # Relationships: extract IAM principals from bucket policy
            if policy_document:
                for statement in policy_document.get("Statement", []):
                    principal = statement.get("Principal", {})
                    principals: list[str] = []
                    if isinstance(principal, str):
                        principals.append(principal)
                    elif isinstance(principal, dict):
                        for _key, val in principal.items():
                            if isinstance(val, str):
                                principals.append(val)
                            elif isinstance(val, list):
                                principals.extend(val)

                    for p in principals:
                        if p == "*":
                            continue
                        # Only record ARN-like principals
                        if p.startswith("arn:"):
                            db.upsert_relationship(p, arn, "has_access_to")

        logger.info("scan_s3 completed")

    except (ClientError, BotoCoreError) as exc:
        logger.warning("scan_s3 failed: %s", exc)


# ---------------------------------------------------------------------------
# scan_lambda
# ---------------------------------------------------------------------------

def scan_lambda(
    session: boto3.Session, db: GraphDB, region: str, account: str,
) -> None:
    """Discover Lambda functions."""
    try:
        lambda_ = session.client("lambda", region_name=region)
        marker: str | None = None

        while True:
            if marker:
                response = lambda_.list_functions(Marker=marker)  # HARDCODED
            else:
                response = lambda_.list_functions()  # HARDCODED

            for func in response.get("Functions", []):
                func_name = func["FunctionName"]
                arn = func.get(
                    "FunctionArn",
                    _build_arn("lambda", region, account, "function", func_name),
                )
                env = classify_environment(None, func_name)

                env_vars = func.get("Environment", {}).get("Variables", {})
                # Redact env var values for security -- only store keys.
                env_var_keys = list(env_vars.keys())

                db.upsert_resource({
                    "arn": arn,
                    "provider": "aws",
                    "service": "lambda",
                    "resource_type": "Function",
                    "name": func_name,
                    "region": region,
                    "account_or_project": account,
                    "environment": env,
                    "tags": {},
                    "metadata": {
                        "function_name": func_name,
                        "runtime": func.get("Runtime"),
                        "handler": func.get("Handler"),
                        "memory_size": func.get("MemorySize"),
                        "timeout": func.get("Timeout"),
                        "last_modified": func.get("LastModified"),
                        "code_size": func.get("CodeSize"),
                        "env_var_keys": env_var_keys,
                    },
                })

                # Relationship: Lambda -> IAM Role
                role_arn = func.get("Role")
                if role_arn:
                    db.upsert_relationship(arn, role_arn, "assumes")

                # Relationship: Lambda -> VPC / Security Groups
                vpc_config = func.get("VpcConfig", {})
                vpc_id = vpc_config.get("VpcId")
                if vpc_id:
                    vpc_arn = _build_arn("ec2", region, account, "vpc", vpc_id)
                    db.upsert_relationship(arn, vpc_arn, "resides_in")

                for sg_id in vpc_config.get("SecurityGroupIds", []):
                    sg_arn = _build_arn(
                        "ec2", region, account, "security-group", sg_id,
                    )
                    db.upsert_relationship(arn, sg_arn, "attached_to")

                for subnet_id in vpc_config.get("SubnetIds", []):
                    subnet_arn = _build_arn(
                        "ec2", region, account, "subnet", subnet_id,
                    )
                    db.upsert_relationship(arn, subnet_arn, "resides_in")

            marker = response.get("NextMarker")
            if not marker:
                break

        logger.info("scan_lambda completed for region %s", region)

    except (ClientError, BotoCoreError) as exc:
        logger.warning("scan_lambda failed for region %s: %s", region, exc)


# ---------------------------------------------------------------------------
# scan_iam_roles
# ---------------------------------------------------------------------------

def scan_iam_roles(
    session: boto3.Session, db: GraphDB, account: str,
) -> None:
    """Discover IAM roles and their attached policies."""
    try:
        iam = session.client("iam")
        marker: str | None = None

        while True:
            if marker:
                response = iam.list_roles(Marker=marker)  # HARDCODED
            else:
                response = iam.list_roles()  # HARDCODED

            for role in response.get("Roles", []):
                role_name = role["RoleName"]
                arn = role.get(
                    "Arn",
                    f"arn:aws:iam::{account}:role/{role_name}",
                )
                tags = {
                    t["Key"]: t["Value"]
                    for t in role.get("Tags", [])
                }
                env = classify_environment(tags, role_name)

                assume_role_doc = role.get("AssumeRolePolicyDocument")
                if isinstance(assume_role_doc, str):
                    assume_role_doc = json.loads(
                        urllib.parse.unquote(assume_role_doc)
                    )

                db.upsert_resource({
                    "arn": arn,
                    "provider": "aws",
                    "service": "iam",
                    "resource_type": "Role",
                    "name": role_name,
                    "region": "global",
                    "account_or_project": account,
                    "environment": env,
                    "tags": tags,
                    "metadata": {
                        "role_name": role_name,
                        "role_id": role.get("RoleId"),
                        "path": role.get("Path"),
                        "create_date": str(role.get("CreateDate", "")),
                        "max_session_duration": role.get("MaxSessionDuration"),
                        "assume_role_policy": assume_role_doc,
                    },
                })

                # Discover attached policies for this role
                try:
                    policy_marker: str | None = None
                    while True:
                        if policy_marker:
                            pol_resp = iam.list_attached_role_policies(
                                RoleName=role_name, Marker=policy_marker,
                            )  # HARDCODED
                        else:
                            pol_resp = iam.list_attached_role_policies(
                                RoleName=role_name,
                            )  # HARDCODED

                        for policy in pol_resp.get("AttachedPolicies", []):
                            policy_arn = policy.get("PolicyArn", "")
                            if policy_arn:
                                db.upsert_relationship(
                                    arn, policy_arn, "attached_policy",
                                )

                        if not pol_resp.get("IsTruncated", False):
                            break
                        policy_marker = pol_resp.get("Marker")
                        if not policy_marker:
                            break

                except (ClientError, BotoCoreError) as pol_exc:
                    logger.warning(
                        "Failed to list attached policies for role %s: %s",
                        role_name, pol_exc,
                    )

            if not response.get("IsTruncated", False):
                break
            marker = response.get("Marker")
            if not marker:
                break

        logger.info("scan_iam_roles completed")

    except (ClientError, BotoCoreError) as exc:
        logger.warning("scan_iam_roles failed: %s", exc)


# ---------------------------------------------------------------------------
# scan_iam_policies
# ---------------------------------------------------------------------------

def scan_iam_policies(
    session: boto3.Session, db: GraphDB, account: str,
) -> None:
    """Discover customer-managed IAM policies."""
    try:
        iam = session.client("iam")
        marker: str | None = None

        while True:
            if marker:
                response = iam.list_policies(Scope="Local", Marker=marker)  # HARDCODED
            else:
                response = iam.list_policies(Scope="Local")  # HARDCODED

            for policy in response.get("Policies", []):
                policy_name = policy["PolicyName"]
                arn = policy.get(
                    "Arn",
                    f"arn:aws:iam::{account}:policy/{policy_name}",
                )
                env = classify_environment(None, policy_name)

                metadata: dict[str, Any] = {
                    "policy_name": policy_name,
                    "policy_id": policy.get("PolicyId"),
                    "path": policy.get("Path"),
                    "default_version_id": policy.get("DefaultVersionId"),
                    "attachment_count": policy.get("AttachmentCount"),
                    "create_date": str(policy.get("CreateDate", "")),
                    "update_date": str(policy.get("UpdateDate", "")),
                }

                # Fetch the policy document for the default version
                version_id = policy.get("DefaultVersionId")
                policy_document = None
                if version_id:
                    try:
                        ver_resp = iam.get_policy_version(
                            PolicyArn=arn, VersionId=version_id,
                        )  # HARDCODED
                        policy_document = ver_resp.get(
                            "PolicyVersion", {},
                        ).get("Document")
                        if isinstance(policy_document, str):
                            policy_document = json.loads(
                                urllib.parse.unquote(policy_document)
                            )
                        metadata["document"] = policy_document
                    except (ClientError, BotoCoreError) as ver_exc:
                        logger.warning(
                            "Failed to get policy version for %s: %s",
                            policy_name, ver_exc,
                        )

                db.upsert_resource({
                    "arn": arn,
                    "provider": "aws",
                    "service": "iam",
                    "resource_type": "Policy",
                    "name": policy_name,
                    "region": "global",
                    "account_or_project": account,
                    "environment": env,
                    "tags": {},
                    "metadata": metadata,
                })

                # Relationships: policy -> resources referenced in policy
                if policy_document:
                    for statement in policy_document.get("Statement", []):
                        resources = statement.get("Resource", [])
                        if isinstance(resources, str):
                            resources = [resources]
                        for res in resources:
                            if res == "*":
                                continue
                            if res.startswith("arn:"):
                                db.upsert_relationship(
                                    arn, res, "grants_access_to",
                                )

            if not response.get("IsTruncated", False):
                break
            marker = response.get("Marker")
            if not marker:
                break

        logger.info("scan_iam_policies completed")

    except (ClientError, BotoCoreError) as exc:
        logger.warning("scan_iam_policies failed: %s", exc)


# ---------------------------------------------------------------------------
# scan_ecs
# ---------------------------------------------------------------------------

def scan_ecs(
    session: boto3.Session, db: GraphDB, region: str, account: str,
) -> None:
    """Discover ECS clusters and services."""
    try:
        ecs = session.client("ecs", region_name=region)

        # List clusters (paginated)
        cluster_arns: list[str] = []
        next_token: str | None = None

        while True:
            if next_token:
                resp = ecs.list_clusters(nextToken=next_token)  # HARDCODED
            else:
                resp = ecs.list_clusters()  # HARDCODED

            cluster_arns.extend(resp.get("clusterArns", []))
            next_token = resp.get("nextToken")
            if not next_token:
                break

        for cluster_arn in cluster_arns:
            cluster_name = cluster_arn.rsplit("/", 1)[-1]
            env = classify_environment(None, cluster_name)

            db.upsert_resource({
                "arn": cluster_arn,
                "provider": "aws",
                "service": "ecs",
                "resource_type": "Cluster",
                "name": cluster_name,
                "region": region,
                "account_or_project": account,
                "environment": env,
                "tags": {},
                "metadata": {"cluster_name": cluster_name},
            })

            # List services in cluster (paginated)
            service_arns: list[str] = []
            svc_token: str | None = None

            while True:
                if svc_token:
                    svc_resp = ecs.list_services(
                        cluster=cluster_arn, nextToken=svc_token,
                    )  # HARDCODED
                else:
                    svc_resp = ecs.list_services(
                        cluster=cluster_arn,
                    )  # HARDCODED

                service_arns.extend(svc_resp.get("serviceArns", []))
                svc_token = svc_resp.get("nextToken")
                if not svc_token:
                    break

            if not service_arns:
                continue

            # Describe services in batches of 10 (API limit)
            for i in range(0, len(service_arns), 10):
                batch = service_arns[i : i + 10]
                desc_resp = ecs.describe_services(
                    cluster=cluster_arn, services=batch,
                )  # HARDCODED

                for svc in desc_resp.get("services", []):
                    svc_arn = svc.get("serviceArn", "")
                    svc_name = svc.get("serviceName", svc_arn.rsplit("/", 1)[-1])
                    svc_tags = {
                        t["key"]: t["value"]
                        for t in svc.get("tags", [])
                    }
                    svc_env = classify_environment(svc_tags, svc_name)

                    db.upsert_resource({
                        "arn": svc_arn,
                        "provider": "aws",
                        "service": "ecs",
                        "resource_type": "Service",
                        "name": svc_name,
                        "region": region,
                        "account_or_project": account,
                        "environment": svc_env,
                        "tags": svc_tags,
                        "metadata": {
                            "service_name": svc_name,
                            "status": svc.get("status"),
                            "desired_count": svc.get("desiredCount"),
                            "running_count": svc.get("runningCount"),
                            "launch_type": svc.get("launchType"),
                        },
                    })

                    # Relationship: service -> cluster
                    db.upsert_relationship(svc_arn, cluster_arn, "belongs_to")

                    # Relationship: service -> task definition
                    task_def = svc.get("taskDefinition")
                    if task_def:
                        db.upsert_relationship(svc_arn, task_def, "uses")

                    # Relationship: service -> IAM role
                    role_arn = svc.get("roleArn")
                    if role_arn:
                        db.upsert_relationship(svc_arn, role_arn, "assumes")

                    # Relationship: service -> load balancers / target groups
                    for lb in svc.get("loadBalancers", []):
                        tg_arn = lb.get("targetGroupArn")
                        if tg_arn:
                            db.upsert_relationship(svc_arn, tg_arn, "registered_to")

        logger.info("scan_ecs completed for region %s", region)

    except (ClientError, BotoCoreError) as exc:
        logger.warning("scan_ecs failed for region %s: %s", region, exc)


# ---------------------------------------------------------------------------
# scan_eks
# ---------------------------------------------------------------------------

def scan_eks(
    session: boto3.Session, db: GraphDB, region: str, account: str,
) -> None:
    """Discover EKS clusters."""
    try:
        eks = session.client("eks", region_name=region)
        next_token: str | None = None
        cluster_names: list[str] = []

        while True:
            if next_token:
                resp = eks.list_clusters(nextToken=next_token)  # HARDCODED
            else:
                resp = eks.list_clusters()  # HARDCODED

            cluster_names.extend(resp.get("clusters", []))
            next_token = resp.get("nextToken")
            if not next_token:
                break

        for cluster_name in cluster_names:
            try:
                desc_resp = eks.describe_cluster(name=cluster_name)  # HARDCODED
                cluster = desc_resp.get("cluster", {})

                arn = cluster.get(
                    "arn",
                    _build_arn("eks", region, account, "cluster", cluster_name),
                )
                tags = cluster.get("tags", {})
                env = classify_environment(tags, cluster_name)

                db.upsert_resource({
                    "arn": arn,
                    "provider": "aws",
                    "service": "eks",
                    "resource_type": "Cluster",
                    "name": cluster_name,
                    "region": region,
                    "account_or_project": account,
                    "environment": env,
                    "tags": tags,
                    "metadata": {
                        "cluster_name": cluster_name,
                        "status": cluster.get("status"),
                        "version": cluster.get("version"),
                        "platform_version": cluster.get("platformVersion"),
                        "endpoint": cluster.get("endpoint"),
                    },
                })

                # Relationship: EKS -> VPC
                resources_vpc = cluster.get("resourcesVpcConfig", {})
                vpc_id = resources_vpc.get("vpcId")
                if vpc_id:
                    vpc_arn = _build_arn("ec2", region, account, "vpc", vpc_id)
                    db.upsert_relationship(arn, vpc_arn, "resides_in")

                # Relationship: EKS -> Security Groups
                for sg_id in resources_vpc.get("securityGroupIds", []):
                    sg_arn = _build_arn(
                        "ec2", region, account, "security-group", sg_id,
                    )
                    db.upsert_relationship(arn, sg_arn, "attached_to")

                cluster_sg = resources_vpc.get("clusterSecurityGroupId")
                if cluster_sg:
                    sg_arn = _build_arn(
                        "ec2", region, account, "security-group", cluster_sg,
                    )
                    db.upsert_relationship(arn, sg_arn, "attached_to")

                # Relationship: EKS -> IAM Role
                role_arn = cluster.get("roleArn")
                if role_arn:
                    db.upsert_relationship(arn, role_arn, "assumes")

            except (ClientError, BotoCoreError) as desc_exc:
                logger.warning(
                    "Failed to describe EKS cluster %s: %s",
                    cluster_name, desc_exc,
                )

        logger.info("scan_eks completed for region %s", region)

    except (ClientError, BotoCoreError) as exc:
        logger.warning("scan_eks failed for region %s: %s", region, exc)


# ---------------------------------------------------------------------------
# scan_elb
# ---------------------------------------------------------------------------

def scan_elb(
    session: boto3.Session, db: GraphDB, region: str, account: str,
) -> None:
    """Discover ELBv2 (ALB/NLB) load balancers and target groups."""
    try:
        elbv2 = session.client("elbv2", region_name=region)

        # --- Load Balancers ---
        lb_marker: str | None = None
        while True:
            if lb_marker:
                lb_resp = elbv2.describe_load_balancers(Marker=lb_marker)  # HARDCODED
            else:
                lb_resp = elbv2.describe_load_balancers()  # HARDCODED

            for lb in lb_resp.get("LoadBalancers", []):
                lb_arn = lb.get("LoadBalancerArn", "")
                lb_name = lb.get("LoadBalancerName", lb_arn.rsplit("/", 1)[-1])
                env = classify_environment(None, lb_name)

                db.upsert_resource({
                    "arn": lb_arn,
                    "provider": "aws",
                    "service": "elbv2",
                    "resource_type": "LoadBalancer",
                    "name": lb_name,
                    "region": region,
                    "account_or_project": account,
                    "environment": env,
                    "tags": {},
                    "metadata": {
                        "lb_name": lb_name,
                        "dns_name": lb.get("DNSName"),
                        "type": lb.get("Type"),
                        "scheme": lb.get("Scheme"),
                        "state": lb.get("State", {}).get("Code"),
                        "ip_address_type": lb.get("IpAddressType"),
                    },
                })

                # Relationship: LB -> VPC
                vpc_id = lb.get("VpcId")
                if vpc_id:
                    vpc_arn = _build_arn("ec2", region, account, "vpc", vpc_id)
                    db.upsert_relationship(lb_arn, vpc_arn, "resides_in")

                # Relationship: LB -> Security Groups
                for sg_id in lb.get("SecurityGroups", []):
                    sg_arn = _build_arn(
                        "ec2", region, account, "security-group", sg_id,
                    )
                    db.upsert_relationship(lb_arn, sg_arn, "attached_to")

                # Relationship: LB -> AZs / Subnets
                for az_info in lb.get("AvailabilityZones", []):
                    subnet_id = az_info.get("SubnetId")
                    if subnet_id:
                        subnet_arn = _build_arn(
                            "ec2", region, account, "subnet", subnet_id,
                        )
                        db.upsert_relationship(lb_arn, subnet_arn, "resides_in")

            lb_marker = lb_resp.get("NextMarker")
            if not lb_marker:
                break

        # --- Target Groups ---
        tg_marker: str | None = None
        while True:
            if tg_marker:
                tg_resp = elbv2.describe_target_groups(Marker=tg_marker)  # HARDCODED
            else:
                tg_resp = elbv2.describe_target_groups()  # HARDCODED

            for tg in tg_resp.get("TargetGroups", []):
                tg_arn = tg.get("TargetGroupArn", "")
                tg_name = tg.get("TargetGroupName", tg_arn.rsplit("/", 1)[-1])
                env = classify_environment(None, tg_name)

                db.upsert_resource({
                    "arn": tg_arn,
                    "provider": "aws",
                    "service": "elbv2",
                    "resource_type": "TargetGroup",
                    "name": tg_name,
                    "region": region,
                    "account_or_project": account,
                    "environment": env,
                    "tags": {},
                    "metadata": {
                        "tg_name": tg_name,
                        "protocol": tg.get("Protocol"),
                        "port": tg.get("Port"),
                        "target_type": tg.get("TargetType"),
                        "health_check_path": tg.get("HealthCheckPath"),
                    },
                })

                # Relationship: TG -> Load Balancers
                for associated_lb_arn in tg.get("LoadBalancerArns", []):
                    db.upsert_relationship(
                        associated_lb_arn, tg_arn, "routes_to",
                    )

                # Relationship: TG -> VPC
                tg_vpc = tg.get("VpcId")
                if tg_vpc:
                    vpc_arn = _build_arn("ec2", region, account, "vpc", tg_vpc)
                    db.upsert_relationship(tg_arn, vpc_arn, "resides_in")

            tg_marker = tg_resp.get("NextMarker")
            if not tg_marker:
                break

        logger.info("scan_elb completed for region %s", region)

    except (ClientError, BotoCoreError) as exc:
        logger.warning("scan_elb failed for region %s: %s", region, exc)


# ---------------------------------------------------------------------------
# scan_route53
# ---------------------------------------------------------------------------

def scan_route53(
    session: boto3.Session, db: GraphDB, account: str,
) -> None:
    """Discover Route53 hosted zones and record sets."""
    try:
        route53 = session.client("route53")
        marker: str | None = None
        zones: list[dict] = []

        while True:
            if marker:
                resp = route53.list_hosted_zones(Marker=marker)  # HARDCODED
            else:
                resp = route53.list_hosted_zones()  # HARDCODED

            zones.extend(resp.get("HostedZones", []))
            if resp.get("IsTruncated", False):
                marker = resp.get("NextMarker")
                if not marker:
                    break
            else:
                break

        for zone in zones:
            zone_id = zone["Id"].rsplit("/", 1)[-1]
            zone_name = zone.get("Name", zone_id)
            arn = f"arn:aws:route53:::hostedzone/{zone_id}"
            env = classify_environment(None, zone_name)

            db.upsert_resource({
                "arn": arn,
                "provider": "aws",
                "service": "route53",
                "resource_type": "HostedZone",
                "name": zone_name,
                "region": "global",
                "account_or_project": account,
                "environment": env,
                "tags": {},
                "metadata": {
                    "zone_id": zone_id,
                    "zone_name": zone_name,
                    "private_zone": zone.get("Config", {}).get("PrivateZone", False),
                    "record_count": zone.get("ResourceRecordSetCount"),
                },
            })

            # List record sets (paginated)
            try:
                rs_name: str | None = None
                rs_type: str | None = None

                while True:
                    if rs_name and rs_type:
                        rr_resp = route53.list_resource_record_sets(
                            HostedZoneId=zone_id,
                            StartRecordName=rs_name,
                            StartRecordType=rs_type,
                        )  # HARDCODED
                    else:
                        rr_resp = route53.list_resource_record_sets(
                            HostedZoneId=zone_id,
                        )  # HARDCODED

                    for rr in rr_resp.get("ResourceRecordSets", []):
                        rr_name = rr.get("Name", "")
                        rr_type = rr.get("Type", "")
                        rr_arn = f"arn:aws:route53:::hostedzone/{zone_id}/recordset/{rr_name}/{rr_type}"

                        db.upsert_resource({
                            "arn": rr_arn,
                            "provider": "aws",
                            "service": "route53",
                            "resource_type": "RecordSet",
                            "name": rr_name,
                            "region": "global",
                            "account_or_project": account,
                            "environment": classify_environment(None, rr_name),
                            "tags": {},
                            "metadata": {
                                "record_name": rr_name,
                                "record_type": rr_type,
                                "ttl": rr.get("TTL"),
                                "values": [
                                    r.get("Value", "")
                                    for r in rr.get("ResourceRecords", [])
                                ],
                            },
                        })

                        # Relationship: record -> hosted zone
                        db.upsert_relationship(rr_arn, arn, "belongs_to")

                        # Relationship: ALIAS records -> target resource (ELB, etc.)
                        alias = rr.get("AliasTarget")
                        if alias:
                            dns_name = alias.get("DNSName", "")
                            hosted_zone_id = alias.get("HostedZoneId", "")
                            # ELB alias targets contain "elb" or "amazonaws.com"
                            if dns_name:
                                # Store as metadata; we cannot always resolve
                                # DNS to ARN, but we note the relationship.
                                db.upsert_resource({
                                    "arn": f"arn:aws:dns-target:::{dns_name}",
                                    "provider": "aws",
                                    "service": "route53",
                                    "resource_type": "AliasTarget",
                                    "name": dns_name,
                                    "region": "global",
                                    "account_or_project": account,
                                    "environment": "unknown",
                                    "tags": {},
                                    "metadata": {
                                        "dns_name": dns_name,
                                        "hosted_zone_id": hosted_zone_id,
                                    },
                                })
                                db.upsert_relationship(
                                    rr_arn,
                                    f"arn:aws:dns-target:::{dns_name}",
                                    "routes_to",
                                )

                    if not rr_resp.get("IsTruncated", False):
                        break
                    rs_name = rr_resp.get("NextRecordName")
                    rs_type = rr_resp.get("NextRecordType")
                    if not rs_name or not rs_type:
                        break

            except (ClientError, BotoCoreError) as rr_exc:
                logger.warning(
                    "Failed to list record sets for zone %s: %s",
                    zone_id, rr_exc,
                )

        logger.info("scan_route53 completed")

    except (ClientError, BotoCoreError) as exc:
        logger.warning("scan_route53 failed: %s", exc)


# ---------------------------------------------------------------------------
# scan_cloudfront
# ---------------------------------------------------------------------------

def scan_cloudfront(
    session: boto3.Session, db: GraphDB, account: str,
) -> None:
    """Discover CloudFront distributions."""
    try:
        cf = session.client("cloudfront")
        marker: str | None = None

        while True:
            if marker:
                resp = cf.list_distributions(Marker=marker)  # HARDCODED
            else:
                resp = cf.list_distributions()  # HARDCODED

            dist_list = resp.get("DistributionList", {})
            items = dist_list.get("Items", [])

            for dist in items:
                dist_id = dist["Id"]
                arn = dist.get(
                    "ARN",
                    f"arn:aws:cloudfront::{account}:distribution/{dist_id}",
                )
                domain_name = dist.get("DomainName", dist_id)
                aliases = dist.get("Aliases", {}).get("Items", [])
                name = aliases[0] if aliases else domain_name
                env = classify_environment(None, name)

                origins = dist.get("Origins", {}).get("Items", [])
                origin_list: list[dict[str, Any]] = []
                for origin in origins:
                    origin_list.append({
                        "id": origin.get("Id"),
                        "domain_name": origin.get("DomainName"),
                        "origin_path": origin.get("OriginPath", ""),
                    })

                db.upsert_resource({
                    "arn": arn,
                    "provider": "aws",
                    "service": "cloudfront",
                    "resource_type": "Distribution",
                    "name": name,
                    "region": "global",
                    "account_or_project": account,
                    "environment": env,
                    "tags": {},
                    "metadata": {
                        "distribution_id": dist_id,
                        "domain_name": domain_name,
                        "aliases": aliases,
                        "status": dist.get("Status"),
                        "enabled": dist.get("Enabled"),
                        "http_version": dist.get("HttpVersion"),
                        "price_class": dist.get("PriceClass"),
                        "origins": origin_list,
                    },
                })

                # Relationships: CloudFront -> origins (S3, ALB, custom)
                for origin in origins:
                    origin_domain = origin.get("DomainName", "")
                    if not origin_domain:
                        continue

                    # S3 origin: <bucket>.s3.amazonaws.com or <bucket>.s3.<region>.amazonaws.com
                    if ".s3." in origin_domain or origin_domain.endswith(
                        ".s3.amazonaws.com"
                    ):
                        bucket_name = origin_domain.split(".s3")[0]
                        s3_arn = f"arn:aws:s3:::{bucket_name}"
                        db.upsert_relationship(arn, s3_arn, "origins_from")

                    # ELB origin: contains "elb.amazonaws.com"
                    elif "elb.amazonaws.com" in origin_domain:
                        # Store as a DNS-target since we may not have the
                        # exact ELB ARN yet; the graph can correlate later.
                        db.upsert_resource({
                            "arn": f"arn:aws:dns-target:::{origin_domain}",
                            "provider": "aws",
                            "service": "elbv2",
                            "resource_type": "AliasTarget",
                            "name": origin_domain,
                            "region": "global",
                            "account_or_project": account,
                            "environment": "unknown",
                            "tags": {},
                            "metadata": {"dns_name": origin_domain},
                        })
                        db.upsert_relationship(
                            arn,
                            f"arn:aws:dns-target:::{origin_domain}",
                            "origins_from",
                        )

                    # Custom origin: record the relationship generically
                    else:
                        db.upsert_resource({
                            "arn": f"arn:aws:dns-target:::{origin_domain}",
                            "provider": "aws",
                            "service": "custom",
                            "resource_type": "Origin",
                            "name": origin_domain,
                            "region": "global",
                            "account_or_project": account,
                            "environment": "unknown",
                            "tags": {},
                            "metadata": {"dns_name": origin_domain},
                        })
                        db.upsert_relationship(
                            arn,
                            f"arn:aws:dns-target:::{origin_domain}",
                            "origins_from",
                        )

            if not dist_list.get("IsTruncated", False):
                break
            marker = dist_list.get("NextMarker")
            if not marker:
                break

        logger.info("scan_cloudfront completed")

    except (ClientError, BotoCoreError) as exc:
        logger.warning("scan_cloudfront failed: %s", exc)


# ---------------------------------------------------------------------------
# scan_dynamodb
# ---------------------------------------------------------------------------

def scan_dynamodb(
    session: boto3.Session, db: GraphDB, region: str, account: str,
) -> None:
    """Discover DynamoDB tables, their backups, and Lambda triggers."""
    try:
        dynamodb = session.client("dynamodb", region_name=region)
        table_names: list[str] = []
        last_evaluated: str | None = None

        while True:
            if last_evaluated:
                response = dynamodb.list_tables(ExclusiveStartTableName=last_evaluated)  # HARDCODED
            else:
                response = dynamodb.list_tables()  # HARDCODED

            table_names.extend(response.get("TableNames", []))
            last_evaluated = response.get("LastEvaluatedTableName")
            if not last_evaluated:
                break

        for table_name in table_names:
            try:
                desc_resp = dynamodb.describe_table(TableName=table_name)  # HARDCODED
                table = desc_resp.get("Table", {})

                table_arn = table.get("TableArn", _build_arn(
                    "dynamodb", region, account, "table", table_name,
                ))
                table_status = table.get("TableStatus", "")
                item_count = table.get("ItemCount", 0)
                table_size = table.get("TableSizeBytes", 0)
                billing = table.get("BillingModeSummary", {}).get(
                    "BillingMode", "PROVISIONED"
                )

                # GSIs and LSIs
                gsis = table.get("GlobalSecondaryIndexes", [])
                lsis = table.get("LocalSecondaryIndexes", [])

                # Stream info
                stream_spec = table.get("StreamSpecification", {})
                stream_enabled = stream_spec.get("StreamEnabled", False)
                latest_stream_arn = table.get("LatestStreamArn", "")

                tags: dict[str, str] = {}
                try:
                    tags_resp = dynamodb.list_tags_of_resource(ResourceArn=table_arn)  # HARDCODED
                    tags = {
                        t["Key"]: t["Value"]
                        for t in tags_resp.get("Tags", [])
                    }
                except (ClientError, BotoCoreError):
                    pass

                env = classify_environment(tags, table_name)

                # PITR status
                pitr_enabled = False
                try:
                    backup_resp = dynamodb.describe_continuous_backups(
                        TableName=table_name,
                    )  # HARDCODED
                    pitr_desc = backup_resp.get(
                        "ContinuousBackupsDescription", {},
                    ).get("PointInTimeRecoveryDescription", {})
                    pitr_enabled = pitr_desc.get(
                        "PointInTimeRecoveryStatus", ""
                    ) == "ENABLED"
                except (ClientError, BotoCoreError):
                    pass

                db.upsert_resource({
                    "arn": table_arn,
                    "provider": "aws",
                    "service": "dynamodb",
                    "resource_type": "Table",
                    "name": table_name,
                    "region": region,
                    "account_or_project": account,
                    "environment": env,
                    "tags": tags,
                    "metadata": {
                        "table_name": table_name,
                        "status": table_status,
                        "item_count": item_count,
                        "table_size_bytes": table_size,
                        "billing_mode": billing,
                        "stream_enabled": stream_enabled,
                        "pitr_enabled": pitr_enabled,
                        "gsi_count": len(gsis),
                        "lsi_count": len(lsis),
                        "gsi_names": [g.get("IndexName", "") for g in gsis],
                        "lsi_names": [l.get("IndexName", "") for l in lsis],
                    },
                })

                # Lambda triggers via DynamoDB Streams
                if stream_enabled and latest_stream_arn:
                    try:
                        lambda_ = session.client("lambda", region_name=region)
                        esm_marker: str | None = None

                        while True:
                            if esm_marker:
                                esm_resp = lambda_.list_event_source_mappings(
                                    EventSourceArn=latest_stream_arn,
                                    Marker=esm_marker,
                                )  # HARDCODED
                            else:
                                esm_resp = lambda_.list_event_source_mappings(
                                    EventSourceArn=latest_stream_arn,
                                )  # HARDCODED

                            for mapping in esm_resp.get("EventSourceMappings", []):
                                func_arn = mapping.get("FunctionArn", "")
                                if func_arn:
                                    db.upsert_relationship(
                                        func_arn, table_arn, "triggered_by",
                                    )

                            esm_marker = esm_resp.get("NextMarker")
                            if not esm_marker:
                                break

                    except (ClientError, BotoCoreError) as esm_exc:
                        logger.warning(
                            "Failed to list event source mappings for %s: %s",
                            table_name, esm_exc,
                        )

            except (ClientError, BotoCoreError) as desc_exc:
                logger.warning(
                    "Failed to describe DynamoDB table %s: %s",
                    table_name, desc_exc,
                )

        logger.info("scan_dynamodb completed for region %s", region)

    except (ClientError, BotoCoreError) as exc:
        logger.warning("scan_dynamodb failed for region %s: %s", region, exc)


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

_SERVICE_SCANNERS = {
    "ec2": scan_ec2,
    "rds": scan_rds,
    "s3": scan_s3,
    "lambda": scan_lambda,
    "iam": scan_iam_roles,
    "ecs": scan_ecs,
    "eks": scan_eks,
    "elb": scan_elb,
    "elbv2": scan_elb,
    "route53": scan_route53,
    "cloudfront": scan_cloudfront,
    "dynamodb": scan_dynamodb,
    "sqs": None,
    "sns": None,
}


def scan_aws_service(
    db: GraphDB,
    service: str,
    profile: str | None = None,
    region: str | None = None,
) -> None:
    """Run the scanner for a single AWS service.

    Looks up *service* in the known scanners. If no scanner exists for
    this service, returns silently (graceful no-op).

    All scanner functions are READ-ONLY — they only call describe_*(),
    list_*(), get_*() APIs.
    """
    scanner_fn = _SERVICE_SCANNERS.get(service)
    if scanner_fn is None:
        return

    session_kwargs: dict[str, str] = {}
    if profile:
        session_kwargs["profile_name"] = profile
    if region:
        session_kwargs["region_name"] = region
    session = boto3.Session(**session_kwargs)
    account = _get_account_id(session)
    scan_region = region or session.region_name or "us-east-1"

    # Global services don't take a region parameter.
    if scanner_fn in (scan_iam_roles, scan_iam_policies):
        scanner_fn(session, db, account)
    elif scanner_fn in (scan_route53, scan_cloudfront):
        scanner_fn(session, db, account)
    elif scanner_fn == scan_s3:
        scanner_fn(session, db, scan_region, account)
    else:
        scanner_fn(session, db, scan_region, account)


def scan_aws(
    db: GraphDB,
    profile: str | None = None,
    region: str | None = None,
    on_progress=None,
) -> dict:
    """Scan AWS resources and populate the infrastructure graph.

    Parameters
    ----------
    db:
        The GraphDB instance to populate.
    profile:
        Optional AWS CLI profile name.
    region:
        Optional region to scan.  If omitted the session default region
        is used.

    Returns
    -------
    dict
        Summary with keys: account_or_project, region, resource_count,
        relationship_count, environments.
    """
    # Build session
    session_kwargs: dict[str, str] = {}
    if profile:
        session_kwargs["profile_name"] = profile
    if region:
        session_kwargs["region_name"] = region

    session = boto3.Session(**session_kwargs)

    # Detect account
    account = _get_account_id(session)
    logger.info("Detected AWS account: %s", account)

    # Determine regions to scan.
    # We auto-detect available regions but only scan the session default
    # region (plus any explicitly requested region) for speed.
    default_region = session.region_name or "us-east-1"
    regions_to_scan: list[str] = [default_region]

    if region and region != default_region:
        regions_to_scan.append(region)

    # Optionally validate regions exist
    try:
        ec2_client = session.client("ec2", region_name=default_region)
        resp = ec2_client.describe_regions()  # HARDCODED
        valid_regions = {r["RegionName"] for r in resp.get("Regions", [])}
        regions_to_scan = [r for r in regions_to_scan if r in valid_regions]
        if not regions_to_scan:
            regions_to_scan = [default_region]
        logger.info("Valid AWS regions detected: %d", len(valid_regions))
    except (ClientError, BotoCoreError) as exc:
        logger.warning("Could not list AWS regions: %s", exc)

    logger.info("Scanning regions: %s", regions_to_scan)

    # ---- Run regional scanners ----
    for scan_region in regions_to_scan:
        if on_progress:
            on_progress("EC2 Instances")
        scan_ec2(session, db, scan_region, account)

        if on_progress:
            on_progress("Security Groups")
        scan_security_groups(session, db, scan_region, account)

        if on_progress:
            on_progress("RDS Databases")
        scan_rds(session, db, scan_region, account)

        if on_progress:
            on_progress("Lambda Functions")
        scan_lambda(session, db, scan_region, account)

        if on_progress:
            on_progress("ECS Clusters")
        scan_ecs(session, db, scan_region, account)

        if on_progress:
            on_progress("EKS Clusters")
        scan_eks(session, db, scan_region, account)

        if on_progress:
            on_progress("Load Balancers")
        scan_elb(session, db, scan_region, account)

        if on_progress:
            on_progress("DynamoDB Tables")
        scan_dynamodb(session, db, scan_region, account)

    # ---- Run global scanners ----
    if on_progress:
        on_progress("S3 Buckets")
    scan_s3(session, db, default_region, account)

    if on_progress:
        on_progress("IAM Roles")
    scan_iam_roles(session, db, account)

    if on_progress:
        on_progress("IAM Policies")
    scan_iam_policies(session, db, account)

    if on_progress:
        on_progress("Route53 DNS")
    scan_route53(session, db, account)

    if on_progress:
        on_progress("CloudFront Distributions")
    scan_cloudfront(session, db, account)

    # ---- Build summary ----
    summary = db.get_scan_summary()
    resource_count = summary["resource_count"]
    relationship_count = summary["relationship_count"]
    env_breakdown = summary.get("environment_breakdown", {})

    # Log the scan
    db.log_scan("aws", account, resource_count, relationship_count)

    result = {
        "account_or_project": account,
        "regions": regions_to_scan,
        "resource_count": resource_count,
        "relationship_count": relationship_count,
        "environments": {
            "prod": env_breakdown.get("prod", 0),
            "staging": env_breakdown.get("staging", 0),
            "dev": env_breakdown.get("dev", 0),
            "unknown": env_breakdown.get("unknown", 0),
        },
    }

    logger.info(
        "AWS scan complete: %d resources, %d relationships across %s",
        resource_count,
        relationship_count,
        regions_to_scan,
    )

    return result
