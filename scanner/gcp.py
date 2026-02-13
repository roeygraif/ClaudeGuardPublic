"""
GCP resource discovery scanner.

Discovers GCP infrastructure using HARDCODED, LITERAL, read-only API calls
and stores resources + relationships in the local graph database.

Every GCP client method invocation is written explicitly in source code.
No dynamic dispatch, no interpolated method names, no getattr tricks.
"""

from __future__ import annotations

import logging
import os
from datetime import datetime, timezone
from typing import Any

from scanner.graph import GraphDB, classify_environment

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Helper: resolve project ID
# ---------------------------------------------------------------------------

def _get_project_id() -> str:
    """Resolve the GCP project ID from environment or default credentials.

    Resolution order:
      1. GOOGLE_CLOUD_PROJECT environment variable
      2. GCLOUD_PROJECT environment variable
      3. google.auth.default() credentials
    """
    # 1. Environment variables
    for env_var in ("GOOGLE_CLOUD_PROJECT", "GCLOUD_PROJECT"):
        project = os.environ.get(env_var)
        if project:
            return project

    # 2. google.auth.default()
    try:
        import google.auth  # noqa: E402
        _credentials, project = google.auth.default()
        if project:
            return project
    except Exception as exc:
        logger.debug("google.auth.default() failed: %s", exc)

    raise RuntimeError(
        "Cannot determine GCP project. Set GOOGLE_CLOUD_PROJECT, "
        "GCLOUD_PROJECT, or configure gcloud with a default project."
    )


# ---------------------------------------------------------------------------
# Zone / region helpers
# ---------------------------------------------------------------------------

def _zone_to_region(zone: str) -> str:
    """Extract the region from a zone string (e.g. 'us-central1-a' -> 'us-central1')."""
    parts = zone.split("-")
    if len(parts) >= 3:
        return "-".join(parts[:-1])
    return zone


def _extract_zone_from_scope(scope_key: str) -> str:
    """Extract the bare zone name from an aggregated-list scope key.

    Scope keys look like 'zones/us-central1-a'.
    """
    if "/" in scope_key:
        return scope_key.split("/", 1)[1]
    return scope_key


# ---------------------------------------------------------------------------
# Scan: Compute Engine instances
# ---------------------------------------------------------------------------

def scan_compute_instances(db: GraphDB, project: str) -> int:
    """Scan GCE instances using compute_v1.InstancesClient.aggregated_list.

    Returns the number of resources discovered.
    """
    try:
        from google.cloud import compute_v1
    except ImportError:
        logger.warning(
            "google-cloud-compute is not installed. "
            "Run: pip install google-cloud-compute"
        )
        return 0

    count = 0
    try:
        client = compute_v1.InstancesClient()
        request = compute_v1.AggregatedListInstancesRequest(project=project)
        # HARDCODED read-only call
        response = client.aggregated_list(request=request)

        for scope_key, instances_scoped_list in response:
            if not instances_scoped_list.instances:
                continue

            zone = _extract_zone_from_scope(scope_key)
            region = _zone_to_region(zone)

            for instance in instances_scoped_list.instances:
                resource_id = (
                    f"projects/{project}/zones/{zone}/instances/{instance.name}"
                )
                labels = dict(instance.labels) if instance.labels else {}
                env = classify_environment(labels, instance.name)

                status_str = instance.status if instance.status else None
                is_active = 1 if status_str == "RUNNING" else 0

                metadata_dict: dict[str, Any] = {
                    "machine_type": instance.machine_type or None,
                    "status": status_str,
                    "zone": zone,
                    "creation_timestamp": instance.creation_timestamp or None,
                }

                db.upsert_resource({
                    "arn": resource_id,
                    "provider": "gcp",
                    "service": "compute",
                    "resource_type": "instance",
                    "name": instance.name,
                    "region": region,
                    "account_or_project": project,
                    "environment": env,
                    "is_active": is_active,
                    "metadata": metadata_dict,
                    "tags": labels,
                })
                count += 1

                # Relationships: instance -> network interfaces
                if instance.network_interfaces:
                    for nic in instance.network_interfaces:
                        if nic.network:
                            db.upsert_relationship(
                                source_arn=resource_id,
                                target_arn=nic.network,
                                rel_type="ATTACHED_TO_NETWORK",
                            )
                        if nic.subnetwork:
                            db.upsert_relationship(
                                source_arn=resource_id,
                                target_arn=nic.subnetwork,
                                rel_type="ATTACHED_TO_SUBNET",
                            )

                # Relationships: instance -> service accounts
                if instance.service_accounts:
                    for sa in instance.service_accounts:
                        if sa.email:
                            sa_arn = (
                                f"projects/{project}/serviceAccounts/{sa.email}"
                            )
                            db.upsert_resource({
                                "arn": sa_arn,
                                "provider": "gcp",
                                "service": "iam",
                                "resource_type": "service_account",
                                "name": sa.email,
                                "region": "global",
                                "account_or_project": project,
                            })
                            db.upsert_relationship(
                                source_arn=resource_id,
                                target_arn=sa_arn,
                                rel_type="USES_SERVICE_ACCOUNT",
                            )

    except Exception as exc:
        logger.warning("Failed to scan GCE instances: %s", exc)

    return count


# ---------------------------------------------------------------------------
# Scan: GKE clusters
# ---------------------------------------------------------------------------

def scan_gke_clusters(db: GraphDB, project: str) -> int:
    """Scan GKE clusters using container_v1.ClusterManagerClient.list_clusters.

    Returns the number of resources discovered.
    """
    try:
        from google.cloud import container_v1
    except ImportError:
        logger.warning(
            "google-cloud-container is not installed. "
            "Run: pip install google-cloud-container"
        )
        return 0

    count = 0
    try:
        client = container_v1.ClusterManagerClient()
        # HARDCODED read-only call
        response = client.list_clusters(
            parent=f"projects/{project}/locations/-"
        )

        for cluster in response.clusters:
            location = cluster.location or "unknown"
            resource_id = (
                f"projects/{project}/locations/{location}"
                f"/clusters/{cluster.name}"
            )
            labels = dict(cluster.resource_labels) if cluster.resource_labels else {}
            env = classify_environment(labels, cluster.name)

            is_active = 1 if cluster.status == container_v1.Cluster.Status.RUNNING else 0

            metadata_dict: dict[str, Any] = {
                "status": str(cluster.status) if cluster.status else None,
                "current_master_version": cluster.current_master_version or None,
                "current_node_version": cluster.current_node_version or None,
                "location": location,
                "endpoint": cluster.endpoint or None,
                "initial_cluster_version": cluster.initial_cluster_version or None,
            }

            db.upsert_resource({
                "arn": resource_id,
                "provider": "gcp",
                "service": "container",
                "resource_type": "gke_cluster",
                "name": cluster.name,
                "region": location,
                "account_or_project": project,
                "environment": env,
                "is_active": is_active,
                "metadata": metadata_dict,
                "tags": labels,
            })
            count += 1

            # Relationship: cluster -> network
            if cluster.network:
                network_arn = (
                    f"projects/{project}/global/networks/{cluster.network}"
                )
                db.upsert_relationship(
                    source_arn=resource_id,
                    target_arn=network_arn,
                    rel_type="ATTACHED_TO_NETWORK",
                )

            # Relationship: cluster -> subnetwork
            if cluster.subnetwork:
                subnet_arn = (
                    f"projects/{project}/regions/{location}"
                    f"/subnetworks/{cluster.subnetwork}"
                )
                db.upsert_relationship(
                    source_arn=resource_id,
                    target_arn=subnet_arn,
                    rel_type="ATTACHED_TO_SUBNET",
                )

    except Exception as exc:
        logger.warning("Failed to scan GKE clusters: %s", exc)

    return count


# ---------------------------------------------------------------------------
# Scan: Cloud SQL instances
# ---------------------------------------------------------------------------

def scan_cloud_sql(db: GraphDB, project: str) -> int:
    """Scan Cloud SQL instances using sqladmin_v1.SqlInstancesServiceClient.list.

    Returns the number of resources discovered.
    """
    try:
        from google.cloud import sqladmin_v1
    except ImportError:
        logger.warning(
            "google-cloud-sqladmin is not installed. "
            "Run: pip install google-cloud-sqladmin"
        )
        return 0

    count = 0
    try:
        client = sqladmin_v1.SqlInstancesServiceClient()
        # HARDCODED read-only call
        response = client.list(project=project)

        items = response.items if response.items else []
        for instance in items:
            region = instance.region or "unknown"
            resource_id = (
                f"projects/{project}/instances/{instance.name}"
            )

            labels = dict(instance.settings.user_labels) if (
                instance.settings and instance.settings.user_labels
            ) else {}
            env = classify_environment(labels, instance.name)

            state_str = str(instance.state) if instance.state else None
            is_active = 1 if state_str and "RUNNABLE" in state_str else 0

            metadata_dict: dict[str, Any] = {
                "database_version": instance.database_version or None,
                "state": state_str,
                "region": region,
                "tier": (
                    instance.settings.tier
                    if instance.settings else None
                ),
                "connection_name": instance.connection_name or None,
            }

            db.upsert_resource({
                "arn": resource_id,
                "provider": "gcp",
                "service": "sqladmin",
                "resource_type": "cloud_sql_instance",
                "name": instance.name,
                "region": region,
                "account_or_project": project,
                "environment": env,
                "is_active": is_active,
                "metadata": metadata_dict,
                "tags": labels,
            })
            count += 1

            # Relationship: SQL instance -> network (private IP)
            if (
                instance.settings
                and instance.settings.ip_configuration
                and instance.settings.ip_configuration.private_network
            ):
                db.upsert_relationship(
                    source_arn=resource_id,
                    target_arn=instance.settings.ip_configuration.private_network,
                    rel_type="ATTACHED_TO_NETWORK",
                )

    except Exception as exc:
        logger.warning("Failed to scan Cloud SQL instances: %s", exc)

    return count


# ---------------------------------------------------------------------------
# Scan: GCS buckets
# ---------------------------------------------------------------------------

def scan_gcs_buckets(db: GraphDB, project: str) -> int:
    """Scan GCS buckets using storage.Client.list_buckets.

    Returns the number of resources discovered.
    """
    try:
        from google.cloud import storage
    except ImportError:
        logger.warning(
            "google-cloud-storage is not installed. "
            "Run: pip install google-cloud-storage"
        )
        return 0

    count = 0
    try:
        client = storage.Client(project=project)
        # HARDCODED read-only call
        buckets = client.list_buckets()

        for bucket in buckets:
            resource_id = f"projects/{project}/buckets/{bucket.name}"
            labels = dict(bucket.labels) if bucket.labels else {}
            env = classify_environment(labels, bucket.name)

            metadata_dict: dict[str, Any] = {
                "location": bucket.location or None,
                "storage_class": bucket.storage_class or None,
                "versioning_enabled": bucket.versioning_enabled,
                "time_created": (
                    bucket.time_created.isoformat()
                    if bucket.time_created else None
                ),
            }

            db.upsert_resource({
                "arn": resource_id,
                "provider": "gcp",
                "service": "storage",
                "resource_type": "bucket",
                "name": bucket.name,
                "region": bucket.location or "unknown",
                "account_or_project": project,
                "environment": env,
                "is_active": 1,
                "metadata": metadata_dict,
                "tags": labels,
            })
            count += 1

    except Exception as exc:
        logger.warning("Failed to scan GCS buckets: %s", exc)

    return count


# ---------------------------------------------------------------------------
# Scan: IAM policy
# ---------------------------------------------------------------------------

def scan_iam_policy(db: GraphDB, project: str) -> int:
    """Scan project IAM policy using resourcemanager_v3.ProjectsClient.get_iam_policy.

    Returns the number of resources discovered (roles + members).
    """
    try:
        from google.cloud import resourcemanager_v3
    except ImportError:
        logger.warning(
            "google-cloud-resource-manager is not installed. "
            "Run: pip install google-cloud-resource-manager"
        )
        return 0

    count = 0
    try:
        client = resourcemanager_v3.ProjectsClient()
        # HARDCODED read-only call
        policy = client.get_iam_policy(resource=f"projects/{project}")

        for binding in policy.bindings:
            role = binding.role
            role_arn = f"projects/{project}/roles/{role}"

            db.upsert_resource({
                "arn": role_arn,
                "provider": "gcp",
                "service": "iam",
                "resource_type": "role_binding",
                "name": role,
                "region": "global",
                "account_or_project": project,
                "is_active": 1,
            })
            count += 1

            for member in binding.members:
                member_arn = f"projects/{project}/members/{member}"

                # Determine member type from the prefix
                # (e.g. "user:", "serviceAccount:", "group:", "domain:")
                member_type = "member"
                if ":" in member:
                    member_type = member.split(":", 1)[0]

                db.upsert_resource({
                    "arn": member_arn,
                    "provider": "gcp",
                    "service": "iam",
                    "resource_type": f"iam_{member_type}",
                    "name": member,
                    "region": "global",
                    "account_or_project": project,
                    "is_active": 1,
                })
                count += 1

                # Relationship: member -> role
                db.upsert_relationship(
                    source_arn=member_arn,
                    target_arn=role_arn,
                    rel_type="HAS_ROLE",
                )

    except Exception as exc:
        logger.warning("Failed to scan IAM policy: %s", exc)

    return count


# ---------------------------------------------------------------------------
# Scan: Cloud Functions (v2)
# ---------------------------------------------------------------------------

def scan_cloud_functions(db: GraphDB, project: str) -> int:
    """Scan Cloud Functions using functions_v2.FunctionServiceClient.list_functions.

    Returns the number of resources discovered.
    """
    try:
        from google.cloud import functions_v2
    except ImportError:
        logger.warning(
            "google-cloud-functions is not installed. "
            "Run: pip install google-cloud-functions"
        )
        return 0

    count = 0
    try:
        client = functions_v2.FunctionServiceClient()
        # HARDCODED read-only call
        response = client.list_functions(
            parent=f"projects/{project}/locations/-"
        )

        for function in response:
            # function.name is the full resource path already
            resource_id = function.name or (
                f"projects/{project}/locations/unknown/functions/unknown"
            )
            labels = dict(function.labels) if function.labels else {}

            # Extract short name from full resource path
            short_name = resource_id.rsplit("/", 1)[-1]
            env = classify_environment(labels, short_name)

            # Extract location from the resource path
            # Format: projects/{project}/locations/{location}/functions/{name}
            parts = resource_id.split("/")
            location = "unknown"
            if len(parts) >= 4:
                loc_idx = None
                for i, part in enumerate(parts):
                    if part == "locations" and i + 1 < len(parts):
                        loc_idx = i + 1
                        break
                if loc_idx is not None:
                    location = parts[loc_idx]

            state_str = str(function.state) if function.state else None
            is_active = 1 if state_str and "ACTIVE" in state_str else 0

            metadata_dict: dict[str, Any] = {
                "state": state_str,
                "runtime": (
                    function.build_config.runtime
                    if function.build_config else None
                ),
                "entry_point": (
                    function.build_config.entry_point
                    if function.build_config else None
                ),
                "location": location,
                "update_time": (
                    function.update_time.isoformat()
                    if function.update_time else None
                ),
            }

            db.upsert_resource({
                "arn": resource_id,
                "provider": "gcp",
                "service": "cloudfunctions",
                "resource_type": "function",
                "name": short_name,
                "region": location,
                "account_or_project": project,
                "environment": env,
                "is_active": is_active,
                "metadata": metadata_dict,
                "tags": labels,
            })
            count += 1

            # Relationship: function -> service account
            if function.service_config and function.service_config.service_account_email:
                sa_email = function.service_config.service_account_email
                sa_arn = f"projects/{project}/serviceAccounts/{sa_email}"
                db.upsert_resource({
                    "arn": sa_arn,
                    "provider": "gcp",
                    "service": "iam",
                    "resource_type": "service_account",
                    "name": sa_email,
                    "region": "global",
                    "account_or_project": project,
                })
                db.upsert_relationship(
                    source_arn=resource_id,
                    target_arn=sa_arn,
                    rel_type="USES_SERVICE_ACCOUNT",
                )

            # Relationship: function -> VPC connector
            if (
                function.service_config
                and function.service_config.vpc_connector
            ):
                db.upsert_relationship(
                    source_arn=resource_id,
                    target_arn=function.service_config.vpc_connector,
                    rel_type="ATTACHED_TO_VPC_CONNECTOR",
                )

    except Exception as exc:
        logger.warning("Failed to scan Cloud Functions: %s", exc)

    return count


# ---------------------------------------------------------------------------
# Scan: Cloud Run services
# ---------------------------------------------------------------------------

def scan_cloud_run(db: GraphDB, project: str) -> int:
    """Scan Cloud Run services using run_v2.ServicesClient.list_services.

    Returns the number of resources discovered.
    """
    try:
        from google.cloud import run_v2
    except ImportError:
        logger.warning(
            "google-cloud-run is not installed. "
            "Run: pip install google-cloud-run"
        )
        return 0

    count = 0
    try:
        client = run_v2.ServicesClient()
        # HARDCODED read-only call
        response = client.list_services(
            parent=f"projects/{project}/locations/-"
        )

        for service in response:
            # service.name is the full resource path
            resource_id = service.name or (
                f"projects/{project}/locations/unknown/services/unknown"
            )
            labels = dict(service.labels) if service.labels else {}

            # Extract short name from full resource path
            short_name = resource_id.rsplit("/", 1)[-1]
            env = classify_environment(labels, short_name)

            # Extract location from the resource path
            # Format: projects/{project}/locations/{location}/services/{name}
            parts = resource_id.split("/")
            location = "unknown"
            for i, part in enumerate(parts):
                if part == "locations" and i + 1 < len(parts):
                    location = parts[i + 1]
                    break

            is_active = 1  # Cloud Run services are active if they exist

            metadata_dict: dict[str, Any] = {
                "uri": service.uri or None,
                "location": location,
                "launch_stage": (
                    str(service.launch_stage) if service.launch_stage else None
                ),
                "create_time": (
                    service.create_time.isoformat()
                    if service.create_time else None
                ),
                "update_time": (
                    service.update_time.isoformat()
                    if service.update_time else None
                ),
                "ingress": (
                    str(service.ingress) if service.ingress else None
                ),
            }

            db.upsert_resource({
                "arn": resource_id,
                "provider": "gcp",
                "service": "cloudrun",
                "resource_type": "service",
                "name": short_name,
                "region": location,
                "account_or_project": project,
                "environment": env,
                "is_active": is_active,
                "metadata": metadata_dict,
                "tags": labels,
            })
            count += 1

            # Relationship: service -> service account
            if service.template and service.template.service_account:
                sa_email = service.template.service_account
                sa_arn = f"projects/{project}/serviceAccounts/{sa_email}"
                db.upsert_resource({
                    "arn": sa_arn,
                    "provider": "gcp",
                    "service": "iam",
                    "resource_type": "service_account",
                    "name": sa_email,
                    "region": "global",
                    "account_or_project": project,
                })
                db.upsert_relationship(
                    source_arn=resource_id,
                    target_arn=sa_arn,
                    rel_type="USES_SERVICE_ACCOUNT",
                )

            # Relationship: service -> VPC connector / network
            if (
                service.template
                and service.template.vpc_access
                and service.template.vpc_access.connector
            ):
                db.upsert_relationship(
                    source_arn=resource_id,
                    target_arn=service.template.vpc_access.connector,
                    rel_type="ATTACHED_TO_VPC_CONNECTOR",
                )

    except Exception as exc:
        logger.warning("Failed to scan Cloud Run services: %s", exc)

    return count


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def scan_gcp(db: GraphDB, project: str | None = None, on_progress=None) -> dict:
    """Discover GCP resources and store them in the graph database.

    Parameters
    ----------
    db : GraphDB
        The graph database instance to store discovered resources.
    project : str, optional
        The GCP project ID. If not provided, auto-detection is attempted
        via environment variables or google.auth.default().

    Returns
    -------
    dict
        Summary with keys: account_or_project, region, resource_count,
        relationship_count, environments.
    """
    if project is None:
        project = _get_project_id()

    logger.info("Starting GCP scan for project: %s", project)
    start_time = datetime.now(timezone.utc)

    # Clear previous data for this project before re-scanning.
    db.clear(account_or_project=project)

    # Run all scanners, collecting total resource count.
    total_resources = 0

    if on_progress:
        on_progress("Compute Instances")
    total_resources += scan_compute_instances(db, project)

    if on_progress:
        on_progress("GKE Clusters")
    total_resources += scan_gke_clusters(db, project)

    if on_progress:
        on_progress("Cloud SQL")
    total_resources += scan_cloud_sql(db, project)

    if on_progress:
        on_progress("Cloud Storage")
    total_resources += scan_gcs_buckets(db, project)

    if on_progress:
        on_progress("IAM Policy")
    total_resources += scan_iam_policy(db, project)

    if on_progress:
        on_progress("Cloud Functions")
    total_resources += scan_cloud_functions(db, project)

    if on_progress:
        on_progress("Cloud Run")
    total_resources += scan_cloud_run(db, project)

    # Count relationships from the database.
    summary = db.get_scan_summary()
    relationship_count = summary.get("relationship_count", 0)
    env_breakdown = summary.get("environment_breakdown", {})

    # Log the scan.
    db.log_scan(
        provider="gcp",
        account_or_project=project,
        resource_count=total_resources,
        relationship_count=relationship_count,
    )

    elapsed = (datetime.now(timezone.utc) - start_time).total_seconds()
    logger.info(
        "GCP scan complete for project %s: %d resources, %d relationships (%.1fs)",
        project,
        total_resources,
        relationship_count,
        elapsed,
    )

    return {
        "account_or_project": project,
        "region": "global",
        "resource_count": total_resources,
        "relationship_count": relationship_count,
        "environments": {
            "prod": env_breakdown.get("prod", 0),
            "staging": env_breakdown.get("staging", 0),
            "dev": env_breakdown.get("dev", 0),
            "unknown": env_breakdown.get("unknown", 0),
        },
    }
