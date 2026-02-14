"""
Infrastructure graph backed by the Claude Guard server API.

Stores cloud resources and relationships in an in-memory buffer during scans,
then flushes them to the server via POST /api/v1/graph/sync.  Read methods
query the server directly.

When ``server_url`` is None (offline), write methods still buffer data and
read methods return empty/default values.
"""

from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Environment classifier
# ---------------------------------------------------------------------------

def classify_environment(tags: dict | None, name: str | None) -> str:
    """Return one of prod, staging, dev, or unknown.

    Priority:
      1. Explicit tag (``Environment``, ``environment``, or ``env``).
      2. Pattern matching on *name*.
      3. Fallback to ``"unknown"``.
    """
    if tags:
        for key in ("Environment", "environment", "env"):
            val = tags.get(key)
            if val:
                lower = val.strip().lower()
                if lower in ("prod", "production"):
                    return "prod"
                if lower in ("stag", "staging"):
                    return "staging"
                if lower in ("dev", "development"):
                    return "dev"

    if name:
        lower_name = name.lower()
        if "production" in lower_name or "prod" in lower_name:
            return "prod"
        if "staging" in lower_name or "stag" in lower_name:
            return "staging"
        if "development" in lower_name or "dev" in lower_name:
            return "dev"

    return "unknown"


# ---------------------------------------------------------------------------
# GraphDB — API client + in-memory write buffer
# ---------------------------------------------------------------------------

class GraphDB:
    """API-backed infrastructure graph with an in-memory write buffer.

    During scans the caller writes resources and relationships into memory.
    Calling ``flush()`` (or ``log_scan()``) posts them to the server.
    Read methods hit the server API directly.
    """

    def __init__(
        self,
        server_url: str | None = None,
        token: str | None = None,
    ) -> None:
        self._server_url = server_url.rstrip("/") if server_url else None
        self._token = token

        # In-memory write buffers (flushed on sync).
        self._resources: dict[str, dict] = {}
        self._relationships: list[dict] = []
        self._scan_provider: str | None = None
        self._scan_account: str | None = None

    # ------------------------------------------------------------------
    # HTTP helpers
    # ------------------------------------------------------------------

    def _headers(self) -> dict[str, str]:
        h: dict[str, str] = {}
        if self._token:
            h["Authorization"] = f"Bearer {self._token}"
        return h

    def _get(self, path: str, params: dict | None = None) -> dict | None:
        """GET request to the server. Returns parsed JSON or None on failure."""
        if not self._server_url:
            return None
        try:
            import requests
            resp = requests.get(
                f"{self._server_url}{path}",
                params=params,
                headers=self._headers(),
                timeout=30,
            )
            if resp.status_code == 200:
                return resp.json()
            logger.debug("GET %s returned %s", path, resp.status_code)
        except Exception as exc:
            logger.debug("GET %s failed: %s", path, exc)
        return None

    # ------------------------------------------------------------------
    # Write methods (buffer in memory)
    # ------------------------------------------------------------------

    def upsert_resource(self, resource: dict) -> None:
        """Buffer a resource for later flush."""
        env = resource.get("environment")
        if not env or env == "unknown":
            env = classify_environment(
                resource.get("tags"), resource.get("name")
            )
            resource = {**resource, "environment": env}

        arn = resource["arn"]
        self._resources[arn] = resource

    def upsert_relationship(
        self,
        source_arn: str,
        target_arn: str,
        rel_type: str,
        metadata: dict | None = None,
    ) -> None:
        """Buffer a relationship for later flush."""
        self._relationships.append({
            "source_arn": source_arn,
            "target_arn": target_arn,
            "rel_type": rel_type,
            "metadata": metadata,
        })

    # ------------------------------------------------------------------
    # Scan log / flush
    # ------------------------------------------------------------------

    def log_scan(
        self,
        provider: str,
        account_or_project: str,
        resource_count: int,
        relationship_count: int,
    ) -> None:
        """Record a completed scan and flush buffers to the server."""
        self._scan_provider = provider
        self._scan_account = account_or_project
        self.flush()

    def flush(self) -> None:
        """POST buffered resources and relationships to /api/v1/graph/sync."""
        if not self._server_url or not self._token:
            return
        if not self._resources and not self._relationships:
            return

        try:
            import requests

            payload = {
                "resources": list(self._resources.values()),
                "relationships": self._relationships,
                "provider": self._scan_provider,
                "account_or_project": self._scan_account,
            }
            resp = requests.post(
                f"{self._server_url}/api/v1/graph/sync",
                json=payload,
                headers=self._headers(),
                timeout=60,
            )
            if resp.status_code == 200:
                data = resp.json()
                logger.debug(
                    "Synced %s resources, %s relationships",
                    data.get("resources_upserted"),
                    data.get("relationships_upserted"),
                )
            else:
                logger.debug("Sync failed: %s", resp.status_code)
        except Exception as exc:
            logger.debug("Sync failed: %s", exc)

        # Clear buffers after flush attempt.
        self._resources.clear()
        self._relationships.clear()

    # ------------------------------------------------------------------
    # Read methods (hit server API)
    # ------------------------------------------------------------------

    def find_resource(self, identifier: str) -> dict | None:
        """Search by ARN, name, or ARN substring."""
        data = self._get("/api/v1/graph/find-resource", params={"id": identifier})
        if data:
            return data.get("resource")
        return None

    def get_connections(self, arn: str, hops: int = 2) -> list[dict]:
        """Graph traversal — connected resources up to *hops* hops."""
        data = self._get("/api/v1/graph/connections", params={"arn": arn, "hops": hops})
        if data:
            return data.get("connections", [])
        return []

    def get_dependents(self, arn: str) -> list[dict]:
        """Return resources that depend on *arn* (incoming relationships)."""
        data = self._get("/api/v1/graph/dependents", params={"arn": arn})
        if data:
            return data.get("dependents", [])
        return []

    def is_populated(self, account_or_project: str | None = None) -> bool:
        """Return True if the org has any resources."""
        data = self._get(
            "/api/v1/graph/populated",
            params={"provider": "aws", "profile": account_or_project},
        )
        if data:
            return data.get("populated", False)
        return False

    def is_populated_for(self, provider: str, profile: str | None = None) -> bool:
        """Return True if resources exist for a given provider/account."""
        params: dict = {"provider": provider}
        if profile:
            params["profile"] = profile
        data = self._get("/api/v1/graph/populated", params=params)
        if data:
            return data.get("populated", False)
        return False

    def staleness_minutes(self, account_or_project: str | None = None) -> int:
        """Minutes since the last completed scan. Returns -1 if no scans."""
        params: dict = {}
        if account_or_project:
            params["account"] = account_or_project
        data = self._get("/api/v1/graph/staleness", params=params)
        if data:
            return data.get("staleness_minutes", -1)
        return -1

    def get_scan_summary(self) -> dict:
        """Return an overview of the current graph state."""
        data = self._get("/api/v1/graph/summary")
        if data:
            return data
        return {
            "resource_count": 0,
            "relationship_count": 0,
            "environment_breakdown": {},
            "last_scan_time": None,
        }

    def incremental_fetch(
        self, provider: str, service: str, resource_id: str
    ) -> None:
        """No-op — incremental fetching is handled by scanner modules."""
        return None

    # ------------------------------------------------------------------
    # Clearing data (no-op — server manages data lifecycle)
    # ------------------------------------------------------------------

    def clear(self, account_or_project: str | None = None) -> None:
        """Clear local buffers. Server-side data is not affected."""
        self._resources.clear()
        self._relationships.clear()
