"""
Infrastructure graph backed by SQLite.

Stores cloud resources and their relationships in a local SQLite database
located at ~/.cloud-watchdog/infra.db (configurable).  The schema is
auto-created on first use.
"""

from __future__ import annotations

import json
import os
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------

_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS resources (
    arn TEXT PRIMARY KEY,
    provider TEXT NOT NULL,
    service TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    name TEXT,
    region TEXT,
    account_or_project TEXT,
    environment TEXT,
    is_active INTEGER,
    activity_summary TEXT,
    metadata JSON,
    tags JSON,
    last_scanned TIMESTAMP
);

CREATE TABLE IF NOT EXISTS relationships (
    source_arn TEXT NOT NULL,
    target_arn TEXT NOT NULL,
    rel_type TEXT NOT NULL,
    metadata JSON,
    PRIMARY KEY (source_arn, target_arn, rel_type)
);

CREATE TABLE IF NOT EXISTS scan_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    provider TEXT,
    account_or_project TEXT,
    started_at TIMESTAMP,
    completed_at TIMESTAMP,
    resource_count INTEGER,
    relationship_count INTEGER
);
"""


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
                # If the tag exists but is something unexpected, still
                # return it normalised to our canonical set if possible,
                # otherwise fall through to name-based detection.

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
# GraphDB
# ---------------------------------------------------------------------------

class GraphDB:
    """Thread-safe wrapper around the infrastructure SQLite database."""

    _DEFAULT_DIR = os.path.join(Path.home(), ".cloud-watchdog")
    _DEFAULT_DB = "infra.db"

    def __init__(self, db_path: str | None = None) -> None:
        if db_path is None:
            os.makedirs(self._DEFAULT_DIR, exist_ok=True)
            db_path = os.path.join(self._DEFAULT_DIR, self._DEFAULT_DB)

        self._db_path: str = db_path
        self._local = threading.local()

        # Ensure schema exists on initialisation.
        with self._connect() as conn:
            conn.executescript(_SCHEMA_SQL)

    # ------------------------------------------------------------------
    # Connection helpers
    # ------------------------------------------------------------------

    def _get_connection(self) -> sqlite3.Connection:
        """Return a per-thread cached connection."""
        conn: sqlite3.Connection | None = getattr(self._local, "conn", None)
        if conn is None:
            conn = sqlite3.connect(self._db_path, check_same_thread=False)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA foreign_keys=ON")
            self._local.conn = conn
        return conn

    @contextmanager
    def _connect(self):
        """Context manager that yields a connection and commits on success."""
        conn = self._get_connection()
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise

    # ------------------------------------------------------------------
    # Internal JSON helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _to_json(obj: Any) -> str | None:
        if obj is None:
            return None
        if isinstance(obj, str):
            # Already serialised — validate then pass through.
            try:
                json.loads(obj)
                return obj
            except (json.JSONDecodeError, TypeError):
                return json.dumps(obj)
        return json.dumps(obj)

    @staticmethod
    def _from_json(raw: str | None) -> Any:
        if raw is None:
            return None
        try:
            return json.loads(raw)
        except (json.JSONDecodeError, TypeError):
            return raw

    def _row_to_dict(self, row: sqlite3.Row | None) -> dict | None:
        if row is None:
            return None
        d = dict(row)
        # Parse JSON columns back to native types.
        for key in ("metadata", "tags"):
            if key in d:
                d[key] = self._from_json(d[key])
        return d

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def is_populated(self, account_or_project: str | None = None) -> bool:
        """Return True if any resources exist, optionally scoped to an account."""
        with self._connect() as conn:
            if account_or_project:
                row = conn.execute(
                    "SELECT COUNT(*) AS cnt FROM resources WHERE account_or_project = ?",
                    (account_or_project,),
                ).fetchone()
            else:
                row = conn.execute("SELECT COUNT(*) AS cnt FROM resources").fetchone()
            return row["cnt"] > 0

    def is_populated_for(self, provider: str, profile: str | None = None) -> bool:
        """Return True if resources exist for a given provider/account."""
        with self._connect() as conn:
            if profile:
                row = conn.execute(
                    "SELECT COUNT(*) AS cnt FROM resources "
                    "WHERE provider = ? AND account_or_project = ?",
                    (provider, profile),
                ).fetchone()
            else:
                row = conn.execute(
                    "SELECT COUNT(*) AS cnt FROM resources WHERE provider = ?",
                    (provider,),
                ).fetchone()
            return row["cnt"] > 0

    def staleness_minutes(self, account_or_project: str | None = None) -> int:
        """Minutes since the last completed scan.  Returns -1 if no scans."""
        with self._connect() as conn:
            if account_or_project:
                row = conn.execute(
                    "SELECT MAX(completed_at) AS last "
                    "FROM scan_log WHERE account_or_project = ?",
                    (account_or_project,),
                ).fetchone()
            else:
                row = conn.execute(
                    "SELECT MAX(completed_at) AS last FROM scan_log"
                ).fetchone()

            if row is None or row["last"] is None:
                return -1

            last_ts = row["last"]
            if isinstance(last_ts, str):
                last_dt = datetime.fromisoformat(last_ts)
            else:
                last_dt = last_ts

            # Ensure timezone-aware comparison.
            if last_dt.tzinfo is None:
                last_dt = last_dt.replace(tzinfo=timezone.utc)

            delta = datetime.now(timezone.utc) - last_dt
            return int(delta.total_seconds() / 60)

    # ------------------------------------------------------------------
    # Resource look-up
    # ------------------------------------------------------------------

    def find_resource(self, identifier: str) -> dict | None:
        """Search for a resource by ARN (exact), name (exact), or ARN substring."""
        with self._connect() as conn:
            # 1. Exact ARN match.
            row = conn.execute(
                "SELECT * FROM resources WHERE arn = ?", (identifier,)
            ).fetchone()
            if row:
                return self._row_to_dict(row)

            # 2. Exact name match.
            row = conn.execute(
                "SELECT * FROM resources WHERE name = ?", (identifier,)
            ).fetchone()
            if row:
                return self._row_to_dict(row)

            # 3. Substring match on ARN (e.g. resource ID portion).
            row = conn.execute(
                "SELECT * FROM resources WHERE arn LIKE ? LIMIT 1",
                (f"%{identifier}%",),
            ).fetchone()
            if row:
                return self._row_to_dict(row)

        return None

    # ------------------------------------------------------------------
    # Graph traversal
    # ------------------------------------------------------------------

    def get_connections(self, arn: str, hops: int = 2) -> list[dict]:
        """Return all related resources within *hops* relationship hops.

        Each returned dict contains:
            arn, resource_type, name, environment, is_active,
            relationship (rel_type), direction ("outgoing" | "incoming").
        """
        visited: set[str] = {arn}
        results: list[dict] = []
        frontier: set[str] = {arn}

        with self._connect() as conn:
            for _ in range(hops):
                if not frontier:
                    break
                next_frontier: set[str] = set()
                for current in frontier:
                    # Outgoing edges.
                    rows = conn.execute(
                        "SELECT r.arn, r.resource_type, r.name, r.environment, "
                        "r.is_active, rel.rel_type "
                        "FROM relationships rel "
                        "JOIN resources r ON r.arn = rel.target_arn "
                        "WHERE rel.source_arn = ?",
                        (current,),
                    ).fetchall()
                    for row in rows:
                        d = dict(row)
                        target = d["arn"]
                        if target not in visited:
                            visited.add(target)
                            next_frontier.add(target)
                            results.append({
                                "arn": d["arn"],
                                "resource_type": d["resource_type"],
                                "name": d["name"],
                                "environment": d["environment"],
                                "is_active": d["is_active"],
                                "relationship": d["rel_type"],
                                "direction": "outgoing",
                            })

                    # Incoming edges.
                    rows = conn.execute(
                        "SELECT r.arn, r.resource_type, r.name, r.environment, "
                        "r.is_active, rel.rel_type "
                        "FROM relationships rel "
                        "JOIN resources r ON r.arn = rel.source_arn "
                        "WHERE rel.target_arn = ?",
                        (current,),
                    ).fetchall()
                    for row in rows:
                        d = dict(row)
                        source = d["arn"]
                        if source not in visited:
                            visited.add(source)
                            next_frontier.add(source)
                            results.append({
                                "arn": d["arn"],
                                "resource_type": d["resource_type"],
                                "name": d["name"],
                                "environment": d["environment"],
                                "is_active": d["is_active"],
                                "relationship": d["rel_type"],
                                "direction": "incoming",
                            })

                frontier = next_frontier

        return results

    def get_dependents(self, arn: str) -> list[dict]:
        """Return resources that depend on *arn* (incoming relationships)."""
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT r.arn, r.resource_type, r.name, r.environment, "
                "r.is_active, rel.rel_type "
                "FROM relationships rel "
                "JOIN resources r ON r.arn = rel.source_arn "
                "WHERE rel.target_arn = ?",
                (arn,),
            ).fetchall()
            return [
                {
                    "arn": dict(row)["arn"],
                    "resource_type": dict(row)["resource_type"],
                    "name": dict(row)["name"],
                    "environment": dict(row)["environment"],
                    "is_active": dict(row)["is_active"],
                    "relationship": dict(row)["rel_type"],
                    "direction": "incoming",
                }
                for row in rows
            ]

    # ------------------------------------------------------------------
    # Mutations
    # ------------------------------------------------------------------

    def upsert_resource(self, resource: dict) -> None:
        """Insert or update a resource record.

        *resource* must contain at least ``arn``, ``provider``, ``service``,
        and ``resource_type``.
        """
        now = datetime.now(timezone.utc).isoformat()

        # Auto-classify environment if not explicitly provided.
        env = resource.get("environment")
        if not env or env == "unknown":
            env = classify_environment(
                resource.get("tags"), resource.get("name")
            )

        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO resources
                    (arn, provider, service, resource_type, name, region,
                     account_or_project, environment, is_active,
                     activity_summary, metadata, tags, last_scanned)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(arn) DO UPDATE SET
                    provider          = excluded.provider,
                    service           = excluded.service,
                    resource_type     = excluded.resource_type,
                    name              = COALESCE(excluded.name, resources.name),
                    region            = COALESCE(excluded.region, resources.region),
                    account_or_project = COALESCE(excluded.account_or_project, resources.account_or_project),
                    environment       = excluded.environment,
                    is_active         = COALESCE(excluded.is_active, resources.is_active),
                    activity_summary  = COALESCE(excluded.activity_summary, resources.activity_summary),
                    metadata          = COALESCE(excluded.metadata, resources.metadata),
                    tags              = COALESCE(excluded.tags, resources.tags),
                    last_scanned      = excluded.last_scanned
                """,
                (
                    resource["arn"],
                    resource["provider"],
                    resource["service"],
                    resource["resource_type"],
                    resource.get("name"),
                    resource.get("region"),
                    resource.get("account_or_project"),
                    env,
                    resource.get("is_active"),
                    resource.get("activity_summary"),
                    self._to_json(resource.get("metadata")),
                    self._to_json(resource.get("tags")),
                    now,
                ),
            )

    def upsert_relationship(
        self,
        source_arn: str,
        target_arn: str,
        rel_type: str,
        metadata: dict | None = None,
    ) -> None:
        """Insert or update a relationship between two resources."""
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO relationships (source_arn, target_arn, rel_type, metadata)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(source_arn, target_arn, rel_type) DO UPDATE SET
                    metadata = excluded.metadata
                """,
                (source_arn, target_arn, rel_type, self._to_json(metadata)),
            )

    # ------------------------------------------------------------------
    # Scan log
    # ------------------------------------------------------------------

    def log_scan(
        self,
        provider: str,
        account_or_project: str,
        resource_count: int,
        relationship_count: int,
    ) -> None:
        """Record a completed scan."""
        now = datetime.now(timezone.utc).isoformat()
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO scan_log
                    (provider, account_or_project, started_at, completed_at,
                     resource_count, relationship_count)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (provider, account_or_project, now, now, resource_count, relationship_count),
            )

    def get_scan_summary(self) -> dict:
        """Return an overview of the current graph state.

        Keys: ``resource_count``, ``relationship_count``,
              ``environment_breakdown``, ``last_scan_time``.
        """
        with self._connect() as conn:
            res_count = conn.execute(
                "SELECT COUNT(*) AS cnt FROM resources"
            ).fetchone()["cnt"]

            rel_count = conn.execute(
                "SELECT COUNT(*) AS cnt FROM relationships"
            ).fetchone()["cnt"]

            env_rows = conn.execute(
                "SELECT environment, COUNT(*) AS cnt "
                "FROM resources GROUP BY environment"
            ).fetchall()
            env_breakdown = {row["environment"]: row["cnt"] for row in env_rows}

            last_row = conn.execute(
                "SELECT MAX(completed_at) AS last FROM scan_log"
            ).fetchone()
            last_scan = last_row["last"] if last_row else None

        return {
            "resource_count": res_count,
            "relationship_count": rel_count,
            "environment_breakdown": env_breakdown,
            "last_scan_time": last_scan,
        }

    # ------------------------------------------------------------------
    # Incremental fetch (placeholder)
    # ------------------------------------------------------------------

    def incremental_fetch(
        self, provider: str, service: str, resource_id: str
    ) -> None:
        """Placeholder -- actual fetching is performed by scanner modules."""
        return None

    # ------------------------------------------------------------------
    # Clearing data
    # ------------------------------------------------------------------

    def clear(self, account_or_project: str | None = None) -> None:
        """Remove resources and their relationships.

        If *account_or_project* is given, only resources belonging to that
        account are deleted; otherwise the entire graph is wiped.
        """
        with self._connect() as conn:
            if account_or_project:
                # Delete relationships that reference the account's resources.
                conn.execute(
                    "DELETE FROM relationships WHERE source_arn IN "
                    "(SELECT arn FROM resources WHERE account_or_project = ?)",
                    (account_or_project,),
                )
                conn.execute(
                    "DELETE FROM relationships WHERE target_arn IN "
                    "(SELECT arn FROM resources WHERE account_or_project = ?)",
                    (account_or_project,),
                )
                conn.execute(
                    "DELETE FROM resources WHERE account_or_project = ?",
                    (account_or_project,),
                )
                conn.execute(
                    "DELETE FROM scan_log WHERE account_or_project = ?",
                    (account_or_project,),
                )
            else:
                conn.execute("DELETE FROM relationships")
                conn.execute("DELETE FROM resources")
                conn.execute("DELETE FROM scan_log")
