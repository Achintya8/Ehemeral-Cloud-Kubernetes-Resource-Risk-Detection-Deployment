from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path
from typing import Any, Dict, List

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "security_events.db"
_DB_LOCK = threading.Lock()


def get_connection() -> sqlite3.Connection:
    connection = sqlite3.connect(DB_PATH, check_same_thread=False)
    connection.row_factory = sqlite3.Row
    return connection


def _seed_users(connection: sqlite3.Connection) -> None:
    from auth import hash_password

    seed_users = [
        ("analyst1", hash_password("hackathon"), "analyst"),
        ("admin1", hash_password("hackathon"), "admin"),
    ]
    connection.executemany(
        """
        INSERT OR IGNORE INTO users (username, hashed_password, role)
        VALUES (?, ?, ?)
        """,
        seed_users,
    )


def _ensure_column(connection: sqlite3.Connection, table: str, column_name: str, definition: str) -> None:
    columns = connection.execute(f"PRAGMA table_info({table})").fetchall()
    if any(col[1] == column_name for col in columns):
        return
    connection.execute(f"ALTER TABLE {table} ADD COLUMN {column_name} {definition}")


def init_db() -> None:
    with _DB_LOCK:
        connection = get_connection()
        try:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_id TEXT UNIQUE DEFAULT 'unknown',
                    timestamp DATETIME NOT NULL DEFAULT '1970-01-01T00:00:00Z',
                    log_type TEXT NOT NULL DEFAULT 'k8s_audit',
                    severity TEXT NOT NULL DEFAULT 'INFO',
                    event_name TEXT NOT NULL DEFAULT 'unknown',
                    event_source TEXT NOT NULL DEFAULT 'unknown',
                    principal_id TEXT NOT NULL DEFAULT 'unknown',
                    source_ip TEXT NOT NULL DEFAULT '0.0.0.0',
                    verb TEXT NOT NULL DEFAULT 'unknown',
                    resource_name TEXT NOT NULL DEFAULT 'unknown',
                    namespace TEXT NOT NULL DEFAULT 'default',
                    is_privileged INTEGER NOT NULL DEFAULT 0,
                    risk_score REAL NOT NULL DEFAULT 0.0,
                    user_agent TEXT NOT NULL DEFAULT 'unknown',
                    actor TEXT NOT NULL DEFAULT 'unknown',
                    action TEXT NOT NULL DEFAULT 'unknown',
                    resource_id TEXT NOT NULL DEFAULT 'unknown',
                    region TEXT NOT NULL DEFAULT 'local',
                    is_anomaly INTEGER NOT NULL DEFAULT 0,
                    cluster_id TEXT DEFAULT NULL,
                    payload_json TEXT NOT NULL DEFAULT '{}'
                );

                CREATE TABLE IF NOT EXISTS incidents (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    incident_id TEXT UNIQUE,
                    cluster_id TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    report_text TEXT NOT NULL,
                    pivot_ip TEXT NOT NULL,
                    resource_count INTEGER NOT NULL,
                    node_count INTEGER NOT NULL,
                    related_event_ids TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    hashed_password TEXT NOT NULL,
                    role TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS monitored_pipelines (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    repo_name TEXT NOT NULL,
                    target_namespace TEXT NOT NULL,
                    secret_token TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'active'
                );

                CREATE TABLE IF NOT EXISTS quarantine_blocklist (
                    id            INTEGER PRIMARY KEY AUTOINCREMENT,
                    principal_id  TEXT NOT NULL,
                    source_ip     TEXT NOT NULL DEFAULT '',
                    namespace     TEXT NOT NULL DEFAULT 'default',
                    incident_id   TEXT,
                    action_type   TEXT NOT NULL,
                    operator      TEXT NOT NULL DEFAULT 'system',
                    created_at    TEXT NOT NULL,
                    status        TEXT NOT NULL DEFAULT 'active'
                );
                CREATE INDEX IF NOT EXISTS idx_blocklist_principal
                    ON quarantine_blocklist(principal_id) WHERE status = 'active';

                CREATE TABLE IF NOT EXISTS action_log (
                    id               INTEGER PRIMARY KEY AUTOINCREMENT,
                    incident_id      TEXT,
                    action_type      TEXT NOT NULL,
                    target_resource  TEXT NOT NULL,
                    namespace        TEXT NOT NULL DEFAULT 'default',
                    source_ip        TEXT NOT NULL DEFAULT '',
                    principal_id     TEXT NOT NULL DEFAULT '',
                    operator         TEXT NOT NULL,
                    result           TEXT NOT NULL DEFAULT 'success',
                    message          TEXT NOT NULL DEFAULT '',
                    created_at       TEXT NOT NULL
                );
                """
            )
            # Self-healing column checks for backward compatibility
            _ensure_column(connection, "events", "log_type", "TEXT NOT NULL DEFAULT 'k8s_audit'")
            _ensure_column(connection, "events", "severity", "TEXT NOT NULL DEFAULT 'INFO'")
            _ensure_column(connection, "events", "event_name", "TEXT NOT NULL DEFAULT 'unknown'")
            _ensure_column(connection, "events", "event_source", "TEXT NOT NULL DEFAULT 'unknown'")
            _ensure_column(connection, "events", "principal_id", "TEXT NOT NULL DEFAULT 'unknown'")
            _ensure_column(connection, "events", "verb", "TEXT NOT NULL DEFAULT 'unknown'")
            _ensure_column(connection, "events", "resource_name", "TEXT NOT NULL DEFAULT 'unknown'")
            _ensure_column(connection, "events", "namespace", "TEXT NOT NULL DEFAULT 'default'")
            _ensure_column(connection, "events", "is_privileged", "INTEGER NOT NULL DEFAULT 0")
            _ensure_column(connection, "events", "risk_score", "REAL NOT NULL DEFAULT 0.0")
            _ensure_column(connection, "events", "payload_json", "TEXT NOT NULL DEFAULT '{}'")
            
            _ensure_column(connection, "incidents", "status", "TEXT NOT NULL DEFAULT 'active'")
            
            # Backfill monitored_pipelines with a sample seed for convenience
            connection.execute(
                "INSERT OR IGNORE INTO monitored_pipelines (id, repo_name, target_namespace, secret_token, status) VALUES (1, ?, ?, ?, ?)",
                ("example/repo", "ci-build", "seed-token", "active"),
            )
            _seed_users(connection)
            connection.commit()
        finally:
            connection.close()


def add_pipeline(repo_name: str, target_namespace: str, secret_token: str, status: str = "active") -> int:
    with _DB_LOCK:
        connection = get_connection()
        try:
            cursor = connection.execute(
                "INSERT INTO monitored_pipelines (repo_name, target_namespace, secret_token, status) VALUES (?, ?, ?, ?)",
                (repo_name, target_namespace, secret_token, status),
            )
            connection.commit()
            return int(cursor.lastrowid)
        finally:
            connection.close()


def activate_pipeline(pipeline_id: int) -> bool:
    with _DB_LOCK:
        connection = get_connection()
        try:
            cursor = connection.execute(
                "UPDATE monitored_pipelines SET status = ? WHERE id = ? AND status = ?",
                ("active", pipeline_id, "pending"),
            )
            connection.commit()
            return cursor.rowcount == 1
        finally:
            connection.close()


def list_pipelines() -> List[Dict[str, Any]]:
    connection = get_connection()
    try:
        rows = connection.execute(
            "SELECT id, repo_name, target_namespace, secret_token, status FROM monitored_pipelines ORDER BY id DESC"
        ).fetchall()
        return [dict(row) for row in rows]
    finally:
        connection.close()


def fetch_active_pipelines() -> List[Dict[str, Any]]:
    connection = get_connection()
    try:
        rows = connection.execute(
            "SELECT id, repo_name, target_namespace, secret_token FROM monitored_pipelines WHERE status = 'active'"
        ).fetchall()
        return [dict(row) for row in rows]
    finally:
        connection.close()


def insert_event(event: Dict[str, Any]) -> int:
    with _DB_LOCK:
        connection = get_connection()
        try:
            cursor = connection.execute(
                """
                INSERT OR REPLACE INTO events (
                    event_id, timestamp, log_type, severity, event_name, event_source,
                    principal_id, source_ip, verb, resource_name, namespace, is_privileged,
                    risk_score, user_agent, actor, action, resource_id, region, is_anomaly,
                    cluster_id, payload_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event.get("event_id") or "unknown",
                    event.get("timestamp") or "1970-01-01T00:00:00Z",
                    event.get("log_type") or "unknown",
                    event.get("severity") or "INFO",
                    event.get("event_name") or "unknown",
                    event.get("event_source") or "unknown",
                    event.get("principal_id") or "unknown",
                    event.get("source_ip") or "0.0.0.0",
                    event.get("verb") or "unknown",
                    event.get("resource_name") or "unknown",
                    event.get("namespace") or "default",
                    int(event.get("is_privileged") or 0),
                    float(event.get("risk_score") or 0.0),
                    event.get("user_agent") or "unknown",
                    event.get("actor") or "unknown",
                    event.get("action") or "unknown",
                    event.get("resource_id") or "unknown",
                    event.get("region") or "local",
                    int(bool(event.get("is_anomaly", False))),
                    event.get("cluster_id"),
                    json.dumps(event, ensure_ascii=False),
                ),
            )
            connection.commit()
            return int(cursor.lastrowid)
        finally:
            connection.close()


def insert_incident(record: Dict[str, Any]) -> int:
    with _DB_LOCK:
        connection = get_connection()
        try:
            cursor = connection.execute(
                """
                INSERT OR REPLACE INTO incidents (
                    incident_id, cluster_id, created_at, severity, report_text,
                    pivot_ip, resource_count, node_count, related_event_ids
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    record.get("incident_id"),
                    record.get("cluster_id"),
                    record.get("created_at"),
                    record.get("severity"),
                    record.get("report_text"),
                    record.get("pivot_ip"),
                    int(record.get("resource_count", 0)),
                    int(record.get("node_count", 0)),
                    json.dumps(record.get("related_event_ids", []), ensure_ascii=False),
                ),
            )
            connection.commit()
            return int(cursor.lastrowid)
        finally:
            connection.close()


def resolve_incident(incident_id: str) -> None:
    with _DB_LOCK:
        connection = get_connection()
        try:
            connection.execute(
                "UPDATE incidents SET status = 'resolved' WHERE incident_id = ?",
                (incident_id,)
            )
            connection.commit()
        finally:
            connection.close()


# ── Quarantine blocklist ──────────────────────────────────────────────────────
# Persistent record of sources (by principal_id / SA) that an analyst has
# already contained.  Re-runs from a blocklisted principal are suppressed at
# incident-emission time (ml_pipeline) so they don't fire fresh HIGH alerts.

_BLOCKLIST_PRINCIPAL_IGNORE = {"", "unknown", "none", "nan", "system"}


def add_blocklist_entry(
    principal_id: str,
    source_ip: str = "",
    namespace: str = "default",
    incident_id: str | None = None,
    action_type: str = "contain_pods",
    operator: str = "system",
) -> None:
    """Idempotently record (or refresh) a blocklist entry for a principal.
    Re-acting on the same SA bumps created_at + latest incident rather than
    inserting a duplicate row."""
    if not principal_id or principal_id.lower() in _BLOCKLIST_PRINCIPAL_IGNORE:
        return
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    with _DB_LOCK:
        connection = get_connection()
        try:
            existing = connection.execute(
                "SELECT id FROM quarantine_blocklist WHERE principal_id = ? AND status = 'active'",
                (principal_id,),
            ).fetchone()
            if existing:
                connection.execute(
                    """UPDATE quarantine_blocklist
                       SET source_ip = ?, namespace = ?, incident_id = ?,
                           action_type = ?, operator = ?, created_at = ?
                       WHERE id = ?""",
                    (source_ip, namespace, incident_id, action_type, operator, now, existing["id"]),
                )
            else:
                connection.execute(
                    """INSERT INTO quarantine_blocklist
                       (principal_id, source_ip, namespace, incident_id,
                        action_type, operator, created_at, status)
                       VALUES (?, ?, ?, ?, ?, ?, ?, 'active')""",
                    (principal_id, source_ip, namespace, incident_id, action_type, operator, now),
                )
            connection.commit()
        finally:
            connection.close()


def is_principal_blocklisted(principal_id: str) -> Dict[str, Any] | None:
    """Return the active blocklist entry for a principal, or None."""
    if not principal_id or principal_id.lower() in _BLOCKLIST_PRINCIPAL_IGNORE:
        return None
    connection = get_connection()
    try:
        row = connection.execute(
            """SELECT principal_id, source_ip, namespace, incident_id,
                      action_type, operator, created_at, status
               FROM quarantine_blocklist
               WHERE principal_id = ? AND status = 'active'
               ORDER BY id DESC LIMIT 1""",
            (principal_id,),
        ).fetchone()
        return dict(row) if row else None
    finally:
        connection.close()


def fetch_active_blocklist() -> List[Dict[str, Any]]:
    connection = get_connection()
    try:
        rows = connection.execute(
            """SELECT principal_id, source_ip, namespace, incident_id,
                      action_type, operator, created_at
               FROM quarantine_blocklist
               WHERE status = 'active'
               ORDER BY created_at DESC"""
        ).fetchall()
        return [dict(row) for row in rows]
    finally:
        connection.close()


def release_blocklist_entry(principal_id: str) -> bool:
    """Manually unblock a principal.  Returns True if a row was updated."""
    if not principal_id:
        return False
    with _DB_LOCK:
        connection = get_connection()
        try:
            cursor = connection.execute(
                "UPDATE quarantine_blocklist SET status = 'released' WHERE principal_id = ? AND status = 'active'",
                (principal_id,),
            )
            connection.commit()
            return cursor.rowcount >= 1
        finally:
            connection.close()


def fetch_recent_events(limit: int = 100) -> List[Dict[str, Any]]:
    connection = get_connection()
    try:
        rows = connection.execute(
            """
            SELECT event_id, timestamp, log_type, severity, event_name, event_source,
                   principal_id, source_ip, verb, resource_name, namespace, is_privileged,
                   risk_score, user_agent, actor, action, resource_id, region, is_anomaly,
                   cluster_id
            FROM events
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
        return [dict(row) for row in rows]
    finally:
        connection.close()


def fetch_recent_incidents(limit: int = 25) -> List[Dict[str, Any]]:
    connection = get_connection()
    try:
        rows = connection.execute(
            """
            SELECT incident_id, cluster_id, created_at, severity, report_text,
                   pivot_ip, resource_count, node_count, related_event_ids
            FROM incidents
            WHERE status != 'resolved'
              AND (severity IN ('CRITICAL', 'HIGH', 'MEDIUM') OR node_count > 0)
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
        incidents: List[Dict[str, Any]] = []
        for row in rows:
            item = dict(row)
            try:
                item["related_event_ids"] = json.loads(item.get("related_event_ids") or "[]")
            except json.JSONDecodeError:
                item["related_event_ids"] = []
            incidents.append(item)
        return incidents
    finally:
        connection.close()


def get_user_by_username(username: str) -> Dict[str, Any] | None:
    connection = get_connection()
    try:
        row = connection.execute(
            "SELECT id, username, hashed_password, role FROM users WHERE username = ?",
            (username,),
        ).fetchone()
        return dict(row) if row else None
    finally:
        connection.close()


def database_size_bytes() -> int:
    return DB_PATH.stat().st_size if DB_PATH.exists() else 0


def stats() -> Dict[str, Any]:
    connection = get_connection()
    try:
        event_count = connection.execute("SELECT COUNT(*) AS total FROM events").fetchone()["total"]
        incident_count = connection.execute("SELECT COUNT(*) AS total FROM incidents").fetchone()["total"]
        user_count = connection.execute("SELECT COUNT(*) AS total FROM users").fetchone()["total"]
        return {
            "events": int(event_count),
            "incidents": int(incident_count),
            "users": int(user_count),
            "database_size_bytes": database_size_bytes(),
            "database_size_kb": round(database_size_bytes() / 1024.0, 2),
        }
    finally:
        connection.close()


# ── Action log ─────────────────────────────────────────────────────────────────
# Append-only record of every analyst remediation action for the activity feed.

def insert_action_log(
    incident_id: str | None,
    action_type: str,
    target_resource: str,
    namespace: str = "default",
    source_ip: str = "",
    principal_id: str = "",
    operator: str = "system",
    result: str = "success",
    message: str = "",
) -> int:
    """Insert a remediation action into the persistent action log. Returns row ID."""
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    with _DB_LOCK:
        connection = get_connection()
        try:
            cursor = connection.execute(
                """INSERT INTO action_log
                   (incident_id, action_type, target_resource, namespace,
                    source_ip, principal_id, operator, result, message, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (incident_id, action_type, target_resource, namespace,
                 source_ip, principal_id, operator, result, message, now),
            )
            connection.commit()
            return int(cursor.lastrowid)
        finally:
            connection.close()


def fetch_action_log(limit: int = 50) -> List[Dict[str, Any]]:
    """Return the most recent action log entries (newest first)."""
    connection = get_connection()
    try:
        rows = connection.execute(
            """SELECT id, incident_id, action_type, target_resource, namespace,
                      source_ip, principal_id, operator, result, message, created_at
               FROM action_log
               ORDER BY id DESC
               LIMIT ?""",
            (limit,),
        ).fetchall()
        return [dict(row) for row in rows]
    finally:
        connection.close()


# ── TTL distribution (Item 10) ────────────────────────────────────────────────
# Six buckets spanning the full ephemeral-resource lifespan range so the
# Analytics chart can show churn vs. long-lived resources.

_TTL_BUCKETS: list[tuple[str, float, float]] = [
    ("0s",       0,     1),
    ("<1m",      1,     60),
    ("1-5m",     60,    300),
    ("5-15m",    300,   900),
    ("15-60m",   900,   3600),
    ("60m+",     3600,  float("inf")),
]


def fetch_ttl_distribution() -> Dict[str, Any]:
    """Aggregate per-resource TTL (max timestamp − min timestamp) into the
    six buckets above.  Returns {labels, counts, total_resources}."""
    connection = get_connection()
    try:
        rows = connection.execute(
            """
            SELECT resource_name,
                   (julianday(MAX(timestamp)) - julianday(MIN(timestamp))) * 86400 AS ttl_seconds
            FROM events
            WHERE resource_name IS NOT NULL
              AND resource_name != ''
              AND resource_name != 'unknown'
            GROUP BY resource_name
            """,
        ).fetchall()
    finally:
        connection.close()

    counts = [0] * len(_TTL_BUCKETS)
    for row in rows:
        try:
            ttl = float(row["ttl_seconds"] or 0)
        except (TypeError, ValueError):
            ttl = 0.0
        for i, (_label, lo, hi) in enumerate(_TTL_BUCKETS):
            if lo <= ttl < hi:
                counts[i] += 1
                break

    return {
        "labels": [label for label, _lo, _hi in _TTL_BUCKETS],
        "counts": counts,
        "total_resources": sum(counts),
    }


# ── Incident drill-down (Item 11) ─────────────────────────────────────────────

def fetch_incident_with_events(incident_id: str) -> Dict[str, Any] | None:
    """Fetch a single incident plus its related telemetry events for the
    drill-down modal.  Returns None if the incident is not found."""
    connection = get_connection()
    try:
        row = connection.execute(
            """
            SELECT incident_id, cluster_id, created_at, severity, report_text,
                   pivot_ip, resource_count, node_count, related_event_ids
            FROM incidents
            WHERE incident_id = ?
            """,
            (incident_id,),
        ).fetchone()
        if row is None:
            return None

        item = dict(row)
        try:
            event_ids = json.loads(item.get("related_event_ids") or "[]")
        except json.JSONDecodeError:
            event_ids = []
        item["related_event_ids"] = event_ids

        # Pull the related event rows for the per-event timeline.
        events: List[Dict[str, Any]] = []
        if event_ids:
            placeholders = ",".join("?" for _ in event_ids)
            rows = connection.execute(
                f"""
                SELECT event_id, timestamp, log_type, severity, event_name, event_source,
                       principal_id, source_ip, verb, resource_name, namespace, is_privileged,
                       risk_score, user_agent, actor, action, resource_id, region, is_anomaly,
                       cluster_id
                FROM events
                WHERE event_id IN ({placeholders})
                ORDER BY timestamp ASC
                """,
                event_ids,
            ).fetchall()
            events = [dict(r) for r in rows]
        item["events"] = events
        return item
    finally:
        connection.close()

def clear_all_events() -> None:
    """Wipes all telemetry events, incidents, and action logs from the database."""
    with _DB_LOCK:
        connection = get_connection()
        try:
            connection.executescript(
                """
                DELETE FROM events;
                DELETE FROM incidents;
                DELETE FROM action_log;
                """
            )
            connection.commit()
        finally:
            connection.close()
