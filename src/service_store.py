from __future__ import annotations

import json
import sqlite3
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from pathlib import Path
from typing import TypeAlias

from .config import SERVICE_DB_PATH

JsonValue: TypeAlias = str | int | float | bool | None | list["JsonValue"] | dict[str, "JsonValue"]
JsonObject: TypeAlias = dict[str, JsonValue]


class TaskStatus(StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"


@dataclass(frozen=True, slots=True)
class QueuedTask:
    task_id: str
    task_type: str
    status: TaskStatus
    payload: JsonObject
    result: JsonObject | None
    error: str | None = None


class ServiceStore:
    """SQLite-backed service boundary for runs, incidents, and queued jobs."""

    def __init__(self, db_path: Path = SERVICE_DB_PATH) -> None:
        self.db_path = db_path

    def initialize(self) -> None:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        with self._connection() as connection:
            # Keep the full run payload for dashboard rendering, but also split
            # common analyst queries into indexed tables for incidents, alerts,
            # and telemetry events.
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS runs (
                    run_id TEXT PRIMARY KEY,
                    generated_at TEXT NOT NULL,
                    status TEXT NOT NULL,
                    decision TEXT NOT NULL,
                    payload TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS incidents (
                    run_id TEXT NOT NULL,
                    incident_id TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    risk_score INTEGER NOT NULL,
                    host_display_name TEXT NOT NULL,
                    payload TEXT NOT NULL,
                    PRIMARY KEY (run_id, incident_id)
                );
                CREATE TABLE IF NOT EXISTS alerts (
                    run_id TEXT NOT NULL,
                    alert_id TEXT NOT NULL,
                    rule_id TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    risk_score INTEGER NOT NULL,
                    host_id TEXT NOT NULL,
                    event_time TEXT NOT NULL,
                    payload TEXT NOT NULL,
                    PRIMARY KEY (run_id, alert_id)
                );
                CREATE TABLE IF NOT EXISTS events (
                    run_id TEXT NOT NULL,
                    event_id TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    host_id TEXT NOT NULL,
                    event_time TEXT NOT NULL,
                    process_name TEXT NOT NULL,
                    destination TEXT NOT NULL,
                    payload TEXT NOT NULL,
                    PRIMARY KEY (run_id, event_id)
                );
                CREATE TABLE IF NOT EXISTS tasks (
                    task_id TEXT PRIMARY KEY,
                    task_type TEXT NOT NULL,
                    status TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    payload TEXT NOT NULL,
                    result TEXT,
                    error TEXT
                );
                CREATE INDEX IF NOT EXISTS idx_incidents_severity ON incidents(severity);
                CREATE INDEX IF NOT EXISTS idx_alerts_host_severity ON alerts(host_id, severity);
                CREATE INDEX IF NOT EXISTS idx_events_host_type ON events(host_id, event_type);
                """
            )

    def save_run_result(self, payload: JsonObject) -> str:
        run_id = _new_id("run")
        generated_at = _text(payload.get("generated_at")) or _now()
        status = _text(payload.get("status")) or "unknown"
        decision = _text(payload.get("decision")) or "unknown"
        events = _json_list(payload.get("events"))
        alerts = _json_list(payload.get("alerts"))
        incidents = _json_list(payload.get("incidents"))
        with self._connection() as connection:
            # A saved run is the immutable analysis snapshot; child rows make
            # server-side filtering possible without reparsing the JSON blob.
            connection.execute(
                "INSERT INTO runs(run_id, generated_at, status, decision, payload) VALUES (?, ?, ?, ?, ?)",
                (run_id, generated_at, status, decision, _dumps(payload)),
            )
            for event in events:
                connection.execute(
                    """
                    INSERT INTO events(run_id, event_id, event_type, host_id, event_time, process_name, destination, payload)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        run_id,
                        _text(event.get("event_id")) or _new_id("event"),
                        _text(event.get("event_type")) or "unknown",
                        _text(event.get("host_id")) or "unknown",
                        _text(event.get("event_time")),
                        _text(event.get("process_name")) or "-",
                        _text(event.get("domain")) or _text(event.get("dst_ip")) or "-",
                        _dumps(event),
                    ),
                )
            for alert in alerts:
                connection.execute(
                    """
                    INSERT INTO alerts(run_id, alert_id, rule_id, severity, risk_score, host_id, event_time, payload)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        run_id,
                        _text(alert.get("alert_id")) or _new_id("alert"),
                        _text(alert.get("rule_id")) or "unknown",
                        _text(alert.get("severity")) or "info",
                        _int(alert.get("risk_score")),
                        _text(alert.get("host_id")) or "unknown",
                        _text(alert.get("event_time")),
                        _dumps(alert),
                    ),
                )
            for incident in incidents:
                connection.execute(
                    """
                    INSERT INTO incidents(run_id, incident_id, severity, risk_score, host_display_name, payload)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        run_id,
                        _text(incident.get("incident_id")) or _new_id("incident"),
                        _text(incident.get("severity")) or "info",
                        _int(incident.get("risk_score")),
                        _text(incident.get("host_display_name")) or _text(incident.get("host_id")) or "unknown",
                        _dumps(incident),
                    ),
                )
        return run_id

    def get_latest_run(self) -> JsonObject | None:
        with self._connection() as connection:
            row = connection.execute("SELECT payload FROM runs ORDER BY generated_at DESC, rowid DESC LIMIT 1").fetchone()
        if row is None:
            return None
        return _loads_object(row["payload"])

    def list_incidents(self, severity: str | None = None, limit: int = 50) -> list[JsonObject]:
        params: list[str | int] = []
        query = "SELECT payload FROM incidents"
        if severity:
            query += " WHERE severity = ?"
            params.append(severity)
        query += " ORDER BY risk_score DESC LIMIT ?"
        params.append(limit)
        with self._connection() as connection:
            rows = connection.execute(query, params).fetchall()
        return [_loads_object(row["payload"]) for row in rows]

    def count_events(self) -> int:
        return self._count_rows("events")

    def count_alerts(self) -> int:
        return self._count_rows("alerts")

    def enqueue_task(self, task_type: str, payload: JsonObject) -> QueuedTask:
        task = QueuedTask(
            task_id=_new_id("task"),
            task_type=task_type,
            status=TaskStatus.PENDING,
            payload=payload,
            result=None,
            error=None,
        )
        now = _now()
        with self._connection() as connection:
            connection.execute(
                """
                INSERT INTO tasks(task_id, task_type, status, created_at, updated_at, payload, result, error)
                VALUES (?, ?, ?, ?, ?, ?, NULL, NULL)
                """,
                (task.task_id, task.task_type, task.status.value, now, now, _dumps(task.payload)),
            )
        return task

    def claim_next_task(self) -> QueuedTask | None:
        with self._connection() as connection:
            row = connection.execute(
                "SELECT * FROM tasks WHERE status = ? ORDER BY created_at ASC LIMIT 1",
                (TaskStatus.PENDING.value,),
            ).fetchone()
            if row is None:
                return None
            connection.execute(
                "UPDATE tasks SET status = ?, updated_at = ? WHERE task_id = ?",
                (TaskStatus.RUNNING.value, _now(), row["task_id"]),
            )
        return QueuedTask(
            task_id=row["task_id"],
            task_type=row["task_type"],
            status=TaskStatus.RUNNING,
            payload=_loads_object(row["payload"]),
            result=None,
            error=None,
        )

    def complete_task(self, task_id: str, status: TaskStatus, result: JsonObject) -> None:
        with self._connection() as connection:
            connection.execute(
                "UPDATE tasks SET status = ?, updated_at = ?, result = ?, error = NULL WHERE task_id = ?",
                (status.value, _now(), _dumps(result), task_id),
            )

    def fail_task(self, task_id: str, error: str) -> None:
        with self._connection() as connection:
            connection.execute(
                "UPDATE tasks SET status = ?, updated_at = ?, result = NULL, error = ? WHERE task_id = ?",
                (TaskStatus.FAILED.value, _now(), error, task_id),
            )

    def get_task(self, task_id: str) -> QueuedTask:
        with self._connection() as connection:
            row = connection.execute("SELECT * FROM tasks WHERE task_id = ?", (task_id,)).fetchone()
        if row is None:
            raise KeyError(task_id)
        return QueuedTask(
            task_id=row["task_id"],
            task_type=row["task_type"],
            status=TaskStatus(row["status"]),
            payload=_loads_object(row["payload"]),
            result=_loads_object(row["result"]) if row["result"] else None,
            error=row["error"],
        )

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.db_path)
        connection.row_factory = sqlite3.Row
        return connection

    def _count_rows(self, table: str) -> int:
        if table not in {"events", "alerts", "incidents", "runs", "tasks"}:
            raise ValueError(f"unsupported table: {table}")
        with self._connection() as connection:
            row = connection.execute(f"SELECT COUNT(*) AS count FROM {table}").fetchone()
        return int(row["count"])

    @contextmanager
    def _connection(self):
        connection = self._connect()
        try:
            yield connection
            connection.commit()
        finally:
            connection.close()


def _now() -> str:
    return datetime.now().isoformat(timespec="seconds")


def _new_id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:12]}"


def _dumps(value: JsonValue) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def _loads_object(value: str) -> JsonObject:
    parsed = json.loads(value)
    if not isinstance(parsed, dict):
        raise TypeError("stored JSON payload is not an object")
    return parsed


def _json_list(value: JsonValue) -> list[JsonObject]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


def _text(value: JsonValue) -> str:
    return value if isinstance(value, str) else ""


def _int(value: JsonValue) -> int:
    return value if isinstance(value, int) else 0
