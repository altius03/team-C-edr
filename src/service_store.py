"""Persist runs, incidents, events, DLQ rows, outbox rows, and task state."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

from sqlalchemy import desc, select
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from .config import DEFAULT_DATABASE_URL
from .service_models import Base, IncidentRow, RunRow, TaskRow
from .service_store_counts import count_rows
from .service_store_engine import create_store_engine
from .service_store_payloads import JsonObject, JsonValue, dump_json, load_json_object, new_id, now_iso, text_value
from .service_store_rows import OutboxRecord, alert_event_rows, alert_rows, dlq_rows, event_rows, incident_alert_rows, incident_rows, outbox_row, tenant_fields


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
    def __init__(self, db_path: Path | None = None, *, database_url: str | None = None) -> None:
        if db_path is not None and database_url is not None:
            raise ValueError("db_path and database_url cannot both be set")
        self.database_url = database_url or (_sqlite_url(db_path) if db_path is not None else DEFAULT_DATABASE_URL)
        self._sqlite_path = db_path
        self._engine: Engine | None = None
        self._session_factory: sessionmaker[Session] | None = None

    @property
    def storage_label(self) -> str:
        if self.database_url.startswith("sqlite"):
            return "sqlite"
        if self.database_url.startswith("postgresql"):
            return "postgresql"
        return "database"

    def initialize(self) -> None:
        if self._sqlite_path is not None:
            self._sqlite_path.parent.mkdir(parents=True, exist_ok=True)
        Base.metadata.create_all(self._get_engine())

    def close(self) -> None:
        if self._engine is None:
            return
        self._engine.dispose()
        self._engine = None
        self._session_factory = None

    def save_run_result(self, payload: JsonObject) -> str:
        run_id = new_id("run")
        customer_id, tenant_id = tenant_fields(payload)
        with self._session() as session:
            with session.begin():
                session.add(
                    RunRow(
                        run_id=run_id,
                        generated_at=text_value(payload.get("generated_at")) or now_iso(),
                        status=text_value(payload.get("status")) or "unknown",
                        decision=text_value(payload.get("decision")) or "unknown",
                        customer_id=customer_id,
                        tenant_id=tenant_id,
                        payload=dump_json(payload),
                    )
                )
                session.flush()
                session.add_all(event_rows(run_id, payload))
                session.flush()
                session.add_all(alert_rows(run_id, payload))
                session.flush()
                session.add_all(incident_rows(run_id, payload))
                session.flush()
                session.add_all(alert_event_rows(run_id, payload))
                session.add_all(incident_alert_rows(run_id, payload))
                session.add_all(dlq_rows(run_id, payload))
                session.add(
                    outbox_row(
                        OutboxRecord(
                            event_type="analysis.run_saved",
                            aggregate_type="run",
                            aggregate_id=run_id,
                            payload={
                                "run_id": run_id,
                                "status": text_value(payload.get("status")) or "unknown",
                                "decision": text_value(payload.get("decision")) or "unknown",
                            },
                        )
                    )
                )
        return run_id

    def get_latest_run(self) -> JsonObject | None:
        """Return the most recent stored run payload, if any exists."""

        with self._session() as session:
            payload = session.scalars(select(RunRow.payload).order_by(desc(RunRow.generated_at), desc(RunRow.run_id)).limit(1)).first()
        if payload is None:
            return None
        return load_json_object(payload)

    def list_incidents(self, severity: str | None = None, limit: int = 50) -> list[JsonObject]:
        """Return incident payloads ordered by risk with an optional severity filter."""

        statement = select(IncidentRow.payload).order_by(desc(IncidentRow.risk_score)).limit(limit)
        if severity:
            statement = statement.where(IncidentRow.severity == severity)
        with self._session() as session:
            rows = session.scalars(statement).all()
        return [load_json_object(row) for row in rows]

    def count_events(self) -> int:
        """Count normalized telemetry event rows."""

        return self._count_rows("events")

    def count_alerts(self) -> int:
        """Count normalized alert rows."""

        return self._count_rows("alerts")

    def count_alert_events(self) -> int:
        return self._count_rows("alert_events")

    def count_incident_alerts(self) -> int:
        return self._count_rows("incident_alerts")

    def count_dlq_events(self) -> int:
        """Count dead-letter telemetry rows."""

        return self._count_rows("dlq_events")

    def count_outbox_events(self) -> int:
        """Count pending or recorded outbox rows."""

        return self._count_rows("outbox_events")

    def enqueue_task(self, task_type: str, payload: JsonObject) -> QueuedTask:
        """Persist a pending task and emit the matching outbox event."""

        task = QueuedTask(
            task_id=new_id("task"),
            task_type=task_type,
            status=TaskStatus.PENDING,
            payload=payload,
            result=None,
            error=None,
        )
        now = now_iso()
        with self._session() as session:
            with session.begin():
                session.add(
                    TaskRow(
                        task_id=task.task_id,
                        task_type=task.task_type,
                        status=task.status.value,
                        created_at=now,
                        updated_at=now,
                        payload=dump_json(task.payload),
                        result=None,
                        error=None,
                    )
                )
                session.add(
                    outbox_row(
                        OutboxRecord(
                            event_type="task.enqueued",
                            aggregate_type="task",
                            aggregate_id=task.task_id,
                            payload={"task_id": task.task_id, "task_type": task.task_type},
                        )
                    )
                )
        return task

    def claim_next_task(self) -> QueuedTask | None:
        """Atomically move the oldest pending task to running state."""

        with self._session() as session:
            with session.begin():
                row = session.scalars(
                    select(TaskRow).where(TaskRow.status == TaskStatus.PENDING.value).order_by(TaskRow.created_at).limit(1)
                ).first()
                if row is None:
                    return None
                row.status = TaskStatus.RUNNING.value
                row.updated_at = now_iso()
                task = _queued_task(row, TaskStatus.RUNNING)
        return task

    def complete_task(self, task_id: str, status: TaskStatus, result: JsonObject) -> None:
        """Store task completion state, result JSON, and an outbox event."""

        with self._session() as session:
            with session.begin():
                row = _require_task_row(session, task_id)
                row.status = status.value
                row.updated_at = now_iso()
                row.result = dump_json(result)
                row.error = None
                session.add(
                    outbox_row(
                        OutboxRecord(
                            event_type="task.completed",
                            aggregate_type="task",
                            aggregate_id=task_id,
                            payload={"task_id": task_id, "status": status.value},
                        )
                    )
                )

    def fail_task(self, task_id: str, error: str) -> None:
        """Store task failure details and emit a failure outbox event."""

        with self._session() as session:
            with session.begin():
                row = _require_task_row(session, task_id)
                row.status = TaskStatus.FAILED.value
                row.updated_at = now_iso()
                row.result = None
                row.error = error
                session.add(
                    outbox_row(
                        OutboxRecord(
                            event_type="task.failed",
                            aggregate_type="task",
                            aggregate_id=task_id,
                            payload={"task_id": task_id, "status": TaskStatus.FAILED.value},
                        )
                    )
                )

    def get_task(self, task_id: str) -> QueuedTask:
        """Load one queued task by identifier or raise when it is absent."""

        with self._session() as session:
            row = session.get(TaskRow, task_id)
            if row is None:
                raise KeyError(task_id)
            return _queued_task(row, TaskStatus(row.status))

    def _count_rows(self, table: str) -> int:
        with self._session() as session:
            return count_rows(session, table)

    def _get_engine(self) -> Engine:
        """Create or reuse the SQLAlchemy engine with backend-specific options."""

        if self._engine is None:
            self._engine = create_store_engine(self.database_url, self.storage_label)
        return self._engine

    def _session(self) -> Session:
        """Return a new SQLAlchemy session from the cached factory."""

        if self._session_factory is None:
            self._session_factory = sessionmaker(self._get_engine(), expire_on_commit=False, future=True)
        return self._session_factory()


def _require_task_row(session: Session, task_id: str) -> TaskRow:
    """Return a task row from an active session or raise KeyError."""

    row = session.get(TaskRow, task_id)
    if row is None:
        raise KeyError(task_id)
    return row


def _queued_task(row: TaskRow, status: TaskStatus) -> QueuedTask:
    """Map a persisted task row into the typed queue contract."""

    return QueuedTask(
        task_id=row.task_id,
        task_type=row.task_type,
        status=status,
        payload=load_json_object(row.payload),
        result=load_json_object(row.result) if row.result else None,
        error=row.error,
    )


def _sqlite_url(path: Path) -> str:
    """Build a SQLAlchemy SQLite URL from a filesystem path."""

    return f"sqlite:///{path.resolve().as_posix()}"
