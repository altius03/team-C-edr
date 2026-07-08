"""Persist runs, incidents, events, DLQ rows, outbox rows, and task state."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

from sqlalchemy import desc, select
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from .config import DEFAULT_DATABASE_URL
from . import service_analysis_jobs
from . import service_tasks
from .schema_migrations import assert_service_schema
from .service_analysis_jobs import AnalysisJobState
from .service_models import Base, IncidentRow, RunRow
from .service_tasks import TaskState
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
        engine = self._get_engine()
        Base.metadata.create_all(engine)
        assert_service_schema(engine)

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
        with self._session() as session:
            with session.begin():
                task = service_tasks.enqueue_task(session, task_type, payload, TaskStatus.PENDING.value)
        return _queued_task(task)

    def create_analysis_job(self, job_id: str, celery_task_id: str, input_meta: JsonObject) -> QueuedTask:
        task = QueuedTask(
            task_id=celery_task_id,
            task_type="analysis",
            status=TaskStatus.PENDING,
            payload={"input_meta": input_meta},
            result=None,
            error=None,
        )
        with self._session() as session:
            with session.begin():
                service_analysis_jobs.create_analysis_job(
                    session,
                    job_id,
                    celery_task_id,
                    input_meta,
                    TaskStatus.PENDING.value,
                )
        return task

    def set_analysis_job_task_id(self, job_id: str, celery_task_id: str) -> None:
        with self._session() as session:
            with session.begin():
                service_analysis_jobs.set_analysis_job_task_id(session, job_id, celery_task_id)

    def start_analysis_job(self, job_id: str) -> None:
        with self._session() as session:
            with session.begin():
                service_analysis_jobs.start_analysis_job(session, job_id, TaskStatus.RUNNING.value)

    def complete_analysis_job(self, job_id: str, run_id: str) -> None:
        with self._session() as session:
            with session.begin():
                service_analysis_jobs.complete_analysis_job(session, job_id, run_id, TaskStatus.SUCCEEDED.value)

    def fail_analysis_job(self, job_id: str, error: str) -> None:
        with self._session() as session:
            with session.begin():
                service_analysis_jobs.fail_analysis_job(session, job_id, error, TaskStatus.FAILED.value)

    def claim_next_task(self) -> QueuedTask | None:
        with self._session() as session:
            with session.begin():
                task = service_tasks.claim_next_task(session, TaskStatus.PENDING.value, TaskStatus.RUNNING.value)
        return _queued_task(task) if task is not None else None

    def complete_task(self, task_id: str, status: TaskStatus, result: JsonObject) -> None:
        with self._session() as session:
            with session.begin():
                service_tasks.complete_task(session, task_id, status.value, result)

    def fail_task(self, task_id: str, error: str) -> None:
        with self._session() as session:
            with session.begin():
                service_tasks.fail_task(session, task_id, TaskStatus.FAILED.value, error)

    def get_task(self, task_id: str) -> QueuedTask:
        with self._session() as session:
            task = service_tasks.task_by_id(session, task_id)
            if task is not None:
                return _queued_task(task)
            job = service_analysis_jobs.analysis_job_by_task_id(session, task_id)
            if job is None:
                raise KeyError(task_id)
            return _queued_analysis_job(job)

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


def _queued_analysis_job(job: AnalysisJobState) -> QueuedTask:
    return QueuedTask(
        task_id=job.task_id,
        task_type="analysis",
        status=TaskStatus(job.status),
        payload=job.payload,
        result=job.result,
        error=job.error,
    )


def _queued_task(task: TaskState) -> QueuedTask:
    return QueuedTask(
        task_id=task.task_id,
        task_type=task.task_type,
        status=TaskStatus(task.status),
        payload=task.payload,
        result=task.result,
        error=task.error,
    )


def _sqlite_url(path: Path) -> str:
    """Build a SQLAlchemy SQLite URL from a filesystem path."""

    return f"sqlite:///{path.resolve().as_posix()}"
