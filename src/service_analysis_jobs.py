from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.orm import Session

from .service_models import AnalysisJobRow
from .service_store_payloads import JsonObject, dump_json, load_json_object, now_iso, text_value
from .service_store_rows import OutboxRecord, outbox_row


@dataclass(frozen=True, slots=True)
class AnalysisJobState:
    task_id: str
    status: str
    payload: JsonObject
    result: JsonObject | None
    error: str | None


def create_analysis_job(
    session: Session,
    job_id: str,
    celery_task_id: str,
    input_meta: JsonObject,
    status: str,
) -> None:
    now = now_iso()
    session.add(
        AnalysisJobRow(
            job_id=job_id,
            celery_task_id=celery_task_id,
            status=status,
            created_at=now,
            updated_at=now,
            started_at=None,
            completed_at=None,
            run_id=None,
            customer_id=text_value(input_meta.get("customer_id")) or "unknown",
            tenant_id=text_value(input_meta.get("tenant_id")) or "unknown",
            agent_version=text_value(input_meta.get("agent_version")) or "unknown",
            payload_version=text_value(input_meta.get("payload_version")) or "unknown",
            input_meta=dump_json(input_meta),
            result=None,
            error=None,
        )
    )
    session.add(
        outbox_row(
            OutboxRecord(
                event_type="analysis_job.queued",
                aggregate_type="analysis_job",
                aggregate_id=job_id,
                payload={"task_id": celery_task_id, "status": status},
            )
        )
    )


def set_analysis_job_task_id(session: Session, job_id: str, celery_task_id: str) -> None:
    row = require_analysis_job_row(session, job_id)
    row.celery_task_id = celery_task_id
    row.updated_at = now_iso()


def start_analysis_job(session: Session, job_id: str, status: str) -> None:
    now = now_iso()
    row = require_analysis_job_row(session, job_id)
    row.status = status
    row.started_at = now
    row.updated_at = now


def complete_analysis_job(session: Session, job_id: str, run_id: str, status: str) -> None:
    now = now_iso()
    row = require_analysis_job_row(session, job_id)
    row.status = status
    row.run_id = run_id
    row.completed_at = now
    row.updated_at = now
    row.result = dump_json({"run_id": run_id})
    row.error = None
    session.add(
        outbox_row(
            OutboxRecord(
                event_type="analysis_job.completed",
                aggregate_type="analysis_job",
                aggregate_id=job_id,
                payload={"task_id": row.celery_task_id, "status": status, "run_id": run_id},
            )
        )
    )


def fail_analysis_job(session: Session, job_id: str, error: str, status: str) -> None:
    now = now_iso()
    row = require_analysis_job_row(session, job_id)
    row.status = status
    row.completed_at = now
    row.updated_at = now
    row.result = None
    row.error = error
    session.add(
        outbox_row(
            OutboxRecord(
                event_type="analysis_job.failed",
                aggregate_type="analysis_job",
                aggregate_id=job_id,
                payload={"task_id": row.celery_task_id, "status": status},
            )
        )
    )


def analysis_job_by_task_id(session: Session, task_id: str) -> AnalysisJobState | None:
    row = session.get(AnalysisJobRow, task_id)
    if row is None:
        row = session.scalars(
            select(AnalysisJobRow).where(AnalysisJobRow.celery_task_id == task_id).limit(1)
        ).first()
    if row is None:
        return None
    return _analysis_job_state(row)


def require_analysis_job_row(session: Session, job_id: str) -> AnalysisJobRow:
    row = session.get(AnalysisJobRow, job_id)
    if row is None:
        raise KeyError(job_id)
    return row


def _analysis_job_state(row: AnalysisJobRow) -> AnalysisJobState:
    return AnalysisJobState(
        task_id=row.celery_task_id,
        status=row.status,
        payload={"input_meta": load_json_object(row.input_meta)},
        result=load_json_object(row.result) if row.result else None,
        error=row.error,
    )
