from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.orm import Session

from .service_models import TaskRow
from .service_store_payloads import JsonObject, dump_json, load_json_object, new_id, now_iso
from .service_store_rows import OutboxRecord, outbox_row


@dataclass(frozen=True, slots=True)
class TaskState:
    task_id: str
    task_type: str
    status: str
    payload: JsonObject
    result: JsonObject | None
    error: str | None = None


def enqueue_task(session: Session, task_type: str, payload: JsonObject, status: str) -> TaskState:
    task = TaskState(
        task_id=new_id("task"),
        task_type=task_type,
        status=status,
        payload=payload,
        result=None,
        error=None,
    )
    now = now_iso()
    session.add(
        TaskRow(
            task_id=task.task_id,
            task_type=task.task_type,
            status=task.status,
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


def claim_next_task(session: Session, pending_status: str, running_status: str) -> TaskState | None:
    row = session.scalars(
        select(TaskRow).where(TaskRow.status == pending_status).order_by(TaskRow.created_at).limit(1)
    ).first()
    if row is None:
        return None
    row.status = running_status
    row.updated_at = now_iso()
    return _task_state(row, running_status)


def complete_task(session: Session, task_id: str, status: str, result: JsonObject) -> None:
    row = require_task_row(session, task_id)
    row.status = status
    row.updated_at = now_iso()
    row.result = dump_json(result)
    row.error = None
    session.add(
        outbox_row(
            OutboxRecord(
                event_type="task.completed",
                aggregate_type="task",
                aggregate_id=task_id,
                payload={"task_id": task_id, "status": status},
            )
        )
    )


def fail_task(session: Session, task_id: str, status: str, error: str) -> None:
    row = require_task_row(session, task_id)
    row.status = status
    row.updated_at = now_iso()
    row.result = None
    row.error = error
    session.add(
        outbox_row(
            OutboxRecord(
                event_type="task.failed",
                aggregate_type="task",
                aggregate_id=task_id,
                payload={"task_id": task_id, "status": status},
            )
        )
    )


def task_by_id(session: Session, task_id: str) -> TaskState | None:
    row = session.get(TaskRow, task_id)
    if row is None:
        return None
    return _task_state(row, row.status)


def require_task_row(session: Session, task_id: str) -> TaskRow:
    row = session.get(TaskRow, task_id)
    if row is None:
        raise KeyError(task_id)
    return row


def _task_state(row: TaskRow, status: str) -> TaskState:
    return TaskState(
        task_id=row.task_id,
        task_type=row.task_type,
        status=status,
        payload=load_json_object(row.payload),
        result=load_json_object(row.result) if row.result else None,
        error=row.error,
    )
