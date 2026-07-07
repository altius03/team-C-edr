from __future__ import annotations

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .service_models import AlertEventRow, AlertRow, DlqEventRow, EventRow, IncidentAlertRow, IncidentRow, OutboxEventRow, RunRow, TaskRow


class UnsupportedTableError(ValueError):
    def __init__(self, table: str) -> None:
        super().__init__(f"unsupported table: {table}")


def count_rows(session: Session, table: str) -> int:
    match table:
        case "runs":
            count = session.scalar(select(func.count()).select_from(RunRow))
        case "events":
            count = session.scalar(select(func.count()).select_from(EventRow))
        case "alerts":
            count = session.scalar(select(func.count()).select_from(AlertRow))
        case "incidents":
            count = session.scalar(select(func.count()).select_from(IncidentRow))
        case "alert_events":
            count = session.scalar(select(func.count()).select_from(AlertEventRow))
        case "incident_alerts":
            count = session.scalar(select(func.count()).select_from(IncidentAlertRow))
        case "dlq_events":
            count = session.scalar(select(func.count()).select_from(DlqEventRow))
        case "tasks":
            count = session.scalar(select(func.count()).select_from(TaskRow))
        case "outbox_events":
            count = session.scalar(select(func.count()).select_from(OutboxEventRow))
        case _:
            raise UnsupportedTableError(table)
    return int(count or 0)
