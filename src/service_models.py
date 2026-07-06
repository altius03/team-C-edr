from __future__ import annotations

from sqlalchemy import Index, Integer, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class RunRow(Base):
    __tablename__ = "runs"

    run_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    generated_at: Mapped[str] = mapped_column(String(40), nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(40), nullable=False)
    decision: Mapped[str] = mapped_column(String(80), nullable=False)
    payload: Mapped[str] = mapped_column(Text, nullable=False)


class EventRow(Base):
    __tablename__ = "events"

    run_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    event_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    event_type: Mapped[str] = mapped_column(String(80), nullable=False)
    host_id: Mapped[str] = mapped_column(String(128), nullable=False)
    event_time: Mapped[str] = mapped_column(String(40), nullable=False)
    process_name: Mapped[str] = mapped_column(String(255), nullable=False)
    destination: Mapped[str] = mapped_column(String(255), nullable=False)
    payload: Mapped[str] = mapped_column(Text, nullable=False)


class AlertRow(Base):
    __tablename__ = "alerts"

    run_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    alert_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    rule_id: Mapped[str] = mapped_column(String(40), nullable=False)
    severity: Mapped[str] = mapped_column(String(40), nullable=False)
    risk_score: Mapped[int] = mapped_column(Integer, nullable=False)
    host_id: Mapped[str] = mapped_column(String(128), nullable=False)
    event_time: Mapped[str] = mapped_column(String(40), nullable=False)
    payload: Mapped[str] = mapped_column(Text, nullable=False)


class IncidentRow(Base):
    __tablename__ = "incidents"

    run_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    incident_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    severity: Mapped[str] = mapped_column(String(40), nullable=False)
    risk_score: Mapped[int] = mapped_column(Integer, nullable=False)
    host_display_name: Mapped[str] = mapped_column(String(255), nullable=False)
    payload: Mapped[str] = mapped_column(Text, nullable=False)


class DlqEventRow(Base):
    __tablename__ = "dlq_events"

    run_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    dlq_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    event_id: Mapped[str] = mapped_column(String(128), nullable=False)
    error_code: Mapped[str] = mapped_column(String(80), nullable=False)
    payload: Mapped[str] = mapped_column(Text, nullable=False)


class TaskRow(Base):
    __tablename__ = "tasks"

    task_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    task_type: Mapped[str] = mapped_column(String(80), nullable=False)
    status: Mapped[str] = mapped_column(String(40), nullable=False, index=True)
    created_at: Mapped[str] = mapped_column(String(40), nullable=False)
    updated_at: Mapped[str] = mapped_column(String(40), nullable=False)
    payload: Mapped[str] = mapped_column(Text, nullable=False)
    result: Mapped[str | None] = mapped_column(Text, nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)


class OutboxEventRow(Base):
    __tablename__ = "outbox_events"

    outbox_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    event_type: Mapped[str] = mapped_column(String(80), nullable=False)
    aggregate_type: Mapped[str] = mapped_column(String(80), nullable=False)
    aggregate_id: Mapped[str] = mapped_column(String(128), nullable=False)
    status: Mapped[str] = mapped_column(String(40), nullable=False, index=True)
    created_at: Mapped[str] = mapped_column(String(40), nullable=False)
    payload: Mapped[str] = mapped_column(Text, nullable=False)


Index("idx_events_host_type", EventRow.host_id, EventRow.event_type)
Index("idx_alerts_host_severity", AlertRow.host_id, AlertRow.severity)
Index("idx_incidents_severity", IncidentRow.severity)
Index("idx_dlq_events_error_code", DlqEventRow.error_code)
Index("idx_outbox_events_status", OutboxEventRow.status)
