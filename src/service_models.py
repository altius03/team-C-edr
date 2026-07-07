"""Define SQLAlchemy tables used by the service store."""

from __future__ import annotations

from sqlalchemy import ForeignKey, ForeignKeyConstraint, Index, Integer, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    """Declarative base shared by all persisted service rows."""

    pass


class RunRow(Base):
    """Stored analysis run with the full original payload retained as JSON."""

    __tablename__ = "runs"

    run_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    generated_at: Mapped[str] = mapped_column(String(40), nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(40), nullable=False)
    decision: Mapped[str] = mapped_column(String(80), nullable=False)
    customer_id: Mapped[str] = mapped_column(String(128), nullable=False, default="unknown")
    tenant_id: Mapped[str] = mapped_column(String(128), nullable=False, default="unknown")
    payload: Mapped[str] = mapped_column(Text, nullable=False)


class EventRow(Base):
    """Normalized telemetry event row derived from a stored run payload."""

    __tablename__ = "events"

    run_id: Mapped[str] = mapped_column(String(64), ForeignKey("runs.run_id", ondelete="CASCADE"), primary_key=True)
    event_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    customer_id: Mapped[str] = mapped_column(String(128), nullable=False, default="unknown")
    tenant_id: Mapped[str] = mapped_column(String(128), nullable=False, default="unknown")
    event_type: Mapped[str] = mapped_column(String(80), nullable=False)
    host_id: Mapped[str] = mapped_column(String(128), nullable=False)
    event_time: Mapped[str] = mapped_column(String(40), nullable=False)
    process_name: Mapped[str] = mapped_column(String(255), nullable=False)
    destination: Mapped[str] = mapped_column(String(255), nullable=False)
    payload: Mapped[str] = mapped_column(Text, nullable=False)


class AlertRow(Base):
    """Normalized alert row used for severity and host lookups."""

    __tablename__ = "alerts"

    __table_args__ = (ForeignKeyConstraint(["run_id", "primary_event_id"], ["events.run_id", "events.event_id"]),)

    run_id: Mapped[str] = mapped_column(String(64), ForeignKey("runs.run_id", ondelete="CASCADE"), primary_key=True)
    alert_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    customer_id: Mapped[str] = mapped_column(String(128), nullable=False, default="unknown")
    tenant_id: Mapped[str] = mapped_column(String(128), nullable=False, default="unknown")
    primary_event_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    rule_id: Mapped[str] = mapped_column(String(40), nullable=False)
    severity: Mapped[str] = mapped_column(String(40), nullable=False)
    risk_score: Mapped[int] = mapped_column(Integer, nullable=False)
    host_id: Mapped[str] = mapped_column(String(128), nullable=False)
    event_time: Mapped[str] = mapped_column(String(40), nullable=False)
    payload: Mapped[str] = mapped_column(Text, nullable=False)


class IncidentRow(Base):
    """Normalized incident row used by dashboard and incident APIs."""

    __tablename__ = "incidents"

    __table_args__ = (ForeignKeyConstraint(["run_id", "primary_alert_id"], ["alerts.run_id", "alerts.alert_id"]),)

    run_id: Mapped[str] = mapped_column(String(64), ForeignKey("runs.run_id", ondelete="CASCADE"), primary_key=True)
    incident_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    customer_id: Mapped[str] = mapped_column(String(128), nullable=False, default="unknown")
    tenant_id: Mapped[str] = mapped_column(String(128), nullable=False, default="unknown")
    primary_alert_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    severity: Mapped[str] = mapped_column(String(40), nullable=False)
    risk_score: Mapped[int] = mapped_column(Integer, nullable=False)
    host_display_name: Mapped[str] = mapped_column(String(255), nullable=False)
    payload: Mapped[str] = mapped_column(Text, nullable=False)


class DlqEventRow(Base):
    """Dead-letter telemetry event captured with its schema error code."""

    __tablename__ = "dlq_events"

    run_id: Mapped[str] = mapped_column(String(64), ForeignKey("runs.run_id", ondelete="CASCADE"), primary_key=True)
    dlq_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    event_id: Mapped[str] = mapped_column(String(128), nullable=False)
    error_code: Mapped[str] = mapped_column(String(80), nullable=False)
    payload: Mapped[str] = mapped_column(Text, nullable=False)


class TaskRow(Base):
    """Durable task queue row shared by local and external workers."""

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
    """Outbox event row for side effects derived from persistence changes."""

    __tablename__ = "outbox_events"

    outbox_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    event_type: Mapped[str] = mapped_column(String(80), nullable=False)
    aggregate_type: Mapped[str] = mapped_column(String(80), nullable=False)
    aggregate_id: Mapped[str] = mapped_column(String(128), nullable=False)
    status: Mapped[str] = mapped_column(String(40), nullable=False, index=True)
    created_at: Mapped[str] = mapped_column(String(40), nullable=False)
    payload: Mapped[str] = mapped_column(Text, nullable=False)


class AlertEventRow(Base):
    __tablename__ = "alert_events"
    __table_args__ = (
        ForeignKeyConstraint(["run_id", "alert_id"], ["alerts.run_id", "alerts.alert_id"], ondelete="CASCADE"),
        ForeignKeyConstraint(["run_id", "event_id"], ["events.run_id", "events.event_id"], ondelete="CASCADE"),
    )

    run_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    alert_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    event_id: Mapped[str] = mapped_column(String(128), primary_key=True)


class IncidentAlertRow(Base):
    __tablename__ = "incident_alerts"
    __table_args__ = (
        ForeignKeyConstraint(["run_id", "incident_id"], ["incidents.run_id", "incidents.incident_id"], ondelete="CASCADE"),
        ForeignKeyConstraint(["run_id", "alert_id"], ["alerts.run_id", "alerts.alert_id"], ondelete="CASCADE"),
    )

    run_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    incident_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    alert_id: Mapped[str] = mapped_column(String(128), primary_key=True)

# Lookup indexes mirror the REST and dashboard query paths.
Index("idx_events_host_type", EventRow.host_id, EventRow.event_type)
Index("idx_alerts_host_severity", AlertRow.host_id, AlertRow.severity)
Index("idx_incidents_severity", IncidentRow.severity)
Index("idx_alert_events_event", AlertEventRow.run_id, AlertEventRow.event_id)
Index("idx_incident_alerts_alert", IncidentAlertRow.run_id, IncidentAlertRow.alert_id)
Index("idx_dlq_events_error_code", DlqEventRow.error_code)
Index("idx_outbox_events_status", OutboxEventRow.status)
