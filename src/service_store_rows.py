"""Convert analysis payload sections into SQLAlchemy row objects."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

from .service_models import AlertRow, DlqEventRow, EventRow, IncidentRow, OutboxEventRow
from .service_store_payloads import (
    JsonObject,
    dump_json,
    int_value,
    json_list,
    new_id,
    now_iso,
    text_value,
)

_OUTBOX_PENDING: Final = "pending"


@dataclass(frozen=True, slots=True)
class OutboxRecord:
    """Input value used to create a durable outbox event row."""

    event_type: str
    aggregate_type: str
    aggregate_id: str
    payload: JsonObject


def event_rows(run_id: str, payload: JsonObject) -> list[EventRow]:
    """Map run payload telemetry events into normalized event rows."""

    return [_event_row(run_id, event) for event in json_list(payload.get("events"))]


def alert_rows(run_id: str, payload: JsonObject) -> list[AlertRow]:
    """Map run payload alerts into normalized alert rows."""

    return [_alert_row(run_id, alert) for alert in json_list(payload.get("alerts"))]


def incident_rows(run_id: str, payload: JsonObject) -> list[IncidentRow]:
    """Map run payload incidents into normalized incident rows."""

    return [_incident_row(run_id, incident) for incident in json_list(payload.get("incidents"))]


def dlq_rows(run_id: str, payload: JsonObject) -> list[DlqEventRow]:
    """Map run payload dead-letter events into normalized DLQ rows."""

    return [_dlq_row(run_id, index, event) for index, event in enumerate(json_list(payload.get("dlq_events")), start=1)]


def outbox_row(record: OutboxRecord) -> OutboxEventRow:
    """Create a pending outbox row from a typed outbox record."""

    return OutboxEventRow(
        outbox_id=new_id("outbox"),
        event_type=record.event_type,
        aggregate_type=record.aggregate_type,
        aggregate_id=record.aggregate_id,
        status=_OUTBOX_PENDING,
        created_at=now_iso(),
        payload=dump_json(record.payload),
    )


def _event_row(run_id: str, event: JsonObject) -> EventRow:
    """Map one telemetry JSON object into an event table row."""

    return EventRow(
        run_id=run_id,
        event_id=text_value(event.get("event_id")) or new_id("event"),
        event_type=text_value(event.get("event_type")) or "unknown",
        host_id=text_value(event.get("host_id")) or "unknown",
        event_time=text_value(event.get("event_time")),
        process_name=text_value(event.get("process_name")) or "-",
        destination=text_value(event.get("domain")) or text_value(event.get("dst_ip")) or "-",
        payload=dump_json(event),
    )


def _alert_row(run_id: str, alert: JsonObject) -> AlertRow:
    """Map one alert JSON object into an alert table row."""

    return AlertRow(
        run_id=run_id,
        alert_id=text_value(alert.get("alert_id")) or new_id("alert"),
        rule_id=text_value(alert.get("rule_id")) or "unknown",
        severity=text_value(alert.get("severity")) or "info",
        risk_score=int_value(alert.get("risk_score")),
        host_id=text_value(alert.get("host_id")) or "unknown",
        event_time=text_value(alert.get("event_time")),
        payload=dump_json(alert),
    )


def _incident_row(run_id: str, incident: JsonObject) -> IncidentRow:
    """Map one incident JSON object into an incident table row."""

    return IncidentRow(
        run_id=run_id,
        incident_id=text_value(incident.get("incident_id")) or new_id("incident"),
        severity=text_value(incident.get("severity")) or "info",
        risk_score=int_value(incident.get("risk_score")),
        host_display_name=text_value(incident.get("host_display_name")) or text_value(incident.get("host_id")) or "unknown",
        payload=dump_json(incident),
    )


def _dlq_row(run_id: str, index: int, event: JsonObject) -> DlqEventRow:
    """Map one dead-letter event JSON object into a DLQ table row."""

    return DlqEventRow(
        run_id=run_id,
        dlq_id=f"{run_id}-dlq-{index:03d}",
        event_id=text_value(event.get("event_id")) or f"index-{int_value(event.get('index'))}",
        error_code=text_value(event.get("code")) or "UNKNOWN_SCHEMA_ERROR",
        payload=dump_json(event),
    )
