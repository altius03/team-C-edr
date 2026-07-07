"""Convert analysis payload sections into SQLAlchemy row objects."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

from .service_models import AlertEventRow, AlertRow, DlqEventRow, EventRow, IncidentAlertRow, IncidentRow, OutboxEventRow
from .service_store_payloads import (
    JsonObject,
    JsonValue,
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

    customer_id, tenant_id = tenant_fields(payload)
    return [_event_row(run_id, event, customer_id, tenant_id) for event in json_list(payload.get("events"))]


def alert_rows(run_id: str, payload: JsonObject) -> list[AlertRow]:
    """Map run payload alerts into normalized alert rows."""

    customer_id, tenant_id = tenant_fields(payload)
    event_ids = _event_id_set(payload)
    return [_alert_row(run_id, alert, customer_id, tenant_id, _primary_event_id(alert, event_ids)) for alert in json_list(payload.get("alerts"))]


def incident_rows(run_id: str, payload: JsonObject) -> list[IncidentRow]:
    """Map run payload incidents into normalized incident rows."""

    customer_id, tenant_id = tenant_fields(payload)
    alerts = json_list(payload.get("alerts"))
    return [_incident_row(run_id, incident, customer_id, tenant_id, _primary_alert_id(incident, alerts)) for incident in json_list(payload.get("incidents"))]


def alert_event_rows(run_id: str, payload: JsonObject) -> list[AlertEventRow]:
    event_ids = _event_id_set(payload)
    rows: list[AlertEventRow] = []
    seen: set[tuple[str, str]] = set()
    for alert in json_list(payload.get("alerts")):
        alert_id = text_value(alert.get("alert_id"))
        if not alert_id:
            continue
        for event_id in _alert_event_ids(alert):
            if event_id not in event_ids or (alert_id, event_id) in seen:
                continue
            seen.add((alert_id, event_id))
            rows.append(AlertEventRow(run_id=run_id, alert_id=alert_id, event_id=event_id))
    return rows


def incident_alert_rows(run_id: str, payload: JsonObject) -> list[IncidentAlertRow]:
    alerts = json_list(payload.get("alerts"))
    rows: list[IncidentAlertRow] = []
    seen: set[tuple[str, str]] = set()
    for incident in json_list(payload.get("incidents")):
        incident_id = text_value(incident.get("incident_id"))
        if not incident_id:
            continue
        for alert_id in _incident_alert_ids(incident, alerts):
            if (incident_id, alert_id) in seen:
                continue
            seen.add((incident_id, alert_id))
            rows.append(IncidentAlertRow(run_id=run_id, incident_id=incident_id, alert_id=alert_id))
    return rows


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


def tenant_fields(payload: JsonObject) -> tuple[str, str]:
    telemetry = _tenant_payload(payload)
    return text_value(telemetry.get("customer_id")) or "unknown", text_value(telemetry.get("tenant_id")) or "unknown"


def _event_row(run_id: str, event: JsonObject, customer_id: str, tenant_id: str) -> EventRow:
    """Map one telemetry JSON object into an event table row."""

    return EventRow(
        run_id=run_id,
        event_id=text_value(event.get("event_id")) or new_id("event"),
        customer_id=customer_id,
        tenant_id=tenant_id,
        event_type=text_value(event.get("event_type")) or "unknown",
        host_id=text_value(event.get("host_id")) or "unknown",
        event_time=text_value(event.get("event_time")),
        process_name=text_value(event.get("process_name")) or "-",
        destination=text_value(event.get("domain")) or text_value(event.get("dst_ip")) or "-",
        payload=dump_json(event),
    )


def _alert_row(run_id: str, alert: JsonObject, customer_id: str, tenant_id: str, primary_event_id: str | None) -> AlertRow:
    """Map one alert JSON object into an alert table row."""

    return AlertRow(
        run_id=run_id,
        alert_id=text_value(alert.get("alert_id")) or new_id("alert"),
        customer_id=customer_id,
        tenant_id=tenant_id,
        primary_event_id=primary_event_id,
        rule_id=text_value(alert.get("rule_id")) or "unknown",
        severity=text_value(alert.get("severity")) or "info",
        risk_score=int_value(alert.get("risk_score")),
        host_id=text_value(alert.get("host_id")) or "unknown",
        event_time=text_value(alert.get("event_time")),
        payload=dump_json(alert),
    )


def _incident_row(run_id: str, incident: JsonObject, customer_id: str, tenant_id: str, primary_alert_id: str | None) -> IncidentRow:
    """Map one incident JSON object into an incident table row."""

    return IncidentRow(
        run_id=run_id,
        incident_id=text_value(incident.get("incident_id")) or new_id("incident"),
        customer_id=customer_id,
        tenant_id=tenant_id,
        primary_alert_id=primary_alert_id,
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


def _event_id_set(payload: JsonObject) -> set[str]:
    return {event_id for event_id in (text_value(event.get("event_id")) for event in json_list(payload.get("events"))) if event_id}


def _primary_event_id(alert: JsonObject, valid_event_ids: set[str]) -> str | None:
    return next((event_id for event_id in _alert_event_ids(alert) if event_id in valid_event_ids), None)


def _primary_alert_id(incident: JsonObject, alerts: list[JsonObject]) -> str | None:
    return next(iter(_incident_alert_ids(incident, alerts)), None)


def _alert_event_ids(alert: JsonObject) -> list[str]:
    return _text_list(alert.get("event_ids"))


def _incident_alert_ids(incident: JsonObject, alerts: list[JsonObject]) -> list[str]:
    alert_by_id: dict[str, JsonObject] = {}
    for alert in alerts:
        alert_id = text_value(alert.get("alert_id"))
        if alert_id:
            alert_by_id[alert_id] = alert
    explicit_alert_ids = [alert_id for alert_id in _text_list(incident.get("alert_ids")) if alert_id in alert_by_id]
    primary_alert_id = text_value(incident.get("primary_alert_id"))
    if primary_alert_id and primary_alert_id in alert_by_id and primary_alert_id not in explicit_alert_ids:
        explicit_alert_ids.append(primary_alert_id)
    if explicit_alert_ids:
        return explicit_alert_ids

    incident_event_ids = set(_incident_event_ids(incident))
    if not incident_event_ids:
        return []
    incident_host_id = text_value(incident.get("host_id"))
    alert_ids: list[str] = []
    for alert in alerts:
        alert_id = text_value(alert.get("alert_id"))
        if not alert_id:
            continue
        if incident_host_id and text_value(alert.get("host_id")) != incident_host_id:
            continue
        if not incident_event_ids.intersection(_alert_event_ids(alert)):
            continue
        alert_ids.append(alert_id)
    return alert_ids


def _incident_event_ids(incident: JsonObject) -> list[str]:
    event_ids: list[str] = []
    for stage in json_list(incident.get("detected_sequence")):
        event_id = text_value(stage.get("event_id"))
        if event_id:
            event_ids.append(event_id)
        event_ids.extend(_text_list(stage.get("event_ids")))
    return event_ids


def _text_list(value: JsonValue) -> list[str]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, str) and item]


def _tenant_payload(payload: JsonObject) -> JsonObject:
    for key in ("telemetry_metadata", "input"):
        value = payload.get(key)
        if isinstance(value, dict):
            return value
    siem = payload.get("siem_analysis")
    if isinstance(siem, dict):
        telemetry = siem.get("telemetry_metadata")
        if isinstance(telemetry, dict):
            return telemetry
    return {}
