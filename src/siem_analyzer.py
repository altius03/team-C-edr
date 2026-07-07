"""Create SIEM-style correlation views from endpoint detection output."""

from __future__ import annotations

from collections import Counter, defaultdict
from typing import Any

from .config import (
    AGENT_VERSION,
    CUSTOMER_ID,
    HOST_DISPLAY_NAMES,
    PAYLOAD_VERSION,
    TENANT_ID,
)


# Fixed layers keep graph rendering stable across runs and separate endpoint,
# tenant-boundary, and external-destination concepts.
TOPOLOGY_LAYERS = ["Endpoint", "Internal Zone", "External Destination"]


def display_host(host_id: str | None) -> str:
    """Return a dashboard-safe host label for a host identifier."""

    if not host_id:
        return "-"
    return HOST_DISPLAY_NAMES.get(host_id, host_id)


def build_siem_analysis(
    events: list[dict[str, Any]],
    alerts: list[dict[str, Any]],
    incidents: list[dict[str, Any]],
    endpoint_risk: list[dict[str, Any]],
) -> dict[str, Any]:
    """Return query findings, topology, timeline, and telemetry metadata."""

    return {
        "query_findings": _query_findings(alerts),
        "egress_topology": _egress_topology(events, alerts, endpoint_risk),
        "correlation_timeline": _correlation_timeline(events, alerts, incidents),
        "destination_intelligence": _destination_intelligence(events, alerts),
        "collector_explanation": (
            "Endpoint process telemetry is collected from Windows Win32_Process / process snapshot style data. "
            "DNS cache observations are collected as a separate resolver/cache source and correlated later by "
            "host_id, process_name, domain, and event_time; DNS is not inferred from Win32_Process itself."
        ),
        "telemetry_metadata": {
            "customer_id": CUSTOMER_ID,
            "tenant_id": TENANT_ID,
            "agent_version": AGENT_VERSION,
            "payload_version": PAYLOAD_VERSION,
            "schema_version": PAYLOAD_VERSION,
        },
        "api_contract": {
            "current_transport": "REST",
            "swagger_path": "/docs",
            "openapi_path": "/openapi.json",
            "note": "Local PoC exposes REST ingestion through FastAPI generated OpenAPI.",
        },
    }


def _query_findings(alerts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Group alerts into SIEM query rows by host and rule."""

    grouped: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for alert in alerts:
        grouped[(alert.get("host_id", "-"), alert.get("rule_id", "-"))].append(alert)

    rows: list[dict[str, Any]] = []
    for index, ((host_id, rule_id), items) in enumerate(
        sorted(grouped.items(), key=lambda item: (-sum(alert.get("risk_score", 0) for alert in item[1]), item[0])),
        start=1,
    ):
        highest = max(items, key=lambda alert: alert.get("risk_score", 0))
        evidence_count = sum(len(alert.get("evidence", [])) for alert in items)
        rows.append(
            {
                "query_id": f"SIEM-Q{index:03d}",
                "title": highest.get("rule_name") or highest.get("title") or rule_id,
                "rule_id": rule_id,
                "severity": highest.get("severity", "info"),
                "host_id": host_id,
                "host_display_name": display_host(host_id),
                "summary": highest.get("title", "-"),
                "evidence_count": evidence_count,
                "alert_count": len(items),
                "last_event_time": max(alert.get("event_time", "") for alert in items),
            }
        )
    return rows[:12]


def _egress_topology(
    events: list[dict[str, Any]],
    alerts: list[dict[str, Any]],
    endpoint_risk: list[dict[str, Any]],
) -> dict[str, Any]:
    """Build endpoint-to-destination graph data with alert-aware states."""

    # The dashboard renders this as Endpoint fleet -> tenant boundary ->
    # external destinations, so the topology keeps nodes and edges separate.
    alert_event_ids = {event_id for alert in alerts for event_id in alert.get("event_ids", [])}
    risk_by_host = {row["host_id"]: row for row in endpoint_risk}
    nodes: list[dict[str, Any]] = [
        {
            "id": "tenant-boundary",
            "label": "Protected tenant boundary",
            "layer": "Internal Zone",
            "state": "observed",
            "description": "Customer-controlled network and SIEM collection boundary",
        }
    ]
    for host_id, row in sorted(risk_by_host.items(), key=lambda item: item[0]):
        nodes.append(
            {
                "id": host_id,
                "label": display_host(host_id),
                "layer": "Endpoint",
                "state": _node_state(row.get("risk_score", 0), row.get("alert_count", 0)),
                "risk_score": row.get("risk_score", 0),
                "alert_count": row.get("alert_count", 0),
            }
        )

    destination_rows: dict[str, dict[str, Any]] = {}
    edge_counter: Counter[tuple[str, str]] = Counter()
    edge_bytes: Counter[tuple[str, str]] = Counter()
    edge_alerts: Counter[tuple[str, str]] = Counter()
    endpoint_seen: set[str] = set()

    for event in events:
        host_id = event.get("host_id")
        destination = _destination(event)
        if not host_id or not destination:
            continue
        endpoint_seen.add(host_id)
        edge_key = (host_id, destination)
        edge_counter[edge_key] += 1
        edge_bytes[edge_key] += int(event.get("bytes_out") or 0)
        if event.get("event_id") in alert_event_ids:
            edge_alerts[edge_key] += 1
        destination_rows.setdefault(
            destination,
            {
                "id": destination,
                "label": destination,
                "layer": "External Destination",
                "state": "not_detected",
                "event_count": 0,
                "bytes_out": 0,
            },
        )
        destination_rows[destination]["event_count"] += 1
        destination_rows[destination]["bytes_out"] += int(event.get("bytes_out") or 0)
        if event.get("event_id") in alert_event_ids:
            destination_rows[destination]["state"] = "alert"

    nodes.extend(sorted(destination_rows.values(), key=lambda row: (row["state"] != "alert", row["id"]))[:18])
    edges = [
        {
            "source": host_id,
            "through": "tenant-boundary",
            "target": destination,
            "source_label": display_host(host_id),
            "protocol": "tcp/dns/http",
            "event_count": count,
            "alert_count": edge_alerts[(host_id, destination)],
            "bytes_out": edge_bytes[(host_id, destination)],
            "state": "alert" if edge_alerts[(host_id, destination)] else "not_detected",
        }
        for (host_id, destination), count in edge_counter.most_common(24)
    ]
    return {
        "title": "Endpoint Egress Topology",
        "layers": TOPOLOGY_LAYERS,
        "nodes": nodes,
        "edges": edges,
        "summary": {
            "endpoint_count": len(endpoint_seen),
            "external_destination_count": len(destination_rows),
            "alert_edge_count": sum(1 for edge in edges if edge["state"] == "alert"),
        },
    }


def _correlation_timeline(
    events: list[dict[str, Any]],
    alerts: list[dict[str, Any]],
    incidents: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Return incident stages or alert fallbacks in chronological order."""

    event_by_id = {event["event_id"]: event for event in events}
    rows: list[dict[str, Any]] = []
    for incident in incidents:
        for stage in incident.get("detected_sequence", []):
            event_ids = stage.get("event_ids") or [stage.get("event_id")]
            event_ids = [event_id for event_id in event_ids if event_id in event_by_id]
            event = event_by_id.get(event_ids[0]) if event_ids else None
            rows.append(
                {
                    "time": event.get("event_time") if event else "",
                    "host_id": incident.get("host_id", "-"),
                    "host_display_name": display_host(incident.get("host_id")),
                    "stage": stage.get("stage", "-"),
                    "summary": stage.get("summary", "-"),
                    "severity": incident.get("severity", "info"),
                }
            )
    if rows:
        return sorted(rows, key=lambda row: row["time"])

    return [
        {
            "time": alert.get("event_time", ""),
            "host_id": alert.get("host_id", "-"),
            "host_display_name": display_host(alert.get("host_id")),
            "stage": alert.get("rule_id", "-"),
            "summary": alert.get("title", "-"),
            "severity": alert.get("severity", "info"),
        }
        for alert in alerts[:10]
    ]


def _destination_intelligence(events: list[dict[str, Any]], alerts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Aggregate destination counts, bytes, and alert state for analysts."""

    alert_event_ids = {event_id for alert in alerts for event_id in alert.get("event_ids", [])}
    counts: Counter[str] = Counter()
    alert_counts: Counter[str] = Counter()
    bytes_out: Counter[str] = Counter()
    for event in events:
        destination = _destination(event)
        if not destination:
            continue
        counts[destination] += 1
        bytes_out[destination] += int(event.get("bytes_out") or 0)
        if event.get("event_id") in alert_event_ids:
            alert_counts[destination] += 1
    return [
        {
            "destination": destination,
            "event_count": count,
            "alert_count": alert_counts[destination],
            "bytes_out": bytes_out[destination],
            "state": "alert" if alert_counts[destination] else "not_detected",
        }
        for destination, count in counts.most_common(12)
    ]


def _destination(event: dict[str, Any]) -> str:
    """Extract the best available external destination from an event."""

    return str(
        event.get("domain")
        or event.get("source_domain")
        or event.get("dst_ip")
        or event.get("destination_ip")
        or ""
    )


def _node_state(risk_score: int, alert_count: int) -> str:
    """Map risk and alert counts to topology node state."""

    if risk_score >= 80:
        return "red"
    if alert_count:
        return "alert"
    return "not_detected"
