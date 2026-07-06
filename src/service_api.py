from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import TypeAlias
from urllib.parse import parse_qs, urlparse

from .service_store import JsonObject, ServiceStore
from .service_worker import run_default_analysis_job

ServerAddress: TypeAlias = tuple[str, int]


def create_service_server(address: ServerAddress, store: ServiceStore) -> ThreadingHTTPServer:
    class LayerTraceHandler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            route = urlparse(self.path)
            if route.path == "/v1/health":
                _send_json(
                    self,
                    {
                        "status": "ok",
                        "transport": "REST",
                        "storage": "sqlite",
                        "queue": "local-worker",
                    },
                )
                return
            if route.path == "/v1/dashboard/latest":
                latest = store.get_latest_run()
                _send_json(self, latest or {"status": "empty", "message": "no analysis run stored yet"})
                return
            if route.path == "/v1/reports/latest":
                latest = store.get_latest_run()
                _send_json(self, _latest_report(latest))
                return
            if route.path == "/v1/incidents":
                query = parse_qs(route.query)
                severity = query.get("severity", [None])[0]
                _send_json(self, {"incidents": store.list_incidents(severity=severity)})
                return
            _send_json(self, {"error": "not_found", "path": route.path}, status=404)

        def do_POST(self) -> None:
            route = urlparse(self.path)
            if route.path == "/v1/telemetry/events":
                payload = _read_json(self)
                events = payload.get("events")
                if not isinstance(events, list):
                    _send_json(self, {"error": "invalid_request", "message": "events must be an array"}, status=400)
                    return
                event_objects = [event for event in events if isinstance(event, dict)]
                run_id = run_default_analysis_job(
                    store,
                    events=event_objects,
                    input_meta=_input_meta_from_headers(self),
                )
                latest = store.get_latest_run() or {}
                summary = latest.get("summary", {})
                _send_json(
                    self,
                    {
                        "status": "accepted",
                        "run_id": run_id,
                        "accepted_count": len(event_objects),
                        "dlq_count": summary.get("dlq_event_count", 0) if isinstance(summary, dict) else 0,
                    },
                    status=202,
                )
                return
            _send_json(self, {"error": "not_found", "path": route.path}, status=404)

        def log_message(self, format: str, *args: object) -> None:
            return

    # Binding the store through a handler class keeps the stdlib HTTP surface
    # replaceable by FastAPI later without leaking SQLite details into callers.
    return ThreadingHTTPServer(address, LayerTraceHandler)


def _send_json(handler: BaseHTTPRequestHandler, payload: JsonObject, status: int = 200) -> None:
    body = json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


def _read_json(handler: BaseHTTPRequestHandler) -> JsonObject:
    length = int(handler.headers.get("Content-Length", "0") or "0")
    raw = handler.rfile.read(length).decode("utf-8") if length else "{}"
    parsed = json.loads(raw)
    if not isinstance(parsed, dict):
        raise ValueError("request body must be a JSON object")
    return parsed


def _input_meta_from_headers(handler: BaseHTTPRequestHandler) -> JsonObject:
    return {
        "source": "rest_api",
        "customer_id": handler.headers.get("X-Customer-Id", "unknown"),
        "tenant_id": handler.headers.get("X-Tenant-Id", "unknown"),
        "agent_version": handler.headers.get("X-Agent-Version", "unknown"),
        "payload_version": handler.headers.get("X-Payload-Version", "unknown"),
    }


def _latest_report(latest: JsonObject | None) -> JsonObject:
    if not latest:
        return {"status": "empty", "message": "no report generated yet"}
    report = latest.get("report")
    if not isinstance(report, dict):
        return {"status": "empty", "message": "latest run has no report metadata"}
    return {
        "generated_at": latest.get("generated_at"),
        "html_path": report.get("latest_html_path"),
        "markdown_path": report.get("latest_markdown_path"),
        "pdf_export": "browser_print_to_pdf",
    }
