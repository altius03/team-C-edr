from __future__ import annotations

import json
from typing import Any

from django.http import HttpRequest, HttpResponseNotAllowed, JsonResponse
from django.views.decorators.csrf import csrf_exempt

from src.service_store import JsonObject
from src.service_worker import run_default_analysis_job

from .state import get_store


def health(request: HttpRequest) -> JsonResponse:
    if request.method != "GET":
        return _method_not_allowed(["GET"])
    return JsonResponse(
        {
            "status": "ok",
            "transport": "REST",
            "framework": "django",
            "storage": "sqlite",
            "queue": "local-worker",
        }
    )


def dashboard_latest(request: HttpRequest) -> JsonResponse:
    if request.method != "GET":
        return _method_not_allowed(["GET"])
    latest = get_store().get_latest_run()
    return JsonResponse(latest or {"status": "empty", "message": "no analysis run stored yet"})


def reports_latest(request: HttpRequest) -> JsonResponse:
    if request.method != "GET":
        return _method_not_allowed(["GET"])
    return JsonResponse(_latest_report(get_store().get_latest_run()))


def incidents(request: HttpRequest) -> JsonResponse:
    if request.method != "GET":
        return _method_not_allowed(["GET"])
    severity = request.GET.get("severity") or None
    return JsonResponse({"incidents": get_store().list_incidents(severity=severity)})


@csrf_exempt
def telemetry_events(request: HttpRequest) -> JsonResponse:
    if request.method != "POST":
        return _method_not_allowed(["POST"])
    payload = _read_json(request)
    events = payload.get("events")
    if not isinstance(events, list):
        return JsonResponse({"error": "invalid_request", "message": "events must be an array"}, status=400)

    event_objects = [event for event in events if isinstance(event, dict)]
    store = get_store()
    run_id = run_default_analysis_job(
        store,
        events=event_objects,
        input_meta=_input_meta_from_headers(request),
    )
    latest = store.get_latest_run() or {}
    summary = latest.get("summary", {})
    return JsonResponse(
        {
            "status": "accepted",
            "run_id": run_id,
            "accepted_count": len(event_objects),
            "dlq_count": summary.get("dlq_event_count", 0) if isinstance(summary, dict) else 0,
        },
        status=202,
    )


def _read_json(request: HttpRequest) -> JsonObject:
    if not request.body:
        return {}
    parsed: Any = json.loads(request.body.decode("utf-8"))
    if not isinstance(parsed, dict):
        raise ValueError("request body must be a JSON object")
    return parsed


def _input_meta_from_headers(request: HttpRequest) -> JsonObject:
    return {
        "source": "rest_api",
        "customer_id": request.headers.get("X-Customer-Id", "unknown"),
        "tenant_id": request.headers.get("X-Tenant-Id", "unknown"),
        "agent_version": request.headers.get("X-Agent-Version", "unknown"),
        "payload_version": request.headers.get("X-Payload-Version", "unknown"),
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


def _method_not_allowed(methods: list[str]) -> HttpResponseNotAllowed:
    return HttpResponseNotAllowed(methods)
