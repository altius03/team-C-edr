from __future__ import annotations

import json
from hmac import compare_digest
from typing import Any

from django.conf import settings
from django.http import HttpRequest, HttpResponse, HttpResponseNotAllowed, JsonResponse
from django.views.decorators.csrf import csrf_exempt

from src.django_backend.queue import enqueue_analysis_job
from src.service_store import JsonObject

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
def telemetry_events(request: HttpRequest) -> HttpResponse:
    # The ingest endpoint accepts telemetry quickly and lets the worker perform
    # analysis, which prevents a large upload from tying up the request thread.
    if request.method != "POST":
        return _method_not_allowed(["POST"])
    auth_error = _require_api_token(request)
    if auth_error is not None:
        return auth_error
    tenant_error = _require_tenant_headers(request)
    if tenant_error is not None:
        return tenant_error

    try:
        payload = _read_json(request)
    except (json.JSONDecodeError, UnicodeDecodeError, ValueError) as exc:
        return _json_error("invalid_json", str(exc), status=400)

    events = payload.get("events")
    if not isinstance(events, list):
        return _json_error("invalid_request", "events must be an array", status=400)

    event_objects = [event for event in events if isinstance(event, dict)]
    store = get_store()
    task = enqueue_analysis_job(
        store,
        events=event_objects,
        input_meta=_input_meta_from_headers(request),
    )
    return JsonResponse(
        {
            "status": "accepted",
            "task_id": task.task_id,
            "task_status": task.status.value,
            "accepted_count": len(event_objects),
            "queued": True,
        },
        status=202,
    )


def task_detail(request: HttpRequest, task_id: str) -> HttpResponse:
    if request.method != "GET":
        return _method_not_allowed(["GET"])
    try:
        task = get_store().get_task(task_id)
    except KeyError:
        return _json_error("not_found", f"task {task_id} was not found", status=404)
    return JsonResponse(
        {
            "task_id": task.task_id,
            "task_type": task.task_type,
            "status": task.status.value,
            "result": task.result,
            "error": task.error,
        }
    )


def _read_json(request: HttpRequest) -> JsonObject:
    if not request.body:
        return {}
    parsed: Any = json.loads(request.body.decode("utf-8"))
    if not isinstance(parsed, dict):
        raise ValueError("request body must be a JSON object")
    return parsed


def _input_meta_from_headers(request: HttpRequest) -> JsonObject:
    # These headers make one shared API usable by multiple customers, tenants,
    # and agent versions without changing the telemetry body schema.
    return {
        "source": "rest_api",
        "customer_id": request.headers.get("X-Customer-Id", "unknown"),
        "tenant_id": request.headers.get("X-Tenant-Id", "unknown"),
        "agent_version": request.headers.get("X-Agent-Version", "unknown"),
        "payload_version": request.headers.get("X-Payload-Version", "unknown"),
    }


def _require_api_token(request: HttpRequest) -> JsonResponse | None:
    if not settings.LAYERTRACE_REQUIRE_API_TOKEN:
        return None
    expected = str(settings.LAYERTRACE_API_TOKEN)
    provided = request.headers.get("X-Api-Token", "")
    authorization = request.headers.get("Authorization", "")
    if authorization.lower().startswith("bearer "):
        provided = authorization[7:].strip()
    if not provided:
        return _json_error("unauthorized", "X-Api-Token or Bearer token is required", status=401)
    if not compare_digest(provided, expected):
        return _json_error("forbidden", "invalid API token", status=403)
    return None


def _require_tenant_headers(request: HttpRequest) -> JsonResponse | None:
    missing = [
        name
        for name in ("X-Customer-Id", "X-Tenant-Id", "X-Agent-Version", "X-Payload-Version")
        if not request.headers.get(name)
    ]
    if missing:
        return _json_error("missing_headers", f"missing required headers: {', '.join(missing)}", status=400)
    return None


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


def _json_error(code: str, message: str, *, status: int) -> JsonResponse:
    return JsonResponse({"error": code, "message": message}, status=status)
