"""Expose the FastAPI REST surface for health, dashboard, ingest, and task state."""

from __future__ import annotations

import os
import logging
from dataclasses import dataclass
from hmac import compare_digest
from typing import Final

from fastapi import Depends, FastAPI, Request, Security, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.security import APIKeyHeader
from pydantic import ValidationError

from .api_models import (
    ApiSettings,
    DashboardResult,
    ErrorResponse,
    HealthResponse,
    IncidentListResponse,
    IngestResponse,
    ReportLatestResponse,
    Severity,
    TaskStatusResponse,
    TelemetryBatchRequest,
    TenantHeaders,
)
from .service_store import JsonObject, JsonValue, ServiceStore
from .task_queue import DatabaseTaskQueue, LocalTaskRunner, TaskQueue

LOGGER = logging.getLogger(__name__)
_API_TOKEN_HEADER = APIKeyHeader(name="X-Api-Token", auto_error=False)

_INGEST_HEADER_PARAMETERS: Final[list[JsonObject]] = [
    {"name": "X-Customer-Id", "in": "header", "required": True, "schema": {"type": "string"}},
    {"name": "X-Tenant-Id", "in": "header", "required": True, "schema": {"type": "string"}},
    {"name": "X-Agent-Version", "in": "header", "required": True, "schema": {"type": "string"}},
    {"name": "X-Payload-Version", "in": "header", "required": True, "schema": {"type": "string"}},
    {"name": "X-Api-Token", "in": "header", "required": False, "schema": {"type": "string"}},
]


@dataclass(frozen=True, slots=True)
class ApiError(Exception):
    """Typed HTTP error translated into the public JSON error envelope."""

    status_code: int
    code: str
    message: str


def create_app(
    store: ServiceStore | None = None,
    task_queue: TaskQueue | None = None,
    settings: ApiSettings | None = None,
) -> FastAPI:
    """Create the REST application with injected or environment-backed services."""

    actual_settings = settings or _settings_from_env()
    actual_store = store or ServiceStore()
    actual_store.initialize()
    actual_queue = task_queue or _task_queue_from_settings(actual_store, actual_settings)
    app = FastAPI(title="LayerTrace EDR/SIEM REST API", version="0.5.0")
    app.add_middleware(
        CORSMiddleware,
        allow_origins=actual_settings.cors_origins or _default_cors_origins(),
        allow_credentials=False,
        allow_methods=["GET", "POST"],
        allow_headers=["Authorization", "Content-Type", "X-Api-Token", "X-Agent-Version", "X-Customer-Id", "X-Payload-Version", "X-Tenant-Id"],
    )
    app.state.store = actual_store
    app.state.task_queue = actual_queue
    app.state.settings = actual_settings

    @app.exception_handler(ApiError)
    async def api_error_handler(_: Request, exc: ApiError) -> JSONResponse:
        return _json_error(exc.code, exc.message, exc.status_code)

    @app.exception_handler(RequestValidationError)
    async def request_validation_handler(_: Request, exc: RequestValidationError) -> JSONResponse:
        code = _validation_error_code(exc)
        return _json_error(code, str(exc.errors()[0].get("msg", "invalid request")), status.HTTP_400_BAD_REQUEST)

    @app.get("/v1/health", response_model=HealthResponse, tags=["health"])
    def health(request: Request) -> HealthResponse:
        return HealthResponse(storage=_store(request).storage_label, queue=_queue(request).queue_label)

    @app.get("/v1/dashboard/latest", response_model=DashboardResult, tags=["dashboard"], dependencies=[Depends(_require_read_token_dependency)])
    def dashboard_latest(request: Request) -> DashboardResult:
        latest = _store(request).get_latest_run()
        if latest is None:
            return DashboardResult(status="empty", message="no analysis run stored yet")
        return DashboardResult.model_validate(latest)

    @app.get("/v1/reports/latest", response_model=ReportLatestResponse, tags=["reports"], dependencies=[Depends(_require_read_token_dependency)])
    def reports_latest(request: Request) -> ReportLatestResponse:
        return _latest_report(_store(request).get_latest_run())

    @app.get("/v1/incidents", response_model=IncidentListResponse, tags=["incidents"], dependencies=[Depends(_require_read_token_dependency)])
    def incidents(request: Request, severity: Severity | None = None) -> IncidentListResponse:
        return IncidentListResponse(incidents=_store(request).list_incidents(severity=severity.value if severity else None))

    @app.post(
        "/v1/telemetry/events",
        response_model=IngestResponse,
        status_code=status.HTTP_202_ACCEPTED,
        tags=["telemetry"],
        openapi_extra={"parameters": _INGEST_HEADER_PARAMETERS},
        dependencies=[Depends(_require_api_token_dependency)],
    )
    def telemetry_events(payload: TelemetryBatchRequest, request: Request) -> IngestResponse:
        headers = _tenant_headers(request)
        event_objects = payload.events
        task = _queue(request).enqueue_analysis_job(events=event_objects, input_meta=_input_meta(headers))
        LOGGER.info(
            "accepted telemetry batch",
            extra={
                "task_id": task.task_id,
                "accepted_count": len(event_objects),
                "customer_id": headers.customer_id,
                "tenant_id": headers.tenant_id,
            },
        )
        return IngestResponse(
            status="accepted",
            task_id=task.task_id,
            task_status=task.status,
            accepted_count=len(event_objects),
            queued=True,
        )

    @app.get("/v1/tasks/{task_id}", response_model=TaskStatusResponse, tags=["tasks"], dependencies=[Depends(_require_read_token_dependency)])
    def task_detail(task_id: str, request: Request) -> TaskStatusResponse:
        try:
            task = _store(request).get_task(task_id)
        except KeyError:
            raise ApiError(status.HTTP_404_NOT_FOUND, "not_found", f"task {task_id} was not found") from None
        return TaskStatusResponse(
            task_id=task.task_id,
            task_type=task.task_type,
            status=task.status,
            result=task.result,
            error=task.error,
        )

    return app


def _settings_from_env() -> ApiSettings:
    """Read REST settings from environment variables with local defaults."""

    return ApiSettings(
        require_api_token=_env_bool("LAYERTRACE_REQUIRE_API_TOKEN", True),
        api_token=os.environ.get("LAYERTRACE_API_TOKEN", ""),
        allow_public_reads=_env_bool("LAYERTRACE_ALLOW_PUBLIC_READS", False),
        cors_origins=_env_csv("LAYERTRACE_CORS_ORIGINS") or _default_cors_origins(),
        task_runner=os.environ.get("LAYERTRACE_TASK_RUNNER", "local").strip().lower(),
    )


def settings_from_env() -> ApiSettings:
    return _settings_from_env()


def _task_queue_from_settings(store: ServiceStore, settings: ApiSettings) -> TaskQueue:
    match settings.task_runner:
        case "external":
            return DatabaseTaskQueue(store)
        case "local" | "":
            return LocalTaskRunner(store)
        case unknown:
            raise ValueError(f"unsupported task runner: {unknown}")


def _store(request: Request) -> ServiceStore:
    store = request.app.state.store
    if not isinstance(store, ServiceStore):
        raise RuntimeError("FastAPI app state does not contain ServiceStore")
    return store


def _queue(request: Request) -> TaskQueue:
    queue = request.app.state.task_queue
    if not isinstance(queue, TaskQueue):
        raise RuntimeError("FastAPI app state does not contain TaskQueue")
    return queue


def _settings(request: Request) -> ApiSettings:
    settings = request.app.state.settings
    if not isinstance(settings, ApiSettings):
        raise RuntimeError("FastAPI app state does not contain ApiSettings")
    return settings


def _tenant_headers(request: Request) -> TenantHeaders:
    """Parse required tenant and agent headers at the HTTP boundary."""

    headers = request.headers
    missing = [name for name in ("X-Customer-Id", "X-Tenant-Id", "X-Agent-Version", "X-Payload-Version") if not headers.get(name)]
    if missing:
        raise ApiError(status.HTTP_400_BAD_REQUEST, "missing_headers", f"missing required headers: {', '.join(missing)}")
    try:
        return TenantHeaders(
            customer_id=headers["X-Customer-Id"],
            tenant_id=headers["X-Tenant-Id"],
            agent_version=headers["X-Agent-Version"],
            payload_version=headers["X-Payload-Version"],
        )
    except ValidationError as exc:
        raise ApiError(status.HTTP_400_BAD_REQUEST, "invalid_headers", str(exc)) from exc


def _require_api_token(request: Request) -> None:
    """Enforce configured API token auth using header or Bearer credentials."""

    settings = _settings(request)
    if not settings.require_api_token:
        return
    if not settings.api_token:
        raise ApiError(status.HTTP_503_SERVICE_UNAVAILABLE, "auth_not_configured", "API token is not configured")
    provided = request.headers.get("X-Api-Token", "")
    authorization = request.headers.get("Authorization", "")
    if authorization.lower().startswith("bearer "):
        provided = authorization[7:].strip()
    if not provided:
        raise ApiError(status.HTTP_401_UNAUTHORIZED, "unauthorized", "X-Api-Token or Bearer token is required")
    if not compare_digest(provided, settings.api_token):
        raise ApiError(status.HTTP_403_FORBIDDEN, "forbidden", "invalid API token")


def _require_api_token_dependency(request: Request, _: str | None = Security(_API_TOKEN_HEADER)) -> None:
    _require_api_token(request)


def _require_read_token_dependency(request: Request, _: str | None = Security(_API_TOKEN_HEADER)) -> None:
    if _settings(request).allow_public_reads:
        return
    _require_api_token(request)


def _input_meta(headers: TenantHeaders) -> JsonObject:
    """Convert trusted tenant headers into analysis job metadata."""

    return {
        "source": "rest_api",
        "customer_id": headers.customer_id,
        "tenant_id": headers.tenant_id,
        "agent_version": headers.agent_version,
        "payload_version": headers.payload_version,
    }


def _latest_report(latest: JsonObject | None) -> ReportLatestResponse:
    """Project stored run payloads into the report metadata response."""

    if latest is None:
        return ReportLatestResponse(status="empty", message="no report generated yet")
    report = latest.get("report")
    if not isinstance(report, dict):
        return ReportLatestResponse(status="empty", message="latest run has no report metadata")
    return ReportLatestResponse(
        generated_at=_text(latest.get("generated_at")),
        html_path=_text(report.get("latest_html_path")),
        markdown_path=_text(report.get("latest_markdown_path")),
        pdf_export="browser_print_to_pdf",
    )


def _text(value: JsonValue) -> str | None:
    """Return string JSON values and drop every other JSON type."""

    return value if isinstance(value, str) else None


def _env_bool(name: str, default: bool) -> bool:
    """Read a boolean-like environment variable with a fallback."""

    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _env_csv(name: str) -> list[str]:
    """Read a comma-separated environment variable into trimmed entries."""

    value = os.environ.get(name, "")
    return [item.strip() for item in value.split(",") if item.strip()]


def _default_cors_origins() -> list[str]:
    """Return local development origins accepted by browser clients."""

    return [
        "http://127.0.0.1:5173",
        "http://localhost:5173",
        "http://127.0.0.1:4173",
        "http://localhost:4173",
        "http://127.0.0.1:3000",
        "http://localhost:3000",
    ]


def _validation_error_code(exc: RequestValidationError) -> str:
    """Distinguish malformed JSON from other request validation failures."""

    first = exc.errors()[0] if exc.errors() else {}
    return "invalid_json" if first.get("type") == "json_invalid" else "invalid_request"


def _json_error(code: str, message: str, status_code: int) -> JSONResponse:
    """Build the canonical JSON error response for REST callers."""

    return JSONResponse(status_code=status_code, content=ErrorResponse(error=code, message=message).model_dump())
