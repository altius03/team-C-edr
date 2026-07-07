from __future__ import annotations

from dataclasses import dataclass
from hmac import compare_digest

from fastapi import Request, Security, status
from fastapi.security import APIKeyHeader
from pydantic import ValidationError

from .api_models import ApiSettings, ReportLatestResponse, TenantHeaders
from .service_store import JsonObject, JsonValue, ServiceStore
from .task_queue import TaskQueue

_API_TOKEN_HEADER = APIKeyHeader(name="X-Api-Token", auto_error=False)


@dataclass(frozen=True, slots=True)
class ApiError(Exception):
    status_code: int
    code: str
    message: str


def store_from_request(request: Request) -> ServiceStore:
    store = request.app.state.store
    if not isinstance(store, ServiceStore):
        raise RuntimeError("FastAPI app state does not contain ServiceStore")
    return store


def queue_from_request(request: Request) -> TaskQueue:
    queue = request.app.state.task_queue
    if not isinstance(queue, TaskQueue):
        raise RuntimeError("FastAPI app state does not contain TaskQueue")
    return queue


def settings_from_request(request: Request) -> ApiSettings:
    settings = request.app.state.settings
    if not isinstance(settings, ApiSettings):
        raise RuntimeError("FastAPI app state does not contain ApiSettings")
    return settings


def tenant_headers_from_request(request: Request) -> TenantHeaders:
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


def require_api_token_dependency(request: Request, _: str | None = Security(_API_TOKEN_HEADER)) -> None:
    require_api_token(request)


def require_read_token_dependency(request: Request, _: str | None = Security(_API_TOKEN_HEADER)) -> None:
    if settings_from_request(request).allow_public_reads:
        return
    require_api_token(request)


def require_api_token(request: Request) -> None:
    settings = settings_from_request(request)
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


def input_meta_from_headers(headers: TenantHeaders) -> JsonObject:
    return {
        "source": "rest_api",
        "customer_id": headers.customer_id,
        "tenant_id": headers.tenant_id,
        "agent_version": headers.agent_version,
        "payload_version": headers.payload_version,
    }


def latest_report_from_run(latest: JsonObject | None) -> ReportLatestResponse:
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
    return value if isinstance(value, str) else None
