from __future__ import annotations

import os

from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from .api_context import ApiError
from .api_models import ApiSettings, ErrorResponse
from .api_routes import ROUTERS
from .service_store import ServiceStore
from .task_queue import DatabaseTaskQueue, LocalTaskRunner, TaskQueue


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

    for router in ROUTERS:
        app.include_router(router)

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
