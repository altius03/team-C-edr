from __future__ import annotations

from enum import StrEnum
from typing import TypeAlias

from pydantic import BaseModel, ConfigDict, Field, JsonValue

from .service_store import TaskStatus

JsonDocument: TypeAlias = dict[str, JsonValue]


class ApiSettings(BaseModel):
    model_config = ConfigDict(frozen=True)

    require_api_token: bool = True
    api_token: str = "local-dev-token"
    cors_origins: list[str] = Field(default_factory=list)
    task_runner: str = "local"


class ErrorResponse(BaseModel):
    model_config = ConfigDict(frozen=True)

    error: str
    message: str


class TenantHeaders(BaseModel):
    model_config = ConfigDict(frozen=True)

    customer_id: str
    tenant_id: str
    agent_version: str
    payload_version: str


class HealthResponse(BaseModel):
    model_config = ConfigDict(frozen=True)

    status: str = "ok"
    transport: str = "REST"
    framework: str = "fastapi"
    storage: str = "postgresql"
    queue: str = "local-runner"


class TelemetryBatchRequest(BaseModel):
    model_config = ConfigDict(frozen=True)

    events: list[JsonValue] = Field(default_factory=list)


class IngestResponse(BaseModel):
    model_config = ConfigDict(frozen=True)

    status: str
    task_id: str
    task_status: TaskStatus
    accepted_count: int
    queued: bool


class TaskStatusResponse(BaseModel):
    model_config = ConfigDict(frozen=True)

    task_id: str
    task_type: str
    status: TaskStatus
    result: JsonDocument | None = None
    error: str | None = None


class DashboardResult(BaseModel):
    model_config = ConfigDict(extra="allow", frozen=True)

    status: str
    message: str | None = None


class IncidentListResponse(BaseModel):
    model_config = ConfigDict(frozen=True)

    incidents: list[JsonDocument]


class ReportLatestResponse(BaseModel):
    model_config = ConfigDict(frozen=True)

    status: str | None = None
    message: str | None = None
    generated_at: str | None = None
    html_path: str | None = None
    markdown_path: str | None = None
    pdf_export: str | None = None


class Severity(StrEnum):
    CRITICAL = "critical"
    WARNING = "warning"
    SUSPICIOUS = "suspicious"
    INFO = "info"
