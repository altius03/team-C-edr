from __future__ import annotations

import logging
from typing import Final

from fastapi import APIRouter, Depends, Request, status

from ..api_context import (
    input_meta_from_headers,
    queue_from_request,
    require_api_token_dependency,
    tenant_headers_from_request,
)
from ..api_models import IngestResponse, TelemetryBatchRequest
from ..service_store import JsonObject

LOGGER = logging.getLogger(__name__)

_INGEST_HEADER_PARAMETERS: Final[list[JsonObject]] = [
    {"name": "X-Customer-Id", "in": "header", "required": True, "schema": {"type": "string"}},
    {"name": "X-Tenant-Id", "in": "header", "required": True, "schema": {"type": "string"}},
    {"name": "X-Agent-Version", "in": "header", "required": True, "schema": {"type": "string"}},
    {"name": "X-Payload-Version", "in": "header", "required": True, "schema": {"type": "string"}},
    {"name": "X-Api-Token", "in": "header", "required": False, "schema": {"type": "string"}},
]

router = APIRouter(tags=["telemetry"])


@router.post(
    "/v1/telemetry/events",
    response_model=IngestResponse,
    status_code=status.HTTP_202_ACCEPTED,
    openapi_extra={"parameters": _INGEST_HEADER_PARAMETERS},
    dependencies=[Depends(require_api_token_dependency)],
)
def telemetry_events(payload: TelemetryBatchRequest, request: Request) -> IngestResponse:
    headers = tenant_headers_from_request(request)
    event_objects = payload.events
    task = queue_from_request(request).enqueue_analysis_job(events=event_objects, input_meta=input_meta_from_headers(headers))
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
