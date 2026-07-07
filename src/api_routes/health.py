from __future__ import annotations

from fastapi import APIRouter, Request

from ..api_context import queue_from_request, store_from_request
from ..api_models import HealthResponse

router = APIRouter(tags=["health"])


@router.get("/v1/health", response_model=HealthResponse)
def health(request: Request) -> HealthResponse:
    return HealthResponse(storage=store_from_request(request).storage_label, queue=queue_from_request(request).queue_label)
