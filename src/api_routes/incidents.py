from __future__ import annotations

from fastapi import APIRouter, Depends, Request

from ..api_context import require_read_token_dependency, store_from_request
from ..api_models import IncidentListResponse, Severity

router = APIRouter(tags=["incidents"])


@router.get("/v1/incidents", response_model=IncidentListResponse, dependencies=[Depends(require_read_token_dependency)])
def incidents(request: Request, severity: Severity | None = None) -> IncidentListResponse:
    return IncidentListResponse(incidents=store_from_request(request).list_incidents(severity=severity.value if severity else None))
