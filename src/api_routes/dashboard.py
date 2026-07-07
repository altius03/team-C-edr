from __future__ import annotations

from fastapi import APIRouter, Depends, Request

from ..api_context import require_read_token_dependency, store_from_request
from ..api_models import DashboardResult

router = APIRouter(tags=["dashboard"])


@router.get("/v1/dashboard/latest", response_model=DashboardResult, dependencies=[Depends(require_read_token_dependency)])
def dashboard_latest(request: Request) -> DashboardResult:
    latest = store_from_request(request).get_latest_run()
    if latest is None:
        return DashboardResult(status="empty", message="no analysis run stored yet")
    return DashboardResult.model_validate(latest)
