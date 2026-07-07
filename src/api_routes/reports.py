from __future__ import annotations

from fastapi import APIRouter, Depends, Request

from ..api_context import latest_report_from_run, require_read_token_dependency, store_from_request
from ..api_models import ReportLatestResponse

router = APIRouter(tags=["reports"])


@router.get("/v1/reports/latest", response_model=ReportLatestResponse, dependencies=[Depends(require_read_token_dependency)])
def reports_latest(request: Request) -> ReportLatestResponse:
    return latest_report_from_run(store_from_request(request).get_latest_run())
