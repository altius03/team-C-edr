from __future__ import annotations

from fastapi import APIRouter, Depends, Request, status

from ..api_context import ApiError, require_read_token_dependency, store_from_request
from ..api_models import TaskStatusResponse

router = APIRouter(tags=["tasks"])


@router.get("/v1/tasks/{task_id}", response_model=TaskStatusResponse, dependencies=[Depends(require_read_token_dependency)])
def task_detail(task_id: str, request: Request) -> TaskStatusResponse:
    try:
        task = store_from_request(request).get_task(task_id)
    except KeyError:
        raise ApiError(status.HTTP_404_NOT_FOUND, "not_found", f"task {task_id} was not found") from None
    return TaskStatusResponse(
        task_id=task.task_id,
        task_type=task.task_type,
        status=task.status,
        result=task.result,
        error=task.error,
    )
