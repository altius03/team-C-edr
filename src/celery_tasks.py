from __future__ import annotations

import os

from .celery_app import celery_app
from .config import DEFAULT_DATABASE_URL
from .service_store import JsonObject, ServiceStore, TaskStatus
from .service_worker import run_default_analysis_job


def database_url_from_env() -> str:
    return os.environ.get("DATABASE_URL") or os.environ.get("LAYERTRACE_DATABASE_URL") or DEFAULT_DATABASE_URL


@celery_app.task(name="layertrace.analysis.run")
def run_analysis_task(events: list[JsonObject], input_meta: JsonObject, database_url: str | None = None) -> JsonObject:
    store = ServiceStore(database_url=database_url or database_url_from_env())
    try:
        store.initialize()
        run_id = run_default_analysis_job(store, events=events, input_meta=input_meta)
        return {"status": TaskStatus.SUCCEEDED.value, "run_id": run_id}
    finally:
        store.close()
