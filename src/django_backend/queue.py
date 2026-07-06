from __future__ import annotations

from threading import Lock, Thread

from src.service_store import JsonObject, QueuedTask, ServiceStore, TaskStatus
from src.service_worker import run_default_analysis_job

_worker_lock = Lock()


def enqueue_analysis_job(
    store: ServiceStore,
    *,
    events: list[JsonObject],
    input_meta: JsonObject,
) -> QueuedTask:
    # This in-process queue is intentionally small for the local PoC. The
    # ServiceStore task contract is the boundary that can later move to Celery,
    # RabbitMQ, or Kafka without changing the REST API shape.
    task = store.enqueue_task("analysis", {"events": events, "input_meta": input_meta})
    Thread(target=_drain_queue, args=(store,), daemon=True).start()
    return task


def _drain_queue(store: ServiceStore) -> None:
    # Only one worker drains at a time so SQLite writes stay predictable during
    # local demos and unit tests.
    if not _worker_lock.acquire(blocking=False):
        return
    try:
        while True:
            task = store.claim_next_task()
            if task is None:
                return
            try:
                events = task.payload.get("events")
                input_meta = task.payload.get("input_meta")
                if not isinstance(events, list) or not isinstance(input_meta, dict):
                    raise ValueError("analysis task payload must include events and input_meta")
                event_objects = [event for event in events if isinstance(event, dict)]
                run_id = run_default_analysis_job(store, events=event_objects, input_meta=input_meta)
                store.complete_task(task.task_id, TaskStatus.SUCCEEDED, {"run_id": run_id})
            except Exception as exc:  # pragma: no cover - exercised by integration failure paths.
                store.fail_task(task.task_id, str(exc))
    finally:
        _worker_lock.release()
