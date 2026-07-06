from __future__ import annotations

from threading import Lock, Thread
from typing import Protocol, runtime_checkable

from .service_store import JsonObject, QueuedTask, ServiceStore, TaskStatus
from .service_worker import run_default_analysis_job


@runtime_checkable
class TaskQueue(Protocol):
    def enqueue_analysis_job(self, events: list[JsonObject], input_meta: JsonObject) -> QueuedTask:
        ...


class LocalTaskRunner:
    def __init__(self, store: ServiceStore) -> None:
        self._store = store
        self._worker_lock = Lock()

    def enqueue_analysis_job(self, events: list[JsonObject], input_meta: JsonObject) -> QueuedTask:
        task = self._store.enqueue_task("analysis", {"events": events, "input_meta": input_meta})
        Thread(target=self._drain_queue, daemon=True).start()
        return task

    def _drain_queue(self) -> None:
        if not self._worker_lock.acquire(blocking=False):
            return
        try:
            while True:
                task = self._store.claim_next_task()
                if task is None:
                    return
                self._run_task(task)
        finally:
            self._worker_lock.release()

    def _run_task(self, task: QueuedTask) -> None:
        try:
            events = task.payload.get("events")
            input_meta = task.payload.get("input_meta")
            if not isinstance(events, list) or not isinstance(input_meta, dict):
                raise ValueError("analysis task payload must include events and input_meta")
            event_objects = [event for event in events if isinstance(event, dict)]
            run_id = run_default_analysis_job(self._store, events=event_objects, input_meta=input_meta)
            self._store.complete_task(task.task_id, TaskStatus.SUCCEEDED, {"run_id": run_id})
        except Exception as exc:
            self._store.fail_task(task.task_id, str(exc))
