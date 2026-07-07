from __future__ import annotations

import logging
from threading import Lock, Thread
from typing import Protocol, runtime_checkable

from .service_store import JsonObject, QueuedTask, ServiceStore, TaskStatus
from .service_worker import run_default_analysis_job

LOGGER = logging.getLogger(__name__)


@runtime_checkable
class TaskQueue(Protocol):
    @property
    def queue_label(self) -> str:
        ...

    def enqueue_analysis_job(self, events: list[JsonObject], input_meta: JsonObject) -> QueuedTask:
        ...


class DatabaseTaskQueue:
    queue_label = "external-worker"

    def __init__(self, store: ServiceStore) -> None:
        self._store = store

    def enqueue_analysis_job(self, events: list[JsonObject], input_meta: JsonObject) -> QueuedTask:
        task = self._store.enqueue_task("analysis", {"events": events, "input_meta": input_meta})
        LOGGER.info("analysis task enqueued for external worker", extra={"task_id": task.task_id})
        return task


class LocalTaskRunner:
    queue_label = "local-runner"

    def __init__(self, store: ServiceStore) -> None:
        self._store = store
        self._worker_lock = Lock()
        self._worker = TaskWorker(store)

    def enqueue_analysis_job(self, events: list[JsonObject], input_meta: JsonObject) -> QueuedTask:
        task = self._store.enqueue_task("analysis", {"events": events, "input_meta": input_meta})
        LOGGER.info("analysis task enqueued for local runner", extra={"task_id": task.task_id})
        Thread(target=self._drain_queue, daemon=True).start()
        return task

    def _drain_queue(self) -> None:
        if not self._worker_lock.acquire(blocking=False):
            return
        try:
            while True:
                processed = self._worker.drain_once()
                if processed == 0:
                    return
        finally:
            self._worker_lock.release()


class TaskWorker:
    def __init__(self, store: ServiceStore) -> None:
        self._store = store

    def drain_once(self) -> int:
        task = self._store.claim_next_task()
        if task is None:
            return 0
        self._run_task(task)
        return 1

    def _run_task(self, task: QueuedTask) -> None:
        try:
            events = task.payload.get("events")
            input_meta = task.payload.get("input_meta")
            if not isinstance(events, list) or not isinstance(input_meta, dict):
                raise ValueError("analysis task payload must include events and input_meta")
            event_objects = [event for event in events if isinstance(event, dict)]
            run_id = run_default_analysis_job(self._store, events=event_objects, input_meta=input_meta)
            self._store.complete_task(task.task_id, TaskStatus.SUCCEEDED, {"run_id": run_id})
            LOGGER.info("analysis task completed", extra={"task_id": task.task_id, "run_id": run_id})
        except Exception as exc:
            LOGGER.exception("analysis task failed", extra={"task_id": task.task_id})
            self._store.fail_task(task.task_id, str(exc))
