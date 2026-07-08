"""Define local and external task queue boundaries for asynchronous analysis."""

from __future__ import annotations

import logging
from threading import Lock, Thread
from typing import Protocol, runtime_checkable

from .service_store import JsonObject, QueuedTask, ServiceStore, TaskStatus
from .service_worker import run_default_analysis_job

LOGGER = logging.getLogger(__name__)


class AnalysisTaskSender(Protocol):
    def __call__(self, events: list[JsonObject], input_meta: JsonObject) -> str: ...


@runtime_checkable
class TaskQueue(Protocol):
    """Queue interface used by the REST API regardless of execution mode."""

    @property
    def queue_label(self) -> str:
        """Return the queue mode shown by the health endpoint."""

        ...

    def enqueue_analysis_job(self, events: list[JsonObject], input_meta: JsonObject) -> QueuedTask:
        """Persist or start an analysis task for the provided telemetry batch."""

        ...


class DatabaseTaskQueue:
    """Queue adapter that leaves persisted tasks for an external worker."""

    queue_label = "external-worker"

    def __init__(self, store: ServiceStore) -> None:
        """Store the persistence dependency used to enqueue tasks."""

        self._store = store

    def enqueue_analysis_job(self, events: list[JsonObject], input_meta: JsonObject) -> QueuedTask:
        """Persist an analysis task without starting local execution."""

        task = self._store.enqueue_task("analysis", {"events": events, "input_meta": input_meta})
        LOGGER.info("analysis task enqueued for external worker", extra={"task_id": task.task_id})
        return task


class CeleryTaskQueue:
    queue_label = "celery-redis"

    def __init__(self, *, broker_url: str | None = None, task_sender: AnalysisTaskSender | None = None) -> None:
        self._broker_url = broker_url
        self._task_sender = task_sender or self._send_analysis_task

    def enqueue_analysis_job(self, events: list[JsonObject], input_meta: JsonObject) -> QueuedTask:
        task_id = self._task_sender(events, input_meta)
        LOGGER.info("analysis task published to celery broker", extra={"task_id": task_id})
        return QueuedTask(
            task_id=task_id,
            task_type="analysis",
            status=TaskStatus.PENDING,
            payload={"events": events, "input_meta": input_meta},
            result=None,
            error=None,
        )

    def _send_analysis_task(self, events: list[JsonObject], input_meta: JsonObject) -> str:
        from .celery_tasks import run_analysis_task

        if self._broker_url:
            run_analysis_task.app.conf.broker_url = self._broker_url
        async_result = run_analysis_task.apply_async(kwargs={"events": events, "input_meta": input_meta})
        if async_result.id is None:
            raise RuntimeError("Celery did not return a task id")
        return async_result.id


class LocalTaskRunner:
    """Queue adapter that drains persisted tasks in an in-process worker thread."""

    queue_label = "local-runner"

    def __init__(self, store: ServiceStore) -> None:
        """Create the local worker and its single-drain concurrency guard."""

        self._store = store
        self._worker_lock = Lock()
        self._worker = TaskWorker(store)

    def enqueue_analysis_job(self, events: list[JsonObject], input_meta: JsonObject) -> QueuedTask:
        """Persist an analysis task and trigger local background draining."""

        task = self._store.enqueue_task("analysis", {"events": events, "input_meta": input_meta})
        LOGGER.info("analysis task enqueued for local runner", extra={"task_id": task.task_id})
        Thread(target=self._drain_queue, daemon=True).start()
        return task

    def _drain_queue(self) -> None:
        """Drain pending tasks while preventing overlapping local workers."""

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
    """Worker that claims persisted tasks and runs the default analysis job."""

    def __init__(self, store: ServiceStore) -> None:
        """Store the persistence dependency used by claimed tasks."""

        self._store = store

    def drain_once(self) -> int:
        """Claim and run at most one pending task, returning the processed count."""

        task = self._store.claim_next_task()
        if task is None:
            return 0
        self._run_task(task)
        return 1

    def _run_task(self, task: QueuedTask) -> None:
        """Run one analysis task and persist success or failure state."""

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
