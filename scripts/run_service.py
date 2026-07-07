"""Run the local LayerTrace REST API against the configured service store."""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parents[1]
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from src.config import DEFAULT_DATABASE_URL, DEFAULT_EVENTS_PATH, LATEST_OUTPUT_DIR
from src.sample_loader import load_events
from src.api_app import settings_from_env
from src.service_api import create_service_server
from src.service_store import ServiceStore
from src.service_worker import run_default_analysis_job
from src.task_queue import DatabaseTaskQueue, LocalTaskRunner


def main() -> int:
    """Start the HTTP service with optional startup seeding for local validation."""
    logging.basicConfig(level=os.environ.get("LAYERTRACE_LOG_LEVEL", "INFO"), format="%(asctime)s %(levelname)s %(name)s %(message)s")
    parser = argparse.ArgumentParser(description="Run the local LayerTrace FastAPI REST service.")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--database-url", default=os.environ.get("DATABASE_URL") or os.environ.get("LAYERTRACE_DATABASE_URL") or DEFAULT_DATABASE_URL)
    parser.add_argument("--task-runner", choices=["local", "external"], default=os.environ.get("LAYERTRACE_TASK_RUNNER", "local"))
    parser.add_argument("--seed-sample", action="store_true", help="Run sample telemetry into the configured database before serving.")
    parser.add_argument("--no-seed-latest", action="store_true", help="Do not import outputs/latest/result.json on startup.")
    args = parser.parse_args()

    store = ServiceStore(database_url=args.database_url)
    store.initialize()
    _seed_store(store, seed_latest=not args.no_seed_latest, seed_sample=args.seed_sample)

    task_queue = DatabaseTaskQueue(store) if args.task_runner == "external" else LocalTaskRunner(store)
    settings = settings_from_env().model_copy(update={"task_runner": args.task_runner})
    server = create_service_server((args.host, args.port), store, task_queue=task_queue, settings=settings)
    print(f"LayerTrace FastAPI REST service listening on http://{args.host}:{args.port}")
    print(f"Storage: {store.storage_label} / task runner: {task_queue.queue_label}")
    print("Available: /docs, /openapi.json, /v1/health, /v1/dashboard/latest, /v1/incidents, /v1/reports/latest")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("Stopping LayerTrace REST service")
    finally:
        server.server_close()
        store.close()
    return 0


def _seed_store(store: ServiceStore, *, seed_latest: bool, seed_sample: bool) -> None:
    """Populate the store from the latest artifact or sample telemetry before serving."""
    latest_result_path = LATEST_OUTPUT_DIR / "result.json"
    if seed_latest and latest_result_path.exists():
        payload = json.loads(latest_result_path.read_text(encoding="utf-8"))
        if isinstance(payload, dict):
            store.save_run_result(payload)
            return
    if seed_sample:
        events, input_meta = load_events(DEFAULT_EVENTS_PATH)
        run_default_analysis_job(store, events=events, input_meta=input_meta)


if __name__ == "__main__":
    raise SystemExit(main())
