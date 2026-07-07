"""Run the LayerTrace task worker that drains persisted analysis jobs."""

from __future__ import annotations

import argparse
import logging
import os
import sys
import time
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parents[1]
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from src.config import DEFAULT_DATABASE_URL
from src.service_store import ServiceStore
from src.task_queue import TaskWorker


def main() -> int:
    """Drain pending tasks once or keep polling the configured service store."""
    logging.basicConfig(level=os.environ.get("LAYERTRACE_LOG_LEVEL", "INFO"), format="%(asctime)s %(levelname)s %(name)s %(message)s")
    parser = argparse.ArgumentParser(description="Run the LayerTrace task worker.")
    parser.add_argument("--database-url", default=os.environ.get("DATABASE_URL") or os.environ.get("LAYERTRACE_DATABASE_URL") or DEFAULT_DATABASE_URL)
    parser.add_argument("--poll-interval", type=float, default=1.0)
    parser.add_argument("--once", action="store_true", help="Drain available tasks once and exit.")
    args = parser.parse_args()

    store = ServiceStore(database_url=args.database_url)
    worker = TaskWorker(store)
    store.initialize()
    print(f"LayerTrace worker using {store.storage_label}")
    try:
        while True:
            processed = worker.drain_once()
            if args.once:
                return 0
            if processed == 0:
                time.sleep(max(args.poll_interval, 0.1))
    except KeyboardInterrupt:
        print("Stopping LayerTrace worker")
        return 0
    finally:
        store.close()


if __name__ == "__main__":
    raise SystemExit(main())
