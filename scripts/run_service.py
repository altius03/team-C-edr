from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parents[1]
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from src.config import DEFAULT_EVENTS_PATH, LATEST_OUTPUT_DIR, SERVICE_DB_PATH
from src.sample_loader import load_events
from src.service_api import create_service_server
from src.service_store import ServiceStore
from src.service_worker import run_default_analysis_job


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the local LayerTrace REST service.")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--db-path", type=Path, default=SERVICE_DB_PATH)
    parser.add_argument("--seed-sample", action="store_true", help="Run sample telemetry into SQLite before serving.")
    parser.add_argument("--no-seed-latest", action="store_true", help="Do not import outputs/latest/result.json on startup.")
    args = parser.parse_args()

    store = ServiceStore(args.db_path)
    store.initialize()
    _seed_store(store, seed_latest=not args.no_seed_latest, seed_sample=args.seed_sample)

    server = create_service_server((args.host, args.port), store)
    print(f"LayerTrace REST service listening on http://{args.host}:{args.port}")
    print("Available: /v1/health, /v1/dashboard/latest, /v1/incidents, /v1/reports/latest")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("Stopping LayerTrace REST service")
    finally:
        server.server_close()
    return 0


def _seed_store(store: ServiceStore, *, seed_latest: bool, seed_sample: bool) -> None:
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
