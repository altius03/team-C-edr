import http.client
import json
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

PROJECT_DIR = Path(__file__).resolve().parents[1]
if str(PROJECT_DIR) not in sys.path:
    sys.path.insert(0, str(PROJECT_DIR))

from src.sample_loader import load_events
from src.service_api import create_service_server
from src.service_store import ServiceStore, TaskStatus
from src.service_worker import run_default_analysis_job


class ServiceArchitectureTests(unittest.TestCase):
    def test_service_store_persists_run_incidents_and_queue_state(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            store = ServiceStore(Path(temp_dir) / "layertrace.sqlite3")
            store.initialize()

            task = store.enqueue_task("analysis", {"source": "unit-test"})
            claimed = store.claim_next_task()
            self.assertIsNotNone(claimed)
            self.assertEqual(claimed.task_id, task.task_id)

            events, meta = load_events(PROJECT_DIR / "samples" / "default_events.json")
            run_id = run_default_analysis_job(store, events=events, input_meta=meta)
            store.complete_task(task.task_id, TaskStatus.SUCCEEDED, {"run_id": run_id})

            latest = store.get_latest_run()
            self.assertIsNotNone(latest)
            self.assertEqual(latest["status"], "success")
            self.assertGreaterEqual(len(store.list_incidents(severity="critical")), 1)
            self.assertGreater(store.count_events(), 0)
            self.assertGreater(store.count_alerts(), 0)
            self.assertEqual(store.get_task(task.task_id).status, TaskStatus.SUCCEEDED)

    def test_service_api_exposes_health_dashboard_and_incidents(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            store = ServiceStore(Path(temp_dir) / "layertrace.sqlite3")
            store.initialize()
            events, meta = load_events(PROJECT_DIR / "samples" / "default_events.json")
            run_default_analysis_job(store, events=events, input_meta=meta)

            server = create_service_server(("127.0.0.1", 0), store)
            port = server.server_address[1]
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                health = _get_json(port, "/v1/health")
                dashboard = _get_json(port, "/v1/dashboard/latest")
                incidents = _get_json(port, "/v1/incidents?severity=critical")
                report = _get_json(port, "/v1/reports/latest")
                accepted = _post_json(
                    port,
                    "/v1/telemetry/events",
                    {"events": events},
                    {
                        "X-Customer-Id": "techeer-demo",
                        "X-Tenant-Id": "techeer-demo-lab",
                        "X-Agent-Version": "0.4.0",
                        "X-Payload-Version": "1.1",
                        "X-Api-Token": "local-dev-token",
                    },
                )
                task = _wait_for_task(port, str(accepted["task_id"]))
            finally:
                server.shutdown()
                thread.join(timeout=5)
                server.server_close()

            self.assertEqual(health["status"], "ok")
            self.assertEqual(health["framework"], "django")
            self.assertEqual(health["storage"], "sqlite")
            self.assertEqual(dashboard["status"], "success")
            self.assertGreaterEqual(len(incidents["incidents"]), 1)
            self.assertEqual(report["pdf_export"], "browser_print_to_pdf")
            self.assertEqual(accepted["status"], "accepted")
            self.assertEqual(accepted["task_status"], "pending")
            self.assertTrue(accepted["queued"])
            self.assertEqual(accepted["accepted_count"], len(events))
            self.assertEqual(task["status"], "succeeded")


def _get_json(port: int, path: str) -> dict[str, object]:
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        connection.request("GET", path)
        response = connection.getresponse()
        body = response.read().decode("utf-8")
    finally:
        connection.close()
    if response.status != 200:
        raise AssertionError(f"GET {path} returned {response.status}: {body}")
    parsed = json.loads(body)
    if not isinstance(parsed, dict):
        raise AssertionError(f"GET {path} did not return a JSON object: {body}")
    return parsed


def _post_json(port: int, path: str, payload: dict[str, object], headers: dict[str, str]) -> dict[str, object]:
    body = json.dumps(payload).encode("utf-8")
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        connection.request(
            "POST",
            path,
            body=body,
            headers={"Content-Type": "application/json", "Content-Length": str(len(body)), **headers},
        )
        response = connection.getresponse()
        response_body = response.read().decode("utf-8")
    finally:
        connection.close()
    if response.status != 202:
        raise AssertionError(f"POST {path} returned {response.status}: {response_body}")
    parsed = json.loads(response_body)
    if not isinstance(parsed, dict):
        raise AssertionError(f"POST {path} did not return a JSON object: {response_body}")
    return parsed


def _wait_for_task(port: int, task_id: str) -> dict[str, object]:
    for _ in range(40):
        payload = _get_json(port, f"/v1/tasks/{task_id}")
        if payload.get("status") in {"succeeded", "failed"}:
            return payload
        time.sleep(0.1)
    raise AssertionError(f"task {task_id} did not finish")


if __name__ == "__main__":
    unittest.main()
