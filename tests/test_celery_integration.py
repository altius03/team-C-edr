import http.client
import json
import tempfile
import threading
import unittest
from pathlib import Path

from src.api_models import ApiSettings
from src.sample_loader import load_events
from src.service_api import create_service_server
from src.service_store import JsonObject, ServiceStore, TaskStatus

PROJECT_DIR = Path(__file__).resolve().parents[1]


class CeleryIntegrationTests(unittest.TestCase):
    def test_celery_queue_publishes_analysis_task_without_database_queue_polling(self) -> None:
        from src.task_queue import CeleryTaskQueue

        with tempfile.TemporaryDirectory() as temp_dir:
            store = ServiceStore(Path(temp_dir) / "layertrace.sqlite3")
            store.initialize()
            events, _ = load_events(PROJECT_DIR / "samples" / "default_events.json")
            published: list[JsonObject] = []
            task_queue = CeleryTaskQueue(
                broker_url="memory://",
                task_sender=lambda events, input_meta: _record_publish(published, events, input_meta),
            )
            server = create_service_server(
                ("127.0.0.1", 0),
                store,
                task_queue=task_queue,
                settings=ApiSettings(api_token="local-dev-token", allow_public_reads=True, task_runner="celery"),
            )
            port = server.server_address[1]
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                health = _get_json(port, "/v1/health")
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
            finally:
                server.shutdown()
                thread.join(timeout=5)
                server.server_close()
                store.close()

            self.assertEqual(health["queue"], "celery-redis")
            self.assertEqual(accepted["status"], "accepted")
            self.assertEqual(accepted["task_id"], "celery-task-123")
            self.assertEqual(accepted["task_status"], TaskStatus.PENDING.value)
            self.assertTrue(accepted["queued"])
            self.assertEqual(len(published), 1)
            self.assertEqual(published[0]["input_meta"]["source"], "rest_api")
            with self.assertRaises(KeyError):
                store.get_task("celery-task-123")

    def test_celery_task_runs_default_analysis_and_persists_postgres_read_model(self) -> None:
        from src.celery_tasks import run_analysis_task

        with tempfile.TemporaryDirectory() as temp_dir:
            database_url = f"sqlite:///{Path(temp_dir) / 'layertrace.sqlite3'}"
            store = ServiceStore(database_url=database_url)
            store.initialize()
            store.close()
            events, input_meta = load_events(PROJECT_DIR / "samples" / "default_events.json")

            result = run_analysis_task.run(
                events=events,
                input_meta=input_meta,
                database_url=database_url,
            )

            persisted = ServiceStore(database_url=database_url)
            try:
                latest = persisted.get_latest_run()
                self.assertIsNotNone(latest)
                self.assertEqual(latest["status"], "success")
                self.assertEqual(result["status"], TaskStatus.SUCCEEDED.value)
                self.assertTrue(str(result["run_id"]).startswith("run-"))
                self.assertGreater(persisted.count_events(), 0)
                self.assertGreater(persisted.count_alerts(), 0)
                self.assertGreaterEqual(len(persisted.list_incidents(severity="critical")), 1)
            finally:
                persisted.close()

    def test_celery_app_uses_redis_broker_without_result_backend(self) -> None:
        from src.celery_app import create_celery_app

        app = create_celery_app("redis://redis:6379/0")

        self.assertEqual(app.conf.broker_url, "redis://redis:6379/0")
        self.assertIn(app.conf.result_backend, {None, "disabled://"})


def _record_publish(published: list[JsonObject], events: list[JsonObject], input_meta: JsonObject) -> str:
    published.append({"events": events, "input_meta": input_meta})
    return "celery-task-123"


def _get_json(port: int, path: str) -> JsonObject:
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


def _post_json(port: int, path: str, payload: JsonObject, headers: dict[str, str]) -> JsonObject:
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


if __name__ == "__main__":
    unittest.main()
