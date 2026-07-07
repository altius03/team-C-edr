"""Protect FastAPI REST behavior through real local HTTP requests."""

import json
import http.client
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

PROJECT_DIR = Path(__file__).resolve().parents[1]
if str(PROJECT_DIR) not in sys.path:
    sys.path.insert(0, str(PROJECT_DIR))

from src.api_app import create_app
from src.api_models import ApiSettings
from src.sample_loader import load_events
from src.service_api import create_service_server
from src.service_store import JsonObject, JsonValue
from src.service_store import ServiceStore
from src.service_worker import run_default_analysis_job


class FastAPIBackendTests(unittest.TestCase):
    """Exercise service endpoints, OpenAPI paths, and ingestion error handling."""

    def test_fastapi_app_exposes_service_contract_and_openapi(self) -> None:
        """Ensure the HTTP API serves health, dashboard, incidents, reports, and tasks."""
        with tempfile.TemporaryDirectory() as temp_dir:
            store = ServiceStore(Path(temp_dir) / "layertrace.sqlite3")
            store.initialize()
            events, meta = load_events(PROJECT_DIR / "samples" / "default_events.json")
            run_default_analysis_job(store, events=events, input_meta=meta)

            settings = ApiSettings(api_token="local-dev-token", allow_public_reads=True)
            server = create_service_server(("127.0.0.1", 0), store, settings=settings)
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

            openapi = create_app(store, settings=settings).openapi()
            self.assertEqual(health["framework"], "fastapi")
            self.assertEqual(dashboard["status"], "success")
            self.assertGreaterEqual(len(incidents["incidents"]), 1)
            self.assertEqual(report["pdf_export"], "browser_print_to_pdf")
            self.assertEqual(accepted["accepted_count"], len(events))
            self.assertEqual(task["status"], "succeeded")
            self.assertIn("/v1/telemetry/events", openapi["paths"])
            self.assertIn("/v1/tasks/{task_id}", openapi["paths"])

    def test_fastapi_ingest_rejects_missing_token_and_bad_json(self) -> None:
        """Ensure ingestion rejects unauthenticated and malformed requests."""
        with tempfile.TemporaryDirectory() as temp_dir:
            store = ServiceStore(Path(temp_dir) / "layertrace.sqlite3")
            store.initialize()
            server = create_service_server(("127.0.0.1", 0), store, settings=ApiSettings(api_token="local-dev-token"))
            port = server.server_address[1]
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                missing_token = _post_raw(
                    port,
                    "/v1/telemetry/events",
                    json.dumps({"events": []}),
                    {
                        "X-Customer-Id": "techeer-demo",
                        "X-Tenant-Id": "techeer-demo-lab",
                        "X-Agent-Version": "0.4.0",
                        "X-Payload-Version": "1.1",
                    },
                )
                bad_json = _post_raw(
                    port,
                    "/v1/telemetry/events",
                    "{",
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

            self.assertEqual(missing_token["status"], 401)
            self.assertEqual(missing_token["body"]["error"], "unauthorized")
            self.assertEqual(bad_json["status"], 400)
            self.assertEqual(bad_json["body"]["error"], "invalid_json")

    def test_fastapi_production_read_endpoints_require_token_and_openapi_security(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            store = ServiceStore(Path(temp_dir) / "layertrace.sqlite3")
            store.initialize()
            events, meta = load_events(PROJECT_DIR / "samples" / "default_events.json")
            run_default_analysis_job(store, events=events, input_meta=meta)
            settings = ApiSettings(require_api_token=True, api_token="prod-token", task_runner="external")

            server = create_service_server(("127.0.0.1", 0), store, settings=settings)
            port = server.server_address[1]
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                health = _get_json(port, "/v1/health")
                protected_paths = ("/v1/dashboard/latest", "/v1/reports/latest", "/v1/incidents", "/v1/tasks/not-real")
                unauthenticated = {path: _get_raw(port, path)["status"] for path in protected_paths}
                authenticated_dashboard = _get_json(port, "/v1/dashboard/latest", {"X-Api-Token": "prod-token"})
            finally:
                server.shutdown()
                thread.join(timeout=5)
                server.server_close()

            openapi = create_app(store, settings=settings).openapi()

        self.assertEqual(health["status"], "ok")
        self.assertEqual(unauthenticated, {path: 401 for path in protected_paths})
        self.assertEqual(authenticated_dashboard["status"], "success")
        for path in ("/v1/dashboard/latest", "/v1/reports/latest", "/v1/incidents", "/v1/tasks/{task_id}"):
            self.assertTrue(openapi["paths"][path]["get"].get("security"), path)

    def test_fastapi_ingest_rejects_mixed_non_object_event_batch(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            store = ServiceStore(Path(temp_dir) / "layertrace.sqlite3")
            store.initialize()
            server = create_service_server(("127.0.0.1", 0), store, settings=ApiSettings(api_token="local-dev-token"))
            port = server.server_address[1]
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                malformed_batch = _post_raw(
                    port,
                    "/v1/telemetry/events",
                    json.dumps({"events": [{"event_id": "valid-minimal"}, "not-an-object", 42]}),
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

        self.assertIn(malformed_batch["status"], {400, 422})
        self.assertIn(malformed_batch["body"]["error"], {"invalid_request", "invalid_event_batch"})


def _get_json(port: int, path: str, headers: dict[str, str] | None = None) -> JsonObject:
    """Fetch a JSON object from the temporary HTTP service."""
    result = _get_raw(port, path, headers)
    if result["status"] != 200:
        raise AssertionError(f"GET {path} returned {result['status']}: {result['body']}")
    body = result["body"]
    if not isinstance(body, dict):
        raise AssertionError(f"GET {path} did not return a JSON object: {body}")
    return body


def _get_raw(port: int, path: str, headers: dict[str, str] | None = None) -> JsonObject:
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        connection.request("GET", path, headers=headers or {})
        response = connection.getresponse()
        body = response.read().decode("utf-8")
    finally:
        connection.close()
    return {"status": response.status, "body": _json_body(body)}


def _post_json(port: int, path: str, payload: JsonObject, headers: dict[str, str]) -> JsonObject:
    """Post JSON and require the accepted ingestion response."""
    result = _post_raw(port, path, json.dumps(payload), headers)
    if result["status"] != 202:
        raise AssertionError(f"POST {path} returned {result['status']}: {result['body']}")
    body = result["body"]
    if not isinstance(body, dict):
        raise AssertionError(f"POST {path} did not return a JSON object: {body}")
    return body


def _post_raw(port: int, path: str, body: str, headers: dict[str, str]) -> JsonObject:
    """Post raw request text so tests can cover malformed JSON payloads."""
    encoded = body.encode("utf-8")
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        connection.request(
            "POST",
            path,
            body=encoded,
            headers={"Content-Type": "application/json", "Content-Length": str(len(encoded)), **headers},
        )
        response = connection.getresponse()
        response_body = response.read().decode("utf-8")
    finally:
        connection.close()
    return {"status": response.status, "body": _json_body(response_body)}


def _wait_for_task(port: int, task_id: str) -> JsonObject:
    """Poll the task endpoint until the local analysis finishes."""
    for _ in range(40):
        payload = _get_json(port, f"/v1/tasks/{task_id}")
        if payload.get("status") in {"succeeded", "failed"}:
            return payload
        time.sleep(0.1)
    raise AssertionError(f"task {task_id} did not finish")


def _json_body(body: str) -> JsonObject:
    """Parse an HTTP response body and require a JSON object contract."""
    parsed: JsonValue = json.loads(body)
    if not isinstance(parsed, dict):
        raise AssertionError(f"response did not return a JSON object: {body}")
    return parsed


if __name__ == "__main__":
    unittest.main()
