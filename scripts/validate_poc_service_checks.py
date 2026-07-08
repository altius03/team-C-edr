from __future__ import annotations

import http.client
import json
import tempfile
import threading
import time
from pathlib import Path
from typing import Any

from scripts.validate_poc_paths import BASE_DIR


def _check_service_architecture() -> dict[str, Any]:
    failures: list[str] = []
    try:
        from src.api_models import ApiSettings
        from src.sample_loader import load_events
        from src.service_api import create_service_server
        from src.service_store import ServiceStore, TaskStatus
        from src.service_worker import run_default_analysis_job
    except Exception as exc:
        return {"name": "service_architecture", "status": "fail", "details": f"service import failed: {exc}"}

    with tempfile.TemporaryDirectory() as temp_dir:
        store = ServiceStore(Path(temp_dir) / "layertrace.sqlite3")
        try:
            store.initialize()
            task = store.enqueue_task("analysis", {"source": "validate_poc"})
            claimed = store.claim_next_task()
            if claimed is None or claimed.task_id != task.task_id:
                failures.append("local queue did not claim the pending analysis task")
            events, input_meta = load_events(BASE_DIR / "samples" / "default_events.json")
            run_id = run_default_analysis_job(store, events=events, input_meta=input_meta)
            store.complete_task(task.task_id, TaskStatus.SUCCEEDED, {"run_id": run_id})
            latest = store.get_latest_run()
            if not latest or latest.get("status") != "success":
                failures.append("service store did not persist the latest successful run")
            if store.get_task(task.task_id).status != TaskStatus.SUCCEEDED:
                failures.append("local queue did not persist the succeeded task state")
            if not store.list_incidents(severity="critical"):
                failures.append("service incident query did not return critical incidents")
            if store.count_dlq_events() < 1:
                failures.append("service DLQ table did not persist rejected telemetry")
            if store.count_outbox_events() < 3:
                failures.append("service outbox_events table did not capture run/task events")
            settings = ApiSettings(api_token="local-dev-token", allow_public_reads=True)
            failures.extend(_check_service_http_surface(create_service_server, store, events, settings))
        finally:
            store.close()

    return {
        "name": "service_architecture",
        "status": "pass" if not failures else "fail",
        "details": "Service store, local queue, and REST surface are functional." if not failures else failures,
    }


def _check_service_http_surface(create_service_server: Any, store: Any, events: list[dict[str, Any]], settings: Any) -> list[str]:
    failures: list[str] = []
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
        task = _wait_for_task(port, str(accepted.get("task_id")))
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()
    if health.get("status") != "ok" or health.get("storage") != "sqlite" or health.get("framework") != "fastapi":
        failures.append(f"health endpoint returned unexpected payload: {health}")
    if dashboard.get("status") != "success":
        failures.append("dashboard latest endpoint did not return the saved successful run")
    if not incidents.get("incidents"):
        failures.append("incidents endpoint did not return critical incidents")
    if report.get("pdf_export") != "browser_print_to_pdf":
        failures.append("latest report endpoint did not expose print-to-PDF metadata")
    if accepted.get("status") != "accepted" or accepted.get("accepted_count") != len(events) or not accepted.get("queued"):
        failures.append(f"telemetry ingestion endpoint returned unexpected payload: {accepted}")
    if task.get("status") != "succeeded":
        failures.append(f"queued analysis task did not complete successfully: {task}")
    return failures


def _check_openapi_contract() -> dict[str, Any]:
    failures: list[str] = []
    try:
        from src.api_app import create_app
        from src.service_store import ServiceStore
    except Exception as exc:
        failures.append(f"FastAPI OpenAPI import failed: {exc}")
    if not failures:
        with tempfile.TemporaryDirectory() as temp_dir:
            store = ServiceStore(Path(temp_dir) / "layertrace.sqlite3")
            try:
                openapi = create_app(store).openapi()
            finally:
                store.close()
            text = json.dumps(openapi, ensure_ascii=False)
            for required in (
                '"openapi":',
                "/v1/telemetry/events",
                "/v1/tasks/{task_id}",
                "/v1/dashboard/latest",
                "/v1/reports/latest",
                "X-Customer-Id",
                "X-Agent-Version",
                "REST",
                "postgresql",
                "local-runner",
            ):
                if required not in text:
                    failures.append(f"FastAPI OpenAPI contract missing: {required}")
            if "future_transport" in text:
                failures.append("OpenAPI contract still includes future transport")
    return {
        "name": "openapi_contract",
        "status": "pass" if not failures else "fail",
        "details": "FastAPI OpenAPI REST contract is generated." if not failures else failures,
    }


def _get_json(port: int, path: str) -> dict[str, Any]:
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        connection.request("GET", path)
        response = connection.getresponse()
        body = response.read().decode("utf-8")
    finally:
        connection.close()
    if response.status != 200:
        raise RuntimeError(f"GET {path} returned {response.status}: {body}")
    parsed = json.loads(body)
    if not isinstance(parsed, dict):
        raise TypeError(f"GET {path} did not return a JSON object")
    return parsed


def _post_json(port: int, path: str, payload: dict[str, Any], headers: dict[str, str]) -> dict[str, Any]:
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
        raise RuntimeError(f"POST {path} returned {response.status}: {response_body}")
    parsed = json.loads(response_body)
    if not isinstance(parsed, dict):
        raise TypeError(f"POST {path} did not return a JSON object")
    return parsed


def _wait_for_task(port: int, task_id: str) -> dict[str, Any]:
    for _ in range(40):
        payload = _get_json(port, f"/v1/tasks/{task_id}")
        if payload.get("status") in {"succeeded", "failed"}:
            return payload
        time.sleep(0.1)
    return {"task_id": task_id, "status": "timeout"}
