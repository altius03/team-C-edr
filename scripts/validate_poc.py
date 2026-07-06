from __future__ import annotations

import compileall
import http.client
import json
import subprocess
import sys
import tempfile
import threading
from datetime import datetime
from pathlib import Path
from typing import Any


BASE_DIR = Path(__file__).resolve().parents[1]
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))
LATEST_RESULT_PATH = BASE_DIR / "outputs" / "latest" / "result.json"
VERIFICATION_DIR = BASE_DIR / "outputs" / "verification"
DASHBOARD_INDEX_PATH = BASE_DIR / "dashboard" / "index.html"
DASHBOARD_APP_PATH = BASE_DIR / "dashboard" / "app.js"
DASHBOARD_DATA_PATH = BASE_DIR / "dashboard" / "data" / "latest-result.js"
PACKAGE_JSON_PATH = BASE_DIR / "package.json"
PACKAGE_LOCK_PATH = BASE_DIR / "package-lock.json"
REACT_INDEX_PATH = BASE_DIR / "web" / "index.html"
REACT_APP_PATH = BASE_DIR / "web" / "src" / "App.tsx"
REACT_ADAPTER_PATH = BASE_DIR / "web" / "src" / "resultAdapter.ts"
REACT_STYLES_PATH = BASE_DIR / "web" / "src" / "styles.css"
REACT_BUILD_SCRIPT_PATH = BASE_DIR / "scripts" / "build_react.mjs"
WEB_DASHBOARD_JSON_PATH = BASE_DIR / "web" / "public" / "latest-result.json"
LATEST_REPORT_MD_PATH = BASE_DIR / "outputs" / "reports" / "latest" / "security_report.md"
LATEST_REPORT_HTML_PATH = BASE_DIR / "outputs" / "reports" / "latest" / "security_report.html"
LATEST_PIPELINE_BUNDLE_PATH = BASE_DIR / "outputs" / "pipeline" / "latest" / "telemetry_bundle.json.gz"
OPENAPI_PATH = BASE_DIR / "docs" / "openapi.yaml"


def main() -> int:
    checks: list[dict[str, Any]] = []
    checks.append(_check_compile())
    checks.append(_check_unit_tests())
    checks.append(_check_cli_default_run())
    result = _read_latest_result()
    checks.append(_check_result_contract(result))
    checks.append(_check_dashboard_artifacts())
    checks.append(_check_react_project_contract())
    checks.append(_check_react_build())
    checks.append(_check_service_architecture())
    checks.append(_check_report_artifacts(result))
    checks.append(_check_pipeline_artifacts(result))
    checks.append(_check_openapi_contract())

    report = _build_report(checks, result)
    paths = _write_report(report)
    _print_summary(report, paths)
    return 1 if any(check["status"] == "fail" for check in checks) else 0


def _check_compile() -> dict[str, Any]:
    ok = compileall.compile_dir(str(BASE_DIR / "src"), quiet=1, force=True)
    return {
        "name": "python_compile",
        "status": "pass" if ok else "fail",
        "details": "src modules compile successfully." if ok else "At least one src module failed to compile.",
    }


def _check_unit_tests() -> dict[str, Any]:
    completed = subprocess.run(
        [sys.executable, "-m", "unittest", "discover", "-s", "tests"],
        cwd=BASE_DIR,
        text=True,
        capture_output=True,
        encoding="utf-8",
        errors="replace",
        timeout=30,
    )
    return {
        "name": "unit_tests",
        "status": "pass" if completed.returncode == 0 else "fail",
        "details": _combined_output(completed),
    }


def _check_cli_default_run() -> dict[str, Any]:
    completed = subprocess.run(
        [sys.executable, "-m", "src.run"],
        cwd=BASE_DIR,
        text=True,
        capture_output=True,
        encoding="utf-8",
        errors="replace",
        timeout=30,
    )
    return {
        "name": "cli_default_run",
        "status": "pass" if completed.returncode == 0 else "fail",
        "details": {
            "returncode": completed.returncode,
            "stdout": completed.stdout.strip(),
            "stderr": completed.stderr.strip(),
        },
    }


def _check_result_contract(result: dict[str, Any]) -> dict[str, Any]:
    failures: list[str] = []
    if result.get("status") != "success":
        failures.append(f"status is {result.get('status')!r}, expected success")
    if result.get("decision") != "needs_security_review":
        failures.append(f"decision is {result.get('decision')!r}, expected needs_security_review")

    summary = result.get("summary", {})
    if summary.get("input_event_count", 0) < 50:
        failures.append("input_event_count below 50")
    if summary.get("valid_event_count", 0) < 50:
        failures.append("valid_event_count below 50")
    if summary.get("dlq_event_count", 0) < 1:
        failures.append("invalid event was not sent to DLQ")
    if summary.get("alert_count", 0) < 8:
        failures.append("alert_count below expected rule coverage")
    if summary.get("l7_event_count", 0) < 2:
        failures.append("L7 event coverage missing")
    if summary.get("decryption_event_count", 0) < 1:
        failures.append("decryption event coverage missing")
    if summary.get("response_action_count", 0) < 1:
        failures.append("response actions were not generated")
    if summary.get("ai_prediction_count", 0) < 1:
        failures.append("AI predictions were not generated")
    if not result.get("edr_state", {}).get("state"):
        failures.append("EDR RED/YELLOW/GREEN state is missing")
    siem = result.get("siem_analysis", {})
    if not siem.get("query_findings"):
        failures.append("SIEM query findings are missing")
    if not siem.get("egress_topology", {}).get("edges"):
        failures.append("Endpoint egress topology edges are missing")
    serialized = json.dumps(result, ensure_ascii=False)
    for name in ("황건하", "박소연", "이혜령", "이주호"):
        if name not in serialized:
            failures.append(f"missing host display name: {name}")

    rules = {alert.get("rule_id") for alert in result.get("alerts", [])}
    for rule_id in {"R001", "R002", "R003", "R004", "R005", "R006", "R007", "R008", "R009", "R010", "R011"}:
        if rule_id not in rules:
            failures.append(f"missing rule alert: {rule_id}")

    incident_tactics = {
        mapping.get("tactic")
        for incident in result.get("incidents", [])
        for mapping in incident.get("mitre_mapping", [])
    }
    for tactic in {"Initial Access", "Execution", "Command and Control", "Exfiltration"}:
        if tactic not in incident_tactics:
            failures.append(f"missing MITRE tactic: {tactic}")

    if (
        "김테커" in serialized
        or "private message body should never be retained" in serialized
        or "sample body must be removed" in serialized
        or "이 메시지 본문" in serialized
    ):
        failures.append("privacy-sensitive sample value leaked into result")

    return {
        "name": "result_contract",
        "status": "pass" if not failures else "fail",
        "details": "result JSON satisfies PoC contract." if not failures else failures,
    }


def _check_dashboard_artifacts() -> dict[str, Any]:
    failures: list[str] = []
    if not DASHBOARD_INDEX_PATH.exists():
        failures.append(f"missing dashboard index: {DASHBOARD_INDEX_PATH}")
    else:
        index = DASHBOARD_INDEX_PATH.read_text(encoding="utf-8")
        for required in (
            "Endpoint Egress Topology",
            'class="visual-stage',
            'id="detection-chart-panel"',
            'id="detection-charts"',
            'id="alert-inspector"',
            'id="data-source-current"',
            'id="data-source-switch"',
            'id="report-modal"',
            'value="last10m"',
            'value="last1h"',
            'value="last24h"',
        ):
            if required not in index:
                failures.append(f"dashboard surface missing: {required}")
        if "result JSON" in index or "../outputs/latest/result.json" in index:
            failures.append("dashboard still exposes result JSON link")
    if not DASHBOARD_APP_PATH.exists():
        failures.append(f"missing dashboard app: {DASHBOARD_APP_PATH}")
    else:
        app = DASHBOARD_APP_PATH.read_text(encoding="utf-8")
        for required in (
            "renderTopologySvg",
            "renderDetectionCharts",
            "Endpoint fleet",
            "Protected tenant boundary",
            "External destinations",
            "python -m src.run --collect-local",
        ):
            if required not in app:
                failures.append(f"dashboard app missing visual behavior: {required}")
    if not DASHBOARD_DATA_PATH.exists():
        failures.append(f"missing dashboard data script: {DASHBOARD_DATA_PATH}")
    elif "window.SIEM_RESULT" not in DASHBOARD_DATA_PATH.read_text(encoding="utf-8"):
        failures.append("dashboard data script does not define window.SIEM_RESULT")
    if not WEB_DASHBOARD_JSON_PATH.exists():
        failures.append(f"missing React dashboard JSON: {WEB_DASHBOARD_JSON_PATH}")

    return {
        "name": "dashboard_artifacts",
        "status": "pass" if not failures else "fail",
        "details": "dashboard index and latest-result.js are present." if not failures else failures,
    }


def _check_react_project_contract() -> dict[str, Any]:
    failures: list[str] = []
    for path in (
        PACKAGE_JSON_PATH,
        PACKAGE_LOCK_PATH,
        REACT_INDEX_PATH,
        REACT_APP_PATH,
        REACT_ADAPTER_PATH,
        REACT_STYLES_PATH,
        REACT_BUILD_SCRIPT_PATH,
    ):
        if not path.exists():
            failures.append(f"missing React project file: {path}")
    if PACKAGE_JSON_PATH.exists():
        package = json.loads(PACKAGE_JSON_PATH.read_text(encoding="utf-8"))
        scripts = package.get("scripts", {})
        dependencies = package.get("dependencies", {})
        dev_dependencies = package.get("devDependencies", {})
        for script in ("dev", "build", "preview", "typecheck"):
            if script not in scripts:
                failures.append(f"package script missing: {script}")
        if "scripts/build_react.mjs" not in scripts.get("build", ""):
            failures.append("build script must use the verified React build wrapper")
        for dependency in ("react", "react-dom"):
            if dependency not in dependencies:
                failures.append(f"React dependency missing: {dependency}")
        for dependency in ("typescript", "vite"):
            if dependency not in dev_dependencies:
                failures.append(f"React dev dependency missing: {dependency}")
    if REACT_APP_PATH.exists():
        app = REACT_APP_PATH.read_text(encoding="utf-8")
        for required in (
            "Endpoint fleet",
            "Protected tenant boundary",
            "External destinations",
            "last10m",
            "last1h",
            "last24h",
            "severityFilter",
            "ReportModal",
        ):
            if required not in app:
                failures.append(f"React dashboard missing surface text/behavior: {required}")
        if "result JSON" in app:
            failures.append("React dashboard still exposes result JSON copy")
    if REACT_ADAPTER_PATH.exists():
        adapter = REACT_ADAPTER_PATH.read_text(encoding="utf-8")
        if "latest-result.json" not in adapter or "window.SIEM_RESULT" not in adapter:
            failures.append("React adapter must support static JSON and legacy SIEM_RESULT fallback")

    return {
        "name": "react_project_contract",
        "status": "pass" if not failures else "fail",
        "details": "React/Vite project contract is present." if not failures else failures,
    }


def _check_react_build() -> dict[str, Any]:
    completed = subprocess.run(
        [_npm_command(), "run", "build"],
        cwd=BASE_DIR,
        text=True,
        capture_output=True,
        encoding="utf-8",
        errors="replace",
        timeout=60,
    )
    return {
        "name": "react_build",
        "status": "pass" if completed.returncode == 0 else "fail",
        "details": _combined_output(completed),
    }


def _check_service_architecture() -> dict[str, Any]:
    failures: list[str] = []
    try:
        from src.sample_loader import load_events
        from src.service_api import create_service_server
        from src.service_store import ServiceStore, TaskStatus
        from src.service_worker import run_default_analysis_job
    except Exception as exc:
        return {"name": "service_architecture", "status": "fail", "details": f"service import failed: {exc}"}

    with tempfile.TemporaryDirectory() as temp_dir:
        store = ServiceStore(Path(temp_dir) / "layertrace.sqlite3")
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
            failures.append("SQLite store did not persist the latest successful run")
        if store.get_task(task.task_id).status != TaskStatus.SUCCEEDED:
            failures.append("local queue did not persist the succeeded task state")
        if not store.list_incidents(severity="critical"):
            failures.append("SQLite incident query did not return critical incidents")
        failures.extend(_check_service_http_surface(create_service_server, store, events))

    return {
        "name": "service_architecture",
        "status": "pass" if not failures else "fail",
        "details": "SQLite store, local queue, and REST surface are functional." if not failures else failures,
    }


def _check_service_http_surface(create_service_server: Any, store: Any, events: list[dict[str, Any]]) -> list[str]:
    failures: list[str] = []
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
            },
        )
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()
    if health.get("status") != "ok" or health.get("storage") != "sqlite":
        failures.append(f"health endpoint returned unexpected payload: {health}")
    if dashboard.get("status") != "success":
        failures.append("dashboard latest endpoint did not return the saved successful run")
    if not incidents.get("incidents"):
        failures.append("incidents endpoint did not return critical incidents")
    if report.get("pdf_export") != "browser_print_to_pdf":
        failures.append("latest report endpoint did not expose print-to-PDF metadata")
    if accepted.get("status") != "accepted" or accepted.get("accepted_count") != len(events):
        failures.append(f"telemetry ingestion endpoint returned unexpected payload: {accepted}")
    return failures


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


def _check_report_artifacts(result: dict[str, Any]) -> dict[str, Any]:
    failures: list[str] = []
    if not LATEST_REPORT_MD_PATH.exists():
        failures.append(f"missing report markdown: {LATEST_REPORT_MD_PATH}")
    else:
        markdown = LATEST_REPORT_MD_PATH.read_text(encoding="utf-8")
        if "LayerTrace EDR/SIEM 분석 보고서" not in markdown:
            failures.append("markdown report title is missing")
        if "Endpoint Egress Topology" not in markdown or "SIEM Analysis" not in markdown:
            failures.append("markdown report SIEM sections are missing")
    if not LATEST_REPORT_HTML_PATH.exists():
        failures.append(f"missing report html: {LATEST_REPORT_HTML_PATH}")
    elif "<html" not in LATEST_REPORT_HTML_PATH.read_text(encoding="utf-8"):
        failures.append("html report is not valid-looking HTML")
    if not result.get("report"):
        failures.append("result JSON does not include report paths")

    return {
        "name": "report_artifacts",
        "status": "pass" if not failures else "fail",
        "details": "latest Markdown/HTML reports are present." if not failures else failures,
    }


def _check_pipeline_artifacts(result: dict[str, Any]) -> dict[str, Any]:
    failures: list[str] = []
    delivery = result.get("pipeline_delivery", {})
    if not delivery:
        failures.append("result JSON does not include pipeline_delivery")
    if not LATEST_PIPELINE_BUNDLE_PATH.exists():
        failures.append(f"missing gzip pipeline bundle: {LATEST_PIPELINE_BUNDLE_PATH}")
    elif LATEST_PIPELINE_BUNDLE_PATH.stat().st_size <= 0:
        failures.append("gzip pipeline bundle is empty")
    if delivery.get("compression") != "gzip":
        failures.append("pipeline compression is not gzip")

    return {
        "name": "pipeline_artifacts",
        "status": "pass" if not failures else "fail",
        "details": "gzip telemetry bundle is present." if not failures else failures,
    }


def _check_openapi_contract() -> dict[str, Any]:
    failures: list[str] = []
    if not OPENAPI_PATH.exists():
        failures.append(f"missing OpenAPI contract: {OPENAPI_PATH}")
    else:
        text = OPENAPI_PATH.read_text(encoding="utf-8")
        for required in (
            "openapi: 3.",
            "/v1/telemetry/events",
            "/v1/dashboard/latest",
            "/v1/reports/latest",
            "X-Customer-Id",
            "X-Agent-Version",
            "REST",
            "sqlite",
            "local-worker",
        ):
            if required not in text:
                failures.append(f"OpenAPI contract missing: {required}")
        if "future_transport" in text:
            failures.append("OpenAPI contract still includes future transport")
    return {
        "name": "openapi_contract",
        "status": "pass" if not failures else "fail",
        "details": "OpenAPI REST contract is documented." if not failures else failures,
    }


def _read_latest_result() -> dict[str, Any]:
    if not LATEST_RESULT_PATH.exists():
        return {}
    return json.loads(LATEST_RESULT_PATH.read_text(encoding="utf-8"))


def _npm_command() -> str:
    return "npm.cmd" if sys.platform == "win32" else "npm"


def _combined_output(completed: subprocess.CompletedProcess[str]) -> str:
    return ((completed.stdout or "") + (completed.stderr or "")).strip()


def _build_report(checks: list[dict[str, Any]], result: dict[str, Any]) -> dict[str, Any]:
    has_fail = any(check["status"] == "fail" for check in checks)
    return {
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "poc_name": "layertrace_edr_siem_poc",
        "decision": "local_poc_passed_with_advanced_modules" if not has_fail else "local_validation_failed",
        "checks": checks,
        "result_summary": result.get("summary", {}),
        "dashboard": result.get("dashboard", {}),
        "report": result.get("report", {}),
        "implemented_capabilities": [
            "offline event file loader with generated sample flows",
            "schema validation and DLQ result preservation",
            "privacy-sensitive field removal and pattern masking",
            "rule-based detection R001-R008",
            "advanced detection R009-R011 for L7 URL, application action, and malware hash",
            "MITRE ATT&CK attack-chain mapping",
            "PCAP TCP flow analyzer and decrypted L7 proxy-log ingestion",
            "dry-run response plan generation",
            "AI-style host risk prediction",
            "gzip telemetry pipeline bundle",
            "static SIEM dashboard fed by latest CLI result",
            "React/TypeScript dashboard build with Vite runtime assets",
            "SQLite service store for latest runs, incidents, and queued task state",
            "local worker boundary that can later be replaced by a broker-backed worker",
            "REST health, latest dashboard, and incident query endpoints",
            "Markdown and HTML report artifacts generated from latest result",
            "SIEM query findings and Endpoint Egress Topology",
            "dashboard report modal with print-to-PDF flow",
            "REST OpenAPI contract documented in docs/openapi.yaml",
        ],
        "next_user_required": [
            "Run the macOS agent on an actual Mac if packet-capture validation is required.",
            "Use an approved local proxy/CA setup before collecting decrypted HTTPS metadata in a real environment.",
            "Review false-positive tolerance with security scenario owners.",
        ],
    }


def _write_report(report: dict[str, Any]) -> dict[str, str]:
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    run_dir = VERIFICATION_DIR / "runs" / timestamp
    latest_path = VERIFICATION_DIR / "latest_verification.json"
    run_path = run_dir / "verification.json"
    run_dir.mkdir(parents=True, exist_ok=True)
    VERIFICATION_DIR.mkdir(parents=True, exist_ok=True)

    payload = json.dumps(report, ensure_ascii=False, indent=2)
    run_path.write_text(payload + "\n", encoding="utf-8")
    latest_path.write_text(payload + "\n", encoding="utf-8")
    return {"latest": str(latest_path), "run": str(run_path)}


def _print_summary(report: dict[str, Any], paths: dict[str, str]) -> None:
    summary = {
        "decision": report["decision"],
        "checks": {check["name"]: check["status"] for check in report["checks"]},
        "latest": paths["latest"],
        "run": paths["run"],
    }
    print(json.dumps(summary, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    sys.exit(main())
