from __future__ import annotations

import json
from datetime import datetime
from typing import Any

from scripts.validate_poc_paths import (
    LATEST_PIPELINE_BUNDLE_PATH,
    LATEST_REPORT_HTML_PATH,
    LATEST_REPORT_MD_PATH,
    LATEST_RESULT_PATH,
    VERIFICATION_DIR,
)


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


def _read_latest_result() -> dict[str, Any]:
    if not LATEST_RESULT_PATH.exists():
        return {}
    return json.loads(LATEST_RESULT_PATH.read_text(encoding="utf-8"))


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
            "React/TypeScript dashboard fed by REST API and latest JSON fallback",
            "SQLAlchemy PostgreSQL service store for runs, events, alerts, incidents, DLQ events, tasks, and outbox events",
            "TaskQueue interface with Celery runner plus legacy local/external worker fallback",
            "REST health, latest dashboard, and incident query endpoints",
            "Markdown and HTML report artifacts generated from latest result",
            "SIEM query findings and Endpoint Egress Topology",
            "dashboard report modal with print-to-PDF flow",
            "FastAPI generated OpenAPI contract exposed through /docs and /openapi.json",
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
