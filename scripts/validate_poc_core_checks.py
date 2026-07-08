from __future__ import annotations

import compileall
import json
import subprocess
import sys
from typing import Any

from scripts.validate_poc_paths import (
    BASE_DIR,
    PACKAGE_JSON_PATH,
    PACKAGE_LOCK_PATH,
    REACT_ADAPTER_PATH,
    REACT_APP_PATH,
    REACT_BUILD_SCRIPT_PATH,
    REACT_INDEX_PATH,
    REACT_STYLES_PATH,
    WEB_DASHBOARD_JSON_PATH,
    npm_command,
)


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
    if not WEB_DASHBOARD_JSON_PATH.exists():
        failures.append(f"missing React dashboard JSON: {WEB_DASHBOARD_JSON_PATH}")
    else:
        payload = json.loads(WEB_DASHBOARD_JSON_PATH.read_text(encoding="utf-8"))
        dashboard = payload.get("dashboard", {})
        if dashboard.get("react_data_path") != "web/public/latest-result.json":
            failures.append("React dashboard JSON metadata does not point to web/public/latest-result.json")
        if "dashboard/index.html" in json.dumps(dashboard, ensure_ascii=False):
            failures.append("React dashboard metadata still points to deleted static dashboard")

    return {
        "name": "react_dashboard_artifacts",
        "status": "pass" if not failures else "fail",
        "details": "React dashboard JSON fallback is present." if not failures else failures,
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
        if "latest-result.json" not in adapter or "/v1/dashboard/latest" not in adapter:
            failures.append("React adapter must support API-first loading and static JSON fallback")
        if "window.SIEM_RESULT" in adapter:
            failures.append("React adapter still depends on legacy SIEM_RESULT fallback")

    return {
        "name": "react_project_contract",
        "status": "pass" if not failures else "fail",
        "details": "React/Vite project contract is present." if not failures else failures,
    }


def _check_react_build() -> dict[str, Any]:
    completed = subprocess.run(
        [npm_command(), "run", "build"],
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


def _combined_output(completed: subprocess.CompletedProcess[str]) -> str:
    return ((completed.stdout or "") + (completed.stderr or "")).strip()
