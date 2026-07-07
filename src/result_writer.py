"""Persist analysis results to JSON, dashboard data, and report artifacts."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import TypeAlias

from .config import (
    BASE_DIR,
    LATEST_OUTPUT_DIR,
    LATEST_REPORT_DIR,
    REPORT_RUNS_DIR,
    RUNS_OUTPUT_DIR,
    WEB_DASHBOARD_JSON_PATH,
)
from .report_builder import write_report_artifacts

JsonPrimitive: TypeAlias = str | int | float | bool | None
JsonValue: TypeAlias = JsonPrimitive | list["JsonValue"] | dict[str, "JsonValue"]
JsonObject: TypeAlias = dict[str, JsonValue]


def write_result(payload: JsonObject) -> dict[str, Path]:
    """Write the result payload fan-out and return every generated path."""
    run_dir = _new_run_dir()
    latest_path = LATEST_OUTPUT_DIR / "result.json"
    run_path = run_dir / "result.json"
    report_run_dir = REPORT_RUNS_DIR / run_dir.name

    payload = dict(payload)
    # JSON, 대시보드 데이터, 보고서가 모두 같은 생성 경로를 가리키도록
    # 어떤 산출물이든 쓰기 전에 결과 메타데이터를 주입합니다.
    dashboard_paths = {
        "react_data_path": WEB_DASHBOARD_JSON_PATH,
    }
    report_paths = {
        "latest_markdown_path": LATEST_REPORT_DIR / "security_report.md",
        "latest_html_path": LATEST_REPORT_DIR / "security_report.html",
        "run_markdown_path": report_run_dir / "security_report.md",
        "run_html_path": report_run_dir / "security_report.html",
    }
    payload["dashboard"] = {
        "react_data_path": str(dashboard_paths["react_data_path"]),
        "api_path": "/v1/dashboard/latest",
        "open_note": "React 대시보드는 FastAPI API를 우선 읽고, demo/local fallback flag가 있을 때만 web/public/latest-result.json을 사용합니다.",
    }
    payload["report"] = {
        "latest_markdown_path": str(report_paths["latest_markdown_path"]),
        "latest_html_path": str(report_paths["latest_html_path"]),
        "run_markdown_path": str(report_paths["run_markdown_path"]),
        "run_html_path": str(report_paths["run_html_path"]),
        "open_note": "HTML 보고서는 outputs/reports/latest/security_report.html에서 볼 수 있습니다.",
    }

    _write_dashboard_data(payload)
    written_report_paths = write_report_artifacts(payload, LATEST_REPORT_DIR, report_run_dir)
    _write_json(latest_path, payload)
    _write_json(run_path, payload)

    return {
        "latest_path": latest_path,
        "run_path": run_path,
        **dashboard_paths,
        **written_report_paths,
    }


def _write_json(path: Path, payload: JsonObject) -> None:
    """Write one UTF-8 JSON file with a trailing newline."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


def _write_dashboard_data(payload: JsonObject) -> dict[str, Path]:
    safe_payload = _repo_safe_payload(payload)
    WEB_DASHBOARD_JSON_PATH.parent.mkdir(parents=True, exist_ok=True)
    WEB_DASHBOARD_JSON_PATH.write_text(
        json.dumps(safe_payload, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    return {
        "react_data_path": WEB_DASHBOARD_JSON_PATH,
    }


def _repo_safe_payload(value: JsonValue) -> JsonValue:
    """Recursively convert absolute repo paths inside payload strings."""
    if isinstance(value, dict):
        return {key: _repo_safe_payload(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_repo_safe_payload(item) for item in value]
    if isinstance(value, str):
        return _repo_safe_path(value)
    return value


def _repo_safe_path(value: str) -> str:
    """Return a repo-relative path string when an absolute path is under BASE_DIR."""
    path = Path(value)
    if not path.is_absolute():
        return value
    try:
        # 대시보드/보고서 메타데이터는 저장소를 복제한 뒤에도 이식 가능해야 합니다.
        return path.relative_to(BASE_DIR).as_posix()
    except ValueError:
        return value


def _new_run_dir() -> Path:
    """Create a unique timestamped output directory path for this run."""
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    run_dir = RUNS_OUTPUT_DIR / stamp
    suffix = 1
    while run_dir.exists():
        run_dir = RUNS_OUTPUT_DIR / f"{stamp}_{suffix:02d}"
        suffix += 1
    return run_dir
