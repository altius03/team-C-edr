from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any

from .config import (
    BASE_DIR,
    DASHBOARD_DATA_PATH,
    DASHBOARD_DIR,
    LATEST_OUTPUT_DIR,
    LATEST_REPORT_DIR,
    REPORT_RUNS_DIR,
    RUNS_OUTPUT_DIR,
)
from .report_builder import write_report_artifacts


def write_result(payload: dict[str, Any]) -> dict[str, Path]:
    run_dir = _new_run_dir()
    latest_path = LATEST_OUTPUT_DIR / "result.json"
    run_path = run_dir / "result.json"
    report_run_dir = REPORT_RUNS_DIR / run_dir.name

    payload = dict(payload)
    dashboard_paths = {
        "index_path": DASHBOARD_DIR / "index.html",
        "data_script_path": DASHBOARD_DATA_PATH,
    }
    report_paths = {
        "latest_markdown_path": LATEST_REPORT_DIR / "security_report.md",
        "latest_html_path": LATEST_REPORT_DIR / "security_report.html",
        "run_markdown_path": report_run_dir / "security_report.md",
        "run_html_path": report_run_dir / "security_report.html",
    }
    payload["dashboard"] = {
        "index_path": str(dashboard_paths["index_path"]),
        "data_script_path": str(dashboard_paths["data_script_path"]),
        "open_note": "브라우저에서 dashboard/index.html을 열면 최신 CLI 결과를 볼 수 있습니다.",
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


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


def _write_dashboard_data(payload: dict[str, Any]) -> dict[str, Path]:
    DASHBOARD_DATA_PATH.parent.mkdir(parents=True, exist_ok=True)
    # The dashboard is static HTML, so the CLI publishes its latest result as a
    # JavaScript assignment instead of requiring a local API server.
    script = "window.SIEM_RESULT = "
    script += json.dumps(_repo_safe_payload(payload), ensure_ascii=False, indent=2)
    script += ";\n"
    DASHBOARD_DATA_PATH.write_text(script, encoding="utf-8")
    return {
        "index_path": DASHBOARD_DIR / "index.html",
        "data_script_path": DASHBOARD_DATA_PATH,
    }


def _repo_safe_payload(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: _repo_safe_payload(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_repo_safe_payload(item) for item in value]
    if isinstance(value, str):
        return _repo_safe_path(value)
    return value


def _repo_safe_path(value: str) -> str:
    path = Path(value)
    if not path.is_absolute():
        return value
    try:
        # Dashboard/report metadata should stay portable after the repo is cloned.
        return path.relative_to(BASE_DIR).as_posix()
    except ValueError:
        return value


def _new_run_dir() -> Path:
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    run_dir = RUNS_OUTPUT_DIR / stamp
    suffix = 1
    while run_dir.exists():
        run_dir = RUNS_OUTPUT_DIR / f"{stamp}_{suffix:02d}"
        suffix += 1
    return run_dir
