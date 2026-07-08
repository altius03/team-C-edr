from __future__ import annotations

from typing import Any

from scripts.validate_poc_core_checks import (
    _check_cli_default_run,
    _check_compile,
    _check_dashboard_artifacts,
    _check_react_build,
    _check_react_project_contract,
    _check_result_contract,
    _check_unit_tests,
)
from scripts.validate_poc_report_checks import (
    _build_report,
    _check_pipeline_artifacts,
    _check_report_artifacts,
    _print_summary,
    _read_latest_result,
    _write_report,
)
from scripts.validate_poc_service_checks import _check_openapi_contract, _check_service_architecture


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
