from __future__ import annotations

import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parents[1]
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

LATEST_RESULT_PATH = BASE_DIR / "outputs" / "latest" / "result.json"
VERIFICATION_DIR = BASE_DIR / "outputs" / "verification"
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


def npm_command() -> str:
    return "npm.cmd" if sys.platform == "win32" else "npm"
