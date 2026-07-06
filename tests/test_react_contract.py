import json
import unittest
from pathlib import Path

PROJECT_DIR = Path(__file__).resolve().parents[1]


class ReactDashboardContractTests(unittest.TestCase):
    def test_react_vite_project_contract_exists(self) -> None:
        package_json = PROJECT_DIR / "package.json"
        self.assertTrue(package_json.exists(), package_json)

        package = json.loads(package_json.read_text(encoding="utf-8"))
        self.assertIn("dev", package["scripts"])
        self.assertIn("build", package["scripts"])
        self.assertIn("preview", package["scripts"])
        self.assertIn("react", package["dependencies"])
        self.assertIn("vite", package["devDependencies"])
        self.assertIn("scripts/build_react.mjs", package["scripts"]["build"])

        for relative_path in (
            "tsconfig.json",
            "scripts/build_react.mjs",
            "web/index.html",
            "web/src/main.tsx",
            "web/src/App.tsx",
            "web/src/resultAdapter.ts",
            "web/src/styles.css",
        ):
            self.assertTrue((PROJECT_DIR / relative_path).exists(), relative_path)

    def test_react_dashboard_preserves_required_edr_surface(self) -> None:
        app = (PROJECT_DIR / "web" / "src" / "App.tsx").read_text(encoding="utf-8")
        adapter = (PROJECT_DIR / "web" / "src" / "resultAdapter.ts").read_text(encoding="utf-8")

        for required in (
            "Endpoint fleet",
            "Protected tenant boundary",
            "External destinations",
            "last10m",
            "last1h",
            "last24h",
            "all",
            "ReportModal",
            "Report Center",
            "Endpoint Risk",
            "DLQ Monitor",
            "Process Tree",
            "SignalStrip",
            "severityFilter",
        ):
            self.assertIn(required, app)
        self.assertIn("window.SIEM_RESULT", adapter)
        self.assertIn("/v1/dashboard/latest", adapter)
        self.assertIn("VITE_LAYERTRACE_API_BASE_URL", adapter)
        self.assertIn("process_trees", adapter)
        self.assertIn("dlq_events", adapter)
        self.assertIn("value.toLowerCase()", adapter)
        self.assertNotIn("result JSON", app)


if __name__ == "__main__":
    unittest.main()
