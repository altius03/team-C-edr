import sys
import tempfile
import unittest
from pathlib import Path

PROJECT_DIR = Path(__file__).resolve().parents[1]
if str(PROJECT_DIR) not in sys.path:
    sys.path.insert(0, str(PROJECT_DIR))

from src.api_app import create_app
from src.service_store import ServiceStore


class DashboardContractTests(unittest.TestCase):
    """Check analyst-facing dashboard surfaces and REST schema visibility."""

    def test_react_dashboard_exposes_required_user_surface(self) -> None:
        index = (PROJECT_DIR / "web" / "index.html").read_text(encoding="utf-8")
        app = (PROJECT_DIR / "web" / "src" / "App.tsx").read_text(encoding="utf-8")
        adapter = (PROJECT_DIR / "web" / "src" / "resultAdapter.ts").read_text(encoding="utf-8")

        self.assertIn('id="root"', index)
        self.assertNotIn("result JSON", index)

        for required in (
            "Endpoint fleet",
            "Protected tenant boundary",
            "External destinations",
            "last10m",
            "last1h",
            "last24h",
            "ReportModal",
            "Report Center",
            "DLQ Monitor",
            "Process Tree",
            "severityFilter",
        ):
            self.assertIn(required, app)
        self.assertIn("/v1/dashboard/latest", adapter)
        self.assertIn("latest-result.json", adapter)
        self.assertIn("VITE_LAYERTRACE_API_BASE_URL", adapter)
        self.assertIn("VITE_LAYERTRACE_ALLOW_DEMO_FALLBACK", adapter)
        self.assertIn("demo-fallback", adapter)
        self.assertIn("api_error", adapter)
        self.assertNotIn("window.SIEM_RESULT", adapter)
        self.assertFalse((PROJECT_DIR / "dashboard" / "index.html").exists())

    def test_openapi_contract_is_generated_by_fastapi(self) -> None:
        """Ensure FastAPI produces the documented REST paths and deployment terms."""
        with tempfile.TemporaryDirectory() as temp_dir:
            store = ServiceStore(Path(temp_dir) / "layertrace.sqlite3")
            openapi = create_app(store).openapi()

        text = str(openapi)
        self.assertEqual(openapi["openapi"].split(".")[0], "3")
        self.assertIn("/v1/telemetry/events", openapi["paths"])
        self.assertIn("/v1/tasks/{task_id}", openapi["paths"])
        self.assertIn("X-Customer-Id", text)
        self.assertIn("X-Agent-Version", text)
        self.assertIn("REST", text)
        self.assertIn("postgresql", text)
        self.assertNotIn("future_transport", text)


if __name__ == "__main__":
    unittest.main()
