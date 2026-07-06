import sys
import unittest
from pathlib import Path

PROJECT_DIR = Path(__file__).resolve().parents[1]
if str(PROJECT_DIR) not in sys.path:
    sys.path.insert(0, str(PROJECT_DIR))


class DashboardContractTests(unittest.TestCase):
    def test_dashboard_exposes_required_user_surface(self) -> None:
        index = (PROJECT_DIR / "dashboard" / "index.html").read_text(encoding="utf-8")
        app = (PROJECT_DIR / "dashboard" / "app.js").read_text(encoding="utf-8")

        self.assertIn("Endpoint Egress Topology", index)
        self.assertIn('class="visual-stage', index)
        self.assertIn('id="egress-topology"', index)
        self.assertIn('id="detection-charts"', index)
        self.assertIn('id="detection-chart-panel"', index)
        self.assertIn('id="alert-inspector"', index)
        self.assertIn('id="data-source-current"', index)
        self.assertIn('id="data-source-switch"', index)
        self.assertIn('id="report-modal"', index)
        self.assertIn('id="open-report-button"', index)
        self.assertIn('id="print-report-button"', index)
        self.assertIn('value="last10m"', index)
        self.assertIn('value="last1h"', index)
        self.assertIn('value="last24h"', index)
        self.assertNotIn("result JSON", index)
        self.assertNotIn("../outputs/latest/result.json", index)

        self.assertIn("renderEgressTopology", app)
        self.assertIn("renderTopologySvg", app)
        self.assertIn("renderDetectionCharts", app)
        self.assertIn("renderAlertInspector", app)
        self.assertIn("Endpoint fleet", app)
        self.assertIn("Protected tenant boundary", app)
        self.assertIn("External destinations", app)
        self.assertIn("python -m src.run --collect-local", app)
        self.assertIn("openReportModal", app)
        self.assertIn("EDR 상태", app)

    def test_openapi_contract_is_documented_for_swagger(self) -> None:
        openapi = PROJECT_DIR / "docs" / "openapi.yaml"
        self.assertTrue(openapi.exists(), openapi)
        text = openapi.read_text(encoding="utf-8")

        self.assertIn("openapi: 3.", text)
        self.assertIn("/v1/telemetry/events", text)
        self.assertIn("/v1/tasks/{task_id}", text)
        self.assertIn("X-Customer-Id", text)
        self.assertIn("X-Agent-Version", text)
        self.assertIn("X-Api-Token", text)
        self.assertIn("REST", text)
        self.assertNotIn("future_transport", text)


if __name__ == "__main__":
    unittest.main()
