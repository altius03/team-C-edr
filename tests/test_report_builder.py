import sys
import tempfile
import unittest
from pathlib import Path

PROJECT_DIR = Path(__file__).resolve().parents[1]
if str(PROJECT_DIR) not in sys.path:
    sys.path.insert(0, str(PROJECT_DIR))

from src.report_builder import build_html_report, build_markdown_report, write_report_artifacts


SAMPLE_RESULT = {
    "status": "success",
    "generated_at": "2026-07-06T00:00:00",
    "decision": "needs_security_review",
    "input": {"source": "unit_test"},
    "summary": {
        "valid_event_count": 55,
        "alert_count": 2,
        "incident_count": 1,
        "dlq_event_count": 0,
        "highest_risk_score": 91,
    },
    "endpoint_risk": [
        {
            "host_id": "endpoint-01",
            "host_display_name": "황건하-PC",
            "risk_score": 91,
            "severity": "critical",
            "alert_count": 2,
            "incident_count": 1,
            "top_rules": ["R004", "R005"],
        }
    ],
    "alerts": [
        {
            "rule_id": "R004",
            "host_id": "endpoint-01",
            "host_display_name": "황건하-PC",
            "severity": "suspicious",
            "risk_score": 36,
            "evidence": ["regular interval connection"],
        }
    ],
    "incidents": [
        {
            "incident_id": "incident-001",
            "host_id": "endpoint-01",
            "host_display_name": "황건하-PC",
            "risk_score": 91,
            "severity": "critical",
            "primary_category": "suspicious_download_to_c2_sequence",
            "decision": "needs_security_review",
            "detected_sequence": [{"stage": "periodic_external_connection", "summary": "Periodic outbound connection"}],
            "mitre_mapping": [{"tactic": "Command and Control"}],
        }
    ],
    "mitre_distribution": [{"tactic": "Command and Control", "count": 1}],
    "siem_analysis": {
        "query_findings": [
            {
                "query_id": "SIEM-Q001",
                "title": "Repeated outbound C2 pattern",
                "severity": "suspicious",
                "host_display_name": "황건하-PC",
                "summary": "Regular beaconing and outbound transfer were correlated.",
                "evidence_count": 4,
            }
        ],
        "egress_topology": {
            "layers": ["Endpoint", "Internal Zone", "External Destination"],
            "nodes": [
                {"id": "endpoint-01", "label": "황건하-PC", "layer": "Endpoint", "state": "alert"},
                {"id": "tenant-boundary", "label": "Protected Tenant Boundary", "layer": "Internal Zone", "state": "observed"},
                {"id": "c2.badbeacon.example", "label": "c2.badbeacon.example", "layer": "External Destination", "state": "alert"},
            ],
            "edges": [{"source": "endpoint-01", "target": "c2.badbeacon.example", "protocol": "tcp", "alert_count": 1}],
        },
        "correlation_timeline": [
            {"time": "2026-07-06T00:00:00", "host_display_name": "황건하-PC", "summary": "Outbound C2 pattern"}
        ],
        "collector_explanation": "Win32_Process telemetry is collected separately from DNS cache observations.",
        "telemetry_metadata": {
            "customer_id": "techeer-demo",
            "tenant_id": "techeer-demo-lab",
            "agent_version": "0.3.0",
            "payload_version": "1.1",
        },
        "api_contract": {"current_transport": "REST"},
    },
    "dlq_events": [],
    "limitations": ["unit test limitation"],
}


class ReportBuilderTests(unittest.TestCase):
    def test_markdown_and_html_report_include_core_sections(self) -> None:
        markdown = build_markdown_report(SAMPLE_RESULT)
        html = build_html_report(SAMPLE_RESULT, markdown)

        self.assertIn("# LayerTrace EDR/SIEM 분석 보고서", markdown)
        self.assertNotIn("Agent Parser", markdown)
        self.assertIn("## 4. SIEM Analysis", markdown)
        self.assertIn("Endpoint Egress Topology", markdown)
        self.assertIn("황건하-PC", markdown)
        self.assertIn("Win32_Process", markdown)
        self.assertIn("REST", markdown)
        self.assertNotIn("Future transport", markdown)
        self.assertIn("## 5. Alert Evidence", markdown)
        self.assertIn("<html", html)
        self.assertIn("<td>황건하-PC</td>", html)

    def test_write_report_artifacts_creates_latest_and_run_outputs(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            paths = write_report_artifacts(SAMPLE_RESULT, root / "latest", root / "runs" / "run-001")

            for path in paths.values():
                self.assertTrue(path.exists(), path)


if __name__ == "__main__":
    unittest.main()
