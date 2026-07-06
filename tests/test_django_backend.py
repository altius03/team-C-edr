import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

PROJECT_DIR = Path(__file__).resolve().parents[1]
if str(PROJECT_DIR) not in sys.path:
    sys.path.insert(0, str(PROJECT_DIR))

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "src.django_backend.settings")

import django
from django.test import Client

from src.django_backend.state import set_store
from src.sample_loader import load_events
from src.service_store import ServiceStore
from src.service_worker import run_default_analysis_job


class DjangoBackendTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        django.setup()

    def test_django_views_expose_service_contract(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            store = ServiceStore(Path(temp_dir) / "layertrace.sqlite3")
            store.initialize()
            events, meta = load_events(PROJECT_DIR / "samples" / "default_events.json")
            run_default_analysis_job(store, events=events, input_meta=meta)
            set_store(store)

            client = Client()
            health = client.get("/v1/health")
            dashboard = client.get("/v1/dashboard/latest")
            incidents = client.get("/v1/incidents", {"severity": "critical"})
            report = client.get("/v1/reports/latest")
            accepted = client.post(
                "/v1/telemetry/events",
                data=json.dumps({"events": events}),
                content_type="application/json",
                headers={
                    "X-Customer-Id": "techeer-demo",
                    "X-Tenant-Id": "techeer-demo-lab",
                    "X-Agent-Version": "0.4.0",
                    "X-Payload-Version": "1.1",
                },
            )

            self.assertEqual(health.status_code, 200)
            self.assertEqual(health.json()["framework"], "django")
            self.assertEqual(dashboard.json()["status"], "success")
            self.assertGreaterEqual(len(incidents.json()["incidents"]), 1)
            self.assertEqual(report.json()["pdf_export"], "browser_print_to_pdf")
            self.assertEqual(accepted.status_code, 202)
            self.assertEqual(accepted.json()["accepted_count"], len(events))


if __name__ == "__main__":
    unittest.main()
