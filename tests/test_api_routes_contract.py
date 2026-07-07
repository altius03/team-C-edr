from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path
from typing import Final

PROJECT_DIR = Path(__file__).resolve().parents[1]
if str(PROJECT_DIR) not in sys.path:
    sys.path.insert(0, str(PROJECT_DIR))

from src.api_app import create_app
from src.api_models import ApiSettings
from src.service_store import ServiceStore

CANONICAL_PUBLIC_PATHS: Final[frozenset[str]] = frozenset(
    {
        "/v1/health",
        "/v1/telemetry/events",
        "/v1/tasks/{task_id}",
        "/v1/dashboard/latest",
        "/v1/incidents",
        "/v1/reports/latest",
    }
)


class ApiRouteContractTests(unittest.TestCase):
    def test_openapi_paths_are_exact_public_v1_contract(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            store = ServiceStore(Path(temp_dir) / "layertrace.sqlite3")
            openapi = create_app(store, settings=ApiSettings(allow_public_reads=True)).openapi()

        self.assertEqual(set(openapi["paths"]), CANONICAL_PUBLIC_PATHS)


if __name__ == "__main__":
    unittest.main()
