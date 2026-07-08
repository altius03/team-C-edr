from __future__ import annotations

import json
import os
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from unittest.mock import patch

from scripts import run_agent_once
from src.agent_shipper import AgentShipConfig, JsonObject, ShipResult


class WindowsAgentCollectorPolicyTests(unittest.TestCase):
    def test_rejects_non_loopback_http_collector_before_collecting(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            stderr = StringIO()
            with patch("src.local_collector.collect_local_events") as collect_mock:
                collect_mock.return_value = ([], {"source": "local_windows_collector"})
                with patch("src.agent_shipper.ship_events") as ship_mock:
                    ship_mock.return_value = ShipResult(status="accepted", accepted_count=0, task_id="task-win", replayed_count=0, queued_count=0)
                    with redirect_stderr(stderr):
                        exit_code = run_agent_once.main(
                            [
                                "--collector-url",
                                "http://collector.example.test/v1/telemetry/events",
                                "--api-token",
                                "unit-token",
                                "--queue-dir",
                                temp_dir,
                            ]
                        )

        self.assertTrue(stderr.getvalue())
        output = json.loads(stderr.getvalue())
        self.assertEqual(exit_code, 2)
        self.assertEqual(output["status"], "error")
        self.assertEqual(output["error"]["code"], "insecure_collector_url")
        collect_mock.assert_not_called()
        ship_mock.assert_not_called()

    def test_requires_explicit_token_for_non_loopback_https_collector(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            stderr = StringIO()
            with patch.dict(os.environ, {"LAYERTRACE_API_TOKEN": ""}):
                with patch("src.local_collector.collect_local_events") as collect_mock:
                    collect_mock.return_value = ([], {"source": "local_windows_collector"})
                    with patch("src.agent_shipper.ship_events") as ship_mock:
                        ship_mock.return_value = ShipResult(status="accepted", accepted_count=0, task_id="task-win", replayed_count=0, queued_count=0)
                        with redirect_stderr(stderr):
                            exit_code = run_agent_once.main(
                                [
                                    "--collector-url",
                                    "https://collector.example.test/v1/telemetry/events",
                                    "--queue-dir",
                                    temp_dir,
                                ]
                            )

        self.assertTrue(stderr.getvalue())
        output = json.loads(stderr.getvalue())
        self.assertEqual(exit_code, 2)
        self.assertEqual(output["status"], "error")
        self.assertEqual(output["error"]["code"], "missing_api_token")
        collect_mock.assert_not_called()
        ship_mock.assert_not_called()

    def test_allows_loopback_http_collector_default_token(self) -> None:
        captured: list[AgentShipConfig] = []

        def fake_collect_local_events(**_kwargs) -> tuple[list[JsonObject], dict[str, str]]:
            return [
                {
                    "event_id": "win-unit-001",
                    "event_time": "2026-07-08T00:00:00+09:00",
                    "received_time": "2026-07-08T00:00:01+09:00",
                    "host_id": "win-unit",
                    "event_type": "network_connection",
                    "source": "local_windows_collector",
                    "payload_version": "v1",
                }
            ], {"source": "local_windows_collector"}

        def fake_ship_events(_events: list[JsonObject], config: AgentShipConfig) -> ShipResult:
            captured.append(config)
            return ShipResult(status="accepted", accepted_count=1, task_id="task-win", replayed_count=0, queued_count=0)

        with tempfile.TemporaryDirectory() as temp_dir:
            stdout = StringIO()
            with patch.dict(os.environ, {"LAYERTRACE_API_TOKEN": ""}):
                with patch("src.local_collector.collect_local_events", side_effect=fake_collect_local_events):
                    with patch("src.agent_shipper.ship_events", side_effect=fake_ship_events):
                        with redirect_stdout(stdout):
                            exit_code = run_agent_once.main(
                                [
                                    "--collector-url",
                                    "http://127.0.0.1:8080/v1/telemetry/events",
                                    "--queue-dir",
                                    temp_dir,
                                ]
                            )

        output = json.loads(stdout.getvalue())
        self.assertEqual(exit_code, 0)
        self.assertEqual(output["status"], "accepted")
        self.assertEqual(captured[0].identity.api_token, "local-dev-token")


if __name__ == "__main__":
    unittest.main()
