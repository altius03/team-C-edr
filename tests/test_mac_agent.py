from __future__ import annotations

import json
import os
import subprocess
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from unittest.mock import patch

from src import mac_agent
from src.agent_shipper import AgentShipConfig, JsonObject, ShipResult


class FakeTcpdumpProcess:
    def __init__(self, *, returncode: int, stdout_text: str = "", stderr_text: str = "", timeout_once: bool = False) -> None:
        self.returncode = returncode
        self.stdout_text = stdout_text
        self.stderr_text = stderr_text
        self.timeout_once = timeout_once
        self.terminated = False
        self.killed = False
        self.written = False
        self.stdout_file = None
        self.stderr_file = None

    def attach(self, stdout_file, stderr_file) -> None:
        self.stdout_file = stdout_file
        self.stderr_file = stderr_file

    def wait(self, timeout: float | int | None = None) -> int:
        if self.timeout_once and not self.terminated and not self.killed:
            raise subprocess.TimeoutExpired(cmd=["tcpdump"], timeout=timeout)
        self.write_output()
        return self.returncode

    def terminate(self) -> None:
        self.terminated = True
        self.returncode = -15

    def kill(self) -> None:
        self.killed = True
        self.returncode = -9

    def write_output(self) -> None:
        if self.written:
            return
        self.written = True
        if self.stdout_file is not None:
            self.stdout_file.write(self.stdout_text)
            self.stdout_file.flush()
        if self.stderr_file is not None:
            self.stderr_file.write(self.stderr_text)
            self.stderr_file.flush()


def fake_popen_for(process: FakeTcpdumpProcess):
    def fake_popen(command, stdout=None, stderr=None, text=False):
        process.attach(stdout, stderr)
        return process

    return fake_popen


class MacAgentTests(unittest.TestCase):
    def test_simulate_ships_with_required_identity_headers_when_collector_url_is_set(self) -> None:
        captured: list[tuple[list[JsonObject], AgentShipConfig]] = []

        def fake_ship_events(events: list[JsonObject], config: AgentShipConfig) -> ShipResult:
            captured.append((events, config))
            return ShipResult(status="accepted", accepted_count=1, task_id="task-mac", replayed_count=0, queued_count=0)

        with tempfile.TemporaryDirectory() as temp_dir:
            stdout = StringIO()
            with patch("src.mac_agent.ship_events", side_effect=fake_ship_events):
                with redirect_stdout(stdout):
                    exit_code = mac_agent.run_agent(
                        [
                            "--simulate",
                            "--host-id",
                            "mac-unit",
                            "--collector-url",
                            "https://collector.example.test/v1/telemetry/events",
                            "--api-token",
                            "unit-token",
                            "--customer-id",
                            "techeer-demo",
                            "--tenant-id",
                            "techeer-demo-lab",
                            "--agent-version",
                            "0.4.0",
                            "--payload-version",
                            "1.1",
                            "--queue-dir",
                            temp_dir,
                        ]
                    )

        output = json.loads(stdout.getvalue())
        self.assertEqual(exit_code, 0)
        self.assertEqual(output["status"], "accepted")
        self.assertEqual(captured[0][0][0]["host_id"], "mac-unit")
        self.assertEqual(captured[0][1].collector_url, "https://collector.example.test/v1/telemetry/events")
        self.assertEqual(captured[0][1].identity.customer_id, "techeer-demo")
        self.assertEqual(captured[0][1].identity.tenant_id, "techeer-demo-lab")
        self.assertEqual(captured[0][1].identity.agent_version, "0.4.0")
        self.assertEqual(captured[0][1].identity.payload_version, "1.1")
        self.assertEqual(captured[0][1].identity.api_token, "unit-token")

    def test_returns_nonzero_when_shipper_rejects(self) -> None:
        def fake_ship_events(events: list[JsonObject], config: AgentShipConfig) -> ShipResult:
            return ShipResult(status="rejected", accepted_count=0, task_id=None, replayed_count=0, queued_count=1, error="http_403")

        with tempfile.TemporaryDirectory() as temp_dir:
            stdout = StringIO()
            with patch("src.mac_agent.ship_events", side_effect=fake_ship_events):
                with redirect_stdout(stdout):
                    exit_code = mac_agent.run_agent(
                        [
                            "--simulate",
                            "--collector-url",
                            "http://127.0.0.1:8080/v1/telemetry/events",
                            "--api-token",
                            "wrong-token",
                            "--queue-dir",
                            temp_dir,
                        ]
                    )

        output = json.loads(stdout.getvalue())
        self.assertEqual(exit_code, 1)
        self.assertEqual(output["status"], "rejected")
        self.assertEqual(output["error"], "http_403")

    def test_surfaces_tcpdump_nonzero_as_structured_error(self) -> None:
        process = FakeTcpdumpProcess(returncode=1, stderr_text="tcpdump: /dev/bpf0: Operation not permitted\n")

        stderr = StringIO()
        with patch("src.mac_agent.subprocess.Popen", side_effect=fake_popen_for(process)):
            with redirect_stderr(stderr):
                exit_code = mac_agent.run_agent(["--iface", "en0", "--duration", "10", "--host-id", "mac-unit"])

        output = json.loads(stderr.getvalue())
        self.assertEqual(exit_code, 1)
        self.assertEqual(output["status"], "error")
        self.assertEqual(output["error"]["code"], "tcpdump_failed")
        self.assertIn("Operation not permitted", output["error"]["message"])
        self.assertEqual(output["events"], [])

    def test_capture_timeout_without_packets_returns_empty_success(self) -> None:
        process = FakeTcpdumpProcess(returncode=0, timeout_once=True)

        stdout = StringIO()
        with patch("src.mac_agent.subprocess.Popen", side_effect=fake_popen_for(process)):
            with redirect_stdout(stdout):
                exit_code = mac_agent.run_agent(["--iface", "en0", "--duration", "1", "--host-id", "mac-unit"])

        output = json.loads(stdout.getvalue())
        self.assertEqual(exit_code, 0)
        self.assertEqual(output["events"], [])
        self.assertTrue(process.terminated)
        self.assertFalse(process.killed)

    def test_parses_valid_tcpdump_line_and_ignores_malformed_lines(self) -> None:
        process = FakeTcpdumpProcess(
            returncode=0,
            stdout_text=(
                "malformed tcpdump output\n"
                "1719990000.125000 IP 192.168.1.10.54321 > 203.0.113.77.443: tcp 0, length 128\n"
                "also malformed\n"
            ),
        )

        stdout = StringIO()
        with patch("src.mac_agent.subprocess.Popen", side_effect=fake_popen_for(process)):
            with redirect_stdout(stdout):
                exit_code = mac_agent.run_agent(["--iface", "en0", "--duration", "1", "--host-id", "mac-unit"])

        output = json.loads(stdout.getvalue())
        events = output["events"]
        self.assertEqual(exit_code, 0)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["event_id"], "mac-net-0001")
        self.assertEqual(events[0]["src_ip"], "192.168.1.10")
        self.assertEqual(events[0]["src_port"], 54321)
        self.assertEqual(events[0]["dst_ip"], "203.0.113.77")
        self.assertEqual(events[0]["dst_port"], 443)
        self.assertEqual(events[0]["bytes_out"], 128)

    def test_rejects_invalid_duration_and_bpf_option_tokens(self) -> None:
        duration_stderr = StringIO()
        with redirect_stderr(duration_stderr):
            duration_exit = mac_agent.run_agent(["--simulate", "--duration", "0"])

        bpf_stderr = StringIO()
        with redirect_stderr(bpf_stderr):
            bpf_exit = mac_agent.run_agent(["--simulate", "--bpf=-w /tmp/capture.pcap"])

        duration_output = json.loads(duration_stderr.getvalue())
        bpf_output = json.loads(bpf_stderr.getvalue())
        self.assertEqual(duration_exit, 2)
        self.assertEqual(duration_output["error"]["code"], "invalid_duration")
        self.assertEqual(bpf_exit, 2)
        self.assertEqual(bpf_output["error"]["code"], "invalid_bpf")

    def test_requires_explicit_token_for_non_loopback_collector(self) -> None:
        stderr = StringIO()
        with patch.dict(os.environ, {"LAYERTRACE_API_TOKEN": ""}):
            with patch("src.mac_agent.ship_events") as ship_events_mock:
                with redirect_stderr(stderr):
                    exit_code = mac_agent.run_agent(
                        [
                            "--simulate",
                            "--collector-url",
                            "https://collector.example.test/v1/telemetry/events",
                        ]
                    )

        output = json.loads(stderr.getvalue())
        self.assertEqual(exit_code, 2)
        self.assertEqual(output["error"]["code"], "missing_api_token")
        ship_events_mock.assert_not_called()

    def test_rejects_non_loopback_http_collector_even_with_token(self) -> None:
        stderr = StringIO()
        with patch("src.mac_agent.ship_events") as ship_events_mock:
            with redirect_stderr(stderr):
                exit_code = mac_agent.run_agent(
                    [
                        "--simulate",
                        "--collector-url",
                        "http://collector.example.test/v1/telemetry/events",
                        "--api-token",
                        "unit-token",
                    ]
                )

        output = json.loads(stderr.getvalue())
        self.assertEqual(exit_code, 2)
        self.assertEqual(output["error"]["code"], "insecure_collector_url")
        ship_events_mock.assert_not_called()

    def test_allows_localhost_collector_default_token(self) -> None:
        captured: list[AgentShipConfig] = []

        def fake_ship_events(events: list[JsonObject], config: AgentShipConfig) -> ShipResult:
            captured.append(config)
            return ShipResult(status="accepted", accepted_count=1, task_id="task-local", replayed_count=0, queued_count=0)

        stdout = StringIO()
        with tempfile.TemporaryDirectory() as temp_dir:
            with patch.dict(os.environ, {"LAYERTRACE_API_TOKEN": ""}):
                with patch("src.mac_agent.ship_events", side_effect=fake_ship_events):
                    with redirect_stdout(stdout):
                        exit_code = mac_agent.run_agent(
                            [
                                "--simulate",
                                "--collector-url",
                                "http://localhost:8080/v1/telemetry/events",
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
