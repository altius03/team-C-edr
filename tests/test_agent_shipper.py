from __future__ import annotations

import json
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from src import mac_agent
from src.agent_shipper import AgentHttpRequest, AgentIdentity, AgentShipConfig, HttpSendResult, JsonObject, ShipResult, ship_events


def sample_events(event_id: str = "unit-event-001") -> list[JsonObject]:
    return [
        {
            "event_id": event_id,
            "event_time": "2026-07-07T00:00:00+09:00",
            "received_time": "2026-07-07T00:00:01+09:00",
            "host_id": "unit-host",
            "event_type": "network_connection",
            "source": "unit-test",
            "payload_version": "1.1",
            "process_name": "powershell.exe",
            "dst_domain": "c2.badbeacon.example",
            "dst_port": 443,
        }
    ]


class RecordingSender:
    def __init__(self, results: list[HttpSendResult]) -> None:
        self._results = list(results)
        self.calls: list[AgentHttpRequest] = []

    def send(self, request: AgentHttpRequest) -> HttpSendResult:
        self.calls.append(request)
        if self._results:
            return self._results.pop(0)
        return HttpSendResult(status_code=202, body={"status": "accepted", "accepted_count": 1, "task_id": "task-fallback"}, error=None)


class RaisingSender:
    def send(self, request: AgentHttpRequest) -> HttpSendResult:
        raise ValueError("unknown url type")


class AgentShipperTests(unittest.TestCase):
    def test_ship_events_posts_events_with_required_headers_when_collector_accepts(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            sender = RecordingSender(
                [
                    HttpSendResult(
                        status_code=202,
                        body={"status": "accepted", "accepted_count": 1, "task_id": "task-123", "queued": True},
                        error=None,
                    )
                ]
            )

            result = ship_events(
                sample_events(),
                AgentShipConfig(
                    collector_url="http://127.0.0.1:8080/v1/telemetry/events",
                    identity=AgentIdentity(
                        customer_id="techeer-demo",
                        tenant_id="techeer-demo-lab",
                        agent_version="0.4.0",
                        payload_version="1.1",
                        api_token="local-dev-token",
                    ),
                    queue_dir=Path(temp_dir),
                ),
                sender=sender.send,
            )

        self.assertEqual(result, ShipResult(status="accepted", accepted_count=1, task_id="task-123", replayed_count=0, queued_count=0))
        request = sender.calls[0]
        self.assertEqual(request.url, "http://127.0.0.1:8080/v1/telemetry/events")
        self.assertEqual(request.payload["events"], sample_events())
        self.assertEqual(request.headers["X-Customer-Id"], "techeer-demo")
        self.assertEqual(request.headers["X-Tenant-Id"], "techeer-demo-lab")
        self.assertEqual(request.headers["X-Agent-Version"], "0.4.0")
        self.assertEqual(request.headers["X-Payload-Version"], "1.1")
        self.assertEqual(request.headers["X-Api-Token"], "local-dev-token")

    def test_ship_events_spools_unreachable_batch_and_replays_before_new_events(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            queue_dir = Path(temp_dir)
            config = AgentShipConfig(
                collector_url="http://127.0.0.1:8080/v1/telemetry/events",
                identity=AgentIdentity(
                    customer_id="techeer-demo",
                    tenant_id="techeer-demo-lab",
                    agent_version="0.4.0",
                    payload_version="1.1",
                    api_token="local-dev-token",
                ),
                queue_dir=queue_dir,
            )
            failing_sender = RecordingSender([HttpSendResult(status_code=0, body={}, error="connection refused")])

            pending_events = sample_events("pending-event-001")
            new_events = sample_events("new-event-001")

            first = ship_events(pending_events, config, sender=failing_sender.send)

            self.assertEqual(first.status, "queued")
            self.assertEqual(first.queued_count, 1)
            self.assertEqual(len(list(queue_dir.glob("*.json"))), 1)

            succeeding_sender = RecordingSender(
                [
                    HttpSendResult(status_code=202, body={"status": "accepted", "accepted_count": 1, "task_id": "task-replay"}, error=None),
                    HttpSendResult(status_code=202, body={"status": "accepted", "accepted_count": 1, "task_id": "task-new"}, error=None),
                ]
            )

            second = ship_events(new_events, config, sender=succeeding_sender.send)
            self.assertEqual(len(list(queue_dir.glob("*.json"))), 0)

        self.assertEqual(second.status, "accepted")
        self.assertEqual(second.replayed_count, 1)
        self.assertEqual(second.queued_count, 0)
        self.assertEqual(len(succeeding_sender.calls), 2)
        self.assertEqual(succeeding_sender.calls[0].payload["events"], pending_events)
        self.assertEqual(succeeding_sender.calls[1].payload["events"], new_events)

    def test_ship_events_keeps_malformed_spool_and_queues_new_batch(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            queue_dir = Path(temp_dir)
            bad_spool = queue_dir / "bad.json"
            bad_spool.write_text("{bad", encoding="utf-8")
            sender = RecordingSender([])

            result = ship_events(sample_events("new-after-bad-spool"), self.config(queue_dir), sender=sender.send)

            self.assertEqual(result.status, "queued")
            self.assertEqual(result.replayed_count, 0)
            self.assertEqual(result.queued_count, 1)
            self.assertEqual(len(sender.calls), 0)
            self.assertTrue(bad_spool.exists())
            self.assertEqual(len(list(queue_dir.glob("*.json"))), 2)

    def test_ship_events_spools_current_batch_when_sender_raises(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            queue_dir = Path(temp_dir)

            result = ship_events(sample_events("invalid-url-event"), self.config(queue_dir), sender=RaisingSender().send)

            self.assertEqual(result.status, "queued")
            self.assertEqual(result.queued_count, 1)
            self.assertEqual(len(list(queue_dir.glob("*.json"))), 1)

    def test_ship_events_surfaces_auth_rejection_and_queues_batch(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            queue_dir = Path(temp_dir)
            sender = RecordingSender([HttpSendResult(status_code=401, body={"error": "unauthorized"}, error="unauthorized")])

            result = ship_events(sample_events("bad-token-event"), self.config(queue_dir), sender=sender.send)

            self.assertEqual(result.status, "rejected")
            self.assertEqual(result.accepted_count, 0)
            self.assertEqual(result.queued_count, 1)
            self.assertEqual(result.error, "unauthorized")
            self.assertEqual(len(list(queue_dir.glob("*.json"))), 1)

    def test_ship_events_replays_spool_only_after_http_202(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            queue_dir = Path(temp_dir)
            config = self.config(queue_dir)
            failing_sender = RecordingSender([HttpSendResult(status_code=0, body={}, error="connection refused")])
            pending_events = sample_events("pending-needs-202")
            new_events = sample_events("new-waits-for-202")

            first = ship_events(pending_events, config, sender=failing_sender.send)
            self.assertEqual(first.status, "queued")
            self.assertEqual(len(list(queue_dir.glob("*.json"))), 1)

            non_accepted_sender = RecordingSender([HttpSendResult(status_code=200, body={"status": "accepted"}, error=None)])
            second = ship_events(new_events, config, sender=non_accepted_sender.send)

            self.assertEqual(second.status, "queued")
            self.assertEqual(second.replayed_count, 0)
            self.assertEqual(second.queued_count, 1)
            self.assertEqual(non_accepted_sender.calls[0].payload["events"], pending_events)
            self.assertEqual(len(list(queue_dir.glob("*.json"))), 2)

    def test_mac_agent_simulate_ships_with_required_identity_headers_when_collector_url_is_set(self) -> None:
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
                            "http://127.0.0.1:8080/v1/telemetry/events",
                            "--api-token",
                            "local-dev-token",
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
        self.assertEqual(captured[0][1].collector_url, "http://127.0.0.1:8080/v1/telemetry/events")
        self.assertEqual(captured[0][1].identity.customer_id, "techeer-demo")
        self.assertEqual(captured[0][1].identity.tenant_id, "techeer-demo-lab")
        self.assertEqual(captured[0][1].identity.agent_version, "0.4.0")
        self.assertEqual(captured[0][1].identity.payload_version, "1.1")
        self.assertEqual(captured[0][1].identity.api_token, "local-dev-token")

    def test_mac_agent_returns_nonzero_when_shipper_rejects(self) -> None:
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

    def config(self, queue_dir: Path) -> AgentShipConfig:
        return AgentShipConfig(
            collector_url="http://127.0.0.1:8080/v1/telemetry/events",
            identity=AgentIdentity(
                customer_id="techeer-demo",
                tenant_id="techeer-demo-lab",
                agent_version="0.4.0",
                payload_version="1.1",
                api_token="local-dev-token",
            ),
            queue_dir=queue_dir,
        )


if __name__ == "__main__":
    unittest.main()
