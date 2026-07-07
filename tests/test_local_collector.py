"""Protect local Windows collector mapping without invoking real PowerShell."""

import json
import sys
import tempfile
import unittest
from datetime import datetime
from pathlib import Path

PROJECT_DIR = Path(__file__).resolve().parents[1]
if str(PROJECT_DIR) not in sys.path:
    sys.path.insert(0, str(PROJECT_DIR))

from src.detection_engine import analyze_events
from src.local_collector import collect_local_events


def fake_runner(command: str) -> tuple[int, str, str]:
    """Return deterministic command output for collector unit tests."""
    if "Win32_Process" in command:
        return (
            0,
            json.dumps(
                [
                    {
                        "ProcessId": 100,
                        "ParentProcessId": 1,
                        "Name": "explorer.exe",
                        "ExecutablePath": "C:\\Windows\\explorer.exe",
                    },
                    {
                        "ProcessId": 200,
                        "ParentProcessId": 100,
                        "Name": "powershell.exe",
                        "ExecutablePath": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                    },
                ]
            ),
            "",
        )
    if "Get-NetTCPConnection" in command:
        return (
            0,
            json.dumps(
                [
                    {
                        "RemoteAddress": "198.51.100.9",
                        "RemotePort": 443,
                        "State": "Established",
                        "OwningProcess": 200,
                        "CreationTime": "2026-07-06T00:01:00+09:00",
                    }
                ]
            ),
            "",
        )
    if "Get-DnsClientCache" in command:
        return (
            0,
            json.dumps([{"Entry": "example.test", "Data": "198.51.100.9", "Type": "A", "TimeToLive": 120}]),
            "",
        )
    return 1, "", "unexpected command"


class LocalCollectorTests(unittest.TestCase):
    """Check collector event normalization and downstream detection compatibility."""

    def test_collect_local_events_maps_rows_to_schema(self) -> None:
        """Ensure process, TCP, DNS, and download observations map into event schema."""
        with tempfile.TemporaryDirectory() as temp_dir:
            download_path = Path(temp_dir) / "tool.zip"
            download_path.write_text("sample", encoding="utf-8")

            events, meta = collect_local_events(
                command_runner=fake_runner,
                downloads_dir=Path(temp_dir),
                include_dns_cache=True,
                now=datetime.fromisoformat("2026-07-06T00:10:00+09:00"),
            )

        self.assertEqual(meta["source"], "local_windows_collector")
        self.assertEqual(meta["event_sources"]["process_snapshot"], 2)
        self.assertEqual(meta["event_sources"]["tcp_connections"], 1)
        self.assertEqual(meta["event_sources"]["dns_cache"], 1)
        self.assertIn("process_start", {event["event_type"] for event in events})
        self.assertIn("network_connection", {event["event_type"] for event in events})
        self.assertIn("dns_query", {event["event_type"] for event in events})
        self.assertIn("file_download", {event["event_type"] for event in events})

    def test_collected_events_can_be_analyzed(self) -> None:
        """Ensure collected local events remain valid input for detection analysis."""
        events, meta = collect_local_events(
            command_runner=fake_runner,
            include_dns_cache=True,
            now=datetime.fromisoformat("2026-07-06T00:10:00+09:00"),
        )

        result = analyze_events(events, input_meta=meta)

        self.assertEqual(result["status"], "success")
        self.assertEqual(result["input"]["source"], "local_windows_collector")
        self.assertGreaterEqual(result["summary"]["valid_event_count"], 3)
        self.assertIn("R007", {alert["rule_id"] for alert in result["alerts"]})


if __name__ == "__main__":
    unittest.main()
