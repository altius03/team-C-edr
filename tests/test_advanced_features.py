import json
import struct
import sys
import tempfile
import unittest
from pathlib import Path

PROJECT_DIR = Path(__file__).resolve().parents[1]
if str(PROJECT_DIR) not in sys.path:
    sys.path.insert(0, str(PROJECT_DIR))

from src.ai_predictor import build_ai_predictions
from src.detection_engine import analyze_events
from src.l7_inspector import events_from_l7_file
from src.pcap_flow import events_from_pcap
from src.pipeline import build_pipeline_bundle
from src.response_engine import build_response_plan


class AdvancedFeatureTests(unittest.TestCase):
    def test_pcap_flow_analyzer_extracts_flow_and_http_request(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            pcap_path = Path(temp_dir) / "http.pcap"
            pcap_path.write_bytes(_pcap_with_http_get())

            events, meta = events_from_pcap(pcap_path, host_id="pcap-host")

        self.assertEqual(meta["flow_count"], 1)
        self.assertEqual(meta["http_request_count"], 1)
        self.assertIn("flow_summary", {event["event_type"] for event in events})
        http = next(event for event in events if event["event_type"] == "http_request")
        self.assertEqual(http["dst_domain"], "malware-drop.example")

    def test_l7_inspector_and_new_rules_generate_alerts(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "l7.json"
            path.write_text(
                json.dumps(
                    {
                        "records": [
                            {
                                "record_type": "http_request",
                                "event_id": "l7-test-001",
                                "event_time": "2026-07-05T10:00:00+09:00",
                                "host_id": "l7-host",
                                "url": "https://phish-login.example/login",
                                "url_category": "phishing",
                                "decrypted": True,
                            },
                            {
                                "record_type": "application_action",
                                "event_id": "l7-test-002",
                                "event_time": "2026-07-05T10:01:00+09:00",
                                "host_id": "l7-host",
                                "app_name": "KakaoTalk",
                                "app_action": "message_send",
                                "object_url": "https://evil-kakao-link.example/collect",
                                "attachment_hash": "badbeef0000000000000000000000000000000000000000000000000000000001",
                                "message_content": "must be removed",
                            },
                        ]
                    }
                ),
                encoding="utf-8",
            )
            events, meta = events_from_l7_file(path)

        result = analyze_events(events, input_meta=meta)
        rules = {alert["rule_id"] for alert in result["alerts"]}
        serialized = json.dumps(result, ensure_ascii=False)

        self.assertIn("R009", rules)
        self.assertIn("R010", rules)
        self.assertIn("R011", rules)
        self.assertNotIn("must be removed", serialized)

    def test_response_ai_and_pipeline_outputs_are_created(self) -> None:
        events, meta = events_from_l7_file(PROJECT_DIR / "samples" / "decrypted_l7_records.json")
        result = analyze_events(events, input_meta=meta)
        result["response_plan"] = build_response_plan(result)
        result["ai_predictions"] = build_ai_predictions(result)
        with tempfile.TemporaryDirectory() as temp_dir:
            from src import pipeline

            original_latest = pipeline.LATEST_PIPELINE_DIR
            original_runs = pipeline.PIPELINE_RUNS_DIR
            pipeline.LATEST_PIPELINE_DIR = Path(temp_dir) / "latest"
            pipeline.PIPELINE_RUNS_DIR = Path(temp_dir) / "runs"
            try:
                delivery = build_pipeline_bundle(result)
                bundle_exists = Path(delivery["latest_bundle_path"]).exists()
            finally:
                pipeline.LATEST_PIPELINE_DIR = original_latest
                pipeline.PIPELINE_RUNS_DIR = original_runs

        self.assertGreater(result["response_plan"]["action_count"], 0)
        self.assertGreaterEqual(result["ai_predictions"]["prediction_count"], 1)
        self.assertEqual(delivery["compression"], "gzip")
        self.assertTrue(bundle_exists)


def _pcap_with_http_get() -> bytes:
    payload = b"GET /payload/invoice.exe HTTP/1.1\r\nHost: malware-drop.example\r\n\r\n"
    frame = _ethernet_ipv4_tcp_frame(payload)
    global_header = b"\xd4\xc3\xb2\xa1" + struct.pack("<HHIIII", 2, 4, 0, 0, 65535, 1)
    packet_header = struct.pack("<IIII", 1_783_200_000, 0, len(frame), len(frame))
    return global_header + packet_header + frame


def _ethernet_ipv4_tcp_frame(payload: bytes) -> bytes:
    ethernet = b"\x00\x11\x22\x33\x44\x55" + b"\x66\x77\x88\x99\xaa\xbb" + struct.pack("!H", 0x0800)
    src_ip = b"\x0a\x00\x00\x01"
    dst_ip = b"\xcb\x00\x71\x4d"
    tcp_header = struct.pack("!HHIIHHHH", 53000, 80, 1, 0, (5 << 12) | 0x18, 8192, 0, 0)
    total_len = 20 + len(tcp_header) + len(payload)
    ip_header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total_len, 1, 0, 64, 6, 0, src_ip, dst_ip)
    return ethernet + ip_header + tcp_header + payload


if __name__ == "__main__":
    unittest.main()
