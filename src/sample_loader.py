"""Load sample event fixtures and expand compact generated-flow specs."""

from __future__ import annotations

import json
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any


class SampleLoadError(Exception):
    """Raised when a sample input cannot be converted into event rows."""

    def __init__(self, code: str, message: str, partial_result: dict[str, Any] | None = None) -> None:
        """Store a stable error code with optional context for failure output."""
        super().__init__(message)
        self.code = code
        self.partial_result = partial_result or {}


def load_events(path: Path) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Read a JSON event file and return event rows with input metadata."""
    if not path.exists():
        raise SampleLoadError(
            "MISSING_INPUT",
            f"이벤트 파일을 찾을 수 없습니다: {path}",
            {"requested_path": str(path)},
        )

    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        raise SampleLoadError(
            "INVALID_EVENT_FILE",
            f"JSON 파싱에 실패했습니다: {error}",
            {"requested_path": str(path), "line": error.lineno, "column": error.colno},
        ) from error

    if isinstance(payload, list):
        events = payload
        generated_count = 0
    elif isinstance(payload, dict):
        events = list(payload.get("events", []))
        # Generated flows are compact fixture specs; expand them before adding
        # intentionally invalid rows so downstream validation sees one stream.
        generated_events = _expand_generated_flows(payload.get("generated_flows", []))
        generated_count = len(generated_events)
        events.extend(generated_events)
        events.extend(payload.get("invalid_events", []))
    else:
        raise SampleLoadError(
            "INVALID_EVENT_FILE",
            "이벤트 파일은 list 또는 object 형식이어야 합니다.",
            {"requested_path": str(path), "payload_type": type(payload).__name__},
        )

    if not all(isinstance(item, dict) for item in events):
        raise SampleLoadError(
            "INVALID_EVENT_FILE",
            "모든 event는 JSON object여야 합니다.",
            {"requested_path": str(path)},
        )

    return events, {
        "source": "event_file",
        "path": str(path),
        "raw_event_count": len(events),
        "generated_event_count": generated_count,
    }


def _expand_generated_flows(specs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Convert compact flow specifications into timestamped network events."""
    events: list[dict[str, Any]] = []
    for spec in specs:
        count = int(spec.get("count", 0))
        start = datetime.fromisoformat(spec["start_time"])
        interval = int(spec.get("interval_seconds", 60))
        prefix = spec.get("id_prefix", "generated-flow")
        domains = spec.get("dst_domain_cycle") or [spec.get("dst_domain", "intranet.company.test")]
        ips = spec.get("dst_ip_cycle") or [spec.get("dst_ip", "10.10.10.10")]

        for index in range(count):
            event_time = start + timedelta(seconds=interval * index)
            received_time = event_time + timedelta(seconds=int(spec.get("receive_delay_seconds", 2)))
            events.append(
                {
                    "event_id": f"{prefix}-{index + 1:03d}",
                    "event_time": event_time.isoformat(timespec="seconds"),
                    "received_time": received_time.isoformat(timespec="seconds"),
                    "host_id": spec["host_id"],
                    "event_type": spec.get("event_type", "network_connection"),
                    "source": spec.get("source", "agent"),
                    "payload_version": spec.get("payload_version", "v1"),
                    "process_name": spec.get("process_name", "chrome.exe"),
                    "dst_domain": domains[index % len(domains)],
                    "dst_ip": ips[index % len(ips)],
                    "dst_port": int(spec.get("dst_port", 443)),
                    "protocol": spec.get("protocol", "tcp"),
                    "bytes_out": int(spec.get("bytes_out", 18_000)),
                    "bytes_in": int(spec.get("bytes_in", 82_000)),
                    "duration_ms": int(spec.get("duration_ms", 3_200)),
                    "destination_asn": spec.get("destination_asn", "AS15169"),
                }
            )
    return events
