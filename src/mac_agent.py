"""macOS metadata agent that emits tcpdump-derived or simulated events."""

from __future__ import annotations

import argparse
import json
import os
import re
import socket
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.agent_shipper import AgentIdentity, AgentShipConfig, json_objects_from_dicts, ship_events
from src.config import AGENT_VERSION, CUSTOMER_ID, OUTPUTS_DIR, PAYLOAD_VERSION, TENANT_ID


TCPDUMP_RE = re.compile(
    r"^(?P<ts>\d+(?:\.\d+)?)\s+IP\s+(?P<src>[^ ]+)\s+>\s+(?P<dst>[^:]+):.*?(?:length\s+(?P<len>\d+))?"
)


def run_agent(argv: list[str] | None = None) -> int:
    """Parse CLI options, collect events, and print or post the payload."""
    parser = argparse.ArgumentParser(description="macOS endpoint metadata agent PoC")
    parser.add_argument("--iface", default="en0")
    parser.add_argument("--host-id", default=socket.gethostname() or "mac-endpoint")
    parser.add_argument("--collector-url", default="")
    parser.add_argument("--duration", type=int, default=30)
    parser.add_argument("--bpf", default="tcp or udp")
    parser.add_argument("--simulate", action="store_true")
    parser.add_argument("--api-token", default=os.environ.get("LAYERTRACE_API_TOKEN", "local-dev-token"))
    parser.add_argument("--customer-id", default=CUSTOMER_ID)
    parser.add_argument("--tenant-id", default=TENANT_ID)
    parser.add_argument("--agent-version", default=AGENT_VERSION)
    parser.add_argument("--payload-version", default=PAYLOAD_VERSION)
    parser.add_argument("--queue-dir", default=str(OUTPUTS_DIR / "agent_queue"))
    parser.add_argument("--timeout-seconds", type=float, default=8.0)
    args = parser.parse_args(argv)

    events = simulate_events(args.host_id) if args.simulate else capture_tcpdump_events(args.iface, args.host_id, args.duration, args.bpf)
    payload = {
        "source": "mac_agent",
        "host_id": args.host_id,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "events": events,
    }
    if args.collector_url:
        result = ship_events(
            json_objects_from_dicts(events),
            AgentShipConfig(
                collector_url=args.collector_url,
                identity=AgentIdentity(
                    customer_id=args.customer_id,
                    tenant_id=args.tenant_id,
                    agent_version=args.agent_version,
                    payload_version=args.payload_version,
                    api_token=args.api_token,
                ),
                queue_dir=Path(args.queue_dir),
                timeout_seconds=args.timeout_seconds,
            ),
        )
        print(
            json.dumps(
                {
                    "status": result.status,
                    "accepted_count": result.accepted_count,
                    "task_id": result.task_id,
                    "replayed_count": result.replayed_count,
                    "queued_count": result.queued_count,
                    "error": result.error,
                    "collected_count": len(events),
                    "source": payload["source"],
                    "queue_dir": str(Path(args.queue_dir)),
                },
                ensure_ascii=False,
                indent=2,
            )
        )
        return 0 if result.status in {"accepted", "queued"} else 1
    else:
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    return 0


def capture_tcpdump_events(iface: str, host_id: str, duration: int, bpf: str) -> list[dict[str, Any]]:
    """Capture tcpdump output for a bounded duration and return event rows."""
    command = ["tcpdump", "-i", iface, "-l", "-n", "-tt", "-q", *bpf.split()]
    started = time.time()
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    events: list[dict[str, Any]] = []
    try:
        assert process.stdout is not None
        while time.time() - started < duration:
            line = process.stdout.readline()
            if not line:
                break
            event = parse_tcpdump_line(line, host_id, len(events) + 1)
            if event:
                events.append(event)
    finally:
        process.terminate()
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            process.kill()
    return events


def parse_tcpdump_line(line: str, host_id: str, index: int) -> dict[str, Any] | None:
    """Convert one tcpdump line into a network_connection event when it matches."""
    match = TCPDUMP_RE.search(line.strip())
    if not match:
        return None
    src_ip, src_port = _split_addr(match.group("src"))
    dst_ip, dst_port = _split_addr(match.group("dst"))
    event_time = datetime.fromtimestamp(float(match.group("ts")), timezone.utc).isoformat()
    return {
        "event_id": f"mac-net-{index:04d}",
        "event_time": event_time,
        "received_time": datetime.now(timezone.utc).isoformat(),
        "host_id": host_id,
        "event_type": "network_connection",
        "source": "mac_agent_tcpdump",
        "payload_version": "v1",
        "process_name": "unknown",
        "src_ip": src_ip,
        "src_port": src_port,
        "dst_ip": dst_ip,
        "dst_port": dst_port,
        "protocol": "tcp",
        "bytes_out": int(match.group("len") or 0),
        "bytes_in": 0,
        "duration_ms": 0,
        "collection_mode": "tcpdump_metadata",
    }


def simulate_events(host_id: str) -> list[dict[str, Any]]:
    """Return deterministic macOS-style events for environments without tcpdump."""
    now = datetime.now(timezone.utc)
    return [
        {
            "event_id": "mac-sim-001",
            "event_time": now.isoformat(),
            "received_time": now.isoformat(),
            "host_id": host_id,
            "event_type": "network_connection",
            "source": "mac_agent_simulate",
            "payload_version": "v1",
            "process_name": "zsh",
            "dst_domain": "c2.badbeacon.example",
            "dst_ip": "203.0.113.77",
            "dst_port": 443,
            "protocol": "tcp",
            "bytes_out": 2048,
            "bytes_in": 1024,
            "duration_ms": 900,
        }
    ]


def _split_addr(value: str) -> tuple[str, int]:
    """Split tcpdump host.port text into host and integer port."""
    host, _, port = value.rpartition(".")
    try:
        return host, int(port)
    except ValueError:
        return value, 0


if __name__ == "__main__":
    sys.exit(run_agent())
