from __future__ import annotations

import argparse
import json
import re
import socket
import subprocess
import sys
import time
import urllib.request
from datetime import datetime, timezone
from typing import Any


TCPDUMP_RE = re.compile(
    r"^(?P<ts>\d+(?:\.\d+)?)\s+IP\s+(?P<src>[^ ]+)\s+>\s+(?P<dst>[^:]+):.*?(?:length\s+(?P<len>\d+))?"
)


def run_agent(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="macOS endpoint metadata agent PoC")
    parser.add_argument("--iface", default="en0")
    parser.add_argument("--host-id", default=socket.gethostname() or "mac-endpoint")
    parser.add_argument("--collector-url", default="")
    parser.add_argument("--duration", type=int, default=30)
    parser.add_argument("--bpf", default="tcp or udp")
    parser.add_argument("--simulate", action="store_true")
    args = parser.parse_args(argv)

    events = simulate_events(args.host_id) if args.simulate else capture_tcpdump_events(args.iface, args.host_id, args.duration, args.bpf)
    payload = {
        "source": "mac_agent",
        "host_id": args.host_id,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "events": events,
    }
    if args.collector_url:
        _post_json(args.collector_url, payload)
    else:
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    return 0


def capture_tcpdump_events(iface: str, host_id: str, duration: int, bpf: str) -> list[dict[str, Any]]:
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
    host, _, port = value.rpartition(".")
    try:
        return host, int(port)
    except ValueError:
        return value, 0


def _post_json(url: str, payload: dict[str, Any]) -> None:
    data = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(url, data=data, method="POST", headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(request, timeout=8) as response:
        response.read()


if __name__ == "__main__":
    sys.exit(run_agent())
