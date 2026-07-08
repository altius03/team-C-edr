"""macOS metadata agent that emits tcpdump-derived or simulated events."""

from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import socket
import subprocess
import sys
import tempfile
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.agent_shipper import AgentIdentity, AgentShipConfig, JsonObject, json_objects_from_dicts, ship_events
from src.collector_policy import CollectorPolicyError, api_token_for_collector
from src.config import AGENT_VERSION, CUSTOMER_ID, OUTPUTS_DIR, PAYLOAD_VERSION, TENANT_ID


TCPDUMP_RE = re.compile(
    r"^(?P<ts>\d+(?:\.\d+)?)\s+IP\s+(?P<src>[^ ]+)\s+>\s+(?P<dst>[^:]+):(?P<body>.*)$"
)
TCPDUMP_LENGTH_RE = re.compile(r"\blength\s+(?P<len>\d+)")
MAX_CAPTURE_DURATION_SECONDS = 3600


@dataclass(frozen=True, slots=True)
class AgentCliError(Exception):
    code: str
    message: str
    exit_code: int


@dataclass(frozen=True, slots=True)
class TcpdumpCaptureConfig:
    iface: str
    host_id: str
    duration: int
    bpf_tokens: list[str]


def run_agent(argv: list[str] | None = None) -> int:
    """Parse CLI options, collect events, and print or post the payload."""
    parser = argparse.ArgumentParser(description="macOS endpoint metadata agent PoC")
    parser.add_argument("--iface", default="en0")
    parser.add_argument("--host-id", default=socket.gethostname() or "mac-endpoint")
    parser.add_argument("--collector-url", default="")
    parser.add_argument("--duration", type=int, default=30)
    parser.add_argument("--bpf", default="tcp or udp")
    parser.add_argument("--simulate", action="store_true")
    parser.add_argument("--api-token", default=os.environ.get("LAYERTRACE_API_TOKEN") or "")
    parser.add_argument("--customer-id", default=CUSTOMER_ID)
    parser.add_argument("--tenant-id", default=TENANT_ID)
    parser.add_argument("--agent-version", default=AGENT_VERSION)
    parser.add_argument("--payload-version", default=PAYLOAD_VERSION)
    parser.add_argument("--queue-dir", default=str(OUTPUTS_DIR / "agent_queue"))
    parser.add_argument("--timeout-seconds", type=float, default=8.0)
    args = parser.parse_args(argv)

    try:
        _validate_duration(args.duration)
        bpf_tokens = _parse_bpf_tokens(args.bpf)
        api_token = api_token_for_collector(args.collector_url, args.api_token)
        events = (
            simulate_events(args.host_id)
            if args.simulate
            else capture_tcpdump_events(
                TcpdumpCaptureConfig(
                    iface=args.iface,
                    host_id=args.host_id,
                    duration=args.duration,
                    bpf_tokens=bpf_tokens,
                )
            )
        )
    except AgentCliError as error:
        _print_error(args.host_id, error)
        return error.exit_code
    except CollectorPolicyError as error:
        _print_error(args.host_id, AgentCliError(error.code, error.message, error.exit_code))
        return error.exit_code

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
                    api_token=api_token,
                ),
                queue_dir=Path(args.queue_dir),
                timeout_seconds=args.timeout_seconds,
            ),
        )
        output = {
            "status": result.status,
            "accepted_count": result.accepted_count,
            "task_id": result.task_id,
            "replayed_count": result.replayed_count,
            "queued_count": result.queued_count,
            "error": result.error,
            "collected_count": len(events),
            "source": payload["source"],
            "queue_dir": str(Path(args.queue_dir)),
        }
        print(json.dumps(output, ensure_ascii=False, indent=2))
        return 0 if result.status in {"accepted", "queued"} else 1
    print(json.dumps(payload, ensure_ascii=False, indent=2))
    return 0


def capture_tcpdump_events(config: TcpdumpCaptureConfig) -> list[JsonObject]:
    """Capture tcpdump output for a bounded duration and return event rows."""
    command = ["tcpdump", "-i", config.iface, "-l", "-n", "-tt", "-q", *config.bpf_tokens]
    with tempfile.TemporaryFile("w+t", encoding="utf-8") as stdout_file, tempfile.TemporaryFile("w+t", encoding="utf-8") as stderr_file:
        try:
            process = subprocess.Popen(command, stdout=stdout_file, stderr=stderr_file, text=True)
        except OSError as error:
            raise AgentCliError("tcpdump_start_failed", str(error), 1) from error
        completed = _wait_until_duration(process, config.duration)
        stderr_file.seek(0)
        if completed and process.returncode != 0:
            raise AgentCliError("tcpdump_failed", _tcpdump_error_message(stderr_file.read(), process.returncode), 1)
        stdout_file.seek(0)
        return _parse_tcpdump_lines(stdout_file, config.host_id)


def _parse_tcpdump_lines(lines: Iterable[str], host_id: str) -> list[JsonObject]:
    events: list[JsonObject] = []
    for line in lines:
        event = parse_tcpdump_line(line, host_id, len(events) + 1)
        if event:
            events.append(event)
    return events


def parse_tcpdump_line(line: str, host_id: str, index: int) -> JsonObject | None:
    """Convert one tcpdump line into a network_connection event when it matches."""
    match = TCPDUMP_RE.search(line.strip())
    if not match:
        return None
    src_ip, src_port = _split_addr(match.group("src"))
    dst_ip, dst_port = _split_addr(match.group("dst"))
    length_match = TCPDUMP_LENGTH_RE.search(match.group("body"))
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
        "bytes_out": int(length_match.group("len")) if length_match else 0,
        "bytes_in": 0,
        "duration_ms": 0,
        "collection_mode": "tcpdump_metadata",
    }


def simulate_events(host_id: str) -> list[JsonObject]:
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


def _validate_duration(duration: int) -> None:
    if duration <= 0 or duration > MAX_CAPTURE_DURATION_SECONDS:
        raise AgentCliError("invalid_duration", f"--duration must be between 1 and {MAX_CAPTURE_DURATION_SECONDS} seconds", 2)


def _parse_bpf_tokens(bpf: str) -> list[str]:
    try:
        tokens = shlex.split(bpf)
    except ValueError as error:
        raise AgentCliError("invalid_bpf", str(error), 2) from error
    for token in tokens:
        if token.startswith("-"):
            raise AgentCliError("invalid_bpf", "BPF tokens must not start with '-'", 2)
    return tokens


def _wait_until_duration(process: subprocess.Popen[str], duration: int) -> bool:
    try:
        process.wait(timeout=duration)
        return True
    except subprocess.TimeoutExpired:
        process.terminate()
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
        return False


def _tcpdump_error_message(stderr_text: str, returncode: int | None) -> str:
    message = stderr_text.strip()
    return message or f"tcpdump exited with status {returncode}"


def _print_error(host_id: str, error: AgentCliError) -> None:
    payload = {
        "status": "error",
        "source": "mac_agent",
        "host_id": host_id,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "events": [],
        "error": {"code": error.code, "message": error.message},
    }
    print(json.dumps(payload, ensure_ascii=False, indent=2), file=sys.stderr)


if __name__ == "__main__":
    sys.exit(run_agent())
