"""Parse PCAP files into TCP flow summaries and plaintext HTTP events."""

from __future__ import annotations

import ipaddress
import struct
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


class PcapFlowError(Exception):
    """Raised when PCAP bytes are missing or use an unsupported format."""

    pass


HTTP_METHODS = {b"GET", b"POST", b"PUT", b"DELETE", b"PATCH", b"HEAD", b"OPTIONS"}


@dataclass
class FlowState:
    """Accumulates bidirectional counters for one normalized TCP flow."""

    first_ts: float
    last_ts: float
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    packets_out: int = 0
    packets_in: int = 0
    bytes_out: int = 0
    bytes_in: int = 0
    flags: set[str] = field(default_factory=set)


def events_from_pcap(path: Path, *, host_id: str = "pcap-endpoint") -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Read a PCAP file and return flow/http events with parse metadata."""
    packets = list(_iter_tcp_packets(path))
    flows: dict[tuple, FlowState] = {}
    http_events: list[dict[str, Any]] = []

    for packet in packets:
        # 흐름 키는 방향 중립적입니다. 각 패킷 엔드포인트를 상태에 저장된
        # 첫 패킷과 비교해 패킷 방향을 복원합니다.
        key = _flow_key(packet)
        flow = flows.get(key)
        if flow is None:
            flow = FlowState(
                first_ts=packet["ts"],
                last_ts=packet["ts"],
                src_ip=packet["src_ip"],
                src_port=packet["src_port"],
                dst_ip=packet["dst_ip"],
                dst_port=packet["dst_port"],
            )
            flows[key] = flow
        flow.last_ts = max(flow.last_ts, packet["ts"])
        if packet["src_ip"] == flow.src_ip and packet["src_port"] == flow.src_port:
            flow.packets_out += 1
            flow.bytes_out += packet["payload_len"]
        else:
            flow.packets_in += 1
            flow.bytes_in += packet["payload_len"]
        flow.flags.update(packet["flags"])

        http = _parse_http_request(packet["payload"])
        if http:
            event_time = _iso(packet["ts"])
            http_events.append(
                {
                    "event_id": f"pcap-http-{len(http_events) + 1:03d}",
                    "event_time": event_time,
                    "received_time": event_time,
                    "host_id": host_id,
                    "event_type": "http_request",
                    "source": "pcap_flow_analyzer",
                    "payload_version": "v1",
                    "process_name": "pcap_capture",
                    "method": http["method"],
                    "url": http["url"],
                    "url_path": http["path"],
                    "dst_domain": http["host"],
                    "dst_ip": packet["dst_ip"],
                    "dst_port": packet["dst_port"],
                    "protocol": "http",
                    "decrypted": False,
                    "collection_mode": "pcap_l7_plaintext",
                }
            )

    flow_events: list[dict[str, Any]] = []
    for index, flow in enumerate(flows.values(), start=1):
        duration_ms = max(0, int((flow.last_ts - flow.first_ts) * 1000))
        flow_events.append(
            {
                "event_id": f"pcap-flow-{index:03d}",
                "event_time": _iso(flow.first_ts),
                "received_time": _iso(flow.last_ts),
                "host_id": host_id,
                "event_type": "flow_summary",
                "source": "pcap_flow_analyzer",
                "payload_version": "v1",
                "process_name": "pcap_capture",
                "dst_ip": flow.dst_ip,
                "dst_port": flow.dst_port,
                "protocol": "tcp",
                "packet_count": flow.packets_out + flow.packets_in,
                "bytes_out": flow.bytes_out,
                "bytes_in": flow.bytes_in,
                "duration_ms": duration_ms,
                "tcp_flags": sorted(flow.flags),
                "collection_mode": "pcap_tcp_flow_reassembly",
            }
        )

    events = flow_events + http_events
    meta = {
        "source": "pcap_file",
        "path": str(path),
        "packet_count": len(packets),
        "flow_count": len(flow_events),
        "http_request_count": len(http_events),
        "raw_event_count": len(events),
    }
    return events, meta


def _iter_tcp_packets(path: Path):
    """Yield parsed IPv4/TCP packets from classic PCAP record bytes."""
    data = path.read_bytes()
    if len(data) < 24:
        raise PcapFlowError(f"not a pcap file or too short: {path}")

    endian, resolution = _pcap_format(data[:4])
    offset = 24
    while offset + 16 <= len(data):
        ts_sec, ts_frac, incl_len, _orig_len = struct.unpack(endian + "IIII", data[offset : offset + 16])
        offset += 16
        frame = data[offset : offset + incl_len]
        offset += incl_len
        packet = _parse_ethernet_ipv4_tcp(frame)
        if packet is None:
            continue
        packet["ts"] = ts_sec + (ts_frac / resolution)
        yield packet


def _pcap_format(magic: bytes) -> tuple[str, int]:
    """Return struct endianness and timestamp resolution for a PCAP magic."""
    if magic == b"\xd4\xc3\xb2\xa1":
        return "<", 1_000_000
    if magic == b"\xa1\xb2\xc3\xd4":
        return ">", 1_000_000
    if magic == b"\x4d\x3c\xb2\xa1":
        return "<", 1_000_000_000
    if magic == b"\xa1\xb2\x3c\x4d":
        return ">", 1_000_000_000
    raise PcapFlowError("unsupported pcap magic")


def _parse_ethernet_ipv4_tcp(frame: bytes) -> dict[str, Any] | None:
    """Parse one Ethernet frame into TCP metadata and payload bytes."""
    if len(frame) < 54:
        return None
    eth_type = struct.unpack("!H", frame[12:14])[0]
    if eth_type != 0x0800:
        return None

    ip_start = 14
    version_ihl = frame[ip_start]
    version = version_ihl >> 4
    ihl = (version_ihl & 0x0F) * 4
    if version != 4 or len(frame) < ip_start + ihl + 20:
        return None
    protocol = frame[ip_start + 9]
    if protocol != 6:
        return None
    total_len = struct.unpack("!H", frame[ip_start + 2 : ip_start + 4])[0]
    src_ip = str(ipaddress.ip_address(frame[ip_start + 12 : ip_start + 16]))
    dst_ip = str(ipaddress.ip_address(frame[ip_start + 16 : ip_start + 20]))

    tcp_start = ip_start + ihl
    src_port, dst_port, _seq, _ack, offset_flags = struct.unpack("!HHIIH", frame[tcp_start : tcp_start + 14])
    tcp_header_len = ((offset_flags >> 12) & 0x0F) * 4
    flags_value = offset_flags & 0x01FF
    payload_start = tcp_start + tcp_header_len
    payload_end = min(len(frame), ip_start + total_len)
    payload = frame[payload_start:payload_end]
    return {
        "src_ip": src_ip,
        "src_port": src_port,
        "dst_ip": dst_ip,
        "dst_port": dst_port,
        "payload": payload,
        "payload_len": len(payload),
        "flags": _flags(flags_value),
    }


def _flags(value: int) -> set[str]:
    """Convert TCP flag bits into readable flag names."""
    names = [
        (0x001, "FIN"),
        (0x002, "SYN"),
        (0x004, "RST"),
        (0x008, "PSH"),
        (0x010, "ACK"),
        (0x020, "URG"),
        (0x040, "ECE"),
        (0x080, "CWR"),
    ]
    return {name for bit, name in names if value & bit}


def _flow_key(packet: dict[str, Any]) -> tuple:
    """Build a direction-neutral key from packet endpoint pairs."""
    a = (packet["src_ip"], packet["src_port"])
    b = (packet["dst_ip"], packet["dst_port"])
    return tuple(sorted((a, b)))


def _parse_http_request(payload: bytes) -> dict[str, str] | None:
    """Extract method, host, path, and URL from a plaintext HTTP payload."""
    if not payload:
        return None
    first_line = payload.split(b"\r\n", 1)[0]
    parts = first_line.split()
    if len(parts) < 2 or parts[0] not in HTTP_METHODS:
        return None
    headers = payload.decode("iso-8859-1", errors="replace").split("\r\n")
    host = ""
    for line in headers[1:]:
        if line.lower().startswith("host:"):
            host = line.split(":", 1)[1].strip().lower()
            break
    path = parts[1].decode("utf-8", errors="replace")
    url = f"http://{host}{path}" if host and path.startswith("/") else path
    return {"method": parts[0].decode("ascii"), "path": path, "host": host, "url": url}


def _iso(ts: float) -> str:
    """Format a packet timestamp as a UTC ISO-8601 string."""
    return datetime.fromtimestamp(ts, timezone.utc).isoformat()
