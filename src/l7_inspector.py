"""Convert decrypted L7 metadata records into normalized event dictionaries."""

from __future__ import annotations

import json
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


class L7InspectionError(Exception):
    """Raised when L7 metadata input is not readable as supported records."""

    pass


def events_from_l7_file(path: Path, *, default_host: str = "l7-endpoint") -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Load JSON/JSONL L7 records and return events with source metadata."""
    try:
        text = path.read_text(encoding="utf-8")
        payload = _load_records_payload(text, path)
    except json.JSONDecodeError as error:
        raise L7InspectionError(f"invalid L7 inspection JSON: {error}") from error

    records = payload.get("records") if isinstance(payload, dict) else payload
    if not isinstance(records, list):
        raise L7InspectionError("L7 inspection input must be a list or {records: [...]}")

    events = events_from_l7_records(records, default_host=default_host)
    return events, {
        "source": "decrypted_l7_file",
        "path": str(path),
        "record_count": len(records),
        "raw_event_count": len(events),
        "privacy_note": "L7 records keep metadata only; message/http body fields are dropped by privacy sanitizer.",
    }


def _load_records_payload(text: str, path: Path) -> Any:
    """Parse JSON or JSONL text into the raw payload shape."""
    stripped = text.strip()
    if not stripped:
        return []
    if path.suffix.lower() == ".jsonl":
        return [json.loads(line) for line in stripped.splitlines() if line.strip()]
    return json.loads(stripped)


def events_from_l7_records(records: list[dict[str, Any]], *, default_host: str = "l7-endpoint") -> list[dict[str, Any]]:
    """Map L7 record variants into HTTP, decryption, or application events."""
    base_time = datetime.now().astimezone().replace(microsecond=0)
    events: list[dict[str, Any]] = []
    for index, record in enumerate(records, start=1):
        record_type = str(record.get("record_type") or record.get("type") or "http_request")
        event_time = _time(record.get("event_time"), base_time + timedelta(seconds=index))
        host_id = str(record.get("host_id") or default_host)
        # Common fields keep the L7 source compatible with the detector's event
        # contract before variant-specific HTTP/TLS/application fields are added.
        common = {
            "event_id": str(record.get("event_id") or f"l7-{index:03d}"),
            "event_time": event_time.isoformat(),
            "received_time": (event_time + timedelta(seconds=1)).isoformat(),
            "host_id": host_id,
            "source": str(record.get("source") or "l7_inspection_proxy"),
            "payload_version": "v1",
            "process_name": str(record.get("process_name") or record.get("app") or "unknown"),
            "collection_mode": "decrypted_l7_metadata",
        }
        if record_type in {"http", "http_request"}:
            url = str(record.get("url") or "")
            parsed = urlparse(url)
            events.append(
                {
                    **common,
                    "event_type": "http_request",
                    "method": str(record.get("method") or "GET").upper(),
                    "url": url,
                    "url_path": parsed.path or "/",
                    "dst_domain": str(record.get("dst_domain") or parsed.hostname or "").lower(),
                    "dst_ip": record.get("dst_ip", ""),
                    "dst_port": int(record.get("dst_port") or parsed.port or (443 if parsed.scheme == "https" else 80)),
                    "protocol": parsed.scheme or "https",
                    "app_id": record.get("app_id") or record.get("app") or "browser",
                    "url_category": record.get("url_category", "unknown"),
                    "decrypted": bool(record.get("decrypted", True)),
                }
            )
        elif record_type in {"tls", "decryption_event"}:
            events.append(
                {
                    **common,
                    "event_type": "decryption_event",
                    "sni": str(record.get("sni") or record.get("dst_domain") or "").lower(),
                    "dst_domain": str(record.get("dst_domain") or record.get("sni") or "").lower(),
                    "dst_port": int(record.get("dst_port") or 443),
                    "tls_version": record.get("tls_version", "TLS1.3"),
                    "decryption_policy": record.get("decryption_policy", "inspect-known-risk"),
                    "decryption_result": record.get("decryption_result", "decrypted"),
                    "proxy_mode": record.get("proxy_mode", "explicit_proxy"),
                    "certificate_issuer": record.get("certificate_issuer", "PoC Local CA"),
                }
            )
        elif record_type in {"application", "application_action"}:
            url = str(record.get("url") or record.get("object_url") or "")
            parsed = urlparse(url)
            events.append(
                {
                    **common,
                    "event_type": "application_action",
                    "app_name": record.get("app_name") or record.get("app") or "unknown",
                    "app_action": record.get("app_action") or record.get("action") or "unknown",
                    "object_url": url,
                    "dst_domain": str(record.get("dst_domain") or parsed.hostname or "").lower(),
                    "attachment_name": record.get("attachment_name", ""),
                    "attachment_hash": record.get("attachment_hash", ""),
                    "message_content": record.get("message_content", ""),
                    "decrypted": bool(record.get("decrypted", True)),
                }
            )
    return events


def _time(value: Any, fallback: datetime) -> datetime:
    """Parse an event timestamp and use the supplied fallback on bad input."""
    if not value:
        return fallback
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return fallback
