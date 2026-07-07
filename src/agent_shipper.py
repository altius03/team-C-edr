from __future__ import annotations

import json
import uuid
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, TypeAlias

JsonValue: TypeAlias = str | int | float | bool | None | list["JsonValue"] | dict[str, "JsonValue"]
JsonObject: TypeAlias = dict[str, JsonValue]
EventBatch: TypeAlias = list[JsonObject]


@dataclass(frozen=True, slots=True)
class AgentIdentity:
    customer_id: str
    tenant_id: str
    agent_version: str
    payload_version: str
    api_token: str


@dataclass(frozen=True, slots=True)
class AgentShipConfig:
    collector_url: str
    identity: AgentIdentity
    queue_dir: Path
    timeout_seconds: float = 8.0


@dataclass(frozen=True, slots=True)
class AgentHttpRequest:
    url: str
    payload: JsonObject
    headers: dict[str, str]
    timeout_seconds: float


@dataclass(frozen=True, slots=True)
class HttpSendResult:
    status_code: int
    body: JsonObject
    error: str | None


@dataclass(frozen=True, slots=True)
class ShipResult:
    status: str
    accepted_count: int
    task_id: str | None
    replayed_count: int
    queued_count: int
    error: str | None = None


@dataclass(frozen=True, slots=True)
class SpoolReadResult:
    status: str
    events: EventBatch
    error: str | None


HttpSender: TypeAlias = Callable[[AgentHttpRequest], HttpSendResult]


def ship_events(events: EventBatch, config: AgentShipConfig, *, sender: HttpSender | None = None) -> ShipResult:
    actual_sender = sender or send_http_json
    headers = identity_headers(config.identity)
    replayed_count = 0
    queued_count = 0

    for spool_path in _pending_spool_paths(config.queue_dir):
        read_result = _read_spooled_events(spool_path)
        if read_result.status != "ready":
            _spool_events(config.queue_dir, events, read_result.error or "spool_unreadable")
            return ShipResult(
                status="queued",
                accepted_count=0,
                task_id=None,
                replayed_count=replayed_count,
                queued_count=1,
                error=read_result.error,
            )
        replay_result = _send(actual_sender, _request(config, read_result.events, headers))
        if _is_auth_rejected(replay_result):
            _spool_events(config.queue_dir, events, replay_result.error or f"http_{replay_result.status_code}")
            return _rejected_result(replay_result, replayed_count=replayed_count, queued_count=queued_count + 1)
        if not _is_accepted(replay_result):
            _spool_events(config.queue_dir, events, replay_result.error or f"http_{replay_result.status_code}")
            queued_count += 1
            return ShipResult(
                status="queued",
                accepted_count=0,
                task_id=None,
                replayed_count=replayed_count,
                queued_count=queued_count,
                error=replay_result.error or f"http_{replay_result.status_code}",
            )
        spool_path.unlink()
        replayed_count += 1

    send_result = _send(actual_sender, _request(config, events, headers))
    if _is_accepted(send_result):
        return ShipResult(
            status="accepted",
            accepted_count=_int_field(send_result.body, "accepted_count"),
            task_id=_str_field(send_result.body, "task_id"),
            replayed_count=replayed_count,
            queued_count=queued_count,
        )

    if _is_auth_rejected(send_result):
        _spool_events(config.queue_dir, events, send_result.error or f"http_{send_result.status_code}")
        return _rejected_result(send_result, replayed_count=replayed_count, queued_count=queued_count + 1)

    _spool_events(config.queue_dir, events, send_result.error or f"http_{send_result.status_code}")
    return ShipResult(
        status="queued",
        accepted_count=0,
        task_id=None,
        replayed_count=replayed_count,
        queued_count=queued_count + 1,
        error=send_result.error or f"http_{send_result.status_code}",
    )


def identity_headers(identity: AgentIdentity) -> dict[str, str]:
    return {
        "X-Customer-Id": identity.customer_id,
        "X-Tenant-Id": identity.tenant_id,
        "X-Agent-Version": identity.agent_version,
        "X-Payload-Version": identity.payload_version,
        "X-Api-Token": identity.api_token,
    }


def json_objects_from_dicts(events: list[JsonObject]) -> EventBatch:
    json_events: EventBatch = []
    for event in events:
        json_events.append(_json_object(event))
    return json_events


def send_http_json(request: AgentHttpRequest) -> HttpSendResult:
    data = json.dumps(request.payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    http_request = urllib.request.Request(
        request.url,
        data=data,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "Content-Length": str(len(data)),
            **request.headers,
        },
    )
    try:
        with urllib.request.urlopen(http_request, timeout=request.timeout_seconds) as response:
            return HttpSendResult(status_code=response.getcode(), body=_decode_json_object(response.read()), error=None)
    except urllib.error.HTTPError as error:
        return HttpSendResult(status_code=error.code, body=_decode_json_object(error.read()), error=f"http_{error.code}")
    except urllib.error.URLError as error:
        return HttpSendResult(status_code=0, body={}, error=str(error.reason))
    except TimeoutError:
        return HttpSendResult(status_code=0, body={}, error="timeout")
    except ValueError as error:
        return HttpSendResult(status_code=0, body={}, error=str(error))


def _send(sender: HttpSender, request: AgentHttpRequest) -> HttpSendResult:
    try:
        return sender(request)
    except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError, ValueError, OSError) as error:
        return HttpSendResult(status_code=0, body={}, error=str(error))


def _request(config: AgentShipConfig, events: EventBatch, headers: dict[str, str]) -> AgentHttpRequest:
    return AgentHttpRequest(
        url=config.collector_url,
        payload={"events": events},
        headers=headers,
        timeout_seconds=config.timeout_seconds,
    )


def _is_accepted(result: HttpSendResult) -> bool:
    return result.status_code == 202


def _is_auth_rejected(result: HttpSendResult) -> bool:
    return result.status_code in {401, 403}


def _rejected_result(result: HttpSendResult, *, replayed_count: int, queued_count: int) -> ShipResult:
    return ShipResult(
        status="rejected",
        accepted_count=0,
        task_id=None,
        replayed_count=replayed_count,
        queued_count=queued_count,
        error=result.error or f"http_{result.status_code}",
    )


def _spool_events(queue_dir: Path, events: EventBatch, reason: str) -> Path:
    queue_dir.mkdir(parents=True, exist_ok=True)
    spool_path = queue_dir / f"{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')}-{uuid.uuid4().hex[:8]}.json"
    envelope: JsonObject = {
        "created_at": datetime.now(timezone.utc).isoformat(),
        "reason": reason,
        "events": events,
    }
    temp_path = spool_path.with_suffix(".tmp")
    temp_path.write_text(json.dumps(envelope, ensure_ascii=False, indent=2), encoding="utf-8")
    temp_path.replace(spool_path)
    return spool_path


def _pending_spool_paths(queue_dir: Path) -> list[Path]:
    if not queue_dir.exists():
        return []
    return sorted(path for path in queue_dir.glob("*.json") if path.is_file())


def _read_spooled_events(path: Path) -> SpoolReadResult:
    try:
        parsed = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        return SpoolReadResult(status="blocked", events=[], error=f"spool_unreadable:{error}")
    if not isinstance(parsed, dict):
        return SpoolReadResult(status="blocked", events=[], error="spool_not_object")
    events = parsed.get("events")
    if not isinstance(events, list):
        return SpoolReadResult(status="blocked", events=[], error="spool_events_not_list")
    normalized = [_json_object(event) for event in events if isinstance(event, dict)]
    if len(normalized) != len(events):
        return SpoolReadResult(status="blocked", events=[], error="spool_events_malformed")
    return SpoolReadResult(status="ready", events=normalized, error=None)


def _decode_json_object(data: bytes) -> JsonObject:
    if not data:
        return {}
    try:
        parsed = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return {}
    if not isinstance(parsed, dict):
        return {}
    return _json_object(parsed)


def _json_object(value) -> JsonObject:
    normalized: JsonObject = {}
    for key, item in value.items():
        if isinstance(key, str) and _is_json_value(item):
            normalized[key] = item
    return normalized


def _is_json_value(value) -> bool:
    if value is None or isinstance(value, str | int | float | bool):
        return True
    if isinstance(value, list):
        return all(_is_json_value(item) for item in value)
    if isinstance(value, dict):
        return all(isinstance(key, str) and _is_json_value(item) for key, item in value.items())
    return False


def _int_field(payload: JsonObject, field: str) -> int:
    value = payload.get(field)
    return value if isinstance(value, int) else 0


def _str_field(payload: JsonObject, field: str) -> str | None:
    value = payload.get(field)
    return value if isinstance(value, str) else None
