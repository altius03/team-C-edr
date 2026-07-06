from __future__ import annotations

import hashlib
import json
import socket
import subprocess
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Callable


class LocalCollectionError(Exception):
    def __init__(self, code: str, message: str, partial_result: dict[str, Any] | None = None) -> None:
        super().__init__(message)
        self.code = code
        self.partial_result = partial_result or {}


CommandRunner = Callable[[str], tuple[int, str, str]]


def collect_local_events(
    *,
    lookback_hours: int = 24,
    max_processes: int = 80,
    max_connections: int = 120,
    include_dns_cache: bool = False,
    command_runner: CommandRunner | None = None,
    downloads_dir: Path | None = None,
    now: datetime | None = None,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    collected_at = (now or datetime.now().astimezone()).replace(microsecond=0)
    host_id = socket.gethostname() or "local-endpoint"
    runner = command_runner or _run_powershell
    warnings: list[dict[str, str]] = []

    processes = _safe_collect("process_snapshot", _collect_process_rows, runner, warnings)
    connections = _safe_collect("tcp_connections", _collect_tcp_rows, runner, warnings)
    dns_rows: list[dict[str, Any]] = []
    if include_dns_cache:
        dns_rows = _safe_collect("dns_cache", _collect_dns_rows, runner, warnings)

    pid_to_process = _build_pid_map(processes)
    events: list[dict[str, Any]] = []
    events.extend(_process_events(processes[:max_processes], pid_to_process, host_id, collected_at))
    events.extend(_connection_events(connections[:max_connections], pid_to_process, host_id, collected_at))
    if include_dns_cache:
        events.extend(_dns_events(dns_rows[:max_connections], host_id, collected_at))
    events.extend(_download_events(downloads_dir or Path.home() / "Downloads", host_id, collected_at, lookback_hours))

    meta = {
        "source": "local_windows_collector",
        "host_id": host_id,
        "collected_at": collected_at.isoformat(),
        "lookback_hours": lookback_hours,
        "include_dns_cache": include_dns_cache,
        "raw_event_count": len(events),
        "event_sources": {
            "process_snapshot": len(processes[:max_processes]),
            "tcp_connections": len(connections[:max_connections]),
            "dns_cache": len(dns_rows[:max_connections]) if include_dns_cache else 0,
            "recent_downloads": sum(1 for event in events if event["event_type"] == "file_download"),
        },
        "warnings": warnings,
        "privacy_note": "수집기는 payload, HTTP body, message content, keystroke를 수집하지 않습니다.",
    }
    return events, meta


def _safe_collect(
    name: str,
    collector: Callable[[CommandRunner], list[dict[str, Any]]],
    runner: CommandRunner,
    warnings: list[dict[str, str]],
) -> list[dict[str, Any]]:
    try:
        return collector(runner)
    except LocalCollectionError as error:
        warnings.append({"source": name, "code": error.code, "message": str(error)})
        return []


def _collect_process_rows(runner: CommandRunner) -> list[dict[str, Any]]:
    command = (
        "Get-CimInstance Win32_Process | "
        "Select-Object ProcessId,ParentProcessId,Name,ExecutablePath | "
        "ConvertTo-Json -Depth 3"
    )
    return _run_json_command(runner, command, "PROCESS_COLLECTION_FAILED")


def _collect_tcp_rows(runner: CommandRunner) -> list[dict[str, Any]]:
    command = (
        "Get-NetTCPConnection -State Established | "
        "Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,State,OwningProcess,CreationTime | "
        "ConvertTo-Json -Depth 3"
    )
    return _run_json_command(runner, command, "TCP_COLLECTION_FAILED")


def _collect_dns_rows(runner: CommandRunner) -> list[dict[str, Any]]:
    command = (
        "Get-DnsClientCache | "
        "Where-Object { $_.Entry -and ($_.Type -eq 'A' -or $_.Type -eq 'AAAA' -or $_.Type -eq 'CNAME') } | "
        "Select-Object Entry,Data,Type,TimeToLive | "
        "ConvertTo-Json -Depth 3"
    )
    return _run_json_command(runner, command, "DNS_COLLECTION_FAILED")


def _run_json_command(runner: CommandRunner, command: str, code: str) -> list[dict[str, Any]]:
    returncode, stdout, stderr = runner(command)
    if returncode != 0:
        raise LocalCollectionError(code, stderr.strip() or f"PowerShell command failed: {command[:80]}")
    if not stdout.strip():
        return []
    try:
        parsed = json.loads(stdout)
    except json.JSONDecodeError as error:
        raise LocalCollectionError(code, f"PowerShell JSON 파싱 실패: {error}") from error
    return _as_rows(parsed)


def _run_powershell(command: str) -> tuple[int, str, str]:
    completed = subprocess.run(
        ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", command],
        text=True,
        encoding="utf-8",
        errors="replace",
        capture_output=True,
        timeout=20,
    )
    return completed.returncode, completed.stdout, completed.stderr


def _as_rows(payload: Any) -> list[dict[str, Any]]:
    if payload is None:
        return []
    if isinstance(payload, dict):
        return [payload]
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    return []


def _build_pid_map(rows: list[dict[str, Any]]) -> dict[int, dict[str, Any]]:
    pid_map: dict[int, dict[str, Any]] = {}
    for row in rows:
        pid = _to_int(row.get("ProcessId"))
        if pid is not None:
            pid_map[pid] = row
    return pid_map


def _process_events(
    rows: list[dict[str, Any]],
    pid_to_process: dict[int, dict[str, Any]],
    host_id: str,
    collected_at: datetime,
) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    for index, row in enumerate(rows, start=1):
        pid = _to_int(row.get("ProcessId"))
        parent_pid = _to_int(row.get("ParentProcessId"))
        parent = pid_to_process.get(parent_pid or -1, {})
        events.append(
            _base_event(
                event_id=f"local-proc-{pid or index}",
                event_type="process_start",
                host_id=host_id,
                event_time=collected_at,
                received_time=collected_at + timedelta(seconds=1),
                extra={
                    "process_name": row.get("Name") or "unknown",
                    "process_path": _redact_user_path(row.get("ExecutablePath") or ""),
                    "parent_process": parent.get("Name") or "unknown",
                    "signed": "unknown",
                    "collection_mode": "snapshot",
                },
            )
        )
    return events


def _connection_events(
    rows: list[dict[str, Any]],
    pid_to_process: dict[int, dict[str, Any]],
    host_id: str,
    collected_at: datetime,
) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    for index, row in enumerate(rows, start=1):
        pid = _to_int(row.get("OwningProcess"))
        process = pid_to_process.get(pid or -1, {})
        event_time = _parse_windows_time(row.get("CreationTime")) or collected_at
        events.append(
            _base_event(
                event_id=f"local-net-{index:03d}",
                event_type="network_connection",
                host_id=host_id,
                event_time=event_time,
                received_time=collected_at + timedelta(seconds=2),
                extra={
                    "process_name": process.get("Name") or f"pid-{pid or 'unknown'}",
                    "dst_ip": row.get("RemoteAddress") or "",
                    "dst_port": _to_int(row.get("RemotePort")) or 0,
                    "protocol": "tcp",
                    "bytes_out": 0,
                    "bytes_in": 0,
                    "duration_ms": 0,
                    "connection_state": row.get("State") or "Established",
                    "collection_mode": "snapshot",
                },
            )
        )
    return events


def _dns_events(rows: list[dict[str, Any]], host_id: str, collected_at: datetime) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    for index, row in enumerate(rows, start=1):
        events.append(
            _base_event(
                event_id=f"local-dns-{index:03d}",
                event_type="dns_query",
                host_id=host_id,
                event_time=collected_at,
                received_time=collected_at + timedelta(seconds=3),
                extra={
                    "process_name": "dns_cache",
                    "query": str(row.get("Entry") or "").lower(),
                    "answer_ip": row.get("Data") or "",
                    "record_type": row.get("Type") or "",
                    "collection_mode": "cache_snapshot",
                },
            )
        )
    return events


def _download_events(downloads_dir: Path, host_id: str, collected_at: datetime, lookback_hours: int) -> list[dict[str, Any]]:
    if not downloads_dir.exists():
        return []

    cutoff = collected_at - timedelta(hours=max(1, lookback_hours))
    events: list[dict[str, Any]] = []
    suffixes = {".exe", ".dll", ".ps1", ".bat", ".cmd", ".msi", ".zip"}
    for path in sorted(downloads_dir.iterdir(), key=lambda item: item.stat().st_mtime if item.exists() else 0, reverse=True):
        if not path.is_file() or path.suffix.lower() not in suffixes:
            continue
        modified_at = datetime.fromtimestamp(path.stat().st_mtime).astimezone().replace(microsecond=0)
        if modified_at < cutoff:
            continue
        events.append(
            _base_event(
                event_id=f"local-download-{len(events) + 1:03d}",
                event_type="file_download",
                host_id=host_id,
                event_time=modified_at,
                received_time=collected_at + timedelta(seconds=4),
                extra={
                    "process_name": "browser_or_download_client",
                    "parent_process": "unknown",
                    "file_name": path.name,
                    "file_path": _redact_user_path(str(path)),
                    "hash_sha256": _sha256_if_small(path),
                    "source_domain": "",
                    "file_size_bytes": path.stat().st_size,
                    "collection_mode": "recent_downloads_snapshot",
                },
            )
        )
    return events


def _base_event(
    *,
    event_id: str,
    event_type: str,
    host_id: str,
    event_time: datetime,
    received_time: datetime,
    extra: dict[str, Any],
) -> dict[str, Any]:
    return {
        "event_id": event_id,
        "event_time": event_time.isoformat(),
        "received_time": received_time.isoformat(),
        "host_id": host_id,
        "event_type": event_type,
        "source": "local_collector",
        "payload_version": "v1",
        **extra,
    }


def _parse_windows_time(value: Any) -> datetime | None:
    if not value:
        return None
    if isinstance(value, str):
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone().replace(microsecond=0)
        except ValueError:
            return None
    return None


def _to_int(value: Any) -> int | None:
    try:
        if value is None or value == "":
            return None
        return int(value)
    except (TypeError, ValueError):
        return None


def _redact_user_path(value: str) -> str:
    if not value:
        return ""
    home = str(Path.home())
    return value.replace(home, "%USERPROFILE%")


def _sha256_if_small(path: Path) -> str:
    if path.stat().st_size > 50_000_000:
        return ""
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()
