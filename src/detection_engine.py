"""Validate endpoint telemetry and produce alerts, incidents, and risk views."""

from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime
from typing import Any
from urllib.parse import urlparse

from .config import (
    BEACON_INTERVAL_TOLERANCE_SECONDS,
    BEACON_MIN_EVENTS,
    DEFAULT_LIMITATIONS,
    KNOWN_MALICIOUS_DOMAINS,
    KNOWN_MALICIOUS_IPS,
    KNOWN_MALWARE_HASHES,
    LARGE_OUTBOUND_BYTES,
    MITRE_TACTIC_ORDER,
    POC_NAME,
    PROJECT_NAME,
    REQUIRED_EVENT_FIELDS,
    SHELL_PROCESSES,
    SUPPORTED_EVENT_TYPES,
    TRUSTED_ASNS,
)
from .privacy import sanitize_event
from .siem_analyzer import build_siem_analysis, display_host
from .signature_db import load_signature_db


class DetectionError(Exception):
    """Carry a detector failure code plus any safe partial result."""

    def __init__(self, code: str, message: str, partial_result: dict[str, Any] | None = None) -> None:
        """Store a stable error code, human message, and partial output."""

        super().__init__(message)
        self.code = code
        self.partial_result = partial_result or {}


# 규칙 메타데이터는 각 판단 결과가 보고서, MITRE 분포, 대응 계획,
# 대시보드 심각도 라벨에서 안정적인 계약을 갖게 합니다.
RULES = {
    "R001": {
        "name": "known malicious domain access",
        "mitre": ["Initial Access"],
        "base_score": 34,
    },
    "R002": {
        "name": "suspicious executable downloaded from browser",
        "mitre": ["Initial Access"],
        "base_score": 28,
    },
    "R003": {
        "name": "unsigned executable started from Downloads",
        "mitre": ["Execution"],
        "base_score": 30,
    },
    "R004": {
        "name": "periodic external connection",
        "mitre": ["Command and Control"],
        "base_score": 36,
    },
    "R005": {
        "name": "large outbound transfer",
        "mitre": ["Exfiltration"],
        "base_score": 35,
    },
    "R006": {
        "name": "rare ASN connection outside work hours",
        "mitre": ["Command and Control"],
        "base_score": 22,
    },
    "R007": {
        "name": "shell process creates network connection",
        "mitre": ["Execution", "Command and Control"],
        "base_score": 26,
    },
    "R008": {
        "name": "VPN tunnel plus abnormal transfer",
        "mitre": ["Exfiltration"],
        "base_score": 32,
    },
    "R009": {
        "name": "decrypted L7 malicious URL access",
        "mitre": ["Initial Access", "Command and Control"],
        "base_score": 38,
    },
    "R010": {
        "name": "risky application action with malicious URL",
        "mitre": ["Collection", "Exfiltration"],
        "base_score": 34,
    },
    "R011": {
        "name": "known malware hash signature match",
        "mitre": ["Execution", "Defense Evasion"],
        "base_score": 42,
    },
    "R012": {
        "name": "response action generated for high-risk detection",
        "mitre": ["Impact"],
        "base_score": 20,
    },
    "R013": {
        "name": "AI predicted high-risk host trajectory",
        "mitre": ["Command and Control", "Exfiltration"],
        "base_score": 33,
    },
}


def analyze_events(raw_events: list[dict[str, Any]], input_meta: dict[str, Any] | None = None) -> dict[str, Any]:
    """Return the full detection result for raw endpoint event dictionaries."""

    input_meta = input_meta or {}
    signature_db = load_signature_db()
    valid_events, dlq_events, privacy_actions = _validate_and_sanitize(raw_events)

    if not valid_events:
        raise DetectionError(
            "NO_VALID_EVENTS",
            "분석 가능한 valid event가 없습니다.",
            {"dlq_events": dlq_events[:10], "input": input_meta},
        )

    valid_events = sorted(valid_events, key=lambda item: (_parse_time(item["event_time"]), item["event_id"]))
    alerts = _detect_alerts(valid_events, signature_db)
    incidents = _build_incidents(valid_events, alerts)
    endpoint_risk = _build_endpoint_risk(valid_events, alerts, incidents)
    mitre_distribution = _build_mitre_distribution(alerts, incidents)
    siem_analysis = build_siem_analysis(valid_events, alerts, incidents, endpoint_risk)

    # 이 페이로드는 보고서, 대시보드, 검증이 소비하는 제품 계약입니다.
    # 해당 소비자를 함께 갱신하지 않는 한 새 필드는 추가형으로 유지합니다.
    result = {
        "status": "success",
        "poc_name": POC_NAME,
        "project": PROJECT_NAME,
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "input": input_meta,
        "summary": {
            "input_event_count": len(raw_events),
            "valid_event_count": len(valid_events),
            "dlq_event_count": len(dlq_events),
            "privacy_mask_action_count": len(privacy_actions),
            "alert_count": len(alerts),
            "incident_count": len(incidents),
            "critical_endpoint_count": sum(1 for item in endpoint_risk if item["severity"] == "critical"),
            "highest_risk_score": max((item["risk_score"] for item in endpoint_risk), default=0),
            "flow_event_count": sum(1 for item in valid_events if item["event_type"] == "flow_summary"),
            "l7_event_count": sum(1 for item in valid_events if item["event_type"] in {"http_request", "application_action"}),
            "decryption_event_count": sum(1 for item in valid_events if item["event_type"] == "decryption_event"),
        },
        "signature_db": {"version": signature_db["version"]},
        "edr_state": _edr_state(endpoint_risk),
        "telemetry_metadata": siem_analysis["telemetry_metadata"],
        "rules_run": [{"rule_id": rule_id, **meta} for rule_id, meta in RULES.items()],
        "events": [_event_summary(event) for event in valid_events],
        "alerts": alerts,
        "incidents": incidents,
        "endpoint_risk": endpoint_risk,
        "siem_analysis": siem_analysis,
        "mitre_distribution": mitre_distribution,
        "top_suspicious_domains": _top_suspicious_domains(valid_events, alerts),
        "top_suspicious_ips": _top_suspicious_ips(valid_events, alerts),
        "process_trees": _build_process_trees(valid_events),
        "dlq_events": dlq_events,
        "privacy_actions": privacy_actions,
        "decision": _decision(endpoint_risk, incidents, dlq_events),
        "limitations": DEFAULT_LIMITATIONS,
    }
    return result


def build_failure_result(
    code: str,
    message: str,
    error_type: str,
    input_meta: dict[str, Any] | None = None,
    partial_result: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Return the standard failed-result payload used by callers and UI."""

    return {
        "status": "failed",
        "poc_name": POC_NAME,
        "project": PROJECT_NAME,
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "input": input_meta or {},
        "error": {
            "code": code,
            "type": error_type,
            "message": message,
        },
        "partial_result": partial_result or {},
        "limitations": DEFAULT_LIMITATIONS,
    }


def _validate_and_sanitize(raw_events: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    """Split raw input into valid events, DLQ records, and privacy actions."""

    valid_events: list[dict[str, Any]] = []
    dlq_events: list[dict[str, Any]] = []
    privacy_actions: list[dict[str, Any]] = []
    seen_event_ids: set[str] = set()

    for index, event in enumerate(raw_events):
        sanitized, masks = sanitize_event(event)
        if masks:
            privacy_actions.append(
                {
                    "event_id": sanitized.get("event_id", f"index-{index}"),
                    "masked_fields": [item["field"] for item in masks],
                    "actions": [item["action"] for item in masks],
                }
            )

        errors = _schema_errors(sanitized, seen_event_ids)
        if errors:
            dlq_events.append(
                {
                    "index": index,
                    "event_id": sanitized.get("event_id"),
                    "code": "INVALID_EVENT_SCHEMA",
                    "errors": errors,
                    "sanitized_event": sanitized,
                }
            )
            continue

        seen_event_ids.add(sanitized["event_id"])
        valid_events.append(sanitized)

    return valid_events, dlq_events, privacy_actions


def _schema_errors(event: dict[str, Any], seen_event_ids: set[str]) -> list[str]:
    """Return schema and duplicate-ID errors for one sanitized event."""

    errors: list[str] = []
    missing = sorted(REQUIRED_EVENT_FIELDS - set(event))
    if missing:
        errors.append(f"missing required fields: {missing}")

    event_id = event.get("event_id")
    if event_id in seen_event_ids:
        errors.append(f"duplicate event_id: {event_id}")

    event_type = event.get("event_type")
    if event_type and event_type not in SUPPORTED_EVENT_TYPES:
        errors.append(f"unsupported event_type: {event_type}")

    for field in ("event_time", "received_time"):
        if field in event:
            try:
                _parse_time(str(event[field]))
            except ValueError:
                errors.append(f"invalid datetime field: {field}")

    return errors


def _detect_alerts(events: list[dict[str, Any]], signature_db: dict[str, Any]) -> list[dict[str, Any]]:
    """Run all rule helpers and return normalized alert dictionaries."""

    alerts: list[dict[str, Any]] = []

    # 이벤트 타입 조건은 출처별 규칙을 읽기 쉽게 유지하면서도
    # 하나의 이벤트가 여러 독립 보안 판단 결과를 만들 수 있게 합니다.
    for event in events:
        event_type = event["event_type"]
        if event_type in {"dns_query", "network_connection", "file_download", "http_request", "application_action", "decryption_event"}:
            _maybe_add_domain_alert(alerts, event, signature_db)
        if event_type == "file_download":
            _maybe_add_download_alert(alerts, event, signature_db)
            _maybe_add_hash_signature_alert(alerts, event, signature_db)
        if event_type == "process_start":
            _maybe_add_unsigned_execution_alert(alerts, event, signature_db)
            _maybe_add_hash_signature_alert(alerts, event, signature_db)
        if event_type in {"network_connection", "flow_summary"}:
            _maybe_add_large_outbound_alert(alerts, event)
            _maybe_add_rare_asn_alert(alerts, event)
            _maybe_add_shell_network_alert(alerts, event)
            _maybe_add_vpn_abnormal_alert(alerts, event)
        if event_type == "http_request":
            _maybe_add_l7_url_alert(alerts, event, signature_db)
        if event_type == "application_action":
            _maybe_add_application_action_alert(alerts, event, signature_db)
            _maybe_add_hash_signature_alert(alerts, event, signature_db)
        if event_type == "response_action":
            _maybe_add_response_action_alert(alerts, event)
        if event_type == "ai_prediction":
            _maybe_add_ai_prediction_alert(alerts, event)

    alerts.extend(_detect_beaconing(events))

    for index, alert in enumerate(alerts, start=1):
        alert["alert_id"] = f"alert-{index:03d}"
        alert["severity"] = _severity(alert["risk_score"])

    return alerts


def _maybe_add_domain_alert(alerts: list[dict[str, Any]], event: dict[str, Any], signature_db: dict[str, Any]) -> None:
    """Append R001 when an event destination matches malicious indicators."""

    domain = _event_domain(event)
    ip = str(event.get("dst_ip") or event.get("destination_ip") or "")
    if domain in signature_db["malicious_domains"] or ip in signature_db["malicious_ips"]:
        alerts.append(
            _alert(
                "R001",
                event["host_id"],
                [event["event_id"]],
                f"Known malicious destination observed: {domain or ip}",
                [f"destination matched signature set: {domain or ip}", f"source event type: {event['event_type']}"],
                event,
            )
        )


def _maybe_add_download_alert(alerts: list[dict[str, Any]], event: dict[str, Any], signature_db: dict[str, Any]) -> None:
    """Append R002 for executable downloads with suspicious provenance."""

    file_name = str(event.get("file_name") or event.get("file_path") or "").lower()
    source_domain = str(event.get("source_domain") or "")
    hash_value = str(event.get("hash_sha256") or "")
    browser_parent = str(event.get("parent_process") or event.get("process_name") or "").lower() in {"chrome.exe", "msedge.exe", "firefox.exe", "safari"}

    if file_name.endswith((".exe", ".dll", ".ps1", ".bat")) and (
        browser_parent or source_domain.lower() in signature_db["malicious_domains"] or hash_value.lower() in signature_db["malware_hashes"]
    ):
        alerts.append(
            _alert(
                "R002",
                event["host_id"],
                [event["event_id"]],
                f"Executable download needs review: {event.get('file_name', file_name)}",
                [
                    "downloaded file has executable extension",
                    f"source_domain={source_domain or 'unknown'}",
                    "browser initiated the download" if browser_parent else "signature context raised suspicion",
                ],
                event,
            )
        )


def _maybe_add_unsigned_execution_alert(alerts: list[dict[str, Any]], event: dict[str, Any], signature_db: dict[str, Any]) -> None:
    """Append R003 for unsigned execution from Downloads or malware hashes."""

    path = str(event.get("process_path") or "").lower()
    hash_value = str(event.get("hash_sha256") or "")
    signed = event.get("signed")
    if signed is False and ("\\downloads\\" in path or "/downloads/" in path or hash_value.lower() in signature_db["malware_hashes"]):
        alerts.append(
            _alert(
                "R003",
                event["host_id"],
                [event["event_id"]],
                f"Unsigned executable started: {event.get('process_name', 'unknown process')}",
                [
                    "process is unsigned",
                    "process path is under Downloads" if "downloads" in path else "hash matched suspicious set",
                    f"parent_process={event.get('parent_process', 'unknown')}",
                ],
                event,
            )
        )


def _maybe_add_large_outbound_alert(alerts: list[dict[str, Any]], event: dict[str, Any]) -> None:
    """Append R005 when outbound bytes exceed the configured threshold."""

    bytes_out = int(event.get("bytes_out") or event.get("byte_count_out") or 0)
    if bytes_out >= LARGE_OUTBOUND_BYTES:
        alerts.append(
            _alert(
                "R005",
                event["host_id"],
                [event["event_id"]],
                f"Large outbound transfer: {bytes_out:,} bytes",
                [
                    f"bytes_out={bytes_out}",
                    f"process_name={event.get('process_name', 'unknown')}",
                    f"destination={_event_domain(event) or event.get('dst_ip', 'unknown')}",
                ],
                event,
            )
        )


def _maybe_add_rare_asn_alert(alerts: list[dict[str, Any]], event: dict[str, Any]) -> None:
    """Append R006 for off-hours traffic to untrusted ASNs."""

    asn = str(event.get("destination_asn") or "")
    if asn and asn not in TRUSTED_ASNS and _is_off_hours(event["event_time"]):
        alerts.append(
            _alert(
                "R006",
                event["host_id"],
                [event["event_id"]],
                f"Rare ASN connection outside work hours: {asn}",
                [
                    f"destination_asn={asn}",
                    "event_time is outside 07:00-20:00",
                    f"destination={_event_domain(event) or event.get('dst_ip', 'unknown')}",
                ],
                event,
            )
        )


def _maybe_add_shell_network_alert(alerts: list[dict[str, Any]], event: dict[str, Any]) -> None:
    """Append R007 when a shell process opens outbound network activity."""

    process_name = str(event.get("process_name") or "").lower()
    if process_name in SHELL_PROCESSES:
        alerts.append(
            _alert(
                "R007",
                event["host_id"],
                [event["event_id"]],
                f"Shell process made outbound connection: {process_name}",
                [
                    f"process_name={process_name}",
                    f"destination={_event_domain(event) or event.get('dst_ip', 'unknown')}",
                    "shell network activity often needs analyst review",
                ],
                event,
            )
        )


def _maybe_add_vpn_abnormal_alert(alerts: list[dict[str, Any]], event: dict[str, Any]) -> None:
    """Append R008 for VPN traffic combined with transfer or ASN risk."""

    bytes_out = int(event.get("bytes_out") or 0)
    rare_asn = str(event.get("destination_asn") or "") not in TRUSTED_ASNS
    if event.get("vpn_active") is True and (bytes_out >= LARGE_OUTBOUND_BYTES or rare_asn):
        alerts.append(
            _alert(
                "R008",
                event["host_id"],
                [event["event_id"]],
                "VPN session with abnormal external transfer",
                [
                    "vpn_active=true",
                    f"bytes_out={bytes_out}",
                    f"destination_asn={event.get('destination_asn', 'unknown')}",
                ],
                event,
            )
        )


def _maybe_add_l7_url_alert(alerts: list[dict[str, Any]], event: dict[str, Any], signature_db: dict[str, Any]) -> None:
    """Append R009 for decrypted HTTP requests matching URL policy."""

    url = str(event.get("url") or event.get("object_url") or "").lower()
    domain = _event_domain(event)
    category = str(event.get("url_category") or "").lower()
    if url in signature_db["malicious_urls"] or domain in signature_db["malicious_domains"] or category in signature_db["blocked_categories"]:
        alerts.append(
            _alert(
                "R009",
                event["host_id"],
                [event["event_id"]],
                f"Decrypted L7 request matched policy: {url or domain}",
                [
                    f"url={url or 'unknown'}",
                    f"domain={domain or 'unknown'}",
                    f"url_category={category or 'unknown'}",
                    f"decrypted={event.get('decrypted', False)}",
                ],
                event,
            )
        )


def _maybe_add_application_action_alert(alerts: list[dict[str, Any]], event: dict[str, Any], signature_db: dict[str, Any]) -> None:
    """Append R010 for risky app actions tied to malicious destinations."""

    app_name = str(event.get("app_name") or event.get("app_id") or "").lower()
    action = str(event.get("app_action") or "").lower()
    domain = _event_domain(event)
    url = str(event.get("object_url") or event.get("url") or "").lower()
    monitored = any(
        str(item.get("app", "")).lower() == app_name and str(item.get("action", "")).lower() == action
        for item in signature_db["monitored_app_actions"]
    )
    if monitored and (domain in signature_db["malicious_domains"] or url in signature_db["malicious_urls"]):
        alerts.append(
            _alert(
                "R010",
                event["host_id"],
                [event["event_id"]],
                f"Risky application action observed: {event.get('app_name', app_name)} {event.get('app_action', action)}",
                [
                    f"app={event.get('app_name', app_name)}",
                    f"action={event.get('app_action', action)}",
                    f"object_url={url or 'unknown'}",
                    "message body was not retained",
                ],
                event,
            )
        )


def _maybe_add_hash_signature_alert(alerts: list[dict[str, Any]], event: dict[str, Any], signature_db: dict[str, Any]) -> None:
    """Append R011 when file or attachment hashes hit malware signatures."""

    hash_value = str(event.get("hash_sha256") or event.get("attachment_hash") or "").lower()
    if not hash_value or hash_value not in signature_db["malware_hashes"]:
        return
    alerts.append(
        _alert(
            "R011",
            event["host_id"],
            [event["event_id"]],
            f"Known malware hash observed: {hash_value[:12]}...",
            [
                f"hash_sha256={hash_value}",
                f"event_type={event['event_type']}",
                f"process_name={event.get('process_name', 'unknown')}",
            ],
            event,
        )
    )


def _maybe_add_response_action_alert(alerts: list[dict[str, Any]], event: dict[str, Any]) -> None:
    """Append R012 for planned, queued, or applied response-action events."""

    if str(event.get("status") or "") not in {"planned", "queued", "applied"}:
        return
    alerts.append(
        _alert(
            "R012",
            event["host_id"],
            [event["event_id"]],
            f"Response action generated: {event.get('action_type', 'unknown')}",
            [
                f"status={event.get('status', 'unknown')}",
                f"mode={event.get('mode', 'unknown')}",
                f"rule_id={event.get('rule_id', 'unknown')}",
            ],
            event,
        )
    )


def _maybe_add_ai_prediction_alert(alerts: list[dict[str, Any]], event: dict[str, Any]) -> None:
    """Append R013 when model telemetry predicts high or critical risk."""

    if str(event.get("prediction") or "") not in {"high", "critical"}:
        return
    alerts.append(
        _alert(
            "R013",
            event["host_id"],
            [event["event_id"]],
            f"AI model predicted {event.get('prediction')} risk trajectory",
            [
                f"score={event.get('score', 'unknown')}",
                f"confidence={event.get('confidence', 'unknown')}",
                f"horizon={event.get('horizon', 'unknown')}",
            ],
            event,
        )
    )


def _detect_beaconing(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Detect repeated host/process/destination intervals as C2 beaconing."""

    groups: dict[tuple[str, str, str], list[dict[str, Any]]] = defaultdict(list)
    for event in events:
        if event["event_type"] != "network_connection":
            continue
        destination = _event_domain(event) or str(event.get("dst_ip") or "")
        if not destination:
            continue
        groups[(event["host_id"], str(event.get("process_name") or "unknown"), destination)].append(event)

    alerts: list[dict[str, Any]] = []
    for (host_id, process_name, destination), grouped_events in groups.items():
        if len(grouped_events) < BEACON_MIN_EVENTS:
            continue
        grouped_events = sorted(grouped_events, key=lambda item: _parse_time(item["event_time"]))
        intervals = [
            int((_parse_time(grouped_events[index]["event_time"]) - _parse_time(grouped_events[index - 1]["event_time"])).total_seconds())
            for index in range(1, len(grouped_events))
        ]
        if not intervals:
            continue
        # 비컨 탐지는 개수뿐 아니라 규칙성을 사용합니다.
        # 허용 오차 안의 반복 간격은 일반적인 순간 집중 연결의 오탐을 줄입니다.
        most_common_interval, count = Counter(intervals).most_common(1)[0]
        regular = sum(1 for interval in intervals if abs(interval - most_common_interval) <= BEACON_INTERVAL_TOLERANCE_SECONDS)
        if count >= 2 and regular >= BEACON_MIN_EVENTS - 1 and most_common_interval <= 120:
            first_event = grouped_events[0]
            alerts.append(
                _alert(
                    "R004",
                    host_id,
                    [item["event_id"] for item in grouped_events],
                    f"Periodic outbound connection every ~{most_common_interval}s",
                    [
                        f"process_name={process_name}",
                        f"destination={destination}",
                        f"regular_interval_count={regular}",
                    ],
                    first_event,
                    extra={"interval_seconds": most_common_interval, "event_count": len(grouped_events)},
                )
            )
    return alerts


def _build_incidents(events: list[dict[str, Any]], alerts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Correlate alert chains into host-level attack sequence incidents."""

    events_by_host: dict[str, list[dict[str, Any]]] = defaultdict(list)
    alerts_by_host: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for event in events:
        events_by_host[event["host_id"]].append(event)
    for alert in alerts:
        alerts_by_host[alert["host_id"]].append(alert)

    incidents: list[dict[str, Any]] = []
    for host_id, host_events in events_by_host.items():
        host_events = sorted(host_events, key=lambda item: _parse_time(item["event_time"]))
        downloads = [event for event in host_events if event["event_type"] == "file_download"]
        for download in downloads:
            execution = _find_related_execution(download, host_events)
            beacon_alert = _find_alert(alerts_by_host[host_id], "R004")
            outbound_alert = _find_alert(alerts_by_host[host_id], "R005")
            if not (execution and beacon_alert and outbound_alert):
                continue

            incident_alerts = [
                alert
                for alert in alerts_by_host[host_id]
                if alert["rule_id"] in {"R001", "R002", "R003", "R004", "R005", "R006", "R008"}
            ]
            risk_score = min(100, 52 + sum(alert["risk_score"] for alert in incident_alerts) // 4)
            incidents.append(
                {
                    "incident_id": f"incident-{len(incidents) + 1:03d}",
                    "host_id": host_id,
                    "host_display_name": display_host(host_id),
                    "risk_score": risk_score,
                    "severity": _severity(risk_score),
                    "primary_category": "suspicious_download_to_c2_sequence",
                    "detected_sequence": [
                        {
                            "stage": "unknown_file_download",
                            "event_id": download["event_id"],
                            "summary": f"{download.get('file_name', 'file')} downloaded from {download.get('source_domain', 'unknown domain')}",
                        },
                        {
                            "stage": "unsigned_process_execution",
                            "event_id": execution["event_id"],
                            "summary": f"{execution.get('process_name', 'process')} started by {execution.get('parent_process', 'unknown parent')}",
                        },
                        {
                            "stage": "periodic_external_connection",
                            "event_ids": beacon_alert["event_ids"],
                            "summary": beacon_alert["title"],
                        },
                        {
                            "stage": "large_outbound_transfer",
                            "event_ids": outbound_alert["event_ids"],
                            "summary": outbound_alert["title"],
                        },
                    ],
                    "mitre_mapping": [
                        {
                            "tactic": "Initial Access",
                            "reason": "unknown executable was downloaded from a rare or malicious domain",
                        },
                        {
                            "tactic": "Execution",
                            "reason": "downloaded unsigned executable was started from Downloads",
                        },
                        {
                            "tactic": "Command and Control",
                            "reason": "process made repeated outbound connections at a regular interval",
                        },
                        {
                            "tactic": "Exfiltration",
                            "reason": "large outbound transfer followed the suspicious process activity",
                        },
                    ],
                    "evidence": [
                        "downloaded file was not trusted",
                        "parent process was browser",
                        "destination matched suspicious domain or IP evidence",
                        "connection interval was regular",
                        "large outbound transfer occurred after execution",
                    ],
                    "decision": "needs_security_review",
                }
            )
            break

    return incidents


def _find_related_execution(download: dict[str, Any], events: list[dict[str, Any]]) -> dict[str, Any] | None:
    """Find a process start that follows a download by hash or path."""

    download_time = _parse_time(download["event_time"])
    hash_value = download.get("hash_sha256")
    file_path = str(download.get("file_path") or "").lower()
    for event in events:
        if event["event_type"] != "process_start":
            continue
        delta = (_parse_time(event["event_time"]) - download_time).total_seconds()
        if delta < 0 or delta > 900:
            continue
        same_hash = hash_value and event.get("hash_sha256") == hash_value
        same_path = file_path and str(event.get("process_path") or "").lower() == file_path
        if same_hash or same_path:
            return event
    return None


def _find_alert(alerts: list[dict[str, Any]], rule_id: str) -> dict[str, Any] | None:
    """Return the first alert for a rule ID, if present."""

    return next((alert for alert in alerts if alert["rule_id"] == rule_id), None)


def _build_endpoint_risk(
    events: list[dict[str, Any]],
    alerts: list[dict[str, Any]],
    incidents: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Return per-host risk rows sorted by highest risk first."""

    hosts = sorted({event["host_id"] for event in events})
    incident_bonus = {incident["host_id"]: incident["risk_score"] for incident in incidents}
    rows: list[dict[str, Any]] = []

    for host_id in hosts:
        host_alerts = [alert for alert in alerts if alert["host_id"] == host_id]
        base_score = min(100, sum(alert["risk_score"] for alert in host_alerts))
        risk_score = max(base_score, incident_bonus.get(host_id, 0))
        rows.append(
            {
                "host_id": host_id,
                "host_display_name": display_host(host_id),
                "risk_score": risk_score,
                "severity": _severity(risk_score),
                "alert_count": len(host_alerts),
                "incident_count": sum(1 for incident in incidents if incident["host_id"] == host_id),
                "top_rules": [rule_id for rule_id, _ in Counter(alert["rule_id"] for alert in host_alerts).most_common(4)],
                "last_event_time": max(event["event_time"] for event in events if event["host_id"] == host_id),
            }
        )

    return sorted(rows, key=lambda item: (-item["risk_score"], item["host_id"]))


def _edr_state(endpoint_risk: list[dict[str, Any]]) -> dict[str, Any]:
    """Return fleet-level EDR state from the highest endpoint risk score."""

    highest = max((int(row.get("risk_score", 0) or 0) for row in endpoint_risk), default=0)
    if highest >= 80:
        state = "RED"
    elif highest >= 50:
        state = "YELLOW"
    else:
        state = "GREEN"
    return {
        "state": state,
        "highest_risk_score": highest,
        "meaning": {
            "RED": "High-confidence endpoint risk requires analyst review.",
            "YELLOW": "Suspicious endpoint activity is present.",
            "GREEN": "No active high-risk endpoint signal was observed.",
        }[state],
    }


def _build_mitre_distribution(alerts: list[dict[str, Any]], incidents: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Count MITRE tactics represented by alerts and incidents."""

    counts: Counter[str] = Counter()
    for alert in alerts:
        for tactic in alert["mitre_mapping"]:
            counts[tactic] += 1
    for incident in incidents:
        for mapping in incident["mitre_mapping"]:
            counts[mapping["tactic"]] += 1
    return [{"tactic": tactic, "count": counts[tactic]} for tactic in MITRE_TACTIC_ORDER if counts[tactic] > 0]


def _top_suspicious_domains(events: list[dict[str, Any]], alerts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Return top domains from events that contributed to alerts."""

    alerted_event_ids = {event_id for alert in alerts for event_id in alert["event_ids"]}
    counter: Counter[str] = Counter()
    for event in events:
        if event["event_id"] in alerted_event_ids:
            domain = _event_domain(event)
            if domain:
                counter[domain] += 1
    return [{"domain": domain, "count": count} for domain, count in counter.most_common(8)]


def _top_suspicious_ips(events: list[dict[str, Any]], alerts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Return top destination IPs from events that contributed to alerts."""

    alerted_event_ids = {event_id for alert in alerts for event_id in alert["event_ids"]}
    counter: Counter[str] = Counter()
    for event in events:
        if event["event_id"] in alerted_event_ids:
            ip = str(event.get("dst_ip") or event.get("destination_ip") or "")
            if ip:
                counter[ip] += 1
    return [{"ip": ip, "count": count} for ip, count in counter.most_common(8)]


def _build_process_trees(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Return process-start rows for endpoint process-tree inspection."""

    rows: list[dict[str, Any]] = []
    for event in events:
        if event["event_type"] != "process_start":
            continue
        rows.append(
            {
                "host_id": event["host_id"],
                "parent_process": event.get("parent_process", "unknown"),
                "process_name": event.get("process_name", "unknown"),
                "process_path": event.get("process_path", "unknown"),
                "signed": event.get("signed", "unknown"),
                "event_id": event["event_id"],
                "event_time": event["event_time"],
            }
        )
    return rows


def _event_summary(event: dict[str, Any]) -> dict[str, Any]:
    """Return a compact event row for report and dashboard tables."""

    summary = {
        "event_id": event["event_id"],
        "event_time": event["event_time"],
        "host_id": event["host_id"],
        "host_display_name": display_host(event["host_id"]),
        "event_type": event["event_type"],
        "process_name": event.get("process_name"),
        "domain": _event_domain(event),
        "dst_ip": event.get("dst_ip") or event.get("destination_ip"),
        "dst_port": event.get("dst_port"),
        "bytes_out": event.get("bytes_out"),
        "method": event.get("method"),
        "url": event.get("url") or event.get("object_url"),
        "app_name": event.get("app_name") or event.get("app_id"),
        "app_action": event.get("app_action"),
        "decrypted": event.get("decrypted"),
        "collection_mode": event.get("collection_mode"),
    }
    if "privacy_masked_fields" in event:
        summary["privacy_masked_fields"] = event["privacy_masked_fields"]
    return {key: value for key, value in summary.items() if value is not None}


def _alert(
    rule_id: str,
    host_id: str,
    event_ids: list[str],
    title: str,
    evidence: list[str],
    event: dict[str, Any],
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build the shared alert payload from rule metadata and evidence."""

    rule = RULES[rule_id]
    payload = {
        "rule_id": rule_id,
        "rule_name": rule["name"],
        "host_id": host_id,
        "host_display_name": display_host(host_id),
        "event_ids": event_ids,
        "event_time": event["event_time"],
        "title": title,
        "risk_score": rule["base_score"],
        "mitre_mapping": rule["mitre"],
        "evidence": evidence,
        "decision": "needs_security_review" if rule["base_score"] >= 30 else "needs_review",
    }
    if extra:
        payload.update(extra)
    return payload


def _event_domain(event: dict[str, Any]) -> str:
    """Extract a lowercase domain from direct fields or URL hostnames."""

    direct = str(event.get("query") or event.get("dst_domain") or event.get("source_domain") or event.get("sni") or "").lower()
    if direct:
        return direct
    url = str(event.get("url") or event.get("object_url") or "")
    if url:
        return str(urlparse(url).hostname or "").lower()
    return ""


def _parse_time(value: str) -> datetime:
    """Parse ISO timestamps, accepting a trailing Z as UTC."""

    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _is_off_hours(value: str) -> bool:
    """Return whether an event timestamp is outside 07:00-20:00."""

    hour = _parse_time(value).hour
    return hour < 7 or hour >= 20


def _severity(score: int) -> str:
    """Map detector risk scores to alert and endpoint severity labels."""

    if score >= 80:
        return "critical"
    if score >= 60:
        return "warning"
    if score >= 30:
        return "suspicious"
    return "info"


def _decision(endpoint_risk: list[dict[str, Any]], incidents: list[dict[str, Any]], dlq_events: list[dict[str, Any]]) -> str:
    """Return the top-level review decision for the detection result."""

    if any(item["severity"] == "critical" for item in endpoint_risk) or incidents:
        return "needs_security_review"
    if dlq_events:
        return "needs_schema_review"
    return "no_high_risk_signal_in_sample"
