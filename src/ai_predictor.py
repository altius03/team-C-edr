from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime
from typing import Any


HIGH_VALUE_RULES = {"R004", "R005", "R008", "R009", "R010", "R011"}


def build_ai_predictions(result: dict[str, Any]) -> dict[str, Any]:
    alerts_by_host: dict[str, list[dict[str, Any]]] = defaultdict(list)
    incidents_by_host: Counter[str] = Counter()
    for alert in result.get("alerts", []):
        alerts_by_host[str(alert.get("host_id", "unknown"))].append(alert)
    for incident in result.get("incidents", []):
        incidents_by_host[str(incident.get("host_id", "unknown"))] += 1

    predictions: list[dict[str, Any]] = []
    for host_id, alerts in sorted(alerts_by_host.items()):
        rules = {str(alert.get("rule_id")) for alert in alerts}
        score = min(
            100,
            12
            + len(alerts) * 7
            + len(rules & HIGH_VALUE_RULES) * 13
            + incidents_by_host[host_id] * 18
            + _chain_bonus(rules),
        )
        prediction = {
            "prediction_id": f"prediction-{len(predictions) + 1:03d}",
            "host_id": host_id,
            "model": "poc_feature_risk_model_v1",
            "prediction": _label(score),
            "score": score,
            "confidence": min(0.95, round(0.45 + (len(alerts) * 0.04) + (len(rules) * 0.03), 2)),
            "horizon": "next_24h",
            "features": {
                "alert_count": len(alerts),
                "incident_count": incidents_by_host[host_id],
                "rules": sorted(rules),
                "has_c2_and_exfil": {"R004", "R005"}.issubset(rules),
                "has_l7_malicious_url": bool({"R009", "R010"} & rules),
            },
            "reason": _reason(rules),
            "created_at": datetime.now().isoformat(timespec="seconds"),
        }
        predictions.append(prediction)

    return {
        "model": "poc_feature_risk_model_v1",
        "prediction_count": len(predictions),
        "high_or_critical_count": sum(1 for item in predictions if item["prediction"] in {"high", "critical"}),
        "predictions": sorted(predictions, key=lambda item: (-item["score"], item["host_id"])),
        "note": "This is a deterministic PoC risk model, not a trained production ML model.",
    }


def _chain_bonus(rules: set[str]) -> int:
    bonus = 0
    if {"R001", "R002", "R003", "R004"}.issubset(rules):
        bonus += 16
    if {"R004", "R005"}.issubset(rules):
        bonus += 14
    if {"R009", "R011"}.issubset(rules):
        bonus += 10
    return bonus


def _label(score: int) -> str:
    if score >= 85:
        return "critical"
    if score >= 65:
        return "high"
    if score >= 40:
        return "medium"
    return "low"


def _reason(rules: set[str]) -> str:
    if {"R004", "R005"}.issubset(rules):
        return "Beaconing and outbound transfer appeared together."
    if {"R009", "R010"} & rules:
        return "L7 inspection observed malicious URL or risky application action."
    if "R011" in rules:
        return "Known malware hash appeared in endpoint telemetry."
    return "Multiple weak signals were combined into a host-level risk estimate."
