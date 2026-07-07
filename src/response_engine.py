"""Map detection alerts to response actions without executing actuators."""

from __future__ import annotations

from collections import Counter
from datetime import datetime
from typing import Any


# Rule-to-action mapping stays descriptive because this PoC must not mutate
# firewall, endpoint, or identity state without an approved integration.
ACTION_BY_RULE = {
    "R001": ("block_destination", "Block known malicious domain/IP at DNS or proxy policy."),
    "R002": ("quarantine_download", "Quarantine executable downloaded from suspicious source."),
    "R003": ("kill_and_quarantine_process", "Stop unsigned executable and quarantine file."),
    "R004": ("contain_host_for_c2_review", "Open C2 beaconing review and consider host containment."),
    "R005": ("rate_limit_or_block_transfer", "Review and block abnormal outbound transfer."),
    "R006": ("review_rare_asn", "Review off-hours rare ASN connection."),
    "R007": ("review_shell_network", "Inspect shell process command line and destination."),
    "R008": ("review_vpn_exfiltration", "Review VPN transfer and destination ASN."),
    "R009": ("block_url", "Block malicious or phishing URL at proxy."),
    "R010": ("block_app_url_and_notify", "Block application-level URL and notify analyst."),
    "R011": ("quarantine_hash", "Quarantine known malware hash."),
    "R012": ("confirm_response_applied", "Confirm response action applied successfully."),
    "R013": ("escalate_predicted_risk", "Escalate AI-predicted high risk host for triage."),
}


def build_response_plan(result: dict[str, Any], *, mode: str = "dry-run") -> dict[str, Any]:
    """Return planned or queued response actions for each alert in a result."""

    actions: list[dict[str, Any]] = []
    for alert in result.get("alerts", []):
        action_type, description = ACTION_BY_RULE.get(
            alert.get("rule_id", ""),
            ("open_triage_ticket", "Open analyst triage ticket."),
        )
        actions.append(
            {
                "action_id": f"response-{len(actions) + 1:03d}",
                "mode": mode,
                "status": "planned" if mode == "dry-run" else "queued",
                "host_id": alert.get("host_id"),
                "rule_id": alert.get("rule_id"),
                "alert_id": alert.get("alert_id"),
                "action_type": action_type,
                "description": description,
                "created_at": datetime.now().isoformat(timespec="seconds"),
                "evidence": alert.get("evidence", [])[:3],
            }
        )

    counts = Counter(item["action_type"] for item in actions)
    return {
        "mode": mode,
        "action_count": len(actions),
        "by_action_type": [{"action_type": key, "count": value} for key, value in counts.most_common()],
        "actions": actions,
        "note": "PoC response engine does not change firewall/process state unless integrated with an approved actuator.",
    }
