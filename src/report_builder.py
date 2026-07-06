from __future__ import annotations

import html
from datetime import datetime
from pathlib import Path
from typing import Any

from .siem_analyzer import display_host


def write_report_artifacts(payload: dict[str, Any], latest_dir: Path, run_dir: Path) -> dict[str, Path]:
    latest_dir.mkdir(parents=True, exist_ok=True)
    run_dir.mkdir(parents=True, exist_ok=True)

    markdown = build_markdown_report(payload)
    html_report = build_html_report(payload, markdown)

    latest_markdown = latest_dir / "security_report.md"
    latest_html = latest_dir / "security_report.html"
    run_markdown = run_dir / "security_report.md"
    run_html = run_dir / "security_report.html"

    for path in (latest_markdown, run_markdown):
        path.write_text(markdown, encoding="utf-8")
    for path in (latest_html, run_html):
        path.write_text(html_report, encoding="utf-8")

    return {
        "latest_markdown_path": latest_markdown,
        "latest_html_path": latest_html,
        "run_markdown_path": run_markdown,
        "run_html_path": run_html,
    }


def build_markdown_report(payload: dict[str, Any]) -> str:
    summary = payload.get("summary", {})
    input_meta = payload.get("input", {})
    endpoint_rows = payload.get("endpoint_risk", [])
    alerts = payload.get("alerts", [])
    incidents = payload.get("incidents", [])
    dlq_events = payload.get("dlq_events", [])
    response_plan = payload.get("response_plan", {})
    ai_predictions = payload.get("ai_predictions", {})
    pipeline_delivery = payload.get("pipeline_delivery", {})
    siem_analysis = payload.get("siem_analysis", {})
    generated_at = payload.get("generated_at") or datetime.now().isoformat(timespec="seconds")
    highest = summary.get("highest_risk_score", 0)
    decision = payload.get("decision", "unknown")

    lines = [
        "# LayerTrace EDR/SIEM 분석 보고서",
        "",
        "## 1. Executive Summary",
        "",
        f"- 생성 시각: `{generated_at}`",
        f"- 데이터 소스: `{input_meta.get('source', 'unknown')}`",
        f"- 판정: `{decision}`",
        f"- 최고 Risk Score: `{highest}`",
        f"- Valid Events: `{summary.get('valid_event_count', 0)}`",
        f"- Alerts: `{summary.get('alert_count', 0)}`",
        f"- Incidents: `{summary.get('incident_count', 0)}`",
        f"- L7 Events: `{summary.get('l7_event_count', 0)}`",
        f"- AI Predictions: `{summary.get('ai_prediction_count', 0)}`",
        f"- Response Actions: `{summary.get('response_action_count', 0)}`",
        f"- DLQ Events: `{summary.get('dlq_event_count', 0)}`",
        "",
        _executive_sentence(payload),
        "",
        "## 2. Endpoint Risk",
        "",
        "| Endpoint | Risk | Severity | Alerts | Incidents | Top Rules |",
        "|---|---:|---|---:|---:|---|",
    ]

    for row in endpoint_rows[:10]:
        lines.append(
            "| {host} | {risk} | {severity} | {alerts} | {incidents} | {rules} |".format(
                host=_host_label(row),
                risk=row.get("risk_score", 0),
                severity=row.get("severity", "-"),
                alerts=row.get("alert_count", 0),
                incidents=row.get("incident_count", 0),
                rules=", ".join(row.get("top_rules", [])) or "-",
            )
        )

    lines.extend(
        [
            "",
            "## 3. Incident Summary",
            "",
        ]
    )
    if incidents:
        for incident in incidents:
            lines.extend(
                [
                    f"### {incident.get('incident_id', 'incident')} / {_host_label(incident)}",
                    "",
                    f"- Risk Score: `{incident.get('risk_score', 0)}`",
                    f"- Severity: `{incident.get('severity', '-')}`",
                    f"- Category: `{incident.get('primary_category', '-')}`",
                    f"- Decision: `{incident.get('decision', '-')}`",
                    "",
                    "Detected sequence:",
                ]
            )
            for stage in incident.get("detected_sequence", []):
                lines.append(f"- `{stage.get('stage', '-')}`: {stage.get('summary', '-')}")
            lines.append("")
    else:
        lines.extend(["- 공격 흐름으로 묶인 incident는 없습니다.", ""])

    lines.extend(
        [
            "## 4. SIEM Analysis",
            "",
            "### Endpoint Egress Topology",
            "",
            _topology_sentence(siem_analysis),
            "",
            "| Layer | Node | State | Detail |",
            "|---|---|---|---|",
        ]
    )
    for node in siem_analysis.get("egress_topology", {}).get("nodes", [])[:18]:
        lines.append(
            "| {layer} | {label} | {state} | {detail} |".format(
                layer=node.get("layer", "-"),
                label=node.get("label", "-"),
                state=node.get("state", "-"),
                detail=(
                    f"risk {node.get('risk_score', '-')}, alerts {node.get('alert_count', '-')}"
                    if node.get("layer") == "Endpoint"
                    else node.get("description") or f"events {node.get('event_count', '-')}"
                ),
            )
        )

    lines.extend(
        [
            "",
            "### SIEM Query Findings",
            "",
            "| Query | Host | Severity | Alerts | Evidence | Summary |",
            "|---|---|---|---:|---:|---|",
        ]
    )
    for finding in siem_analysis.get("query_findings", [])[:12]:
        lines.append(
            "| {query} | {host} | {severity} | {alerts} | {evidence} | {summary} |".format(
                query=finding.get("query_id", "-"),
                host=_host_label(finding),
                severity=finding.get("severity", "-"),
                alerts=finding.get("alert_count", 0),
                evidence=finding.get("evidence_count", 0),
                summary=str(finding.get("summary", "-")).replace("|", "\\|"),
            )
        )

    metadata = siem_analysis.get("telemetry_metadata", {})
    api_contract = siem_analysis.get("api_contract", {})
    lines.extend(
        [
            "",
            "### Telemetry / API Contract",
            "",
            f"- Customer: `{metadata.get('customer_id', '-')}` / Tenant: `{metadata.get('tenant_id', '-')}`",
            f"- Agent version: `{metadata.get('agent_version', '-')}` / Payload version: `{metadata.get('payload_version', '-')}`",
            f"- Current transport: `{api_contract.get('current_transport', 'REST')}`",
            f"- Swagger/OpenAPI: `{api_contract.get('swagger_path', '/docs')}`",
            f"- Collector note: {siem_analysis.get('collector_explanation', '-')}",
            "",
            "## 5. Alert Evidence",
            "",
            "| Rule | Host | Severity | Risk | Evidence |",
            "|---|---|---|---:|---|",
        ]
    )
    for alert in alerts[:20]:
        evidence = "; ".join(alert.get("evidence", [])[:3]) or "-"
        lines.append(
            "| {rule} | {host} | {severity} | {risk} | {evidence} |".format(
                rule=alert.get("rule_id", "-"),
                host=_host_label(alert),
                severity=alert.get("severity", "-"),
                risk=alert.get("risk_score", 0),
                evidence=evidence.replace("|", "\\|"),
            )
        )

    lines.extend(
        [
            "",
            "## 6. MITRE ATT&CK Mapping",
            "",
            "| Tactic | Count |",
            "|---|---:|",
        ]
    )
    for item in payload.get("mitre_distribution", []):
        lines.append(f"| {item.get('tactic', '-')} | {item.get('count', 0)} |")

    lines.extend(
        [
            "",
            "## 7. Deep Inspection / L7 Visibility",
            "",
            f"- Decryption events: `{summary.get('decryption_event_count', 0)}`",
            f"- L7 events: `{summary.get('l7_event_count', 0)}`",
            "- PoC stores metadata such as URL, domain, app action, and policy result. Sensitive body/message fields are removed by privacy masking.",
            "",
            "| Event | Host | Domain / URL | App | Decrypted |",
            "|---|---|---|---|---|",
        ]
    )
    for event in payload.get("events", []):
        if event.get("event_type") not in {"http_request", "application_action", "decryption_event"}:
            continue
        lines.append(
            "| {etype} | {host} | {dest} | {app} | {decrypted} |".format(
                etype=event.get("event_type", "-"),
                host=_host_label(event),
                dest=(event.get("url") or event.get("domain") or event.get("dst_ip") or "-"),
                app=event.get("app_name") or event.get("process_name") or "-",
                decrypted=event.get("decrypted", "-"),
            )
        )

    lines.extend(
        [
            "",
            "## 8. AI Prediction / Response Plan",
            "",
            f"- Prediction model: `{ai_predictions.get('model', '-')}`",
            f"- High or critical predictions: `{ai_predictions.get('high_or_critical_count', 0)}`",
            f"- Response mode: `{response_plan.get('mode', '-')}`",
            "",
            "| Host | Prediction | Score | Confidence | Reason |",
            "|---|---|---:|---:|---|",
        ]
    )
    for prediction in ai_predictions.get("predictions", [])[:10]:
        lines.append(
            "| {host} | {pred} | {score} | {conf} | {reason} |".format(
                host=_host_label(prediction),
                pred=prediction.get("prediction", "-"),
                score=prediction.get("score", 0),
                conf=prediction.get("confidence", 0),
                reason=prediction.get("reason", "-").replace("|", "\\|"),
            )
        )

    lines.extend(
        [
            "",
            "Response actions:",
        ]
    )
    for action in response_plan.get("actions", [])[:12]:
        lines.append(
            f"- `{action.get('action_type', '-')}` / `{action.get('mode', '-')}` / `{_host_label(action)}`: {action.get('description', '-')}"
        )

    lines.extend(
        [
            "",
            "## 9. Pipeline Delivery",
            "",
            f"- Compression: `{pipeline_delivery.get('compression', '-')}`",
            f"- Raw bytes: `{pipeline_delivery.get('raw_bytes', 0)}`",
            f"- Compressed bytes: `{pipeline_delivery.get('compressed_bytes', 0)}`",
            f"- Compression ratio: `{pipeline_delivery.get('compression_ratio', '-')}`",
            f"- Ship status: `{pipeline_delivery.get('ship_status', '-')}`",
            f"- Latest bundle: `{pipeline_delivery.get('latest_bundle_path', '-')}`",
            "",
            "## 10. Data Quality / DLQ",
            "",
            f"- DLQ event count: `{len(dlq_events)}`",
        ]
    )
    for event in dlq_events[:10]:
        lines.append(f"- `{event.get('event_id', 'unknown')}`: {'; '.join(event.get('errors', []))}")

    lines.extend(
        [
            "",
            "## 11. Recommended Next Actions",
            "",
            "- critical 또는 suspicious Endpoint의 process/network event를 우선 검토합니다.",
            "- R004 beaconing 후보는 정상 update/telemetry traffic인지 allowlist와 대조합니다.",
            "- R005/R008이 발생하면 전송 대상, 시간대, 사용자 업무 맥락을 확인합니다.",
            "- DLQ event가 있으면 schema producer 또는 collector mapping을 수정합니다.",
            "- 현재 PoC는 payload를 수집하지 않으므로 privacy-safe metadata 기준의 근거만 제시합니다.",
            "",
            "## 12. Limitations",
            "",
        ]
    )
    for limitation in payload.get("limitations", []):
        lines.append(f"- {limitation}")

    return "\n".join(lines) + "\n"


def build_html_report(payload: dict[str, Any], markdown: str) -> str:
    summary = payload.get("summary", {})
    highest = summary.get("highest_risk_score", 0)
    severity_class = "critical" if highest >= 80 else "warning" if highest >= 60 else "normal"
    body = _markdown_to_report_html(markdown)
    return f"""<!doctype html>
<html lang="ko">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>LayerTrace EDR/SIEM 분석 보고서</title>
    <style>
      :root {{
        color-scheme: light;
        --text: #121821;
        --muted: #607086;
        --line: #d9e1eb;
        --panel: #ffffff;
        --bg: #f4f7fb;
        --red: #c9243f;
        --amber: #b96a00;
        --blue: #1663c7;
      }}
      * {{ box-sizing: border-box; }}
      body {{
        margin: 0;
        background: var(--bg);
        color: var(--text);
        font-family: "Segoe UI", system-ui, sans-serif;
        letter-spacing: 0;
      }}
      header {{
        padding: 28px 36px;
        background: #0f1722;
        color: #f8fbff;
        border-bottom: 4px solid var(--blue);
      }}
      header p {{ margin: 8px 0 0; color: #b9c6d8; }}
      main {{ max-width: 1080px; margin: 0 auto; padding: 24px; }}
      .summary {{
        display: grid;
        grid-template-columns: repeat(4, minmax(0, 1fr));
        gap: 12px;
        margin-bottom: 18px;
      }}
      .stat, section {{
        background: var(--panel);
        border: 1px solid var(--line);
        border-radius: 8px;
      }}
      .stat {{ padding: 14px; }}
      .stat span {{ display: block; color: var(--muted); font-size: 12px; }}
      .stat strong {{ display: block; margin-top: 6px; font-size: 26px; }}
      .stat.critical strong {{ color: var(--red); }}
      .stat.warning strong {{ color: var(--amber); }}
      section {{ padding: 18px 20px; }}
      h1, h2, h3, p {{ margin-top: 0; }}
      h1 {{ font-size: 26px; margin-bottom: 0; }}
      h2 {{ margin-top: 28px; padding-bottom: 8px; border-bottom: 1px solid var(--line); font-size: 20px; }}
      h3 {{ font-size: 16px; }}
      table {{ width: 100%; border-collapse: collapse; margin: 10px 0 18px; }}
      th, td {{ border: 1px solid var(--line); padding: 8px 9px; text-align: left; vertical-align: top; font-size: 13px; }}
      th {{ background: #eef3f9; color: #344054; }}
      code {{ background: #eef3f9; border-radius: 4px; padding: 1px 4px; }}
      li {{ margin: 4px 0; }}
      @media (max-width: 780px) {{
        header {{ padding: 22px; }}
        main {{ padding: 14px; }}
        .summary {{ grid-template-columns: 1fr 1fr; }}
      }}
    </style>
  </head>
  <body>
    <header>
      <h1>LayerTrace EDR/SIEM 분석 보고서</h1>
      <p>허가된 endpoint / network metadata 기반 PoC 분석 결과입니다.</p>
    </header>
    <main>
      <div class="summary">
        <div class="stat {severity_class}"><span>Highest Risk</span><strong>{html.escape(str(highest))}</strong></div>
        <div class="stat"><span>Valid Events</span><strong>{html.escape(str(summary.get("valid_event_count", 0)))}</strong></div>
        <div class="stat"><span>Alerts</span><strong>{html.escape(str(summary.get("alert_count", 0)))}</strong></div>
        <div class="stat"><span>Incidents</span><strong>{html.escape(str(summary.get("incident_count", 0)))}</strong></div>
      </div>
      <section>
        {body}
      </section>
    </main>
  </body>
</html>
"""


def _host_label(row: dict[str, Any]) -> str:
    host_id = row.get("host_id")
    return str(row.get("host_display_name") or display_host(host_id))


def _topology_sentence(siem_analysis: dict[str, Any]) -> str:
    topology = siem_analysis.get("egress_topology", {})
    summary = topology.get("summary", {})
    endpoint_count = summary.get("endpoint_count", 0)
    destination_count = summary.get("external_destination_count", 0)
    alert_edge_count = summary.get("alert_edge_count", 0)
    return (
        "Endpoint Egress Topology는 Endpoint, Internal Zone, External Destination으로 나누어 "
        f"{endpoint_count}개 endpoint의 outbound connection과 {destination_count}개 external destination, "
        f"{alert_edge_count}개 alert edge를 보여줍니다."
    )


def _executive_sentence(payload: dict[str, Any]) -> str:
    summary = payload.get("summary", {})
    decision = payload.get("decision", "unknown")
    highest = int(summary.get("highest_risk_score", 0) or 0)
    if decision == "needs_security_review" or highest >= 80:
        return "현재 결과는 보안 담당자의 우선 검토가 필요한 상태입니다. 특히 높은 Risk Score를 가진 Endpoint와 반복 연결 또는 대용량 전송 Alert를 먼저 확인해야 합니다."
    if summary.get("dlq_event_count", 0):
        return "고위험 신호는 제한적이지만 DLQ event가 있어 수집 schema와 producer mapping 확인이 필요합니다."
    return "현재 sample에서는 고위험 신호가 제한적입니다. 다만 PoC 결과이므로 실제 운영 전 수집 범위와 오탐 기준을 추가 검증해야 합니다."


def _markdown_to_report_html(markdown: str) -> str:
    lines = markdown.splitlines()
    html_lines: list[str] = []
    in_ul = False
    in_table = False
    table_header_done = False

    for line in lines:
        if line.startswith("# "):
            _close_lists(html_lines, in_ul, in_table)
            in_ul = False
            in_table = False
            table_header_done = False
            html_lines.append(f"<h1>{html.escape(line[2:])}</h1>")
        elif line.startswith("## "):
            _close_lists(html_lines, in_ul, in_table)
            in_ul = False
            in_table = False
            table_header_done = False
            html_lines.append(f"<h2>{html.escape(line[3:])}</h2>")
        elif line.startswith("### "):
            _close_lists(html_lines, in_ul, in_table)
            in_ul = False
            in_table = False
            table_header_done = False
            html_lines.append(f"<h3>{html.escape(line[4:])}</h3>")
        elif line.startswith("|") and line.endswith("|"):
            cells = [cell.strip() for cell in line.strip("|").split("|")]
            if set(cells[0]) <= {"-", ":"}:
                continue
            if not in_table:
                _close_lists(html_lines, in_ul, False)
                in_ul = False
                in_table = True
                table_header_done = False
                html_lines.append("<table>")
            tag = "th" if not table_header_done else "td"
            html_lines.append("<tr>" + "".join(f"<{tag}>{_inline_html(cell)}</{tag}>" for cell in cells) + "</tr>")
            table_header_done = True
        elif line.startswith("- "):
            if in_table:
                html_lines.append("</table>")
                in_table = False
                table_header_done = False
            if not in_ul:
                html_lines.append("<ul>")
                in_ul = True
            html_lines.append(f"<li>{_inline_html(line[2:])}</li>")
        elif not line.strip():
            if in_ul:
                html_lines.append("</ul>")
                in_ul = False
            if in_table:
                html_lines.append("</table>")
                in_table = False
                table_header_done = False
        else:
            if in_ul:
                html_lines.append("</ul>")
                in_ul = False
            if in_table:
                html_lines.append("</table>")
                in_table = False
                table_header_done = False
            html_lines.append(f"<p>{_inline_html(line)}</p>")

    _close_lists(html_lines, in_ul, in_table)
    return "\n".join(html_lines)


def _close_lists(html_lines: list[str], in_ul: bool, in_table: bool) -> None:
    if in_ul:
        html_lines.append("</ul>")
    if in_table:
        html_lines.append("</table>")


def _inline_html(value: str) -> str:
    escaped = html.escape(value)
    parts = escaped.split("`")
    if len(parts) == 1:
        return escaped
    rendered: list[str] = []
    for index, part in enumerate(parts):
        rendered.append(f"<code>{part}</code>" if index % 2 else part)
    return "".join(rendered)
