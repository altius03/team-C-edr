import { FileText, Printer, X } from "lucide-react";
import { useEffect, useState, type ReactNode } from "react";
import {
  type Alert,
  type AiSummary,
  type CountRow,
  type DlqEvent,
  type EdrState,
  type EndpointRisk,
  type EventRow,
  type Incident,
  type PipelineDelivery,
  type ProcessTreeRow,
  type QueryFinding,
  type ResponseAction,
  type Severity,
  type TelemetryMetadata,
  type TimelineItem,
  type TopologyEdge,
  type TopologyNode,
  type TopologySummary
} from "./resultAdapter";

const SEVERITY_ORDER: readonly Severity[] = ["critical", "warning", "suspicious", "info"];

export function Kpi({
  accent = "neutral",
  icon,
  label,
  value,
  detail
}: {
  readonly accent?: Severity | "neutral";
  readonly icon: ReactNode;
  readonly label: string;
  readonly value: number | string;
  readonly detail: string;
}) {
  return (
    <article className={`kpi-card ${accent}`}>
      <div className="kpi-icon">{icon}</div>
      <span>{label}</span>
      <strong>{value}</strong>
      <small>{detail}</small>
    </article>
  );
}

export function PanelHeading({
  title,
  subtitle,
  chip
}: {
  readonly title: string;
  readonly subtitle: string;
  readonly chip?: string | undefined;
}) {
  return (
    <header className="panel-heading">
      <div>
        <h3>{title}</h3>
        <p>{subtitle}</p>
      </div>
      {chip ? <span className="panel-chip">{chip}</span> : null}
    </header>
  );
}

export function TopologyCanvas({
  nodes,
  edges
}: {
  readonly nodes: readonly TopologyNode[];
  readonly edges: readonly TopologyEdge[];
}) {
  const endpointNodes = nodes.filter((node) => node.layer.toLowerCase().includes("endpoint")).slice(0, 4);
  const externalNodes = nodes.filter((node) => node.layer.toLowerCase().includes("external")).slice(0, 5);
  const endpointPositions = positionNodes(endpointNodes, 150, 96, 328);
  const externalPositions = positionNodes(externalNodes, 800, 96, 328);
  const sourceLookup = new Map(endpointPositions.map((node) => [node.id, node]));
  const targetLookup = new Map(externalPositions.flatMap((node) => [[node.id, node], [node.label, node]]));
  const flows = edges.length ? edges.slice(0, 10) : [];

  return (
    <div className="topology-stage">
      <svg className="topology-svg" viewBox="0 0 1040 420" role="img" aria-label="Endpoint egress topology">
        <defs>
          <marker id="flow-arrow" markerHeight="7" markerWidth="8" orient="auto" refX="7" refY="3.5">
            <path className="flow-arrow" d="M 0 0 L 8 3.5 L 0 7 z" />
          </marker>
        </defs>
        <text className="lane-label" x="150" y="34" textAnchor="middle">Endpoint fleet</text>
        <text className="lane-label boundary-label" x="520" y="34" textAnchor="middle">Protected tenant boundary</text>
        <text className="lane-label" x="800" y="34" textAnchor="middle">External destinations</text>
        <rect className="boundary-box" height="248" rx="10" width="180" x="430" y="86" />
        <line className="boundary-axis" x1="430" x2="610" y1="210" y2="210" />
        <text className="boundary-title" x="520" y="194" textAnchor="middle">Tenant SIEM</text>
        <text className="boundary-state" x="520" y="218" textAnchor="middle">inspection boundary</text>
        {flows.map((edge, index) => {
          const source = sourceLookup.get(edge.source) ?? endpointPositions[index % Math.max(endpointPositions.length, 1)];
          const target = targetLookup.get(edge.target) ?? externalPositions[index % Math.max(externalPositions.length, 1)];
          if (!source || !target) return null;
          const path = `M ${source.x + 30} ${source.y} C 310 ${source.y}, 370 210, 430 210 S 720 ${target.y}, ${target.x - 42} ${target.y}`;
          return <path className={`flow-line ${edgeState(edge)}`} d={path} key={`${edge.source}-${edge.target}-${index}`} />;
        })}
        {endpointPositions.map((node) => <GraphNode key={node.id} node={node} side="left" />)}
        {externalPositions.map((node) => <GraphNode key={node.id} node={node} side="right" />)}
      </svg>
      <div className="topology-legend">
        <span><i className="dot alert" />alert</span>
        <span><i className="dot observed" />observed</span>
        <span><i className="dot not-detected" />not detected</span>
      </div>
      <div className="edge-list">
        {flows.slice(0, 5).map((edge, index) => (
          <div className={`edge-row ${edgeState(edge)}`} key={`${edge.source}-${edge.target}-${index}`}>
            <span>{edge.sourceLabel}</span>
            <strong>{edge.target}</strong>
            <small>{edge.protocol} / alerts {edge.alertCount} / {formatBytes(edge.bytesOut)}</small>
          </div>
        ))}
      </div>
    </div>
  );
}

export function SeverityChart({
  counts,
  active,
  onSelect
}: {
  readonly counts: Readonly<Record<Severity | "all", number>>;
  readonly active: Severity | "all";
  readonly onSelect: (severity: Severity | "all") => void;
}) {
  const total = Math.max(counts.all, 1);
  return (
    <div className="severity-chart">
      <div className="severity-track">
        {SEVERITY_ORDER.map((severity) => (
          <span
            className={`severity-segment ${severity}`}
            key={severity}
            style={{ width: `${Math.max(3, Math.round((counts[severity] / total) * 100))}%` }}
          />
        ))}
      </div>
      <div className="severity-buttons">
        <button className={active === "all" ? "active" : ""} onClick={() => onSelect("all")} type="button">
          <span>All</span>
          <strong>{counts.all}</strong>
        </button>
        {SEVERITY_ORDER.map((severity) => (
          <button
            className={active === severity ? `active ${severity}` : severity}
            key={severity}
            onClick={() => onSelect(severity)}
            type="button"
          >
            <span>{severity}</span>
            <strong>{counts[severity]}</strong>
          </button>
        ))}
      </div>
    </div>
  );
}

export function VolumeChart({
  events,
  alerts
}: {
  readonly events: readonly EventRow[];
  readonly alerts: readonly Alert[];
}) {
  const buckets = buildBuckets(events, alerts).slice(-10);
  const maxValue = Math.max(...buckets.map((bucket) => bucket.events + bucket.alerts), 1);
  return (
    <div className="volume-chart" aria-label="event and alert volume chart">
      {buckets.map((bucket) => {
        const eventHeight = Math.max(4, Math.round((bucket.events / maxValue) * 150));
        const alertHeight = bucket.alerts ? Math.max(4, Math.round((bucket.alerts / maxValue) * 150)) : 0;
        return (
          <div className="volume-column" key={bucket.label}>
            <div className="volume-stack">
              <span className="alert-bar" style={{ height: alertHeight }} />
              <span className="event-bar" style={{ height: eventHeight }} />
            </div>
            <small>{bucket.shortLabel}</small>
          </div>
        );
      })}
    </div>
  );
}

export function CountBars({ rows, kind }: { readonly rows: readonly CountRow[]; readonly kind: string }) {
  if (!rows.length) return <EmptyState label="현재 필터 범위에 ranked data가 없습니다" />;
  const maxCount = Math.max(...rows.map((row) => row.count), 1);
  return (
    <div className="bar-list">
      {rows.slice(0, 6).map((row) => (
        <div className="bar-row" key={`${kind}-${row.label}`}>
          <div className="bar-label">
            <span>{row.label}</span>
            <strong>{row.count}</strong>
          </div>
          <div className="bar-track">
            <span className="bar-fill" style={{ width: `${Math.round((row.count / maxCount) * 100)}%` }} />
          </div>
        </div>
      ))}
    </div>
  );
}

export function SignalStrip({
  signals
}: {
  readonly signals: readonly {
    readonly label: string;
    readonly value: string;
    readonly detail: string;
    readonly tone: Severity | "neutral";
  }[];
}) {
  return (
    <section className="signal-strip" aria-label="EDR SIEM signal health">
      {signals.map((signal) => (
        <article className={`signal-card ${signal.tone}`} key={signal.label}>
          <span>{signal.label}</span>
          <strong>{signal.value}</strong>
          <small>{signal.detail}</small>
        </article>
      ))}
    </section>
  );
}

export function IncidentQueue({ incidents }: { readonly incidents: readonly Incident[] }) {
  if (!incidents.length) return <EmptyState label="선택한 범위에 incident가 없습니다" />;
  return (
    <div className="incident-queue">
      {incidents.slice(0, 4).map((incident) => (
        <article className={`incident-card ${incident.severity}`} key={incident.incidentId}>
          <div className="incident-top">
            <strong>{incident.host}</strong>
            <span className={`pill ${incident.severity}`}>{incident.severity}</span>
          </div>
          <div className="incident-score">risk {incident.riskScore}</div>
          <p>{incident.category.replace(/_/g, " ")}</p>
          <ol>
            {incident.stages.slice(0, 4).map((stage) => <li key={`${incident.incidentId}-${stage.stage}`}>{stage.summary}</li>)}
          </ol>
        </article>
      ))}
    </div>
  );
}

export function EndpointRiskList({ rows }: { readonly rows: readonly EndpointRisk[] }) {
  if (!rows.length) return <EmptyState label="현재 범위에 endpoint risk row가 없습니다" />;
  return (
    <div className="endpoint-risk-list">
      {rows.slice(0, 8).map((row) => (
        <article className="endpoint-risk-row" key={row.hostId}>
          <div className="row-top">
            <strong>{row.host}</strong>
            <span className={`pill ${row.severity}`}>{row.severity}</span>
          </div>
          <div className="score-track" aria-label={`Risk score ${row.riskScore}`}>
            <span className={`score-fill ${row.severity}`} style={{ width: `${clamp(row.riskScore)}%` }} />
          </div>
          <div className="risk-meta">
            <span>Risk <strong>{row.riskScore}</strong>/100</span>
            <span>Alert {row.alerts}</span>
            <span>Incident {row.incidents}</span>
          </div>
          <small>Rules: {row.topRules.join(", ") || "not detected"}</small>
        </article>
      ))}
    </div>
  );
}

export function Timeline({ rows }: { readonly rows: readonly TimelineItem[] }) {
  if (!rows.length) return <EmptyState label="현재 범위에 연결된 attack timeline이 없습니다" />;
  return (
    <div className="timeline">
      {rows.slice(0, 6).map((row, index) => (
        <article className={`timeline-card ${row.severity}`} key={`${row.stage}-${index}`}>
          <span className="step">STEP {index + 1}</span>
          <strong>{row.stage.replace(/_/g, " ")}</strong>
          <p>{row.summary}</p>
          <small>{row.host} / {formatTime(row.time)}</small>
        </article>
      ))}
    </div>
  );
}

export function DlqMonitor({ rows }: { readonly rows: readonly DlqEvent[] }) {
  if (!rows.length) return <EmptyState label="현재 DLQ로 이동한 event가 없습니다" />;
  return (
    <div className="dlq-list">
      {rows.map((row) => (
        <article className="dlq-row" key={`${row.eventId}-${row.index}`}>
          <div className="row-top">
            <strong>{row.eventId}</strong>
            <span className="pill warning">{row.code}</span>
          </div>
          <p>{row.errors.join(" / ") || "Schema validation failed"}</p>
        </article>
      ))}
    </div>
  );
}

export function ProcessTreePanel({ rows }: { readonly rows: readonly ProcessTreeRow[] }) {
  if (!rows.length) return <EmptyState label="현재 범위에 process tree row가 없습니다" />;
  return (
    <div className="process-tree-list">
      {rows.slice(0, 10).map((row) => (
        <article className="process-row" key={`${row.eventId}-${row.processName}`}>
          <div className="process-main">
            <strong>{row.parentProcess} {"->"} {row.processName}</strong>
            <span className={`pill ${row.signed ? "info" : "suspicious"}`}>{row.signed ? "signed" : "unsigned"}</span>
          </div>
          <small>{row.host} / {formatTime(row.eventTime)}</small>
          <code>{row.processPath || "path not available"}</code>
        </article>
      ))}
    </div>
  );
}

export function AlertInspector({ alert }: { readonly alert: Alert }) {
  return (
    <div className={`inspector ${alert.severity}`}>
      <div className="inspector-top">
        <span className={`pill ${alert.severity}`}>{alert.severity}</span>
        <strong>risk {alert.riskScore}</strong>
      </div>
      <h3>{alert.ruleId} / {alert.title}</h3>
      <dl className="inspector-grid">
        <div>
          <dt>Host</dt>
          <dd>{alert.host}</dd>
        </div>
        <div>
          <dt>MITRE</dt>
          <dd>{alert.mitre.join(" / ") || "-"}</dd>
        </div>
      </dl>
      <ul>
        {alert.evidence.slice(0, 5).map((line) => <li key={line}>{line}</li>)}
      </ul>
    </div>
  );
}

export function ReportCenter({
  aiSummary,
  decision,
  edrState,
  htmlPath,
  markdownPath,
  pipeline,
  queryFindings,
  summary,
  telemetry,
  topologySummary
}: ReportModalProps & { readonly aiSummary: AiSummary }) {
  return (
    <div className="report-center-panel">
      <div className="report-summary">
        <strong>분석 report가 생성되었습니다</strong>
        <p>판단: {decision}</p>
        <p>Executive Summary, Endpoint Risk, SIEM Analysis, Alert Evidence, MITRE ATT&CK, DLQ, L7, AI, Pipeline 섹션을 포함합니다.</p>
        <p>AI predictions: {aiSummary.predictionCount} / high {aiSummary.highOrCriticalCount} · Pipeline: {pipeline.compression} {formatBytes(pipeline.compressedBytes)}</p>
        <p className="mono">{fileName(htmlPath)} · {fileName(markdownPath)}</p>
      </div>
      <ReportModal
        decision={decision}
        edrState={edrState}
        htmlPath={htmlPath}
        markdownPath={markdownPath}
        pipeline={pipeline}
        queryFindings={queryFindings}
        summary={summary}
        telemetry={telemetry}
        topologySummary={topologySummary}
        triggerLabel="Open report"
      />
    </div>
  );
}

export function AlertList({
  alerts,
  selectedAlertId,
  onSelect
}: {
  readonly alerts: readonly Alert[];
  readonly selectedAlertId: string;
  readonly onSelect: (alertId: string) => void;
}) {
  if (!alerts.length) return <EmptyState label="선택한 필터에 맞는 alert가 없습니다" />;
  return (
    <div className="alert-list">
      {alerts.slice(0, 18).map((alert) => (
        <button
          className={selectedAlertId === alert.alertId ? `alert-row ${alert.severity} selected` : `alert-row ${alert.severity}`}
          key={alert.alertId}
          onClick={() => onSelect(alert.alertId)}
          type="button"
        >
          <span>{alert.ruleId} / {alert.title}</span>
          <strong>{alert.host}</strong>
          <small>{alert.severity} / risk {alert.riskScore} / {formatTime(alert.eventTime)}</small>
        </button>
      ))}
    </div>
  );
}

export function EventTable({ events }: { readonly events: readonly EventRow[] }) {
  if (!events.length) return <EmptyState label="선택한 필터에 맞는 event가 없습니다" />;
  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>
            <th>Time</th>
            <th>Endpoint</th>
            <th>Type</th>
            <th>Process</th>
            <th>Destination</th>
            <th>Bytes out</th>
          </tr>
        </thead>
        <tbody>
          {events.slice(-60).reverse().map((event) => (
            <tr key={event.eventId}>
              <td>{formatTime(event.eventTime)}</td>
              <td>{event.host}</td>
              <td>{event.eventType}</td>
              <td>{event.processName}</td>
              <td>{event.destination}</td>
              <td>{formatBytes(event.bytesOut)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export function ResponsePlan({ actions }: { readonly actions: readonly ResponseAction[] }) {
  if (!actions.length) return <EmptyState label="생성된 response action이 없습니다" />;
  return (
    <div className="response-list">
      {actions.slice(0, 6).map((action, index) => (
        <article className="response-item" key={`${action.ruleId}-${index}`}>
          <div>
            <strong>{action.actionType.replace(/_/g, " ")}</strong>
            <small>{action.host} / {action.ruleId} / {action.status}</small>
          </div>
          <span className="pill info">{action.mode}</span>
          <p>{action.description}</p>
        </article>
      ))}
    </div>
  );
}

export function EmptyState({ label }: { readonly label: string }) {
  return <div className="empty-state">{label}</div>;
}

type ReportModalProps = {
  readonly decision: string;
  readonly edrState: EdrState;
  readonly htmlPath: string;
  readonly markdownPath: string;
  readonly pipeline: PipelineDelivery;
  readonly queryFindings: readonly QueryFinding[];
  readonly summary: {
    readonly alerts: number;
    readonly incidents: number;
    readonly highestRisk: number;
  };
  readonly telemetry: TelemetryMetadata;
  readonly topologySummary: TopologySummary;
  readonly triggerLabel?: string;
};

export function ReportModal({
  decision,
  edrState,
  htmlPath,
  markdownPath,
  pipeline,
  queryFindings,
  summary,
  telemetry,
  topologySummary,
  triggerLabel = "Open report"
}: ReportModalProps) {
  const [open, setOpen] = useState(false);

  useEffect(() => {
    if (!open) return undefined;
    const closeOnEscape = (event: KeyboardEvent) => {
      if (event.key === "Escape") setOpen(false);
    };
    window.addEventListener("keydown", closeOnEscape);
    return () => window.removeEventListener("keydown", closeOnEscape);
  }, [open]);

  const printReport = () => {
    setOpen(true);
    window.setTimeout(() => window.print(), 50);
  };

  return (
    <>
      <div className="report-actions">
        <button onClick={() => setOpen(true)} type="button"><FileText size={16} /> {triggerLabel}</button>
      </div>
      {open ? (
        <div aria-modal="true" className="modal" onMouseDown={() => setOpen(false)} role="dialog">
          <section className="modal-card" onMouseDown={(event) => event.stopPropagation()}>
            <div className="modal-heading">
              <PanelHeading title="LayerTrace EDR/SIEM report" subtitle="현재 dashboard 결과를 브라우저 PDF로 저장할 수 있습니다" />
              <button aria-label="Close report" className="icon-button" onClick={() => setOpen(false)} type="button">
                <X size={16} />
              </button>
            </div>
            <div className="modal-body">
              <section className="print-section">
                <h3>Executive summary</h3>
                <div className="report-stat-grid">
                  <div><span>EDR State</span><strong>{edrState}</strong></div>
                  <div><span>Highest risk</span><strong>{summary.highestRisk}</strong></div>
                  <div><span>Alerts</span><strong>{summary.alerts}</strong></div>
                  <div><span>Incidents</span><strong>{summary.incidents}</strong></div>
                </div>
                <p>판단: {decision}</p>
                <p>Customer {telemetry.customerId} · Tenant {telemetry.tenantId} · Agent {telemetry.agentVersion} · Payload {telemetry.payloadVersion}</p>
              </section>
              <section className="print-section">
                <h3>Endpoint Egress Topology</h3>
                <p>{topologySummary.endpointCount} endpoints, 외부 목적지 {topologySummary.externalDestinationCount}개, alert edge {topologySummary.alertEdgeCount}개입니다.</p>
                <p>Pipeline {pipeline.compression} · {formatBytes(pipeline.compressedBytes)} 압축 · ship {pipeline.shipStatus}</p>
              </section>
              <section className="print-section">
                <h3>SIEM query findings</h3>
                <div className="finding-list">
                  {queryFindings.length ? queryFindings.slice(0, 8).map((finding) => (
                    <article className="modal-finding" key={finding.queryId}>
                      <strong>{finding.queryId} · {finding.title}</strong>
                      <span>{finding.host} · {finding.severity} · evidence {finding.evidenceCount}</span>
                      <p>{finding.summary || "요약이 없습니다"}</p>
                    </article>
                  )) : <EmptyState label="표시할 SIEM finding이 없습니다" />}
                </div>
              </section>
              <section className="print-section">
                <h3>Report artifacts</h3>
                <p className="mono">HTML: {htmlPath}</p>
                <p className="mono">Markdown: {markdownPath}</p>
              </section>
            </div>
            <div className="modal-actions">
              <button onClick={printReport} type="button"><Printer size={16} /> Save PDF</button>
              <button onClick={() => setOpen(false)} type="button">닫기</button>
            </div>
          </section>
        </div>
      ) : null}
    </>
  );
}

function GraphNode({ node, side }: { readonly node: PositionedNode; readonly side: "left" | "right" }) {
  const textX = side === "left" ? -34 : 34;
  const anchor = side === "left" ? "end" : "start";
  return (
    <g className={`graph-node ${node.state}`} transform={`translate(${node.x} ${node.y})`}>
      <circle className="node-ring" r="25" />
      <circle className="node-core" r="11" />
      <text className="node-label" textAnchor={anchor} x={textX} y="2">{node.label}</text>
      <text className="node-state" textAnchor={anchor} x={textX} y="18">{stateLabel(node.state)}</text>
    </g>
  );
}

type PositionedNode = TopologyNode & { readonly x: number; readonly y: number };

function positionNodes(nodes: readonly TopologyNode[], x: number, minY: number, maxY: number): readonly PositionedNode[] {
  const visibleNodes = nodes.length ? nodes : [{ id: "empty", label: "No data", layer: "empty", state: "not-detected", riskScore: 0, alertCount: 0 }];
  const step = visibleNodes.length === 1 ? 0 : (maxY - minY) / (visibleNodes.length - 1);
  return visibleNodes.map((node, index) => ({
    ...node,
    x,
    y: visibleNodes.length === 1 ? (minY + maxY) / 2 : minY + step * index
  }));
}

function edgeState(edge: TopologyEdge): string {
  if (edge.alertCount > 0 || edge.state === "alert") return "alert";
  if (edge.state === "observed") return "observed";
  return "not-detected";
}

function buildBuckets(events: readonly EventRow[], alerts: readonly Alert[]) {
  const buckets = new Map<string, { label: string; shortLabel: string; events: number; alerts: number }>();
  for (const event of events) {
    const key = hourBucket(event.eventTime);
    if (!buckets.has(key)) buckets.set(key, { label: key, shortLabel: key.slice(11), events: 0, alerts: 0 });
    const bucket = buckets.get(key);
    if (bucket) bucket.events += 1;
  }
  for (const alert of alerts) {
    const key = hourBucket(alert.eventTime);
    if (!buckets.has(key)) buckets.set(key, { label: key, shortLabel: key.slice(11), events: 0, alerts: 0 });
    const bucket = buckets.get(key);
    if (bucket) bucket.alerts += 1;
  }
  return [...buckets.values()].sort((a, b) => a.label.localeCompare(b.label));
}

function hourBucket(value: string): string {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "unknown";
  const month = String(date.getMonth() + 1).padStart(2, "0");
  const day = String(date.getDate()).padStart(2, "0");
  const hour = String(date.getHours()).padStart(2, "0");
  return `${month}-${day} ${hour}:00`;
}

function formatTime(value: string): string {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "-";
  const month = String(date.getMonth() + 1).padStart(2, "0");
  const day = String(date.getDate()).padStart(2, "0");
  const hour = String(date.getHours()).padStart(2, "0");
  const minute = String(date.getMinutes()).padStart(2, "0");
  return `${month}-${day} ${hour}:${minute}`;
}

function formatBytes(value: number): string {
  if (!value) return "-";
  if (value >= 1_000_000) return `${(value / 1_000_000).toFixed(1)} MB`;
  if (value >= 1_000) return `${(value / 1_000).toFixed(1)} KB`;
  return `${value} B`;
}

function clamp(value: number): number {
  return Math.min(100, Math.max(0, value));
}

function fileName(value: string): string {
  return value.split(/[\\/]/).pop() || value;
}

function stateLabel(state: string): string {
  if (state === "alert") return "alert";
  if (state === "observed") return "observed";
  return "not detected";
}
