import type { Alert, DlqEvent, EndpointRisk, EventRow, Incident, ProcessTreeRow, ResponseAction, TimelineItem } from "./resultAdapter";
import { EmptyState } from "./dashboardPanelCore";
import { clamp, formatBytes, formatTime } from "./dashboardPanelUtils";

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
