import { Activity, AlertTriangle, Database, Radar, ShieldAlert, Siren, Workflow } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import {
  AlertInspector,
  AlertList,
  CountBars,
  DlqMonitor,
  EmptyState,
  EndpointRiskList,
  EventTable,
  IncidentQueue,
  Kpi,
  PanelHeading,
  ProcessTreePanel,
  ReportCenter,
  ReportModal,
  ResponsePlan,
  SeverityChart,
  SignalStrip,
  Timeline,
  TopologyCanvas,
  VolumeChart
} from "./dashboardPanels";
import {
  type Alert,
  type DashboardResult,
  type DlqEvent,
  type EndpointRisk,
  type EventRow,
  type Incident,
  type ProcessTreeRow,
  type Severity,
  type TimelineItem,
  emptyDashboardResult,
  loadDashboardResult,
} from "./resultAdapter";

type TimeRange = "last10m" | "last1h" | "last24h" | "all";
type SeverityFilter = Severity | "all";

// Shared filter literals keep select controls and scoping predicates on one contract.
const TIME_RANGES: readonly TimeRange[] = ["last10m", "last1h", "last24h", "all"];
const TIME_RANGE_LABELS: Readonly<Record<TimeRange, string>> = {
  last10m: "Last 10m",
  last1h: "Last 1h",
  last24h: "Last 24h",
  all: "All"
};

const SEVERITIES: readonly Severity[] = ["critical", "warning", "suspicious", "info"];

// Coordinates dashboard state, filters, and panel data for the main React view.
export function App() {
  const [result, setResult] = useState<DashboardResult>(() => emptyDashboardResult());
  const [timeRange, setTimeRange] = useState<TimeRange>("last24h");
  const [severityFilter, setSeverityFilter] = useState<SeverityFilter>("all");
  const [hostFilter, setHostFilter] = useState("all");
  const [search, setSearch] = useState("");
  const [selectedAlertId, setSelectedAlertId] = useState<string>(result.alerts[0]?.alertId ?? "");

  useEffect(() => {
    const controller = new AbortController();
    void loadDashboardResult(controller.signal).then((loadedResult) => {
      setResult(loadedResult);
      setSelectedAlertId(loadedResult.alerts[0]?.alertId ?? "");
    });
    return () => controller.abort();
  }, []);

  // Every panel derives its rows from the same normalized filters to avoid split views.
  const latestObservedAt = useMemo(() => latestObservedTime(result), [result]);
  const hostOptions = useMemo(() => buildHostOptions(result), [result]);
  const query = search.trim().toLowerCase();
  const scopedAlerts = result.alerts.filter((alert) => matchesAlertScope(alert, hostFilter, severityFilter, query, timeRange, latestObservedAt));
  const scopedEvents = result.events.filter((event) => matchesEventScope(event, hostFilter, query, timeRange, latestObservedAt));
  const activeHostIds = new Set([...scopedAlerts.map((alert) => alert.hostId), ...scopedEvents.map((event) => event.hostId)]);
  const scopedIncidents = result.incidents.filter((incident) => matchesIncidentScope(incident, hostFilter, severityFilter, query));
  const scopedTimeline = result.timeline.filter((item) => matchesTimelineScope(item, hostOptions, hostFilter, severityFilter, query, timeRange, latestObservedAt));
  const scopedEndpointRisk = result.endpointRisk.filter((row) => matchesEndpointRiskScope(row, hostFilter, severityFilter, query, activeHostIds));
  const scopedProcessTrees = result.processTrees.filter((row) => matchesProcessScope(row, hostFilter, query, timeRange, latestObservedAt));
  const scopedDlq = result.dlqEvents.filter((row) => matchesDlqScope(row, query));
  const scopedTopology = scopeTopology(result.topology, hostFilter, query, activeHostIds);
  const severityCounts = countSeverity(scopedAlerts);
  const selectedAlert = scopedAlerts.find((alert) => alert.alertId === selectedAlertId) ?? scopedAlerts[0];
  const actionPending = scopedAlerts.filter((alert) => alert.severity === "critical" || alert.severity === "warning").length;

  return (
    <main className="app-shell">
      <aside className="sidebar">
        <div className="brand">
          <span className="brand-mark">LT</span>
          <div>
            <strong>LayerTrace</strong>
            <span>EDR/SIEM Console</span>
          </div>
        </div>
        <nav className="nav-list" aria-label="Dashboard sections">
          <a className="nav-item active" href="#overview">Overview</a>
          <a className="nav-item" href="#topology">Topology</a>
          <a className="nav-item" href="#detection">Detection</a>
          <a className="nav-item" href="#alert-inspector">Alert Inspector</a>
          <a className="nav-item" href="#incidents">Incidents</a>
          <a className="nav-item" href="#reports">Reports</a>
          <a className="nav-item" href="#event-volume">Event Volume</a>
          <a className="nav-item" href="#response-playbook">Response Playbook</a>
          <a className="nav-item" href="#endpoint-risk">Endpoint Risk</a>
          <a className="nav-item" href="#timeline">Timeline</a>
          <a className="nav-item" href="#threat-intel">MITRE/Domain/IP</a>
          <a className="nav-item" href="#dlq">DLQ</a>
          <a className="nav-item" href="#alerts">Alerts</a>
          <a className="nav-item" href="#process-event">Process/Event</a>
        </nav>
      </aside>

      <section className="workspace">
        <header className="topbar">
          <div>
            <p className="eyebrow">Current State</p>
            <h1>{stateLabel(result.edrState)}</h1>
            <p className="subtitle">실행 상태 {result.status} / 생성 {formatTime(result.generatedAt)} / 판단 {result.decision}</p>
            <p className="source-note">데이터 출처: {result.source}</p>
          </div>
          <div className="topbar-right">
            <div className="selected-alert-pill">
              <span>선택한 alert</span>
              <strong>{selectedAlert ? `${selectedAlert.ruleId} / ${selectedAlert.host}` : "none"}</strong>
            </div>
            <ReportModal
              decision={result.decision}
              edrState={result.edrState}
              htmlPath={result.report.htmlPath}
              markdownPath={result.report.markdownPath}
              pipeline={result.pipeline}
              queryFindings={result.queryFindings}
              summary={result.summary}
              telemetry={result.telemetry}
              topologySummary={result.topology.summary}
            />
          </div>
        </header>

        <section className="toolbar" aria-label="Dashboard filters">
          <label className="select-field">
            <span>Time range</span>
            <select onChange={(event) => setTimeRange(toTimeRange(event.target.value))} value={timeRange}>
              {TIME_RANGES.map((range) => <option key={range} value={range}>{TIME_RANGE_LABELS[range]}</option>)}
            </select>
          </label>
          <label className="select-field">
            <span>Endpoint</span>
            <select onChange={(event) => setHostFilter(event.target.value)} value={hostFilter}>
              <option value="all">All endpoints</option>
              {[...hostOptions.entries()].map(([hostId, hostLabel]) => <option key={hostId} value={hostId}>{hostLabel}</option>)}
            </select>
          </label>
          <label className="select-field">
            <span>Severity</span>
            <select onChange={(event) => setSeverityFilter(toSeverityFilter(event.target.value))} value={severityFilter}>
              <option value="all">All severity</option>
              {SEVERITIES.map((severity) => <option key={severity} value={severity}>{severity}</option>)}
            </select>
          </label>
          <label className="search-field">
            <span>Search</span>
            <input onChange={(event) => setSearch(event.target.value)} placeholder="domain, process, rule" type="search" value={search} />
          </label>
        </section>

        <section className="kpi-grid" id="overview" aria-label="Security summary">
          <Kpi accent="critical" detail="가장 높은 endpoint risk" icon={<Siren size={18} />} label="Risk peak" value={result.summary.highestRisk} />
          <Kpi accent={actionPending ? "warning" : "neutral"} detail="critical 또는 warning alerts" icon={<AlertTriangle size={18} />} label="Action pending" value={actionPending} />
          <Kpi detail="검증된 telemetry" icon={<Activity size={18} />} label="Events" value={scopedEvents.length} />
          <Kpi accent="critical" detail="현재 필터의 alert" icon={<ShieldAlert size={18} />} label="Alerts" value={scopedAlerts.length} />
          <Kpi detail="상관 분석된 case" icon={<Workflow size={18} />} label="Incidents" value={scopedIncidents.length} />
          <Kpi accent="warning" detail="schema 검토 대기열" icon={<Database size={18} />} label="DLQ" value={scopedDlq.length} />
        </section>

        <SignalStrip signals={buildSignals(result)} />

        <section className="hero-grid">
          <article className="panel topology-panel" id="topology">
            <PanelHeading
              chip={`${scopedTopology.edges.length} edges`}
              title="Endpoint Egress Topology"
              subtitle="Endpoint fleet에서 Protected tenant boundary를 거쳐 External destinations로 나가는 흐름"
            />
            <TopologyCanvas nodes={scopedTopology.nodes} edges={scopedTopology.edges} />
          </article>

          <article className="panel" id="detection">
            <PanelHeading chip={TIME_RANGE_LABELS[timeRange]} title="Detection Overview" subtitle="Severity, event volume, MITRE coverage를 한 화면에서 확인" />
            <SeverityChart active={severityFilter} counts={severityCounts} onSelect={setSeverityFilter} />
            <VolumeChart alerts={scopedAlerts} events={scopedEvents} />
            <CountBars kind="mitre" rows={result.mitreDistribution} />
          </article>
        </section>

        <section className="content-grid">
          <article className="panel" id="alert-inspector">
            <PanelHeading chip={selectedAlert?.severity} title="Alert Inspector" subtitle="alert 또는 severity를 선택하면 이 영역의 context가 즉시 바뀜" />
            {selectedAlert ? <AlertInspector alert={selectedAlert} /> : <EmptyState label="선택된 alert가 없습니다" />}
          </article>

          <article className="panel" id="incidents">
            <PanelHeading chip={`${scopedIncidents.length} cases`} title="Incident Workbench" subtitle="연결된 host 흐름과 risk context" />
            <IncidentQueue incidents={scopedIncidents} />
          </article>

          <article className="panel" id="reports">
            <PanelHeading title="Report Center" subtitle="생성된 report를 열고 모달 안에서 PDF로 저장" />
            <ReportCenter
              aiSummary={result.aiSummary}
              decision={result.decision}
              edrState={result.edrState}
              htmlPath={result.report.htmlPath}
              markdownPath={result.report.markdownPath}
              pipeline={result.pipeline}
              queryFindings={result.queryFindings}
              summary={result.summary}
              telemetry={result.telemetry}
              topologySummary={result.topology.summary}
            />
          </article>
        </section>

        <section className="wide-grid">
          <article className="panel" id="event-volume">
            <PanelHeading chip={TIME_RANGE_LABELS[timeRange]} title="Event Volume" subtitle="관측 시간대별 telemetry와 alert 수" />
            <VolumeChart alerts={scopedAlerts} events={scopedEvents} />
          </article>

          <article className="panel" id="response-playbook">
            <PanelHeading title="Response Playbook" subtitle="선택된 결과에서 생성된 local dry-run 대응 액션" />
            <ResponsePlan actions={result.responseActions} />
          </article>
        </section>

        <section className="wide-grid">
          <article className="panel" id="endpoint-risk">
            <PanelHeading chip={`${scopedEndpointRisk.length} endpoints`} title="Endpoint Risk" subtitle="Risk score, alert 수, incident 수, 주요 rule" />
            <EndpointRiskList rows={scopedEndpointRisk} />
          </article>

          <article className="panel" id="timeline">
            <PanelHeading title="Attack Timeline" subtitle="Download, execution, command and control, exfiltration 단계" />
            <Timeline rows={scopedTimeline} />
          </article>
        </section>

        <section className="content-grid" id="threat-intel">
          <article className="panel">
            <PanelHeading title="MITRE ATT&CK" subtitle="매칭된 rule 기준 tactic coverage" />
            <CountBars kind="mitre" rows={result.mitreDistribution} />
          </article>

          <article className="panel">
            <PanelHeading title="Top Domains" subtitle="의심스러운 외부 domain" />
            <CountBars kind="domain" rows={result.topDomains} />
          </article>

          <article className="panel">
            <PanelHeading title="Top IPs" subtitle="의심스러운 외부 IP 주소" />
            <CountBars kind="ip" rows={result.topIps} />
          </article>
        </section>

        <section className="wide-grid">
          <article className="panel" id="dlq">
            <PanelHeading chip={`${scopedDlq.length} events`} title="DLQ Monitor" subtitle="ingestion 전에 수정해야 하는 schema validation 실패" />
            <DlqMonitor rows={scopedDlq} />
          </article>

          <article className="panel" id="alerts">
            <PanelHeading chip={`${scopedAlerts.length} visible`} title="Alert Explorer" subtitle="severity 선택 시 목록이 즉시 전환됨" />
            <AlertList alerts={scopedAlerts} onSelect={setSelectedAlertId} selectedAlertId={selectedAlert?.alertId ?? ""} />
          </article>
        </section>

        <section className="wide-grid" id="process-event">
          <article className="panel">
            <PanelHeading title="Process Tree" subtitle="endpoint evidence와 연결된 Win32 process start telemetry" />
            <ProcessTreePanel rows={scopedProcessTrees} />
          </article>

          <article className="panel" id="events">
            <PanelHeading chip={`${scopedEvents.length} events`} title="Event Log" subtitle="time, endpoint, search 필터가 적용된 telemetry row" />
            <EventTable events={scopedEvents} />
          </article>
        </section>
      </section>
    </main>
  );
}

// Scope predicates centralize dashboard filtering while preserving each panel's row shape.
function matchesAlertScope(
  alert: Alert,
  hostFilter: string,
  severityFilter: SeverityFilter,
  query: string,
  timeRange: TimeRange,
  latestObservedAt: Date | null
): boolean {
  if (hostFilter !== "all" && alert.hostId !== hostFilter) return false;
  if (severityFilter !== "all" && alert.severity !== severityFilter) return false;
  if (!matchesTimeRange(alert.eventTime, timeRange, latestObservedAt)) return false;
  if (!query) return true;
  const haystack = [alert.alertId, alert.ruleId, alert.title, alert.host, alert.hostId, alert.severity, alert.evidence.join(" "), alert.mitre.join(" ")].join(" ");
  return includesQuery(haystack, query);
}

// Checks whether a telemetry event matches host, search, and time filters.
function matchesEventScope(event: EventRow, hostFilter: string, query: string, timeRange: TimeRange, latestObservedAt: Date | null): boolean {
  if (hostFilter !== "all" && event.hostId !== hostFilter) return false;
  if (!matchesTimeRange(event.eventTime, timeRange, latestObservedAt)) return false;
  if (!query) return true;
  const haystack = [event.eventId, event.host, event.hostId, event.eventType, event.processName, event.destination].join(" ");
  return includesQuery(haystack, query);
}

// Checks whether an incident belongs in the current incident queue.
function matchesIncidentScope(incident: Incident, hostFilter: string, severityFilter: SeverityFilter, query: string): boolean {
  if (hostFilter !== "all" && incident.hostId !== hostFilter) return false;
  if (severityFilter !== "all" && incident.severity !== severityFilter) return false;
  if (!query) return true;
  const haystack = [
    incident.incidentId,
    incident.host,
    incident.hostId,
    incident.category,
    incident.evidence.join(" "),
    incident.stages.map((stage) => `${stage.stage} ${stage.summary}`).join(" ")
  ].join(" ");
  return includesQuery(haystack, query);
}

// Filters timeline rows while keeping severity and host labels aligned.
function matchesTimelineScope(
  item: TimelineItem,
  hostOptions: ReadonlyMap<string, string>,
  hostFilter: string,
  severityFilter: SeverityFilter,
  query: string,
  timeRange: TimeRange,
  latestObservedAt: Date | null
): boolean {
  if (hostFilter !== "all" && hostOptions.get(hostFilter) !== item.host) return false;
  if (severityFilter !== "all" && item.severity !== severityFilter) return false;
  if (!matchesTimeRange(item.time, timeRange, latestObservedAt)) return false;
  if (!query) return true;
  return includesQuery([item.host, item.stage, item.summary, item.severity].join(" "), query);
}

// Filters endpoint risk rows without dropping active hosts that have evidence.
function matchesEndpointRiskScope(
  row: EndpointRisk,
  hostFilter: string,
  severityFilter: SeverityFilter,
  query: string,
  activeHostIds: ReadonlySet<string>
): boolean {
  if (hostFilter !== "all" && row.hostId !== hostFilter) return false;
  if (severityFilter !== "all" && row.severity !== severityFilter && !activeHostIds.has(row.hostId)) return false;
  if (!query) return true;
  const haystack = [row.host, row.hostId, row.severity, row.topRules.join(" ")].join(" ");
  return includesQuery(haystack, query) || activeHostIds.has(row.hostId);
}

// Filters process-tree rows by host, search text, and time window.
function matchesProcessScope(row: ProcessTreeRow, hostFilter: string, query: string, timeRange: TimeRange, latestObservedAt: Date | null): boolean {
  if (hostFilter !== "all" && row.hostId !== hostFilter) return false;
  if (!matchesTimeRange(row.eventTime, timeRange, latestObservedAt)) return false;
  if (!query) return true;
  const haystack = [row.eventId, row.host, row.hostId, row.parentProcess, row.processName, row.processPath].join(" ");
  return includesQuery(haystack, query);
}

// Filters DLQ rows by event id, error code, and validation messages.
function matchesDlqScope(row: DlqEvent, query: string): boolean {
  if (!query) return true;
  return includesQuery([row.eventId, row.code, row.errors.join(" ")].join(" "), query);
}

// Topology filtering keeps matching edges first, then preserves enough nodes for context.
function scopeTopology(
  topology: DashboardResult["topology"],
  hostFilter: string,
  query: string,
  activeHostIds: ReadonlySet<string>
): DashboardResult["topology"] {
  const matchingEdges = topology.edges.filter((edge) => {
    if (hostFilter !== "all" && edge.source !== hostFilter) return false;
    if (query && !includesQuery([edge.sourceLabel, edge.source, edge.target, edge.protocol, edge.state].join(" "), query) && !activeHostIds.has(edge.source)) {
      return false;
    }
    return true;
  });
  const edges = matchingEdges.length ? matchingEdges : topology.edges.filter((edge) => hostFilter === "all" || edge.source === hostFilter);
  const visibleEndpointIds = new Set(edges.map((edge) => edge.source));
  const visibleTargets = new Set(edges.map((edge) => edge.target));
  const nodes = topology.nodes.filter((node) => {
    const layer = node.layer.toLowerCase();
    if (layer.includes("endpoint")) {
      if (hostFilter !== "all") return node.id === hostFilter;
      return !query || visibleEndpointIds.has(node.id) || includesQuery(node.label, query);
    }
    if (layer.includes("external")) return !query || visibleTargets.has(node.id) || visibleTargets.has(node.label) || includesQuery(node.label, query);
    return true;
  });
  return {
    ...topology,
    edges,
    nodes: nodes.length ? nodes : topology.nodes
  };
}

// Relative time windows are anchored to the newest observed timestamp in the sample.
function matchesTimeRange(value: string, timeRange: TimeRange, latestObservedAt: Date | null): boolean {
  if (timeRange === "all") return true;
  const date = new Date(value);
  if (Number.isNaN(date.getTime()) || !latestObservedAt) return true;
  const ranges: Readonly<Record<Exclude<TimeRange, "all">, number>> = {
    last10m: 10 * 60 * 1000,
    last1h: 60 * 60 * 1000,
    last24h: 24 * 60 * 60 * 1000
  };
  return latestObservedAt.getTime() - date.getTime() <= ranges[timeRange];
}

// Counts alerts by severity for chart bars and filter buttons.
function countSeverity(alerts: readonly Alert[]): Readonly<Record<Severity | "all", number>> {
  return {
    all: alerts.length,
    critical: alerts.filter((alert) => alert.severity === "critical").length,
    warning: alerts.filter((alert) => alert.severity === "warning").length,
    suspicious: alerts.filter((alert) => alert.severity === "suspicious").length,
    info: alerts.filter((alert) => alert.severity === "info").length
  };
}

// Finds the newest timestamp so sample-relative time filters behave consistently.
function latestObservedTime(result: DashboardResult): Date | null {
  const dates = [...result.events.map((event) => event.eventTime), ...result.alerts.map((alert) => alert.eventTime), ...result.timeline.map((item) => item.time)]
    .map((value) => new Date(value))
    .filter((value) => !Number.isNaN(value.getTime()));
  if (!dates.length) return null;
  return new Date(Math.max(...dates.map((value) => value.getTime())));
}

// Builds the host selector map from every panel data source.
function buildHostOptions(result: DashboardResult): ReadonlyMap<string, string> {
  const hosts = new Map<string, string>();
  for (const endpoint of result.endpointRisk) hosts.set(endpoint.hostId, endpoint.host);
  for (const event of result.events) hosts.set(event.hostId, event.host);
  for (const alert of result.alerts) hosts.set(alert.hostId, alert.host);
  for (const row of result.processTrees) hosts.set(row.hostId, row.host);
  for (const node of result.topology.nodes) {
    if (node.layer.toLowerCase().includes("endpoint")) hosts.set(node.id, node.label);
  }
  return hosts;
}

// Signal cards summarize cross-layer coverage without changing the underlying counts.
function buildSignals(result: DashboardResult) {
  const processEvents = result.events.filter((event) => event.eventType === "process_start").length;
  const networkEvents = result.events.filter((event) => event.eventType === "network_connection").length;
  const l7Events = result.summary.l7Events || result.events.filter((event) => ["http_request", "application_action", "decryption_event"].includes(event.eventType)).length;
  return [
    {
      label: "EDR Coverage",
      value: processEvents ? `Active · process ${processEvents}` : "Limited",
      detail: "Win32 process telemetry and endpoint agent data",
      tone: processEvents ? "info" : "warning"
    },
    {
      label: "EDR Correlation",
      value: l7Events ? `L7 ${l7Events} events` : result.summary.incidents ? `Incidents ${result.summary.incidents}` : `Network ${networkEvents}`,
      detail: "Process, network, DNS, and L7 records are correlated",
      tone: result.summary.incidents ? "critical" : "info"
    },
    {
      label: "SIEM Pipeline",
      value: result.pipeline.compressedBytes ? `gzip ${formatBytes(result.pipeline.compressedBytes)}` : result.summary.dlq ? `DLQ ${result.summary.dlq}` : "Normal",
      detail: `Payload ${result.telemetry.payloadVersion} · schema ${result.telemetry.schemaVersion}`,
      tone: result.summary.dlq ? "warning" : "info"
    },
    {
      label: "MITRE ATT&CK",
      value: result.aiSummary.highOrCriticalCount ? `AI high ${result.aiSummary.highOrCriticalCount}` : `${result.mitreDistribution.length} tactics`,
      detail: "Rule mapping plus deterministic PoC risk prediction",
      tone: result.aiSummary.highOrCriticalCount ? "critical" : "neutral"
    }
  ] as const;
}

// Normalizes select input text into a supported time-range value.
function toTimeRange(value: string): TimeRange {
  switch (value) {
    case "last10m":
    case "last1h":
    case "last24h":
    case "all":
      return value;
    default:
      return "last24h";
  }
}

// Normalizes select input text into a supported severity filter.
function toSeverityFilter(value: string): SeverityFilter {
  switch (value) {
    case "critical":
    case "warning":
    case "suspicious":
    case "info":
      return value;
    default:
      return "all";
  }
}

// Converts internal state tokens into display labels.
function stateLabel(state: string): string {
  switch (state) {
    case "red":
      return "EDR RED / active response required";
    case "yellow":
      return "EDR YELLOW / analyst review";
    case "green":
      return "EDR GREEN / not detected";
    default:
      return "EDR UNKNOWN / generate telemetry";
  }
}

// Performs case-insensitive search matching for panel filters.
function includesQuery(value: string, query: string): boolean {
  return value.toLowerCase().includes(query);
}

// Formats ISO timestamps for compact table and timeline labels.
function formatTime(value: string): string {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  const month = String(date.getMonth() + 1).padStart(2, "0");
  const day = String(date.getDate()).padStart(2, "0");
  const hour = String(date.getHours()).padStart(2, "0");
  const minute = String(date.getMinutes()).padStart(2, "0");
  return `${month}-${day} ${hour}:${minute}`;
}

// Formats byte counts into readable units for dashboard tables.
function formatBytes(value: number): string {
  if (!value) return "-";
  if (value >= 1_000_000) return `${(value / 1_000_000).toFixed(1)} MB`;
  if (value >= 1_000) return `${(value / 1_000).toFixed(1)} KB`;
  return `${value} B`;
}
