import { Activity, Database, Radar, ShieldAlert, Siren, Workflow } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import {
  AlertInspector,
  AlertList,
  CountBars,
  EmptyState,
  EventTable,
  IncidentQueue,
  Kpi,
  PanelHeading,
  ReportModal,
  ResponsePlan,
  SeverityChart,
  Timeline,
  TopologyCanvas,
  VolumeChart
} from "./dashboardPanels";
import {
  type Alert,
  type DashboardResult,
  type EventRow,
  type Severity,
  loadDashboardResult,
  readDashboardResult
} from "./resultAdapter";

type TimeRange = "last10m" | "last1h" | "last24h";
type SeverityFilter = Severity | "all";

const TIME_RANGES: readonly TimeRange[] = ["last10m", "last1h", "last24h"];
const TIME_RANGE_LABELS: Readonly<Record<TimeRange, string>> = {
  last10m: "Last 10m",
  last1h: "Last 1h",
  last24h: "Last 24h"
};

const SEVERITIES: readonly Severity[] = ["critical", "warning", "suspicious", "info"];

export function App() {
  const [result, setResult] = useState<DashboardResult>(() => readDashboardResult());
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

  const latestObservedAt = useMemo(() => latestObservedTime(result), [result]);
  const hostOptions = useMemo(() => buildHostOptions(result), [result]);
  const scopedAlerts = result.alerts.filter((alert) => matchesScope(alert, hostFilter, severityFilter, search, timeRange, latestObservedAt));
  const scopedEvents = result.events.filter((event) => matchesEventScope(event, hostFilter, search, timeRange, latestObservedAt));
  const scopedIncidents = result.incidents.filter(
    (incident) => (hostFilter === "all" || incident.hostId === hostFilter) && (severityFilter === "all" || incident.severity === severityFilter)
  );
  const scopedTimeline = result.timeline.filter((item) => hostFilter === "all" || hostOptions.get(hostFilter) === item.host);
  const severityCounts = countSeverity(scopedAlerts);
  const selectedAlert = scopedAlerts.find((alert) => alert.alertId === selectedAlertId) ?? scopedAlerts[0] ?? result.alerts[0];

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
          <a className="nav-item" href="#incidents">Incidents</a>
          <a className="nav-item" href="#timeline">Timeline</a>
          <a className="nav-item" href="#events">Event log</a>
        </nav>
        <section className="source-panel" aria-label="Data source">
          <p className="eyebrow">Data Source</p>
          <strong>{result.source}</strong>
          <span>데이터 소스 변경은 CLI를 다시 실행한 뒤 화면을 새로고침하는 방식입니다.</span>
          <code>python -m src.run</code>
          <code>python -m src.run --collect-local</code>
          <code>python -m src.run --collect-local --include-dns-cache</code>
        </section>
      </aside>

      <section className="workspace">
        <header className="topbar">
          <div>
            <p className="eyebrow">Current State</p>
            <h1>{stateLabel(result.edrState)}</h1>
            <p className="subtitle">Run {result.status} / generated {formatTime(result.generatedAt)} / {result.decision}</p>
          </div>
          <div className="topbar-right">
            <div className="selected-alert-pill">
              <span>Selected alert</span>
              <strong>{selectedAlert ? `${selectedAlert.ruleId} / ${selectedAlert.host}` : "none"}</strong>
            </div>
            <ReportModal htmlPath={result.report.htmlPath} markdownPath={result.report.markdownPath} />
          </div>
        </header>

        <section className="toolbar" aria-label="Dashboard filters">
          <div className="segmented" aria-label="Time range">
            {TIME_RANGES.map((range) => (
              <button
                className={timeRange === range ? "active" : ""}
                key={range}
                onClick={() => setTimeRange(range)}
                type="button"
              >
                {TIME_RANGE_LABELS[range]}
              </button>
            ))}
          </div>
          <label className="select-field">
            <span>Endpoint</span>
            <select onChange={(event) => setHostFilter(event.target.value)} value={hostFilter}>
              <option value="all">All endpoints</option>
              {[...hostOptions.entries()].map(([hostId, hostLabel]) => <option key={hostId} value={hostId}>{hostLabel}</option>)}
            </select>
          </label>
          <label className="search-field">
            <span>Search</span>
            <input onChange={(event) => setSearch(event.target.value)} placeholder="domain, process, rule" type="search" value={search} />
          </label>
        </section>

        <section className="kpi-grid" id="overview" aria-label="Security summary">
          <Kpi accent="critical" detail="highest endpoint risk" icon={<Siren size={18} />} label="Risk peak" value={result.summary.highestRisk} />
          <Kpi accent="critical" detail="visible alert scope" icon={<ShieldAlert size={18} />} label="Alerts" value={scopedAlerts.length} />
          <Kpi detail="correlated cases" icon={<Workflow size={18} />} label="Incidents" value={scopedIncidents.length} />
          <Kpi detail="validated telemetry" icon={<Activity size={18} />} label="Events" value={scopedEvents.length} />
          <Kpi accent="warning" detail="schema review queue" icon={<Database size={18} />} label="DLQ" value={result.summary.dlq} />
          <Kpi detail="dry-run playbook actions" icon={<Radar size={18} />} label="Responses" value={result.summary.responseActions} />
        </section>

        <section className="hero-grid">
          <article className="panel topology-panel">
            <PanelHeading
              chip={`${result.topology.edges.length} edges`}
              title="Endpoint Egress Topology"
              subtitle="Endpoint fleet -> Protected tenant boundary -> External destinations"
            />
            <TopologyCanvas nodes={result.topology.nodes} edges={result.topology.edges} />
          </article>

          <article className="panel">
            <PanelHeading chip={TIME_RANGE_LABELS[timeRange]} title="Detection Overview" subtitle="Severity, event volume, and MITRE coverage" />
            <SeverityChart active={severityFilter} counts={severityCounts} onSelect={setSeverityFilter} />
            <VolumeChart alerts={scopedAlerts} events={scopedEvents} />
            <CountBars kind="mitre" rows={result.mitreDistribution} />
          </article>
        </section>

        <section className="content-grid">
          <article className="panel">
            <PanelHeading chip={selectedAlert?.severity} title="Alert Inspector" subtitle="Click an alert or severity to change this context" />
            {selectedAlert ? <AlertInspector alert={selectedAlert} /> : <EmptyState label="No alert selected" />}
          </article>

          <article className="panel" id="incidents">
            <PanelHeading chip={`${scopedIncidents.length} cases`} title="Incident Workbench" subtitle="Correlated host sequence and risk context" />
            <IncidentQueue incidents={scopedIncidents} />
          </article>

          <article className="panel">
            <PanelHeading title="Top Destinations" subtitle="Suspicious domains and IP addresses" />
            <div className="dual-list">
              <CountBars kind="domain" rows={result.topDomains} />
              <CountBars kind="ip" rows={result.topIps} />
            </div>
          </article>
        </section>

        <section className="wide-grid">
          <article className="panel" id="timeline">
            <PanelHeading title="Attack Timeline" subtitle="Download, execution, command and control, exfiltration stages" />
            <Timeline rows={scopedTimeline} />
          </article>

          <article className="panel">
            <PanelHeading title="Response Playbook" subtitle="Local dry-run actions generated from the selected result" />
            <ResponsePlan actions={result.responseActions} />
          </article>
        </section>

        <section className="wide-grid">
          <article className="panel">
            <PanelHeading chip={`${scopedAlerts.length} visible`} title="Alert Explorer" subtitle="Severity click switches this list immediately" />
            <AlertList alerts={scopedAlerts} onSelect={setSelectedAlertId} selectedAlertId={selectedAlert?.alertId ?? ""} />
          </article>

          <article className="panel" id="events">
            <PanelHeading chip={`${scopedEvents.length} events`} title="Event Log" subtitle="Telemetry rows after time, endpoint, and search filters" />
            <EventTable events={scopedEvents} />
          </article>
        </section>
      </section>
    </main>
  );
}

function matchesScope(
  alert: Alert,
  hostFilter: string,
  severityFilter: SeverityFilter,
  search: string,
  timeRange: TimeRange,
  latestObservedAt: Date | null
): boolean {
  if (hostFilter !== "all" && alert.hostId !== hostFilter) return false;
  if (severityFilter !== "all" && alert.severity !== severityFilter) return false;
  if (!matchesTimeRange(alert.eventTime, timeRange, latestObservedAt)) return false;
  if (!search) return true;
  const haystack = [alert.ruleId, alert.title, alert.host, alert.severity, alert.evidence.join(" "), alert.mitre.join(" ")].join(" ").toLowerCase();
  return haystack.includes(search.toLowerCase());
}

function matchesEventScope(event: EventRow, hostFilter: string, search: string, timeRange: TimeRange, latestObservedAt: Date | null): boolean {
  if (hostFilter !== "all" && event.hostId !== hostFilter) return false;
  if (!matchesTimeRange(event.eventTime, timeRange, latestObservedAt)) return false;
  if (!search) return true;
  const haystack = [event.host, event.eventType, event.processName, event.destination].join(" ").toLowerCase();
  return haystack.includes(search.toLowerCase());
}

function matchesTimeRange(value: string, timeRange: TimeRange, latestObservedAt: Date | null): boolean {
  const date = new Date(value);
  if (Number.isNaN(date.getTime()) || !latestObservedAt) return true;
  const ranges: Readonly<Record<TimeRange, number>> = {
    last10m: 10 * 60 * 1000,
    last1h: 60 * 60 * 1000,
    last24h: 24 * 60 * 60 * 1000
  };
  return latestObservedAt.getTime() - date.getTime() <= ranges[timeRange];
}

function countSeverity(alerts: readonly Alert[]): Readonly<Record<Severity | "all", number>> {
  return {
    all: alerts.length,
    critical: alerts.filter((alert) => alert.severity === "critical").length,
    warning: alerts.filter((alert) => alert.severity === "warning").length,
    suspicious: alerts.filter((alert) => alert.severity === "suspicious").length,
    info: alerts.filter((alert) => alert.severity === "info").length
  };
}

function latestObservedTime(result: DashboardResult): Date | null {
  const dates = [...result.events.map((event) => event.eventTime), ...result.alerts.map((alert) => alert.eventTime)]
    .map((value) => new Date(value))
    .filter((value) => !Number.isNaN(value.getTime()));
  if (!dates.length) return null;
  return new Date(Math.max(...dates.map((value) => value.getTime())));
}

function buildHostOptions(result: DashboardResult): ReadonlyMap<string, string> {
  const hosts = new Map<string, string>();
  for (const endpoint of result.endpointRisk) hosts.set(endpoint.hostId, endpoint.host);
  for (const event of result.events) hosts.set(event.hostId, event.host);
  for (const alert of result.alerts) hosts.set(alert.hostId, alert.host);
  return hosts;
}

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

function formatTime(value: string): string {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  const month = String(date.getMonth() + 1).padStart(2, "0");
  const day = String(date.getDate()).padStart(2, "0");
  const hour = String(date.getHours()).padStart(2, "0");
  const minute = String(date.getMinutes()).padStart(2, "0");
  return `${month}-${day} ${hour}:${minute}`;
}
