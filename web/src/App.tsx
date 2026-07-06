import { Activity, Network, ShieldAlert } from "lucide-react";
import { useEffect, useState } from "react";
import { AlertInspector, EmptyState, Kpi, PanelHeading, ReportModal, TopologyCanvas } from "./dashboardPanels";
import { type Alert, type DashboardResult, type Severity, loadDashboardResult, readDashboardResult } from "./resultAdapter";

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
  const [timeRange, setTimeRange] = useState<TimeRange>("last1h");
  const [severityFilter, setSeverityFilter] = useState<SeverityFilter>("all");
  const [selectedRuleId, setSelectedRuleId] = useState<string>(result.alerts[0]?.ruleId ?? "");
  useEffect(() => {
    const controller = new AbortController();
    void loadDashboardResult(controller.signal).then((loadedResult) => {
      setResult(loadedResult);
      setSelectedRuleId(loadedResult.alerts[0]?.ruleId ?? "");
    });
    return () => controller.abort();
  }, []);
  const selectedAlert = result.alerts.find((alert) => alert.ruleId === selectedRuleId) ?? result.alerts[0];
  const filteredAlerts = result.alerts.filter(
    (alert) => severityFilter === "all" || alert.severity === severityFilter
  );

  return (
    <main className="app-shell">
      <aside className="sidebar">
        <div>
          <p className="eyebrow">LayerTrace</p>
          <h1>EDR/SIEM Console</h1>
          <p className="sidebar-copy">React dashboard over the current Python detection engine.</p>
        </div>
        <section className="source-panel" aria-label="Data source">
          <p className="eyebrow">Data Source</p>
          <strong>{result.source}</strong>
          <code>python -m src.run</code>
          <code>python -m src.run --collect-local</code>
          <code>python -m src.run --collect-local --include-dns-cache</code>
        </section>
      </aside>

      <section className="workspace">
        <header className="topbar">
          <div>
            <p className="eyebrow">Current State</p>
            <h2>{stateLabel(result.edrState)}</h2>
          </div>
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
        </header>

        <section className="kpi-grid" aria-label="Security summary">
          <Kpi icon={<Activity size={18} />} label="Valid events" value={result.summary.events} />
          <Kpi icon={<ShieldAlert size={18} />} label="Alerts" value={result.summary.alerts} />
          <Kpi icon={<Network size={18} />} label="Incidents" value={result.summary.incidents} />
          <Kpi icon={<ShieldAlert size={18} />} label="Highest risk" value={result.summary.highestRisk} />
        </section>

        <section className="hero-grid">
          <article className="panel topology-panel">
            <PanelHeading title="Endpoint Egress Topology" subtitle="Endpoint fleet -> Protected tenant boundary -> External destinations" />
            <TopologyCanvas nodes={result.topology.nodes} edges={result.topology.edges} />
          </article>

          <article className="panel inspector-panel">
            <PanelHeading title="Alert Inspector" subtitle="Selected alert context" />
            {selectedAlert ? <AlertInspector alert={selectedAlert} /> : <EmptyState label="No alert selected" />}
          </article>
        </section>

        <section className="content-grid">
          <article className="panel">
            <PanelHeading title="Severity Distribution" subtitle={`${TIME_RANGE_LABELS[timeRange]} active filter`} />
            <div className="severity-stack">
              <button className={severityFilter === "all" ? "severity-row active" : "severity-row"} onClick={() => setSeverityFilter("all")} type="button">
                <span>all</span>
                <strong>{result.alerts.length}</strong>
              </button>
              {SEVERITIES.map((severity) => (
                <button
                  className={severityFilter === severity ? `severity-row ${severity} active` : `severity-row ${severity}`}
                  key={severity}
                  onClick={() => setSeverityFilter(severity)}
                  type="button"
                >
                  <span>{severity}</span>
                  <strong>{result.alerts.filter((alert) => alert.severity === severity).length}</strong>
                </button>
              ))}
            </div>
          </article>

          <article className="panel">
            <PanelHeading title="Endpoint Risk Ranking" subtitle="EDR 상태와 탐지 수를 함께 표시" />
            <div className="risk-list">
              {result.endpointRisk.map((endpoint) => (
                <div className="risk-row" key={endpoint.host}>
                  <span>{endpoint.host}</span>
                  <strong>{endpoint.riskScore}</strong>
                  <small>{endpoint.severity} / alerts {endpoint.alerts}</small>
                </div>
              ))}
            </div>
          </article>

          <article className="panel">
            <PanelHeading title="Alerts" subtitle="Click severity to switch the visible set immediately" />
            <div className="alert-list">
              {filteredAlerts.map((alert) => (
                <button
                  className={selectedRuleId === alert.ruleId ? `alert-row ${alert.severity} selected` : `alert-row ${alert.severity}`}
                  key={`${alert.ruleId}-${alert.host}`}
                  onClick={() => setSelectedRuleId(alert.ruleId)}
                  type="button"
                >
                  <span>{alert.title}</span>
                  <strong>{alert.ruleId}</strong>
                  <small>{alert.host} / {alert.riskScore}</small>
                </button>
              ))}
            </div>
          </article>
        </section>

        <ReportModal htmlPath={result.report.htmlPath} markdownPath={result.report.markdownPath} />
      </section>
    </main>
  );
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
      return "EDR UNKNOWN / generate data";
  }
}
