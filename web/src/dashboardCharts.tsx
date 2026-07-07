import type { Alert, EventRow, Severity } from "./resultAdapter";
import { SEVERITY_ORDER } from "./dashboardPanelCore";
import { formatTime } from "./dashboardPanelUtils";

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
