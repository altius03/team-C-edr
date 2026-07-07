import type { ReactNode } from "react";
import type { CountRow, Severity } from "./resultAdapter";

export const SEVERITY_ORDER: readonly Severity[] = ["critical", "warning", "suspicious", "info"];

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

export function EmptyState({ label }: { readonly label: string }) {
  return <div className="empty-state">{label}</div>;
}
