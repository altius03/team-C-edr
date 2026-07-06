import { FileText, Printer } from "lucide-react";
import { useState, type ReactNode } from "react";
import { type Alert, type TopologyEdge, type TopologyNode } from "./resultAdapter";

export function Kpi({ icon, label, value }: { readonly icon: ReactNode; readonly label: string; readonly value: number }) {
  return (
    <article className="kpi-card">
      {icon}
      <span>{label}</span>
      <strong>{value}</strong>
    </article>
  );
}

export function PanelHeading({ title, subtitle }: { readonly title: string; readonly subtitle: string }) {
  return (
    <header className="panel-heading">
      <h3>{title}</h3>
      <p>{subtitle}</p>
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
  const endpointNodes = nodes.filter((node) => node.layer.toLowerCase().includes("endpoint"));
  const externalNodes = nodes.filter((node) => node.layer.toLowerCase().includes("external"));

  return (
    <div className="topology-stage">
      <div className="lane">
        <span>Endpoint fleet</span>
        {endpointNodes.slice(0, 4).map((node) => <NodePill key={node.id} node={node} />)}
      </div>
      <div className="lane boundary">
        <span>Protected tenant boundary</span>
        <div className="boundary-core">Tenant SIEM boundary</div>
      </div>
      <div className="lane">
        <span>External destinations</span>
        {externalNodes.slice(0, 5).map((node) => <NodePill key={node.id} node={node} />)}
      </div>
      <div className="edge-summary">
        {edges.length} egress edges / {edges.filter((edge) => edge.alertCount > 0).length} alert-linked
      </div>
    </div>
  );
}

export function AlertInspector({ alert }: { readonly alert: Alert }) {
  return (
    <div className={`inspector ${alert.severity}`}>
      <span className="chip">{alert.severity}</span>
      <h3>{alert.ruleId} / {alert.title}</h3>
      <p>{alert.host}</p>
      <strong>risk {alert.riskScore}</strong>
      <ul>
        {alert.evidence.slice(0, 4).map((line) => <li key={line}>{line}</li>)}
      </ul>
    </div>
  );
}

export function EmptyState({ label }: { readonly label: string }) {
  return <div className="empty-state">{label}</div>;
}

export function ReportModal({ htmlPath, markdownPath }: { readonly htmlPath: string; readonly markdownPath: string }) {
  const [open, setOpen] = useState(false);
  return (
    <>
      <div className="report-actions">
        <button onClick={() => setOpen(true)} type="button"><FileText size={16} /> 보고서 열기</button>
        <button onClick={() => window.print()} type="button"><Printer size={16} /> PDF로 저장</button>
      </div>
      {open ? (
        <div aria-modal="true" className="modal" role="dialog">
          <section className="modal-card">
            <PanelHeading title="LayerTrace Report" subtitle="Generated analysis report" />
            <p>HTML: {htmlPath}</p>
            <p>Markdown: {markdownPath}</p>
            <div className="modal-actions">
              <button onClick={() => window.print()} type="button"><Printer size={16} /> PDF로 저장</button>
              <button onClick={() => setOpen(false)} type="button">닫기</button>
            </div>
          </section>
        </div>
      ) : null}
    </>
  );
}

function NodePill({ node }: { readonly node: TopologyNode }) {
  return <div className={`node-pill ${node.state}`}>{node.label}</div>;
}
