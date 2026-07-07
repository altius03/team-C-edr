import { FileText, Printer, X } from "lucide-react";
import { useEffect, useState } from "react";
import type { AiSummary, EdrState, PipelineDelivery, QueryFinding, TelemetryMetadata, TopologySummary } from "./resultAdapter";
import { EmptyState, PanelHeading } from "./dashboardPanelCore";
import { fileName, formatBytes } from "./dashboardPanelUtils";

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
  if (reportUnavailable(decision)) {
    return (
      <div className="report-center-panel">
        <div className="report-summary">
          <strong>분석 report가 아직 없습니다</strong>
          <p>판단: {decision}</p>
          <p>운영 모드에서는 API 실패를 demo fallback report로 대체하지 않습니다.</p>
        </div>
      </div>
    );
  }

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
  const unavailable = reportUnavailable(decision);

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
        <button disabled={unavailable} onClick={() => setOpen(true)} type="button">
          <FileText size={16} /> {unavailable ? "Report unavailable" : triggerLabel}
        </button>
      </div>
      {open && !unavailable ? (
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

function reportUnavailable(decision: string): boolean {
  return decision === "api_unavailable" || decision === "not_available";
}
