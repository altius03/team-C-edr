export type Severity = "critical" | "warning" | "suspicious" | "info";
export type EdrState = "red" | "yellow" | "green" | "unknown";

export type Alert = {
  readonly ruleId: string;
  readonly title: string;
  readonly host: string;
  readonly severity: Severity;
  readonly riskScore: number;
  readonly evidence: readonly string[];
};

export type EndpointRisk = {
  readonly host: string;
  readonly severity: Severity;
  readonly riskScore: number;
  readonly alerts: number;
  readonly incidents: number;
};

export type TopologyNode = {
  readonly id: string;
  readonly label: string;
  readonly layer: string;
  readonly state: string;
};

export type TopologyEdge = {
  readonly source: string;
  readonly target: string;
  readonly protocol: string;
  readonly alertCount: number;
};

export type DashboardResult = {
  readonly status: string;
  readonly decision: string;
  readonly generatedAt: string;
  readonly edrState: EdrState;
  readonly summary: {
    readonly events: number;
    readonly alerts: number;
    readonly incidents: number;
    readonly highestRisk: number;
  };
  readonly alerts: readonly Alert[];
  readonly endpointRisk: readonly EndpointRisk[];
  readonly topology: {
    readonly nodes: readonly TopologyNode[];
    readonly edges: readonly TopologyEdge[];
  };
  readonly report: {
    readonly htmlPath: string;
    readonly markdownPath: string;
  };
  readonly source: string;
};

declare global {
  interface Window {
    SIEM_RESULT?: unknown;
  }
}

export function readDashboardResult(): DashboardResult {
  return adaptResult(window.SIEM_RESULT);
}

export async function loadDashboardResult(signal: AbortSignal): Promise<DashboardResult> {
  try {
    const response = await fetch("/latest-result.json", { signal });
    if (!response.ok) {
      return readDashboardResult();
    }
    return adaptResult(await response.json());
  } catch (error) {
    if (error instanceof DOMException && error.name === "AbortError") {
      throw error;
    }
    return readDashboardResult();
  }
}

export function adaptResult(raw: unknown): DashboardResult {
  const result = recordOrEmpty(raw);
  const summary = recordOrEmpty(result.summary);
  const siem = recordOrEmpty(result.siem_analysis);
  const topology = recordOrEmpty(siem.egress_topology);
  const report = recordOrEmpty(result.report);
  const input = recordOrEmpty(result.input);
  const edrState = recordOrEmpty(result.edr_state);

  return {
    status: text(result.status, "empty"),
    decision: text(result.decision, "not_available"),
    generatedAt: text(result.generated_at, "not generated"),
    edrState: normalizeEdrState(text(edrState.state, "unknown")),
    summary: {
      events: numberValue(summary.valid_event_count),
      alerts: numberValue(summary.alert_count),
      incidents: numberValue(summary.incident_count),
      highestRisk: numberValue(summary.highest_risk_score)
    },
    alerts: arrayOfRecords(result.alerts).map(toAlert),
    endpointRisk: arrayOfRecords(result.endpoint_risk).map(toEndpointRisk),
    topology: {
      nodes: arrayOfRecords(topology.nodes).map(toTopologyNode),
      edges: arrayOfRecords(topology.edges).map(toTopologyEdge)
    },
    report: {
      htmlPath: text(report.latest_html_path, "outputs/reports/latest/security_report.html"),
      markdownPath: text(report.latest_markdown_path, "outputs/reports/latest/security_report.md")
    },
    source: text(input.source, "latest CLI run")
  };
}

function toAlert(item: Readonly<Record<string, unknown>>): Alert {
  return {
    ruleId: text(item.rule_id, "unknown"),
    title: text(item.title, text(item.rule_id, "Unknown alert")),
    host: text(item.host_display_name, text(item.host_id, "unknown endpoint")),
    severity: normalizeSeverity(text(item.severity, "info")),
    riskScore: numberValue(item.risk_score),
    evidence: arrayOfText(item.evidence)
  };
}

function toEndpointRisk(item: Readonly<Record<string, unknown>>): EndpointRisk {
  return {
    host: text(item.host_display_name, text(item.host_id, "unknown endpoint")),
    severity: normalizeSeverity(text(item.severity, "info")),
    riskScore: numberValue(item.risk_score),
    alerts: numberValue(item.alert_count),
    incidents: numberValue(item.incident_count)
  };
}

function toTopologyNode(item: Readonly<Record<string, unknown>>): TopologyNode {
  return {
    id: text(item.id, "unknown"),
    label: text(item.label, "unknown"),
    layer: text(item.layer, "unknown"),
    state: text(item.state, "observed")
  };
}

function toTopologyEdge(item: Readonly<Record<string, unknown>>): TopologyEdge {
  return {
    source: text(item.source, "unknown"),
    target: text(item.target, "unknown"),
    protocol: text(item.protocol, "tcp"),
    alertCount: numberValue(item.alert_count)
  };
}

function normalizeSeverity(value: string): Severity {
  const normalized = value.toLowerCase();
  switch (normalized) {
    case "critical":
    case "warning":
    case "suspicious":
    case "info":
      return normalized;
    default:
      return "info";
  }
}

function normalizeEdrState(value: string): EdrState {
  const normalized = value.toLowerCase();
  switch (normalized) {
    case "red":
    case "yellow":
    case "green":
      return normalized;
    default:
      return "unknown";
  }
}

function recordOrEmpty(value: unknown): Readonly<Record<string, unknown>> {
  return isRecord(value) ? value : {};
}

function isRecord(value: unknown): value is Readonly<Record<string, unknown>> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function arrayOfRecords(value: unknown): readonly Readonly<Record<string, unknown>>[] {
  return Array.isArray(value) ? value.filter(isRecord) : [];
}

function arrayOfText(value: unknown): readonly string[] {
  return Array.isArray(value) ? value.filter((item): item is string => typeof item === "string") : [];
}

function text(value: unknown, fallback: string): string {
  return typeof value === "string" && value.length > 0 ? value : fallback;
}

function numberValue(value: unknown): number {
  return typeof value === "number" && Number.isFinite(value) ? value : 0;
}
