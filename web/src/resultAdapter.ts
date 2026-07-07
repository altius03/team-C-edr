export type Severity = "critical" | "warning" | "suspicious" | "info";
export type EdrState = "red" | "yellow" | "green" | "unknown";

export type Alert = {
  readonly alertId: string;
  readonly ruleId: string;
  readonly title: string;
  readonly host: string;
  readonly hostId: string;
  readonly eventTime: string;
  readonly severity: Severity;
  readonly riskScore: number;
  readonly mitre: readonly string[];
  readonly evidence: readonly string[];
};

export type EndpointRisk = {
  readonly host: string;
  readonly hostId: string;
  readonly severity: Severity;
  readonly riskScore: number;
  readonly alerts: number;
  readonly incidents: number;
  readonly topRules: readonly string[];
  readonly lastEventTime: string;
};

export type TopologyNode = {
  readonly id: string;
  readonly label: string;
  readonly layer: string;
  readonly state: string;
  readonly riskScore: number;
  readonly alertCount: number;
};

export type TopologyEdge = {
  readonly source: string;
  readonly sourceLabel: string;
  readonly target: string;
  readonly protocol: string;
  readonly state: string;
  readonly eventCount: number;
  readonly alertCount: number;
  readonly bytesOut: number;
};

export type EventRow = {
  readonly eventId: string;
  readonly eventTime: string;
  readonly host: string;
  readonly hostId: string;
  readonly eventType: string;
  readonly processName: string;
  readonly destination: string;
  readonly bytesOut: number;
};

export type DlqEvent = {
  readonly eventId: string;
  readonly index: number;
  readonly code: string;
  readonly errors: readonly string[];
};

export type ProcessTreeRow = {
  readonly eventId: string;
  readonly eventTime: string;
  readonly host: string;
  readonly hostId: string;
  readonly parentProcess: string;
  readonly processName: string;
  readonly processPath: string;
  readonly signed: boolean;
};

export type IncidentStage = {
  readonly stage: string;
  readonly summary: string;
};

export type Incident = {
  readonly incidentId: string;
  readonly host: string;
  readonly hostId: string;
  readonly severity: Severity;
  readonly riskScore: number;
  readonly category: string;
  readonly stages: readonly IncidentStage[];
  readonly evidence: readonly string[];
};

export type TimelineItem = {
  readonly time: string;
  readonly host: string;
  readonly stage: string;
  readonly summary: string;
  readonly severity: Severity;
};

export type CountRow = {
  readonly label: string;
  readonly count: number;
};

export type ResponseAction = {
  readonly actionType: string;
  readonly host: string;
  readonly ruleId: string;
  readonly mode: string;
  readonly status: string;
  readonly description: string;
};

export type PipelineDelivery = {
  readonly compression: string;
  readonly rawBytes: number;
  readonly compressedBytes: number;
  readonly compressionRatio: number;
  readonly shipStatus: string;
};

export type TelemetryMetadata = {
  readonly customerId: string;
  readonly tenantId: string;
  readonly agentVersion: string;
  readonly payloadVersion: string;
  readonly schemaVersion: string;
};

export type AiSummary = {
  readonly model: string;
  readonly predictionCount: number;
  readonly highOrCriticalCount: number;
  readonly note: string;
};

export type QueryFinding = {
  readonly queryId: string;
  readonly title: string;
  readonly ruleId: string;
  readonly severity: Severity;
  readonly host: string;
  readonly hostId: string;
  readonly summary: string;
  readonly evidenceCount: number;
  readonly alertCount: number;
  readonly lastEventTime: string;
};

export type TopologySummary = {
  readonly endpointCount: number;
  readonly externalDestinationCount: number;
  readonly alertEdgeCount: number;
};

export type DashboardResult = {
  readonly status: string;
  readonly decision: string;
  readonly generatedAt: string;
  readonly edrState: EdrState;
  readonly summary: {
    readonly inputEvents: number;
    readonly events: number;
    readonly alerts: number;
    readonly incidents: number;
    readonly highestRisk: number;
    readonly dlq: number;
    readonly privacyMasks: number;
    readonly flowEvents: number;
    readonly l7Events: number;
    readonly decryptionEvents: number;
    readonly responseActions: number;
    readonly aiPredictions: number;
    readonly predictedHighOrCritical: number;
  };
  readonly alerts: readonly Alert[];
  readonly endpointRisk: readonly EndpointRisk[];
  readonly events: readonly EventRow[];
  readonly dlqEvents: readonly DlqEvent[];
  readonly processTrees: readonly ProcessTreeRow[];
  readonly incidents: readonly Incident[];
  readonly timeline: readonly TimelineItem[];
  readonly queryFindings: readonly QueryFinding[];
  readonly mitreDistribution: readonly CountRow[];
  readonly topDomains: readonly CountRow[];
  readonly topIps: readonly CountRow[];
  readonly responseActions: readonly ResponseAction[];
  readonly topology: {
    readonly nodes: readonly TopologyNode[];
    readonly edges: readonly TopologyEdge[];
    readonly summary: TopologySummary;
  };
  readonly pipeline: PipelineDelivery;
  readonly telemetry: TelemetryMetadata;
  readonly aiSummary: AiSummary;
  readonly report: {
    readonly htmlPath: string;
    readonly markdownPath: string;
  };
  readonly source: string;
};

const KNOWN_ENDPOINTS: readonly Pick<EndpointRisk, "host" | "hostId">[] = [
  { host: "이주호-Desktop", hostId: "endpoint-04" }
] as const;

declare global {
  interface Window {
    SIEM_RESULT?: unknown;
  }
}

export function readDashboardResult(): DashboardResult {
  return adaptResult(window.SIEM_RESULT);
}

export async function loadDashboardResult(signal: AbortSignal): Promise<DashboardResult> {
  const apiResult = await fetchDashboardApi(signal);
  if (apiResult) return apiResult;

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

async function fetchDashboardApi(signal: AbortSignal): Promise<DashboardResult | null> {
  try {
    const response = await fetch(`${apiBaseUrl()}/v1/dashboard/latest`, { signal });
    if (!response.ok) return null;
    const payload = await response.json();
    const result = adaptResult(payload);
    return result.status === "empty" ? null : result;
  } catch (error) {
    if (error instanceof DOMException && error.name === "AbortError") {
      throw error;
    }
    return null;
  }
}

function apiBaseUrl(): string {
  return String(import.meta.env.VITE_LAYERTRACE_API_BASE_URL ?? import.meta.env.VITE_API_BASE_URL ?? "").replace(/\/$/, "");
}

export function adaptResult(raw: unknown): DashboardResult {
  const result = recordOrEmpty(raw);
  const summary = recordOrEmpty(result.summary);
  const siem = recordOrEmpty(result.siem_analysis);
  const topology = recordOrEmpty(siem.egress_topology);
  const report = recordOrEmpty(result.report);
  const input = recordOrEmpty(result.input);
  const edrState = recordOrEmpty(result.edr_state);
  const responsePlan = recordOrEmpty(result.response_plan);
  const pipeline = recordOrEmpty(result.pipeline_delivery);
  const ai = recordOrEmpty(result.ai_predictions);
  const telemetry = {
    ...recordOrEmpty(input),
    ...recordOrEmpty(result.telemetry_metadata),
    ...recordOrEmpty(siem.telemetry_metadata)
  };
  const topologySummary = recordOrEmpty(topology.summary);
  const endpointRisk = includeKnownEndpointRisk(arrayOfRecords(result.endpoint_risk).map(toEndpointRisk));
  const topologyNodes = includeKnownTopologyNodes(arrayOfRecords(topology.nodes).map(toTopologyNode));

  return {
    status: text(result.status, "empty"),
    decision: text(result.decision, "not_available"),
    generatedAt: text(result.generated_at, "not generated"),
    edrState: normalizeEdrState(text(edrState.state, "unknown")),
    summary: {
      inputEvents: numberValue(summary.input_event_count),
      events: numberValue(summary.valid_event_count),
      alerts: numberValue(summary.alert_count),
      incidents: numberValue(summary.incident_count),
      highestRisk: numberValue(summary.highest_risk_score),
      dlq: numberValue(summary.dlq_event_count),
      privacyMasks: numberValue(summary.privacy_mask_action_count),
      flowEvents: numberValue(summary.flow_event_count),
      l7Events: numberValue(summary.l7_event_count),
      decryptionEvents: numberValue(summary.decryption_event_count),
      responseActions: numberValue(summary.response_action_count),
      aiPredictions: numberValue(summary.ai_prediction_count),
      predictedHighOrCritical: numberValue(summary.predicted_high_or_critical_count)
    },
    alerts: arrayOfRecords(result.alerts).map(toAlert),
    endpointRisk,
    events: arrayOfRecords(result.events).map(toEventRow),
    dlqEvents: arrayOfRecords(result.dlq_events).map(toDlqEvent),
    processTrees: arrayOfRecords(result.process_trees).map(toProcessTreeRow),
    incidents: arrayOfRecords(result.incidents).map(toIncident),
    timeline: arrayOfRecords(siem.correlation_timeline).map(toTimelineItem),
    queryFindings: arrayOfRecords(siem.query_findings).map(toQueryFinding),
    mitreDistribution: arrayOfRecords(result.mitre_distribution).map((item) => ({
      label: text(item.tactic, "unknown tactic"),
      count: numberValue(item.count)
    })),
    topDomains: arrayOfRecords(result.top_suspicious_domains).map((item) => ({
      label: text(item.domain, "unknown domain"),
      count: numberValue(item.count)
    })),
    topIps: arrayOfRecords(result.top_suspicious_ips).map((item) => ({
      label: text(item.ip, "unknown ip"),
      count: numberValue(item.count)
    })),
    responseActions: arrayOfRecords(responsePlan.actions).map(toResponseAction),
    topology: {
      nodes: topologyNodes,
      edges: arrayOfRecords(topology.edges).map(toTopologyEdge),
      summary: {
        endpointCount: numberValue(topologySummary.endpoint_count),
        externalDestinationCount: numberValue(topologySummary.external_destination_count),
        alertEdgeCount: numberValue(topologySummary.alert_edge_count)
      }
    },
    pipeline: {
      compression: text(pipeline.compression, "none"),
      rawBytes: numberValue(pipeline.raw_bytes),
      compressedBytes: numberValue(pipeline.compressed_bytes),
      compressionRatio: numberValue(pipeline.compression_ratio),
      shipStatus: text(pipeline.ship_status, "not_requested")
    },
    telemetry: {
      customerId: text(telemetry.customer_id, "-"),
      tenantId: text(telemetry.tenant_id, "-"),
      agentVersion: text(telemetry.agent_version, "-"),
      payloadVersion: text(telemetry.payload_version, "-"),
      schemaVersion: text(telemetry.schema_version, "-")
    },
    aiSummary: {
      model: text(ai.model, "not_available"),
      predictionCount: numberValue(ai.prediction_count),
      highOrCriticalCount: numberValue(ai.high_or_critical_count),
      note: text(ai.note, "")
    },
    report: {
      htmlPath: text(report.latest_html_path, "outputs/reports/latest/security_report.html"),
      markdownPath: text(report.latest_markdown_path, "outputs/reports/latest/security_report.md")
    },
    source: sourceLabel(input)
  };
}

function toAlert(item: Readonly<Record<string, unknown>>): Alert {
  const hostId = text(item.host_id, "unknown");
  return {
    alertId: text(item.alert_id, text(item.rule_id, "unknown")),
    ruleId: text(item.rule_id, "unknown"),
    title: text(item.title, text(item.rule_id, "Unknown alert")),
    host: hostLabel(hostId, text(item.host_display_name, "")),
    hostId,
    eventTime: text(item.event_time, ""),
    severity: normalizeSeverity(text(item.severity, "info")),
    riskScore: numberValue(item.risk_score),
    mitre: arrayOfText(item.mitre_mapping),
    evidence: arrayOfText(item.evidence)
  };
}

function toEndpointRisk(item: Readonly<Record<string, unknown>>): EndpointRisk {
  const hostId = text(item.host_id, "unknown");
  return {
    host: hostLabel(hostId, text(item.host_display_name, "")),
    hostId,
    severity: normalizeSeverity(text(item.severity, "info")),
    riskScore: numberValue(item.risk_score),
    alerts: numberValue(item.alert_count),
    incidents: numberValue(item.incident_count),
    topRules: arrayOfText(item.top_rules),
    lastEventTime: text(item.last_event_time, "")
  };
}

function toTopologyNode(item: Readonly<Record<string, unknown>>): TopologyNode {
  const id = text(item.id, "unknown");
  const rawLabel = text(item.label, id);
  const layer = text(item.layer, "unknown");
  return {
    id,
    label: layer.toLowerCase().includes("endpoint") ? hostLabel(id, rawLabel) : rawLabel,
    layer,
    state: normalizeTopologyState(text(item.state, "observed")),
    riskScore: numberValue(item.risk_score),
    alertCount: numberValue(item.alert_count)
  };
}

function toTopologyEdge(item: Readonly<Record<string, unknown>>): TopologyEdge {
  const source = text(item.source, "unknown");
  return {
    source,
    sourceLabel: hostLabel(source, text(item.source_label, source)),
    target: text(item.target, "unknown"),
    protocol: text(item.protocol, "tcp"),
    state: normalizeTopologyState(text(item.state, "observed")),
    eventCount: numberValue(item.event_count),
    alertCount: numberValue(item.alert_count),
    bytesOut: numberValue(item.bytes_out)
  };
}

function toEventRow(item: Readonly<Record<string, unknown>>): EventRow {
  const hostId = text(item.host_id, "unknown");
  return {
    eventId: text(item.event_id, "unknown"),
    eventTime: text(item.event_time, ""),
    host: hostLabel(hostId, text(item.host_display_name, "")),
    hostId,
    eventType: text(item.event_type, "unknown"),
    processName: text(item.process_name, "-"),
    destination: text(item.domain, text(item.dst_ip, "-")),
    bytesOut: numberValue(item.bytes_out)
  };
}

function toDlqEvent(item: Readonly<Record<string, unknown>>): DlqEvent {
  return {
    eventId: text(item.event_id, `index-${numberValue(item.index)}`),
    index: numberValue(item.index),
    code: text(item.code, "UNKNOWN_SCHEMA_ERROR"),
    errors: arrayOfText(item.errors)
  };
}

function toProcessTreeRow(item: Readonly<Record<string, unknown>>): ProcessTreeRow {
  const hostId = text(item.host_id, "unknown");
  return {
    eventId: text(item.event_id, "unknown"),
    eventTime: text(item.event_time, ""),
    host: hostLabel(hostId, text(item.host_display_name, "")),
    hostId,
    parentProcess: text(item.parent_process, "-"),
    processName: text(item.process_name, "-"),
    processPath: text(item.process_path, ""),
    signed: Boolean(item.signed)
  };
}

function toIncident(item: Readonly<Record<string, unknown>>): Incident {
  const hostId = text(item.host_id, "unknown");
  return {
    incidentId: text(item.incident_id, "unknown"),
    host: hostLabel(hostId, text(item.host_display_name, "")),
    hostId,
    severity: normalizeSeverity(text(item.severity, "critical")),
    riskScore: numberValue(item.risk_score),
    category: text(item.primary_category, "incident"),
    stages: arrayOfRecords(item.detected_sequence).map((stage) => ({
      stage: text(stage.stage, "unknown"),
      summary: text(stage.summary, "")
    })),
    evidence: arrayOfText(item.evidence)
  };
}

function toTimelineItem(item: Readonly<Record<string, unknown>>): TimelineItem {
  const hostId = text(item.host_id, "unknown");
  return {
    time: text(item.time, ""),
    host: hostLabel(hostId, text(item.host_display_name, "")),
    stage: text(item.stage, "unknown"),
    summary: text(item.summary, ""),
    severity: normalizeSeverity(text(item.severity, "info"))
  };
}

function toQueryFinding(item: Readonly<Record<string, unknown>>): QueryFinding {
  const hostId = text(item.host_id, "unknown");
  return {
    queryId: text(item.query_id, "SIEM-Q"),
    title: text(item.title, "SIEM query finding"),
    ruleId: text(item.rule_id, "-"),
    severity: normalizeSeverity(text(item.severity, "info")),
    host: hostLabel(hostId, text(item.host_display_name, "")),
    hostId,
    summary: text(item.summary, ""),
    evidenceCount: numberValue(item.evidence_count),
    alertCount: numberValue(item.alert_count),
    lastEventTime: text(item.last_event_time, "")
  };
}

function toResponseAction(item: Readonly<Record<string, unknown>>): ResponseAction {
  const hostId = text(item.host_id, "unknown");
  return {
    actionType: text(item.action_type, "analyst_review"),
    host: hostLabel(hostId, ""),
    ruleId: text(item.rule_id, "-"),
    mode: text(item.mode, "dry-run"),
    status: text(item.status, "planned"),
    description: text(item.description, "")
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

function normalizeTopologyState(value: string): string {
  const normalized = value.toLowerCase().replace(/_/g, "-");
  if (normalized === "red") return "alert";
  return normalized;
}

function sourceLabel(input: Readonly<Record<string, unknown>>): string {
  const source = text(input.source, "latest CLI run");
  if (source === "event_file") return `${numberValue(input.raw_event_count)} events / offline sample`;
  if (source === "local_windows") return "local Windows telemetry";
  if (source === "pcap_file") return "PCAP file telemetry";
  if (source === "l7_file") return "decrypted L7 records";
  return source;
}

function includeKnownEndpointRisk(rows: readonly EndpointRisk[]): readonly EndpointRisk[] {
  const knownHostIds = new Set(rows.map((row) => row.hostId));
  const missingRows = KNOWN_ENDPOINTS
    .filter((endpoint) => !knownHostIds.has(endpoint.hostId))
    .map((endpoint) => ({
      host: endpoint.host,
      hostId: endpoint.hostId,
      severity: "info",
      riskScore: 0,
      alerts: 0,
      incidents: 0,
      topRules: [],
      lastEventTime: ""
    } satisfies EndpointRisk));
  return [...rows, ...missingRows];
}

function includeKnownTopologyNodes(nodes: readonly TopologyNode[]): readonly TopologyNode[] {
  const knownNodeIds = new Set(nodes.map((node) => node.id));
  const missingNodes = KNOWN_ENDPOINTS
    .filter((endpoint) => !knownNodeIds.has(endpoint.hostId))
    .map((endpoint) => ({
      id: endpoint.hostId,
      label: endpoint.host,
      layer: "endpoint",
      state: "not-detected",
      riskScore: 0,
      alertCount: 0
    } satisfies TopologyNode));
  return [...nodes, ...missingNodes];
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

function hostLabel(hostId: string, displayName: string): string {
  const fallback: Readonly<Record<string, string>> = {
    "endpoint-01": "황건하 PC",
    "endpoint-02": "박소연 Laptop",
    "endpoint-03": "이혜령 Workstation",
    "endpoint-04": "이주호-Desktop"
  };
  if (isReadableLabel(displayName)) {
    return displayName;
  }
  return fallback[hostId.toLowerCase()] ?? hostId;
}

function isReadableLabel(value: string): boolean {
  if (!value) return false;
  if (value.includes("\uFFFD")) return false;
  if (/[\u3130-\u318f\uac00-\ud7af]/.test(value)) return true;
  const noisyCharacters = [...value].filter((character) => character === "?");
  return noisyCharacters.length <= Math.max(1, Math.floor(value.length / 3));
}
